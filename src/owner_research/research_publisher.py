"""Local, atomic publication of one strictly typed research report package.

The publisher is deliberately capability-poor: it cannot fetch data, invoke the
valuation kernel, upload, email, or call cloud/GitHub APIs.  It only packages typed,
strictly reloaded inputs and performs an exact post-publication reload.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import stat
import sys
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema.exceptions import ValidationError as JSONSchemaValidationError

from .contracts import ReportSpec, ResearchBundle, RunManifest, Score, contract_from_dict
from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze, to_json_value
from .futu_receipts import SignatureVerifier
from .futu_session import (
    FutuMarketExecutionPublicationManifest,
    FutuObservationDispositionPublicationBundle,
    FutuPartialSessionPublicationManifest,
    FutuSessionPublicationManifest,
    build_futu_market_execution_publication_manifest,
    build_futu_observation_disposition_publication_bundle,
    validate_futu_market_execution_publication_manifest,
    validate_futu_observation_disposition_publication_bundle,
    validate_futu_partial_session_publication_manifest,
    validate_futu_session_publication_manifest,
)
from .owner_equity_types import (
    FutuOptionalDataDispositionPublicationManifest,
    MarketExpectationsPublicationManifest,
    ResearchSourceIndexPublicationManifest,
    RuntimeGapPublicationManifest,
)
from .research_bundle_builder import ResearchBundleBuildResult
from .research_bundle_policies import bundle_payload_sha256
from .research_report import (
    REPORT_PDF_MAX_BYTES,
    REPORT_TEXT_MAX_BYTES,
    ComparableValuationPublicationManifest,
    CompositeValuationPublicationManifest,
    ForwardReOIValuationPublicationManifest,
    OwnerScorecardPublicationManifest,
    PdfRenderResult,
    ReloadedResearchInput,
    ReloadedValuationInput,
    ReportArtifact,
    ReportBuildReceipt,
    ReportBuildResult,
    ResearchReportContent,
    ResearchReportError,
    ScoreV2PublicationManifest,
    _asset_contents,
    _content_charts_svg,
    _content_charts_tex,
    _content_tables_tex,
    _report_data_tex,
    _report_markdown,
    _report_payload,
    _validate_downstream_publication_chain,
    _validate_parallel_schema,
    _validate_render_result,
    _valuation_archive_file_bytes,
    _verify_inputs,
    load_report_toolchain_authority,
    replay_report_pdf_qa,
)
from .valuation_run_archive import (
    VALUATION_RUN_ARCHIVE_FILENAMES,
    ValuationRunArchive,
    load_valuation_run_archive,
)
from .valuation_synthesis_types import retained_authority_replay_scope

PUBLISH_MAX_MEMBERS = 512
PUBLISH_MAX_BYTES = 512 * 1024 * 1024
PUBLISH_PDF_MAX_BYTES = REPORT_PDF_MAX_BYTES
PUBLISH_IMAGE_MAX_BYTES = 16 * 1024 * 1024
PUBLISH_OTHER_MAX_BYTES = REPORT_TEXT_MAX_BYTES
_CONCURRENT_PUBLICATION_WAIT_SECONDS = 5.0
_CONCURRENT_PUBLICATION_POLL_SECONDS = 0.01
PUBLICATION_MANIFEST = "publication-manifest.json"
PUBLISHED_PACKAGE = "published-package.json"
_CONTROL_FILES = frozenset((PUBLICATION_MANIFEST, PUBLISHED_PACKAGE))
_IMAGE_SUFFIXES = frozenset((".png", ".jpg", ".jpeg", ".webp", ".svg"))
_EXPECTED_REPORT_ARTIFACTS = frozenset(
    (
        "font-manifest.json",
        "report-charts.svg",
        "report-chart.tex",
        "report-content.json",
        "report-data.json",
        "report-data.tex",
        "report-extracted.txt",
        "report-table.tex",
        "report.md",
        "report.pdf",
        "report.tex",
    )
)
_SYNTHESIS_PATHS = {
    "forward_reoi": "synthesis/forward-reoi-publication-manifest.json",
    "comparable_valuation": "synthesis/comparable-valuation-publication-manifest.json",
    "composite_valuation": "synthesis/composite-valuation-publication-manifest.json",
}
_OWNER_SCORECARD_PATH = "scoring/owner-scorecard-publication-manifest.json"
_FUTU_SESSION_PATH = "vendor/futu-session-publication-manifest.json"
_FUTU_PARTIAL_SESSION_PATH = "vendor/futu-partial-session-publication-manifest.json"
_FUTU_MARKET_EXECUTION_PATH = "vendor/futu-market-execution-publication-manifest.json"
_FUTU_OBSERVATION_DISPOSITIONS_PATH = (
    "vendor/futu-observation-disposition-publication-bundle.json"
)
_SOURCE_INDEX_PATH = "sources/research-source-index.json"
_MARKET_EXPECTATIONS_PATH = "market/market-expectations.json"
_RUNTIME_GAP_PATH = "market/runtime-gap-publication-manifest.json"
_FUTU_OPTIONAL_DATA_PATHS = {
    protocol_id: (
        f"vendor/futu-optional-data-{protocol_id}-publication-manifest.json"
    )
    for protocol_id in (3235, 3244, 3245, 3246)
}
_SCORE_V2_PATHS = frozenset(
    f"scoring/score-v2-{lens}-publication-manifest.json"
    for lens in ("graham", "buffett", "munger", "duan_yongping")
)


def _closed_payload_paths(
    profile: str,
    *,
    valuation_context_status: str,
    has_forward_reoi: bool,
    has_comparable_valuation: bool,
) -> set[str]:
    paths = {
        *(f"report/{path}" for path in _EXPECTED_REPORT_ARTIFACTS),
        "report/report-build-receipt.json",
        "research/research-bundle.json",
        "research/run-manifest.json",
        _SOURCE_INDEX_PATH,
    }
    if profile == "research_only":
        if (
            valuation_context_status != "not_applicable"
            or has_forward_reoi
            or has_comparable_valuation
        ):
            raise ResearchPublisherError("research_only path declaration is inconsistent")
        return paths
    if profile != "full_valuation":
        raise ResearchPublisherError("publication profile is not closed")
    paths |= {
        *(f"valuation/{name}" for name in VALUATION_RUN_ARCHIVE_FILENAMES),
        _SYNTHESIS_PATHS["composite_valuation"],
        _OWNER_SCORECARD_PATH,
        *_SCORE_V2_PATHS,
        *_FUTU_OPTIONAL_DATA_PATHS.values(),
        _FUTU_MARKET_EXECUTION_PATH,
        _FUTU_OBSERVATION_DISPOSITIONS_PATH,
    }
    if has_forward_reoi:
        paths.add(_SYNTHESIS_PATHS["forward_reoi"])
    if has_comparable_valuation:
        paths.add(_SYNTHESIS_PATHS["comparable_valuation"])
    if valuation_context_status == "complete":
        if not has_forward_reoi or not has_comparable_valuation:
            raise ResearchPublisherError("complete publication lacks three panels")
        paths.update((_FUTU_SESSION_PATH, _MARKET_EXPECTATIONS_PATH))
    elif valuation_context_status == "post_context_not_run":
        paths.update((_FUTU_PARTIAL_SESSION_PATH, _RUNTIME_GAP_PATH))
    else:
        raise ResearchPublisherError("full valuation context status is not closed")
    return paths


class ResearchPublisherError(ValueError):
    """A package is unsafe, non-canonical, unbound, or not publishable."""


class PublicationManifest(Mapping[str, object]):
    """Exact root manifest for one closed local publication package."""

    __slots__ = ("_payload",)

    def __init__(self, payload: Mapping[str, object]) -> None:
        frozen = freeze(payload)
        raw = to_json_value(frozen)
        if not isinstance(raw, dict):
            raise ResearchPublisherError("publication manifest must be an object")
        try:
            _validate_parallel_schema("publication-manifest", raw)
        except ResearchReportError as exc:
            raise ResearchPublisherError("publication manifest schema is invalid") from exc
        supplied = raw.pop("manifest_fingerprint", None)
        if supplied != canonical_sha256(raw):
            raise ResearchPublisherError("publication manifest fingerprint does not replay")
        identity = {
            "profile": raw["profile"],
            "valuation_context_status": raw["valuation_context_status"],
            "effective_recommendation": raw["effective_recommendation"],
            "frozen_score_recommendation": raw["frozen_score_recommendation"],
            "issuer_id": raw["issuer_id"],
            "data_cutoff_date": raw["data_cutoff_date"],
            "report_build_receipt_fingerprint": raw["report_build_receipt_fingerprint"],
            "report_content_fingerprint": raw["report_content_fingerprint"],
            "research_bundle_fingerprint": raw["research_bundle_fingerprint"],
            "research_source_index_fingerprint": raw["research_source_index_fingerprint"],
            "valuation_archive_fingerprint": raw["valuation_archive_fingerprint"],
            "futu_session_evidence_fingerprint": raw["futu_session_evidence_fingerprint"],
            "futu_session_publication_manifest_fingerprint": raw[
                "futu_session_publication_manifest_fingerprint"
            ],
            "futu_market_execution_evidence_fingerprint": raw[
                "futu_market_execution_evidence_fingerprint"
            ],
            "futu_peer_evidence_set_fingerprint": raw["futu_peer_evidence_set_fingerprint"],
            "futu_partial_session_evidence_fingerprint": raw[
                "futu_partial_session_evidence_fingerprint"
            ],
            "futu_partial_session_publication_manifest_fingerprint": raw[
                "futu_partial_session_publication_manifest_fingerprint"
            ],
            "futu_optional_data_disposition_fingerprints": raw[
                "futu_optional_data_disposition_fingerprints"
            ],
            "futu_optional_data_disposition_publication_manifest_fingerprints": raw[
                "futu_optional_data_disposition_publication_manifest_fingerprints"
            ],
            "forward_reoi_fingerprint": raw["forward_reoi_fingerprint"],
            "comparable_valuation_fingerprint": raw["comparable_valuation_fingerprint"],
            "composite_valuation_fingerprint": raw["composite_valuation_fingerprint"],
            "score_v2_fingerprints": raw["score_v2_fingerprints"],
            "owner_scorecard_fingerprint": raw["owner_scorecard_fingerprint"],
            "forward_reoi_publication_manifest_fingerprint": raw[
                "forward_reoi_publication_manifest_fingerprint"
            ],
            "comparable_valuation_publication_manifest_fingerprint": raw[
                "comparable_valuation_publication_manifest_fingerprint"
            ],
            "composite_valuation_publication_manifest_fingerprint": raw[
                "composite_valuation_publication_manifest_fingerprint"
            ],
            "score_v2_publication_manifest_fingerprints": raw[
                "score_v2_publication_manifest_fingerprints"
            ],
            "owner_scorecard_publication_manifest_fingerprint": raw[
                "owner_scorecard_publication_manifest_fingerprint"
            ],
            "market_expectations_fingerprint": raw["market_expectations_fingerprint"],
            "market_expectations_publication_manifest_fingerprint": raw[
                "market_expectations_publication_manifest_fingerprint"
            ],
            "runtime_gap_fingerprint": raw["runtime_gap_fingerprint"],
            "runtime_gap_publication_manifest_fingerprint": raw[
                "runtime_gap_publication_manifest_fingerprint"
            ],
            "payload_members": raw["payload_members"],
        }
        expected_id = f"research-publication:{raw['issuer_id']}:{canonical_sha256(identity)[:24]}"
        if raw["publication_id"] != expected_id:
            raise ResearchPublisherError("publication ID does not replay its exact inputs")
        object.__setattr__(self, "_payload", frozen)

    def __getitem__(self, key: str) -> object:
        return self._payload[key]

    def __iter__(self):
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("PublicationManifest is immutable")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Mapping) and to_json_value(self) == to_json_value(other)

    @property
    def fingerprint(self) -> str:
        return str(self._payload["manifest_fingerprint"])


class PublishedPackageReceipt(Mapping[str, object]):
    """Exact final receipt binding a package to its root manifest bytes."""

    __slots__ = ("_payload",)

    def __init__(self, payload: Mapping[str, object]) -> None:
        frozen = freeze(payload)
        raw = to_json_value(frozen)
        if not isinstance(raw, dict):
            raise ResearchPublisherError("published package receipt must be an object")
        try:
            _validate_parallel_schema("published-package", raw)
        except ResearchReportError as exc:
            raise ResearchPublisherError("published package receipt schema is invalid") from exc
        supplied = raw.pop("package_fingerprint", None)
        if supplied != canonical_sha256(raw):
            raise ResearchPublisherError("published package receipt fingerprint does not replay")
        object.__setattr__(self, "_payload", frozen)

    def __getitem__(self, key: str) -> object:
        return self._payload[key]

    def __iter__(self):
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("PublishedPackageReceipt is immutable")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Mapping) and to_json_value(self) == to_json_value(other)

    @property
    def fingerprint(self) -> str:
        return str(self._payload["package_fingerprint"])


@dataclass(frozen=True, slots=True)
class PublishedResearchPackage:
    output_directory: Path
    profile: str
    report: ReportBuildResult
    research: ResearchBundleBuildResult
    valuation: ValuationRunArchive | None
    research_source_manifest: ResearchSourceIndexPublicationManifest
    futu_market_execution_manifest: FutuMarketExecutionPublicationManifest | None
    futu_observation_disposition_bundle: FutuObservationDispositionPublicationBundle | None
    futu_session_manifest: FutuSessionPublicationManifest | None
    futu_partial_session_manifest: FutuPartialSessionPublicationManifest | None
    futu_optional_data_disposition_manifests: tuple[
        FutuOptionalDataDispositionPublicationManifest, ...
    ]
    forward_reoi_manifest: ForwardReOIValuationPublicationManifest | None
    comparable_valuation_manifest: ComparableValuationPublicationManifest | None
    composite_valuation_manifest: CompositeValuationPublicationManifest | None
    score_v2_manifests: tuple[ScoreV2PublicationManifest, ...]
    owner_scorecard_manifest: OwnerScorecardPublicationManifest | None
    market_expectations_manifest: MarketExpectationsPublicationManifest | None
    runtime_gap_manifest: RuntimeGapPublicationManifest | None
    publication_manifest: PublicationManifest
    package_receipt: PublishedPackageReceipt
    file_sha256: FrozenMap
    file_bytes: FrozenMap

    def __post_init__(self) -> None:
        if type(self.report) is not ReportBuildResult:
            raise ResearchPublisherError("published report has the wrong typed result")
        if type(self.research) is not ResearchBundleBuildResult:
            raise ResearchPublisherError("published research has the wrong typed result")
        if type(self.publication_manifest) is not PublicationManifest:
            raise ResearchPublisherError("published package lacks an exact PublicationManifest")
        expected_effective, expected_frozen = _publication_recommendations(self.report)
        if (
            self.publication_manifest["effective_recommendation"] != expected_effective
            or self.publication_manifest["frozen_score_recommendation"]
            != expected_frozen
        ):
            raise ResearchPublisherError(
                "publication manifest rebinds its report recommendation authority"
            )
        if type(self.package_receipt) is not PublishedPackageReceipt:
            raise ResearchPublisherError("published package lacks an exact package receipt")
        if type(self.research_source_manifest) is not ResearchSourceIndexPublicationManifest:
            raise ResearchPublisherError("published source index has the wrong exact type")
        if self.valuation is not None and type(self.valuation) is not ValuationRunArchive:
            raise ResearchPublisherError("published valuation has the wrong typed result")
        if (
            self.futu_market_execution_manifest is not None
            and type(self.futu_market_execution_manifest)
            is not FutuMarketExecutionPublicationManifest
        ):
            raise ResearchPublisherError("published Futu market manifest has the wrong type")
        if (
            self.futu_observation_disposition_bundle is not None
            and type(self.futu_observation_disposition_bundle)
            is not FutuObservationDispositionPublicationBundle
        ):
            raise ResearchPublisherError(
                "published Futu disposition bundle has the wrong type"
            )
        if (
            self.futu_session_manifest is not None
            and type(self.futu_session_manifest) is not FutuSessionPublicationManifest
        ):
            raise ResearchPublisherError("published Futu manifest has the wrong exact type")
        if (
            self.futu_partial_session_manifest is not None
            and type(self.futu_partial_session_manifest)
            is not FutuPartialSessionPublicationManifest
        ):
            raise ResearchPublisherError("published partial Futu manifest has the wrong type")
        if any(
            type(item) is not FutuOptionalDataDispositionPublicationManifest
            for item in self.futu_optional_data_disposition_manifests
        ):
            raise ResearchPublisherError("published optional Futu manifests have the wrong type")
        if (
            self.forward_reoi_manifest is not None
            and type(self.forward_reoi_manifest) is not ForwardReOIValuationPublicationManifest
        ):
            raise ResearchPublisherError("published forward ReOI manifest has the wrong type")
        if (
            self.comparable_valuation_manifest is not None
            and type(self.comparable_valuation_manifest)
            is not ComparableValuationPublicationManifest
        ):
            raise ResearchPublisherError("published comparable manifest has the wrong type")
        if (
            self.composite_valuation_manifest is not None
            and type(self.composite_valuation_manifest) is not CompositeValuationPublicationManifest
        ):
            raise ResearchPublisherError("published composite manifest has the wrong type")
        if any(type(item) is not ScoreV2PublicationManifest for item in self.score_v2_manifests):
            raise ResearchPublisherError("published Score 2.0 manifests have the wrong type")
        if (
            self.owner_scorecard_manifest is not None
            and type(self.owner_scorecard_manifest) is not OwnerScorecardPublicationManifest
        ):
            raise ResearchPublisherError("published scorecard manifest has the wrong type")
        if (
            self.market_expectations_manifest is not None
            and type(self.market_expectations_manifest) is not MarketExpectationsPublicationManifest
        ):
            raise ResearchPublisherError("published market expectations have the wrong exact type")
        if (
            self.runtime_gap_manifest is not None
            and type(self.runtime_gap_manifest) is not RuntimeGapPublicationManifest
        ):
            raise ResearchPublisherError("published runtime gap has the wrong exact type")
        if self.profile == "full_valuation" and (
            (self.futu_session_manifest is None) == (self.futu_partial_session_manifest is None)
        ):
            raise ResearchPublisherError("published full valuation has mixed Futu contexts")
        if self.profile == "full_valuation":
            if (
                self.futu_market_execution_manifest is None
                or self.futu_observation_disposition_bundle is None
            ):
                raise ResearchPublisherError(
                    "published full valuation lacks its Futu receipt closure"
                )
            try:
                validate_futu_observation_disposition_publication_bundle(
                    self.futu_observation_disposition_bundle,
                    market_manifest=self.futu_market_execution_manifest,
                )
            except ValueError as exc:
                raise ResearchPublisherError(
                    "published Futu disposition closure does not replay"
                ) from exc
            if tuple(
                item.to_dict()["protocol_id"]
                for item in self.futu_optional_data_disposition_manifests
            ) != (3235, 3244, 3245, 3246):
                raise ResearchPublisherError(
                    "published full valuation lacks optional Futu dispositions"
                )
            if self.futu_session_manifest is not None and (
                self.market_expectations_manifest is None or self.runtime_gap_manifest is not None
            ):
                raise ResearchPublisherError("published complete package has mixed gap context")
            if self.futu_partial_session_manifest is not None and (
                self.market_expectations_manifest is not None or self.runtime_gap_manifest is None
            ):
                raise ResearchPublisherError("published partial package exposes post context")
        elif self.profile == "research_only":
            if (
                any(
                    item is not None
                    for item in (
                        self.valuation,
                        self.futu_market_execution_manifest,
                        self.futu_observation_disposition_bundle,
                        self.futu_session_manifest,
                        self.futu_partial_session_manifest,
                        self.forward_reoi_manifest,
                        self.comparable_valuation_manifest,
                        self.composite_valuation_manifest,
                        self.owner_scorecard_manifest,
                        self.market_expectations_manifest,
                        self.runtime_gap_manifest,
                    )
                )
                or self.score_v2_manifests
                or self.futu_optional_data_disposition_manifests
            ):
                raise ResearchPublisherError(
                    "research_only package retains valuation or market data"
                )
        else:
            raise ResearchPublisherError("published package profile is not closed")
        source = Path(self.output_directory).absolute()
        captured = dict(self.file_bytes)
        hashes = dict(self.file_sha256)
        if (
            not captured
            or set(captured) != set(hashes)
            or any(
                type(path) is not str or type(content) is not bytes
                for path, content in captured.items()
            )
            or {path: _sha256(content) for path, content in captured.items()} != hashes
        ):
            raise ResearchPublisherError("published package byte snapshot does not replay")
        disk_files, disk_directories = _read_tree(source)
        if disk_files != captured or disk_directories != _directory_names(captured):
            raise ResearchPublisherError(
                "published package path differs from its immutable byte snapshot"
            )
        object.__setattr__(self, "output_directory", source)
        object.__setattr__(self, "file_sha256", freeze(hashes))
        object.__setattr__(self, "file_bytes", freeze(captured))

    @property
    def fingerprint(self) -> str:
        return self.package_receipt.fingerprint


PublishedPackage = PublishedResearchPackage


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_file(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ResearchPublisherError(f"publication JSON repeats key {key!r}")
        output[key] = value
    return output


def _json_object(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResearchPublisherError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ResearchPublisherError(f"{label} must be a JSON object")
    return value


def _validate_path(value: str) -> tuple[str, ...]:
    if type(value) is not str or not value or "\\" in value:
        raise ResearchPublisherError(f"unsafe publication member path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ResearchPublisherError(f"unsafe publication member path: {value!r}")
    for part in path.parts:
        if not part.isascii() or not all(
            character.islower() or character.isdigit() or character in "-_." for character in part
        ):
            raise ResearchPublisherError(f"unsafe publication member path: {value!r}")
    return path.parts


def _member_limit(path: str) -> int:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".pdf":
        return PUBLISH_PDF_MAX_BYTES
    if suffix in _IMAGE_SUFFIXES:
        return PUBLISH_IMAGE_MAX_BYTES
    return PUBLISH_OTHER_MAX_BYTES


def _directory_names(paths: Mapping[str, bytes]) -> set[str]:
    directories: set[str] = set()
    for path in paths:
        parts = _validate_path(path)
        for length in range(1, len(parts)):
            directories.add("/".join(parts[:length]))
    return directories


def _validate_limits(contents: Mapping[str, bytes]) -> None:
    directories = _directory_names(contents)
    if len(contents) + len(directories) > PUBLISH_MAX_MEMBERS:
        raise ResearchPublisherError("publication exceeds the 512-member limit")
    total = 0
    for path, content in contents.items():
        if type(content) is not bytes or not content:
            raise ResearchPublisherError(f"publication member is empty or untyped: {path}")
        if len(content) > _member_limit(path):
            raise ResearchPublisherError(f"publication member exceeds its byte limit: {path}")
        total += len(content)
        if total > PUBLISH_MAX_BYTES:
            raise ResearchPublisherError("publication exceeds the 512 MiB cumulative limit")


def _replay_fingerprint(payload: Mapping[str, object], field: str, label: str) -> None:
    raw = to_json_value(payload)
    supplied = raw.pop(field, None)
    if type(supplied) is not str or len(supplied) != 64 or supplied != canonical_sha256(raw):
        raise ResearchPublisherError(f"{label} fingerprint does not replay")


def _verify_research_input(research: ReloadedResearchInput) -> ResearchBundleBuildResult:
    if type(research) is not ReloadedResearchInput:
        raise ResearchPublisherError("publisher requires a strictly reloaded research input")
    result = research.result
    if type(result) is not ResearchBundleBuildResult:
        raise ResearchPublisherError("research input lacks an exact typed result")
    expected = {
        "research-bundle.json": _canonical_file(result.bundle.to_dict()),
        "run-manifest.json": _canonical_file(result.run_manifest.to_dict()),
    }
    captured = dict(research.file_bytes)
    if (
        captured != expected
        or {name: _sha256(content) for name, content in captured.items()}
        != dict(research.file_sha256)
    ):
        raise ResearchPublisherError("captured research bytes do not replay typed inputs")
    bundle = result.bundle
    manifest = result.run_manifest
    if (
        bundle.bundle_fingerprint != bundle_payload_sha256(bundle.to_dict())
        or bundle.run_id != manifest.run_id
        or bundle.issuer_id != manifest.issuer_id
        or bundle.data_cutoff_date != manifest.data_cutoff_date
        or bundle.component_lock_sha256 != manifest.component_lock_sha256
        or manifest.output_artifact_hashes.get("research-bundle.json") != bundle.bundle_fingerprint
    ):
        raise ResearchPublisherError("research input identities do not replay")
    return result


def _verify_valuation_input(
    valuation: ReloadedValuationInput,
    *,
    component_lock_path: Path | None,
) -> ValuationRunArchive:
    if type(valuation) is not ReloadedValuationInput:
        raise ResearchPublisherError("publisher requires a strictly reloaded valuation input")
    _ = component_lock_path
    replay = valuation.archive
    captured = dict(valuation.file_bytes)
    expected = _valuation_archive_file_bytes(replay)
    hashes = {name: _sha256(content) for name, content in captured.items()}
    if (
        set(captured) != set(VALUATION_RUN_ARCHIVE_FILENAMES)
        or captured != expected
        or hashes != dict(valuation.file_sha256)
        or hashes != dict(replay.file_sha256)
        or valuation.source_directory != replay.output_directory
    ):
        raise ResearchPublisherError("valuation captured bytes differ from strict replay")
    return replay


def _verify_report_build(
    report: ReportBuildResult,
    *,
    allow_injected_test_renderer: bool = False,
    futu_verifier: SignatureVerifier | None = None,
) -> None:
    if type(report) is not ReportBuildResult:
        raise ResearchPublisherError("publisher requires an exact ReportBuildResult")
    receipt = to_json_value(report.receipt)
    try:
        _validate_parallel_schema("report-build-receipt", receipt)
    except ResearchReportError as exc:
        raise ResearchPublisherError("report build receipt is invalid") from exc
    _replay_fingerprint(receipt, "receipt_fingerprint", "report build receipt")
    if (
        report.profile != receipt["profile"]
        or report.issuer_id != receipt["issuer_id"]
        or report.data_cutoff_date != receipt["data_cutoff_date"]
    ):
        raise ResearchPublisherError("report result differs from its receipt identity")
    renderer = receipt["renderer"]
    toolchain_authority = None
    if not isinstance(renderer, dict) or (
        renderer.get("engine") == "injected-test-renderer" and not allow_injected_test_renderer
    ):
        raise ResearchPublisherError("production publication requires a real LaTeX renderer")
    if renderer.get("engine") == "tectonic":
        try:
            toolchain_authority = load_report_toolchain_authority()
        except ResearchReportError as exc:
            raise ResearchPublisherError(
                "packaged report toolchain authority cannot be replayed"
            ) from exc
        if (
            renderer.get("toolchain_authority_id") != toolchain_authority.authority_id
            or renderer.get("toolchain_authority_fingerprint") != toolchain_authority.fingerprint
            or renderer.get("renderer_version") != toolchain_authority["renderer"]["version"]
            or renderer.get("renderer_id")
            != (
                f"tectonic:sha256:{toolchain_authority['renderer']['sha256']}:"
                f"cache-sha256:{toolchain_authority['offline_bundle']['tree_sha256']}:"
                f"authority:{toolchain_authority.fingerprint}"
            )
        ):
            raise ResearchPublisherError(
                "report renderer is not bound to the packaged toolchain authority"
            )
    elif (
        renderer.get("engine") != "injected-test-renderer"
        or renderer.get("toolchain_authority_id") is not None
        or renderer.get("toolchain_authority_fingerprint") is not None
    ):
        raise ResearchPublisherError("report renderer provenance is not closed")
    artifacts = {item.path: item for item in report.artifacts}
    if set(artifacts) != _EXPECTED_REPORT_ARTIFACTS:
        raise ResearchPublisherError("report build has an unexpected artifact set")
    declared = receipt["artifacts"]
    if not isinstance(declared, list):
        raise ResearchPublisherError("report artifact receipt is malformed")
    expected_entries = [
        {
            "path": item.path,
            "media_type": item.media_type,
            "size": len(item.content),
            "sha256": item.sha256,
        }
        for item in sorted(report.artifacts, key=lambda artifact: artifact.path)
    ]
    if declared != expected_entries:
        raise ResearchPublisherError("report artifacts do not replay their receipt")
    extracted = artifacts["report-extracted.txt"].content
    qa = receipt["qa"]
    if not isinstance(qa, dict) or qa["extracted_text_sha256"] != _sha256(extracted):
        raise ResearchPublisherError("report extracted text does not replay PDF QA")
    if not artifacts["report.pdf"].content.startswith(b"%PDF-"):
        raise ResearchPublisherError("report PDF header is invalid")
    replayed_pdf_qa = None
    if renderer.get("engine") == "tectonic":
        assert toolchain_authority is not None
        try:
            replayed_pdf_qa = replay_report_pdf_qa(
                artifacts["report.pdf"].content,
                authority=toolchain_authority,
            )
        except ResearchReportError as exc:
            raise ResearchPublisherError(
                "report PDF does not independently replay its QA evidence"
            ) from exc
        if (
            extracted != replayed_pdf_qa.extracted_text.encode("utf-8")
            or qa.get("page_count") != replayed_pdf_qa.page_count
            or qa.get("rendered_page_count") != replayed_pdf_qa.page_count
            or qa.get("extracted_text_sha256") != _sha256(extracted)
            or qa.get("page_text_character_counts")
            != list(replayed_pdf_qa.page_text_character_counts)
            or qa.get("rendered_page_sha256")
            != list(replayed_pdf_qa.rendered_page_sha256)
            or qa.get("page_non_white_ratios")
            != list(replayed_pdf_qa.page_non_white_ratios)
            or qa.get("pdf_text_backend")
            != to_json_value(toolchain_authority["pdf_text_backend"])
            or qa.get("pdf_render_backend")
            != to_json_value(toolchain_authority["pdf_render_backend"])
        ):
            raise ResearchPublisherError(
                "report PDF bytes do not independently replay the retained all-page QA evidence"
            )
    data = _json_object(artifacts["report-data.json"].content, "report data")
    if artifacts["report-data.json"].content != _canonical_file(data):
        raise ResearchPublisherError("report data JSON is not canonical")
    (
        report_spec,
        content,
        research_source_manifest,
        legacy_scores,
        futu_session_manifest,
        futu_partial_session_manifest,
        futu_optional_data_disposition_manifests,
        forward_reoi,
        comparable_valuation,
        composite_valuation,
        score_v2,
        owner_scorecard,
        market_expectations_manifest,
        runtime_gap_manifest,
    ) = _typed_report_inputs(data)
    if replayed_pdf_qa is not None:
        try:
            replayed_anti_padding = _validate_render_result(
                PdfRenderResult(
                    pdf_bytes=artifacts["report.pdf"].content,
                    page_count=replayed_pdf_qa.page_count,
                    extracted_text=replayed_pdf_qa.extracted_text,
                    rendered_page_count=replayed_pdf_qa.page_count,
                    renderer_id=str(renderer["renderer_id"]),
                    renderer_version=str(renderer["renderer_version"]),
                    engine="tectonic",
                    toolchain_authority_id=str(renderer["toolchain_authority_id"]),
                    toolchain_authority_fingerprint=str(
                        renderer["toolchain_authority_fingerprint"]
                    ),
                    page_text_character_counts=(
                        replayed_pdf_qa.page_text_character_counts
                    ),
                    rendered_page_sha256=replayed_pdf_qa.rendered_page_sha256,
                    page_non_white_ratios=replayed_pdf_qa.page_non_white_ratios,
                ),
                report_spec,
                content,
            )
        except ResearchReportError as exc:
            raise ResearchPublisherError(
                "report PDF fails independent semantic and anti-padding QA"
            ) from exc
        if qa.get("anti_padding") != replayed_anti_padding:
            raise ResearchPublisherError(
                "report PDF anti-padding receipt does not independently replay"
            )
    if (
        report_spec.fingerprint != receipt["report_spec_fingerprint"]
        or content.fingerprint != receipt["report_content_fingerprint"]
        or report.content != content
        or artifacts["report-content.json"].content != _canonical_file(content.to_dict())
        or content["profile"] != report.profile
        or content["issuer_id"] != report.issuer_id
        or content["data_cutoff_date"] != report.data_cutoff_date
        or content["research_source_index_fingerprint"] != research_source_manifest.fingerprint
        or content["valuation_archive_fingerprint"] != receipt["valuation_archive_fingerprint"]
        or report.research_source_manifest != research_source_manifest
        or report.legacy_scores != legacy_scores
        or report.futu_session_manifest != futu_session_manifest
        or report.futu_partial_session_manifest != futu_partial_session_manifest
        or report.futu_optional_data_disposition_manifests
        != futu_optional_data_disposition_manifests
        or report.forward_reoi_manifest != forward_reoi
        or report.comparable_valuation_manifest != comparable_valuation
        or report.composite_valuation_manifest != composite_valuation
        or report.score_v2_manifests != score_v2
        or report.owner_scorecard_manifest != owner_scorecard
        or report.runtime_gap_manifest != runtime_gap_manifest
        or sorted(score.fingerprint for score in legacy_scores) != receipt["score_fingerprints"]
        or (None if futu_session_manifest is None else futu_session_manifest.session_fingerprint)
        != receipt["futu_session_evidence_fingerprint"]
        or (None if futu_session_manifest is None else futu_session_manifest.fingerprint)
        != receipt["futu_session_publication_manifest_fingerprint"]
        or (
            None
            if futu_partial_session_manifest is None
            else futu_partial_session_manifest.market_execution_evidence["fingerprint"]
        )
        != receipt["futu_market_execution_evidence_fingerprint"]
        or (
            None
            if futu_partial_session_manifest is None
            else futu_partial_session_manifest.peer_evidence_set["fingerprint"]
        )
        != receipt["futu_peer_evidence_set_fingerprint"]
        or (
            None
            if futu_partial_session_manifest is None
            else futu_partial_session_manifest.partial_session_fingerprint
        )
        != receipt["futu_partial_session_evidence_fingerprint"]
        or (
            None
            if futu_partial_session_manifest is None
            else futu_partial_session_manifest.fingerprint
        )
        != receipt["futu_partial_session_publication_manifest_fingerprint"]
        or [item.fingerprint for item in futu_optional_data_disposition_manifests]
        != receipt[
            "futu_optional_data_disposition_publication_manifest_fingerprints"
        ]
        or (
            report.futu_optional_data_dispositions
            and [
                item.fingerprint
                for item in report.futu_optional_data_dispositions
            ]
            != receipt["futu_optional_data_disposition_fingerprints"]
        )
        or (None if forward_reoi is None else forward_reoi.source_fingerprint)
        != receipt["forward_reoi_fingerprint"]
        or (None if comparable_valuation is None else comparable_valuation.source_fingerprint)
        != receipt["comparable_valuation_fingerprint"]
        or (None if composite_valuation is None else composite_valuation.source_fingerprint)
        != receipt["composite_valuation_fingerprint"]
        or sorted(item.source_fingerprint for item in score_v2) != receipt["score_v2_fingerprints"]
        or (None if owner_scorecard is None else owner_scorecard.source_fingerprint)
        != receipt["owner_scorecard_fingerprint"]
        or (None if forward_reoi is None else forward_reoi.fingerprint)
        != receipt["forward_reoi_publication_manifest_fingerprint"]
        or (None if comparable_valuation is None else comparable_valuation.fingerprint)
        != receipt["comparable_valuation_publication_manifest_fingerprint"]
        or (None if composite_valuation is None else composite_valuation.fingerprint)
        != receipt["composite_valuation_publication_manifest_fingerprint"]
        or sorted(item.fingerprint for item in score_v2)
        != receipt["score_v2_publication_manifest_fingerprints"]
        or (None if owner_scorecard is None else owner_scorecard.fingerprint)
        != receipt["owner_scorecard_publication_manifest_fingerprint"]
        or research_source_manifest.fingerprint
        != receipt["research_source_publication_manifest_fingerprint"]
        or receipt["research_source_index_fingerprint"] != research_source_manifest.fingerprint
        or (
            None
            if market_expectations_manifest is None
            else market_expectations_manifest.fingerprint
        )
        != receipt["market_expectations_fingerprint"]
        or (
            None
            if market_expectations_manifest is None
            else market_expectations_manifest.fingerprint
        )
        != receipt["market_expectations_publication_manifest_fingerprint"]
        or (
            None
            if runtime_gap_manifest is None
            else runtime_gap_manifest.source_receipt_fingerprint
        )
        != receipt["runtime_gap_fingerprint"]
        or (None if runtime_gap_manifest is None else runtime_gap_manifest.fingerprint)
        != receipt["runtime_gap_publication_manifest_fingerprint"]
        or sorted(str(item["section_id"]) for item in content["sections"])
        != receipt["qa"]["required_section_ids"]
        or artifacts["report-table.tex"].content != _content_tables_tex(content).encode("utf-8")
        or artifacts["report-chart.tex"].content != _content_charts_tex(content).encode("utf-8")
        or artifacts["report-charts.svg"].content != _content_charts_svg(content)
        or artifacts["report-data.tex"].content != _report_data_tex(content).encode("utf-8")
        or artifacts["report.md"].content != _report_markdown(data).encode("utf-8")
    ):
        raise ResearchPublisherError(
            "report specification, typed downstream results, or generated views drifted"
        )
    template, font_manifest = _asset_contents()
    if artifacts["report.tex"].content != template.encode("utf-8") or artifacts[
        "font-manifest.json"
    ].content != _canonical_file(font_manifest):
        raise ResearchPublisherError("report template or font policy differs from trusted assets")
    identity = {
        "profile": report.profile,
        "valuation_context_status": receipt["valuation_context_status"],
        "issuer_id": report.issuer_id,
        "data_cutoff_date": report.data_cutoff_date,
        "research_bundle_fingerprint": receipt["research_bundle_fingerprint"],
        "research_source_index_fingerprint": receipt["research_source_index_fingerprint"],
        "research_source_publication_manifest_fingerprint": receipt[
            "research_source_publication_manifest_fingerprint"
        ],
        "valuation_archive_fingerprint": receipt["valuation_archive_fingerprint"],
        "futu_session_evidence_fingerprint": receipt["futu_session_evidence_fingerprint"],
        "futu_session_publication_manifest_fingerprint": receipt[
            "futu_session_publication_manifest_fingerprint"
        ],
        "futu_market_execution_evidence_fingerprint": receipt[
            "futu_market_execution_evidence_fingerprint"
        ],
        "futu_peer_evidence_set_fingerprint": receipt["futu_peer_evidence_set_fingerprint"],
        "futu_partial_session_evidence_fingerprint": receipt[
            "futu_partial_session_evidence_fingerprint"
        ],
        "futu_partial_session_publication_manifest_fingerprint": receipt[
            "futu_partial_session_publication_manifest_fingerprint"
        ],
        "futu_optional_data_disposition_fingerprints": receipt[
            "futu_optional_data_disposition_fingerprints"
        ],
        "futu_optional_data_disposition_publication_manifest_fingerprints": receipt[
            "futu_optional_data_disposition_publication_manifest_fingerprints"
        ],
        "forward_reoi_fingerprint": receipt["forward_reoi_fingerprint"],
        "comparable_valuation_fingerprint": receipt["comparable_valuation_fingerprint"],
        "composite_valuation_fingerprint": receipt["composite_valuation_fingerprint"],
        "report_spec_fingerprint": report_spec.fingerprint,
        "report_content_fingerprint": content.fingerprint,
        "score_fingerprints": sorted(score.fingerprint for score in legacy_scores),
        "score_v2_fingerprints": sorted(item.source_fingerprint for item in score_v2),
        "owner_scorecard_fingerprint": (
            None if owner_scorecard is None else owner_scorecard.source_fingerprint
        ),
        "forward_reoi_publication_manifest_fingerprint": (
            None if forward_reoi is None else forward_reoi.fingerprint
        ),
        "comparable_valuation_publication_manifest_fingerprint": (
            None if comparable_valuation is None else comparable_valuation.fingerprint
        ),
        "composite_valuation_publication_manifest_fingerprint": (
            None if composite_valuation is None else composite_valuation.fingerprint
        ),
        "score_v2_publication_manifest_fingerprints": sorted(item.fingerprint for item in score_v2),
        "owner_scorecard_publication_manifest_fingerprint": (
            None if owner_scorecard is None else owner_scorecard.fingerprint
        ),
        "market_expectations_fingerprint": receipt["market_expectations_fingerprint"],
        "market_expectations_publication_manifest_fingerprint": receipt[
            "market_expectations_publication_manifest_fingerprint"
        ],
        "runtime_gap_fingerprint": receipt["runtime_gap_fingerprint"],
        "runtime_gap_publication_manifest_fingerprint": receipt[
            "runtime_gap_publication_manifest_fingerprint"
        ],
        "renderer": renderer,
        "artifacts": expected_entries,
    }
    expected_build_id = f"report-build:{report.issuer_id}:{canonical_sha256(identity)[:24]}"
    if receipt["report_build_id"] != expected_build_id:
        raise ResearchPublisherError("report build ID does not replay its exact inputs")
    if futu_session_manifest is not None:
        try:
            validate_futu_session_publication_manifest(
                futu_session_manifest,
                source_session=report.futu_session_evidence,
                verifier=futu_verifier,
            )
        except ValueError as exc:
            raise ResearchPublisherError("report Futu session projection does not replay") from exc
    if futu_partial_session_manifest is not None:
        try:
            validate_futu_partial_session_publication_manifest(futu_partial_session_manifest)
        except ValueError as exc:
            raise ResearchPublisherError(
                "report partial Futu session projection does not replay"
            ) from exc
    if report.profile == "full_valuation":
        assert composite_valuation is not None
        assert owner_scorecard is not None
        valuation_manifest = data["valuation_manifest"]
        research_bundle = data["research_bundle"]
        try:
            _validate_downstream_publication_chain(
                research_bundle_fingerprint=research_bundle["bundle_fingerprint"],
                contract_graph_fingerprint=research_source_manifest.to_dict()[
                    "contract_graph_fingerprint"
                ],
                valuation_archive_fingerprint=receipt["valuation_archive_fingerprint"],
                valuation_result_sha256=valuation_manifest["valuation_result_sha256"],
                futu_session_manifest=futu_session_manifest,
                futu_partial_session_manifest=futu_partial_session_manifest,
                forward_manifest=forward_reoi,
                comparable_manifest=comparable_valuation,
                composite_manifest=composite_valuation,
                score_manifests=score_v2,
                scorecard_manifest=owner_scorecard,
                market_manifest=market_expectations_manifest,
                runtime_gap_manifest=runtime_gap_manifest,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ResearchPublisherError(
                "report downstream publication chain does not replay"
            ) from exc


def _typed_report_inputs(
    data: Mapping[str, Any],
) -> tuple[
    ReportSpec,
    ResearchReportContent,
    ResearchSourceIndexPublicationManifest,
    tuple[Score, ...],
    FutuSessionPublicationManifest | None,
    FutuPartialSessionPublicationManifest | None,
    tuple[FutuOptionalDataDispositionPublicationManifest, ...],
    ForwardReOIValuationPublicationManifest | None,
    ComparableValuationPublicationManifest | None,
    CompositeValuationPublicationManifest | None,
    tuple[ScoreV2PublicationManifest, ...],
    OwnerScorecardPublicationManifest | None,
    MarketExpectationsPublicationManifest | None,
    RuntimeGapPublicationManifest | None,
]:
    base_fields = {
        "schema_version",
        "artifact_type",
        "profile",
        "issuer_id",
        "data_cutoff_date",
        "research_bundle",
        "research_run_manifest",
        "research_source_index",
        "report_spec",
        "report_content",
        "legacy_scores",
    }
    valuation_fields = {
        "valuation_manifest",
        "valuation_result",
        "futu_session_publication_manifest",
        "futu_partial_session_publication_manifest",
        "futu_optional_data_disposition_publication_manifests",
        "forward_reoi_publication_manifest",
        "comparable_valuation_publication_manifest",
        "composite_valuation_publication_manifest",
        "score_v2_publication_manifests",
        "owner_scorecard_publication_manifest",
        "market_expectations",
        "runtime_gap_publication_manifest",
    }
    profile = data.get("profile")
    expected_fields = base_fields if profile == "research_only" else base_fields | valuation_fields
    if profile not in {"research_only", "full_valuation"} or set(data) != expected_fields:
        raise ResearchPublisherError("report data fields do not match its closed profile")
    try:
        report_spec = contract_from_dict("report-spec", data["report_spec"])
        content = ResearchReportContent.from_dict(data["report_content"])
        research_source_manifest = ResearchSourceIndexPublicationManifest.from_dict(
            data["research_source_index"]
        )
        legacy_scores = tuple(contract_from_dict("score", item) for item in data["legacy_scores"])
        if profile == "full_valuation":
            futu_session_manifest = (
                None
                if data["futu_session_publication_manifest"] is None
                else FutuSessionPublicationManifest.from_dict(
                    data["futu_session_publication_manifest"]
                )
            )
            futu_partial_session_manifest = (
                None
                if data["futu_partial_session_publication_manifest"] is None
                else FutuPartialSessionPublicationManifest.from_dict(
                    data["futu_partial_session_publication_manifest"]
                )
            )
            futu_optional_data_disposition_manifests = tuple(
                FutuOptionalDataDispositionPublicationManifest.from_dict(item)
                for item in data[
                    "futu_optional_data_disposition_publication_manifests"
                ]
            )
            forward_reoi = (
                None
                if data["forward_reoi_publication_manifest"] is None
                else ForwardReOIValuationPublicationManifest.from_dict(
                    data["forward_reoi_publication_manifest"]
                )
            )
            comparable_valuation = (
                None
                if data["comparable_valuation_publication_manifest"] is None
                else ComparableValuationPublicationManifest.from_dict(
                    data["comparable_valuation_publication_manifest"]
                )
            )
            composite_valuation = CompositeValuationPublicationManifest.from_dict(
                data["composite_valuation_publication_manifest"]
            )
            score_v2 = tuple(
                ScoreV2PublicationManifest.from_dict(item)
                for item in data["score_v2_publication_manifests"]
            )
            owner_scorecard = OwnerScorecardPublicationManifest.from_dict(
                data["owner_scorecard_publication_manifest"]
            )
            market_expectations_manifest = (
                None
                if data["market_expectations"] is None
                else MarketExpectationsPublicationManifest.from_dict(data["market_expectations"])
            )
            runtime_gap_manifest = (
                None
                if data["runtime_gap_publication_manifest"] is None
                else RuntimeGapPublicationManifest.from_dict(
                    data["runtime_gap_publication_manifest"]
                )
            )
        else:
            futu_session_manifest = None
            futu_partial_session_manifest = None
            futu_optional_data_disposition_manifests = ()
            forward_reoi = None
            comparable_valuation = None
            composite_valuation = None
            score_v2 = ()
            owner_scorecard = None
            market_expectations_manifest = None
            runtime_gap_manifest = None
    except (JSONSchemaValidationError, KeyError, TypeError, ValueError) as exc:
        raise ResearchPublisherError("report data lacks exact typed inputs") from exc
    if type(report_spec) is not ReportSpec or any(
        type(score) is not Score for score in legacy_scores
    ):
        raise ResearchPublisherError("report data contract types are invalid")
    return (
        report_spec,
        content,
        research_source_manifest,
        legacy_scores,
        futu_session_manifest,
        futu_partial_session_manifest,
        futu_optional_data_disposition_manifests,
        forward_reoi,
        comparable_valuation,
        composite_valuation,
        score_v2,
        owner_scorecard,
        market_expectations_manifest,
        runtime_gap_manifest,
    )


@retained_authority_replay_scope
def _verify_cross_bindings(
    report: ReportBuildResult,
    research: ResearchBundleBuildResult,
    valuation: ValuationRunArchive | None,
    *,
    futu_verifier: SignatureVerifier | None = None,
    manifest_only: bool = False,
) -> None:
    receipt = report.receipt
    bundle = research.bundle
    valuation_fingerprint = None if valuation is None else valuation.fingerprint
    valuation_id = None if valuation is None else str(valuation.manifest["archive_id"])
    forward_fingerprint = (
        None
        if report.forward_reoi_manifest is None
        else report.forward_reoi_manifest.source_fingerprint
    )
    comparable_fingerprint = (
        None
        if report.comparable_valuation_manifest is None
        else report.comparable_valuation_manifest.source_fingerprint
    )
    composite_fingerprint = (
        None
        if report.composite_valuation_manifest is None
        else report.composite_valuation_manifest.source_fingerprint
    )
    scorecard_fingerprint = (
        None
        if report.owner_scorecard_manifest is None
        else report.owner_scorecard_manifest.source_fingerprint
    )
    futu_fingerprint = (
        None
        if report.futu_session_manifest is None
        else report.futu_session_manifest.session_fingerprint
    )
    futu_manifest_fingerprint = (
        None if report.futu_session_manifest is None else report.futu_session_manifest.fingerprint
    )
    partial_futu = report.futu_partial_session_manifest
    partial_market_fingerprint = (
        None if partial_futu is None else str(partial_futu.market_execution_evidence["fingerprint"])
    )
    partial_peer_fingerprint = (
        None if partial_futu is None else str(partial_futu.peer_evidence_set["fingerprint"])
    )
    if (
        receipt["issuer_id"] != bundle.issuer_id
        or receipt["data_cutoff_date"] != bundle.data_cutoff_date
        or receipt["research_bundle_id"] != bundle.bundle_id
        or receipt["research_bundle_fingerprint"] != bundle.bundle_fingerprint
        or receipt["research_run_id"] != bundle.run_id
        or receipt["report_content_fingerprint"] != report.content.fingerprint
        or report.content["research_source_index_fingerprint"]
        != report.research_source_manifest.fingerprint
        or report.content["valuation_archive_fingerprint"] != valuation_fingerprint
        or receipt["research_source_index_fingerprint"]
        != report.research_source_manifest.fingerprint
        or receipt["research_source_publication_manifest_fingerprint"]
        != report.research_source_manifest.fingerprint
        or receipt["valuation_archive_id"] != valuation_id
        or receipt["valuation_archive_fingerprint"] != valuation_fingerprint
        or receipt["futu_session_evidence_fingerprint"] != futu_fingerprint
        or receipt["futu_session_publication_manifest_fingerprint"] != futu_manifest_fingerprint
        or receipt["futu_market_execution_evidence_fingerprint"] != partial_market_fingerprint
        or receipt["futu_peer_evidence_set_fingerprint"] != partial_peer_fingerprint
        or receipt["futu_partial_session_evidence_fingerprint"]
        != (None if partial_futu is None else partial_futu.partial_session_fingerprint)
        or receipt["futu_partial_session_publication_manifest_fingerprint"]
        != (None if partial_futu is None else partial_futu.fingerprint)
        or receipt["futu_optional_data_disposition_fingerprints"]
        != tuple(
            item.fingerprint
            for item in report.futu_optional_data_disposition_manifests
        )
        or receipt[
            "futu_optional_data_disposition_publication_manifest_fingerprints"
        ]
        != tuple(
            item.fingerprint
            for item in report.futu_optional_data_disposition_manifests
        )
        or receipt["forward_reoi_fingerprint"] != forward_fingerprint
        or receipt["comparable_valuation_fingerprint"] != comparable_fingerprint
        or receipt["composite_valuation_fingerprint"] != composite_fingerprint
        or receipt["score_v2_fingerprints"]
        != tuple(sorted(item.source_fingerprint for item in report.score_v2_manifests))
        or receipt["owner_scorecard_fingerprint"] != scorecard_fingerprint
        or receipt["forward_reoi_publication_manifest_fingerprint"]
        != (
            None
            if report.forward_reoi_manifest is None
            else report.forward_reoi_manifest.fingerprint
        )
        or receipt["comparable_valuation_publication_manifest_fingerprint"]
        != (
            None
            if report.comparable_valuation_manifest is None
            else report.comparable_valuation_manifest.fingerprint
        )
        or receipt["composite_valuation_publication_manifest_fingerprint"]
        != (
            None
            if report.composite_valuation_manifest is None
            else report.composite_valuation_manifest.fingerprint
        )
        or receipt["score_v2_publication_manifest_fingerprints"]
        != tuple(sorted(item.fingerprint for item in report.score_v2_manifests))
        or receipt["owner_scorecard_publication_manifest_fingerprint"]
        != (
            None
            if report.owner_scorecard_manifest is None
            else report.owner_scorecard_manifest.fingerprint
        )
        or receipt["market_expectations_fingerprint"]
        != (
            None
            if report.market_expectations_manifest is None
            else report.market_expectations_manifest.fingerprint
        )
        or receipt["market_expectations_publication_manifest_fingerprint"]
        != (
            None
            if report.market_expectations_manifest is None
            else report.market_expectations_manifest.fingerprint
        )
        or receipt["runtime_gap_fingerprint"]
        != (
            None
            if report.runtime_gap_manifest is None
            else report.runtime_gap_manifest.source_receipt_fingerprint
        )
        or receipt["runtime_gap_publication_manifest_fingerprint"]
        != (
            None if report.runtime_gap_manifest is None else report.runtime_gap_manifest.fingerprint
        )
    ):
        raise ResearchPublisherError("report receipt is not bound to its typed inputs")
    if report.profile == "research_only" and valuation is not None:
        raise ResearchPublisherError("research_only publication contains valuation")
    if report.profile == "full_valuation":
        if valuation is None:
            raise ResearchPublisherError("full_valuation publication lacks valuation")
        if (
            valuation.manifest["issuer_id"] != bundle.issuer_id
            or valuation.manifest["data_cutoff_date"] != bundle.data_cutoff_date
            or valuation.manifest["component_lock_sha256"] != bundle.component_lock_sha256
        ):
            raise ResearchPublisherError("valuation and research identities differ")
    report_data = _json_object(
        next(item.content for item in report.artifacts if item.path == "report-data.json"),
        "report data",
    )
    if (
        report_data.get("profile") != report.profile
        or report_data.get("research_bundle") != bundle.to_dict()
        or report_data.get("research_run_manifest") != research.run_manifest.to_dict()
    ):
        raise ResearchPublisherError("report data rebinds or changes a typed input")
    (
        report_spec,
        content,
        research_source_manifest,
        legacy_scores,
        futu_session_manifest,
        futu_partial_session_manifest,
        futu_optional_data_disposition_manifests,
        forward_reoi,
        comparable_valuation,
        composite_valuation,
        score_v2,
        owner_scorecard,
        market_expectations_manifest,
        runtime_gap_manifest,
    ) = _typed_report_inputs(report_data)
    research_bytes = {
        "research-bundle.json": _canonical_file(research.bundle.to_dict()),
        "run-manifest.json": _canonical_file(research.run_manifest.to_dict()),
    }
    research_input = ReloadedResearchInput(
        source_directory=Path("."),
        result=research,
        file_bytes=research_bytes,
        file_sha256={name: _sha256(content) for name, content in research_bytes.items()},
    )
    valuation_input = None
    if valuation is not None:
        valuation_bytes = _valuation_archive_file_bytes(valuation)
        valuation_input = ReloadedValuationInput(
            source_directory=valuation.output_directory,
            archive=valuation,
            file_bytes=valuation_bytes,
            file_sha256={
                name: _sha256(content) for name, content in valuation_bytes.items()
            },
        )
    live_inputs = (
        report.research_source_index,
        report.futu_session_evidence,
        report.futu_market_execution_evidence,
        report.futu_peer_evidence_set,
        report.forward_reoi,
        report.comparable_valuation,
        report.composite_valuation,
        report.owner_scorecard,
        report.market_expectations,
        report.runtime_gap,
        *report.futu_optional_data_dispositions,
        *report.score_v2,
    )
    try:
        if manifest_only:
            if any(item is not None for item in live_inputs):
                raise ResearchPublisherError(
                    "manifest-only package reload retained live report authorities"
                )
        else:
            _verify_inputs(
                profile=report.profile,
                research=research_input,
                valuation=valuation_input,
                report_spec=report_spec,
                research_source_index=report.research_source_index,
                research_source_manifest=research_source_manifest,
                legacy_scores=legacy_scores,
                futu_session_evidence=report.futu_session_evidence,
                futu_session_manifest=futu_session_manifest,
                futu_market_execution_evidence=report.futu_market_execution_evidence,
                futu_peer_evidence_set=report.futu_peer_evidence_set,
                futu_partial_session_manifest=futu_partial_session_manifest,
                futu_optional_data_dispositions=(
                    report.futu_optional_data_dispositions
                ),
                futu_optional_data_disposition_manifests=(
                    futu_optional_data_disposition_manifests
                ),
                futu_verifier=futu_verifier,
                forward_reoi=report.forward_reoi,
                comparable_valuation=report.comparable_valuation,
                composite_valuation=report.composite_valuation,
                score_v2=report.score_v2,
                owner_scorecard=report.owner_scorecard,
                market_expectations=report.market_expectations,
                market_expectations_manifest=market_expectations_manifest,
                runtime_gap=report.runtime_gap,
                runtime_gap_manifest=runtime_gap_manifest,
            )
        if report.profile == "full_valuation":
            assert valuation is not None
            assert composite_valuation is not None
            assert owner_scorecard is not None
            _validate_downstream_publication_chain(
                research_bundle_fingerprint=bundle.bundle_fingerprint,
                contract_graph_fingerprint=research_source_manifest.to_dict()[
                    "contract_graph_fingerprint"
                ],
                valuation_archive_fingerprint=valuation.fingerprint,
                valuation_result_sha256=str(valuation.manifest["valuation_result_sha256"]),
                futu_session_manifest=futu_session_manifest,
                futu_partial_session_manifest=futu_partial_session_manifest,
                forward_manifest=forward_reoi,
                comparable_manifest=comparable_valuation,
                composite_manifest=composite_valuation,
                score_manifests=score_v2,
                scorecard_manifest=owner_scorecard,
                market_manifest=market_expectations_manifest,
                runtime_gap_manifest=runtime_gap_manifest,
            )
    except ResearchReportError as exc:
        raise ResearchPublisherError("report full typed input chain does not replay") from exc
    expected_payload = _report_payload(
        report.profile,
        research_input,
        valuation_input,
        report_spec,
        content,
        research_source_manifest,
        legacy_scores,
        futu_session_manifest,
        futu_partial_session_manifest,
        forward_reoi,
        comparable_valuation,
        composite_valuation,
        score_v2,
        owner_scorecard,
        market_expectations_manifest,
        runtime_gap_manifest,
        futu_optional_data_disposition_manifests,
        forward_reoi,
        comparable_valuation,
        composite_valuation,
        score_v2,
        owner_scorecard,
    )
    data_tex = _report_data_tex(content).encode("utf-8")
    artifacts = {item.path: item.content for item in report.artifacts}
    if (
        report.content != content
        or report_data != expected_payload
        or artifacts["report-data.tex"] != data_tex
    ):
        raise ResearchPublisherError("report payload or deterministic LaTeX input drifted")


def _media_type(path: str) -> str:
    suffix = PurePosixPath(path).suffix.lower()
    return {
        ".json": "application/json",
        ".pdf": "application/pdf",
        ".tex": "application/x-tex",
        ".md": "text/markdown",
        ".txt": "text/plain",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
        ".svg": "image/svg+xml",
    }.get(suffix, "application/octet-stream")


def _payload_contents(
    report: ReportBuildResult,
    research: ReloadedResearchInput,
    valuation: ReloadedValuationInput | None,
    *,
    futu_verifier: SignatureVerifier | None,
) -> tuple[dict[str, bytes], dict[str, str]]:
    contents: dict[str, bytes] = {}
    media_types: dict[str, str] = {}
    for artifact in report.artifacts:
        path = f"report/{artifact.path}"
        contents[path] = artifact.content
        media_types[path] = artifact.media_type
    receipt_path = "report/report-build-receipt.json"
    contents[receipt_path] = _canonical_file(report.receipt)
    media_types[receipt_path] = "application/json"
    for name, content in research.file_bytes.items():
        path = f"research/{name}"
        contents[path] = content
        media_types[path] = "application/json"
    contents[_SOURCE_INDEX_PATH] = _canonical_file(report.research_source_manifest.to_dict())
    media_types[_SOURCE_INDEX_PATH] = "application/json"
    if valuation is not None:
        for name, content in valuation.file_bytes.items():
            path = f"valuation/{name}"
            contents[path] = content
            media_types[path] = "application/json"
        required_downstream = {
            _SYNTHESIS_PATHS["composite_valuation"]: report.composite_valuation_manifest,
            _OWNER_SCORECARD_PATH: report.owner_scorecard_manifest,
        }
        if (
            any(value is None for value in required_downstream.values())
            or len(report.score_v2_manifests) != 4
            or tuple(
                item.to_dict()["protocol_id"]
                for item in report.futu_optional_data_disposition_manifests
            )
            != (3235, 3244, 3245, 3246)
        ):
            raise ResearchPublisherError(
                "full_valuation report lacks its exact typed downstream package"
            )
        optional_downstream = {
            _SYNTHESIS_PATHS["forward_reoi"]: report.forward_reoi_manifest,
            _SYNTHESIS_PATHS["comparable_valuation"]: report.comparable_valuation_manifest,
        }
        context_status = str(report.receipt["valuation_context_status"])
        market_evidence = None
        if context_status == "complete":
            if (
                report.futu_session_manifest is None
                or report.market_expectations_manifest is None
                or any(value is None for value in optional_downstream.values())
                or report.futu_partial_session_manifest is not None
                or report.runtime_gap_manifest is not None
            ):
                raise ResearchPublisherError("complete report lacks its exact typed context")
            contents[_FUTU_SESSION_PATH] = _canonical_file(report.futu_session_manifest.to_dict())
            media_types[_FUTU_SESSION_PATH] = "application/json"
            contents[_MARKET_EXPECTATIONS_PATH] = _canonical_file(
                report.market_expectations_manifest.to_dict()
            )
            media_types[_MARKET_EXPECTATIONS_PATH] = "application/json"
            if report.futu_session_evidence is not None:
                market_evidence = report.futu_session_evidence.market_execution_evidence
        elif context_status == "post_context_not_run":
            if (
                report.futu_partial_session_manifest is None
                or report.runtime_gap_manifest is None
                or report.futu_session_manifest is not None
                or report.market_expectations_manifest is not None
            ):
                raise ResearchPublisherError("partial report has mixed or missing Futu context")
            contents[_FUTU_PARTIAL_SESSION_PATH] = _canonical_file(
                report.futu_partial_session_manifest.to_dict()
            )
            media_types[_FUTU_PARTIAL_SESSION_PATH] = "application/json"
            contents[_RUNTIME_GAP_PATH] = _canonical_file(report.runtime_gap_manifest.to_dict())
            media_types[_RUNTIME_GAP_PATH] = "application/json"
            market_evidence = report.futu_market_execution_evidence
        else:
            raise ResearchPublisherError("full report context status is not closed")
        if market_evidence is None:
            raise ResearchPublisherError(
                "full report lacks exact live Futu market evidence for receipt publication"
            )
        try:
            market_manifest = build_futu_market_execution_publication_manifest(
                market_evidence,
                verifier=futu_verifier,
            )
            disposition_bundle = build_futu_observation_disposition_publication_bundle(
                market_evidence,
                verifier=futu_verifier,
            )
            validate_futu_observation_disposition_publication_bundle(
                disposition_bundle,
                market_manifest=market_manifest,
            )
        except ValueError as exc:
            raise ResearchPublisherError(
                "full report Futu receipt publication does not replay"
            ) from exc
        contents[_FUTU_MARKET_EXECUTION_PATH] = _canonical_file(market_manifest.to_dict())
        media_types[_FUTU_MARKET_EXECUTION_PATH] = "application/json"
        contents[_FUTU_OBSERVATION_DISPOSITIONS_PATH] = _canonical_file(
            disposition_bundle.to_dict()
        )
        media_types[_FUTU_OBSERVATION_DISPOSITIONS_PATH] = "application/json"
        for path, value in {**required_downstream, **optional_downstream}.items():
            if value is None:
                continue
            assert value is not None
            contents[path] = _canonical_file(value.to_dict())
            media_types[path] = "application/json"
        for score in report.score_v2_manifests:
            path = f"scoring/score-v2-{score.lens}-publication-manifest.json"
            contents[path] = _canonical_file(score.to_dict())
            media_types[path] = "application/json"
        for disposition in report.futu_optional_data_disposition_manifests:
            protocol_id = int(disposition.to_dict()["protocol_id"])
            path = _FUTU_OPTIONAL_DATA_PATHS[protocol_id]
            contents[path] = _canonical_file(disposition.to_dict())
            media_types[path] = "application/json"
    return contents, media_types


def _publication_recommendations(report: ReportBuildResult) -> tuple[str | None, str | None]:
    if report.profile == "research_only":
        return None, None
    if report.profile != "full_valuation" or report.owner_scorecard_manifest is None:
        raise ResearchPublisherError("publication recommendation authority is incomplete")
    frozen = str(report.owner_scorecard_manifest.source_payload["recommendation"])
    if frozen not in {"重点关注", "关注", "观察", "回避", "无法评级"}:
        raise ResearchPublisherError("frozen score recommendation is not closed")
    composite_status = (
        None
        if report.composite_valuation_manifest is None
        else str(report.composite_valuation_manifest.source_payload["status"])
    )
    effective = (
        frozen
        if (
            composite_status == "complete"
            and report.market_expectations_manifest is not None
            and report.market_expectations_manifest.status == "complete"
            and report.runtime_gap_manifest is None
        )
        else "无法评级"
    )
    return effective, frozen


def _manifest_payload(
    report: ReportBuildResult,
    research: ResearchBundleBuildResult,
    valuation: ValuationRunArchive | None,
    contents: Mapping[str, bytes],
    media_types: Mapping[str, str],
) -> dict[str, object]:
    effective_recommendation, frozen_score_recommendation = _publication_recommendations(report)
    members = [
        {
            "path": path,
            "media_type": media_types[path],
            "size": len(content),
            "sha256": _sha256(content),
        }
        for path, content in sorted(contents.items())
    ]
    identity = {
        "profile": report.profile,
        "valuation_context_status": report.receipt["valuation_context_status"],
        "effective_recommendation": effective_recommendation,
        "frozen_score_recommendation": frozen_score_recommendation,
        "issuer_id": report.issuer_id,
        "data_cutoff_date": report.data_cutoff_date,
        "report_build_receipt_fingerprint": report.fingerprint,
        "report_content_fingerprint": report.content.fingerprint,
        "research_bundle_fingerprint": research.bundle.bundle_fingerprint,
        "research_source_index_fingerprint": report.research_source_manifest.fingerprint,
        "valuation_archive_fingerprint": (None if valuation is None else valuation.fingerprint),
        "futu_session_evidence_fingerprint": (
            None
            if report.futu_session_manifest is None
            else report.futu_session_manifest.session_fingerprint
        ),
        "futu_session_publication_manifest_fingerprint": (
            None
            if report.futu_session_manifest is None
            else report.futu_session_manifest.fingerprint
        ),
        "futu_market_execution_evidence_fingerprint": (
            None
            if report.futu_partial_session_manifest is None
            else report.futu_partial_session_manifest.market_execution_evidence["fingerprint"]
        ),
        "futu_peer_evidence_set_fingerprint": (
            None
            if report.futu_partial_session_manifest is None
            else report.futu_partial_session_manifest.peer_evidence_set["fingerprint"]
        ),
        "futu_partial_session_evidence_fingerprint": (
            None
            if report.futu_partial_session_manifest is None
            else report.futu_partial_session_manifest.partial_session_fingerprint
        ),
        "futu_partial_session_publication_manifest_fingerprint": (
            None
            if report.futu_partial_session_manifest is None
            else report.futu_partial_session_manifest.fingerprint
        ),
        "futu_optional_data_disposition_fingerprints": [
            item.fingerprint
            for item in report.futu_optional_data_disposition_manifests
        ],
        "futu_optional_data_disposition_publication_manifest_fingerprints": [
            item.fingerprint
            for item in report.futu_optional_data_disposition_manifests
        ],
        "forward_reoi_fingerprint": (
            None
            if report.forward_reoi_manifest is None
            else report.forward_reoi_manifest.source_fingerprint
        ),
        "comparable_valuation_fingerprint": (
            None
            if report.comparable_valuation_manifest is None
            else report.comparable_valuation_manifest.source_fingerprint
        ),
        "composite_valuation_fingerprint": (
            None
            if report.composite_valuation_manifest is None
            else report.composite_valuation_manifest.source_fingerprint
        ),
        "score_v2_fingerprints": sorted(
            item.source_fingerprint for item in report.score_v2_manifests
        ),
        "owner_scorecard_fingerprint": (
            None
            if report.owner_scorecard_manifest is None
            else report.owner_scorecard_manifest.source_fingerprint
        ),
        "forward_reoi_publication_manifest_fingerprint": (
            None
            if report.forward_reoi_manifest is None
            else report.forward_reoi_manifest.fingerprint
        ),
        "comparable_valuation_publication_manifest_fingerprint": (
            None
            if report.comparable_valuation_manifest is None
            else report.comparable_valuation_manifest.fingerprint
        ),
        "composite_valuation_publication_manifest_fingerprint": (
            None
            if report.composite_valuation_manifest is None
            else report.composite_valuation_manifest.fingerprint
        ),
        "score_v2_publication_manifest_fingerprints": sorted(
            item.fingerprint for item in report.score_v2_manifests
        ),
        "owner_scorecard_publication_manifest_fingerprint": (
            None
            if report.owner_scorecard_manifest is None
            else report.owner_scorecard_manifest.fingerprint
        ),
        "market_expectations_fingerprint": (
            None
            if report.market_expectations_manifest is None
            else report.market_expectations_manifest.fingerprint
        ),
        "market_expectations_publication_manifest_fingerprint": (
            None
            if report.market_expectations_manifest is None
            else report.market_expectations_manifest.fingerprint
        ),
        "runtime_gap_fingerprint": (
            None
            if report.runtime_gap_manifest is None
            else report.runtime_gap_manifest.source_receipt_fingerprint
        ),
        "runtime_gap_publication_manifest_fingerprint": (
            None if report.runtime_gap_manifest is None else report.runtime_gap_manifest.fingerprint
        ),
        "payload_members": members,
    }
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "artifact_type": "publication-manifest",
        "publication_id": (
            f"research-publication:{report.issuer_id}:{canonical_sha256(identity)[:24]}"
        ),
        "profile": report.profile,
        "valuation_context_status": report.receipt["valuation_context_status"],
        "effective_recommendation": effective_recommendation,
        "frozen_score_recommendation": frozen_score_recommendation,
        "issuer_id": report.issuer_id,
        "data_cutoff_date": report.data_cutoff_date,
        "report_build_id": str(report.receipt["report_build_id"]),
        "report_build_receipt_fingerprint": report.fingerprint,
        "report_content_fingerprint": report.content.fingerprint,
        "research_bundle_fingerprint": research.bundle.bundle_fingerprint,
        "research_source_index_fingerprint": report.research_source_manifest.fingerprint,
        "valuation_archive_fingerprint": (None if valuation is None else valuation.fingerprint),
        "futu_session_evidence_fingerprint": (
            None
            if report.futu_session_manifest is None
            else report.futu_session_manifest.session_fingerprint
        ),
        "futu_session_publication_manifest_fingerprint": (
            None
            if report.futu_session_manifest is None
            else report.futu_session_manifest.fingerprint
        ),
        "futu_market_execution_evidence_fingerprint": (
            None
            if report.futu_partial_session_manifest is None
            else report.futu_partial_session_manifest.market_execution_evidence["fingerprint"]
        ),
        "futu_peer_evidence_set_fingerprint": (
            None
            if report.futu_partial_session_manifest is None
            else report.futu_partial_session_manifest.peer_evidence_set["fingerprint"]
        ),
        "futu_partial_session_evidence_fingerprint": (
            None
            if report.futu_partial_session_manifest is None
            else report.futu_partial_session_manifest.partial_session_fingerprint
        ),
        "futu_partial_session_publication_manifest_fingerprint": (
            None
            if report.futu_partial_session_manifest is None
            else report.futu_partial_session_manifest.fingerprint
        ),
        "futu_optional_data_disposition_fingerprints": [
            item.fingerprint
            for item in report.futu_optional_data_disposition_manifests
        ],
        "futu_optional_data_disposition_publication_manifest_fingerprints": [
            item.fingerprint
            for item in report.futu_optional_data_disposition_manifests
        ],
        "forward_reoi_fingerprint": (
            None
            if report.forward_reoi_manifest is None
            else report.forward_reoi_manifest.source_fingerprint
        ),
        "comparable_valuation_fingerprint": (
            None
            if report.comparable_valuation_manifest is None
            else report.comparable_valuation_manifest.source_fingerprint
        ),
        "composite_valuation_fingerprint": (
            None
            if report.composite_valuation_manifest is None
            else report.composite_valuation_manifest.source_fingerprint
        ),
        "score_v2_fingerprints": sorted(
            item.source_fingerprint for item in report.score_v2_manifests
        ),
        "owner_scorecard_fingerprint": (
            None
            if report.owner_scorecard_manifest is None
            else report.owner_scorecard_manifest.source_fingerprint
        ),
        "forward_reoi_publication_manifest_fingerprint": (
            None
            if report.forward_reoi_manifest is None
            else report.forward_reoi_manifest.fingerprint
        ),
        "comparable_valuation_publication_manifest_fingerprint": (
            None
            if report.comparable_valuation_manifest is None
            else report.comparable_valuation_manifest.fingerprint
        ),
        "composite_valuation_publication_manifest_fingerprint": (
            None
            if report.composite_valuation_manifest is None
            else report.composite_valuation_manifest.fingerprint
        ),
        "score_v2_publication_manifest_fingerprints": sorted(
            item.fingerprint for item in report.score_v2_manifests
        ),
        "owner_scorecard_publication_manifest_fingerprint": (
            None
            if report.owner_scorecard_manifest is None
            else report.owner_scorecard_manifest.fingerprint
        ),
        "market_expectations_fingerprint": (
            None
            if report.market_expectations_manifest is None
            else report.market_expectations_manifest.fingerprint
        ),
        "market_expectations_publication_manifest_fingerprint": (
            None
            if report.market_expectations_manifest is None
            else report.market_expectations_manifest.fingerprint
        ),
        "runtime_gap_fingerprint": (
            None
            if report.runtime_gap_manifest is None
            else report.runtime_gap_manifest.source_receipt_fingerprint
        ),
        "runtime_gap_publication_manifest_fingerprint": (
            None if report.runtime_gap_manifest is None else report.runtime_gap_manifest.fingerprint
        ),
        "payload_member_count": len(members),
        "payload_total_bytes": sum(item["size"] for item in members),
        "payload_members": members,
    }
    payload["manifest_fingerprint"] = canonical_sha256(payload)
    _validate_parallel_schema("publication-manifest", payload)
    return payload


def _package_payload(manifest: Mapping[str, object], manifest_bytes: bytes) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "artifact_type": "published-package",
        "publication_id": manifest["publication_id"],
        "profile": manifest["profile"],
        "issuer_id": manifest["issuer_id"],
        "data_cutoff_date": manifest["data_cutoff_date"],
        "publication_manifest_sha256": _sha256(manifest_bytes),
        "publication_manifest_fingerprint": manifest["manifest_fingerprint"],
        "payload_member_count": manifest["payload_member_count"],
        "payload_total_bytes": manifest["payload_total_bytes"],
    }
    payload["package_fingerprint"] = canonical_sha256(payload)
    _validate_parallel_schema("published-package", payload)
    return payload


def _open_directory_chain(path: Path) -> int:
    absolute = Path(path).expanduser().absolute()
    if not absolute.is_absolute():
        raise ResearchPublisherError("publication path must be absolute")
    # Darwin exposes /tmp, /var, and /etc as fixed root-owned aliases into
    # /private.  Normalize only that platform-owned first component; every
    # remaining component is still opened by the no-follow descriptor walk.
    if sys.platform == "darwin" and len(absolute.parts) >= 2:
        root_alias = Path(absolute.anchor) / absolute.parts[1]
        expected_target = Path("/private") / absolute.parts[1]
        try:
            alias_details = root_alias.lstat()
            alias_target = root_alias.resolve(strict=True)
        except OSError:
            pass
        else:
            if (
                stat.S_ISLNK(alias_details.st_mode)
                and alias_details.st_uid == 0
                and alias_target == expected_target
                and alias_target.is_dir()
            ):
                absolute = alias_target.joinpath(*absolute.parts[2:])
    final_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    traversal_flags = (
        getattr(os, "O_PATH", os.O_RDONLY)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    components = absolute.parts[1:]
    descriptor = os.open("/", final_flags if not components else traversal_flags)
    try:
        for index, part in enumerate(components):
            flags = final_flags if index == len(components) - 1 else traversal_flags
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError:
        os.close(descriptor)
        raise


def _open_safe_parent(target: Path) -> tuple[Path, int]:
    absolute = Path(target).expanduser().absolute()
    if not absolute.name or absolute == absolute.parent or absolute.name in {".", ".."}:
        raise ResearchPublisherError("publication output path is unsafe")
    if "/" in absolute.name or "\\" in absolute.name:
        raise ResearchPublisherError("publication output name is unsafe")
    try:
        descriptor = _open_directory_chain(absolute.parent)
    except OSError as exc:
        raise ResearchPublisherError(
            "publication parent must already exist without symlinks"
        ) from exc
    details = os.fstat(descriptor)
    if (
        details.st_uid != os.getuid()
        or not stat.S_ISDIR(details.st_mode)
        or stat.S_IMODE(details.st_mode) & 0o022
    ):
        os.close(descriptor)
        raise ResearchPublisherError(
            "publication parent must be host-owned and not group/world writable"
        )
    return absolute, descriptor


def _open_child_directory(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(name, flags, dir_fd=parent_fd)


def _directory_fd(root_fd: int, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(root_fd)
    try:
        for part in parts:
            next_descriptor = _open_child_directory(descriptor, part)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError:
        os.close(descriptor)
        raise


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise ResearchPublisherError("publication write did not complete")
        remaining = remaining[written:]


def _write_staging(parent_fd: int, staging_name: str, contents: Mapping[str, bytes]) -> None:
    _validate_limits(contents)
    os.mkdir(staging_name, 0o700, dir_fd=parent_fd)
    root_fd = _open_child_directory(parent_fd, staging_name)
    directories = sorted(_directory_names(contents), key=lambda value: (value.count("/"), value))
    try:
        for directory in directories:
            parts = _validate_path(directory)
            parent = _directory_fd(root_fd, parts[:-1])
            try:
                os.mkdir(parts[-1], 0o700, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
        for path, content in sorted(contents.items()):
            parts = _validate_path(path)
            parent = _directory_fd(root_fd, parts[:-1])
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(parts[-1], flags, 0o600, dir_fd=parent)
                try:
                    _write_all(descriptor, content)
                    os.fsync(descriptor)
                    os.fchmod(descriptor, 0o444)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.fsync(parent)
            finally:
                os.close(parent)
        for directory in sorted(
            directories,
            key=lambda value: (value.count("/"), value),
            reverse=True,
        ):
            descriptor = _directory_fd(root_fd, _validate_path(directory))
            try:
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o555)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)


def _rename_noreplace(
    parent_fd: int,
    source_name: str,
    target_name: str,
) -> None:
    """Atomically rename within one directory without replacing any target."""

    library = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(source_name)
    target = os.fsencode(target_name)
    if sys.platform == "darwin":
        try:
            rename = library.renameatx_np
        except AttributeError as exc:
            raise OSError(
                errno.ENOTSUP,
                "renameatx_np is required for exclusive publication",
            ) from exc
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        # RENAME_EXCL | RENAME_NOFOLLOW_ANY from <sys/stdio.h> on Darwin.
        flags = 0x00000004 | 0x00000010
    elif sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError as exc:
            raise OSError(
                errno.ENOTSUP,
                "renameat2 is required for exclusive publication",
            ) from exc
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        flags = 0x00000001  # RENAME_NOREPLACE from <linux/fs.h>.
    else:
        raise OSError(
            errno.ENOTSUP,
            "exclusive publication is unsupported on this platform",
        )

    ctypes.set_errno(0)
    if rename(parent_fd, source, parent_fd, target, flags) != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(
            error_number,
            os.strerror(error_number),
            f"{source_name} -> {target_name}",
        )


def _atomic_publish_staging(parent_fd: int, staging_name: str, target_name: str) -> None:
    """Rename then immediately seal the root directory on platforms such as macOS.

    macOS rejects renaming a non-empty tree whose root is already non-writable when
    the tree contains child directories.  The trusted parent is private to the host
    user, so the root remains 0700 during staging and is changed to 0555 through an
    already-open nofollow descriptor immediately after the atomic rename.
    """

    root_fd = _open_child_directory(parent_fd, staging_name)
    renamed = False
    try:
        try:
            fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ResearchPublisherError(
                "publication staging completion lock is unavailable"
            ) from exc
        _rename_noreplace(parent_fd, staging_name, target_name)
        renamed = True
        os.fchmod(root_fd, 0o555)
        os.fsync(root_fd)
        os.fsync(parent_fd)
    except OSError:
        if renamed:
            try:
                os.fchmod(root_fd, 0o700)
                _rename_noreplace(parent_fd, target_name, staging_name)
                os.fsync(parent_fd)
            except OSError as rollback_error:
                try:
                    os.fchmod(root_fd, 0o555)
                    os.fsync(root_fd)
                    os.fsync(parent_fd)
                except OSError as reseal_error:
                    raise ResearchPublisherError(
                        "publication root sealing failed and the retained root "
                        "could not be made read-only"
                    ) from reseal_error
                raise ResearchPublisherError(
                    "publication root sealing failed; rollback was unavailable "
                    "but the retained root was resealed read-only"
                ) from rollback_error
        raise
    finally:
        os.close(root_fd)


def _publication_target_state(parent_fd: int, target_name: str) -> str:
    """Classify a target only after its publishing owner releases completion."""

    try:
        descriptor = _open_child_directory(parent_fd, target_name)
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "settled"
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                return "publishing"
            raise ResearchPublisherError(
                "publication target completion lock is unavailable"
            ) from exc
        details = os.fstat(descriptor)
        try:
            named = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return "missing"
        if (named.st_dev, named.st_ino) != (details.st_dev, details.st_ino):
            return "publishing"
        mode = stat.S_IMODE(details.st_mode)
    finally:
        os.close(descriptor)
    return "staging" if mode == 0o700 else "settled"


def _publish_staging_exclusive(
    parent_fd: int,
    staging_name: str,
    target_name: str,
) -> bool:
    """Publish once, or wait for a racing winner to seal or roll back."""

    deadline = time.monotonic() + _CONCURRENT_PUBLICATION_WAIT_SECONDS
    while True:
        try:
            _atomic_publish_staging(parent_fd, staging_name, target_name)
            return True
        except FileExistsError:
            if _wait_for_publication_target(
                parent_fd,
                target_name,
                deadline=deadline,
            ):
                return False


def _wait_for_publication_target(
    parent_fd: int,
    target_name: str,
    *,
    deadline: float | None = None,
) -> bool:
    """Wait for a visible 0700 publication root to seal or roll back."""

    wait_deadline = (
        time.monotonic() + _CONCURRENT_PUBLICATION_WAIT_SECONDS
        if deadline is None
        else deadline
    )
    while True:
        state = _publication_target_state(parent_fd, target_name)
        if state == "missing":
            return False
        if state == "settled":
            return True
        if time.monotonic() >= wait_deadline:
            raise ResearchPublisherError(
                "concurrent publication target did not finish sealing"
            ) from None
        time.sleep(_CONCURRENT_PUBLICATION_POLL_SECONDS)


def _remove_tree(parent_fd: int, name: str) -> None:
    try:
        root_fd = _open_child_directory(parent_fd, name)
    except OSError:
        return

    def remove_children(directory_fd: int) -> None:
        os.fchmod(directory_fd, 0o700)
        for child in tuple(sorted(os.listdir(directory_fd))):
            details = os.stat(child, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(details.st_mode):
                child_fd = _open_child_directory(directory_fd, child)
                try:
                    remove_children(child_fd)
                finally:
                    os.close(child_fd)
                os.rmdir(child, dir_fd=directory_fd)
            elif stat.S_ISREG(details.st_mode):
                os.unlink(child, dir_fd=directory_fd)
            else:
                raise ResearchPublisherError("publication staging contains an unsafe member")
        os.fsync(directory_fd)

    try:
        remove_children(root_fd)
    finally:
        os.close(root_fd)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def _read_file(directory_fd: int, name: str, path: str, remaining: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        before = os.fstat(descriptor)
        maximum = min(_member_limit(path), remaining)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o444
            or before.st_size > maximum
        ):
            raise ResearchPublisherError(f"publication member is unsafe: {path}")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise ResearchPublisherError(f"publication member exceeds limit: {path}")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
        )
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
        ):
            raise ResearchPublisherError(f"publication member changed while read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_tree(path: Path) -> tuple[dict[str, bytes], set[str]]:
    try:
        root_fd = _open_directory_chain(path)
    except OSError as exc:
        raise ResearchPublisherError("published package directory is unavailable") from exc
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    members = 0
    total = 0

    def visit(directory_fd: int, prefix: str, depth: int) -> None:
        nonlocal members, total
        if depth > 16:
            raise ResearchPublisherError("publication directory depth exceeds the limit")
        before = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o555
        ):
            raise ResearchPublisherError("publication directory permissions are unsafe")
        names = tuple(sorted(os.listdir(directory_fd)))
        for name in names:
            relative = f"{prefix}/{name}" if prefix else name
            _validate_path(relative)
            details = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            members += 1
            if members > PUBLISH_MAX_MEMBERS:
                raise ResearchPublisherError("publication exceeds the 512-member limit")
            if stat.S_ISDIR(details.st_mode):
                if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) != 0o555:
                    raise ResearchPublisherError(f"publication directory is unsafe: {relative}")
                directories.add(relative)
                child_fd = _open_child_directory(directory_fd, name)
                try:
                    visit(child_fd, relative, depth + 1)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(details.st_mode):
                content = _read_file(directory_fd, name, relative, PUBLISH_MAX_BYTES - total)
                files[relative] = content
                total += len(content)
                if total > PUBLISH_MAX_BYTES:
                    raise ResearchPublisherError("publication exceeds the 512 MiB cumulative limit")
            else:
                raise ResearchPublisherError(f"publication member is unsafe: {relative}")
        after = os.fstat(directory_fd)
        if tuple(sorted(os.listdir(directory_fd))) != names or (
            before.st_dev,
            before.st_ino,
            before.st_mtime_ns,
            before.st_mode,
            before.st_uid,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mtime_ns,
            after.st_mode,
            after.st_uid,
        ):
            raise ResearchPublisherError("publication directory changed while read")

    try:
        visit(root_fd, "", 0)
    except OSError as exc:
        raise ResearchPublisherError("published package read failed") from exc
    finally:
        os.close(root_fd)
    return files, directories


def _load_research_pair(files: Mapping[str, bytes]) -> ResearchBundleBuildResult:
    bundle_content = files["research/research-bundle.json"]
    manifest_content = files["research/run-manifest.json"]
    bundle_payload = _json_object(bundle_content, "research bundle")
    manifest_payload = _json_object(manifest_content, "research run manifest")
    if bundle_content != _canonical_file(bundle_payload) or manifest_content != _canonical_file(
        manifest_payload
    ):
        raise ResearchPublisherError("published research pair is not canonical")
    try:
        bundle = contract_from_dict("research-bundle", bundle_payload)
        manifest = contract_from_dict("run-manifest", manifest_payload)
    except (JSONSchemaValidationError, TypeError, ValueError) as exc:
        raise ResearchPublisherError("published research pair has invalid contracts") from exc
    if not isinstance(bundle, ResearchBundle) or not isinstance(manifest, RunManifest):
        raise ResearchPublisherError("published research pair has incorrect contract types")
    result = ResearchBundleBuildResult(bundle=bundle, run_manifest=manifest)
    if (
        bundle.bundle_fingerprint != bundle_payload_sha256(bundle_payload)
        or bundle.run_id != manifest.run_id
        or bundle.issuer_id != manifest.issuer_id
        or bundle.data_cutoff_date != manifest.data_cutoff_date
        or bundle.component_lock_sha256 != manifest.component_lock_sha256
        or manifest.output_artifact_hashes.get("research-bundle.json") != bundle.bundle_fingerprint
    ):
        raise ResearchPublisherError("published research pair does not replay")
    return result


def _load_report(
    files: Mapping[str, bytes],
    *,
    allow_injected_test_renderer: bool,
) -> ReportBuildResult:
    receipt_content = files["report/report-build-receipt.json"]
    receipt = _json_object(receipt_content, "report build receipt")
    if receipt_content != _canonical_file(receipt):
        raise ResearchPublisherError("report build receipt is not canonical")
    try:
        _validate_parallel_schema("report-build-receipt", receipt)
    except ResearchReportError as exc:
        raise ResearchPublisherError("report build receipt schema is invalid") from exc
    _replay_fingerprint(receipt, "receipt_fingerprint", "report build receipt")
    entries = receipt["artifacts"]
    if not isinstance(entries, list):
        raise ResearchPublisherError("report build artifact entries are invalid")
    artifacts: list[ReportArtifact] = []
    paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or type(entry.get("path")) is not str:
            raise ResearchPublisherError("report build artifact entry is invalid")
        path = entry["path"]
        if path in paths:
            raise ResearchPublisherError("report build artifact path is duplicated")
        paths.add(path)
        packaged_path = f"report/{path}"
        if packaged_path not in files:
            raise ResearchPublisherError("report build artifact is absent")
        content = files[packaged_path]
        if entry != {
            "path": path,
            "media_type": entry.get("media_type"),
            "size": len(content),
            "sha256": _sha256(content),
        }:
            raise ResearchPublisherError("report build artifact hash or size differs")
        artifacts.append(ReportArtifact(path, str(entry["media_type"]), content))
    report_data = _json_object(
        next(item.content for item in artifacts if item.path == "report-data.json"),
        "report data",
    )
    (
        _,
        content,
        research_source_manifest,
        legacy_scores,
        futu_session_manifest,
        futu_partial_session_manifest,
        futu_optional_data_disposition_manifests,
        forward_reoi,
        comparable_valuation,
        composite_valuation,
        score_v2,
        owner_scorecard,
        market_expectations_manifest,
        runtime_gap_manifest,
    ) = _typed_report_inputs(report_data)
    report = ReportBuildResult(
        profile=str(receipt["profile"]),
        issuer_id=str(receipt["issuer_id"]),
        data_cutoff_date=str(receipt["data_cutoff_date"]),
        artifacts=tuple(sorted(artifacts, key=lambda item: item.path)),
        receipt=ReportBuildReceipt(receipt),
        content=content,
        research_source_manifest=research_source_manifest,
        legacy_scores=legacy_scores,
        futu_session_manifest=futu_session_manifest,
        futu_partial_session_manifest=futu_partial_session_manifest,
        futu_optional_data_disposition_manifests=(
            futu_optional_data_disposition_manifests
        ),
        forward_reoi_manifest=forward_reoi,
        comparable_valuation_manifest=comparable_valuation,
        composite_valuation_manifest=composite_valuation,
        score_v2_manifests=score_v2,
        owner_scorecard_manifest=owner_scorecard,
        market_expectations_manifest=market_expectations_manifest,
        runtime_gap_manifest=runtime_gap_manifest,
    )
    _verify_report_build(
        report,
        allow_injected_test_renderer=allow_injected_test_renderer,
    )
    return report


def load_owner_research_package(
    input_directory: Path,
    *,
    component_lock_path: Path | None = None,
    allow_injected_test_renderer: bool = False,
) -> PublishedResearchPackage:
    """Strictly reload every package byte, permission, schema, and cross-binding."""

    source = Path(input_directory).expanduser().absolute()
    files, directories = _read_tree(source)
    if not _CONTROL_FILES.issubset(files):
        raise ResearchPublisherError("published package lacks its two control records")
    manifest_content = files[PUBLICATION_MANIFEST]
    package_content = files[PUBLISHED_PACKAGE]
    manifest = _json_object(manifest_content, "publication manifest")
    package = _json_object(package_content, "published package receipt")
    if manifest_content != _canonical_file(manifest) or package_content != _canonical_file(package):
        raise ResearchPublisherError("publication control JSON is not canonical")
    try:
        _validate_parallel_schema("publication-manifest", manifest)
        _validate_parallel_schema("published-package", package)
    except ResearchReportError as exc:
        raise ResearchPublisherError("publication control schema validation failed") from exc
    _replay_fingerprint(manifest, "manifest_fingerprint", "publication manifest")
    _replay_fingerprint(package, "package_fingerprint", "package receipt")
    declared_entries = manifest["payload_members"]
    if not isinstance(declared_entries, list):
        raise ResearchPublisherError("publication payload member list is invalid")
    declared_paths: list[str] = []
    for entry in declared_entries:
        if not isinstance(entry, dict) or type(entry.get("path")) is not str:
            raise ResearchPublisherError("publication payload member is invalid")
        path = entry["path"]
        _validate_path(path)
        declared_paths.append(path)
        content = files.get(path)
        if content is None or entry != {
            "path": path,
            "media_type": _media_type(path),
            "size": len(content),
            "sha256": _sha256(content),
        }:
            raise ResearchPublisherError("publication member hash, size, or media type differs")
    if len(declared_paths) != len(set(declared_paths)):
        raise ResearchPublisherError("publication manifest repeats a member path")
    if set(declared_paths) != _closed_payload_paths(
        str(manifest["profile"]),
        valuation_context_status=str(manifest["valuation_context_status"]),
        has_forward_reoi=manifest["forward_reoi_fingerprint"] is not None,
        has_comparable_valuation=manifest["comparable_valuation_fingerprint"] is not None,
    ):
        raise ResearchPublisherError("publication payload member set is not closed")
    expected_files = set(declared_paths) | _CONTROL_FILES
    if set(files) != expected_files:
        raise ResearchPublisherError("published package has an unexpected file set")
    expected_directories = _directory_names({path: files[path] for path in expected_files})
    if directories != expected_directories:
        raise ResearchPublisherError("published package has an unexpected directory set")
    payload_bytes = sum(len(files[path]) for path in declared_paths)
    if (
        manifest["payload_member_count"] != len(declared_paths)
        or manifest["payload_total_bytes"] != payload_bytes
        or package["publication_id"] != manifest["publication_id"]
        or package["profile"] != manifest["profile"]
        or package["issuer_id"] != manifest["issuer_id"]
        or package["data_cutoff_date"] != manifest["data_cutoff_date"]
        or package["publication_manifest_sha256"] != _sha256(manifest_content)
        or package["publication_manifest_fingerprint"] != manifest["manifest_fingerprint"]
        or package["payload_member_count"] != len(declared_paths)
        or package["payload_total_bytes"] != payload_bytes
    ):
        raise ResearchPublisherError("published package receipt does not replay the manifest")
    report = _load_report(
        files,
        allow_injected_test_renderer=allow_injected_test_renderer,
    )
    research = _load_research_pair(files)
    if files.get(_SOURCE_INDEX_PATH) != _canonical_file(report.research_source_manifest.to_dict()):
        raise ResearchPublisherError("published source index differs from the report input")
    valuation: ValuationRunArchive | None = None
    futu_market_execution_manifest: FutuMarketExecutionPublicationManifest | None = None
    futu_observation_disposition_bundle: FutuObservationDispositionPublicationBundle | None = None
    if manifest["profile"] == "full_valuation":
        market_content = files[_FUTU_MARKET_EXECUTION_PATH]
        disposition_content = files[_FUTU_OBSERVATION_DISPOSITIONS_PATH]
        market_payload = _json_object(market_content, "Futu market execution publication")
        disposition_payload = _json_object(
            disposition_content,
            "Futu observation disposition publication",
        )
        if (
            market_content != _canonical_file(market_payload)
            or disposition_content != _canonical_file(disposition_payload)
        ):
            raise ResearchPublisherError("published Futu receipt closure is not canonical")
        try:
            futu_market_execution_manifest = (
                FutuMarketExecutionPublicationManifest.from_dict(market_payload)
            )
            futu_observation_disposition_bundle = (
                FutuObservationDispositionPublicationBundle.from_dict(disposition_payload)
            )
            validate_futu_market_execution_publication_manifest(
                futu_market_execution_manifest
            )
            validate_futu_observation_disposition_publication_bundle(
                futu_observation_disposition_bundle,
                market_manifest=futu_market_execution_manifest,
            )
        except ValueError as exc:
            raise ResearchPublisherError(
                "published Futu receipt closure does not replay"
            ) from exc
        try:
            valuation = load_valuation_run_archive(
                source / "valuation",
                component_lock_path=component_lock_path,
            )
        except ValueError as exc:
            raise ResearchPublisherError("published valuation archive does not reload") from exc
        for name in VALUATION_RUN_ARCHIVE_FILENAMES:
            if valuation.file_sha256[name] != _sha256(files[f"valuation/{name}"]):
                raise ResearchPublisherError("published valuation bytes differ from typed reload")
        typed_sidecars = {
            _SYNTHESIS_PATHS["composite_valuation"]: report.composite_valuation_manifest,
            _OWNER_SCORECARD_PATH: report.owner_scorecard_manifest,
        }
        if any(value is None for value in typed_sidecars.values()):
            raise ResearchPublisherError("published full valuation lacks typed downstream data")
        optional_sidecars = {
            _SYNTHESIS_PATHS["forward_reoi"]: report.forward_reoi_manifest,
            _SYNTHESIS_PATHS["comparable_valuation"]: report.comparable_valuation_manifest,
        }
        context_status = str(manifest["valuation_context_status"])
        if context_status == "complete":
            context_sidecars = {
                _FUTU_SESSION_PATH: report.futu_session_manifest,
                _MARKET_EXPECTATIONS_PATH: report.market_expectations_manifest,
            }
            if any(
                value is None for value in (*context_sidecars.values(), *optional_sidecars.values())
            ):
                raise ResearchPublisherError("complete package lacks its closed typed context")
        elif context_status == "post_context_not_run":
            context_sidecars = {
                _FUTU_PARTIAL_SESSION_PATH: report.futu_partial_session_manifest,
                _RUNTIME_GAP_PATH: report.runtime_gap_manifest,
            }
            if any(value is None for value in context_sidecars.values()):
                raise ResearchPublisherError("partial package lacks its closed typed context")
        else:
            raise ResearchPublisherError("published full valuation context is not closed")
        typed_sidecars.update(context_sidecars)
        typed_sidecars.update(
            {path: value for path, value in optional_sidecars.items() if value is not None}
        )
        for path, value in typed_sidecars.items():
            assert value is not None
            if files.get(path) != _canonical_file(value.to_dict()):
                raise ResearchPublisherError(
                    "published downstream typed result differs from the report input"
                )
        expected_score_paths = {
            f"scoring/score-v2-{item.lens}-publication-manifest.json": _canonical_file(
                item.to_dict()
            )
            for item in report.score_v2_manifests
        }
        if len(expected_score_paths) != 4 or any(
            files.get(path) != content for path, content in expected_score_paths.items()
        ):
            raise ResearchPublisherError("published ScoreV2 files differ from exact report inputs")
        expected_optional_paths = {
            _FUTU_OPTIONAL_DATA_PATHS[int(item.to_dict()["protocol_id"])]: (
                _canonical_file(item.to_dict())
            )
            for item in report.futu_optional_data_disposition_manifests
        }
        if set(expected_optional_paths) != set(_FUTU_OPTIONAL_DATA_PATHS.values()) or any(
            files.get(path) != content
            for path, content in expected_optional_paths.items()
        ):
            raise ResearchPublisherError(
                "published optional Futu files differ from exact report inputs"
            )
    elif any(
        path.startswith(("valuation/", "vendor/", "synthesis/", "scoring/", "market/"))
        for path in files
    ):
        raise ResearchPublisherError(
            "research_only package includes market-derived valuation or scoring data"
        )
    _verify_cross_bindings(
        report,
        research,
        valuation,
        manifest_only=True,
    )
    expected_effective_recommendation, expected_frozen_score_recommendation = (
        _publication_recommendations(report)
    )
    if (
        manifest["report_build_id"] != report.receipt["report_build_id"]
        or manifest["effective_recommendation"]
        != expected_effective_recommendation
        or manifest["frozen_score_recommendation"]
        != expected_frozen_score_recommendation
        or manifest["report_build_receipt_fingerprint"] != report.fingerprint
        or manifest["report_content_fingerprint"] != report.content.fingerprint
        or manifest["research_bundle_fingerprint"] != research.bundle.bundle_fingerprint
        or manifest["research_source_index_fingerprint"]
        != report.research_source_manifest.fingerprint
        or manifest["valuation_archive_fingerprint"]
        != (None if valuation is None else valuation.fingerprint)
        or manifest["futu_session_evidence_fingerprint"]
        != (
            None
            if report.futu_session_manifest is None
            else report.futu_session_manifest.session_fingerprint
        )
        or manifest["futu_session_publication_manifest_fingerprint"]
        != (
            None
            if report.futu_session_manifest is None
            else report.futu_session_manifest.fingerprint
        )
        or manifest["futu_market_execution_evidence_fingerprint"]
        != (
            None
            if report.futu_partial_session_manifest is None
            else report.futu_partial_session_manifest.market_execution_evidence["fingerprint"]
        )
        or manifest["futu_peer_evidence_set_fingerprint"]
        != (
            None
            if report.futu_partial_session_manifest is None
            else report.futu_partial_session_manifest.peer_evidence_set["fingerprint"]
        )
        or manifest["futu_partial_session_evidence_fingerprint"]
        != (
            None
            if report.futu_partial_session_manifest is None
            else report.futu_partial_session_manifest.partial_session_fingerprint
        )
        or manifest["futu_partial_session_publication_manifest_fingerprint"]
        != (
            None
            if report.futu_partial_session_manifest is None
            else report.futu_partial_session_manifest.fingerprint
        )
        or manifest["futu_optional_data_disposition_fingerprints"]
        != [
            item.fingerprint
            for item in report.futu_optional_data_disposition_manifests
        ]
        or manifest[
            "futu_optional_data_disposition_publication_manifest_fingerprints"
        ]
        != [
            item.fingerprint
            for item in report.futu_optional_data_disposition_manifests
        ]
        or manifest["forward_reoi_fingerprint"]
        != (
            None
            if report.forward_reoi_manifest is None
            else report.forward_reoi_manifest.source_fingerprint
        )
        or manifest["comparable_valuation_fingerprint"]
        != (
            None
            if report.comparable_valuation_manifest is None
            else report.comparable_valuation_manifest.source_fingerprint
        )
        or manifest["composite_valuation_fingerprint"]
        != (
            None
            if report.composite_valuation_manifest is None
            else report.composite_valuation_manifest.source_fingerprint
        )
        or manifest["score_v2_fingerprints"]
        != sorted(item.source_fingerprint for item in report.score_v2_manifests)
        or manifest["owner_scorecard_fingerprint"]
        != (
            None
            if report.owner_scorecard_manifest is None
            else report.owner_scorecard_manifest.source_fingerprint
        )
        or manifest["forward_reoi_publication_manifest_fingerprint"]
        != (
            None
            if report.forward_reoi_manifest is None
            else report.forward_reoi_manifest.fingerprint
        )
        or manifest["comparable_valuation_publication_manifest_fingerprint"]
        != (
            None
            if report.comparable_valuation_manifest is None
            else report.comparable_valuation_manifest.fingerprint
        )
        or manifest["composite_valuation_publication_manifest_fingerprint"]
        != (
            None
            if report.composite_valuation_manifest is None
            else report.composite_valuation_manifest.fingerprint
        )
        or manifest["score_v2_publication_manifest_fingerprints"]
        != sorted(item.fingerprint for item in report.score_v2_manifests)
        or manifest["owner_scorecard_publication_manifest_fingerprint"]
        != (
            None
            if report.owner_scorecard_manifest is None
            else report.owner_scorecard_manifest.fingerprint
        )
        or manifest["market_expectations_fingerprint"]
        != (
            None
            if report.market_expectations_manifest is None
            else report.market_expectations_manifest.fingerprint
        )
        or manifest["market_expectations_publication_manifest_fingerprint"]
        != (
            None
            if report.market_expectations_manifest is None
            else report.market_expectations_manifest.fingerprint
        )
        or manifest["runtime_gap_fingerprint"]
        != (
            None
            if report.runtime_gap_manifest is None
            else report.runtime_gap_manifest.source_receipt_fingerprint
        )
        or manifest["runtime_gap_publication_manifest_fingerprint"]
        != (
            None if report.runtime_gap_manifest is None else report.runtime_gap_manifest.fingerprint
        )
    ):
        raise ResearchPublisherError("publication manifest rebinds a typed input")
    return PublishedResearchPackage(
        output_directory=source,
        profile=str(manifest["profile"]),
        report=report,
        research=research,
        valuation=valuation,
        research_source_manifest=report.research_source_manifest,
        futu_market_execution_manifest=futu_market_execution_manifest,
        futu_observation_disposition_bundle=futu_observation_disposition_bundle,
        futu_session_manifest=report.futu_session_manifest,
        futu_partial_session_manifest=report.futu_partial_session_manifest,
        futu_optional_data_disposition_manifests=(
            report.futu_optional_data_disposition_manifests
        ),
        forward_reoi_manifest=report.forward_reoi_manifest,
        comparable_valuation_manifest=report.comparable_valuation_manifest,
        composite_valuation_manifest=report.composite_valuation_manifest,
        score_v2_manifests=report.score_v2_manifests,
        owner_scorecard_manifest=report.owner_scorecard_manifest,
        market_expectations_manifest=report.market_expectations_manifest,
        runtime_gap_manifest=report.runtime_gap_manifest,
        publication_manifest=PublicationManifest(manifest),
        package_receipt=PublishedPackageReceipt(package),
        file_sha256={path: _sha256(content) for path, content in files.items()},
        file_bytes=files,
    )


def publish_owner_research(
    report: ReportBuildResult,
    research: ReloadedResearchInput,
    *,
    output_directory: Path,
    valuation: ReloadedValuationInput | None = None,
    component_lock_path: Path | None = None,
    futu_verifier: SignatureVerifier | None = None,
    allow_injected_test_renderer: bool = False,
) -> PublishedResearchPackage:
    """Atomically publish locally and return only the exact strict final reload."""

    _verify_report_build(
        report,
        allow_injected_test_renderer=allow_injected_test_renderer,
        futu_verifier=futu_verifier,
    )
    research_result = _verify_research_input(research)
    valuation_archive = None
    if valuation is not None:
        valuation_archive = _verify_valuation_input(
            valuation,
            component_lock_path=component_lock_path,
        )
    _verify_cross_bindings(
        report,
        research_result,
        valuation_archive,
        futu_verifier=futu_verifier,
    )
    payload, media_types = _payload_contents(
        report,
        research,
        valuation,
        futu_verifier=futu_verifier,
    )
    manifest = _manifest_payload(
        report,
        research_result,
        valuation_archive,
        payload,
        media_types,
    )
    manifest_bytes = _canonical_file(manifest)
    package = _package_payload(manifest, manifest_bytes)
    contents = {
        **payload,
        PUBLICATION_MANIFEST: manifest_bytes,
        PUBLISHED_PACKAGE: _canonical_file(package),
    }
    _validate_limits(contents)
    target, parent_fd = _open_safe_parent(output_directory)
    staging_name = f".{target.name}.staging-{uuid.uuid4().hex}"
    try:
        entries = set(os.listdir(parent_fd))
        if target.name in entries and _wait_for_publication_target(
            parent_fd,
            target.name,
        ):
            existing = load_owner_research_package(
                target,
                component_lock_path=component_lock_path,
                allow_injected_test_renderer=allow_injected_test_renderer,
            )
            if (
                existing.publication_manifest["manifest_fingerprint"]
                == manifest["manifest_fingerprint"]
            ):
                return existing
            raise ResearchPublisherError("publication target exists with different content")
        try:
            _write_staging(parent_fd, staging_name, contents)
            if not _publish_staging_exclusive(parent_fd, staging_name, target.name):
                if staging_name in os.listdir(parent_fd):
                    _remove_tree(parent_fd, staging_name)
                existing = load_owner_research_package(
                    target,
                    component_lock_path=component_lock_path,
                    allow_injected_test_renderer=allow_injected_test_renderer,
                )
                if (
                    existing.publication_manifest["manifest_fingerprint"]
                    == manifest["manifest_fingerprint"]
                ):
                    return existing
                raise ResearchPublisherError(
                    "publication target exists with different content"
                ) from None
        except (OSError, ResearchPublisherError) as exc:
            if staging_name in os.listdir(parent_fd):
                _remove_tree(parent_fd, staging_name)
            if isinstance(exc, ResearchPublisherError):
                raise
            raise ResearchPublisherError(f"atomic publication failed: {exc}") from exc
    finally:
        os.close(parent_fd)
    loaded = load_owner_research_package(
        target,
        component_lock_path=component_lock_path,
        allow_injected_test_renderer=allow_injected_test_renderer,
    )
    if (
        to_json_value(loaded.publication_manifest) != manifest
        or to_json_value(loaded.package_receipt) != package
        or loaded.report.fingerprint != report.fingerprint
    ):
        raise ResearchPublisherError("exact final reload differs from the staged publication")
    return loaded


def republish_owner_research_package(
    source: PublishedResearchPackage,
    *,
    output_directory: Path,
    component_lock_path: Path | None = None,
    allow_injected_test_renderer: bool = False,
) -> PublishedResearchPackage:
    """Atomically copy one strict package from its retained immutable byte snapshot.

    Republishing is intentionally a byte-preserving operation.  It does not rebuild a
    report, reconstruct live Futu authorities, or invoke the valuation kernel.  The
    destination is accepted only after the ordinary strict package loader has replayed
    every copied byte and typed control record.
    """

    if type(source) is not PublishedResearchPackage:
        raise ResearchPublisherError("republication requires an exact strict source package")
    contents = dict(source.file_bytes)
    hashes = dict(source.file_sha256)
    _validate_limits(contents)
    if (
        not contents
        or set(contents) != set(hashes)
        or {path: _sha256(content) for path, content in contents.items()} != hashes
    ):
        raise ResearchPublisherError("republication source byte snapshot does not replay")
    manifest_content = contents.get(PUBLICATION_MANIFEST)
    package_content = contents.get(PUBLISHED_PACKAGE)
    if type(manifest_content) is not bytes or type(package_content) is not bytes:
        raise ResearchPublisherError("republication source lacks exact control bytes")
    manifest_payload = _json_object(manifest_content, "republication manifest")
    package_payload = _json_object(package_content, "republication package receipt")
    if (
        manifest_content != _canonical_file(manifest_payload)
        or package_content != _canonical_file(package_payload)
        or PublicationManifest(manifest_payload) != source.publication_manifest
        or PublishedPackageReceipt(package_payload) != source.package_receipt
    ):
        raise ResearchPublisherError("republication source controls do not replay")

    def require_same_snapshot(candidate: PublishedResearchPackage) -> None:
        if (
            dict(candidate.file_bytes) != contents
            or dict(candidate.file_sha256) != hashes
            or candidate.publication_manifest != source.publication_manifest
            or candidate.package_receipt != source.package_receipt
            or candidate.profile != source.profile
            or candidate.report.fingerprint != source.report.fingerprint
        ):
            raise ResearchPublisherError(
                "republication destination differs from the retained source package"
            )

    target, parent_fd = _open_safe_parent(output_directory)
    staging_name = f".{target.name}.staging-{uuid.uuid4().hex}"
    try:
        if target.name in set(os.listdir(parent_fd)) and _wait_for_publication_target(
            parent_fd,
            target.name,
        ):
            existing = load_owner_research_package(
                target,
                component_lock_path=component_lock_path,
                allow_injected_test_renderer=allow_injected_test_renderer,
            )
            require_same_snapshot(existing)
            return existing
        try:
            _write_staging(parent_fd, staging_name, contents)
            if not _publish_staging_exclusive(parent_fd, staging_name, target.name):
                if staging_name in os.listdir(parent_fd):
                    _remove_tree(parent_fd, staging_name)
                existing = load_owner_research_package(
                    target,
                    component_lock_path=component_lock_path,
                    allow_injected_test_renderer=allow_injected_test_renderer,
                )
                require_same_snapshot(existing)
                return existing
        except (OSError, ResearchPublisherError) as exc:
            if staging_name in os.listdir(parent_fd):
                _remove_tree(parent_fd, staging_name)
            if isinstance(exc, ResearchPublisherError):
                raise
            raise ResearchPublisherError(f"atomic republication failed: {exc}") from exc
    finally:
        os.close(parent_fd)

    loaded = load_owner_research_package(
        target,
        component_lock_path=component_lock_path,
        allow_injected_test_renderer=allow_injected_test_renderer,
    )
    require_same_snapshot(loaded)
    return loaded


load_published_package = load_owner_research_package
publish_research_report = publish_owner_research


__all__ = (
    "PUBLISHED_PACKAGE",
    "PUBLICATION_MANIFEST",
    "PUBLISH_IMAGE_MAX_BYTES",
    "PUBLISH_MAX_BYTES",
    "PUBLISH_MAX_MEMBERS",
    "PUBLISH_OTHER_MAX_BYTES",
    "PUBLISH_PDF_MAX_BYTES",
    "PublicationManifest",
    "PublishedPackage",
    "PublishedPackageReceipt",
    "PublishedResearchPackage",
    "ResearchPublisherError",
    "load_owner_research_package",
    "load_published_package",
    "publish_owner_research",
    "publish_research_report",
    "republish_owner_research_package",
)
