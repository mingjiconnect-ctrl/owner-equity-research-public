"""Closed high-level orchestration for the comprehensive Owner Equity Research flow.

This module is intentionally an integration seam.  Data acquisition, the pinned
valuation kernel, synthesis, scoring, report construction, publication, and audit are
supplied as explicit callables and must return the exact phase-result types below.  The
orchestrator itself has no network, filesystem, subprocess, or market-account capability.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .contracts import QuarterlyUpdate
from .fingerprints import canonical_json, canonical_sha256, to_json_value
from .futu_receipts import FutuEvidenceBundle, FutuObservation
from .futu_session import (
    FutuMarketExecutionEvidence,
    FutuPeerEvidenceSet,
    FutuSessionEvidence,
    validate_futu_session_evidence_replay,
)
from .futu_sidecar import (
    FutuSidecarExecution,
    validate_futu_attested_session_finalization,
)
from .owner_equity_types import (
    FutuOptionalDataDisposition,
    MarketExpectationsComparison,
    ResearchSourceIndex,
    RuntimeGapReceipt,
)
from .research_bundle_artifacts import replay_research_bundle_artifact_snapshot
from .research_bundle_builder import ResearchBundleBuildResult
from .research_publisher import (
    PublicationManifest,
    PublishedPackageReceipt,
    PublishedResearchPackage,
)
from .research_publisher import (
    load_owner_research_package as _load_owner_research_package,
)
from .research_report import (
    ReloadedResearchInput,
    ReportBuildReceipt,
    ReportBuildResult,
)
from .valuation_futu_market import FutuMarketReferenceProvider
from .valuation_market_execution_types import (
    FinalRequestCompilationReceipt,
    KernelExecutionReceipt,
)
from .valuation_price_blind_freeze import PriceBlindFreezeCompilationResult
from .valuation_run import ValuationRunInputReceipt, ValuationRunResult
from .valuation_run import _replay_retained_completed_run as _replay_retained_completed_run
from .valuation_run_archive import ValuationRunArchive
from .valuation_synthesis_types import (
    ComparableInputReceipt,
    ComparableValuationResult,
    CompositeValuationResult,
    ForwardReOIValuationResult,
    OwnerScorecard,
    ScoreV2,
)


class OwnerEquityResearchError(ValueError):
    """The high-level request or one of its closed phase transitions is invalid."""


# Compatibility seam for existing adapters/tests. Phase wrappers deliberately never call it;
# the initial audit adapter remains the sole package loader.
load_owner_research_package = _load_owner_research_package


class ResearchIntent(StrEnum):
    RESEARCH = "research"
    QUARTERLY = "quarterly"
    VALUATION = "valuation"
    REPORT = "report"
    PUBLISH = "publish"
    AUDIT = "audit"


class PublicationProfile(StrEnum):
    RESEARCH_ONLY = "research_only"
    FULL_VALUATION = "full_valuation"


class PhaseStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    SPECIALIST_REQUIRED = "specialist_required"
    CONTESTED = "contested"


_PHASE_NAMES = frozenset(
    {
        "official_research_freeze",
        "quarterly",
        "futu_nonprice_verification",
        "price_blind_refreeze",
        "futu_market_reference",
        "owner_valuation_kernel",
        "three_panel_synthesis",
        "owner_scorecard",
        "futu_market_expectations",
        "report",
        "publication",
        "audit",
    }
)
_RECOMMENDATIONS = frozenset({"重点关注", "关注", "观察", "回避", "无法评级"})
_HIGH_LEVEL_SCHEMA_NAMES = frozenset(
    {
        "owner-equity-research-input-receipt",
        "owner-equity-research-phase-receipt",
        "owner-equity-research-result",
        "owner-equity-runtime-config",
    }
)
_HIGH_LEVEL_SCHEMA_MAX_BYTES = 256 * 1024


def _high_level_schema_directory() -> Path:
    packaged = Path(__file__).parent / "extension_schemas"
    repository = Path(__file__).parents[2] / "extension_schemas"
    for candidate in (packaged, repository):
        try:
            metadata = candidate.lstat()
        except OSError:
            continue
        if stat.S_ISDIR(metadata.st_mode) and not candidate.is_symlink():
            return candidate
    raise OwnerEquityResearchError("high-level schema directory is unavailable")


def _read_high_level_schema(path: Path, name: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OwnerEquityResearchError(f"high-level schema is unavailable: {name}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > _HIGH_LEVEL_SCHEMA_MAX_BYTES
        ):
            raise OwnerEquityResearchError(f"high-level schema has invalid size: {name}")
        chunks: list[bytes] = []
        remaining = _HIGH_LEVEL_SCHEMA_MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) != metadata.st_size or len(content) > _HIGH_LEVEL_SCHEMA_MAX_BYTES:
            raise OwnerEquityResearchError(f"high-level schema has invalid size: {name}")
        return content
    finally:
        os.close(descriptor)


def _reject_schema_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate schema member")
        value[key] = item
    return value


def _reject_schema_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def load_owner_equity_research_schema(name: str) -> dict[str, Any]:
    """Load one parallel high-level schema without touching the frozen PR1/PR2 store."""

    if name not in _HIGH_LEVEL_SCHEMA_NAMES:
        raise KeyError(f"unknown owner-equity-research schema: {name}")
    path = _high_level_schema_directory() / f"{name}.schema.json"
    content = _read_high_level_schema(path, name)
    try:
        schema = json.loads(
            content,
            object_pairs_hook=_reject_schema_duplicates,
            parse_constant=_reject_schema_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise OwnerEquityResearchError(f"high-level schema is invalid JSON: {name}") from exc
    if not isinstance(schema, dict):
        raise OwnerEquityResearchError(f"high-level schema must be an object: {name}")
    Draft202012Validator.check_schema(schema)
    return copy.deepcopy(schema)


def _validate_high_level_schema(name: str, payload: object) -> None:
    validator = Draft202012Validator(
        load_owner_equity_research_schema(name),
        format_checker=FormatChecker(),
    )
    errors = sorted(validator.iter_errors(payload), key=lambda item: list(item.path))
    if errors:
        raise OwnerEquityResearchError(
            f"{name} schema validation failed: {errors[0].message}"
        )


def validate_owner_equity_research_result_projection(payload: object) -> None:
    """Validate the disk-safe result envelope without promoting it to live authority."""

    _validate_high_level_schema("owner-equity-research-result", payload)


def validate_owner_equity_research_schema_payload(name: str, payload: object) -> None:
    """Validate a closed high-level or runtime projection against the parallel schemas."""

    _validate_high_level_schema(name, payload)


def _timestamp(value: str, label: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise OwnerEquityResearchError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise OwnerEquityResearchError(f"{label} must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _date(value: str, label: str) -> str:
    try:
        return date.fromisoformat(value).isoformat()
    except (TypeError, ValueError) as exc:
        raise OwnerEquityResearchError(f"{label} must be an ISO-8601 date") from exc


def _identity(value: str, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise OwnerEquityResearchError(f"{label} must be a nonempty bounded string")
    return value


def _issues(values: tuple[str, ...]) -> tuple[str, ...]:
    if type(values) is not tuple or any(
        type(value) is not str or not value or len(value) > 256 for value in values
    ):
        raise OwnerEquityResearchError("issue codes must be exact nonempty bounded strings")
    return tuple(sorted(set(values)))


@dataclass(frozen=True, slots=True)
class OwnerEquityResearchRequest:
    issuer_id: str
    data_cutoff_date: str
    intent: ResearchIntent
    profile: PublicationProfile | None
    requested_by: str
    requested_at: str

    def __post_init__(self) -> None:
        _identity(self.issuer_id, "issuer_id")
        object.__setattr__(
            self, "data_cutoff_date", _date(self.data_cutoff_date, "data_cutoff_date")
        )
        if type(self.intent) is not ResearchIntent:
            raise OwnerEquityResearchError("intent must use the closed ResearchIntent enum")
        if self.profile is not None and type(self.profile) is not PublicationProfile:
            raise OwnerEquityResearchError("profile must use the closed PublicationProfile enum")
        _identity(self.requested_by, "requested_by")
        if not self.requested_by.startswith("human:") or not self.requested_by[6:].strip():
            raise OwnerEquityResearchError("requested_by must identify a named human")
        object.__setattr__(self, "requested_at", _timestamp(self.requested_at, "requested_at"))
        if self.intent in {ResearchIntent.RESEARCH, ResearchIntent.QUARTERLY, ResearchIntent.AUDIT}:
            if self.profile is not None:
                raise OwnerEquityResearchError("this intent does not accept a publication profile")
        elif self.intent is ResearchIntent.REPORT:
            if self.profile is not PublicationProfile.RESEARCH_ONLY:
                raise OwnerEquityResearchError("report-only intent is always price-blind")
        elif self.intent is ResearchIntent.VALUATION:
            if self.profile is not PublicationProfile.FULL_VALUATION:
                raise OwnerEquityResearchError("valuation intent requires full_valuation profile")
        elif self.intent is ResearchIntent.PUBLISH and self.profile is None:
            raise OwnerEquityResearchError("publish intent requires an explicit closed profile")

    def to_dict(self) -> dict[str, object]:
        return {
            "issuer_id": self.issuer_id,
            "data_cutoff_date": self.data_cutoff_date,
            "intent": self.intent.value,
            "profile": self.profile.value if self.profile is not None else None,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at,
        }

    @classmethod
    def from_dict(cls, payload: object) -> OwnerEquityResearchRequest:
        if not isinstance(payload, dict) or set(payload) != {
            "issuer_id",
            "data_cutoff_date",
            "intent",
            "profile",
            "requested_by",
            "requested_at",
        }:
            raise OwnerEquityResearchError("owner-equity request fields are not closed")
        try:
            profile = (
                None
                if payload["profile"] is None
                else PublicationProfile(payload["profile"])
            )
            return cls(
                issuer_id=payload["issuer_id"],
                data_cutoff_date=payload["data_cutoff_date"],
                intent=ResearchIntent(payload["intent"]),
                profile=profile,
                requested_by=payload["requested_by"],
                requested_at=payload["requested_at"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, OwnerEquityResearchError):
                raise
            raise OwnerEquityResearchError("owner-equity request is invalid") from exc


@dataclass(frozen=True, slots=True)
class OwnerEquityResearchInputReceipt:
    receipt_id: str
    request: OwnerEquityResearchRequest

    def __post_init__(self) -> None:
        if type(self.request) is not OwnerEquityResearchRequest:
            raise OwnerEquityResearchError("input receipt requires the exact typed request")
        expected = (
            f"owner-equity-research-input:{self.request.issuer_id}:"
            f"{canonical_sha256(self.request.to_dict())[:24]}"
        )
        if self.receipt_id != expected:
            raise OwnerEquityResearchError("input receipt ID is not deterministic")
        _validate_high_level_schema(
            "owner-equity-research-input-receipt",
            self.to_dict(),
        )

    @classmethod
    def from_request(cls, request: OwnerEquityResearchRequest) -> OwnerEquityResearchInputReceipt:
        if type(request) is not OwnerEquityResearchRequest:
            raise OwnerEquityResearchError("run requires the exact typed request")
        receipt_id = (
            f"owner-equity-research-input:{request.issuer_id}:"
            f"{canonical_sha256(request.to_dict())[:24]}"
        )
        return cls(receipt_id=receipt_id, request=request)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "artifact_type": "owner-equity-research-input-receipt",
            "receipt_id": self.receipt_id,
            "receipt_fingerprint": self.fingerprint,
            "request": self.request.to_dict(),
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(
            {
                "receipt_id": self.receipt_id,
                "request": self.request.to_dict(),
            }
        )

    @classmethod
    def from_dict(cls, payload: object) -> OwnerEquityResearchInputReceipt:
        _validate_high_level_schema("owner-equity-research-input-receipt", payload)
        assert isinstance(payload, dict)
        request = OwnerEquityResearchRequest.from_dict(payload["request"])
        receipt = cls(receipt_id=payload["receipt_id"], request=request)
        if payload["receipt_fingerprint"] != receipt.fingerprint:
            raise OwnerEquityResearchError("input receipt fingerprint does not replay")
        return receipt


@dataclass(frozen=True, slots=True)
class PhaseReceipt:
    receipt_id: str
    phase: str
    input_receipt: OwnerEquityResearchInputReceipt
    upstream_receipts: tuple[PhaseReceipt, ...]
    authorities: tuple[object, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if self.phase not in _PHASE_NAMES:
            raise OwnerEquityResearchError("phase receipt uses an unregistered phase")
        if type(self.input_receipt) is not OwnerEquityResearchInputReceipt:
            raise OwnerEquityResearchError("phase receipt lacks its exact input receipt")
        upstream = tuple(self.upstream_receipts)
        if (
            any(type(value) is not PhaseReceipt for value in upstream)
            or len({value.receipt_id for value in upstream}) != len(upstream)
            or any(value.input_receipt != self.input_receipt for value in upstream)
        ):
            raise OwnerEquityResearchError("phase receipt upstream chain is invalid")
        if type(self.authorities) is not tuple or not self.authorities:
            raise OwnerEquityResearchError("phase receipt requires retained typed authorities")
        authority_fingerprints = _phase_authority_fingerprints(
            self.phase,
            self.authorities,
        )
        object.__setattr__(self, "upstream_receipts", upstream)
        object.__setattr__(self, "authorities", tuple(self.authorities))
        payload = {
            "phase": self.phase,
            "input_receipt_id": self.input_receipt.receipt_id,
            "input_receipt_fingerprint": self.input_receipt.fingerprint,
            "upstream_receipt_ids": [value.receipt_id for value in upstream],
            "authority_fingerprints": list(authority_fingerprints),
        }
        expected = f"owner-research-phase:{self.phase}:{canonical_sha256(payload)[:24]}"
        if self.receipt_id != expected:
            raise OwnerEquityResearchError("phase receipt ID is not deterministic")
        _validate_high_level_schema(
            "owner-equity-research-phase-receipt",
            self.to_dict(),
        )

    @property
    def issuer_id(self) -> str:
        return self.input_receipt.request.issuer_id

    @property
    def data_cutoff_date(self) -> str:
        return self.input_receipt.request.data_cutoff_date

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "phase": self.phase,
            "input_receipt_id": self.input_receipt.receipt_id,
            "input_receipt_fingerprint": self.input_receipt.fingerprint,
            "upstream_receipt_ids": [
                value.receipt_id for value in self.upstream_receipts
            ],
            "authority_fingerprints": list(
                _phase_authority_fingerprints(self.phase, self.authorities)
            ),
        }

    @classmethod
    def create(
        cls,
        *,
        phase: str,
        input_receipt: OwnerEquityResearchInputReceipt,
        upstream_receipts: tuple[PhaseReceipt, ...],
        authorities: tuple[object, ...],
    ) -> PhaseReceipt:
        if type(input_receipt) is not OwnerEquityResearchInputReceipt:
            raise OwnerEquityResearchError("phase receipt factory requires exact input")
        authority_fingerprints = _phase_authority_fingerprints(phase, authorities)
        payload = {
            "phase": phase,
            "input_receipt_id": input_receipt.receipt_id,
            "input_receipt_fingerprint": input_receipt.fingerprint,
            "upstream_receipt_ids": [value.receipt_id for value in upstream_receipts],
            "authority_fingerprints": list(authority_fingerprints),
        }
        return cls(
            receipt_id=f"owner-research-phase:{phase}:{canonical_sha256(payload)[:24]}",
            phase=phase,
            input_receipt=input_receipt,
            upstream_receipts=upstream_receipts,
            authorities=authorities,
        )

    @classmethod
    def from_dict(
        cls,
        payload: object,
        *,
        input_receipt: OwnerEquityResearchInputReceipt,
        upstream_receipts: tuple[PhaseReceipt, ...],
        authorities: tuple[object, ...],
    ) -> PhaseReceipt:
        _validate_high_level_schema("owner-equity-research-phase-receipt", payload)
        assert isinstance(payload, dict)
        expected = cls.create(
            phase=payload["phase"],
            input_receipt=input_receipt,
            upstream_receipts=upstream_receipts,
            authorities=authorities,
        )
        if payload != expected.to_dict():
            raise OwnerEquityResearchError("phase receipt projection was rebound")
        return expected


@dataclass(frozen=True, slots=True)
class SecurityScope:
    listing_mics: tuple[str, ...]
    currency: str
    security_kind: str
    share_classes: tuple[str, ...]
    sec_reporting: bool
    industry_kind: str

    def __post_init__(self) -> None:
        if type(self.listing_mics) is not tuple or not self.listing_mics:
            raise OwnerEquityResearchError("security scope requires at least one listing MIC")
        if type(self.share_classes) is not tuple or not self.share_classes:
            raise OwnerEquityResearchError("security scope requires at least one share class")
        for value in (*self.listing_mics, *self.share_classes):
            _identity(value, "security scope value")
        _identity(self.currency, "security scope currency")
        _identity(self.security_kind, "security kind")
        _identity(self.industry_kind, "industry kind")
        if type(self.sec_reporting) is not bool:
            raise OwnerEquityResearchError("sec_reporting must be boolean")

    @property
    def incomplete_issue(self) -> str | None:
        if (
            "UNRESOLVED" in self.listing_mics
            or self.currency == "UNRESOLVED"
            or self.security_kind == "unresolved"
            or "unresolved" in self.share_classes
            or self.industry_kind == "unresolved"
        ):
            return "official_research_partial:security_scope_unresolved"
        return None

    @property
    def specialist_issue(self) -> str | None:
        if self.incomplete_issue is not None:
            return None
        if not self.sec_reporting:
            return "specialist_required:not_sec_reporting"
        if self.security_kind != "single_common_stock":
            return f"specialist_required:{self.security_kind}"
        if len(self.listing_mics) != 1:
            return "specialist_required:dual_or_multiple_listing"
        if self.listing_mics[0] not in {"XNYS", "XNAS"}:
            return "specialist_required:unsupported_listing"
        if self.currency != "USD":
            return "specialist_required:unsupported_currency"
        if self.share_classes != ("common",):
            return "specialist_required:multiple_or_noncommon_share_class"
        if self.industry_kind in {"bank", "insurance", "fund", "reit"}:
            return f"specialist_required:{self.industry_kind}"
        if self.industry_kind != "general_operating_company":
            return "specialist_required:unsupported_industry"
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "listing_mics": list(self.listing_mics),
            "currency": self.currency,
            "security_kind": self.security_kind,
            "share_classes": list(self.share_classes),
            "sec_reporting": self.sec_reporting,
            "industry_kind": self.industry_kind,
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _research_input_fingerprint(value: ReloadedResearchInput) -> str:
    if type(value) is not ReloadedResearchInput:
        raise OwnerEquityResearchError("research authority has the wrong exact type")
    value.__post_init__()
    return canonical_sha256(
        {
            "source_directory": str(value.source_directory),
            "bundle_fingerprint": value.result.bundle.fingerprint,
            "manifest_fingerprint": value.result.run_manifest.fingerprint,
            "file_sha256": to_json_value(value.file_sha256),
        }
    )


def _sidecar_execution_fingerprint(value: FutuSidecarExecution) -> str:
    if type(value) is not FutuSidecarExecution:
        raise OwnerEquityResearchError("Futu execution has the wrong exact type")
    return canonical_sha256(
        {
            "bundle": value.bundle.fingerprint,
            "requests": [item.fingerprint for item in value.requests],
            "responses": [item.fingerprint for item in value.responses],
            "observations": [item.fingerprint for item in value.observations],
            "history_quota": (
                None if value.history_quota is None else value.history_quota.fingerprint
            ),
        }
    )


def _archive_authority_fingerprint(value: ValuationRunArchive) -> str:
    if type(value) is not ValuationRunArchive:
        raise OwnerEquityResearchError("valuation archive has the wrong exact type")
    return canonical_sha256(
        {
            "output_directory": str(value.output_directory),
            "directory_device": value.directory_device,
            "directory_inode": value.directory_inode,
            "manifest_fingerprint": value.fingerprint,
            "file_sha256": to_json_value(value.file_sha256),
        }
    )


def _package_authority_fingerprint(value: PublishedResearchPackage) -> str:
    if type(value) is not PublishedResearchPackage:
        raise OwnerEquityResearchError("published package has the wrong exact type")
    return canonical_sha256(
        {
            "output_directory": str(value.output_directory),
            "package_fingerprint": value.fingerprint,
            "file_sha256": to_json_value(value.file_sha256),
        }
    )


def _report_authority_fingerprint(value: ReportBuildResult) -> str:
    if type(value) is not ReportBuildResult:
        raise OwnerEquityResearchError("report build has the wrong exact type")
    return canonical_sha256(
        {
            "receipt_fingerprint": value.receipt.fingerprint,
            "content_fingerprint": value.content.fingerprint,
            "artifacts": [
                {
                    "path": item.path,
                    "media_type": item.media_type,
                    "sha256": item.sha256,
                }
                for item in value.artifacts
            ],
        }
    )


def _phase_authority_fingerprints(
    phase: str,
    authorities: tuple[object, ...],
) -> tuple[str, ...]:
    """Validate one closed per-phase authority tuple and derive only from its objects."""

    if type(authorities) is not tuple:
        raise OwnerEquityResearchError("phase authorities must use an exact tuple")
    if phase == "official_research_freeze":
        if len(authorities) != 3 or not (
            type(authorities[0]) is ReloadedResearchInput
            and type(authorities[1]) is ResearchSourceIndex
            and type(authorities[2]) is SecurityScope
        ):
            raise OwnerEquityResearchError("official receipt authority tuple is invalid")
        return (
            _research_input_fingerprint(authorities[0]),
            authorities[1].fingerprint,
            authorities[2].fingerprint,
        )
    if phase == "quarterly":
        if len(authorities) != 1 or type(authorities[0]) is not QuarterlyUpdate:
            raise OwnerEquityResearchError("quarterly receipt authority tuple is invalid")
        return (authorities[0].fingerprint,)
    if phase == "futu_nonprice_verification":
        if len(authorities) != 2 or not (
            type(authorities[0]) is FutuSidecarExecution
            and type(authorities[1]) is tuple
            and all(type(item) is FutuOptionalDataDisposition for item in authorities[1])
            and tuple(item.protocol_id for item in authorities[1])
            == (3235, 3244, 3245, 3246)
        ):
            raise OwnerEquityResearchError("Futu nonprice receipt authority tuple is invalid")
        return (
            _sidecar_execution_fingerprint(authorities[0]),
            canonical_sha256([item.fingerprint for item in authorities[1]]),
        )
    if phase == "price_blind_refreeze":
        if len(authorities) != 2 or not (
            type(authorities[0]) is ReloadedResearchInput
            and type(authorities[1]) is PriceBlindFreezeCompilationResult
        ):
            raise OwnerEquityResearchError("price-blind receipt authority tuple is invalid")
        return (_research_input_fingerprint(authorities[0]), authorities[1].fingerprint)
    if phase == "futu_market_reference":
        if len(authorities) != 2 or not (
            type(authorities[0]) is FutuMarketExecutionEvidence
            and type(authorities[1]) is FutuMarketReferenceProvider
        ):
            raise OwnerEquityResearchError("market receipt authority tuple is invalid")
        return (authorities[0].fingerprint, authorities[1].fingerprint)
    if phase == "owner_valuation_kernel":
        if len(authorities) != 2 or not (
            type(authorities[0]) is ValuationRunResult
            and type(authorities[1]) is ValuationRunArchive
        ):
            raise OwnerEquityResearchError("kernel receipt authority tuple is invalid")
        return (authorities[0].fingerprint, _archive_authority_fingerprint(authorities[1]))
    if phase == "three_panel_synthesis":
        if not 3 <= len(authorities) <= 5:
            raise OwnerEquityResearchError("synthesis receipt authority tuple is invalid")
        if (
            type(authorities[0]) is not ValuationRunResult
            or type(authorities[-2]) is not CompositeValuationResult
            or type(authorities[-1]) is not FutuPeerEvidenceSet
            or any(
                type(value) not in {ForwardReOIValuationResult, ComparableValuationResult}
                for value in authorities[1:-2]
            )
            or len({type(value) for value in authorities[1:-2]})
            != len(authorities[1:-2])
        ):
            raise OwnerEquityResearchError("synthesis receipt authorities are not closed")
        return tuple(
            value.fingerprint
            for value in authorities
        )
    if phase == "owner_scorecard":
        if len(authorities) != 2 or not (
            type(authorities[0]) is tuple
            and len(authorities[0]) == 4
            and all(type(value) is ScoreV2 for value in authorities[0])
            and type(authorities[1]) is OwnerScorecard
        ):
            raise OwnerEquityResearchError("score receipt authority tuple is invalid")
        return (
            canonical_sha256([value.fingerprint for value in authorities[0]]),
            authorities[1].fingerprint,
        )
    if phase == "futu_market_expectations":
        if len(authorities) == 1 and type(authorities[0]) is RuntimeGapReceipt:
            return (authorities[0].fingerprint,)
        if len(authorities) == 2 and (
            type(authorities[0]) is FutuSessionEvidence
            and type(authorities[1]) is MarketExpectationsComparison
        ):
            return (authorities[0].fingerprint, authorities[1].fingerprint)
        raise OwnerEquityResearchError("market-expectations authority tuple is invalid")
    if phase == "report":
        if len(authorities) != 2 or not (
            type(authorities[0]) is ReportBuildResult
            and type(authorities[1]) is ReportBuildReceipt
        ):
            raise OwnerEquityResearchError("report receipt authority tuple is invalid")
        return (
            _report_authority_fingerprint(authorities[0]),
            authorities[1].fingerprint,
        )
    if phase == "publication":
        if len(authorities) == 2 and (
            type(authorities[0]) is PublishedResearchPackage
            and type(authorities[1]) is PublicationManifest
            and authorities[0].publication_manifest is authorities[1]
        ):
            return (
                _package_authority_fingerprint(authorities[0]),
                authorities[1].fingerprint,
            )
        if len(authorities) != 3 or not (
            type(authorities[0]) is PublishedResearchPackage
            and type(authorities[1]) is PublishedResearchPackage
            and type(authorities[2]) is PublicationManifest
            and authorities[1].publication_manifest is authorities[2]
        ):
            raise OwnerEquityResearchError("publication receipt authority tuple is invalid")
        source, published, manifest = authorities
        _replay_captured_published_package(source)
        _replay_captured_published_package(published)
        if (
            source.profile != published.profile
            or source.publication_manifest != manifest
            or source.package_receipt != published.package_receipt
            or dict(source.file_bytes) != dict(published.file_bytes)
            or dict(source.file_sha256) != dict(published.file_sha256)
        ):
            raise OwnerEquityResearchError(
                "republication receipt changed the retained source package"
            )
        return (
            _package_authority_fingerprint(source),
            _package_authority_fingerprint(published),
            manifest.fingerprint,
        )
    if phase == "audit":
        if len(authorities) != 1 or type(authorities[0]) is not PublishedResearchPackage:
            raise OwnerEquityResearchError("audit receipt authority tuple is invalid")
        return (_package_authority_fingerprint(authorities[0]),)
    raise OwnerEquityResearchError("phase receipt uses an unregistered authority route")


def _replay_phase_receipt(
    receipt: PhaseReceipt | None,
    *,
    phase: str,
    authorities: tuple[object, ...],
) -> None:
    if type(receipt) is not PhaseReceipt or receipt.phase != phase:
        raise OwnerEquityResearchError(f"{phase} lacks its exact phase receipt")
    expected = PhaseReceipt.create(
        phase=phase,
        input_receipt=receipt.input_receipt,
        upstream_receipts=receipt.upstream_receipts,
        authorities=authorities,
    )
    if expected != receipt:
        raise OwnerEquityResearchError(f"{phase} receipt was rebound from its typed payload")


def _replay_captured_research_input(
    research_input: ReloadedResearchInput,
    source_index: ResearchSourceIndex,
) -> None:
    """Replay retained research bytes and typed identities without reopening a locator."""

    captured = dict(research_input.file_bytes)
    result = replay_research_bundle_artifact_snapshot(captured, graph=source_index.graph)
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in captured.items()}
    replayed_index = ResearchSourceIndex.from_dict(
        source_index.to_dict(),
        graph=source_index.graph,
        research=result,
    )
    if (
        result != research_input.result
        or hashes != dict(research_input.file_sha256)
        or replayed_index != source_index
        or source_index.research != result
    ):
        raise OwnerEquityResearchError("official research captured authority does not replay")


def _replay_captured_completed_run(
    run: ValuationRunResult,
    archive: ValuationRunArchive,
) -> None:
    """Replay the completed run's retained bindings without a second archive load."""

    if run.archive is not archive:
        raise OwnerEquityResearchError("completed valuation retained objects were rebound")
    try:
        replayed_archive, _request, _result = _replay_retained_completed_run(run)
    except (TypeError, ValueError) as exc:
        raise OwnerEquityResearchError(
            "completed valuation captured archive does not replay"
        ) from exc
    if replayed_archive is not archive:
        raise OwnerEquityResearchError("completed valuation retained archive was rebound")


def _replay_captured_published_package(package: PublishedResearchPackage) -> None:
    """Replay the Publisher's final typed snapshot without touching its final path again."""

    manifest_payload = to_json_value(package.publication_manifest)
    receipt_payload = to_json_value(package.package_receipt)
    if not isinstance(manifest_payload, dict) or not isinstance(receipt_payload, dict):
        raise OwnerEquityResearchError("published package controls are not typed")
    manifest = PublicationManifest(manifest_payload)
    receipt = PublishedPackageReceipt(receipt_payload)
    manifest_bytes = (canonical_json(manifest_payload) + "\n").encode("utf-8")
    receipt_bytes = (canonical_json(receipt_payload) + "\n").encode("utf-8")
    members = manifest_payload.get("payload_members")
    if not isinstance(members, list):
        raise OwnerEquityResearchError("published package member index is not typed")
    captured = dict(package.file_bytes)
    expected_hashes: dict[str, str] = {}
    for item in members:
        if not isinstance(item, dict) or set(item) != {"path", "media_type", "size", "sha256"}:
            raise OwnerEquityResearchError("published package member index was rebound")
        path = str(item["path"])
        content = captured.get(path)
        if (
            type(content) is not bytes
            or len(content) != item["size"]
            or hashlib.sha256(content).hexdigest() != item["sha256"]
        ):
            raise OwnerEquityResearchError(
                "published package captured member bytes were rebound"
            )
        expected_hashes[path] = str(item["sha256"])
    expected_hashes["publication-manifest.json"] = hashlib.sha256(manifest_bytes).hexdigest()
    expected_hashes["published-package.json"] = hashlib.sha256(receipt_bytes).hexdigest()
    if (
        manifest != package.publication_manifest
        or receipt != package.package_receipt
        or set(captured) != set(expected_hashes)
        or captured.get("publication-manifest.json") != manifest_bytes
        or captured.get("published-package.json") != receipt_bytes
        or {
            path: hashlib.sha256(content).hexdigest()
            for path, content in captured.items()
        }
        != expected_hashes
        or dict(package.file_sha256) != expected_hashes
        or receipt_payload.get("publication_manifest_sha256")
        != expected_hashes["publication-manifest.json"]
        or receipt_payload.get("publication_manifest_fingerprint") != manifest.fingerprint
        or receipt_payload.get("profile") != package.profile
        or receipt_payload.get("issuer_id") != package.report.issuer_id
        or receipt_payload.get("data_cutoff_date") != package.report.data_cutoff_date
    ):
        raise OwnerEquityResearchError("published package captured manifest does not replay")


@dataclass(frozen=True, slots=True)
class OfficialResearchPhaseResult:
    status: PhaseStatus
    issuer_id: str
    data_cutoff_date: str
    receipt: PhaseReceipt | None
    security_scope: SecurityScope | None
    research_input: ReloadedResearchInput | None
    source_index: ResearchSourceIndex | None
    price_blind: bool
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_phase_identity(self)
        if self.security_scope is not None and type(self.security_scope) is not SecurityScope:
            raise OwnerEquityResearchError("official research security scope is not exact")
        if type(self.price_blind) is not bool:
            raise OwnerEquityResearchError("official research price-blind attestation is not exact")
        if self.status in {PhaseStatus.COMPLETED, PhaseStatus.PARTIAL}:
            if (
                type(self.research_input) is not ReloadedResearchInput
                or type(self.source_index) is not ResearchSourceIndex
                or type(self.security_scope) is not SecurityScope
            ):
                raise OwnerEquityResearchError(
                    "official research lacks exact strict-load authorities"
                )
            try:
                _replay_captured_research_input(self.research_input, self.source_index)
            except (OSError, TypeError, ValueError) as exc:
                raise OwnerEquityResearchError("official research does not replay") from exc
            if (
                self.source_index.research is not self.research_input.result
                or self.research_input.result.bundle.issuer_id != self.issuer_id
                or self.research_input.result.bundle.data_cutoff_date
                != self.data_cutoff_date
            ):
                raise OwnerEquityResearchError("official research changed its exact identity")
            _replay_phase_receipt(
                self.receipt,
                phase="official_research_freeze",
                authorities=(self.research_input, self.source_index, self.security_scope),
            )
            if not self.price_blind:
                raise OwnerEquityResearchError("official research freeze must remain price-blind")
        elif self.research_input is not None or self.source_index is not None:
            raise OwnerEquityResearchError("stopped official research retained authority")

    @property
    def research_bundle(self) -> ResearchBundleBuildResult | None:
        return None if self.research_input is None else self.research_input.result


@dataclass(frozen=True, slots=True)
class QuarterlyPhaseResult:
    status: PhaseStatus
    issuer_id: str
    data_cutoff_date: str
    receipt: PhaseReceipt | None
    quarterly_result: QuarterlyUpdate | None
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_phase_identity(self)
        if self.status is PhaseStatus.COMPLETED:
            if type(self.quarterly_result) is not QuarterlyUpdate:
                raise OwnerEquityResearchError("quarterly result has the wrong exact type")
            self.quarterly_result.__post_init__()
            if self.quarterly_result.issuer_id != self.issuer_id:
                raise OwnerEquityResearchError("quarterly result changed issuer identity")
            _replay_phase_receipt(
                self.receipt,
                phase="quarterly",
                authorities=(self.quarterly_result,),
            )
        elif self.quarterly_result is not None:
            raise OwnerEquityResearchError("stopped quarterly phase retained a result")


@dataclass(frozen=True, slots=True)
class FutuNonPricePhaseResult:
    status: PhaseStatus
    issuer_id: str
    data_cutoff_date: str
    receipt: PhaseReceipt | None
    execution: FutuSidecarExecution | None
    optional_data_dispositions: tuple[FutuOptionalDataDisposition, ...]
    has_material_conflict: bool
    quote_only_attested: bool
    sec_ir_authority_preserved: bool
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_phase_identity(self)
        if any(
            type(value) is not bool
            for value in (
                self.has_material_conflict,
                self.quote_only_attested,
                self.sec_ir_authority_preserved,
            )
        ):
            raise OwnerEquityResearchError("Futu nonprice result has invalid closed fields")
        if self.status is PhaseStatus.COMPLETED:
            if type(self.execution) is not FutuSidecarExecution:
                raise OwnerEquityResearchError("Futu nonprice execution has the wrong exact type")
            execution = self.execution
            if (
                type(execution.bundle) is not FutuEvidenceBundle
                or any(type(item) is not FutuObservation for item in execution.observations)
                or execution.bundle.stage != "valuation_pre_price_verification"
                or execution.bundle.status != "complete"
                or execution.bundle.issuer_id != self.issuer_id
                or execution.bundle.issues
                or any(
                    not item.qot_logined or item.trd_logined
                    for item in execution.responses
                )
            ):
                raise OwnerEquityResearchError("Futu nonprice execution does not replay")
            expected_observations = [
                {"object_id": item.observation_id, "fingerprint": item.fingerprint}
                for item in execution.observations
            ]
            if to_json_value(execution.bundle.observations) != expected_observations:
                raise OwnerEquityResearchError("Futu nonprice observation graph was rebound")
            dispositions = tuple(self.optional_data_dispositions)
            if (
                tuple(item.protocol_id for item in dispositions)
                != (3235, 3244, 3245, 3246)
                or any(
                    type(item) is not FutuOptionalDataDisposition
                    or item.execution is not execution
                    for item in dispositions
                )
            ):
                raise OwnerEquityResearchError(
                    "Futu optional-data dispositions do not replay the execution"
                )
            for item in dispositions:
                item.__post_init__()
            object.__setattr__(self, "optional_data_dispositions", dispositions)
            _replay_phase_receipt(
                self.receipt,
                phase="futu_nonprice_verification",
                authorities=(execution, dispositions),
            )
            if self.has_material_conflict:
                raise OwnerEquityResearchError("material SEC/Futu conflict cannot complete")
            if not self.quote_only_attested:
                raise OwnerEquityResearchError("Futu phase lacks quote-only global-state proof")
            if not self.sec_ir_authority_preserved:
                raise OwnerEquityResearchError("Futu observations cannot replace SEC/IR facts")
        elif self.execution is not None or self.optional_data_dispositions:
            raise OwnerEquityResearchError(
                "stopped Futu nonprice phase retained execution authority"
            )

    @property
    def evidence_bundle(self) -> FutuEvidenceBundle | None:
        return None if self.execution is None else self.execution.bundle

    @property
    def vendor_observations(self) -> tuple[FutuObservation, ...]:
        return () if self.execution is None else self.execution.observations


@dataclass(frozen=True, slots=True)
class PriceBlindRefreezePhaseResult:
    status: PhaseStatus
    issuer_id: str
    data_cutoff_date: str
    receipt: PhaseReceipt | None
    research_input: ReloadedResearchInput | None
    price_blind_input: PriceBlindFreezeCompilationResult | None
    sec_ir_authority_preserved: bool
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_phase_identity(self)
        if type(self.sec_ir_authority_preserved) is not bool:
            raise OwnerEquityResearchError("price-blind source-authority attestation is not exact")
        if self.status is PhaseStatus.COMPLETED:
            if (
                type(self.research_input) is not ReloadedResearchInput
                or type(self.price_blind_input) is not PriceBlindFreezeCompilationResult
            ):
                raise OwnerEquityResearchError("price-blind phase lacks exact typed inputs")
            self.price_blind_input.__post_init__()
            bundle = self.research_input.result.bundle
            payload = self.price_blind_input.artifact.payload
            frozen_bundle = payload["research_bundle"]
            if (
                bundle.issuer_id != self.issuer_id
                or bundle.data_cutoff_date != self.data_cutoff_date
                or payload["issuer_id"] != self.issuer_id
                or payload["data_cutoff_date"] != self.data_cutoff_date
                or frozen_bundle["bundle_id"] != bundle.bundle_id
                or frozen_bundle["bundle_fingerprint"] != bundle.fingerprint
                or frozen_bundle["dependency_closure_sha256"]
                != bundle.dependency_closure_sha256
                or frozen_bundle["run_manifest_id"] != bundle.run_id
            ):
                raise OwnerEquityResearchError("price-blind refreeze changed research identity")
            _replay_phase_receipt(
                self.receipt,
                phase="price_blind_refreeze",
                authorities=(self.research_input, self.price_blind_input),
            )
            if not self.sec_ir_authority_preserved:
                raise OwnerEquityResearchError("refreeze changed SEC/IR fact authority")
        elif self.research_input is not None or self.price_blind_input is not None:
            raise OwnerEquityResearchError("stopped price-blind phase retained authority")

    @property
    def research_bundle(self) -> ResearchBundleBuildResult | None:
        return None if self.research_input is None else self.research_input.result


@dataclass(frozen=True, slots=True)
class FutuMarketReferencePhaseResult:
    status: PhaseStatus
    issuer_id: str
    data_cutoff_date: str
    receipt: PhaseReceipt | None
    evidence_bundle: FutuMarketExecutionEvidence | None
    market_reference: FutuMarketReferenceProvider | None
    quote_only_attested: bool
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.quote_only_attested) is not bool:
            raise OwnerEquityResearchError("Futu quote-only attestation is not exact")
        _validate_phase_identity(self)
        if self.status is PhaseStatus.COMPLETED:
            if (
                type(self.evidence_bundle) is not FutuMarketExecutionEvidence
                or type(self.market_reference) is not FutuMarketReferenceProvider
            ):
                raise OwnerEquityResearchError("Futu market result has wrong exact types")
            try:
                self.market_reference.__post_init__()
            except (OSError, TypeError, ValueError) as exc:
                raise OwnerEquityResearchError("Futu market provider does not replay") from exc
            if (
                self.market_reference.market_execution_evidence is not self.evidence_bundle
                or self.evidence_bundle.executions[0].bundle.issuer_id != self.issuer_id
                or any(
                    not response.qot_logined or response.trd_logined
                    for execution in self.evidence_bundle.executions
                    for response in execution.responses
                )
            ):
                raise OwnerEquityResearchError("Futu market evidence was rebound")
            _replay_phase_receipt(
                self.receipt,
                phase="futu_market_reference",
                authorities=(self.evidence_bundle, self.market_reference),
            )
            if not self.quote_only_attested:
                raise OwnerEquityResearchError("Futu phase lacks quote-only global-state proof")
        elif self.evidence_bundle is not None or self.market_reference is not None:
            raise OwnerEquityResearchError("stopped Futu market phase retained authority")


@dataclass(frozen=True, slots=True)
class KernelValuationPhaseResult:
    status: PhaseStatus
    issuer_id: str
    data_cutoff_date: str
    receipt: PhaseReceipt | None
    valuation_run: ValuationRunResult | None
    six_file_archive: ValuationRunArchive | None
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_phase_identity(self)
        if self.status is PhaseStatus.COMPLETED:
            if (
                type(self.valuation_run) is not ValuationRunResult
                or type(self.six_file_archive) is not ValuationRunArchive
            ):
                raise OwnerEquityResearchError("kernel phase lacks exact completed authorities")
            try:
                _replay_captured_completed_run(
                    self.valuation_run,
                    self.six_file_archive,
                )
            except (OSError, TypeError, ValueError) as exc:
                raise OwnerEquityResearchError("kernel result or archive does not replay") from exc
            if (
                self.valuation_run.archive is not self.six_file_archive
                or self.valuation_run.issuer_id != self.issuer_id
                or self.valuation_run.data_cutoff_date != self.data_cutoff_date
            ):
                raise OwnerEquityResearchError("kernel phase rebound its strict archive")
            _replay_phase_receipt(
                self.receipt,
                phase="owner_valuation_kernel",
                authorities=(self.valuation_run, self.six_file_archive),
            )
        elif self.valuation_run is not None or self.six_file_archive is not None:
            raise OwnerEquityResearchError("stopped kernel phase exposed valuation output")


@dataclass(frozen=True, slots=True)
class SynthesisPhaseResult:
    status: PhaseStatus
    issuer_id: str
    data_cutoff_date: str
    receipt: PhaseReceipt | None
    mckinsey_panel: ValuationRunResult | None
    forward_reoi_panel: ForwardReOIValuationResult | None
    comparable_panel: ComparableValuationResult | None
    composite_valuation: CompositeValuationResult | None
    peer_evidence_set: FutuPeerEvidenceSet | None
    three_panel_complete: bool
    current_value_available: bool
    twelve_month_target_available: bool
    recommendation_eligible: bool
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_phase_identity(self)
        for value in (
            self.three_panel_complete,
            self.current_value_available,
            self.twelve_month_target_available,
            self.recommendation_eligible,
        ):
            if type(value) is not bool:
                raise OwnerEquityResearchError("synthesis availability fields must be booleans")
        if self.status in {
            PhaseStatus.COMPLETED,
            PhaseStatus.CONTESTED,
            PhaseStatus.PARTIAL,
        }:
            if (
                type(self.mckinsey_panel) is not ValuationRunResult
                or type(self.composite_valuation) is not CompositeValuationResult
                or type(self.peer_evidence_set) is not FutuPeerEvidenceSet
                or (
                    self.forward_reoi_panel is not None
                    and type(self.forward_reoi_panel) is not ForwardReOIValuationResult
                )
                or (
                    self.comparable_panel is not None
                    and type(self.comparable_panel) is not ComparableValuationResult
                )
            ):
                raise OwnerEquityResearchError("synthesis lacks exact retained panels")
            try:
                archive = self.mckinsey_panel.archive
                if type(archive) is not ValuationRunArchive:
                    raise ValueError("synthesis run lacks a captured archive")
                _replay_captured_completed_run(self.mckinsey_panel, archive)
            except (OSError, TypeError, ValueError) as exc:
                raise OwnerEquityResearchError("synthesis authority does not replay") from exc
            composite = self.composite_valuation
            archive_result = to_json_value(archive.result_payload)
            mckinsey_payload = (
                archive_result.get("panels", {}).get("mckinsey")
                if isinstance(archive_result, dict)
                else None
            )
            if not isinstance(mckinsey_payload, dict):
                raise OwnerEquityResearchError("synthesis lacks a captured McKinsey panel")
            derived_status = {
                "complete": PhaseStatus.COMPLETED,
                "contested": PhaseStatus.CONTESTED,
                "blocked": PhaseStatus.PARTIAL,
            }.get(composite.status)
            comparable_input = (
                None
                if self.comparable_panel is None
                else self.comparable_panel._input_authority
            )
            if (
                derived_status is not self.status
                or composite._run_result is not self.mckinsey_panel
                or composite.issuer_id != self.issuer_id
                or self.mckinsey_panel.data_cutoff_date != self.data_cutoff_date
                or composite._forward_authority is not self.forward_reoi_panel
                or composite._comparable_authority is not self.comparable_panel
                or dict(composite.panel_fingerprints)
                != {
                    "mckinsey": canonical_sha256(mckinsey_payload),
                    "forward_reoi": (
                        None
                        if self.forward_reoi_panel is None
                        else self.forward_reoi_panel.fingerprint
                    ),
                    "comparables": (
                        None
                        if self.comparable_panel is None
                        else self.comparable_panel.fingerprint
                    ),
                }
                or (
                    self.forward_reoi_panel is not None
                    and self.forward_reoi_panel._run_result is not self.mckinsey_panel
                )
                or (
                    self.comparable_panel is not None
                    and self.comparable_panel._run_result is not self.mckinsey_panel
                )
                or (
                    self.comparable_panel is not None
                    and (
                        type(comparable_input) is not ComparableInputReceipt
                        or comparable_input.futu_peer_evidence_set_fingerprint
                        != self.peer_evidence_set.fingerprint
                        or comparable_input._peer_authority.futu_peer_evidence_set
                        is not self.peer_evidence_set
                    )
                )
                or self.current_value_available
                is not (composite.current_intrinsic_value is not None)
                or self.twelve_month_target_available
                is not (composite.twelve_month_target is not None)
                or self.recommendation_eligible is not composite.recommendation_eligible
                or self.three_panel_complete
                is not (composite.status in {"complete", "contested"})
                or (
                    composite.status in {"complete", "contested"}
                    and (
                        self.forward_reoi_panel is None
                        or self.comparable_panel is None
                    )
                )
            ):
                raise OwnerEquityResearchError("synthesis projections changed exact panels")
            _replay_phase_receipt(
                self.receipt,
                phase="three_panel_synthesis",
                authorities=tuple(
                    item
                    for item in (
                        self.mckinsey_panel,
                        self.forward_reoi_panel,
                        self.comparable_panel,
                        self.composite_valuation,
                        self.peer_evidence_set,
                    )
                    if item is not None
                ),
            )
        elif any(
            value is not None
            for value in (
                self.mckinsey_panel,
                self.forward_reoi_panel,
                self.comparable_panel,
                self.composite_valuation,
                self.peer_evidence_set,
            )
        ):
            raise OwnerEquityResearchError("stopped synthesis retained valuation panels")


def _score_phase_outcome(
    scorecard: OwnerScorecard,
) -> tuple[PhaseStatus, tuple[str, ...]]:
    if type(scorecard) is not OwnerScorecard:
        raise OwnerEquityResearchError("score outcome requires an exact OwnerScorecard")
    composite = scorecard._composite_authority
    status = (
        PhaseStatus.CONTESTED
        if composite.status == "contested"
        else PhaseStatus.COMPLETED
        if scorecard.status == "complete"
        else PhaseStatus.PARTIAL
    )
    issues = tuple(scorecard.issue_codes)
    if not issues and status is PhaseStatus.PARTIAL:
        issues = ("owner_scorecard_partial",)
    elif not issues and status is PhaseStatus.CONTESTED:
        issues = ("composite_valuation_contested",)
    return status, (() if status is PhaseStatus.COMPLETED else tuple(sorted(set(issues))))


@dataclass(frozen=True, slots=True)
class ScorePhaseResult:
    status: PhaseStatus
    issuer_id: str
    data_cutoff_date: str
    receipt: PhaseReceipt | None
    lens_scores: tuple[ScoreV2, ...]
    scorecard: OwnerScorecard | None
    recommendation: str | None
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_phase_identity(self)
        if type(self.lens_scores) is not tuple:
            raise OwnerEquityResearchError("score lens set is not an exact tuple")
        if self.status in {
            PhaseStatus.COMPLETED,
            PhaseStatus.PARTIAL,
            PhaseStatus.CONTESTED,
        }:
            if (
                len(self.lens_scores) != 4
                or any(type(item) is not ScoreV2 for item in self.lens_scores)
                or type(self.scorecard) is not OwnerScorecard
            ):
                raise OwnerEquityResearchError("score phase lacks four exact lenses")
            try:
                for item in self.lens_scores:
                    item.__post_init__()
                self.scorecard.__post_init__()
            except (OSError, TypeError, ValueError) as exc:
                raise OwnerEquityResearchError("score authority does not replay") from exc
            if (
                len(self.scorecard._score_authorities) != len(self.lens_scores)
                or any(
                    actual is not expected
                    for actual, expected in zip(
                        self.scorecard._score_authorities,
                        self.lens_scores,
                        strict=True,
                    )
                )
                or self.scorecard.issuer_id != self.issuer_id
                or self.scorecard.as_of_date != self.data_cutoff_date
                or self.recommendation != self.scorecard.recommendation
            ):
                raise OwnerEquityResearchError("score phase rebound its lens authorities")
            expected_status, expected_issues = _score_phase_outcome(self.scorecard)
            if self.status is not expected_status or self.issue_codes != expected_issues:
                raise OwnerEquityResearchError(
                    "score phase outcome does not replay its exact scorecard"
                )
            _replay_phase_receipt(
                self.receipt,
                phase="owner_scorecard",
                authorities=(self.lens_scores, self.scorecard),
            )
            if self.recommendation not in _RECOMMENDATIONS:
                raise OwnerEquityResearchError("score recommendation is not registered")
            if (
                self.status in {PhaseStatus.PARTIAL, PhaseStatus.CONTESTED}
                and self.recommendation != "无法评级"
            ):
                raise OwnerEquityResearchError("partial or contested score must remain unrated")
        elif self.recommendation is not None or self.scorecard is not None or self.lens_scores:
            raise OwnerEquityResearchError("incomplete score cannot expose score authority")


@dataclass(frozen=True, slots=True)
class MarketExpectationsPhaseResult:
    status: PhaseStatus
    issuer_id: str
    data_cutoff_date: str
    receipt: PhaseReceipt | None
    session: FutuSessionEvidence | None
    comparison: MarketExpectationsComparison | None
    gap: RuntimeGapReceipt | None
    quote_only_attested: bool
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.quote_only_attested) is not bool:
            raise OwnerEquityResearchError("Futu quote-only attestation is not exact")
        _validate_phase_identity(self)
        if self.status in {PhaseStatus.COMPLETED, PhaseStatus.PARTIAL} and (
            self.session is not None or self.comparison is not None
        ):
            if (
                type(self.session) is not FutuSessionEvidence
                or type(self.comparison) is not MarketExpectationsComparison
                or self.gap is not None
            ):
                raise OwnerEquityResearchError(
                    "market expectations lacks exact completed authorities"
                )
            try:
                self.session.__post_init__()
                self.comparison.__post_init__()
            except (OSError, TypeError, ValueError) as exc:
                raise OwnerEquityResearchError("market expectations does not replay") from exc
            if (
                self.comparison.session is not self.session
                or self.session.issuer_id != self.issuer_id
                or self.comparison.composite_valuation.issuer_id != self.issuer_id
                or self.comparison.status
                != (
                    "complete"
                    if self.status is PhaseStatus.COMPLETED
                    else "partial"
                )
                or self.comparison.issue_codes != self.issue_codes
            ):
                raise OwnerEquityResearchError("market expectations rebound its session")
            _replay_phase_receipt(
                self.receipt,
                phase="futu_market_expectations",
                authorities=(self.session, self.comparison),
            )
            if not self.quote_only_attested:
                raise OwnerEquityResearchError("Futu phase lacks quote-only global-state proof")
        elif self.status is PhaseStatus.PARTIAL:
            if (
                self.session is not None
                or self.comparison is not None
                or type(self.gap) is not RuntimeGapReceipt
            ):
                raise OwnerEquityResearchError("suppressed post-context gap is not exact")
            self.gap.__post_init__()
            if (
                self.gap.issuer_id != self.issuer_id
                or self.gap.data_cutoff_date != self.data_cutoff_date
            ):
                raise OwnerEquityResearchError("post-context gap changed run identity")
            _replay_phase_receipt(
                self.receipt,
                phase="futu_market_expectations",
                authorities=(self.gap,),
            )
            if not self.quote_only_attested:
                raise OwnerEquityResearchError(
                    "suppressed post-context lacks signed quote-only finalization"
                )
        elif any(value is not None for value in (self.session, self.comparison, self.gap)):
            raise OwnerEquityResearchError("stopped market expectations retained authority")

    @property
    def evidence_bundle(self) -> FutuSessionEvidence | RuntimeGapReceipt | None:
        return self.session if self.session is not None else self.gap

    @property
    def market_expectations_comparison(
        self,
    ) -> MarketExpectationsComparison | RuntimeGapReceipt | None:
        return self.comparison if self.comparison is not None else self.gap

    @property
    def post_context_gap(self) -> RuntimeGapReceipt | None:
        return self.gap


def _report_phase_outcome(
    report: ReportBuildResult,
    profile: PublicationProfile,
) -> tuple[PhaseStatus, tuple[str, ...]]:
    if (
        type(report) is not ReportBuildResult
        or type(profile) is not PublicationProfile
        or report.profile != profile.value
    ):
        raise OwnerEquityResearchError(
            "report outcome requires one profile-matched exact build"
        )
    if profile is PublicationProfile.RESEARCH_ONLY:
        if report.content["status"] == "complete":
            return PhaseStatus.COMPLETED, ()
        return PhaseStatus.PARTIAL, ("research_report_partial",)

    composite = report.composite_valuation
    scorecard = report.owner_scorecard
    expectations = report.market_expectations
    runtime_gap = report.runtime_gap
    issues: set[str] = set()
    if composite is not None:
        issues.update(composite.issue_codes)
    if scorecard is not None:
        issues.update(scorecard.issue_codes)
    if expectations is not None:
        issues.update(expectations.issue_codes)
    if runtime_gap is not None:
        issues.update(runtime_gap.issue_codes)

    if composite is not None and composite.status == "contested":
        status = PhaseStatus.CONTESTED
        if not issues:
            issues.add("composite_valuation_contested")
    elif (
        report.content["status"] != "complete"
        or composite is None
        or composite.status != "complete"
        or scorecard is None
        or scorecard.status != "complete"
        or runtime_gap is not None
        or expectations is None
        or expectations.status != "complete"
    ):
        status = PhaseStatus.PARTIAL
        if not issues:
            issues.add("research_report_partial")
    else:
        status = PhaseStatus.COMPLETED
    return status, (() if status is PhaseStatus.COMPLETED else tuple(sorted(issues)))


@dataclass(frozen=True, slots=True)
class ReportPhaseResult:
    status: PhaseStatus
    issuer_id: str
    data_cutoff_date: str
    receipt: PhaseReceipt | None
    profile: PublicationProfile
    report_build: ReportBuildResult | None
    report_build_receipt: ReportBuildReceipt | None
    contains_market_price: bool
    contains_target_price: bool
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.profile) is not PublicationProfile:
            raise OwnerEquityResearchError("report phase profile is not exact")
        if any(
            type(value) is not bool
            for value in (self.contains_market_price, self.contains_target_price)
        ):
            raise OwnerEquityResearchError("report price-content attestations are not exact")
        _validate_phase_identity(self)
        if self.status in {
            PhaseStatus.COMPLETED,
            PhaseStatus.PARTIAL,
            PhaseStatus.CONTESTED,
        }:
            if (
                type(self.report_build) is not ReportBuildResult
                or type(self.report_build_receipt) is not ReportBuildReceipt
            ):
                raise OwnerEquityResearchError("report phase lacks exact build authorities")
            try:
                self.report_build.__post_init__()
            except (OSError, TypeError, ValueError) as exc:
                raise OwnerEquityResearchError("report build does not replay") from exc
            if (
                self.report_build.receipt is not self.report_build_receipt
                or self.report_build.issuer_id != self.issuer_id
                or self.report_build.data_cutoff_date != self.data_cutoff_date
                or self.report_build.profile != self.profile.value
            ):
                raise OwnerEquityResearchError("report phase rebound its build receipt")
            expected_status, expected_issues = _report_phase_outcome(
                self.report_build,
                self.profile,
            )
            if self.status is not expected_status or self.issue_codes != expected_issues:
                raise OwnerEquityResearchError(
                    "report phase outcome does not replay its exact build"
                )
            composite = self.report_build.composite_valuation
            expected_market = self.profile is PublicationProfile.FULL_VALUATION
            expected_target = (
                expected_market
                and composite is not None
                and composite.twelve_month_target is not None
            )
            if (
                self.contains_market_price is not expected_market
                or self.contains_target_price is not expected_target
            ):
                raise OwnerEquityResearchError("report price projections are not derived")
            _replay_phase_receipt(
                self.receipt,
                phase="report",
                authorities=(self.report_build, self.report_build_receipt),
            )
            if self.profile is PublicationProfile.RESEARCH_ONLY and (
                self.contains_market_price or self.contains_target_price
            ):
                raise OwnerEquityResearchError("research-only report must remain price-blind")
            if (
                self.status is PhaseStatus.COMPLETED
                and self.profile is PublicationProfile.FULL_VALUATION
                and not (self.contains_market_price and self.contains_target_price)
            ):
                raise OwnerEquityResearchError("full valuation report lacks valuation outputs")
        elif self.report_build is not None or self.report_build_receipt is not None:
            raise OwnerEquityResearchError("stopped report phase retained output")


def _published_package_outcome(
    package: PublishedResearchPackage,
    profile: PublicationProfile,
) -> tuple[PhaseStatus, tuple[str, ...]]:
    """Replay the public phase outcome from one strict typed package."""

    if (
        type(package) is not PublishedResearchPackage
        or type(profile) is not PublicationProfile
        or package.profile != profile.value
    ):
        raise OwnerEquityResearchError(
            "publication outcome requires one profile-matched strict package"
        )
    if profile is PublicationProfile.RESEARCH_ONLY:
        return _report_phase_outcome(package.report, profile)

    issues: set[str] = set()
    composite = package.composite_valuation_manifest
    scorecard = package.owner_scorecard_manifest
    expectations = package.market_expectations_manifest
    runtime_gap = package.runtime_gap_manifest
    composite_status = "missing"
    if composite is not None:
        composite_status = str(composite.source_payload["status"])
        issues.update(composite.source_payload["issue_codes"])
    scorecard_status = "missing"
    if scorecard is not None:
        scorecard_status = str(scorecard.source_payload["status"])
        issues.update(scorecard.source_payload["issue_codes"])
    expectations_status = "missing"
    if expectations is not None:
        expectations_status = expectations.status
        issues.update(expectations.issue_codes)
    if runtime_gap is not None:
        issues.update(runtime_gap.issue_codes)
    context_status = str(package.publication_manifest["valuation_context_status"])

    if composite_status == "contested":
        status = PhaseStatus.CONTESTED
        if not issues:
            issues.add("publication_replay_contested")
    elif (
        context_status != "complete"
        or composite_status != "complete"
        or scorecard_status != "complete"
        or expectations_status != "complete"
    ):
        status = PhaseStatus.PARTIAL
        if not issues:
            issues.add("publication_replay_partial")
    else:
        status = PhaseStatus.COMPLETED
    return status, (() if status is PhaseStatus.COMPLETED else tuple(sorted(issues)))


@dataclass(frozen=True, slots=True)
class PublicationPhaseResult:
    status: PhaseStatus
    issuer_id: str
    data_cutoff_date: str
    receipt: PhaseReceipt | None
    profile: PublicationProfile
    published_package: PublishedResearchPackage | None
    publication_manifest: PublicationManifest | None
    source_package: PublishedResearchPackage | None = None
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.profile) is not PublicationProfile:
            raise OwnerEquityResearchError("publication phase profile is not exact")
        _validate_phase_identity(self)
        if self.status in {
            PhaseStatus.COMPLETED,
            PhaseStatus.PARTIAL,
            PhaseStatus.CONTESTED,
        }:
            if (
                type(self.published_package) is not PublishedResearchPackage
                or type(self.publication_manifest) is not PublicationManifest
            ):
                raise OwnerEquityResearchError("publication lacks exact package authorities")
            assert self.receipt is not None
            intent = self.receipt.input_receipt.request.intent
            if intent not in {ResearchIntent.PUBLISH, ResearchIntent.VALUATION}:
                raise OwnerEquityResearchError("publication receipt used an invalid route")
            try:
                _replay_captured_published_package(self.published_package)
            except (OSError, TypeError, ValueError) as exc:
                raise OwnerEquityResearchError(
                    "published package captured authority does not replay"
                ) from exc
            if (
                self.published_package.publication_manifest
                is not self.publication_manifest
                or self.published_package.profile != self.profile.value
                or self.published_package.report.issuer_id != self.issuer_id
                or self.published_package.report.data_cutoff_date != self.data_cutoff_date
            ):
                raise OwnerEquityResearchError("publication rebound its final package")
            expected_status, expected_issues = _published_package_outcome(
                self.published_package,
                self.profile,
            )
            if self.status is not expected_status or self.issue_codes != expected_issues:
                raise OwnerEquityResearchError(
                    "publication phase outcome does not replay its strict package"
                )
            if intent is ResearchIntent.PUBLISH:
                if type(self.source_package) is not PublishedResearchPackage:
                    raise OwnerEquityResearchError(
                        "republication lacks its exact retained source package"
                    )
                try:
                    _replay_captured_published_package(self.source_package)
                except (OSError, TypeError, ValueError) as exc:
                    raise OwnerEquityResearchError(
                        "republication source captured authority does not replay"
                    ) from exc
                if (
                    self.source_package.profile != self.published_package.profile
                    or self.source_package.publication_manifest != self.publication_manifest
                    or self.source_package.package_receipt
                    != self.published_package.package_receipt
                    or dict(self.source_package.file_bytes)
                    != dict(self.published_package.file_bytes)
                    or dict(self.source_package.file_sha256)
                    != dict(self.published_package.file_sha256)
                ):
                    raise OwnerEquityResearchError(
                        "republication changed its retained source package"
                    )
                authorities = (
                    self.source_package,
                    self.published_package,
                    self.publication_manifest,
                )
            else:
                if self.source_package is not None:
                    raise OwnerEquityResearchError(
                        "pipeline publication retained an unrelated source package"
                    )
                authorities = (self.published_package, self.publication_manifest)
            _replay_phase_receipt(
                self.receipt,
                phase="publication",
                authorities=authorities,
            )
        elif (
            self.published_package is not None
            or self.publication_manifest is not None
            or self.source_package is not None
        ):
            raise OwnerEquityResearchError("stopped publication retained package")


@dataclass(frozen=True, slots=True)
class AuditPhaseResult:
    status: PhaseStatus
    issuer_id: str
    data_cutoff_date: str
    receipt: PhaseReceipt | None
    audit_result: PublishedResearchPackage | None
    read_only: bool
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.read_only is not True:
            raise OwnerEquityResearchError("audit adapter must attest read-only execution")
        _validate_phase_identity(self)
        if self.status is PhaseStatus.COMPLETED:
            if type(self.audit_result) is not PublishedResearchPackage:
                raise OwnerEquityResearchError("audit result has the wrong exact type")
            try:
                _replay_captured_published_package(self.audit_result)
            except (OSError, TypeError, ValueError) as exc:
                raise OwnerEquityResearchError(
                    "audit package captured authority does not replay"
                ) from exc
            if (
                self.audit_result.report.issuer_id != self.issuer_id
                or self.audit_result.report.data_cutoff_date != self.data_cutoff_date
            ):
                raise OwnerEquityResearchError(
                    "audit package changed or differs from the requested identity"
                )
            _replay_phase_receipt(
                self.receipt,
                phase="audit",
                authorities=(self.audit_result,),
            )
        elif self.audit_result is not None:
            raise OwnerEquityResearchError("stopped audit retained a package")


def _validate_phase_identity(value: object) -> None:
    status = getattr(value, "status", None)
    if type(status) is not PhaseStatus:
        raise OwnerEquityResearchError("phase status must use the closed PhaseStatus enum")
    _identity(getattr(value, "issuer_id", ""), "phase issuer_id")
    normalized = _date(getattr(value, "data_cutoff_date", ""), "phase data_cutoff_date")
    object.__setattr__(value, "data_cutoff_date", normalized)
    normalized_issues = _issues(getattr(value, "issue_codes", ()))
    object.__setattr__(value, "issue_codes", normalized_issues)
    receipt = getattr(value, "receipt", None)
    admitted = status in {
        PhaseStatus.COMPLETED,
        PhaseStatus.PARTIAL,
        PhaseStatus.CONTESTED,
    }
    if admitted and type(receipt) is not PhaseReceipt:
        raise OwnerEquityResearchError("admitted phase lacks its exact causal receipt")
    if not admitted and receipt is not None:
        raise OwnerEquityResearchError("stopped phase cannot retain a causal receipt")
    if receipt is not None and (
        receipt.issuer_id != value.issuer_id
        or receipt.data_cutoff_date != value.data_cutoff_date
    ):
        raise OwnerEquityResearchError("phase receipt identity differs from its result")
    if status is PhaseStatus.COMPLETED and normalized_issues:
        raise OwnerEquityResearchError("completed phase cannot retain issue codes")
    if status is not PhaseStatus.COMPLETED and not normalized_issues:
        raise OwnerEquityResearchError("stopped phase requires at least one issue code")


@dataclass(frozen=True, slots=True)
class NonPriceVerificationInput:
    request: OwnerEquityResearchRequest
    official_research: OfficialResearchPhaseResult


@dataclass(frozen=True, slots=True)
class PriceBlindRefreezeInput:
    request: OwnerEquityResearchRequest
    official_research: OfficialResearchPhaseResult
    futu_nonprice: FutuNonPricePhaseResult


@dataclass(frozen=True, slots=True)
class MarketReferenceInput:
    request: OwnerEquityResearchRequest
    price_blind: PriceBlindRefreezePhaseResult
    futu_nonprice: FutuNonPricePhaseResult


@dataclass(frozen=True, slots=True)
class KernelValuationInput:
    request: OwnerEquityResearchRequest
    price_blind: PriceBlindRefreezePhaseResult
    market_reference: FutuMarketReferencePhaseResult


@dataclass(frozen=True, slots=True)
class SynthesisInput:
    request: OwnerEquityResearchRequest
    price_blind: PriceBlindRefreezePhaseResult
    market_reference: FutuMarketReferencePhaseResult
    kernel: KernelValuationPhaseResult


@dataclass(frozen=True, slots=True)
class ScoringInput:
    request: OwnerEquityResearchRequest
    price_blind: PriceBlindRefreezePhaseResult
    synthesis: SynthesisPhaseResult


@dataclass(frozen=True, slots=True)
class MarketExpectationsInput:
    request: OwnerEquityResearchRequest
    price_blind: PriceBlindRefreezePhaseResult
    market_reference: FutuMarketReferencePhaseResult
    synthesis: SynthesisPhaseResult
    score: ScorePhaseResult


@dataclass(frozen=True, slots=True)
class ReportBuildInput:
    request: OwnerEquityResearchRequest
    profile: PublicationProfile
    official_research: OfficialResearchPhaseResult
    price_blind: PriceBlindRefreezePhaseResult | None
    market_reference: FutuMarketReferencePhaseResult | None
    kernel: KernelValuationPhaseResult | None
    synthesis: SynthesisPhaseResult | None
    score: ScorePhaseResult | None
    market_expectations: MarketExpectationsPhaseResult | None


@dataclass(frozen=True, slots=True)
class PublicationInput:
    request: OwnerEquityResearchRequest
    profile: PublicationProfile
    official_research: OfficialResearchPhaseResult | None
    report: ReportPhaseResult | None
    price_blind: PriceBlindRefreezePhaseResult | None
    kernel: KernelValuationPhaseResult | None
    synthesis: SynthesisPhaseResult | None
    score: ScorePhaseResult | None
    market_expectations: MarketExpectationsPhaseResult | None
    existing_only: bool
    source_package: PublishedResearchPackage | None = None

    def __post_init__(self) -> None:
        if type(self.request) is not OwnerEquityResearchRequest or (
            type(self.profile) is not PublicationProfile
        ):
            raise OwnerEquityResearchError("publication input identity is not exact")
        if self.request.profile is not self.profile or type(self.existing_only) is not bool:
            raise OwnerEquityResearchError("publication input profile is not exact")
        phase_values = (
            self.official_research,
            self.report,
            self.price_blind,
            self.kernel,
            self.synthesis,
            self.score,
            self.market_expectations,
        )
        if self.existing_only:
            if self.request.intent is not ResearchIntent.PUBLISH or any(
                value is not None for value in phase_values
            ) or type(self.source_package) is not PublishedResearchPackage:
                raise OwnerEquityResearchError(
                    "existing-only publication crossed an acquisition or build phase"
                )
            if (
                self.source_package.profile != self.profile.value
                or self.source_package.report.issuer_id != self.request.issuer_id
                or self.source_package.report.data_cutoff_date
                != self.request.data_cutoff_date
            ):
                raise OwnerEquityResearchError(
                    "existing-only publication source differs from the typed request"
                )
            return
        if (
            self.request.intent is not ResearchIntent.VALUATION
            or type(self.official_research) is not OfficialResearchPhaseResult
            or type(self.report) is not ReportPhaseResult
            or self.source_package is not None
        ):
            raise OwnerEquityResearchError("pipeline publication lacks exact phase inputs")


def _noop_cleanup() -> None:
    return None


@dataclass(frozen=True, slots=True)
class OwnerEquityResearchDependencies:
    official_research: Callable[[OwnerEquityResearchRequest], OfficialResearchPhaseResult]
    quarterly: Callable[
        [OwnerEquityResearchRequest, OfficialResearchPhaseResult], QuarterlyPhaseResult
    ]
    futu_nonprice: Callable[[NonPriceVerificationInput], FutuNonPricePhaseResult]
    refreeze_price_blind: Callable[[PriceBlindRefreezeInput], PriceBlindRefreezePhaseResult]
    futu_market_reference: Callable[[MarketReferenceInput], FutuMarketReferencePhaseResult]
    run_owner_valuation: Callable[[KernelValuationInput], KernelValuationPhaseResult]
    synthesize: Callable[[SynthesisInput], SynthesisPhaseResult]
    score: Callable[[ScoringInput], ScorePhaseResult]
    futu_market_expectations: Callable[[MarketExpectationsInput], MarketExpectationsPhaseResult]
    build_report: Callable[[ReportBuildInput], ReportPhaseResult]
    publish: Callable[[PublicationInput], PublicationPhaseResult]
    audit: Callable[[OwnerEquityResearchRequest], AuditPhaseResult]
    intent: ResearchIntent
    profile: PublicationProfile | None
    cleanup: Callable[[], object | None] = _noop_cleanup
    publication_source: PublishedResearchPackage | None = None

    def __post_init__(self) -> None:
        for name in (
            "official_research",
            "quarterly",
            "futu_nonprice",
            "refreeze_price_blind",
            "futu_market_reference",
            "run_owner_valuation",
            "synthesize",
            "score",
            "futu_market_expectations",
            "build_report",
            "publish",
            "audit",
            "cleanup",
        ):
            if not callable(getattr(self, name)):
                raise OwnerEquityResearchError(f"dependency {name} is not callable")
        if self.publication_source is not None and type(
            self.publication_source
        ) is not PublishedResearchPackage:
            raise OwnerEquityResearchError(
                "publication source dependency has the wrong exact type"
            )
        if type(self.intent) is not ResearchIntent:
            raise OwnerEquityResearchError("dependency route intent is not exact")
        if self.profile is not None and type(self.profile) is not PublicationProfile:
            raise OwnerEquityResearchError("dependency route profile is not exact")
        if self.intent in {
            ResearchIntent.RESEARCH,
            ResearchIntent.QUARTERLY,
            ResearchIntent.AUDIT,
        }:
            if self.profile is not None:
                raise OwnerEquityResearchError("dependency route forbids a profile")
        elif self.intent is ResearchIntent.REPORT:
            if self.profile is not PublicationProfile.RESEARCH_ONLY:
                raise OwnerEquityResearchError("report dependency route must be research_only")
        elif self.intent is ResearchIntent.VALUATION:
            if self.profile is not PublicationProfile.FULL_VALUATION:
                raise OwnerEquityResearchError("valuation dependency route must be full_valuation")
        elif self.intent is ResearchIntent.PUBLISH and self.profile is None:
            raise OwnerEquityResearchError("publish dependency route requires a profile")


@dataclass(frozen=True, slots=True)
class ExecutionStepReceipt:
    sequence: int
    phase: str
    status: PhaseStatus

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 1:
            raise OwnerEquityResearchError("execution step sequence is invalid")
        if self.phase not in _PHASE_NAMES:
            raise OwnerEquityResearchError("execution step phase is unregistered")
        if type(self.status) is not PhaseStatus:
            raise OwnerEquityResearchError("execution step status is not exact")


@dataclass(frozen=True, slots=True)
class QuarantineReceipt:
    """Minimal hash-only projection anchored by exact retained kernel receipts."""

    receipt_id: str
    phase: str
    input_receipt: OwnerEquityResearchInputReceipt
    valuation_run_input_receipt: ValuationRunInputReceipt = field(repr=False)
    final_request_receipt: FinalRequestCompilationReceipt = field(repr=False)
    kernel_execution_receipt: KernelExecutionReceipt = field(repr=False)
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.phase not in {
            "three_panel_synthesis",
            "owner_scorecard",
            "futu_market_expectations",
            "report",
            "publication",
        }:
            raise OwnerEquityResearchError("quarantine receipt phase is not post-kernel")
        if (
            type(self.input_receipt) is not OwnerEquityResearchInputReceipt
            or type(self.valuation_run_input_receipt) is not ValuationRunInputReceipt
            or type(self.final_request_receipt) is not FinalRequestCompilationReceipt
            or type(self.kernel_execution_receipt) is not KernelExecutionReceipt
        ):
            raise OwnerEquityResearchError("quarantine receipt lacks exact execution authority")
        try:
            self.valuation_run_input_receipt.__post_init__()
            self.final_request_receipt.__post_init__()
            self.kernel_execution_receipt.__post_init__()
        except (TypeError, ValueError) as exc:
            raise OwnerEquityResearchError(
                "quarantine execution authority does not replay"
            ) from exc
        request = self.input_receipt.request
        valuation_input = self.valuation_run_input_receipt
        handoffs = valuation_input.expected_freeze.handoffs
        if (
            self.final_request_receipt.status != "validated"
            or self.kernel_execution_receipt.status != "succeeded"
            or self.kernel_execution_receipt.call_count != 1
            or valuation_input.issuer_id != request.issuer_id
            or valuation_input.data_cutoff_date != request.data_cutoff_date
            or self.final_request_receipt.issuer_id != request.issuer_id
            or not handoffs
            or self.final_request_receipt.handoff_run_id != handoffs[-1].handoff_run_id
            or self.final_request_receipt.valuation_request_sha256
            != self.kernel_execution_receipt.request_sha256
        ):
            raise OwnerEquityResearchError("quarantine receipt changed the kernel causal chain")
        normalized_issues = _issues(self.issue_codes)
        if not normalized_issues:
            raise OwnerEquityResearchError("quarantine receipt requires an issue code")
        object.__setattr__(self, "issue_codes", normalized_issues)
        payload = self._identity_payload()
        expected = f"owner-research-quarantine:{canonical_sha256(payload)}"
        if self.receipt_id != expected:
            raise OwnerEquityResearchError("quarantine receipt identity is not deterministic")

    @property
    def issuer_id(self) -> str:
        return self.input_receipt.request.issuer_id

    @property
    def data_cutoff_date(self) -> str:
        return self.input_receipt.request.data_cutoff_date

    @property
    def kernel_result_sha256(self) -> str:
        return self.kernel_execution_receipt.result_sha256

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())

    def _identity_payload(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "input_receipt_id": self.input_receipt.receipt_id,
            "input_receipt_fingerprint": self.input_receipt.fingerprint,
            "issuer_id": self.issuer_id,
            "data_cutoff_date": self.data_cutoff_date,
            "valuation_run_input_receipt_fingerprint": (
                self.valuation_run_input_receipt.fingerprint
            ),
            "final_request_receipt_fingerprint": self.final_request_receipt.fingerprint,
            "kernel_execution_receipt_fingerprint": self.kernel_execution_receipt.fingerprint,
            "kernel_result_sha256": self.kernel_result_sha256,
            "issue_codes": list(self.issue_codes),
        }

    def to_dict(self) -> dict[str, object]:
        return {"receipt_id": self.receipt_id, **self._identity_payload()}

    @classmethod
    def from_kernel(
        cls,
        *,
        phase: str,
        kernel: KernelValuationPhaseResult,
        issue_codes: tuple[str, ...],
    ) -> QuarantineReceipt:
        from .valuation_run import ValuationRunResult
        from .valuation_run_archive import ValuationRunArchive

        run = kernel.valuation_run
        archive = kernel.six_file_archive
        if (
            type(run) is not ValuationRunResult
            or type(archive) is not ValuationRunArchive
            or run.status != "completed"
            or run.archive is not archive
            or run.execution is None
        ):
            raise OwnerEquityResearchError(
                "quarantine receipt requires the exact completed kernel authority"
            )
        _replay_captured_completed_run(run, archive)
        execution = run.execution
        assert execution is not None
        final_request_receipt = execution.final_request_receipt
        kernel_execution_receipt = execution.kernel_execution_receipt
        if (
            type(final_request_receipt) is not FinalRequestCompilationReceipt
            or type(kernel_execution_receipt) is not KernelExecutionReceipt
        ):
            raise OwnerEquityResearchError("completed kernel lacks exact quarantine receipts")
        input_receipt = kernel.receipt.input_receipt
        valuation_run_input_receipt = run.input_receipt
        values = {
            "phase": phase,
            "input_receipt": input_receipt,
            "valuation_run_input_receipt": valuation_run_input_receipt,
            "final_request_receipt": final_request_receipt,
            "kernel_execution_receipt": kernel_execution_receipt,
            "issue_codes": _issues(issue_codes),
        }
        identity = {
            "phase": phase,
            "input_receipt_id": input_receipt.receipt_id,
            "input_receipt_fingerprint": input_receipt.fingerprint,
            "issuer_id": input_receipt.request.issuer_id,
            "data_cutoff_date": input_receipt.request.data_cutoff_date,
            "valuation_run_input_receipt_fingerprint": (
                valuation_run_input_receipt.fingerprint
            ),
            "final_request_receipt_fingerprint": final_request_receipt.fingerprint,
            "kernel_execution_receipt_fingerprint": kernel_execution_receipt.fingerprint,
            "kernel_result_sha256": kernel_execution_receipt.result_sha256,
            "issue_codes": list(values["issue_codes"]),
        }
        return cls(
            receipt_id=f"owner-research-quarantine:{canonical_sha256(identity)}",
            **values,
        )


_RESULT_PHASE_FIELDS = (
    "official_research",
    "quarterly",
    "futu_nonprice",
    "price_blind",
    "market_reference",
    "kernel",
    "synthesis",
    "score",
    "market_expectations",
    "report",
    "publication",
    "audit",
)

_UNRATED_RECOMMENDATION = "无法评级"


def _phase_result_projection(value: object | None) -> dict[str, object] | None:
    if value is None:
        return None
    status = getattr(value, "status", None)
    receipt = getattr(value, "receipt", None)
    issues = getattr(value, "issue_codes", ())
    if type(status) is not PhaseStatus or type(issues) is not tuple:
        raise OwnerEquityResearchError("result phase projection is not exact")
    return {
        "status": status.value,
        "receipt_id": None if receipt is None else receipt.receipt_id,
        "receipt_fingerprint": None if receipt is None else receipt.fingerprint,
        "issue_codes": list(issues),
    }


def _result_identity_payload(values: dict[str, object]) -> dict[str, object]:
    input_receipt = values["input_receipt"]
    status = values["status"]
    trace = values["trace"]
    quarantine = values["quarantine_receipt"]
    if (
        type(input_receipt) is not OwnerEquityResearchInputReceipt
        or type(status) is not PhaseStatus
        or type(trace) is not tuple
    ):
        raise OwnerEquityResearchError("result identity inputs are not exact")
    return {
        "schema_version": "1.0.0",
        "artifact_type": "owner-equity-research-result",
        "status": status.value,
        "effective_recommendation": values["effective_recommendation"],
        "input_receipt": input_receipt.to_dict(),
        "phases": {
            name: _phase_result_projection(values[name])
            for name in _RESULT_PHASE_FIELDS
        },
        "quarantine_receipt": (
            None
            if quarantine is None
            else quarantine.to_dict()
        ),
        "trace": [
            {
                "sequence": item.sequence,
                "phase": item.phase,
                "status": item.status.value,
            }
            for item in trace
        ],
        "issue_codes": list(values["issue_codes"]),
    }


def _derive_effective_recommendation(
    values: dict[str, object] | OwnerEquityResearchResult,
) -> str | None:
    """Derive the run-level recommendation without mutating frozen score authority."""

    getter = values.get if isinstance(values, dict) else lambda name: getattr(values, name)
    input_receipt = getter("input_receipt")
    status = getter("status")
    if (
        type(input_receipt) is not OwnerEquityResearchInputReceipt
        or type(status) is not PhaseStatus
    ):
        raise OwnerEquityResearchError(
            "effective recommendation lacks an exact input receipt or status"
        )
    request = input_receipt.request
    recommendation_route = request.intent is ResearchIntent.VALUATION or (
        request.intent is ResearchIntent.PUBLISH
        and request.profile is PublicationProfile.FULL_VALUATION
    )
    if not recommendation_route:
        return None
    if status is not PhaseStatus.COMPLETED:
        return _UNRATED_RECOMMENDATION
    if request.intent is ResearchIntent.PUBLISH:
        publication = getter("publication")
        if type(publication) is not PublicationPhaseResult:
            raise OwnerEquityResearchError(
                "completed full-valuation publication lacks its recommendation authority"
            )
        candidate = publication.publication_manifest["effective_recommendation"]
        if candidate not in {
            "重点关注",
            "关注",
            "观察",
            "回避",
            _UNRATED_RECOMMENDATION,
        }:
            raise OwnerEquityResearchError(
                "publication effective recommendation is not closed"
            )
        return str(candidate)
    score = getter("score")
    if type(score) is not ScorePhaseResult:
        raise OwnerEquityResearchError(
            "completed valuation lacks an exact score recommendation authority"
        )
    return score.recommendation


def _closed_route(request: OwnerEquityResearchRequest) -> tuple[str, ...]:
    routes = {
        ResearchIntent.AUDIT: ("audit",),
        ResearchIntent.PUBLISH: ("publication",),
        ResearchIntent.RESEARCH: ("official_research_freeze",),
        ResearchIntent.QUARTERLY: ("official_research_freeze", "quarterly"),
        ResearchIntent.REPORT: ("official_research_freeze", "report"),
    }
    if request.intent in routes:
        return routes[request.intent]
    return (
        "official_research_freeze",
        "futu_nonprice_verification",
        "price_blind_refreeze",
        "futu_market_reference",
        "owner_valuation_kernel",
        "three_panel_synthesis",
        "owner_scorecard",
        "futu_market_expectations",
        "report",
        "publication",
    )


def _result_phase_map(values: object) -> dict[str, object | None]:
    getter = values.get if isinstance(values, dict) else lambda name: getattr(values, name)
    return {
        "official_research_freeze": getter("official_research"),
        "quarterly": getter("quarterly"),
        "futu_nonprice_verification": getter("futu_nonprice"),
        "price_blind_refreeze": getter("price_blind"),
        "futu_market_reference": getter("market_reference"),
        "owner_valuation_kernel": getter("kernel"),
        "three_panel_synthesis": getter("synthesis"),
        "owner_scorecard": getter("score"),
        "futu_market_expectations": getter("market_expectations"),
        "report": getter("report"),
        "publication": getter("publication"),
        "audit": getter("audit"),
    }


def _derive_result_outcome(values: object) -> tuple[PhaseStatus, tuple[str, ...]]:
    """Derive the public outcome only from the retained route and typed phases."""

    getter = values.get if isinstance(values, dict) else lambda name: getattr(values, name)
    input_receipt = getter("input_receipt")
    trace = getter("trace")
    quarantine = getter("quarantine_receipt")
    if (
        type(input_receipt) is not OwnerEquityResearchInputReceipt
        or type(trace) is not tuple
        or any(type(item) is not ExecutionStepReceipt for item in trace)
        or not trace
    ):
        raise OwnerEquityResearchError("result outcome lacks an exact executed route")
    request = input_receipt.request
    phases = _result_phase_map(values)
    last = trace[-1]

    if quarantine is not None:
        if (
            type(quarantine) is not QuarantineReceipt
            or last.phase != quarantine.phase
            or last.status is not PhaseStatus.BLOCKED
            or quarantine.issue_codes != (f"{quarantine.phase}_blocked",)
        ):
            raise OwnerEquityResearchError(
                "quarantine outcome differs from the failed causal phase"
            )
        return (
            PhaseStatus.BLOCKED,
            _issues(
                (
                    f"{quarantine.phase}_blocked",
                    f"valuation_outputs_quarantined:{quarantine.phase}",
                )
            ),
        )

    last_phase = phases[last.phase]
    if last.status in {PhaseStatus.BLOCKED, PhaseStatus.SPECIALIST_REQUIRED}:
        if last_phase is not None:
            if last_phase.status is not last.status:
                raise OwnerEquityResearchError(
                    "stopped result differs from its retained causal phase"
                )
            return last.status, last_phase.issue_codes
        if last.status is not PhaseStatus.BLOCKED:
            raise OwnerEquityResearchError(
                "specialist result lacks its retained scope authority"
            )
        kernel_completed = any(
            item.phase == "owner_valuation_kernel"
            and item.status is PhaseStatus.COMPLETED
            for item in trace
        )
        if kernel_completed and last.phase in {
            "three_panel_synthesis",
            "owner_scorecard",
            "futu_market_expectations",
            "report",
            "publication",
        }:
            return (
                PhaseStatus.BLOCKED,
                _issues(
                    (
                        f"{last.phase}_blocked",
                        "quarantine_receipt_unavailable",
                        f"valuation_outputs_quarantined:{last.phase}",
                    )
                ),
            )
        return PhaseStatus.BLOCKED, (f"{last.phase}_blocked",)

    official = phases["official_research_freeze"]
    if type(official) is OfficialResearchPhaseResult:
        scope = official.security_scope
        specialist_issue = None if scope is None else scope.specialist_issue
        if specialist_issue is not None:
            if tuple(item.phase for item in trace) != ("official_research_freeze",):
                raise OwnerEquityResearchError(
                    "specialist scope crossed a downstream capability"
                )
            return PhaseStatus.SPECIALIST_REQUIRED, (specialist_issue,)

    route = _closed_route(request)
    if len(trace) < len(route):
        if last_phase is None or last.status not in {
            PhaseStatus.PARTIAL,
            PhaseStatus.CONTESTED,
        }:
            raise OwnerEquityResearchError(
                "result route ended without a deterministic stopped phase"
            )
        return last.status, last_phase.issue_codes

    admitted = tuple(
        phase
        for phase in (phases[item.phase] for item in trace)
        if phase is not None
    )
    status = (
        PhaseStatus.CONTESTED
        if any(phase.status is PhaseStatus.CONTESTED for phase in admitted)
        else PhaseStatus.PARTIAL
        if any(phase.status is PhaseStatus.PARTIAL for phase in admitted)
        else PhaseStatus.COMPLETED
    )
    issues = _issues(
        tuple(
            issue
            for phase in admitted
            if phase.status is not PhaseStatus.COMPLETED
            for issue in phase.issue_codes
        )
    )
    return status, issues


def _same_exact_authority(actual: object, expected: object) -> bool:
    if type(expected) is tuple:
        return type(actual) is tuple and len(actual) == len(expected) and all(
            _same_exact_authority(left, right)
            for left, right in zip(actual, expected, strict=True)
        )
    return actual is expected


def _require_exact_authorities(
    receipt: PhaseReceipt | None,
    expected: tuple[object, ...],
    *,
    label: str,
) -> None:
    if receipt is None or len(receipt.authorities) != len(expected) or any(
        not _same_exact_authority(actual, wanted)
        for actual, wanted in zip(receipt.authorities, expected, strict=True)
    ):
        raise OwnerEquityResearchError(f"{label} receipt rebound its retained authorities")


@dataclass(frozen=True, slots=True)
class OwnerEquityResearchResult:
    status: PhaseStatus
    effective_recommendation: str | None
    input_receipt: OwnerEquityResearchInputReceipt
    official_research: OfficialResearchPhaseResult | None
    quarterly: QuarterlyPhaseResult | None
    futu_nonprice: FutuNonPricePhaseResult | None
    price_blind: PriceBlindRefreezePhaseResult | None
    market_reference: FutuMarketReferencePhaseResult | None
    kernel: KernelValuationPhaseResult | None
    synthesis: SynthesisPhaseResult | None
    score: ScorePhaseResult | None
    market_expectations: MarketExpectationsPhaseResult | None
    report: ReportPhaseResult | None
    publication: PublicationPhaseResult | None
    audit: AuditPhaseResult | None
    quarantine_receipt: QuarantineReceipt | None
    trace: tuple[ExecutionStepReceipt, ...]
    issue_codes: tuple[str, ...]
    result_fingerprint: str

    def __post_init__(self) -> None:
        if type(self.status) is not PhaseStatus:
            raise OwnerEquityResearchError("result status is not exact")
        if type(self.input_receipt) is not OwnerEquityResearchInputReceipt:
            raise OwnerEquityResearchError("result lacks an exact typed input receipt")
        if self.quarantine_receipt is not None and type(
            self.quarantine_receipt
        ) is not QuarantineReceipt:
            raise OwnerEquityResearchError("result quarantine receipt has a wrong exact type")
        phases: tuple[tuple[object | None, type[object]], ...] = (
            (self.official_research, OfficialResearchPhaseResult),
            (self.quarterly, QuarterlyPhaseResult),
            (self.futu_nonprice, FutuNonPricePhaseResult),
            (self.price_blind, PriceBlindRefreezePhaseResult),
            (self.market_reference, FutuMarketReferencePhaseResult),
            (self.kernel, KernelValuationPhaseResult),
            (self.synthesis, SynthesisPhaseResult),
            (self.score, ScorePhaseResult),
            (self.market_expectations, MarketExpectationsPhaseResult),
            (self.report, ReportPhaseResult),
            (self.publication, PublicationPhaseResult),
            (self.audit, AuditPhaseResult),
        )
        request = self.input_receipt.request
        for phase, expected_type in phases:
            if phase is not None:
                if type(phase) is not expected_type:
                    raise OwnerEquityResearchError("result retained a non-exact phase object")
                if (
                    phase.issuer_id != request.issuer_id
                    or phase.data_cutoff_date != request.data_cutoff_date
                ):
                    raise OwnerEquityResearchError("phase identity differs from the input receipt")
        if type(self.trace) is not tuple or any(
            type(item) is not ExecutionStepReceipt for item in self.trace
        ):
            raise OwnerEquityResearchError("result trace is not an exact typed tuple")
        if tuple(item.sequence for item in self.trace) != tuple(range(1, len(self.trace) + 1)):
            raise OwnerEquityResearchError("result trace sequence is not contiguous")
        normalized_issues = _issues(self.issue_codes)
        object.__setattr__(self, "issue_codes", normalized_issues)
        derived_status, derived_issues = _derive_result_outcome(self)
        if self.status is not derived_status or normalized_issues != derived_issues:
            raise OwnerEquityResearchError(
                "result status and issue codes are not derived from its exact route"
            )
        expected_recommendation = _derive_effective_recommendation(self)
        if self.effective_recommendation != expected_recommendation:
            raise OwnerEquityResearchError(
                "effective recommendation is not derived from the exact final route"
            )
        if self.quarantine_receipt is not None:
            if (
                self.status is not PhaseStatus.BLOCKED
                or self.quarantine_receipt.input_receipt != self.input_receipt
                or self.quarantine_receipt.input_receipt.request is not request
                or self.quarantine_receipt.issuer_id != request.issuer_id
                or self.quarantine_receipt.data_cutoff_date != request.data_cutoff_date
                or not set(self.quarantine_receipt.issue_codes).issubset(normalized_issues)
                or any(
                    value is not None
                    for value in (
                        self.futu_nonprice,
                        self.price_blind,
                        self.market_reference,
                        self.kernel,
                        self.synthesis,
                        self.score,
                        self.market_expectations,
                        self.report,
                        self.publication,
                    )
                )
            ):
                raise OwnerEquityResearchError(
                    "quarantined result exposed an invalidated valuation object"
                )
        self._validate_causal_chain()
        self._validate_route()
        expected_fingerprint = canonical_sha256(
            _result_identity_payload(
                {
                    name: getattr(self, name)
                    for name in (
                        "status",
                        "effective_recommendation",
                        "input_receipt",
                        *_RESULT_PHASE_FIELDS,
                        "quarantine_receipt",
                        "trace",
                        "issue_codes",
                    )
                }
            )
        )
        if self.result_fingerprint != expected_fingerprint:
            raise OwnerEquityResearchError("result fingerprint does not replay exact phases")
        _validate_high_level_schema("owner-equity-research-result", self.to_dict())

    @classmethod
    def create(cls, **values: object) -> OwnerEquityResearchResult:
        required = {
            "status",
            "input_receipt",
            *_RESULT_PHASE_FIELDS,
            "quarantine_receipt",
            "trace",
            "issue_codes",
        }
        if set(values) != required:
            raise OwnerEquityResearchError("result factory fields are not closed")
        values["issue_codes"] = _issues(values["issue_codes"])
        if type(values["trace"]) is not tuple:
            raise OwnerEquityResearchError("result factory trace is not exact")
        derived_status, derived_issues = _derive_result_outcome(values)
        if values["status"] is not derived_status or values["issue_codes"] != derived_issues:
            raise OwnerEquityResearchError(
                "result status and issue codes are not derived from its exact route"
            )
        values["effective_recommendation"] = _derive_effective_recommendation(values)
        fingerprint = canonical_sha256(_result_identity_payload(values))
        return cls(result_fingerprint=fingerprint, **values)

    def _validate_causal_chain(self) -> None:
        input_receipt = self.input_receipt
        request = input_receipt.request

        def receipt(value: object | None) -> PhaseReceipt | None:
            candidate = None if value is None else getattr(value, "receipt", None)
            if candidate is not None:
                if candidate.input_receipt != input_receipt:
                    raise OwnerEquityResearchError(
                        "phase receipt belongs to another owner-equity request"
                    )
                if candidate.input_receipt.request is not input_receipt.request:
                    raise OwnerEquityResearchError(
                        "phase receipt belongs to another execution of the same request"
                    )
            return candidate

        official = receipt(self.official_research)
        quarterly = receipt(self.quarterly)
        nonprice = receipt(self.futu_nonprice)
        price_blind = receipt(self.price_blind)
        market = receipt(self.market_reference)
        kernel = receipt(self.kernel)
        synthesis = receipt(self.synthesis)
        score = receipt(self.score)
        expectations = receipt(self.market_expectations)
        report = receipt(self.report)
        publication = receipt(self.publication)
        audit = receipt(self.audit)

        expected_upstreams: tuple[
            tuple[PhaseReceipt | None, tuple[PhaseReceipt | None, ...]], ...
        ] = (
            (official, ()),
            (quarterly, (official,)),
            (nonprice, (official,)),
            (price_blind, (official, nonprice)),
            (market, (price_blind, nonprice)),
            (kernel, (price_blind, market)),
            (synthesis, (price_blind, market, kernel)),
            (score, (synthesis,)),
            (expectations, (market, synthesis, score)),
            (
                report,
                (official,)
                if self.input_receipt.request.profile is PublicationProfile.RESEARCH_ONLY
                else (
                    official,
                    price_blind,
                    market,
                    kernel,
                    synthesis,
                    score,
                    expectations,
                ),
            ),
            (
                publication,
                ()
                if self.input_receipt.request.intent is ResearchIntent.PUBLISH
                else (
                    official,
                    price_blind,
                    kernel,
                    synthesis,
                    score,
                    expectations,
                    report,
                ),
            ),
            (audit, ()),
        )
        for current, upstream in expected_upstreams:
            if current is None:
                continue
            if any(item is None for item in upstream):
                raise OwnerEquityResearchError("phase receipt omits a required upstream phase")
            if len(current.upstream_receipts) != len(upstream) or any(
                actual is not expected
                for actual, expected in zip(
                    current.upstream_receipts,
                    upstream,
                    strict=True,
                )
            ):
                raise OwnerEquityResearchError("phase receipt causal upstreams were rebound")

        if official is not None:
            assert self.official_research is not None
            _require_exact_authorities(
                official,
                (
                    self.official_research.research_input,
                    self.official_research.source_index,
                    self.official_research.security_scope,
                ),
                label="official research",
            )
        if quarterly is not None:
            assert self.quarterly is not None
            _require_exact_authorities(
                quarterly,
                (self.quarterly.quarterly_result,),
                label="quarterly",
            )
        if nonprice is not None:
            assert self.futu_nonprice is not None
            _require_exact_authorities(
                nonprice,
                (
                    self.futu_nonprice.execution,
                    self.futu_nonprice.optional_data_dispositions,
                ),
                label="Futu nonprice",
            )
        if price_blind is not None:
            assert self.price_blind is not None
            _require_exact_authorities(
                price_blind,
                (self.price_blind.research_input, self.price_blind.price_blind_input),
                label="price-blind refreeze",
            )
        if market is not None:
            assert self.market_reference is not None
            _require_exact_authorities(
                market,
                (
                    self.market_reference.evidence_bundle,
                    self.market_reference.market_reference,
                ),
                label="Futu market reference",
            )
        if kernel is not None:
            assert self.kernel is not None
            _require_exact_authorities(
                kernel,
                (self.kernel.valuation_run, self.kernel.six_file_archive),
                label="valuation kernel",
            )
        if synthesis is not None:
            assert self.synthesis is not None
            _require_exact_authorities(
                synthesis,
                tuple(
                    item
                    for item in (
                        self.synthesis.mckinsey_panel,
                        self.synthesis.forward_reoi_panel,
                        self.synthesis.comparable_panel,
                        self.synthesis.composite_valuation,
                        self.synthesis.peer_evidence_set,
                    )
                    if item is not None
                ),
                label="valuation synthesis",
            )
        if score is not None:
            assert self.score is not None
            _require_exact_authorities(
                score,
                (self.score.lens_scores, self.score.scorecard),
                label="owner scorecard",
            )
        if expectations is not None:
            assert self.market_expectations is not None
            expectations_authorities: tuple[object, ...] = (
                (self.market_expectations.gap,)
                if self.market_expectations.gap is not None
                else (
                    self.market_expectations.session,
                    self.market_expectations.comparison,
                )
            )
            _require_exact_authorities(
                expectations,
                expectations_authorities,
                label="market expectations",
            )
        if report is not None:
            assert self.report is not None
            _require_exact_authorities(
                report,
                (self.report.report_build, self.report.report_build_receipt),
                label="report",
            )
        if publication is not None:
            assert self.publication is not None
            publication_authorities = (
                (
                    self.publication.source_package,
                    self.publication.published_package,
                    self.publication.publication_manifest,
                )
                if request.intent is ResearchIntent.PUBLISH
                else (
                    self.publication.published_package,
                    self.publication.publication_manifest,
                )
            )
            _require_exact_authorities(
                publication,
                publication_authorities,
                label="publication",
            )
        if audit is not None:
            assert self.audit is not None
            _require_exact_authorities(
                audit,
                (self.audit.audit_result,),
                label="audit",
            )

        official_phase = self.official_research
        nonprice_phase = self.futu_nonprice
        price_phase = self.price_blind
        market_phase = self.market_reference
        kernel_phase = self.kernel
        synthesis_phase = self.synthesis
        score_phase = self.score
        expectations_phase = self.market_expectations
        report_phase = self.report
        publication_phase = self.publication

        if price_phase is not None and price_phase.receipt is not None:
            if (
                official_phase is None
                or price_phase.research_input is not official_phase.research_input
            ):
                raise OwnerEquityResearchError(
                    "price-blind refreeze was rebound from official research"
                )

        if market_phase is not None and market_phase.receipt is not None:
            provider = market_phase.market_reference
            evidence = market_phase.evidence_bundle
            if (
                type(provider) is not FutuMarketReferenceProvider
                or type(evidence) is not FutuMarketExecutionEvidence
                or provider.market_execution_evidence is not evidence
                or price_phase is None
                or price_phase.price_blind_input is None
                or provider.ticket.expected_freeze_result.fingerprint
                != price_phase.price_blind_input.fingerprint
                or nonprice_phase is None
                or nonprice_phase.execution is None
                or not evidence.executions
                or evidence.executions[0] is not nonprice_phase.execution
            ):
                raise OwnerEquityResearchError(
                    "Futu market phase was rebound from its nonprice or freeze authority"
                )

        if kernel_phase is not None and kernel_phase.receipt is not None:
            run = kernel_phase.valuation_run
            provider = None if market_phase is None else market_phase.market_reference
            if (
                type(run) is not ValuationRunResult
                or type(provider) is not FutuMarketReferenceProvider
                or price_phase is None
                or price_phase.price_blind_input is None
                or run.input_receipt.expected_freeze.fingerprint
                != price_phase.price_blind_input.fingerprint
                or run.input_receipt.graph is not provider.ticket.contract_graph
                or run.input_receipt.expected_security
                is not provider.ticket.expected_security_result
                or run.preparation is None
                or run.preparation.prepared_market_reference is None
            ):
                raise OwnerEquityResearchError(
                    "kernel phase was rebound from its freeze or market authority"
                )
            contexts = (
                run.preparation.prepared_market_reference.graph
                .market_reference_validation_contexts
            )
            acquisition = (
                None
                if len(contexts) != 1
                else contexts[0].vendor_market_acquisition
            )
            if (
                acquisition is None
                or acquisition.ticket is not provider.ticket
                or acquisition.market_execution_evidence
                is not market_phase.evidence_bundle
            ):
                raise OwnerEquityResearchError(
                    "kernel market acquisition was rebound from the admitted provider"
                )

        if synthesis_phase is not None and synthesis_phase.receipt is not None:
            if (
                kernel_phase is None
                or synthesis_phase.mckinsey_panel is not kernel_phase.valuation_run
                or price_phase is None
                or price_phase.price_blind_input is None
                or synthesis_phase.peer_evidence_set is None
                or synthesis_phase.peer_evidence_set.price_blind_freeze.fingerprint
                != price_phase.price_blind_input.fingerprint
            ):
                raise OwnerEquityResearchError(
                    "valuation synthesis was rebound from kernel or freeze authority"
                )

        if score_phase is not None and score_phase.receipt is not None:
            composite = (
                None if synthesis_phase is None else synthesis_phase.composite_valuation
            )
            scorecard = score_phase.scorecard
            if (
                composite is None
                or type(scorecard) is not OwnerScorecard
                or scorecard._composite_authority is not composite
                or len(scorecard._score_authorities) != len(score_phase.lens_scores)
                or any(
                    actual is not expected
                    for actual, expected in zip(
                        scorecard._score_authorities,
                        score_phase.lens_scores,
                        strict=True,
                    )
                )
                or any(
                    item._composite_authority is not composite
                    for item in score_phase.lens_scores
                )
            ):
                raise OwnerEquityResearchError(
                    "owner scorecard was rebound from synthesis authority"
                )

        if expectations_phase is not None and expectations_phase.receipt is not None:
            composite = (
                None if synthesis_phase is None else synthesis_phase.composite_valuation
            )
            scorecard = None if score_phase is None else score_phase.scorecard
            if expectations_phase.session is not None:
                session = expectations_phase.session
                comparison = expectations_phase.comparison
                if (
                    type(comparison) is not MarketExpectationsComparison
                    or comparison.session is not session
                    or comparison.composite_valuation is not composite
                    or comparison.owner_scorecard is not scorecard
                    or market_phase is None
                    or session.market_execution_evidence
                    is not market_phase.evidence_bundle
                    or synthesis_phase is None
                    or session.peer_evidence_set
                    is not synthesis_phase.peer_evidence_set
                    or session.frozen_conclusion.composite_valuation is not composite
                    or session.frozen_conclusion.owner_scorecard is not scorecard
                ):
                    raise OwnerEquityResearchError(
                        "market expectations were rebound from the frozen conclusion"
                    )
            else:
                gap = expectations_phase.gap
                if (
                    type(gap) is not RuntimeGapReceipt
                    or gap.composite_valuation is not composite
                    or gap.owner_scorecard is not scorecard
                ):
                    raise OwnerEquityResearchError(
                        "market expectations gap was rebound from its conclusion"
                    )

        if report_phase is not None and report_phase.receipt is not None:
            build = report_phase.report_build
            if (
                type(build) is not ReportBuildResult
                or official_phase is None
                or build.research_source_index is not official_phase.source_index
            ):
                raise OwnerEquityResearchError(
                    "report was rebound from official research authority"
                )
            if report_phase.profile is PublicationProfile.FULL_VALUATION:
                if (
                    nonprice_phase is None
                    or kernel_phase is None
                    or synthesis_phase is None
                    or score_phase is None
                    or expectations_phase is None
                    or build.forward_reoi is not synthesis_phase.forward_reoi_panel
                    or build.comparable_valuation is not synthesis_phase.comparable_panel
                    or build.composite_valuation is not synthesis_phase.composite_valuation
                    or build.owner_scorecard is not score_phase.scorecard
                    or len(build.score_v2) != len(score_phase.lens_scores)
                    or any(
                        actual is not expected
                        for actual, expected in zip(
                            build.score_v2,
                            score_phase.lens_scores,
                            strict=True,
                        )
                    )
                    or len(build.futu_optional_data_dispositions)
                    != len(nonprice_phase.optional_data_dispositions)
                    or any(
                        actual is not expected
                        for actual, expected in zip(
                            build.futu_optional_data_dispositions,
                            nonprice_phase.optional_data_dispositions,
                            strict=True,
                        )
                    )
                    or build.receipt["valuation_archive_fingerprint"]
                    != kernel_phase.six_file_archive.fingerprint
                ):
                    raise OwnerEquityResearchError(
                        "full report was rebound from valuation or scoring authority"
                    )
                if expectations_phase.session is not None:
                    if (
                        build.futu_session_evidence is not expectations_phase.session
                        or build.market_expectations is not expectations_phase.comparison
                    ):
                        raise OwnerEquityResearchError(
                            "full report was rebound from post-context authority"
                        )
                elif (
                    build.runtime_gap is not expectations_phase.gap
                    or market_phase is None
                    or build.futu_market_execution_evidence
                    is not market_phase.evidence_bundle
                    or build.futu_peer_evidence_set
                    is not synthesis_phase.peer_evidence_set
                ):
                    raise OwnerEquityResearchError(
                        "partial report was rebound from its runtime gap"
                    )

        if publication_phase is not None and publication_phase.receipt is not None:
            package = publication_phase.published_package
            manifest = publication_phase.publication_manifest
            if request.intent is ResearchIntent.PUBLISH:
                source = publication_phase.source_package
                if (
                    type(source) is not PublishedResearchPackage
                    or type(package) is not PublishedResearchPackage
                    or type(manifest) is not PublicationManifest
                    or package.publication_manifest is not manifest
                    or source.profile != package.profile
                    or source.publication_manifest != manifest
                    or source.package_receipt != package.package_receipt
                    or dict(source.file_bytes) != dict(package.file_bytes)
                    or dict(source.file_sha256) != dict(package.file_sha256)
                    or package.profile != request.profile.value
                    or package.report.issuer_id != request.issuer_id
                    or package.report.data_cutoff_date != request.data_cutoff_date
                ):
                    raise OwnerEquityResearchError(
                        "existing-only publication rebound its strict package"
                    )
            report_build = None if report_phase is None else report_phase.report_build
            official_bundle = (
                None if official_phase is None else official_phase.research_bundle
            )
            if request.intent is not ResearchIntent.PUBLISH and (
                type(package) is not PublishedResearchPackage
                or type(manifest) is not PublicationManifest
                or package.publication_manifest is not manifest
                or report_build is None
                or package.report.fingerprint != report_build.fingerprint
                or official_bundle is None
                or package.research.bundle.fingerprint
                != official_bundle.bundle.fingerprint
                or package.research.run_manifest.fingerprint
                != official_bundle.run_manifest.fingerprint
            ):
                raise OwnerEquityResearchError(
                    "publication was rebound from report or research authority"
                )
            if (
                request.intent is not ResearchIntent.PUBLISH
                and publication_phase.profile is PublicationProfile.FULL_VALUATION
            ):
                if (
                    kernel_phase is None
                    or synthesis_phase is None
                    or score_phase is None
                    or expectations_phase is None
                    or package.valuation is None
                    or package.valuation.fingerprint
                    != kernel_phase.six_file_archive.fingerprint
                    or manifest["forward_reoi_fingerprint"]
                    != (
                        None
                        if synthesis_phase.forward_reoi_panel is None
                        else synthesis_phase.forward_reoi_panel.fingerprint
                    )
                    or manifest["comparable_valuation_fingerprint"]
                    != (
                        None
                        if synthesis_phase.comparable_panel is None
                        else synthesis_phase.comparable_panel.fingerprint
                    )
                    or manifest["composite_valuation_fingerprint"]
                    != synthesis_phase.composite_valuation.fingerprint
                    or manifest["score_v2_fingerprints"]
                    != tuple(sorted(item.fingerprint for item in score_phase.lens_scores))
                    or manifest["owner_scorecard_fingerprint"]
                    != score_phase.scorecard.fingerprint
                ):
                    raise OwnerEquityResearchError(
                        "publication manifest was rebound from downstream authority"
                    )
                expected_context = (
                    expectations_phase.session.fingerprint
                    if expectations_phase.session is not None
                    else None
                )
                expected_gap = (
                    expectations_phase.gap.fingerprint
                    if expectations_phase.gap is not None
                    else None
                )
                if (
                    manifest["futu_session_evidence_fingerprint"] != expected_context
                    or manifest["runtime_gap_fingerprint"] != expected_gap
                ):
                    raise OwnerEquityResearchError(
                        "publication manifest was rebound from market expectations"
                    )

        request = input_receipt.request
        allowed = _closed_route(request)
        actual = tuple(item.phase for item in self.trace)
        if actual != allowed[: len(actual)] or len(actual) != len(set(actual)):
            raise OwnerEquityResearchError("execution trace is not a closed route prefix")
        phase_by_name = {
            "official_research_freeze": self.official_research,
            "quarterly": self.quarterly,
            "futu_nonprice_verification": self.futu_nonprice,
            "price_blind_refreeze": self.price_blind,
            "futu_market_reference": self.market_reference,
            "owner_valuation_kernel": self.kernel,
            "three_panel_synthesis": self.synthesis,
            "owner_scorecard": self.score,
            "futu_market_expectations": self.market_expectations,
            "report": self.report,
            "publication": self.publication,
            "audit": self.audit,
        }
        for step in self.trace:
            phase = phase_by_name[step.phase]
            if phase is not None and step.status is not phase.status:
                raise OwnerEquityResearchError("trace status differs from its exact phase")

        if self.market_reference is not None and self.market_expectations is not None:
            provider = self.market_reference.market_reference
            if type(provider) is FutuMarketReferenceProvider:
                verifier = provider.verifier
                if self.market_expectations.session is not None:
                    validate_futu_session_evidence_replay(
                        self.market_expectations.session,
                        verifier=verifier,
                    )
                elif (
                    self.market_expectations.gap is not None
                    and self.synthesis is not None
                    and self.synthesis.peer_evidence_set is not None
                ):
                    authority_set = self.market_reference.evidence_bundle.authority_set
                    supply = authority_set.supply_chain
                    runtime_authorization = authority_set.runtime_authorization
                    if supply is None or runtime_authorization is None:
                        raise OwnerEquityResearchError(
                            "gap finalization lacks pre-run Futu authority"
                        )
                    validate_futu_attested_session_finalization(
                        self.market_expectations.gap.attested_finalization,
                        expected_executions=(
                            *self.market_reference.evidence_bundle.executions,
                            *(
                                item.execution
                                for item in self.synthesis.peer_evidence_set.peers
                            ),
                        ),
                        supply_chain=supply,
                        runtime_authorization=runtime_authorization,
                        verifier=verifier,
                    )

    def _validate_route(self) -> None:
        request = self.input_receipt.request
        if request.intent is ResearchIntent.AUDIT:
            crossed_capability = any(
                value is not None
                for value in (
                    self.official_research,
                    self.quarterly,
                    self.futu_nonprice,
                    self.price_blind,
                    self.market_reference,
                    self.kernel,
                    self.synthesis,
                    self.score,
                    self.market_expectations,
                    self.report,
                    self.publication,
                )
            )
            if crossed_capability or (
                self.audit is None and self.status is not PhaseStatus.BLOCKED
            ):
                raise OwnerEquityResearchError("audit route crossed a non-audit capability")
            return
        if request.intent is ResearchIntent.PUBLISH:
            crossed_capability = any(
                value is not None
                for value in (
                    self.official_research,
                    self.quarterly,
                    self.futu_nonprice,
                    self.price_blind,
                    self.market_reference,
                    self.kernel,
                    self.synthesis,
                    self.score,
                    self.market_expectations,
                    self.report,
                    self.audit,
                )
            )
            if crossed_capability or (
                self.publication is None and self.status is not PhaseStatus.BLOCKED
            ):
                raise OwnerEquityResearchError(
                    "existing-only publication crossed a non-publication capability"
                )
            if self.publication is not None and self.publication.profile is not request.profile:
                raise OwnerEquityResearchError(
                    "publication profile differs from the typed request"
                )
            return
        if self.official_research is None:
            if self.status is not PhaseStatus.BLOCKED:
                raise OwnerEquityResearchError("non-audit result lacks official research")
            return
        if self.report is not None and self.report.profile is not request.profile:
            raise OwnerEquityResearchError("report profile differs from the typed request")
        if self.publication is not None and self.publication.profile is not request.profile:
            raise OwnerEquityResearchError("publication profile differs from the typed request")
        price_blind_only = request.intent in {
            ResearchIntent.RESEARCH,
            ResearchIntent.QUARTERLY,
            ResearchIntent.REPORT,
        }
        if price_blind_only and any(
            value is not None
            for value in (
                self.futu_nonprice,
                self.price_blind,
                self.market_reference,
                self.kernel,
                self.synthesis,
                self.score,
                self.market_expectations,
            )
        ):
            raise OwnerEquityResearchError("price-blind route crossed a Futu or valuation phase")
        if self.status in {PhaseStatus.COMPLETED, PhaseStatus.CONTESTED}:
            if request.intent is ResearchIntent.QUARTERLY and self.quarterly is None:
                raise OwnerEquityResearchError("completed quarterly route lacks its result")
            if request.intent is ResearchIntent.REPORT and self.report is None:
                raise OwnerEquityResearchError("completed report route lacks its report")
            if request.intent is ResearchIntent.VALUATION and self.publication is None:
                raise OwnerEquityResearchError("completed publish route lacks its package")
            full = request.intent is ResearchIntent.VALUATION
            if full and any(
                value is None
                for value in (
                    self.futu_nonprice,
                    self.price_blind,
                    self.market_reference,
                    self.kernel,
                    self.synthesis,
                    self.score,
                    self.market_expectations,
                    self.report,
                    self.publication,
                )
            ):
                raise OwnerEquityResearchError("completed valuation route lacks a required phase")
            if self.status is PhaseStatus.CONTESTED and (
                self.synthesis is None
                or self.synthesis.status is not PhaseStatus.CONTESTED
                or self.score is None
                or self.effective_recommendation != _UNRATED_RECOMMENDATION
            ):
                raise OwnerEquityResearchError("contested result must remain unrated")
        full = request.intent is ResearchIntent.VALUATION
        if self.status is PhaseStatus.PARTIAL and full:
            if any(
                value is None
                for value in (
                    self.futu_nonprice,
                    self.price_blind,
                    self.market_reference,
                    self.kernel,
                    self.synthesis,
                    self.score,
                    self.market_expectations,
                    self.report,
                )
            ):
                raise OwnerEquityResearchError(
                    "partial valuation must retain its downstream gap report"
                )
            if self.effective_recommendation != _UNRATED_RECOMMENDATION:
                raise OwnerEquityResearchError("partial valuation must remain unrated")
            if self.publication is None:
                raise OwnerEquityResearchError(
                    "partial valuation route lacks its audit package"
                )

    @property
    def futu_evidence_bundle(
        self,
    ) -> FutuSessionEvidence | FutuMarketExecutionEvidence | FutuEvidenceBundle | None:
        if (
            self.market_expectations is not None
            and self.market_expectations.session is not None
        ):
            return self.market_expectations.session
        if self.market_reference is not None:
            return self.market_reference.evidence_bundle
        if self.futu_nonprice is not None:
            return self.futu_nonprice.evidence_bundle
        return None

    @property
    def futu_market_evidence(self) -> FutuMarketExecutionEvidence | None:
        return (
            None if self.market_reference is None else self.market_reference.evidence_bundle
        )

    @property
    def futu_optional_data_dispositions(
        self,
    ) -> tuple[FutuOptionalDataDisposition, ...]:
        return (
            ()
            if self.futu_nonprice is None
            else self.futu_nonprice.optional_data_dispositions
        )

    @property
    def post_context_evidence_or_gap(
        self,
    ) -> FutuSessionEvidence | RuntimeGapReceipt | None:
        return (
            None
            if self.market_expectations is None
            else self.market_expectations.evidence_bundle
        )

    @property
    def six_file_archive(self) -> ValuationRunArchive | None:
        return self.kernel.six_file_archive if self.kernel is not None else None

    @property
    def valuation_run_result(self) -> ValuationRunResult | None:
        return self.kernel.valuation_run if self.kernel is not None else None

    @property
    def mckinsey_panel(self) -> ValuationRunResult | None:
        return self.synthesis.mckinsey_panel if self.synthesis is not None else None

    @property
    def forward_reoi_panel(self) -> ForwardReOIValuationResult | None:
        return self.synthesis.forward_reoi_panel if self.synthesis is not None else None

    @property
    def comparable_panel(self) -> ComparableValuationResult | None:
        return self.synthesis.comparable_panel if self.synthesis is not None else None

    @property
    def composite_valuation(self) -> CompositeValuationResult | None:
        return self.synthesis.composite_valuation if self.synthesis is not None else None

    @property
    def scorecard(self) -> OwnerScorecard | None:
        return self.score.scorecard if self.score is not None else None

    @property
    def report_build_receipt(self) -> ReportBuildReceipt | None:
        return self.report.report_build_receipt if self.report is not None else None

    @property
    def report_build(self) -> ReportBuildResult | None:
        return self.report.report_build if self.report is not None else None

    @property
    def publication_manifest(self) -> PublicationManifest | None:
        return self.publication.publication_manifest if self.publication is not None else None

    @property
    def published_package(self) -> PublishedResearchPackage | None:
        return self.publication.published_package if self.publication is not None else None

    @property
    def result_id(self) -> str:
        return (
            f"owner-equity-research-result:{self.input_receipt.request.issuer_id}:"
            f"{self.result_fingerprint[:24]}"
        )

    def to_dict(self) -> dict[str, object]:
        values = {
            name: getattr(self, name)
            for name in (
                "status",
                "effective_recommendation",
                "input_receipt",
                *_RESULT_PHASE_FIELDS,
                "quarantine_receipt",
                "trace",
                "issue_codes",
            )
        }
        return {
            **_result_identity_payload(values),
            "result_id": self.result_id,
            "result_fingerprint": self.result_fingerprint,
        }

    def summary(self) -> dict[str, Any]:
        """Return a bounded, credential-free CLI projection."""

        request = self.input_receipt.request
        return {
            "schema_version": "1.0.0",
            "artifact_type": "owner-equity-research-run-summary",
            "status": self.status.value,
            "effective_recommendation": self.effective_recommendation,
            "issuer_id": request.issuer_id,
            "data_cutoff_date": request.data_cutoff_date,
            "intent": request.intent.value,
            "profile": request.profile.value if request.profile is not None else None,
            "input_receipt_id": self.input_receipt.receipt_id,
            "result_id": self.result_id,
            "result_fingerprint": self.result_fingerprint,
            "quarantine_receipt_id": (
                None if self.quarantine_receipt is None else self.quarantine_receipt.receipt_id
            ),
            "phases": [
                {"sequence": item.sequence, "phase": item.phase, "status": item.status.value}
                for item in self.trace
            ],
            "issue_codes": list(self.issue_codes),
        }


@dataclass(frozen=True, slots=True)
class _PhaseFailure(Exception):
    phase: str
    code: str


def run_owner_equity_research(
    *,
    request: OwnerEquityResearchRequest,
    dependencies: OwnerEquityResearchDependencies,
) -> OwnerEquityResearchResult:
    """Run one closed intent route and return all admitted typed downstream objects.

    The only market-enabled route is explicit ``valuation``.  ``publish`` consumes an
    already strict-reloaded package and cannot cross research, Futu, kernel, scoring, or
    report-build capabilities.  The low-level valuation dependency appears exactly once
    and is never retried by this orchestrator.
    """

    if type(request) is not OwnerEquityResearchRequest:
        raise OwnerEquityResearchError("run requires the exact typed request")
    if type(dependencies) is not OwnerEquityResearchDependencies:
        raise OwnerEquityResearchError("run requires the exact dependency record")
    if dependencies.intent is not request.intent or dependencies.profile is not request.profile:
        raise OwnerEquityResearchError("dependency route differs from the typed request")
    input_receipt = OwnerEquityResearchInputReceipt.from_request(request)
    trace: list[ExecutionStepReceipt] = []
    official: OfficialResearchPhaseResult | None = None
    quarterly: QuarterlyPhaseResult | None = None
    nonprice: FutuNonPricePhaseResult | None = None
    price_blind: PriceBlindRefreezePhaseResult | None = None
    market: FutuMarketReferencePhaseResult | None = None
    kernel: KernelValuationPhaseResult | None = None
    synthesis: SynthesisPhaseResult | None = None
    score: ScorePhaseResult | None = None
    expectations: MarketExpectationsPhaseResult | None = None
    report: ReportPhaseResult | None = None
    publication: PublicationPhaseResult | None = None
    audit: AuditPhaseResult | None = None
    quarantine_receipt: QuarantineReceipt | None = None

    def finish(status: PhaseStatus, issues: tuple[str, ...] = ()) -> OwnerEquityResearchResult:
        return OwnerEquityResearchResult.create(
            status=status,
            input_receipt=input_receipt,
            official_research=official,
            quarterly=quarterly,
            futu_nonprice=nonprice,
            price_blind=price_blind,
            market_reference=market,
            kernel=kernel,
            synthesis=synthesis,
            score=score,
            market_expectations=expectations,
            report=report,
            publication=publication,
            audit=audit,
            quarantine_receipt=quarantine_receipt,
            trace=tuple(trace),
            issue_codes=issues,
        )

    def quarantine_after_kernel(
        phase: str,
        issues: tuple[str, ...],
    ) -> OwnerEquityResearchResult:
        nonlocal nonprice, price_blind, market, kernel
        nonlocal synthesis, score, expectations, report, publication, quarantine_receipt

        _ = issues
        normalized = (f"{phase}_blocked",)
        if kernel is not None:
            try:
                quarantine_receipt = QuarantineReceipt.from_kernel(
                    phase=phase,
                    kernel=kernel,
                    issue_codes=normalized,
                )
            except (OSError, TypeError, ValueError):
                normalized = _issues(
                    (f"{phase}_blocked", "quarantine_receipt_unavailable")
                )
        normalized = _issues((*normalized, f"valuation_outputs_quarantined:{phase}"))
        nonprice = None
        price_blind = None
        market = None
        kernel = None
        synthesis = None
        score = None
        expectations = None
        report = None
        publication = None
        return finish(PhaseStatus.BLOCKED, normalized)

    def invoke(
        phase: str,
        function: Callable[..., object],
        expected_type: type[object],
        *args: object,
    ) -> object:
        try:
            value = function(*args)
        except Exception as exc:  # adapters may fail; do not leak messages or retry
            trace.append(
                ExecutionStepReceipt(
                    sequence=len(trace) + 1,
                    phase=phase,
                    status=PhaseStatus.BLOCKED,
                )
            )
            raise _PhaseFailure(phase, f"{phase}_blocked") from exc
        if type(value) is not expected_type:
            trace.append(
                ExecutionStepReceipt(
                    sequence=len(trace) + 1,
                    phase=phase,
                    status=PhaseStatus.BLOCKED,
                )
            )
            raise _PhaseFailure(phase, f"{phase}_blocked:wrong_result_type")
        if (
            value.issuer_id != request.issuer_id
            or value.data_cutoff_date != request.data_cutoff_date
        ):
            trace.append(
                ExecutionStepReceipt(
                    sequence=len(trace) + 1,
                    phase=phase,
                    status=PhaseStatus.BLOCKED,
                )
            )
            raise _PhaseFailure(phase, f"{phase}_blocked:identity_mismatch")
        trace.append(
            ExecutionStepReceipt(
                sequence=len(trace) + 1,
                phase=phase,
                status=value.status,
            )
        )
        return value

    def stop(
        phase: object,
        *,
        preserve_partial: bool = False,
    ) -> OwnerEquityResearchResult | None:
        phase_status = phase.status
        continuing = {PhaseStatus.COMPLETED, PhaseStatus.CONTESTED}
        if preserve_partial:
            continuing.add(PhaseStatus.PARTIAL)
        if phase_status in continuing:
            return None
        return finish(phase_status, phase.issue_codes)

    def mark_last_blocked(phase: str) -> None:
        trace[-1] = ExecutionStepReceipt(
            sequence=trace[-1].sequence,
            phase=phase,
            status=PhaseStatus.BLOCKED,
        )

    try:
        if request.intent is ResearchIntent.AUDIT:
            audit = invoke("audit", dependencies.audit, AuditPhaseResult, request)  # type: ignore[assignment]
            return finish(audit.status, audit.issue_codes)

        if request.intent is ResearchIntent.PUBLISH:
            source = dependencies.publication_source
            if (
                type(source) is not PublishedResearchPackage
                or source.profile != request.profile.value
                or source.report.issuer_id != request.issuer_id
                or source.report.data_cutoff_date != request.data_cutoff_date
            ):
                trace.append(
                    ExecutionStepReceipt(
                        sequence=len(trace) + 1,
                        phase="publication",
                        status=PhaseStatus.BLOCKED,
                    )
                )
                return finish(PhaseStatus.BLOCKED, ("publication_blocked",))
            publication = invoke(
                "publication",
                dependencies.publish,
                PublicationPhaseResult,
                PublicationInput(
                    request=request,
                    profile=request.profile,
                    official_research=None,
                    report=None,
                    price_blind=None,
                    kernel=None,
                    synthesis=None,
                    score=None,
                    market_expectations=None,
                    existing_only=True,
                    source_package=source,
                ),
            )  # type: ignore[assignment]
            if publication.source_package is not source:
                mark_last_blocked("publication")
                publication = None
                return finish(PhaseStatus.BLOCKED, ("publication_blocked",))
            return finish(publication.status, publication.issue_codes)

        official = invoke(
            "official_research_freeze",
            dependencies.official_research,
            OfficialResearchPhaseResult,
            request,
        )  # type: ignore[assignment]
        specialist_issue = (
            None
            if official.security_scope is None
            else official.security_scope.specialist_issue
        )
        if specialist_issue is not None:
            return finish(PhaseStatus.SPECIALIST_REQUIRED, (specialist_issue,))
        stopped = stop(official)
        if stopped is not None:
            return stopped

        if request.intent is ResearchIntent.RESEARCH:
            return finish(PhaseStatus.COMPLETED)

        if request.intent is ResearchIntent.QUARTERLY:
            quarterly = invoke(
                "quarterly",
                dependencies.quarterly,
                QuarterlyPhaseResult,
                request,
                official,
            )  # type: ignore[assignment]
            return finish(quarterly.status, quarterly.issue_codes)

        if request.intent is ResearchIntent.REPORT:
            report = invoke(
                "report",
                dependencies.build_report,
                ReportPhaseResult,
                ReportBuildInput(
                    request=request,
                    profile=PublicationProfile.RESEARCH_ONLY,
                    official_research=official,
                    price_blind=None,
                    market_reference=None,
                    kernel=None,
                    synthesis=None,
                    score=None,
                    market_expectations=None,
                ),
            )  # type: ignore[assignment]
            if report.profile is not PublicationProfile.RESEARCH_ONLY:
                mark_last_blocked("report")
                report = None
                return finish(PhaseStatus.BLOCKED, ("report_blocked",))
            stopped = stop(report)
            if stopped is not None:
                return stopped
            return finish(PhaseStatus.COMPLETED)

        nonprice = invoke(
            "futu_nonprice_verification",
            dependencies.futu_nonprice,
            FutuNonPricePhaseResult,
            NonPriceVerificationInput(request=request, official_research=official),
        )  # type: ignore[assignment]
        stopped = stop(nonprice)
        if stopped is not None:
            return stopped
        price_blind = invoke(
            "price_blind_refreeze",
            dependencies.refreeze_price_blind,
            PriceBlindRefreezePhaseResult,
            PriceBlindRefreezeInput(
                request=request,
                official_research=official,
                futu_nonprice=nonprice,
            ),
        )  # type: ignore[assignment]
        stopped = stop(price_blind)
        if stopped is not None:
            return stopped
        market = invoke(
            "futu_market_reference",
            dependencies.futu_market_reference,
            FutuMarketReferencePhaseResult,
            MarketReferenceInput(
                request=request,
                price_blind=price_blind,
                futu_nonprice=nonprice,
            ),
        )  # type: ignore[assignment]
        stopped = stop(market)
        if stopped is not None:
            return stopped
        kernel = invoke(
            "owner_valuation_kernel",
            dependencies.run_owner_valuation,
            KernelValuationPhaseResult,
            KernelValuationInput(
                request=request,
                price_blind=price_blind,
                market_reference=market,
            ),
        )  # type: ignore[assignment]
        stopped = stop(kernel)
        if stopped is not None:
            return stopped
        synthesis = invoke(
            "three_panel_synthesis",
            dependencies.synthesize,
            SynthesisPhaseResult,
            SynthesisInput(
                request=request,
                price_blind=price_blind,
                market_reference=market,
                kernel=kernel,
            ),
        )  # type: ignore[assignment]
        stopped = stop(synthesis, preserve_partial=True)
        if stopped is not None:
            return quarantine_after_kernel("three_panel_synthesis", synthesis.issue_codes)
        score = invoke(
            "owner_scorecard",
            dependencies.score,
            ScorePhaseResult,
            ScoringInput(
                request=request,
                price_blind=price_blind,
                synthesis=synthesis,
            ),
        )  # type: ignore[assignment]
        stopped = stop(score, preserve_partial=True)
        if stopped is not None:
            return quarantine_after_kernel("owner_scorecard", score.issue_codes)
        if synthesis.status is PhaseStatus.CONTESTED and score.recommendation != "无法评级":
            return quarantine_after_kernel(
                "owner_scorecard",
                ("contested_synthesis_requires_unrated_scorecard",),
            )
        expectations = invoke(
            "futu_market_expectations",
            dependencies.futu_market_expectations,
            MarketExpectationsPhaseResult,
            MarketExpectationsInput(
                request=request,
                price_blind=price_blind,
                market_reference=market,
                synthesis=synthesis,
                score=score,
            ),
        )  # type: ignore[assignment]
        stopped = stop(expectations, preserve_partial=True)
        if stopped is not None:
            return quarantine_after_kernel(
                "futu_market_expectations",
                expectations.issue_codes,
            )
        report = invoke(
            "report",
            dependencies.build_report,
            ReportPhaseResult,
            ReportBuildInput(
                request=request,
                profile=PublicationProfile.FULL_VALUATION,
                official_research=official,
                price_blind=price_blind,
                market_reference=market,
                kernel=kernel,
                synthesis=synthesis,
                score=score,
                market_expectations=expectations,
            ),
        )  # type: ignore[assignment]
        if report.profile is not PublicationProfile.FULL_VALUATION:
            mark_last_blocked("report")
            report = None
            return quarantine_after_kernel(
                "report",
                ("report_blocked",),
            )
        stopped = stop(report, preserve_partial=True)
        if stopped is not None:
            return quarantine_after_kernel("report", report.issue_codes)
        downstream = (synthesis, score, expectations, report)
        final_status = (
            PhaseStatus.CONTESTED
            if synthesis.status is PhaseStatus.CONTESTED
            else PhaseStatus.PARTIAL
            if any(item.status is PhaseStatus.PARTIAL for item in downstream)
            else PhaseStatus.COMPLETED
        )
        final_issues = tuple(
            sorted(
                {
                    issue
                    for item in downstream
                    if item.status is not PhaseStatus.COMPLETED
                    for issue in item.issue_codes
                }
            )
        )
        publication = invoke(
            "publication",
            dependencies.publish,
            PublicationPhaseResult,
            PublicationInput(
                request=request,
                profile=PublicationProfile.FULL_VALUATION,
                official_research=official,
                report=report,
                price_blind=price_blind,
                kernel=kernel,
                synthesis=synthesis,
                score=score,
                market_expectations=expectations,
                existing_only=False,
                source_package=None,
            ),
        )  # type: ignore[assignment]
        if publication.profile is not PublicationProfile.FULL_VALUATION:
            mark_last_blocked("publication")
            publication = None
            return quarantine_after_kernel(
                "publication",
                ("publication_blocked",),
            )
        stopped = stop(publication, preserve_partial=True)
        if stopped is not None:
            return quarantine_after_kernel("publication", publication.issue_codes)
        if (
            publication.status is PhaseStatus.PARTIAL
            and final_status is not PhaseStatus.CONTESTED
        ):
            final_status = PhaseStatus.PARTIAL
            final_issues = tuple(sorted({*final_issues, *publication.issue_codes}))
        return finish(final_status, final_issues)
    except _PhaseFailure as exc:
        if kernel is not None and exc.phase in {
            "three_panel_synthesis",
            "owner_scorecard",
            "futu_market_expectations",
            "report",
            "publication",
        }:
            return quarantine_after_kernel(exc.phase, (exc.code,))
        return finish(PhaseStatus.BLOCKED, (exc.code,))
    finally:
        try:
            dependencies.cleanup()
        except Exception as exc:
            raise OwnerEquityResearchError("runtime cleanup failed") from exc


__all__ = (
    "AuditPhaseResult",
    "ExecutionStepReceipt",
    "FutuMarketReferencePhaseResult",
    "FutuNonPricePhaseResult",
    "KernelValuationInput",
    "KernelValuationPhaseResult",
    "MarketExpectationsInput",
    "MarketExpectationsPhaseResult",
    "MarketReferenceInput",
    "NonPriceVerificationInput",
    "OfficialResearchPhaseResult",
    "OwnerEquityResearchDependencies",
    "OwnerEquityResearchError",
    "OwnerEquityResearchInputReceipt",
    "OwnerEquityResearchRequest",
    "OwnerEquityResearchResult",
    "PhaseReceipt",
    "PhaseStatus",
    "PriceBlindRefreezeInput",
    "PriceBlindRefreezePhaseResult",
    "PublicationInput",
    "PublicationPhaseResult",
    "PublicationProfile",
    "QuarantineReceipt",
    "QuarterlyPhaseResult",
    "ReportBuildInput",
    "ReportPhaseResult",
    "ResearchIntent",
    "ScorePhaseResult",
    "ScoringInput",
    "SecurityScope",
    "SynthesisInput",
    "SynthesisPhaseResult",
    "load_owner_equity_research_schema",
    "run_owner_equity_research",
    "validate_owner_equity_research_result_projection",
    "validate_owner_equity_research_schema_payload",
)
