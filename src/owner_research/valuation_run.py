"""Explicit owner-valuation orchestration ending in the strict six-file archive."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze, to_json_value
from .validation import ContractGraph
from .valuation_assumption_candidates import compile_valuation_assumption_candidates
from .valuation_assumption_types import (
    AssumptionCandidateCompilationResult,
    AssumptionCandidateProposal,
    AssumptionReviewRequest,
)
from .valuation_kernel_materializer import (
    MANIFEST_POLICY_ID,
    MANIFEST_POLICY_VERSION,
    KernelMaterializationError,
    load_and_verify_runtime_manifest,
)
from .valuation_market_execution_policies import (
    PINNED_KERNEL_COMMIT,
    PINNED_KERNEL_PACKAGE_VERSION,
    PINNED_KERNEL_PLUGIN_VERSION,
    PINNED_KERNEL_REPOSITORY,
    PINNED_KERNEL_SCHEMA_SHA256,
    PINNED_KERNEL_TAG,
    PINNED_KERNEL_WHEEL_SHA256,
)
from .valuation_market_provider import MarketReferenceProvider, RunClock
from .valuation_owner_execution import (
    OwnerValuationExecutionClock,
    OwnerValuationExecutionResult,
    execute_owner_valuation,
)
from .valuation_owner_preparation import (
    OwnerValuationPreparationResult,
    prepare_owner_valuation,
)
from .valuation_price_blind_freeze import PriceBlindFreezeCompilationResult
from .valuation_run_archive import (
    VALUATION_RUN_ARCHIVE_FILENAMES,
    ValuationRunArchive,
    _project_verified_runtime_manifest_authority,
    load_valuation_run_archive,
    write_valuation_run_archive,
)
from .valuation_security_identity import SecurityIdentityCompilationResult


class ValuationRunError(ValueError):
    """The explicit valuation run lacks closed, replayable authority."""


_HEX = frozenset("0123456789abcdef")
_RUNTIME_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "manifest_policy_id",
        "manifest_policy_version",
        "authority",
        "producer",
        "kernel",
        "target",
        "container",
        "trusted_workflow",
        "result_schema",
        "transport",
        "wheels",
        "manifest_fingerprint",
    }
)


def _checked_sha256(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 64 or set(value) - _HEX:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


@dataclass(frozen=True, slots=True)
class ValuationRunClock:
    market: RunClock
    execution: OwnerValuationExecutionClock

    def __post_init__(self) -> None:
        if (
            type(self.market) is not RunClock
            or type(self.execution) is not OwnerValuationExecutionClock
        ):
            raise ValueError("valuation run requires exact injected market and execution clocks")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class RuntimeManifestInputAuthority:
    """Self-contained typed state for a verified runtime manifest or an unused route."""

    status: str
    manifest_payload: FrozenMap | None

    def __post_init__(self) -> None:
        if self.status == "not_exercised":
            if self.manifest_payload is not None:
                raise ValueError("unused runtime-manifest authority cannot retain a manifest")
            return
        if self.status != "verified" or not isinstance(self.manifest_payload, Mapping):
            raise ValueError("runtime-manifest input authority state is invalid")
        manifest = freeze(to_json_value(self.manifest_payload))
        payload = to_json_value(manifest)
        if (
            not isinstance(payload, dict)
            or set(payload) != _RUNTIME_MANIFEST_FIELDS
            or payload["schema_version"] != "1.0.0"
            or (payload["manifest_policy_id"], payload["manifest_policy_version"])
            != (MANIFEST_POLICY_ID, MANIFEST_POLICY_VERSION)
        ):
            raise ValueError("runtime-manifest input authority shape is invalid")
        fingerprint_payload = dict(payload)
        supplied_fingerprint = fingerprint_payload.pop("manifest_fingerprint")
        _checked_sha256(supplied_fingerprint, "runtime manifest fingerprint")
        if supplied_fingerprint != canonical_sha256(fingerprint_payload):
            raise ValueError("runtime-manifest input authority fingerprint does not replay")
        expected_kernel = {
            "repository": PINNED_KERNEL_REPOSITORY,
            "tag": PINNED_KERNEL_TAG,
            "commit": PINNED_KERNEL_COMMIT,
            "package_version": PINNED_KERNEL_PACKAGE_VERSION,
            "plugin_version": PINNED_KERNEL_PLUGIN_VERSION,
            "wheel_sha256": PINNED_KERNEL_WHEEL_SHA256,
        }
        kernel = payload["kernel"]
        if not isinstance(kernel, dict) or any(
            kernel.get(name) != value for name, value in expected_kernel.items()
        ):
            raise ValueError("runtime-manifest input authority kernel identity drifted")
        authority = payload["authority"]
        result_schema = payload["result_schema"]
        wheels = payload["wheels"]
        transport = payload["transport"]
        if (
            not isinstance(authority, dict)
            or set(authority) != {"path", "sha256"}
            or authority["path"]
            != "owner_research/resources/phase5-v1-kernel-runtime/runtime-authority.json"
            or not isinstance(result_schema, dict)
            or result_schema.get("sha256")
            != PINNED_KERNEL_SCHEMA_SHA256["schemas/valuation-result.schema.json"]
            or not isinstance(wheels, list)
            or len(
                [
                    item
                    for item in wheels
                    if isinstance(item, dict)
                    and item.get("role") == "kernel"
                    and item.get("sha256") == PINNED_KERNEL_WHEEL_SHA256
                ]
            )
            != 1
            or not isinstance(transport, dict)
            or transport.get("kernel_call_count") != 1
        ):
            raise ValueError("runtime-manifest input authority does not bind pinned supply")
        _checked_sha256(authority["sha256"], "runtime authority SHA")
        object.__setattr__(self, "manifest_payload", manifest)

    @classmethod
    def not_exercised(cls) -> RuntimeManifestInputAuthority:
        return cls(status="not_exercised", manifest_payload=None)

    @classmethod
    def verified(cls, manifest: Mapping[str, Any]) -> RuntimeManifestInputAuthority:
        return cls(status="verified", manifest_payload=freeze(manifest))

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "manifest_payload": (
                to_json_value(self.manifest_payload)
                if self.manifest_payload is not None
                else None
            ),
        }

    @property
    def runtime_manifest_file_sha256(self) -> str | None:
        if self.manifest_payload is None:
            return None
        return hashlib.sha256(canonical_json(self.manifest_payload).encode("utf-8")).hexdigest()

    @property
    def runtime_manifest_fingerprint(self) -> str | None:
        if self.manifest_payload is None:
            return None
        return str(self.manifest_payload["manifest_fingerprint"])

    @property
    def runtime_authority_sha256(self) -> str | None:
        if self.manifest_payload is None:
            return None
        return str(self.manifest_payload["authority"]["sha256"])

    @property
    def wheel_inventory_sha256(self) -> str | None:
        if self.manifest_payload is None:
            return None
        return canonical_sha256(self.manifest_payload["wheels"])

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class ValuationRunAuthority:
    """Authority discovered during PR1/PR2 that the original seven-argument sketch omitted."""

    price_blind_artifact_directory: Path
    expected_freeze: PriceBlindFreezeCompilationResult
    expected_security: SecurityIdentityCompilationResult
    kernel_repository: Path
    runtime_manifest: Path
    runtime_manifest_file_sha256: str
    cas_root: Path

    def __post_init__(self) -> None:
        if type(self.expected_freeze) is not PriceBlindFreezeCompilationResult:
            raise ValueError("valuation run authority requires an exact price-blind freeze")
        if type(self.expected_security) is not SecurityIdentityCompilationResult:
            raise ValueError("valuation run authority requires an exact security compilation")
        if (
            type(self.runtime_manifest_file_sha256) is not str
            or len(self.runtime_manifest_file_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.runtime_manifest_file_sha256
            )
        ):
            raise ValueError("valuation run authority manifest SHA is invalid")
        for name in (
            "price_blind_artifact_directory",
            "kernel_repository",
            "runtime_manifest",
            "cas_root",
        ):
            object.__setattr__(self, name, Path(getattr(self, name)))

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(
            {
                "expected_freeze_fingerprint": self.expected_freeze.fingerprint,
                "expected_security_fingerprint": self.expected_security.fingerprint,
                "runtime_manifest_file_sha256": self.runtime_manifest_file_sha256,
            }
        )


@dataclass(frozen=True, slots=True)
class ValuationRunInputReceipt:
    """Typed, replayable identity for the exact inputs admitted to one valuation run."""

    receipt_id: str
    issuer_id: str
    data_cutoff_date: str
    component_lock_sha256: str
    graph: ContractGraph
    candidate_compilation: AssumptionCandidateCompilationResult
    expected_freeze: PriceBlindFreezeCompilationResult
    expected_security: SecurityIdentityCompilationResult
    runtime_manifest_authority: RuntimeManifestInputAuthority
    clock: ValuationRunClock

    def __post_init__(self) -> None:
        if not self.issuer_id.strip() or not self.data_cutoff_date.strip():
            raise ValueError("valuation run input receipt identity is empty")
        if (
            type(self.graph) is not ContractGraph
            or type(self.candidate_compilation) is not AssumptionCandidateCompilationResult
            or type(self.expected_freeze) is not PriceBlindFreezeCompilationResult
            or type(self.expected_security) is not SecurityIdentityCompilationResult
            or type(self.runtime_manifest_authority) is not RuntimeManifestInputAuthority
            or type(self.clock) is not ValuationRunClock
        ):
            raise ValueError("valuation run input receipt requires exact typed authorities")
        self.graph.validate()
        component_lock_sha256 = hashlib.sha256(
            _read_regular_file(
                self.graph.component_lock_path,
                "component lock",
                maximum=16 * 1024 * 1024,
            )
        ).hexdigest()
        artifact = self.expected_freeze.artifact.to_dict()
        if (
            artifact["issuer_id"] != self.issuer_id
            or artifact["data_cutoff_date"] != self.data_cutoff_date
            or self.expected_security.proposal.issuer_id != self.issuer_id
            or self.expected_security.proposal.data_cutoff_date != self.data_cutoff_date
            or self.candidate_compilation.issuer_id != self.issuer_id
            or self.candidate_compilation.data_cutoff_date != self.data_cutoff_date
            or self.candidate_compilation.to_dict() != artifact["assumption_candidates"]
            or tuple(self.candidate_compilation.candidates) != self.expected_freeze.candidates
        ):
            raise ValueError("valuation run input receipt authorities do not replay")
        if self.component_lock_sha256 != component_lock_sha256:
            raise ValueError("valuation run input receipt component lock does not replay")
        if any(item not in self.graph.valuation_handoffs for item in self.expected_freeze.handoffs):
            raise ValueError("valuation run input graph omits the frozen Handoffs")
        if any(
            item not in self.graph.valuation_assumption_candidates
            for item in self.expected_freeze.candidates
        ) or any(
            item not in self.graph.valuation_assumption_review_decisions
            for item in self.expected_freeze.decisions
        ):
            raise ValueError("valuation run input graph omits the reviewed assumptions")
        payload = self.to_dict()
        supplied = payload.pop("receipt_id")
        expected = f"valuation-run-input-receipt:{self.issuer_id}:{canonical_sha256(payload)[:24]}"
        if supplied != expected:
            raise ValueError("valuation run input receipt ID is not deterministic")

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "issuer_id": self.issuer_id,
            "data_cutoff_date": self.data_cutoff_date,
            "component_lock_sha256": self.component_lock_sha256,
            "graph_fingerprint": self.graph_fingerprint,
            "research_bundle_set_sha256": self.research_bundle_set_sha256,
            "run_manifest_set_sha256": self.run_manifest_set_sha256,
            "price_blind_input_fingerprint": self.price_blind_input_fingerprint,
            "expected_freeze_fingerprint": self.expected_freeze_fingerprint,
            "expected_security_fingerprint": self.expected_security_fingerprint,
            "candidate_compilation_fingerprint": self.candidate_compilation_fingerprint,
            "runtime_manifest_authority": self.runtime_manifest_authority.to_dict(),
            "authority_fingerprint": self.authority_fingerprint,
            "clock_fingerprint": self.clock_fingerprint,
        }

    @property
    def graph_fingerprint(self) -> str:
        return _graph_fingerprint(self.graph)

    @property
    def research_bundle_set_sha256(self) -> str:
        return canonical_sha256(tuple(item.fingerprint for item in self.graph.research_bundles))

    @property
    def run_manifest_set_sha256(self) -> str:
        return canonical_sha256(tuple(item.fingerprint for item in self.graph.manifests))

    @property
    def price_blind_input_fingerprint(self) -> str:
        return self.expected_freeze.artifact.fingerprint

    @property
    def expected_freeze_fingerprint(self) -> str:
        return self.expected_freeze.fingerprint

    @property
    def expected_security_fingerprint(self) -> str:
        return self.expected_security.fingerprint

    @property
    def candidate_compilation_fingerprint(self) -> str:
        return self.candidate_compilation.fingerprint

    @property
    def authority_fingerprint(self) -> str:
        return canonical_sha256(
            {
                "expected_freeze_fingerprint": self.expected_freeze.fingerprint,
                "expected_security_fingerprint": self.expected_security.fingerprint,
                "runtime_manifest_authority_fingerprint": (
                    self.runtime_manifest_authority.fingerprint
                ),
            }
        )

    @property
    def clock_fingerprint(self) -> str:
        return canonical_sha256(self.clock.to_dict())

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class ValuationRunResult:
    status: str
    issuer_id: str
    data_cutoff_date: str
    input_receipt: ValuationRunInputReceipt
    preparation: OwnerValuationPreparationResult | None
    execution: OwnerValuationExecutionResult | None
    archive: ValuationRunArchive | None
    issue_codes: tuple[str, ...]
    _integrity_binding: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.status not in {"completed", "blocked", "specialist_required"}:
            raise ValueError("valuation run status is not registered")
        if type(self.input_receipt) is not ValuationRunInputReceipt:
            raise ValueError("valuation run requires an exact typed input receipt")
        if (
            self.input_receipt.issuer_id != self.issuer_id
            or self.input_receipt.data_cutoff_date != self.data_cutoff_date
        ):
            raise ValueError("valuation run input receipt identity changed")
        issues = tuple(sorted(set(self.issue_codes)))
        if any(type(item) is not str or not item for item in issues):
            raise ValueError("valuation run issue codes must be nonempty exact strings")
        object.__setattr__(self, "issue_codes", issues)
        if self.status == "completed":
            if self.input_receipt.runtime_manifest_authority.status != "verified":
                raise ValueError("completed valuation run lacks verified runtime authority")
            if (
                type(self.preparation) is not OwnerValuationPreparationResult
                or type(self.execution) is not OwnerValuationExecutionResult
                or type(self.archive) is not ValuationRunArchive
                or self.preparation.status != "prepared"
                or self.execution.status != "completed"
                or self.preparation != self.execution.preparation
                or self.execution.issuer_id != self.issuer_id
                or self.execution.data_cutoff_date != self.data_cutoff_date
                or self.archive.handoff != self.execution.execution_handoffs[-1]
                or issues
            ):
                raise ValueError("completed valuation run is not fully archived")
            prepared_graph = self.preparation.prepared_market_reference.graph
            contexts = prepared_graph.market_reference_validation_contexts
            if len(contexts) != 1:
                raise ValueError("completed valuation run lacks one market validation context")
            if (
                self.input_receipt.price_blind_input_fingerprint
                != self.execution.expected_freeze.artifact.fingerprint
                or self.input_receipt.expected_freeze_fingerprint
                != self.execution.expected_freeze.fingerprint
                or self.input_receipt.expected_security_fingerprint
                != contexts[0].security_compilation_result.fingerprint
            ):
                raise ValueError("completed valuation run changed its typed input receipt")
            _validate_completed_input_receipt(
                self.input_receipt,
                preparation=self.preparation,
                execution=self.execution,
            )
            reloaded = load_valuation_run_archive(
                self.archive.output_directory,
                expected_execution=self.execution,
                expected_runtime_manifest_authority=(
                    self.input_receipt.runtime_manifest_authority
                ),
            )
            if reloaded != self.archive:
                raise ValueError(
                    "completed valuation run does not retain the strict reloaded archive"
                )
        else:
            expected_runtime_status = (
                "verified"
                if self.preparation is not None and self.preparation.status == "prepared"
                else "not_exercised"
            )
            if self.input_receipt.runtime_manifest_authority.status != expected_runtime_status:
                raise ValueError("stopped valuation run runtime authority state changed")
            if self.archive is not None or not issues:
                raise ValueError("stopped valuation run cannot retain an archive")
            if self.execution is None:
                if self.preparation is not None or not all(
                    item.startswith(
                        ("market_preparation_blocked:", "runtime_supply_blocked:")
                    )
                    for item in issues
                ):
                    raise ValueError("preparation-stopped valuation run is not closed")
            elif (
                type(self.execution) is not OwnerValuationExecutionResult
                or self.execution.status != self.status
                or self.execution.issuer_id != self.issuer_id
                or self.execution.data_cutoff_date != self.data_cutoff_date
                or self.execution.issue_codes != issues
                or not _stopped_execution_preparation_matches(
                    self.preparation,
                    self.execution,
                )
                or self.input_receipt.clock.execution != self.execution.clock
            ):
                raise ValueError("stopped valuation execution binding changed")
            elif self.preparation is None or self.preparation.status not in {
                self.status,
                "prepared",
            }:
                raise ValueError("stopped valuation preparation status changed")
            elif self.preparation.prepared_market_reference is not None:
                _validate_preparation_input_receipt(
                    self.input_receipt,
                    preparation=self.preparation,
                )
        expected_binding = _result_integrity_binding(
            status=self.status,
            issuer_id=self.issuer_id,
            data_cutoff_date=self.data_cutoff_date,
            input_receipt=self.input_receipt,
            preparation=self.preparation,
            execution=self.execution,
            archive=self.archive,
            issue_codes=issues,
        )
        _checked_sha256(self._integrity_binding, "valuation run integrity binding")
        if self._integrity_binding != expected_binding:
            raise ValueError("valuation run retained-object integrity binding changed")

    @property
    def fingerprint(self) -> str:
        return self._integrity_binding

    @property
    def run_input_fingerprint(self) -> str:
        """Compatibility alias derived from the typed receipt, never caller supplied."""

        return self.input_receipt.fingerprint


def _review_projection(request: AssumptionReviewRequest) -> dict[str, Any]:
    return request.to_dict()


def _decision_projection(decision: Any) -> dict[str, Any]:
    payload = decision.to_dict()
    return {
        "candidate_id": payload["candidate_id"],
        "candidate_fingerprint": payload["candidate_fingerprint"],
        "evidence_graph_sha256": payload["evidence_graph_sha256"],
        "decision": payload["decision"],
        "reviewer_id": payload["reviewer_id"],
        "reviewed_at": payload["reviewed_at"],
        "rationale": payload["rationale"],
        "issues": payload["issues"],
        "supersedes_decision_id": payload["supersedes_decision_id"],
    }


def _replay_assumption_inputs(
    *,
    graph: ContractGraph,
    bundle_artifact_directory: Path,
    proposals: tuple[AssumptionCandidateProposal, ...],
    reviews: tuple[AssumptionReviewRequest, ...],
    authority: ValuationRunAuthority,
) -> AssumptionCandidateCompilationResult:
    candidate_result = compile_valuation_assumption_candidates(
        bundle_artifact_directory=bundle_artifact_directory,
        graph=graph,
        kernel_repository=authority.kernel_repository,
        proposals=proposals,
        supplemental_reference_closure=(authority.expected_freeze.supplemental_reference_closure),
    )
    if tuple(candidate_result.candidates) != tuple(authority.expected_freeze.candidates):
        raise ValuationRunError("assumption proposals do not replay the frozen Candidates")
    expected_reviews = tuple(
        sorted(
            (_decision_projection(item) for item in authority.expected_freeze.decisions),
            key=lambda item: (item["candidate_id"], item["reviewed_at"]),
        )
    )
    supplied_reviews = tuple(
        sorted(
            (_review_projection(item) for item in reviews),
            key=lambda item: (item["candidate_id"], item["reviewed_at"]),
        )
    )
    if supplied_reviews != expected_reviews:
        raise ValuationRunError("assumption reviews do not replay the frozen Decisions")
    return candidate_result


def _open_regular_without_symlink_components(path: Path, label: str) -> int:
    absolute = Path(path).expanduser().absolute()
    parts = absolute.parts
    if len(parts) < 2 or not absolute.name:
        raise ValuationRunError(f"{label} path is invalid")
    directory_flags = (
        getattr(os, "O_PATH", os.O_RDONLY)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(parts[0], directory_flags)
        for part in parts[1:-1]:
            next_descriptor = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(
            parts[-1],
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptor,
        )
    except OSError as exc:
        raise ValuationRunError(
            f"{label} path contains an unavailable or symlinked component"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return file_descriptor


def _read_regular_file(path: Path, label: str, *, maximum: int) -> bytes:
    descriptor = _open_regular_without_symlink_components(path, label)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or before.st_size > maximum
        ):
            raise ValuationRunError(f"{label} must be one bounded regular non-symlink file")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise ValuationRunError(f"{label} exceeds the byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or consumed != before.st_size:
            raise ValuationRunError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _verify_runtime_supply(
    *,
    kernel_wheel: Path,
    authority: ValuationRunAuthority,
) -> RuntimeManifestInputAuthority:
    wheel = Path(kernel_wheel).expanduser().absolute()
    expected_wheel = (
        authority.cas_root.expanduser().absolute() / "sha256" / (PINNED_KERNEL_WHEEL_SHA256)
    )
    if wheel != expected_wheel:
        raise ValuationRunError("kernel wheel must be the exact pinned CAS object")
    if hashlib.sha256(
        _read_regular_file(wheel, "kernel wheel", maximum=256 * 1024 * 1024)
    ).hexdigest() != (PINNED_KERNEL_WHEEL_SHA256):
        raise ValuationRunError("kernel wheel bytes do not match the pinned release")
    manifest = load_and_verify_runtime_manifest(
        authority.runtime_manifest,
        cas_root=authority.cas_root,
        expected_manifest_file_sha256=authority.runtime_manifest_file_sha256,
    )
    kernel_items = tuple(item for item in manifest["wheels"] if item["role"] == "kernel")
    if (
        len(kernel_items) != 1
        or kernel_items[0]["sha256"] != PINNED_KERNEL_WHEEL_SHA256
        or kernel_items[0]["uri"] != f"cas://sha256/{PINNED_KERNEL_WHEEL_SHA256}"
    ):
        raise ValuationRunError("runtime manifest does not bind the supplied kernel wheel")
    typed_authority = RuntimeManifestInputAuthority.verified(manifest)
    if typed_authority.runtime_manifest_file_sha256 != authority.runtime_manifest_file_sha256:
        raise ValuationRunError("runtime manifest typed authority changed verified bytes")
    return typed_authority


def _graph_fingerprint(graph: ContractGraph) -> str:
    projection: dict[str, list[str]] = {}
    for item in fields(graph):
        if item.name == "component_lock_path":
            continue
        fingerprints: list[str] = []
        for value in getattr(graph, item.name):
            fingerprint = getattr(value, "fingerprint", None)
            if type(fingerprint) is not str:
                to_dict = getattr(value, "to_dict", None)
                if not callable(to_dict):
                    raise ValuationRunError(
                        f"graph collection {item.name} contains an unreceiptable value"
                    )
                fingerprint = canonical_sha256(to_dict())
            fingerprints.append(_checked_sha256(fingerprint, f"{item.name} fingerprint"))
        projection[item.name] = fingerprints
    return canonical_sha256(projection)


def _validate_completed_input_receipt(
    receipt: ValuationRunInputReceipt,
    *,
    preparation: OwnerValuationPreparationResult,
    execution: OwnerValuationExecutionResult,
) -> None:
    prepared = preparation.prepared_market_reference
    kernel_receipt = execution.kernel_execution_receipt
    if prepared is None or kernel_receipt is None:
        raise ValueError("completed valuation run lacks replayable typed authorities")
    contexts = prepared.graph.market_reference_validation_contexts
    if len(contexts) != 1:
        raise ValueError("completed valuation run lacks one market validation context")
    context = contexts[0]
    access = context.market_access_result
    if access.request is None or access.receipt is None:
        raise ValueError("completed valuation run lacks governed market timing")
    governed_receipt = access.receipt.receipt
    final_graph = prepared.graph
    if receipt.graph.component_lock_path != final_graph.component_lock_path:
        raise ValueError("completed valuation run changed the input component-lock authority")
    _validate_preparation_input_receipt(receipt, preparation=preparation)
    expected_market_clock = RunClock(
        access.request.request_started_at,
        governed_receipt.retrieved_at,
    )
    runtime_authority = receipt.runtime_manifest_authority
    if (
        receipt.expected_freeze != execution.expected_freeze
        or receipt.expected_security != context.security_compilation_result
        or receipt.clock.market != expected_market_clock
        or receipt.clock.execution != execution.clock
        or runtime_authority.status != "verified"
        or runtime_authority.runtime_manifest_file_sha256
        != kernel_receipt.runtime_manifest_file_sha256
        or runtime_authority.runtime_manifest_fingerprint
        != kernel_receipt.runtime_manifest_fingerprint
        or runtime_authority.runtime_authority_sha256
        != kernel_receipt.runtime_authority_sha256
        or runtime_authority.wheel_inventory_sha256
        != kernel_receipt.wheel_inventory_sha256
    ):
        raise ValueError("completed valuation run changed its typed input authorities")


def _allowed_preparation_additions(
    preparation: OwnerValuationPreparationResult,
) -> dict[str, tuple[Any, ...]]:
    prepared = preparation.prepared_market_reference
    if prepared is None:
        return {}
    current_shares = prepared.current_shares
    facts: list[Any] = [prepared.quote_fact]
    if current_shares.output_fact is not None:
        facts.append(current_shares.output_fact)
    rollforward = current_shares.canonical_rollforward
    if rollforward is not None:
        facts.extend(item.canonical_event_fact for item in rollforward.materializations)
    contexts = tuple(prepared.graph.market_reference_validation_contexts)
    return {
        "documents": (prepared.market_source,),
        "facts": tuple(facts),
        "calculations": (prepared.market_equity_calculation,),
        "market_reference_snapshots": (prepared.snapshot,),
        "market_reference_validation_contexts": contexts,
    }


def _collection_is_allowed_derivation(
    original: tuple[Any, ...],
    completed: tuple[Any, ...],
    allowed_additions: tuple[Any, ...],
) -> bool:
    original_index = 0
    remaining_additions = list(allowed_additions)
    for value in completed:
        if original_index < len(original) and value == original[original_index]:
            original_index += 1
            continue
        try:
            remaining_additions.remove(value)
        except ValueError:
            return False
    return original_index == len(original)


def _validate_preparation_input_receipt(
    receipt: ValuationRunInputReceipt,
    *,
    preparation: OwnerValuationPreparationResult,
) -> None:
    prepared = preparation.prepared_market_reference
    if prepared is None:
        raise ValueError("valuation preparation lacks replayable market evidence")
    final_graph = prepared.graph
    final_graph.validate()
    if receipt.graph.component_lock_path != final_graph.component_lock_path:
        raise ValueError("valuation preparation changed component-lock authority")
    additions = _allowed_preparation_additions(preparation)
    for item in fields(ContractGraph):
        if item.name == "component_lock_path":
            continue
        original = tuple(getattr(receipt.graph, item.name))
        completed = tuple(getattr(final_graph, item.name))
        if not _collection_is_allowed_derivation(
            original,
            completed,
            additions.get(item.name, ()),
        ):
            raise ValueError(
                f"valuation preparation does not exactly derive input collection {item.name}"
            )
    contexts = final_graph.market_reference_validation_contexts
    if len(contexts) != 1:
        raise ValueError("valuation preparation lacks one market validation context")
    context = contexts[0]
    access = context.market_access_result
    if access.request is None or access.receipt is None:
        raise ValueError("valuation preparation lacks governed market timing")
    expected_market_clock = RunClock(
        access.request.request_started_at,
        access.receipt.receipt.retrieved_at,
    )
    if (
        receipt.expected_security != context.security_compilation_result
        or receipt.clock.market != expected_market_clock
    ):
        raise ValueError("valuation preparation changed typed input authority")


def _preparation_integrity_binding(
    preparation: OwnerValuationPreparationResult | None,
) -> str | None:
    if preparation is None:
        return None
    prepared = preparation.prepared_market_reference
    return canonical_sha256(
        {
            "status": preparation.status,
            "issuer_id": preparation.issuer_id,
            "data_cutoff_date": preparation.data_cutoff_date,
            "price_blind_input_fingerprint": preparation.price_blind_input_fingerprint,
            "prepared_market_reference_fingerprint": (
                prepared.fingerprint if prepared is not None else None
            ),
            "prepared_graph_fingerprint": (
                _graph_fingerprint(prepared.graph) if prepared is not None else None
            ),
            "issue_codes": preparation.issue_codes,
        }
    )


def _stopped_execution_preparation_matches(
    preparation: OwnerValuationPreparationResult | None,
    execution: OwnerValuationExecutionResult,
) -> bool:
    if preparation == execution.preparation:
        return True
    request = execution.final_request_result
    if (
        type(preparation) is not OwnerValuationPreparationResult
        or preparation.status != "prepared"
        or request.status == "compiled"
    ):
        return False
    expected = OwnerValuationPreparationResult(
        status=execution.status,
        issuer_id=preparation.issuer_id,
        data_cutoff_date=preparation.data_cutoff_date,
        price_blind_input_fingerprint=preparation.price_blind_input_fingerprint,
        prepared_market_reference=None,
        issue_codes=execution.issue_codes,
    )
    return execution.preparation == expected


def _execution_integrity_binding(
    execution: OwnerValuationExecutionResult | None,
) -> str | None:
    if execution is None:
        return None
    return canonical_sha256(
        {
            "status": execution.status,
            "issuer_id": execution.issuer_id,
            "data_cutoff_date": execution.data_cutoff_date,
            "preparation_fingerprint": execution.preparation_fingerprint,
            "stopped_envelope_fingerprint": execution.stopped_envelope_fingerprint,
            "final_request_receipt_fingerprint": (
                execution.final_request_receipt.fingerprint
                if execution.final_request_receipt is not None
                else None
            ),
            "kernel_execution_receipt_fingerprint": (
                execution.kernel_execution_receipt.fingerprint
                if execution.kernel_execution_receipt is not None
                else None
            ),
            "result_sha256": (
                hashlib.sha256(execution.result_bytes).hexdigest()
                if execution.result_bytes is not None
                else None
            ),
            "issue_codes": execution.issue_codes,
        }
    )


def _archive_integrity_binding(archive: ValuationRunArchive | None) -> dict[str, Any] | None:
    if archive is None:
        return None
    return {
        "output_directory": str(archive.output_directory),
        "directory_device": archive.directory_device,
        "directory_inode": archive.directory_inode,
        "manifest_fingerprint": archive.fingerprint,
        "file_sha256": dict(archive.file_sha256),
    }


def _result_integrity_binding(
    *,
    status: str,
    issuer_id: str,
    data_cutoff_date: str,
    input_receipt: ValuationRunInputReceipt,
    preparation: OwnerValuationPreparationResult | None,
    execution: OwnerValuationExecutionResult | None,
    archive: ValuationRunArchive | None,
    issue_codes: tuple[str, ...],
) -> str:
    return canonical_sha256(
        {
            "status": status,
            "issuer_id": issuer_id,
            "data_cutoff_date": data_cutoff_date,
            "input_receipt_fingerprint": input_receipt.fingerprint,
            "preparation_binding": _preparation_integrity_binding(preparation),
            "execution_binding": _execution_integrity_binding(execution),
            "archive_binding": _archive_integrity_binding(archive),
            "issue_codes": issue_codes,
        }
    )


def _captured_archive_file_sha256(archive: ValuationRunArchive) -> dict[str, str]:
    """Hash the retained typed archive values without reopening its locator."""

    contents = {
        "valuation-handoff.json": (
            canonical_json(archive.handoff.to_dict()) + "\n"
        ).encode("utf-8"),
        "price-blind-input.json": (
            canonical_json(archive.price_blind_input.to_dict()) + "\n"
        ).encode("utf-8"),
        "market-reference.json": (
            canonical_json(archive.market_reference.to_dict()) + "\n"
        ).encode("utf-8"),
        "valuation-request.json": canonical_json(
            to_json_value(archive.request_payload)
        ).encode("utf-8"),
        "valuation-result.json": canonical_json(
            to_json_value(archive.result_payload)
        ).encode("utf-8"),
        "valuation-run-manifest.json": (
            canonical_json(to_json_value(archive.manifest)) + "\n"
        ).encode("utf-8"),
    }
    return {name: hashlib.sha256(contents[name]).hexdigest() for name in contents}


def _replay_retained_completed_run(
    run_result: ValuationRunResult,
) -> tuple[ValuationRunArchive, dict[str, Any], dict[str, Any]]:
    """Replay one already-admitted completed run entirely from retained values.

    ``ValuationRunResult.__post_init__`` is the sole boundary that reloads the
    strict six-file archive.  Downstream synthesis, scoring, and reporting use
    this replay so a later path replacement cannot be absorbed and repeated
    extension validation cannot reopen the archive.
    """

    if type(run_result) is not ValuationRunResult or run_result.status != "completed":
        raise ValueError("retained replay requires an exact completed valuation run")
    receipt = run_result.input_receipt
    preparation = run_result.preparation
    execution = run_result.execution
    archive = run_result.archive
    if (
        type(receipt) is not ValuationRunInputReceipt
        or type(preparation) is not OwnerValuationPreparationResult
        or type(execution) is not OwnerValuationExecutionResult
        or type(archive) is not ValuationRunArchive
        or preparation.status != "prepared"
        or execution.status != "completed"
        or preparation != execution.preparation
        or execution.issuer_id != run_result.issuer_id
        or execution.data_cutoff_date != run_result.data_cutoff_date
        or receipt.issuer_id != run_result.issuer_id
        or receipt.data_cutoff_date != run_result.data_cutoff_date
        or receipt.runtime_manifest_authority.status != "verified"
        or len(execution.execution_handoffs) != 2
        or archive.handoff != execution.execution_handoffs[-1]
        or run_result.issue_codes
    ):
        raise ValueError("completed valuation run retained objects were rebound")
    prepared = preparation.prepared_market_reference
    request_result = execution.final_request_result
    request_receipt = execution.final_request_receipt
    kernel_receipt = execution.kernel_execution_receipt
    if (
        prepared is None
        or request_result.request_payload is None
        or request_result.canonical_request_json is None
        or request_result.request_sha256 is None
        or request_receipt is None
        or kernel_receipt is None
        or execution.result_bytes is None
        or archive.price_blind_input != execution.expected_freeze.artifact
        or archive.market_reference != prepared.snapshot
    ):
        raise ValueError("completed valuation run lacks retained typed outputs")
    _validate_completed_input_receipt(
        receipt,
        preparation=preparation,
        execution=execution,
    )
    request = to_json_value(archive.request_payload)
    result = to_json_value(archive.result_payload)
    manifest = to_json_value(archive.manifest)
    if not all(isinstance(value, dict) for value in (request, result, manifest)):
        raise ValueError("completed valuation archive retained payloads are invalid")
    assert isinstance(request, dict)
    assert isinstance(result, dict)
    assert isinstance(manifest, dict)
    request_bytes = canonical_json(request).encode("utf-8")
    result_bytes = canonical_json(result).encode("utf-8")
    if (
        request != to_json_value(request_result.request_payload)
        or request_bytes.decode("utf-8") != request_result.canonical_request_json
        or result_bytes != execution.result_bytes
    ):
        raise ValueError("completed valuation archive request/result bytes were rebound")
    hashes = _captured_archive_file_sha256(archive)
    content_hashes = {
        name: hashes[name] for name in VALUATION_RUN_ARCHIVE_FILENAMES[:-1]
    }
    fingerprint_payload = dict(manifest)
    supplied_manifest_fingerprint = fingerprint_payload.pop(
        "manifest_fingerprint",
        None,
    )
    expected_integrity = _result_integrity_binding(
        status=run_result.status,
        issuer_id=run_result.issuer_id,
        data_cutoff_date=run_result.data_cutoff_date,
        input_receipt=receipt,
        preparation=preparation,
        execution=execution,
        archive=archive,
        issue_codes=run_result.issue_codes,
    )
    archived_kernel_projection = manifest.get("kernel_execution_projection")
    archived_final_projection = manifest.get("final_request_projection")
    expected_final_projection = (
        {
            name: request_receipt.to_dict()[name]
            for name in archived_final_projection
        }
        if isinstance(archived_final_projection, dict)
        else None
    )
    expected_kernel_projection = (
        {
            name: kernel_receipt.to_dict()[name]
            for name in archived_kernel_projection
        }
        if isinstance(archived_kernel_projection, dict)
        else None
    )
    expected_runtime_authority = _project_verified_runtime_manifest_authority(
        receipt.runtime_manifest_authority,
        runner_sha256=kernel_receipt.runner_sha256,
    )
    if (
        run_result.fingerprint != expected_integrity
        or dict(archive.file_sha256) != hashes
        or manifest.get("file_sha256") != content_hashes
        or supplied_manifest_fingerprint != canonical_sha256(fingerprint_payload)
        or manifest.get("issuer_id") != run_result.issuer_id
        or manifest.get("data_cutoff_date") != run_result.data_cutoff_date
        or manifest.get("price_blind_input_fingerprint")
        != execution.expected_freeze.artifact.fingerprint
        or manifest.get("market_reference_snapshot_id") != prepared.snapshot.snapshot_id
        or manifest.get("market_reference_snapshot_fingerprint")
        != prepared.snapshot.fingerprint
        or manifest.get("valuation_handoff_id") != archive.handoff.handoff_id
        or manifest.get("valuation_handoff_fingerprint") != archive.handoff.fingerprint
        or manifest.get("valuation_request_sha256") != hashlib.sha256(request_bytes).hexdigest()
        or manifest.get("valuation_request_sha256") != request_result.request_sha256
        or manifest.get("valuation_result_sha256") != hashlib.sha256(result_bytes).hexdigest()
        or manifest.get("valuation_result_sha256") != kernel_receipt.result_sha256
        or manifest.get("valuation_result_fingerprint") != canonical_sha256(result)
        or archived_final_projection != expected_final_projection
        or manifest.get("kernel_runtime_authority") != expected_runtime_authority
        or archived_kernel_projection != expected_kernel_projection
    ):
        raise ValueError("completed valuation retained archive does not replay")
    return archive, request, result


def _valuation_run_result(
    *,
    status: str,
    issuer_id: str,
    data_cutoff_date: str,
    input_receipt: ValuationRunInputReceipt,
    preparation: OwnerValuationPreparationResult | None,
    execution: OwnerValuationExecutionResult | None,
    archive: ValuationRunArchive | None,
    issue_codes: tuple[str, ...],
) -> ValuationRunResult:
    issues = tuple(sorted(set(issue_codes)))
    return ValuationRunResult(
        status=status,
        issuer_id=issuer_id,
        data_cutoff_date=data_cutoff_date,
        input_receipt=input_receipt,
        preparation=preparation,
        execution=execution,
        archive=archive,
        issue_codes=issues,
        _integrity_binding=_result_integrity_binding(
            status=status,
            issuer_id=issuer_id,
            data_cutoff_date=data_cutoff_date,
            input_receipt=input_receipt,
            preparation=preparation,
            execution=execution,
            archive=archive,
            issue_codes=issues,
        ),
    )


def _input_receipt(
    *,
    graph: ContractGraph,
    candidate_compilation: AssumptionCandidateCompilationResult,
    authority: ValuationRunAuthority,
    runtime_manifest_authority: RuntimeManifestInputAuthority,
    clock: ValuationRunClock,
) -> ValuationRunInputReceipt:
    artifact = authority.expected_freeze.artifact.to_dict()
    if not graph.research_bundles or not graph.manifests:
        raise ValuationRunError("valuation run input lacks ResearchBundle authority")
    component_lock_sha256 = hashlib.sha256(
        _read_regular_file(
            graph.component_lock_path,
            "component lock",
            maximum=16 * 1024 * 1024,
        )
    ).hexdigest()
    values = {
        "issuer_id": artifact["issuer_id"],
        "data_cutoff_date": artifact["data_cutoff_date"],
        "component_lock_sha256": component_lock_sha256,
        "graph": graph,
        "candidate_compilation": candidate_compilation,
        "expected_freeze": authority.expected_freeze,
        "expected_security": authority.expected_security,
        "runtime_manifest_authority": runtime_manifest_authority,
        "clock": clock,
    }
    payload = {
        "issuer_id": artifact["issuer_id"],
        "data_cutoff_date": artifact["data_cutoff_date"],
        "component_lock_sha256": component_lock_sha256,
        "graph_fingerprint": _graph_fingerprint(graph),
        "research_bundle_set_sha256": canonical_sha256(
            tuple(item.fingerprint for item in graph.research_bundles)
        ),
        "run_manifest_set_sha256": canonical_sha256(
            tuple(item.fingerprint for item in graph.manifests)
        ),
        "price_blind_input_fingerprint": authority.expected_freeze.artifact.fingerprint,
        "expected_freeze_fingerprint": authority.expected_freeze.fingerprint,
        "expected_security_fingerprint": authority.expected_security.fingerprint,
        "candidate_compilation_fingerprint": candidate_compilation.fingerprint,
        "runtime_manifest_authority": runtime_manifest_authority.to_dict(),
        "authority_fingerprint": canonical_sha256(
            {
                "expected_freeze_fingerprint": authority.expected_freeze.fingerprint,
                "expected_security_fingerprint": authority.expected_security.fingerprint,
                "runtime_manifest_authority_fingerprint": (
                    runtime_manifest_authority.fingerprint
                ),
            }
        ),
        "clock_fingerprint": canonical_sha256(clock.to_dict()),
    }
    receipt_id = (
        f"valuation-run-input-receipt:{artifact['issuer_id']}:{canonical_sha256(payload)[:24]}"
    )
    return ValuationRunInputReceipt(**{**values, "receipt_id": receipt_id})


def run_owner_valuation(
    *,
    graph: ContractGraph,
    bundle_artifact_directory: Path,
    assumption_proposals: tuple[AssumptionCandidateProposal, ...],
    assumption_reviews: tuple[AssumptionReviewRequest, ...],
    market_provider: MarketReferenceProvider,
    kernel_wheel: Path,
    output_directory: Path,
    clock: ValuationRunClock,
    authority: ValuationRunAuthority,
    timeout_seconds: int = 90,
) -> ValuationRunResult:
    """Replay price-blind authority, acquire once, execute once, then archive once.

    The original Phase 5 sketch listed seven inputs.  PR1/PR2 established additional
    immutable security, freeze, container-manifest, and CAS authorities; they are
    grouped in ``ValuationRunAuthority`` instead of being inferred or fabricated.
    """

    if type(graph) is not ContractGraph or type(clock) is not ValuationRunClock:
        raise ValuationRunError("valuation run requires exact graph and clock inputs")
    if type(authority) is not ValuationRunAuthority:
        raise ValuationRunError("valuation run requires exact replay authority")
    proposals = tuple(assumption_proposals)
    reviews = tuple(assumption_reviews)
    candidate_compilation = _replay_assumption_inputs(
        graph=graph,
        bundle_artifact_directory=Path(bundle_artifact_directory),
        proposals=proposals,
        reviews=reviews,
        authority=authority,
    )
    artifact = authority.expected_freeze.artifact.to_dict()
    runtime_manifest_authority = RuntimeManifestInputAuthority.not_exercised()
    verified_runtime_authority: RuntimeManifestInputAuthority | None = None
    if authority.expected_security.status == "eligible":
        try:
            verified_runtime_authority = _verify_runtime_supply(
                kernel_wheel=kernel_wheel,
                authority=authority,
            )
            if type(verified_runtime_authority) is not RuntimeManifestInputAuthority:
                raise ValuationRunError("runtime supply verifier did not return typed authority")
        except (KernelMaterializationError, OSError, TypeError, ValueError) as exc:
            input_receipt = _input_receipt(
                graph=graph,
                candidate_compilation=candidate_compilation,
                authority=authority,
                runtime_manifest_authority=runtime_manifest_authority,
                clock=clock,
            )
            return _valuation_run_result(
                status="blocked",
                issuer_id=artifact["issuer_id"],
                data_cutoff_date=artifact["data_cutoff_date"],
                input_receipt=input_receipt,
                preparation=None,
                execution=None,
                archive=None,
                issue_codes=(f"runtime_supply_blocked:{type(exc).__name__}",),
            )
    try:
        preparation = prepare_owner_valuation(
            graph=graph,
            price_blind_artifact_directory=authority.price_blind_artifact_directory,
            expected_freeze=authority.expected_freeze,
            expected_security=authority.expected_security,
            market_provider=market_provider,
            clock=clock.market,
        )
    except (OSError, TypeError, ValueError) as exc:
        input_receipt = _input_receipt(
            graph=graph,
            candidate_compilation=candidate_compilation,
            authority=authority,
            runtime_manifest_authority=runtime_manifest_authority,
            clock=clock,
        )
        return _valuation_run_result(
            status="blocked",
            issuer_id=artifact["issuer_id"],
            data_cutoff_date=artifact["data_cutoff_date"],
            input_receipt=input_receipt,
            preparation=None,
            execution=None,
            archive=None,
            issue_codes=(f"market_preparation_blocked:{type(exc).__name__}",),
        )
    if preparation.status == "prepared":
        if type(verified_runtime_authority) is not RuntimeManifestInputAuthority:
            raise ValuationRunError("prepared valuation lacks verified runtime authority")
        runtime_manifest_authority = verified_runtime_authority
    input_receipt = _input_receipt(
        graph=graph,
        candidate_compilation=candidate_compilation,
        authority=authority,
        runtime_manifest_authority=runtime_manifest_authority,
        clock=clock,
    )
    execution = execute_owner_valuation(
        preparation=preparation,
        expected_freeze=authority.expected_freeze,
        kernel_repository=authority.kernel_repository,
        runtime_manifest=authority.runtime_manifest,
        runtime_manifest_file_sha256=authority.runtime_manifest_file_sha256,
        cas_root=authority.cas_root,
        clock=clock.execution,
        timeout_seconds=timeout_seconds,
    )
    if execution.status != "completed":
        return _valuation_run_result(
            status=execution.status,
            issuer_id=execution.issuer_id,
            data_cutoff_date=execution.data_cutoff_date,
            input_receipt=input_receipt,
            preparation=preparation,
            execution=execution,
            archive=None,
            issue_codes=execution.issue_codes,
        )
    archive = write_valuation_run_archive(
        execution,
        output_directory=output_directory,
        runtime_manifest_authority=input_receipt.runtime_manifest_authority,
    )
    return _valuation_run_result(
        status="completed",
        issuer_id=execution.issuer_id,
        data_cutoff_date=execution.data_cutoff_date,
        input_receipt=input_receipt,
        preparation=preparation,
        execution=execution,
        archive=archive,
        issue_codes=(),
    )


__all__ = (
    "RuntimeManifestInputAuthority",
    "ValuationRunAuthority",
    "ValuationRunClock",
    "ValuationRunError",
    "ValuationRunInputReceipt",
    "ValuationRunResult",
    "run_owner_valuation",
)
