"""Strict composition root for the callable Owner Equity Research workflow.

The JSON configuration is only a path/key locator.  It is never admitted as research
authority: every input is reconstructed into an existing immutable contract and replayed
before an adapter is exposed.  Price-blind routes deliberately do not load Futu receipts,
instantiate the Unix-domain-socket transport, or inspect valuation-only paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import (
    Contract,
    Fact,
    QuarterlyUpdate,
    ReportSpec,
    contract_from_dict,
)
from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze, to_json_value
from .futu_crosscheck import (
    OfficialEvidenceOperand,
    build_official_evidence_operand,
    crosscheck_vendor_observation,
    split_observation_matches_official_period,
)
from .futu_receipts import (
    FutuAccountEntitlementReceipt,
    FutuAuthorityDecision,
    FutuAuthoritySet,
    FutuCrossCheckReceipt,
    FutuFrozenConclusionReceipt,
    FutuLegalRightsReceipt,
    FutuRuntimeIsolationAuthorization,
    FutuSecurityIdentityReceipt,
    FutuSupplyChainReceipt,
    SignatureVerifier,
    build_futu_frozen_conclusion_receipt,
    build_futu_runtime_request_plan_item,
    evaluate_futu_authority,
    load_futu_signed_receipt,
)
from .futu_session import (
    FutuMarketExecutionEvidence,
    FutuPeerEvidenceSet,
    FutuSessionEvidence,
    build_futu_peer_evidence_set,
    build_futu_peer_session_evidence,
    finalize_futu_market_execution_evidence,
)
from .futu_sidecar import (
    AttestedFutuSidecarSession,
    FutuAttestedSessionFinalization,
    FutuRequestSpec,
    FutuSidecarAbortAttestation,
    FutuSidecarExecution,
    adapt_futu_daily_close_to_market_reference,
    execute_futu_plan,
    load_critical_financial_concepts,
    load_financial_field_registry,
    load_protocol_registry,
    load_reviewed_financial_field_registry,
    reproject_execution_with_financial_field_registry,
    reviewed_financial_field_registry_scope,
    validate_futu_attested_session_finalization,
)
from .owner_equity_research import (
    AuditPhaseResult,
    FutuMarketReferencePhaseResult,
    FutuNonPricePhaseResult,
    KernelValuationInput,
    KernelValuationPhaseResult,
    MarketExpectationsInput,
    MarketExpectationsPhaseResult,
    MarketReferenceInput,
    NonPriceVerificationInput,
    OfficialResearchPhaseResult,
    OwnerEquityResearchDependencies,
    OwnerEquityResearchError,
    OwnerEquityResearchInputReceipt,
    OwnerEquityResearchRequest,
    PhaseReceipt,
    PhaseStatus,
    PriceBlindRefreezeInput,
    PriceBlindRefreezePhaseResult,
    PublicationPhaseResult,
    PublicationProfile,
    QuarterlyPhaseResult,
    ReportBuildInput,
    ReportPhaseResult,
    ResearchIntent,
    ScorePhaseResult,
    ScoringInput,
    SecurityScope,
    SynthesisInput,
    SynthesisPhaseResult,
    _published_package_outcome,
    _report_phase_outcome,
    _score_phase_outcome,
    validate_owner_equity_research_schema_payload,
)
from .owner_equity_types import (
    FutuOptionalDataDisposition,
    MarketExpectationsComparison,
    ResearchSourceIndex,
    RuntimeGapReceipt,
    build_futu_optional_data_dispositions,
    build_market_expectations_comparison,
    build_research_source_index,
    compile_futu_optional_data_request_specs,
    load_reviewed_financial_field_admission,
)
from .owner_scorecard import (
    CompositeScoreGapAuthority,
    build_owner_scorecard,
    build_score_v2,
    resolve_score_review_authority,
)
from .research_publisher import (
    PublishedResearchPackage,
    load_owner_research_package,
    publish_owner_research,
    republish_owner_research_package,
)
from .research_report import (
    LatexReportRenderer,
    ReloadedResearchInput,
    ReloadedValuationInput,
    ReportBuildResult,
    build_research_report,
    reload_research_input,
    reload_valuation_input,
)
from .validation import ContractGraph
from .valuation_fact_mapping_policies import (
    SEC_SIC_COMPANY_TYPES,
    SEC_SIC_UNSUPPORTED_FINANCIAL_RANGE,
)
from .valuation_futu_market import (
    FutuMarketAuthorizationTicket,
    FutuMarketReferenceAcquisition,
    FutuMarketReferenceProvider,
    bind_futu_market_reference_provider,
    build_futu_daily_close_request_spec,
    complete_futu_market_session,
    reserve_futu_market_reference,
)
from .valuation_kernel_materializer import KernelMaterializationError
from .valuation_market_authority import load_market_access_authority
from .valuation_market_calendar import select_latest_completed_session
from .valuation_price_blind_freeze import PriceBlindFreezeCompilationResult
from .valuation_run import (
    ValuationRunAuthority,
    ValuationRunResult,
    _verify_runtime_supply,
)
from .valuation_run import (
    run_owner_valuation as run_low_level_valuation,
)
from .valuation_run_context import (
    CORE_JSON_MAX_BYTES,
    ValuationRunInputContext,
    load_valuation_run_input_context,
)
from .valuation_security_identity import SUPPORTED_MIC_CURRENCY
from .valuation_synthesis import (
    ReviewedPeerSetAuthority,
    ValuationSynthesisError,
    build_comparable_valuation,
    build_composite_valuation,
    build_forward_reoi_valuation,
    build_reviewed_peer_set_authority,
    build_valuation_basis_receipt,
)
from .valuation_synthesis_types import (
    ComparableValuationResult,
    CompositeValuationResult,
    ForwardReOIValuationResult,
    NamedHumanReviewAuthority,
    OwnerScorecard,
    ScoreV2,
    ValuationBasisReceipt,
    build_named_human_review_authority,
    retained_authority_replay_scope,
)

_CONFIG_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "research",
        "report",
        "publication",
        "audit",
        "valuation",
    }
)
_RESEARCH_FIELDS = frozenset(
    {
        "research_graph_file",
        "research_bundle_directory",
    }
)
_REPORT_FIELDS = frozenset({"report_spec_file"})
_PUBLICATION_OUTPUT_FIELDS = frozenset({"output_directory"})
_REPUBLICATION_FIELDS = frozenset({"input_package_directory", "output_directory"})
_AUDIT_FIELDS = frozenset({"package_directory"})
_VALUATION_LOCATOR_FIELDS = frozenset(
    {
        "keyring_file",
        "legal_receipt_file",
        "account_receipt_file",
        "supply_chain_receipt_file",
        "runtime_authorization_file",
        "runtime_receipt_file",
        "security_identity_receipt_file",
        "sidecar_socket",
        "sidecar_expected_uid",
        "sidecar_timeout_seconds",
        "sidecar_signer_key_id",
        "kernel_wheel",
        "kernel_repository",
        "kernel_runtime_manifest",
        "kernel_cas_root",
        "valuation_output_directory",
        "stage_plan_file",
        "futu_data_review_file",
        "peer_review_file",
        "synthesis_review_file",
        "score_review_file",
        "run_input_file",
        "price_blind_artifact_directory",
    }
)
_PRICE_BLIND_INTENTS = frozenset(
    {
        ResearchIntent.RESEARCH,
        ResearchIntent.QUARTERLY,
        ResearchIntent.REPORT,
        ResearchIntent.AUDIT,
    }
)
_MAX_JSON_DEPTH = 32
_MAX_JSON_MEMBERS = 4096
_MAX_RESEARCH_JSON_MEMBERS = 262_144
_MAX_CONFIG_STRING = 4096
_RESEARCH_JSON_MAX_BYTES = 64 * 1024 * 1024
_RESEARCH_INPUT_TOTAL_MAX_BYTES = 256 * 1024 * 1024

# Only these closed model-qualification/evidence gaps may degrade a genuine
# completed kernel run to a typed partial synthesis. Replay, identity,
# chronology, malformed-payload, and calculation-integrity failures remain
# exceptions and therefore enter the post-kernel quarantine.
_FORWARD_REOI_PANEL_GAPS = frozenset(
    {
        "forward ReOI requires exactly three scenarios",
        "forward ReOI terminal economics are invalid",
        "forward ReOI requires two to thirty forecast years",
        "forward ReOI requires base, bull, and black-swan",
        "kernel request lacks price-blind Penman authority",
        "forward ReOI review lacks current NOA Fact authority",
        "forward ReOI produces nonpositive per-share value",
    }
)
_COMPARABLE_PANEL_GAPS = frozenset(
    {
        "peer authority requires five to fifteen exact single-issuer graphs",
        "peer evidence requires at least one SEC/IR Fact",
        "peer Fact is not backed by SEC/IR authority",
        "peer Fact was unavailable at the research cutoff",
        "peer metrics were not validly pre-registered",
        "peer selection requires five to fifteen peers",
        "selected peer is outside the v1 USD universe",
        "peer multiple operands do not have registered SEC/IR semantics",
        "complete-case policy forbids dropping a preselected peer",
        "each comparable metric requires three scenarios",
        "comparable metric lacks a required scenario",
        "comparable metric implies nonpositive value",
    }
)


def _is_panel_qualification_gap(
    error: ValuationSynthesisError,
    *,
    panel: str,
) -> bool:
    messages = (
        _FORWARD_REOI_PANEL_GAPS
        if panel == "forward_reoi"
        else _COMPARABLE_PANEL_GAPS
    )
    return type(error) is ValuationSynthesisError and str(error) in messages
_RESEARCH_GRAPH_FIELDS = tuple(
    item.name for item in fields(ContractGraph) if item.name != "component_lock_path"
)
_RESEARCH_CONTEXT_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "component_lock_sha256",
        "graph_collections",
        "graph_fingerprint",
        "context_fingerprint",
    }
)
_STAGE_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "run_id",
        "authority_evaluated_at",
        "pre_price_request_started_at",
        "crosscheck_created_at",
        "market_request_started_at",
        "market_checkpoint_at",
        "conclusion_frozen_at",
        "post_request_started_at",
        "finalized_at",
        "kernel_timeout_seconds",
        "runtime_receipt_wait_seconds",
    }
)
_REVIEW_SPEC_FIELDS = frozenset(
    {
        "reviewer_id",
        "reviewed_at",
        "rationale",
        "reviewed_payload",
        "evidence_bindings",
    }
)
_SYNTHESIS_REVIEW_FIELDS = frozenset(
    {"schema_version", "artifact_type", "valuation_basis", "forward_reoi"}
)
_SCORE_REVIEW_FIELDS = frozenset({"schema_version", "artifact_type", "lenses"})
_FUTU_DATA_REVIEW_FIELDS = frozenset({"schema_version", "artifact_type", "review"})
_PEER_REVIEW_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "peer_graph_context_files",
        "selection_review",
        "forecast_review",
        "peers",
    }
)
_PEER_EXECUTION_FIELDS = frozenset(
    {"security_receipt_file", "request_started_at", "expected_trading_date"}
)
_LENSES = ("graham", "buffett", "munger", "duan_yongping")
_RUNTIME_AUTHORITY_PROTOCOLS = (3104,)
_PRE_PRICE_PROTOCOLS = (3202, 3227, 3228, 3234, 3236, 3243)
_POST_CONTEXT_PROTOCOLS = (3229, 3230, 3232)
_LIVE_PROTOCOLS = (
    *_RUNTIME_AUTHORITY_PROTOCOLS,
    *_PRE_PRICE_PROTOCOLS,
    3103,
    3202,
    *_POST_CONTEXT_PROTOCOLS,
)
_REQUEST_PAGE_CAPS = FrozenMap({3227: 10, 3230: 20, 3236: 10, 3246: 50})


class OwnerEquityRuntimeError(ValueError):
    """A runtime locator or reconstructed authority is invalid."""


@dataclass(slots=True)
class _ResearchReadBudget:
    limit: int
    consumed: int = 0
    snapshots: dict[Path, bytes] | None = None

    def __post_init__(self) -> None:
        if type(self.limit) is not int or self.limit <= 0:
            raise OwnerEquityRuntimeError("research input budget is invalid")
        if self.snapshots is None:
            self.snapshots = {}

    def read(self, path: Path, label: str, maximum: int) -> bytes:
        absolute = Path(path).expanduser().absolute()
        assert self.snapshots is not None
        cached = self.snapshots.get(absolute)
        if cached is not None:
            if len(cached) > maximum:
                raise OwnerEquityRuntimeError(f"{label} exceeds the byte limit")
            return cached
        remaining = self.limit - self.consumed
        effective_maximum = min(maximum, remaining)
        cumulative_error = (
            "research inputs exceed the 256 MiB cumulative byte limit"
            if effective_maximum < maximum
            else None
        )
        raw = _read_regular_file(
            absolute,
            label,
            effective_maximum,
            limit_error=cumulative_error,
        )
        self.capture(absolute, raw, label)
        return raw

    def capture(self, path: Path, raw: bytes, label: str) -> None:
        absolute = Path(path).expanduser().absolute()
        if type(raw) is not bytes:
            raise OwnerEquityRuntimeError(f"{label} is not an immutable byte snapshot")
        assert self.snapshots is not None
        cached = self.snapshots.get(absolute)
        if cached is not None:
            if cached != raw:
                raise OwnerEquityRuntimeError(
                    f"{label} differs from the invocation-scoped research snapshot"
                )
            return
        if self.consumed + len(raw) > self.limit:
            raise OwnerEquityRuntimeError(
                "research inputs exceed the 256 MiB cumulative byte limit"
            )
        self.snapshots[absolute] = raw
        self.consumed += len(raw)

    def read_artifact_member(
        self,
        path: Path,
        expected_size: int,
        reader: Callable[[], bytes],
    ) -> bytes:
        """Preflight one strict research-pair member against invocation capacity."""

        absolute = Path(path).expanduser().absolute()
        assert self.snapshots is not None
        if absolute in self.snapshots:
            raise OwnerEquityRuntimeError(
                "research artifact member was unexpectedly reopened in one invocation"
            )
        if expected_size > self.limit - self.consumed:
            raise OwnerEquityRuntimeError(
                "research inputs exceed the 256 MiB cumulative byte limit"
            )
        raw = reader()
        if len(raw) != expected_size:
            raise OwnerEquityRuntimeError(
                "research artifact member size changed during strict capture"
            )
        self.capture(absolute, raw, f"research input {absolute.name}")
        return raw


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OwnerEquityRuntimeError(f"runtime configuration repeats key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise OwnerEquityRuntimeError(f"runtime configuration contains non-finite value {value}")


def _validate_plain_json(
    value: object,
    *,
    depth: int = 0,
    maximum_members: int = _MAX_JSON_MEMBERS,
) -> int:
    if depth > _MAX_JSON_DEPTH:
        raise OwnerEquityRuntimeError("runtime configuration exceeds the nesting limit")
    if value is None or type(value) in {bool, int, float}:
        return 1
    if type(value) is str:
        if len(value) > _MAX_CONFIG_STRING or "\0" in value:
            raise OwnerEquityRuntimeError("runtime configuration string is not bounded")
        return 1
    if type(value) is list:
        count = 1
        for item in value:
            count += _validate_plain_json(
                item,
                depth=depth + 1,
                maximum_members=maximum_members,
            )
            if count > maximum_members:
                raise OwnerEquityRuntimeError("runtime configuration has too many members")
        return count
    if type(value) is dict:
        count = 1
        for key, item in value.items():
            if type(key) is not str:
                raise OwnerEquityRuntimeError("runtime configuration key is not a string")
            count += _validate_plain_json(
                key,
                depth=depth + 1,
                maximum_members=maximum_members,
            )
            count += _validate_plain_json(
                item,
                depth=depth + 1,
                maximum_members=maximum_members,
            )
            if count > maximum_members:
                raise OwnerEquityRuntimeError("runtime configuration has too many members")
        return count
    raise OwnerEquityRuntimeError("runtime configuration contains a non-JSON value")


def _read_regular_file(
    path: Path,
    label: str,
    maximum: int,
    *,
    limit_error: str | None = None,
) -> bytes:
    absolute = Path(path).expanduser().absolute()
    try:
        descriptor = os.open(
            absolute,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise OwnerEquityRuntimeError(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o022
        ):
            raise OwnerEquityRuntimeError(f"{label} is not one protected bounded regular file")
        if before.st_size > maximum:
            raise OwnerEquityRuntimeError(
                limit_error or f"{label} exceeds the byte limit"
            )
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise OwnerEquityRuntimeError(
                    limit_error or f"{label} exceeds the byte limit"
                )
            chunks.append(chunk)
        after = os.fstat(descriptor)

        def identity(item: os.stat_result) -> tuple[int, ...]:
            return (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_nlink,
                item.st_uid,
                item.st_gid,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if identity(before) != identity(after) or consumed != before.st_size:
            raise OwnerEquityRuntimeError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_canonical_object(
    path: Path,
    label: str,
    *,
    maximum_bytes: int = CORE_JSON_MAX_BYTES,
    maximum_members: int = _MAX_JSON_MEMBERS,
    research_budget: _ResearchReadBudget | None = None,
) -> dict[str, Any]:
    raw = (
        _read_regular_file(path, label, maximum_bytes)
        if research_budget is None
        else research_budget.read(path, label, maximum_bytes)
    )
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OwnerEquityRuntimeError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise OwnerEquityRuntimeError(f"{label} must be a JSON object")
    _validate_plain_json(payload, maximum_members=maximum_members)
    if raw != (canonical_json(payload) + "\n").encode("utf-8"):
        raise OwnerEquityRuntimeError(f"{label} is not canonically serialized")
    return payload


def _closed_object(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise OwnerEquityRuntimeError(f"{label} fields are not closed")
    return value


def _absolute_path(value: object, label: str) -> Path:
    if type(value) is not str or not value or "\0" in value:
        raise OwnerEquityRuntimeError(f"{label} must be an absolute path string")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise OwnerEquityRuntimeError(f"{label} must be a normalized absolute path")
    return path


def _runtime_timestamp(value: object, label: str) -> str:
    if type(value) is not str:
        raise OwnerEquityRuntimeError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OwnerEquityRuntimeError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise OwnerEquityRuntimeError(f"{label} must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _runtime_date(value: object, label: str) -> str:
    from datetime import date

    if type(value) is not str:
        raise OwnerEquityRuntimeError(f"{label} must be an ISO-8601 date")
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise OwnerEquityRuntimeError(f"{label} must be an ISO-8601 date") from exc


def _exact_string(value: object, label: str, *, prefix: str | None = None) -> str:
    if type(value) is not str or not value.strip() or len(value) > _MAX_CONFIG_STRING:
        raise OwnerEquityRuntimeError(f"{label} must be a nonempty bounded string")
    if prefix is not None and not value.startswith(prefix):
        raise OwnerEquityRuntimeError(f"{label} must start with {prefix!r}")
    return value


def _component_lock_sha256(graph: ContractGraph) -> str:
    import hashlib

    return hashlib.sha256(
        _read_regular_file(graph.component_lock_path, "component lock", CORE_JSON_MAX_BYTES)
    ).hexdigest()


def _research_graph_payload(graph: ContractGraph) -> dict[str, list[dict[str, Any]]]:
    if type(graph) is not ContractGraph:
        raise OwnerEquityRuntimeError("research context requires the exact ContractGraph")
    graph.validate()
    if graph.market_reference_validation_contexts:
        raise OwnerEquityRuntimeError("research context cannot contain market validation state")
    output: dict[str, list[dict[str, Any]]] = {}
    for name in _RESEARCH_GRAPH_FIELDS:
        records: list[dict[str, Any]] = []
        for item in getattr(graph, name):
            if not isinstance(item, Contract):
                raise OwnerEquityRuntimeError(
                    f"research graph collection {name} contains a non-public authority"
                )
            records.append(
                {
                    "schema_name": item.SCHEMA_NAME,
                    "payload": item.to_dict(),
                }
            )
        output[name] = records
    return output


def _research_context_payload(graph: ContractGraph) -> dict[str, Any]:
    graph_collections = _research_graph_payload(graph)
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "artifact_type": "owner-research-graph-context",
        "component_lock_sha256": _component_lock_sha256(graph),
        "graph_collections": graph_collections,
        "graph_fingerprint": canonical_sha256(graph_collections),
    }
    payload["context_fingerprint"] = canonical_sha256(payload)
    return payload


def _load_research_graph(payload: object) -> ContractGraph:
    if type(payload) is not dict or set(payload) != set(_RESEARCH_GRAPH_FIELDS):
        raise OwnerEquityRuntimeError("research graph collection fields are not closed")
    values: dict[str, tuple[Contract, ...]] = {}
    for name in _RESEARCH_GRAPH_FIELDS:
        records = payload[name]
        if type(records) is not list:
            raise OwnerEquityRuntimeError(f"research graph collection {name} is not an array")
        items: list[Contract] = []
        for record in records:
            if type(record) is not dict or set(record) != {"schema_name", "payload"}:
                raise OwnerEquityRuntimeError(
                    f"research graph collection {name} has an invalid record"
                )
            try:
                item = contract_from_dict(record["schema_name"], record["payload"])
            except (KeyError, TypeError, ValueError) as exc:
                raise OwnerEquityRuntimeError(
                    f"research graph collection {name} contains an invalid contract"
                ) from exc
            items.append(item)
        values[name] = tuple(items)
    try:
        graph = ContractGraph(**values)
        graph.validate()
    except (TypeError, ValueError) as exc:
        raise OwnerEquityRuntimeError("research ContractGraph does not replay") from exc
    return graph


@dataclass(frozen=True, slots=True)
class ResearchRuntimeContext:
    graph: ContractGraph
    component_lock_sha256: str
    graph_fingerprint: str
    context_fingerprint: str

    def __post_init__(self) -> None:
        if type(self.graph) is not ContractGraph:
            raise OwnerEquityRuntimeError("research runtime context lacks an exact graph")
        expected = _research_context_payload(self.graph)
        if (
            self.component_lock_sha256 != expected["component_lock_sha256"]
            or self.graph_fingerprint != expected["graph_fingerprint"]
            or self.context_fingerprint != expected["context_fingerprint"]
        ):
            raise OwnerEquityRuntimeError("research runtime context identity does not replay")


def write_research_runtime_context(*, graph: ContractGraph, output_file: Path) -> Path:
    """Idempotently materialize a price-blind graph authority for ordinary research."""

    content = (canonical_json(_research_context_payload(graph)) + "\n").encode("utf-8")
    if len(content) > _RESEARCH_JSON_MAX_BYTES:
        raise OwnerEquityRuntimeError("research graph context exceeds the byte limit")
    target = Path(output_file).expanduser().absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise OwnerEquityRuntimeError("research graph context cannot be a symlink")
    if target.exists():
        if (
            _read_regular_file(target, "research graph context", _RESEARCH_JSON_MAX_BYTES)
            == content
        ):
            return target
        raise OwnerEquityRuntimeError("research graph context exists with different content")
    staging = target.parent / f".{target.name}.staging-{uuid.uuid4().hex}"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            staging,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OwnerEquityRuntimeError("research graph context write did not complete")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(staging, target, follow_symlinks=False)
        os.unlink(staging)
        parent_descriptor = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except FileExistsError as exc:
        existing = _read_regular_file(
            target,
            "research graph context",
            _RESEARCH_JSON_MAX_BYTES,
        )
        if existing != content:
            raise OwnerEquityRuntimeError(
                "research graph context exists with different content"
            ) from exc
    except OSError as exc:
        raise OwnerEquityRuntimeError("research graph context publication failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if staging.exists():
            staging.unlink()
    return target


def load_research_runtime_context(
    input_file: Path,
    *,
    research_budget: _ResearchReadBudget | None = None,
) -> ResearchRuntimeContext:
    payload = _read_canonical_object(
        input_file,
        "research graph context",
        maximum_bytes=_RESEARCH_JSON_MAX_BYTES,
        maximum_members=_MAX_RESEARCH_JSON_MEMBERS,
        research_budget=research_budget,
    )
    if set(payload) != _RESEARCH_CONTEXT_FIELDS or (
        payload.get("schema_version"),
        payload.get("artifact_type"),
    ) != ("1.0.0", "owner-research-graph-context"):
        raise OwnerEquityRuntimeError("research graph context fields are not closed")
    supplied_fingerprint = payload["context_fingerprint"]
    identity = dict(payload)
    identity.pop("context_fingerprint")
    if supplied_fingerprint != canonical_sha256(identity):
        raise OwnerEquityRuntimeError("research graph context fingerprint does not replay")
    graph = _load_research_graph(payload["graph_collections"])
    expected = _research_context_payload(graph)
    if expected != payload:
        raise OwnerEquityRuntimeError("research graph context changed its graph or component lock")
    return ResearchRuntimeContext(
        graph=graph,
        component_lock_sha256=payload["component_lock_sha256"],
        graph_fingerprint=payload["graph_fingerprint"],
        context_fingerprint=payload["context_fingerprint"],
    )


@dataclass(frozen=True, slots=True)
class Ed25519PublicKeyring(SignatureVerifier):
    """Closed public-key verifier; private keys never enter the research process."""

    keyring_id: str
    keys: FrozenMap
    keyring_fingerprint: str

    def __post_init__(self) -> None:
        if type(self.keyring_id) is not str or not self.keyring_id.startswith("keyring:"):
            raise OwnerEquityRuntimeError("Ed25519 keyring identity is invalid")
        keys = freeze(self.keys)
        if not keys or any(type(key) is not str or not key for key in keys):
            raise OwnerEquityRuntimeError("Ed25519 keyring must contain named public keys")
        for public_key_hex in keys.values():
            if type(public_key_hex) is not str or len(public_key_hex) != 64:
                raise OwnerEquityRuntimeError("Ed25519 public key must be 32-byte hex")
            try:
                key_bytes = bytes.fromhex(public_key_hex)
                Ed25519PublicKey.from_public_bytes(key_bytes)
            except (ValueError, TypeError) as exc:
                raise OwnerEquityRuntimeError("Ed25519 public key is invalid") from exc
        expected = canonical_sha256(
            {"keyring_id": self.keyring_id, "algorithm": "ed25519", "keys": keys}
        )
        if self.keyring_fingerprint != expected:
            raise OwnerEquityRuntimeError("Ed25519 keyring fingerprint does not replay")
        object.__setattr__(self, "keys", keys)

    @classmethod
    def from_file(cls, path: Path) -> Ed25519PublicKeyring:
        payload = _read_canonical_object(path, "Ed25519 public keyring")
        if (
            set(payload)
            != {
                "schema_version",
                "artifact_type",
                "keyring_id",
                "algorithm",
                "keys",
                "keyring_fingerprint",
            }
            or payload.get("schema_version") != "1.0.0"
            or payload.get("artifact_type") != "owner-research-public-keyring"
            or payload.get("algorithm") != "ed25519"
        ):
            raise OwnerEquityRuntimeError("Ed25519 keyring fields are not closed")
        keys = payload["keys"]
        if type(keys) is not list or not keys:
            raise OwnerEquityRuntimeError("Ed25519 keyring keys must be a nonempty array")
        mapped: dict[str, str] = {}
        for item in keys:
            if type(item) is not dict or set(item) != {"key_id", "public_key_hex"}:
                raise OwnerEquityRuntimeError("Ed25519 key record fields are not closed")
            key_id = item["key_id"]
            if type(key_id) is not str or not key_id or key_id in mapped:
                raise OwnerEquityRuntimeError("Ed25519 key IDs must be nonempty and unique")
            mapped[key_id] = item["public_key_hex"]
        return cls(
            keyring_id=payload["keyring_id"],
            keys=freeze(mapped),
            keyring_fingerprint=payload["keyring_fingerprint"],
        )

    def verify(self, *, signer_key_id: str, payload: bytes, signature_hex: str) -> bool:
        public_key_hex = self.keys.get(signer_key_id)
        if type(public_key_hex) is not str or type(payload) is not bytes:
            return False
        if type(signature_hex) is not str or len(signature_hex) != 128:
            return False
        try:
            signature = bytes.fromhex(signature_hex)
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            key.verify(signature, payload)
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True


@dataclass(frozen=True, slots=True)
class RuntimeResearchAuthority:
    context: ResearchRuntimeContext
    research: ReloadedResearchInput
    source_index: ResearchSourceIndex

    def __post_init__(self) -> None:
        if (
            type(self.context) is not ResearchRuntimeContext
            or type(self.research) is not ReloadedResearchInput
            or type(self.source_index) is not ResearchSourceIndex
        ):
            raise OwnerEquityRuntimeError("runtime research authority has a wrong exact type")
        expected_files = {
            "research-bundle.json": (
                canonical_json(self.research.result.bundle.to_dict()) + "\n"
            ).encode("utf-8"),
            "run-manifest.json": (
                canonical_json(self.research.result.run_manifest.to_dict()) + "\n"
            ).encode("utf-8"),
        }
        if dict(self.research.file_bytes) != expected_files:
            raise OwnerEquityRuntimeError("runtime research byte snapshot does not replay")
        expected_index = build_research_source_index(
            graph=self.context.graph,
            research=self.research.result,
        )
        if expected_index != self.source_index:
            raise OwnerEquityRuntimeError("runtime source index changed its exact authority")


@dataclass(frozen=True, slots=True)
class NamedReviewPlan:
    reviewer_id: str
    reviewed_at: str
    rationale: str
    reviewed_payload: FrozenMap
    evidence_bindings: tuple[FrozenMap, ...]

    def __post_init__(self) -> None:
        _exact_string(self.reviewer_id, "reviewer_id", prefix="human:")
        object.__setattr__(
            self,
            "reviewed_at",
            _runtime_timestamp(self.reviewed_at, "reviewed_at"),
        )
        _exact_string(self.rationale, "review rationale")
        if not isinstance(self.reviewed_payload, Mapping):
            raise OwnerEquityRuntimeError("reviewed_payload must be an object")
        bindings = tuple(freeze(item) for item in self.evidence_bindings)
        if not bindings:
            raise OwnerEquityRuntimeError("review plan requires exact evidence bindings")
        for binding in bindings:
            if set(binding) != {"object_type", "object_id", "fingerprint"}:
                raise OwnerEquityRuntimeError("review evidence binding fields are not closed")
        object.__setattr__(self, "reviewed_payload", freeze(self.reviewed_payload))
        object.__setattr__(self, "evidence_bindings", bindings)

    @classmethod
    def from_payload(cls, value: object, label: str) -> NamedReviewPlan:
        payload = _closed_object(value, _REVIEW_SPEC_FIELDS, label)
        bindings = payload["evidence_bindings"]
        if not isinstance(bindings, list):
            raise OwnerEquityRuntimeError(f"{label}.evidence_bindings must be an array")
        return cls(
            reviewer_id=payload["reviewer_id"],
            reviewed_at=payload["reviewed_at"],
            rationale=payload["rationale"],
            reviewed_payload=freeze(payload["reviewed_payload"]),
            evidence_bindings=tuple(freeze(item) for item in bindings),
        )

    def build(
        self,
        *,
        scope: str,
        graph: ContractGraph,
        research_bundle: object,
    ) -> NamedHumanReviewAuthority:
        return build_named_human_review_authority(
            scope=scope,
            graph=graph,
            research_bundle=research_bundle,
            reviewer_id=self.reviewer_id,
            reviewed_at=self.reviewed_at,
            rationale=self.rationale,
            reviewed_payload=self.reviewed_payload,
            evidence_bindings=self.evidence_bindings,
        )


@dataclass(frozen=True, slots=True)
class LiveStagePlan:
    run_id: str
    authority_evaluated_at: str
    pre_price_request_started_at: str
    crosscheck_created_at: str
    market_request_started_at: str
    market_checkpoint_at: str
    conclusion_frozen_at: str
    post_request_started_at: str
    finalized_at: str
    kernel_timeout_seconds: int
    runtime_receipt_wait_seconds: float
    plan_fingerprint: str

    def __post_init__(self) -> None:
        _exact_string(self.run_id, "stage plan run_id", prefix="run:")
        names = (
            "authority_evaluated_at",
            "pre_price_request_started_at",
            "crosscheck_created_at",
            "market_request_started_at",
            "market_checkpoint_at",
            "conclusion_frozen_at",
            "post_request_started_at",
            "finalized_at",
        )
        normalized = tuple(
            _runtime_timestamp(getattr(self, name), f"stage plan {name}") for name in names
        )
        for name, value in zip(names, normalized, strict=True):
            object.__setattr__(self, name, value)
        parsed = tuple(datetime.fromisoformat(item.replace("Z", "+00:00")) for item in normalized)
        if parsed != tuple(sorted(parsed)) or not (
            parsed[0]
            <= parsed[1]
            <= parsed[2]
            <= parsed[3]
            <= parsed[4]
            < parsed[5]
            < parsed[6]
            <= parsed[7]
        ):
            raise OwnerEquityRuntimeError("live stage plan chronology is invalid")
        if (
            type(self.kernel_timeout_seconds) is not int
            or not 1 <= self.kernel_timeout_seconds <= 900
        ):
            raise OwnerEquityRuntimeError("kernel timeout must be between one and 900 seconds")
        if (
            isinstance(self.runtime_receipt_wait_seconds, bool)
            or not isinstance(self.runtime_receipt_wait_seconds, (int, float))
            or not 0 < float(self.runtime_receipt_wait_seconds) <= 60
        ):
            raise OwnerEquityRuntimeError(
                "runtime receipt wait must be between zero and 60 seconds"
            )
        object.__setattr__(
            self,
            "runtime_receipt_wait_seconds",
            float(self.runtime_receipt_wait_seconds),
        )
        if self.plan_fingerprint != canonical_sha256(self.to_dict()):
            raise OwnerEquityRuntimeError("live stage plan fingerprint does not replay")

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "authority_evaluated_at": self.authority_evaluated_at,
            "pre_price_request_started_at": self.pre_price_request_started_at,
            "crosscheck_created_at": self.crosscheck_created_at,
            "market_request_started_at": self.market_request_started_at,
            "market_checkpoint_at": self.market_checkpoint_at,
            "conclusion_frozen_at": self.conclusion_frozen_at,
            "post_request_started_at": self.post_request_started_at,
            "finalized_at": self.finalized_at,
            "kernel_timeout_seconds": self.kernel_timeout_seconds,
            "runtime_receipt_wait_seconds": self.runtime_receipt_wait_seconds,
        }


@dataclass(frozen=True, slots=True)
class SynthesisReviewPlan:
    valuation_basis: NamedReviewPlan
    forward_reoi: NamedReviewPlan
    plan_fingerprint: str

    def __post_init__(self) -> None:
        if (
            type(self.valuation_basis) is not NamedReviewPlan
            or type(self.forward_reoi) is not NamedReviewPlan
        ):
            raise OwnerEquityRuntimeError("synthesis review plan has a wrong exact type")


@dataclass(frozen=True, slots=True)
class ScoreReviewPlan:
    lenses: FrozenMap
    plan_fingerprint: str

    def __post_init__(self) -> None:
        lenses = freeze(self.lenses)
        if set(lenses) != set(_LENSES) or any(
            type(value) is not NamedReviewPlan for value in lenses.values()
        ):
            raise OwnerEquityRuntimeError("score review plan must contain four exact lenses")
        object.__setattr__(self, "lenses", lenses)


@dataclass(frozen=True, slots=True)
class PeerExecutionPlan:
    security_receipt_file: Path
    request_started_at: str
    expected_trading_date: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "security_receipt_file",
            _absolute_path(self.security_receipt_file, "peer security receipt"),
        )
        object.__setattr__(
            self,
            "request_started_at",
            _runtime_timestamp(self.request_started_at, "peer request_started_at"),
        )
        object.__setattr__(
            self,
            "expected_trading_date",
            _runtime_date(self.expected_trading_date, "peer expected_trading_date"),
        )


@dataclass(frozen=True, slots=True)
class PeerReviewPlan:
    peer_graph_contexts: tuple[ResearchRuntimeContext, ...]
    selection_review: NamedReviewPlan
    forecast_review: NamedReviewPlan
    peers: tuple[PeerExecutionPlan, ...]
    plan_fingerprint: str

    def __post_init__(self) -> None:
        contexts = tuple(self.peer_graph_contexts)
        if (
            not 5 <= len(contexts) <= 15
            or any(type(item) is not ResearchRuntimeContext for item in contexts)
            or type(self.selection_review) is not NamedReviewPlan
            or type(self.forecast_review) is not NamedReviewPlan
        ):
            raise OwnerEquityRuntimeError("peer review plan has a wrong exact authority")
        peers = tuple(self.peers)
        if not 5 <= len(peers) <= 15 or any(type(item) is not PeerExecutionPlan for item in peers):
            raise OwnerEquityRuntimeError("peer review plan requires five to fifteen peers")
        if len(contexts) != len(peers):
            raise OwnerEquityRuntimeError("peer graphs and execution plans differ in count")
        object.__setattr__(self, "peer_graph_contexts", contexts)
        object.__setattr__(self, "peers", peers)


@dataclass(frozen=True, slots=True)
class RuntimeValuationLocators:
    values: FrozenMap

    def __post_init__(self) -> None:
        values = freeze(self.values)
        if set(values) != _VALUATION_LOCATOR_FIELDS:
            raise OwnerEquityRuntimeError("valuation runtime locator fields are not closed")
        for name in _VALUATION_LOCATOR_FIELDS - {
            "sidecar_expected_uid",
            "sidecar_timeout_seconds",
            "sidecar_signer_key_id",
        }:
            value = values[name]
            if value is not None:
                _absolute_path(value, f"valuation.{name}")
        uid = values["sidecar_expected_uid"]
        timeout = values["sidecar_timeout_seconds"]
        signer_key_id = values["sidecar_signer_key_id"]
        if uid is not None and (type(uid) is not int or uid < 0):
            raise OwnerEquityRuntimeError("valuation.sidecar_expected_uid is invalid")
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0 < float(timeout) <= 60
        ):
            raise OwnerEquityRuntimeError("valuation.sidecar_timeout_seconds is invalid")
        if signer_key_id is not None:
            _exact_string(
                signer_key_id,
                "valuation.sidecar_signer_key_id",
            )
        object.__setattr__(self, "values", values)

    @property
    def missing_authority_codes(self) -> tuple[str, ...]:
        required = {
            "keyring_file": "authority_keyring_missing",
            "legal_receipt_file": "legal_right_missing",
            "account_receipt_file": "account_entitlement_missing",
            "supply_chain_receipt_file": "supply_chain_missing",
            "runtime_authorization_file": "runtime_isolation_missing",
            "security_identity_receipt_file": "security_identity_missing",
            "sidecar_socket": "sidecar_socket_missing",
            "sidecar_expected_uid": "sidecar_expected_uid_missing",
            "sidecar_timeout_seconds": "sidecar_timeout_missing",
            "sidecar_signer_key_id": "sidecar_signer_key_missing",
            "kernel_wheel": "kernel_wheel_missing",
            "kernel_repository": "kernel_repository_missing",
            "kernel_runtime_manifest": "kernel_runtime_manifest_missing",
            "kernel_cas_root": "kernel_cas_root_missing",
            "valuation_output_directory": "valuation_output_missing",
            "stage_plan_file": "futu_stage_plan_missing",
            "futu_data_review_file": "futu_data_review_missing",
            "peer_review_file": "peer_review_missing",
            "synthesis_review_file": "synthesis_review_missing",
            "score_review_file": "score_review_missing",
            "run_input_file": "run_input_missing",
            "price_blind_artifact_directory": "price_blind_input_missing",
        }
        return tuple(sorted(code for name, code in required.items() if self.values[name] is None))


@dataclass(frozen=True, slots=True)
class OwnerEquityRuntime:
    intent: ResearchIntent
    profile: PublicationProfile | None
    research_authority: RuntimeResearchAuthority | None
    valuation_context: ValuationRunInputContext | None
    report_spec: ReportSpec | None
    publication_output: Path | None
    publication_source_package: PublishedResearchPackage | None
    audit_package: PublishedResearchPackage | None
    valuation_locators: RuntimeValuationLocators | None
    config_fingerprint: str
    research_read_budget: _ResearchReadBudget

    def __post_init__(self) -> None:
        if type(self.intent) is not ResearchIntent:
            raise OwnerEquityRuntimeError("runtime intent has a wrong exact type")
        if self.profile is not None and type(self.profile) is not PublicationProfile:
            raise OwnerEquityRuntimeError("runtime profile has a wrong exact type")
        if self.intent in {
            ResearchIntent.RESEARCH,
            ResearchIntent.QUARTERLY,
            ResearchIntent.AUDIT,
        }:
            if self.profile is not None:
                raise OwnerEquityRuntimeError("runtime route forbids a profile")
        elif self.intent is ResearchIntent.REPORT:
            if self.profile is not PublicationProfile.RESEARCH_ONLY:
                raise OwnerEquityRuntimeError("report runtime must be research_only")
        elif self.intent is ResearchIntent.VALUATION:
            if self.profile is not PublicationProfile.FULL_VALUATION:
                raise OwnerEquityRuntimeError("valuation runtime must be full_valuation")
        elif self.intent is ResearchIntent.PUBLISH and self.profile is None:
            raise OwnerEquityRuntimeError("publish runtime requires a profile")
        if (
            self.research_authority is not None
            and type(self.research_authority) is not RuntimeResearchAuthority
        ):
            raise OwnerEquityRuntimeError("runtime research authority has a wrong exact type")
        if (
            self.valuation_context is not None
            and type(self.valuation_context) is not ValuationRunInputContext
        ):
            raise OwnerEquityRuntimeError("runtime valuation context has a wrong exact type")
        if self.report_spec is not None and type(self.report_spec) is not ReportSpec:
            raise OwnerEquityRuntimeError("runtime report specification has a wrong exact type")
        if self.publication_output is not None and not isinstance(self.publication_output, Path):
            raise OwnerEquityRuntimeError("runtime publication output has a wrong exact type")
        if (
            self.publication_source_package is not None
            and type(self.publication_source_package) is not PublishedResearchPackage
        ):
            raise OwnerEquityRuntimeError(
                "runtime publication source package has a wrong exact type"
            )
        if (
            self.audit_package is not None
            and type(self.audit_package) is not PublishedResearchPackage
        ):
            raise OwnerEquityRuntimeError("runtime audit package has a wrong exact type")
        if (
            self.valuation_locators is not None
            and type(self.valuation_locators) is not RuntimeValuationLocators
        ):
            raise OwnerEquityRuntimeError("runtime valuation locators have a wrong exact type")
        if (
            type(self.config_fingerprint) is not str
            or len(self.config_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in self.config_fingerprint)
        ):
            raise OwnerEquityRuntimeError("runtime config fingerprint is invalid")
        if type(self.research_read_budget) is not _ResearchReadBudget:
            raise OwnerEquityRuntimeError("runtime research input budget is unavailable")
        if self.research_authority is None:
            if (self.audit_package is None) == (self.publication_source_package is None):
                raise OwnerEquityRuntimeError(
                    "authority-free runtime must bind exactly one strict package capability"
                )
        elif self.audit_package is not None or self.publication_source_package is not None:
            raise OwnerEquityRuntimeError(
                "research runtime cannot retain an audit or republication package"
            )
        if self.audit_package is not None and any(
            value is not None
            for value in (
                self.valuation_context,
                self.report_spec,
                self.publication_output,
                self.publication_source_package,
                self.valuation_locators,
            )
        ):
            raise OwnerEquityRuntimeError("audit runtime crossed another capability")
        if self.publication_source_package is not None and (
            self.publication_output is None
            or self.audit_package is not None
            or self.report_spec is not None
            or self.valuation_context is not None
            or self.valuation_locators is not None
        ):
            raise OwnerEquityRuntimeError("republication runtime crossed another capability")
        if self.valuation_context is not None and self.research_authority is None:
            raise OwnerEquityRuntimeError("valuation runtime lacks research authority")
        if self.publication_output is not None:
            object.__setattr__(self, "publication_output", self.publication_output.absolute())


def _load_report_spec(path: Path) -> ReportSpec:
    payload = _read_canonical_object(path, "report specification")
    try:
        value = contract_from_dict("report-spec", payload)
    except (TypeError, ValueError) as exc:
        raise OwnerEquityRuntimeError("report specification does not validate") from exc
    if type(value) is not ReportSpec:
        raise OwnerEquityRuntimeError("report specification has the wrong contract type")
    if value.language != "zh-CN" or "latex_pdf" not in value.output_formats:
        raise OwnerEquityRuntimeError("report specification must require Simplified Chinese PDF")
    return value


def _load_live_stage_plan(path: Path) -> LiveStagePlan:
    payload = _read_canonical_object(path, "live Futu stage plan")
    if set(payload) != _STAGE_PLAN_FIELDS or (
        payload.get("schema_version"),
        payload.get("artifact_type"),
    ) != ("1.0.0", "owner-equity-live-stage-plan"):
        raise OwnerEquityRuntimeError("live Futu stage plan fields are not closed")
    values = dict(payload)
    values.pop("schema_version")
    values.pop("artifact_type")
    return LiveStagePlan(
        **values,
        plan_fingerprint=canonical_sha256(payload),
    )


def _load_synthesis_review_plan(
    path: Path, *, research_budget: _ResearchReadBudget | None = None
) -> SynthesisReviewPlan:
    payload = _read_canonical_object(
        path, "synthesis review plan", research_budget=research_budget
    )
    if set(payload) != _SYNTHESIS_REVIEW_FIELDS or (
        payload.get("schema_version"),
        payload.get("artifact_type"),
    ) != ("1.0.0", "owner-equity-synthesis-review-plan"):
        raise OwnerEquityRuntimeError("synthesis review plan fields are not closed")
    return SynthesisReviewPlan(
        valuation_basis=NamedReviewPlan.from_payload(
            payload["valuation_basis"], "valuation basis review"
        ),
        forward_reoi=NamedReviewPlan.from_payload(payload["forward_reoi"], "forward ReOI review"),
        plan_fingerprint=canonical_sha256(payload),
    )


def _load_futu_data_review_plan(
    path: Path, *, research_budget: _ResearchReadBudget | None = None
) -> NamedReviewPlan:
    payload = _read_canonical_object(
        path, "Futu optional-data review plan", research_budget=research_budget
    )
    if set(payload) != _FUTU_DATA_REVIEW_FIELDS or (
        payload.get("schema_version"),
        payload.get("artifact_type"),
    ) != ("1.0.0", "owner-equity-futu-data-review-plan"):
        raise OwnerEquityRuntimeError("Futu optional-data review plan fields are not closed")
    return NamedReviewPlan.from_payload(payload["review"], "Futu optional-data review")


def _load_score_review_plan(
    path: Path, *, research_budget: _ResearchReadBudget | None = None
) -> ScoreReviewPlan:
    payload = _read_canonical_object(
        path, "score review plan", research_budget=research_budget
    )
    if set(payload) != _SCORE_REVIEW_FIELDS or (
        payload.get("schema_version"),
        payload.get("artifact_type"),
    ) != ("1.0.0", "owner-equity-score-review-plan"):
        raise OwnerEquityRuntimeError("score review plan fields are not closed")
    raw_lenses = payload["lenses"]
    if type(raw_lenses) is not dict or set(raw_lenses) != set(_LENSES):
        raise OwnerEquityRuntimeError("score review lens set is not closed")
    lenses = {
        lens: NamedReviewPlan.from_payload(raw_lenses[lens], f"{lens} score review")
        for lens in _LENSES
    }
    return ScoreReviewPlan(
        lenses=freeze(lenses),
        plan_fingerprint=canonical_sha256(payload),
    )


def _load_peer_review_plan(
    path: Path, *, research_budget: _ResearchReadBudget | None = None
) -> PeerReviewPlan:
    payload = _read_canonical_object(
        path,
        "peer review plan",
        maximum_bytes=_RESEARCH_JSON_MAX_BYTES,
        maximum_members=_MAX_RESEARCH_JSON_MEMBERS,
        research_budget=research_budget,
    )
    if set(payload) != _PEER_REVIEW_FIELDS or (
        payload.get("schema_version"),
        payload.get("artifact_type"),
    ) != ("1.0.0", "owner-equity-peer-review-plan"):
        raise OwnerEquityRuntimeError("peer review plan fields are not closed")
    raw_peers = payload["peers"]
    if not isinstance(raw_peers, list):
        raise OwnerEquityRuntimeError("peer execution plan must be an array")
    peers: list[PeerExecutionPlan] = []
    for index, raw_peer in enumerate(raw_peers):
        item = _closed_object(raw_peer, _PEER_EXECUTION_FIELDS, f"peer plan {index}")
        peers.append(
            PeerExecutionPlan(
                security_receipt_file=_absolute_path(
                    item["security_receipt_file"],
                    f"peer plan {index} security_receipt_file",
                ),
                request_started_at=item["request_started_at"],
                expected_trading_date=item["expected_trading_date"],
            )
        )
    peer_context_files = payload["peer_graph_context_files"]
    if not isinstance(peer_context_files, list):
        raise OwnerEquityRuntimeError("peer graph context files must be an array")
    return PeerReviewPlan(
        peer_graph_contexts=tuple(
            load_research_runtime_context(
                _absolute_path(item, f"peer_graph_context_files[{index}]"),
                research_budget=research_budget,
            )
            for index, item in enumerate(peer_context_files)
        ),
        selection_review=NamedReviewPlan.from_payload(
            payload["selection_review"], "peer selection review"
        ),
        forecast_review=NamedReviewPlan.from_payload(
            payload["forecast_review"], "peer comparable forecast review"
        ),
        peers=tuple(peers),
        plan_fingerprint=canonical_sha256(payload),
    )


def _load_signed_receipt(path: Path, schema_name: str, expected_type: type[Any]) -> Any:
    payload = _read_canonical_object(path, schema_name)
    try:
        receipt = load_futu_signed_receipt(schema_name, payload)
    except (TypeError, ValueError) as exc:
        raise OwnerEquityRuntimeError(f"{schema_name} does not replay") from exc
    if type(receipt) is not expected_type:
        raise OwnerEquityRuntimeError(f"{schema_name} has the wrong exact type")
    return receipt


def _regular_file_sha256(path: Path, label: str, maximum: int = CORE_JSON_MAX_BYTES) -> str:
    return hashlib.sha256(_read_regular_file(path, label, maximum)).hexdigest()


def _load_research_authority(
    research_config: dict[str, Any], *, research_budget: _ResearchReadBudget
) -> RuntimeResearchAuthority:
    research_graph = _absolute_path(
        research_config["research_graph_file"],
        "research.research_graph_file",
    )
    research_directory = _absolute_path(
        research_config["research_bundle_directory"],
        "research.research_bundle_directory",
    )
    context = load_research_runtime_context(
        research_graph, research_budget=research_budget
    )
    try:
        research = reload_research_input(
            research_directory,
            graph=context.graph,
            maximum_total_bytes=research_budget.limit - research_budget.consumed,
            read_callback=research_budget.read_artifact_member,
        )
    except (OSError, TypeError, ValueError) as exc:
        if "cumulative byte limit" in str(exc) or "256 MiB cumulative" in str(exc):
            raise OwnerEquityRuntimeError(
                "research inputs exceed the 256 MiB cumulative byte limit"
            ) from exc
        raise OwnerEquityRuntimeError("research input strict reload failed") from exc
    source_index = build_research_source_index(
        graph=context.graph,
        research=research.result,
    )
    return RuntimeResearchAuthority(
        context=context,
        research=research,
        source_index=source_index,
    )


def load_owner_equity_runtime(
    config_file: Path,
    *,
    intent: ResearchIntent,
    profile: PublicationProfile | None,
) -> OwnerEquityRuntime:
    """Load only the capabilities needed by one closed route."""

    if type(intent) is not ResearchIntent:
        raise OwnerEquityRuntimeError("runtime loader requires an exact ResearchIntent")
    payload = _read_canonical_object(Path(config_file), "owner equity runtime config")
    try:
        validate_owner_equity_research_schema_payload(
            "owner-equity-runtime-config",
            payload,
        )
    except OwnerEquityResearchError as exc:
        raise OwnerEquityRuntimeError("owner equity runtime config schema is invalid") from exc
    if set(payload) != _CONFIG_FIELDS or (
        payload.get("schema_version"),
        payload.get("artifact_type"),
    ) != ("1.0.0", "owner-equity-runtime-config"):
        raise OwnerEquityRuntimeError("owner equity runtime config fields are not closed")
    research_budget = _ResearchReadBudget(_RESEARCH_INPUT_TOTAL_MAX_BYTES)
    research_config = payload["research"]
    if intent in {ResearchIntent.AUDIT, ResearchIntent.PUBLISH}:
        if research_config is not None:
            raise OwnerEquityRuntimeError(
                "audit and publish routes forbid a research acquisition capability"
            )
        research_authority = None
    else:
        research_values = _closed_object(
            research_config,
            _RESEARCH_FIELDS,
            "research config",
        )
        research_authority = _load_research_authority(
            research_values,
            research_budget=research_budget,
        )
    report_required = intent in {ResearchIntent.REPORT, ResearchIntent.VALUATION}
    report_config = payload["report"]
    if report_required:
        report_values = _closed_object(report_config, _REPORT_FIELDS, "report config")
        report_spec = _load_report_spec(
            _absolute_path(report_values["report_spec_file"], "report.report_spec_file")
        )
    elif report_config is not None:
        raise OwnerEquityRuntimeError("this route forbids an unused report capability")
    else:
        report_spec = None
    # A successful explicit valuation is a complete local deliverable, not a transient
    # report-only calculation.  It therefore uses the same strict Publisher boundary as
    # ``publish --profile full_valuation``.
    publication_config = payload["publication"]
    publication_source_package = None
    if intent is ResearchIntent.VALUATION:
        publication_values = _closed_object(
            publication_config,
            _PUBLICATION_OUTPUT_FIELDS,
            "publication config",
        )
        publication_output = _absolute_path(
            publication_values["output_directory"],
            "publication.output_directory",
        )
    elif intent is ResearchIntent.PUBLISH:
        if type(profile) is not PublicationProfile:
            raise OwnerEquityRuntimeError("publish route requires an exact publication profile")
        publication_values = _closed_object(
            publication_config,
            _REPUBLICATION_FIELDS,
            "republication config",
        )
        publication_source_package = load_owner_research_package(
            _absolute_path(
                publication_values["input_package_directory"],
                "publication.input_package_directory",
            )
        )
        if publication_source_package.profile != profile.value:
            raise OwnerEquityRuntimeError(
                "publication source profile differs from the requested profile"
            )
        publication_output = _absolute_path(
            publication_values["output_directory"],
            "publication.output_directory",
        )
    elif publication_config is not None:
        raise OwnerEquityRuntimeError("this route forbids an unused publication capability")
    else:
        publication_output = None
    audit_config = payload["audit"]
    if intent is ResearchIntent.AUDIT:
        audit_values = _closed_object(audit_config, _AUDIT_FIELDS, "audit config")
        audit_package = load_owner_research_package(
            _absolute_path(audit_values["package_directory"], "audit.package_directory")
        )
    elif audit_config is not None:
        raise OwnerEquityRuntimeError("this route forbids an unused audit capability")
    else:
        audit_package = None
    full_valuation = intent is ResearchIntent.VALUATION
    valuation_config = payload["valuation"]
    if full_valuation:
        if valuation_config is None:
            valuation_values = {name: None for name in _VALUATION_LOCATOR_FIELDS}
        else:
            valuation_values = _closed_object(
                valuation_config,
                _VALUATION_LOCATOR_FIELDS,
                "valuation config",
            )
        valuation_locators = RuntimeValuationLocators(freeze(valuation_values))
        run_input_value = valuation_locators.values["run_input_file"]
        price_blind_value = valuation_locators.values["price_blind_artifact_directory"]
        if run_input_value is not None and price_blind_value is not None:
            assert research_authority is not None
            valuation_context = load_valuation_run_input_context(
                _absolute_path(run_input_value, "valuation.run_input_file"),
                price_blind_artifact_directory=_absolute_path(
                    price_blind_value,
                    "valuation.price_blind_artifact_directory",
                ),
            )
            if valuation_context.graph != research_authority.context.graph or dict(
                valuation_context.research_bundle_contents
            ) != dict(research_authority.research.file_bytes):
                raise OwnerEquityRuntimeError(
                    "valuation context differs from the price-blind research authority"
                )
            for name, raw in valuation_context.research_bundle_contents.items():
                research_budget.capture(
                    research_authority.research.source_directory / name,
                    raw,
                    f"valuation research input {name}",
                )
        else:
            valuation_context = None
    else:
        # Crucial zero-Futu boundary: do not validate, stat, or load any valuation path.
        if valuation_config is not None:
            raise OwnerEquityRuntimeError("price-blind route forbids valuation capability")
        valuation_locators = None
        valuation_context = None
    return OwnerEquityRuntime(
        intent=intent,
        profile=profile,
        research_authority=research_authority,
        valuation_context=valuation_context,
        report_spec=report_spec,
        publication_output=publication_output,
        publication_source_package=publication_source_package,
        audit_package=audit_package,
        valuation_locators=valuation_locators,
        config_fingerprint=canonical_sha256(payload),
        research_read_budget=research_budget,
    )


def _phase_receipt(
    phase: str,
    request: OwnerEquityResearchRequest,
    *authorities: object,
    upstream: tuple[PhaseReceipt, ...] = (),
) -> PhaseReceipt:
    return PhaseReceipt.create(
        phase=phase,
        input_receipt=OwnerEquityResearchInputReceipt.from_request(request),
        upstream_receipts=upstream,
        authorities=tuple(authorities),
    )


def _has_exact_upstreams(
    receipt: PhaseReceipt,
    *expected: PhaseReceipt,
) -> bool:
    return len(receipt.upstream_receipts) == len(expected) and all(
        actual is bound
        for actual, bound in zip(
            receipt.upstream_receipts,
            expected,
            strict=True,
        )
    )


def _same_exact_authority(actual: object, expected: object) -> bool:
    if type(expected) is tuple:
        return type(actual) is tuple and len(actual) == len(expected) and all(
            _same_exact_authority(left, right)
            for left, right in zip(actual, expected, strict=True)
        )
    return actual is expected


def _has_exact_authorities(
    receipt: PhaseReceipt,
    *expected: object,
) -> bool:
    return len(receipt.authorities) == len(expected) and all(
        _same_exact_authority(actual, bound)
        for actual, bound in zip(receipt.authorities, expected, strict=True)
    )


def _has_exact_refreeze_topology(receipt: PhaseReceipt) -> bool:
    if len(receipt.upstream_receipts) != 2:
        return False
    official, nonprice = receipt.upstream_receipts
    return (
        official.phase == "official_research_freeze"
        and nonprice.phase == "futu_nonprice_verification"
        and _has_exact_upstreams(official)
        and _has_exact_upstreams(nonprice, official)
    )


def _has_exact_market_topology(
    price_blind: PhaseReceipt,
    market: PhaseReceipt,
) -> bool:
    return _has_exact_refreeze_topology(price_blind) and _has_exact_upstreams(
        market,
        price_blind,
        price_blind.upstream_receipts[1],
    )


def _has_exact_market_predecessor_topology(
    price_blind: PhaseReceipt,
    nonprice: PhaseReceipt,
) -> bool:
    return (
        len(nonprice.upstream_receipts) == 1
        and _has_exact_refreeze_topology(price_blind)
        and _has_exact_upstreams(
            price_blind,
            nonprice.upstream_receipts[0],
            nonprice,
        )
    )


def _has_exact_kernel_topology(
    price_blind: PhaseReceipt,
    market: PhaseReceipt,
    kernel: PhaseReceipt,
) -> bool:
    return _has_exact_market_topology(price_blind, market) and _has_exact_upstreams(
        kernel,
        price_blind,
        market,
    )


def _has_exact_synthesis_topology(
    price_blind: PhaseReceipt,
    market: PhaseReceipt,
    synthesis: PhaseReceipt,
) -> bool:
    if len(synthesis.upstream_receipts) != 3:
        return False
    kernel = synthesis.upstream_receipts[2]
    return (
        kernel.phase == "owner_valuation_kernel"
        and _has_exact_kernel_topology(price_blind, market, kernel)
        and _has_exact_upstreams(synthesis, price_blind, market, kernel)
    )


def _require_research_authority(runtime: OwnerEquityRuntime) -> RuntimeResearchAuthority:
    authority = runtime.research_authority
    if type(authority) is not RuntimeResearchAuthority:
        raise OwnerEquityRuntimeError("this route has no research acquisition authority")
    return authority


_FORMAL_SCOPE_AUTHORITIES = frozenset({"primary_regulatory", "company_primary"})
_SEC_REPORTING_DOCUMENT_TYPES = frozenset({"10-K", "10-Q", "8-K", "DEF 14A"})
_SECURITY_KIND_BY_STRUCTURE = {
    "single_primary_common": "single_common_stock",
    "adr_or_depositary_receipt": "adr",
    "dual_or_multi_class_different_prices": "multiple_share_classes",
    "cross_listed_or_multi_venue": "cross_listed_or_multi_venue",
    "multi_security_aggregation": "multi_security_aggregation",
}


def _latest_formal_scope_facts(
    runtime: OwnerEquityRuntime,
    concept: str,
    *,
    authorities: frozenset[str] = _FORMAL_SCOPE_AUTHORITIES,
) -> tuple[Fact, ...]:
    authority = _require_research_authority(runtime)
    graph = authority.context.graph
    bundle = authority.research.result.bundle
    documents = {item.document_id: item for item in graph.documents}
    eligible: list[tuple[tuple[str, str], Fact]] = []
    for item in graph.facts:
        if (
            item.issuer_id != bundle.issuer_id
            or item.concept != concept
            or item.derivation is not None
            or item.parent_fact_ids
            or item.confidence not in {"high", "medium"}
        ):
            continue
        document = documents.get(item.source_document_id)
        period_end = item.period["end"]
        if (
            document is None
            or document.issuer_id != bundle.issuer_id
            or document.authority_level not in authorities
            or document.published_date > bundle.data_cutoff_date
            or (period_end is not None and period_end > bundle.data_cutoff_date)
        ):
            continue
        eligible.append(
            (
                (str(period_end or document.published_date), document.published_date),
                item,
            )
        )
    if not eligible:
        return ()
    latest = max(key for key, _ in eligible)
    return tuple(
        sorted(
            (item for key, item in eligible if key == latest),
            key=lambda item: item.fact_id,
        )
    )


def _formal_text_scope_values(
    runtime: OwnerEquityRuntime,
    concept: str,
    *,
    normalize: Callable[[str], str],
) -> tuple[str, ...]:
    facts = _latest_formal_scope_facts(runtime, concept)
    if not facts or any(
        item.value_type != "text" or type(item.value) is not str for item in facts
    ):
        return ()
    values = {normalize(item.value) for item in facts}
    if not all(values):
        return ()
    return tuple(sorted(values))


def _official_industry_kind(runtime: OwnerEquityRuntime) -> str:
    facts = _latest_formal_scope_facts(
        runtime,
        "sec_sic_code",
        authorities=frozenset({"primary_regulatory"}),
    )
    if not facts:
        return "unresolved"
    codes: set[int] = set()
    for item in facts:
        if (
            item.value_type != "number"
            or item.unit != "count"
            or item.currency is not None
            or isinstance(item.value, bool)
            or not isinstance(item.value, (int, float))
            or int(item.value) != item.value
        ):
            return "unresolved"
        codes.add(int(item.value))
    if len(codes) != 1:
        return "unresolved"
    code = next(iter(codes))
    for company_type, ranges in SEC_SIC_COMPANY_TYPES.items():
        if any(start <= code <= end for start, end in ranges):
            return "insurance" if company_type == "insurer" else company_type
    if SEC_SIC_UNSUPPORTED_FINANCIAL_RANGE[0] <= code <= (
        SEC_SIC_UNSUPPORTED_FINANCIAL_RANGE[1]
    ):
        return "unsupported"
    return "general_operating_company"


def _research_security_scope(runtime: OwnerEquityRuntime) -> SecurityScope:
    authority = _require_research_authority(runtime)
    bundle = authority.research.result.bundle
    graph = authority.context.graph
    listing_mics = _formal_text_scope_values(
        runtime,
        "security_mic",
        normalize=lambda value: value.strip().upper(),
    )
    share_classes = _formal_text_scope_values(
        runtime,
        "security_share_class",
        normalize=lambda value: value.strip().casefold(),
    )
    structures = _formal_text_scope_values(
        runtime,
        "security_structure",
        normalize=lambda value: value.strip().casefold(),
    )
    security_kind = (
        _SECURITY_KIND_BY_STRUCTURE.get(structures[0], "unresolved")
        if len(structures) == 1
        else "unresolved"
    )
    currencies = {
        SUPPORTED_MIC_CURRENCY[item]
        for item in listing_mics
        if item in SUPPORTED_MIC_CURRENCY
    }
    currency = (
        next(iter(currencies))
        if (
            listing_mics
            and len(currencies) == 1
            and all(item in SUPPORTED_MIC_CURRENCY for item in listing_mics)
        )
        else "UNSUPPORTED"
        if listing_mics
        else "UNRESOLVED"
    )
    sec_reporting = any(
        item.issuer_id == bundle.issuer_id
        and item.authority_level == "primary_regulatory"
        and item.document_type in _SEC_REPORTING_DOCUMENT_TYPES
        and item.published_date <= bundle.data_cutoff_date
        for item in graph.documents
    )
    return SecurityScope(
        listing_mics=listing_mics or ("UNRESOLVED",),
        currency=currency,
        security_kind=security_kind,
        share_classes=share_classes or ("unresolved",),
        sec_reporting=sec_reporting,
        industry_kind=_official_industry_kind(runtime),
    )


def _security_scope(runtime: OwnerEquityRuntime) -> SecurityScope:
    context = runtime.valuation_context
    if context is None:
        return _research_security_scope(runtime)
    security = context.expected_security
    if security.status != "eligible" or security.decision is None:
        return SecurityScope(
            listing_mics=("UNRESOLVED",),
            currency="UNRESOLVED",
            security_kind="unresolved",
            share_classes=("unresolved",),
            sec_reporting=False,
            industry_kind="unresolved",
        )
    decision = security.decision
    readiness = context.expected_freeze.artifact.to_dict()["phase5c_readiness"]
    specialist_route_value = readiness.get("specialist_route")
    if specialist_route_value is None:
        # Frozen PR2 inputs predate the explicit route field.  Both protected panels
        # reaching Phase 5D is the prior schema's exact non-specialist attestation.
        routing = readiness.get("routing")
        specialist_route_value = (
            "none"
            if routing
            == {
                "mckinsey": "ready_for_phase5d",
                "penman": "ready_for_phase5d",
            }
            else "unresolved"
        )
    specialist_route = str(specialist_route_value)
    industry = {
        "none": "general_operating_company",
        "financial_institution": "financial_institution",
        "sum_of_parts": "conglomerate",
        "fund": "fund",
        "reit": "reit",
    }.get(specialist_route, "unsupported")
    documents = _require_research_authority(runtime).context.graph.documents
    bundle = _require_research_authority(runtime).research.result.bundle
    sec_reporting = any(
        item.issuer_id == bundle.issuer_id
        and item.authority_level == "primary_regulatory"
        and item.document_type in {"10-K", "10-Q", "8-K", "DEF 14A"}
        and item.published_date <= bundle.data_cutoff_date
        for item in documents
    )
    return SecurityScope(
        listing_mics=(decision.exchange,),
        currency=decision.quote_currency,
        security_kind="single_common_stock",
        share_classes=(decision.share_class,),
        sec_reporting=sec_reporting,
        industry_kind=industry,
    )


@dataclass(frozen=True, slots=True)
class _LiveBlocked(Exception):
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        issues = tuple(sorted(set(self.issue_codes)))
        if not issues:
            raise OwnerEquityRuntimeError("live block requires a typed issue")
        object.__setattr__(self, "issue_codes", issues)


def _validate_stage_plan_request_time(
    stage_plan: LiveStagePlan,
    request: OwnerEquityResearchRequest,
) -> None:
    request_time = runtime_request_time(request.requested_at)
    authority_time = datetime.fromisoformat(
        stage_plan.authority_evaluated_at.replace("Z", "+00:00")
    ).astimezone(UTC)
    if not request_time <= authority_time <= request_time + timedelta(minutes=5):
        raise _LiveBlocked(("stage_plan_request_time_mismatch",))


def _pre_price_specs(mic: str) -> tuple[FutuRequestSpec, ...]:
    registry = load_protocol_registry()
    ordered_requests = (
        (3202, FrozenMap({})),
        *(
            (
                3227,
                FrozenMap(
                    {
                        "statement_type": statement_type,
                        "financial_type": 7,
                        "currency_code": "USD",
                        "num": 10,
                    }
                ),
            )
            for statement_type in (1, 2, 3)
        ),
        (3228, FrozenMap({"date": 0, "financial_type": 7, "currency_code": "USD"})),
        (3234, FrozenMap({})),
        (3236, FrozenMap({})),
        (3243, FrozenMap({})),
    )
    return (
        FutuRequestSpec(
            stage="runtime_authority",
            protocol_id=3104,
            parameters=FrozenMap({"get_detail": True}),
        ),
        *tuple(
        FutuRequestSpec(
            stage="valuation_pre_price_verification",
            protocol_id=protocol_id,
            parameters=parameters,
        )
        for protocol_id, parameters in ordered_requests
        if mic in registry[protocol_id]["market_scope"]
        ),
    )


def _unadjusted_rth_daily_close_parameters(trading_date: str) -> FrozenMap:
    """Return the one closed last-session quote request admitted by ADR 0044."""

    _runtime_date(trading_date, "daily close trading date")
    return FrozenMap(
        {
            "start": trading_date,
            "end": trading_date,
            "ktype": "K_DAY",
            "autype": "NONE",
            "fields": ["CLOSE", "VOLUME"],
            "max_count": 1,
            "extended_time": False,
            "session": "RTH",
        }
    )


def _peer_specs(
    *,
    expected_trading_date: str,
    price_blind_freeze_fingerprint: str,
) -> tuple[FutuRequestSpec, ...]:
    return (
        FutuRequestSpec(
            stage="peer_comparable_reference",
            protocol_id=3202,
            parameters=FrozenMap({}),
            price_blind_freeze_fingerprint=price_blind_freeze_fingerprint,
        ),
        FutuRequestSpec(
            stage="peer_comparable_reference",
            protocol_id=3103,
            parameters=_unadjusted_rth_daily_close_parameters(expected_trading_date),
            expected_trading_date=expected_trading_date,
            price_blind_freeze_fingerprint=price_blind_freeze_fingerprint,
        ),
    )


def _post_context_specs(
    *,
    price_blind_freeze_fingerprint: str,
    frozen_conclusion: FutuFrozenConclusionReceipt,
) -> tuple[FutuRequestSpec, ...]:
    parameters = _post_context_parameters()
    return tuple(
        FutuRequestSpec(
            stage="post_valuation_context",
            protocol_id=protocol_id,
            parameters=parameters[protocol_id],
            price_blind_freeze_fingerprint=price_blind_freeze_fingerprint,
            frozen_conclusion=frozen_conclusion,
        )
        for protocol_id in _POST_CONTEXT_PROTOCOLS
    )


def _post_context_parameters() -> dict[int, FrozenMap]:
    return {
        3229: FrozenMap({}),
        3230: FrozenMap({"rating_dimension_type": 1, "uid": None, "num": 20}),
        3232: FrozenMap({}),
    }


def _target_market_plan_spec(
    *,
    context: ValuationRunInputContext,
    stage_plan: LiveStagePlan,
) -> FutuRequestSpec:
    official_security = context.expected_security.decision
    if official_security is None:
        raise _LiveBlocked(("target_security_identity_missing",))
    authority = load_market_access_authority(context.graph.component_lock_path)
    selection = select_latest_completed_session(
        authority,
        mic=official_security.exchange,
        cutoff_date=date.fromisoformat(
            str(context.expected_freeze.artifact.payload["data_cutoff_date"])
        ),
        observed_at=datetime.fromisoformat(
            stage_plan.market_request_started_at.replace("Z", "+00:00")
        ),
    )
    trading_date = selection.session.trading_date
    return FutuRequestSpec(
        stage="market_reference",
        protocol_id=3103,
        parameters=_unadjusted_rth_daily_close_parameters(trading_date),
        expected_trading_date=trading_date,
    )


def _compile_expected_request_plan(
    *,
    context: ValuationRunInputContext,
    stage_plan: LiveStagePlan,
    target_security: FutuSecurityIdentityReceipt,
    optional_data_review: NamedHumanReviewAuthority,
    peer_authorities: tuple[
        tuple[
            PeerExecutionPlan,
            FutuSecurityIdentityReceipt,
            FutuAuthoritySet,
            FutuAuthorityDecision,
        ],
        ...,
    ],
) -> tuple[tuple[str, ...], tuple[FrozenMap, ...]]:
    target_market_spec = _target_market_plan_spec(
        context=context,
        stage_plan=stage_plan,
    )
    target_trading_date = target_market_spec.expected_trading_date
    if target_trading_date is None or any(
        item[0].expected_trading_date != target_trading_date
        for item in peer_authorities
    ):
        raise _LiveBlocked(("peer_trading_date_differs_from_target_calendar",))
    operations: list[tuple[str, int, FrozenMap]] = [
        *(
            (target_security.vendor_code, spec.protocol_id, spec.parameters)
            for spec in (
                *_pre_price_specs(target_security.mic),
                *compile_futu_optional_data_request_specs(optional_data_review),
                target_market_spec,
            )
        ),
    ]
    freeze_fingerprint = context.expected_freeze.artifact.fingerprint
    for peer_plan, peer_security, _authority, _decision in peer_authorities:
        operations.extend(
            (
                peer_security.vendor_code,
                spec.protocol_id,
                spec.parameters,
            )
            for spec in _peer_specs(
                expected_trading_date=peer_plan.expected_trading_date,
                price_blind_freeze_fingerprint=freeze_fingerprint,
            )
        )
    operations.extend(
        (target_security.vendor_code, protocol_id, parameters)
        for protocol_id, parameters in _post_context_parameters().items()
    )
    plan = tuple(
        build_futu_runtime_request_plan_item(
            plan_index=index,
            security_code=security_code,
            protocol_id=protocol_id,
            parameters=parameters,
            maximum_pages=int(_REQUEST_PAGE_CAPS.get(str(protocol_id), 1)),
        )
        for index, (security_code, protocol_id, parameters) in enumerate(operations)
    )
    authorized_codes = (
        target_security.vendor_code,
        *(item[1].vendor_code for item in peer_authorities),
    )
    return authorized_codes, plan


def _require_complete_execution(
    execution: FutuSidecarExecution,
    label: str,
) -> FutuSidecarExecution:
    if type(execution) is not FutuSidecarExecution:
        raise _LiveBlocked((f"{label}:wrong_execution_type",))
    if execution.bundle.status != "complete" or execution.bundle.issues:
        issues = execution.bundle.issues or ("execution_incomplete",)
        raise _LiveBlocked(tuple(f"{label}:{item}" for item in issues))
    if execution.bundle.stage == "valuation_pre_price_verification" and (
        execution.history_quota is None or not execution.history_quota.sufficient
    ):
        raise _LiveBlocked((f"{label}:historical_kline_quota_missing",))
    if any(not response.qot_logined or response.trd_logined for response in execution.responses):
        raise _LiveBlocked((f"{label}:trade_login_true",))
    return execution


def _official_crosschecks(
    *,
    graph: ContractGraph,
    execution: FutuSidecarExecution,
    created_at: str,
) -> tuple[tuple[OfficialEvidenceOperand, ...], tuple[FutuCrossCheckReceipt, ...]]:
    operands: list[OfficialEvidenceOperand] = []
    receipts: list[FutuCrossCheckReceipt] = []
    documents = {item.document_id: item for item in graph.documents}

    def preferred_official_facts(candidates: tuple[Fact, ...]) -> tuple[Fact, ...]:
        official = tuple(
            fact
            for fact in candidates
            if documents[fact.source_document_id].authority_level
            in _FORMAL_SCOPE_AUTHORITIES
        )
        regulatory = tuple(
            fact
            for fact in official
            if documents[fact.source_document_id].authority_level
            == "primary_regulatory"
        )
        return regulatory or official

    def preferred_official_split_facts(candidates: tuple[Fact, ...]) -> tuple[Fact, ...]:
        event_groups: dict[tuple[str, str, str], list[Fact]] = {}
        for fact in candidates:
            event_key = (
                fact.issuer_id,
                fact.concept,
                canonical_json(fact.period),
            )
            event_groups.setdefault(event_key, []).append(fact)
        selected: list[Fact] = []
        for event_key in sorted(event_groups):
            preferred = preferred_official_facts(tuple(event_groups[event_key]))
            if len(preferred) > 1:
                raise _LiveBlocked(
                    ("futu_nonprice:official_fact_missing_or_ambiguous",)
                )
            selected.extend(preferred)
        return tuple(selected)

    split_concepts = frozenset(
        {"stock_split_completed", "reverse_stock_split_completed"}
    )
    official_split_facts = preferred_official_split_facts(
        tuple(
            fact
            for fact in graph.facts
            if type(fact) is Fact
            and fact.issuer_id == execution.bundle.issuer_id
            and fact.concept in split_concepts
            and fact.value_type == "number"
            and fact.unit == "ratio"
            and fact.currency is None
        )
    )
    vendor_split_entries = tuple(
        (index, observation)
        for index, observation in enumerate(execution.observations)
        if observation.canonical_concept in split_concepts
    )
    vendor_split_observations = tuple(
        observation for _, observation in vendor_split_entries
    )

    def split_event_assignment() -> dict[int, Fact]:
        """Bind every split observation to one official event without fuzzy reuse."""

        conflict = ("futu_nonprice:sec_futu_split_event_set_conflict",)
        if vendor_split_entries and not official_split_facts:
            raise _LiveBlocked(
                ("futu_nonprice:official_fact_missing_or_ambiguous",)
            )
        if len(official_split_facts) != len(vendor_split_entries) or any(
            observation.source_role != "vendor_secondary"
            or not observation.comparison_eligible
            for _, observation in vendor_split_entries
        ):
            raise _LiveBlocked(conflict)

        assignments: dict[int, int] = {}
        available_official = set(range(len(official_split_facts)))
        fuzzy_vendor_indices: list[int] = []
        observations_by_index = dict(vendor_split_entries)

        # Exact periods are authoritative and are consumed before the documented
        # US announcement-only fallback is considered.
        for observation_index, observation in vendor_split_entries:
            exact_candidates = tuple(
                official_index
                for official_index, fact in enumerate(official_split_facts)
                if fact.issuer_id == observation.issuer_id
                and fact.concept == observation.canonical_concept
                and to_json_value(fact.period) == to_json_value(observation.period)
            )
            if len(exact_candidates) > 1:
                raise _LiveBlocked(conflict)
            if not exact_candidates:
                fuzzy_vendor_indices.append(observation_index)
                continue
            official_index = exact_candidates[0]
            if official_index not in available_official:
                raise _LiveBlocked(conflict)
            assignments[observation_index] = official_index
            available_official.remove(official_index)

        fuzzy_edges = {
            observation_index: tuple(
                official_index
                for official_index in sorted(available_official)
                if official_split_facts[official_index].issuer_id
                == observations_by_index[observation_index].issuer_id
                and official_split_facts[official_index].concept
                == observations_by_index[observation_index].canonical_concept
                and split_observation_matches_official_period(
                    observations_by_index[observation_index],
                    official_split_facts[official_index].period,
                )
            )
            for observation_index in fuzzy_vendor_indices
        }

        def perfect_fuzzy_matching(
            excluded_edge: tuple[int, int] | None = None,
        ) -> dict[int, int] | None:
            matched_vendor_by_official: dict[int, int] = {}

            def augment(observation_index: int, visited: set[int]) -> bool:
                for official_index in fuzzy_edges[observation_index]:
                    if (
                        excluded_edge == (observation_index, official_index)
                        or official_index in visited
                    ):
                        continue
                    visited.add(official_index)
                    incumbent = matched_vendor_by_official.get(official_index)
                    if incumbent is None or augment(incumbent, visited):
                        matched_vendor_by_official[official_index] = observation_index
                        return True
                return False

            for observation_index in fuzzy_vendor_indices:
                if not augment(observation_index, set()):
                    return None
            return {
                observation_index: official_index
                for official_index, observation_index in matched_vendor_by_official.items()
            }

        fuzzy_assignment = perfect_fuzzy_matching()
        if fuzzy_assignment is None or set(fuzzy_assignment.values()) != available_official:
            raise _LiveBlocked(conflict)
        if any(
            perfect_fuzzy_matching((observation_index, official_index)) is not None
            for observation_index, official_index in fuzzy_assignment.items()
        ):
            raise _LiveBlocked(conflict)
        assignments.update(fuzzy_assignment)
        if set(assignments) != {index for index, _ in vendor_split_entries}:
            raise _LiveBlocked(conflict)
        return {
            observation_index: official_split_facts[official_index]
            for observation_index, official_index in assignments.items()
        }

    split_fact_by_observation_index = split_event_assignment()

    for observation_index, observation in enumerate(execution.observations):
        if not (observation.source_role == "vendor_secondary" and observation.comparison_eligible):
            continue
        split_observation = observation.canonical_concept in split_concepts
        candidates = (
            (split_fact_by_observation_index[observation_index],)
            if split_observation
            else preferred_official_facts(
                tuple(
                    fact
                    for fact in graph.facts
                    if type(fact) is Fact
                    and fact.issuer_id == observation.issuer_id
                    and fact.concept == observation.canonical_concept
                    and to_json_value(fact.period) == to_json_value(observation.period)
                    and fact.value_type == observation.value_type
                    and fact.unit == observation.unit
                    and fact.currency == observation.currency
                )
            )
        )
        if len(candidates) != 1:
            raise _LiveBlocked(("futu_nonprice:official_fact_missing_or_ambiguous",))
        operand = build_official_evidence_operand(
            graph=graph,
            official_object=candidates[0],
        )
        receipt = crosscheck_vendor_observation(
            graph=graph,
            official=operand,
            vendor=observation,
            created_at=created_at,
        )
        if receipt.result == "conflict" or receipt.status == "review_required":
            raise _LiveBlocked(("futu_nonprice:sec_futu_material_conflict",))
        operands.append(operand)
        receipts.append(receipt)

    required_by_statement = load_critical_financial_concepts()
    required_concepts = frozenset(
        concept
        for concepts in required_by_statement.values()
        for concept in concepts
    )
    mapped_concepts = {
        str(mapping["canonical_concept"])
        for mapping in load_financial_field_registry().values()
    }
    if not required_concepts.issubset(mapped_concepts):
        raise _LiveBlocked(("futu_nonprice:critical_financial_field_not_mapped",))
    consistent_concepts = {
        receipt.canonical_concept
        for receipt in receipts
        if receipt.result == "consistent" and receipt.status == "resolved"
    }
    if not required_concepts.issubset(consistent_concepts):
        raise _LiveBlocked(("futu_nonprice:critical_financial_verification_missing",))

    official_dividend_dates = tuple(
        sorted(
            event.announcement_date
            for event in graph.capital_allocation_events
            if event.issuer_id == execution.bundle.issuer_id
            and event.event_type == "dividend"
        )
    )
    vendor_dividend_dates = tuple(
        sorted(
            str(observation.qualifiers.get("publication_date"))
            for observation in execution.observations
            if observation.data_family == "corporate_actions"
            and observation.field_id == "dividend_event"
        )
    )
    if (
        any(value in {"", "None"} for value in vendor_dividend_dates)
        or len(set(vendor_dividend_dates)) != len(vendor_dividend_dates)
        or official_dividend_dates != vendor_dividend_dates
    ):
        raise _LiveBlocked(("futu_nonprice:sec_futu_dividend_event_set_conflict",))
    current_share_dispositions = tuple(
        observation
        for observation in execution.observations
        if observation.data_family == "corporate_actions"
        and observation.field_id == "current_common_shares"
    )
    if (
        len(current_share_dispositions) != 1
        or current_share_dispositions[0].value_type != "null"
        or current_share_dispositions[0].value is not None
        or to_json_value(current_share_dispositions[0].qualifiers)
        != {
            "reason_code": "us_3236_shares_after_effect_not_supported",
            "verification_status": "vendor_not_supported",
        }
    ):
        raise _LiveBlocked(("futu_nonprice:current_common_shares_identity_conflict",))
    if any(
        observation.qualifiers.get("current_shares_status")
        != "vendor_not_supported"
        for observation in vendor_split_observations
    ):
        raise _LiveBlocked(("futu_nonprice:current_common_shares_identity_conflict",))
    return tuple(operands), tuple(receipts)


def _market_acquisition(run_result: ValuationRunResult) -> FutuMarketReferenceAcquisition:
    if run_result.status != "completed" or run_result.preparation is None:
        raise OwnerEquityRuntimeError("market acquisition requires a completed valuation run")
    contexts = (
        run_result.preparation.prepared_market_reference.graph.market_reference_validation_contexts
    )
    if (
        len(contexts) != 1
        or type(contexts[0].vendor_market_acquisition) is not FutuMarketReferenceAcquisition
    ):
        raise OwnerEquityRuntimeError("completed valuation lacks exact Futu acquisition")
    return contexts[0].vendor_market_acquisition


@dataclass(slots=True)
class _LiveRuntimeState:
    runtime: OwnerEquityRuntime
    initialized: bool = False
    keyring: Ed25519PublicKeyring | None = None
    stage_plan: LiveStagePlan | None = None
    synthesis_plan: SynthesisReviewPlan | None = None
    score_plan: ScoreReviewPlan | None = None
    peer_plan: PeerReviewPlan | None = None
    optional_data_review: NamedHumanReviewAuthority | None = None
    authority_set: FutuAuthoritySet | None = None
    authority_decision: FutuAuthorityDecision | None = None
    transport: AttestedFutuSidecarSession | None = None
    sidecar_finalization: FutuAttestedSessionFinalization | None = None
    sidecar_abort: FutuSidecarAbortAttestation | None = None
    peer_authorities: tuple[
        tuple[
            PeerExecutionPlan,
            FutuSecurityIdentityReceipt,
            FutuAuthoritySet,
            FutuAuthorityDecision,
        ],
        ...,
    ] = ()
    basis_review: NamedHumanReviewAuthority | None = None
    forward_review: NamedHumanReviewAuthority | None = None
    selection_review: NamedHumanReviewAuthority | None = None
    forecast_review: NamedHumanReviewAuthority | None = None
    score_reviews: tuple[NamedHumanReviewAuthority | CompositeScoreGapAuthority, ...] = ()
    financial_field_registry: Mapping[str, FrozenMap] | None = None
    pre_execution: FutuSidecarExecution | None = None
    optional_data_dispositions: tuple[FutuOptionalDataDisposition, ...] = ()
    official_operands: tuple[OfficialEvidenceOperand, ...] = ()
    cross_checks: tuple[FutuCrossCheckReceipt, ...] = ()
    ticket: FutuMarketAuthorizationTicket | None = None
    market_execution: FutuSidecarExecution | None = None
    market_evidence: FutuMarketExecutionEvidence | None = None
    market_provider: FutuMarketReferenceProvider | None = None
    run_result: ValuationRunResult | None = None
    peer_evidence_set: FutuPeerEvidenceSet | None = None
    basis_receipt: ValuationBasisReceipt | None = None
    forward_reoi: ForwardReOIValuationResult | None = None
    peer_authority: ReviewedPeerSetAuthority | None = None
    comparable: ComparableValuationResult | None = None
    composite: CompositeValuationResult | None = None
    lens_scores: tuple[ScoreV2, ...] = ()
    owner_scorecard: OwnerScorecard | None = None
    frozen_conclusion: FutuFrozenConclusionReceipt | None = None
    post_execution: FutuSidecarExecution | None = None
    session: FutuSessionEvidence | None = None
    market_expectations: MarketExpectationsComparison | None = None
    downstream_gap: RuntimeGapReceipt | None = None
    valuation_input: ReloadedValuationInput | None = None
    report: ReportBuildResult | None = None
    kernel_authority: ValuationRunAuthority | None = None
    kernel_calls: int = 0

    def _locator(self, name: str) -> Any:
        locators = self.runtime.valuation_locators
        if locators is None:
            raise _LiveBlocked(("valuation_capability_not_loaded",))
        return locators.values[name]

    def _path(self, name: str) -> Path:
        return _absolute_path(self._locator(name), f"valuation.{name}")

    def _preflight_kernel_runtime_supply(self) -> ValuationRunAuthority:
        if self.kernel_authority is not None:
            return self.kernel_authority
        context = self.runtime.valuation_context
        if context is None:
            raise _LiveBlocked(("valuation_input_missing",))
        runtime_manifest = self._path("kernel_runtime_manifest")
        try:
            authority = ValuationRunAuthority(
                price_blind_artifact_directory=self._path(
                    "price_blind_artifact_directory"
                ),
                expected_freeze=context.expected_freeze,
                expected_security=context.expected_security,
                kernel_repository=self._path("kernel_repository"),
                runtime_manifest=runtime_manifest,
                runtime_manifest_file_sha256=_regular_file_sha256(
                    runtime_manifest,
                    "kernel runtime manifest",
                ),
                cas_root=self._path("kernel_cas_root"),
            )
            _verify_runtime_supply(
                kernel_wheel=self._path("kernel_wheel"),
                authority=authority,
            )
        except (KernelMaterializationError, OSError, TypeError, ValueError) as exc:
            raise _LiveBlocked(
                (f"runtime_supply_blocked:{type(exc).__name__}",)
            ) from exc
        self.kernel_authority = authority
        return authority

    def initialize(self, request: OwnerEquityResearchRequest) -> None:
        if self.initialized:
            return
        locators = self.runtime.valuation_locators
        context = self.runtime.valuation_context
        if locators is None:
            raise _LiveBlocked(("valuation_capability_not_loaded",))
        if locators.missing_authority_codes:
            raise _LiveBlocked(locators.missing_authority_codes)
        if context is None:
            raise _LiveBlocked(("valuation_input_missing",))
        if (
            request.issuer_id != context.expected_freeze.artifact.payload["issuer_id"]
            or request.data_cutoff_date
            != context.expected_freeze.artifact.payload["data_cutoff_date"]
        ):
            raise _LiveBlocked(("valuation_input_identity_mismatch",))
        if context.expected_security.status == "eligible":
            self._preflight_kernel_runtime_supply()

        keyring = Ed25519PublicKeyring.from_file(self._path("keyring_file"))
        legal = _load_signed_receipt(
            self._path("legal_receipt_file"),
            "futu-legal-rights-receipt",
            FutuLegalRightsReceipt,
        )
        account = _load_signed_receipt(
            self._path("account_receipt_file"),
            "futu-account-entitlement-receipt",
            FutuAccountEntitlementReceipt,
        )
        supply = _load_signed_receipt(
            self._path("supply_chain_receipt_file"),
            "futu-supply-chain-receipt",
            FutuSupplyChainReceipt,
        )
        runtime_authorization = _load_signed_receipt(
            self._path("runtime_authorization_file"),
            "futu-runtime-isolation-authorization",
            FutuRuntimeIsolationAuthorization,
        )
        security = _load_signed_receipt(
            self._path("security_identity_receipt_file"),
            "futu-security-identity-receipt",
            FutuSecurityIdentityReceipt,
        )
        stage_plan = _load_live_stage_plan(self._path("stage_plan_file"))
        synthesis_plan = _load_synthesis_review_plan(
            self._path("synthesis_review_file"),
            research_budget=self.runtime.research_read_budget,
        )
        score_plan = _load_score_review_plan(
            self._path("score_review_file"),
            research_budget=self.runtime.research_read_budget,
        )
        peer_plan = _load_peer_review_plan(
            self._path("peer_review_file"),
            research_budget=self.runtime.research_read_budget,
        )
        optional_data_plan = _load_futu_data_review_plan(
            self._path("futu_data_review_file"),
            research_budget=self.runtime.research_read_budget,
        )
        if stage_plan.run_id != account.run_id or stage_plan.run_id != runtime_authorization.run_id:
            raise _LiveBlocked(("account_scope_mismatch",))
        _validate_stage_plan_request_time(stage_plan, request)
        if stage_plan.market_request_started_at != context.clock.market.request_started_at:
            raise _LiveBlocked(("market_clock_mismatch",))
        if self._locator("runtime_receipt_file") is not None:
            raise _LiveBlocked(("static_runtime_completion_receipt_forbidden",))

        authority_set = FutuAuthoritySet(
            legal=legal,
            account=account,
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            runtime=None,
            security_identity=security,
        )
        official_security = context.expected_security.decision
        if official_security is None or any(
            (
                security.official_evidence_fingerprint != context.expected_security.fingerprint,
                security.issuer_id != official_security.issuer_id,
                security.security_id != official_security.security_id,
                security.ticker != official_security.ticker,
                security.mic != official_security.exchange,
                security.currency != official_security.quote_currency,
                security.share_class != official_security.share_class,
            )
        ):
            raise _LiveBlocked(("target_security_identity_mismatch",))
        bundle = _require_research_authority(self.runtime).research.result.bundle
        optional_data_review = optional_data_plan.build(
            scope="futu_optional_data_plan",
            graph=context.graph,
            research_bundle=bundle,
        )
        if datetime.fromisoformat(
            optional_data_review.reviewed_at.replace("Z", "+00:00")
        ) >= datetime.fromisoformat(
            stage_plan.pre_price_request_started_at.replace("Z", "+00:00")
        ):
            raise _LiveBlocked(("futu_optional_data_plan_not_frozen",))
        optional_protocols = tuple(
            item.protocol_id
            for item in compile_futu_optional_data_request_specs(
                optional_data_review
            )
        )
        registry = load_protocol_registry()
        required_protocols = tuple(sorted({*_LIVE_PROTOCOLS, *optional_protocols}))
        required_families = tuple(
            sorted({registry[item]["data_family"] for item in required_protocols})
        )
        authority_decision = evaluate_futu_authority(
            authority_set,
            verifier=keyring,
            now=datetime.fromisoformat(stage_plan.authority_evaluated_at.replace("Z", "+00:00")),
            run_id=stage_plan.run_id,
            policy_sha256=legal.policy_sha256,
            component_lock_sha256=_component_lock_sha256(context.graph),
            required_data_families=required_families,
            required_protocol_ids=required_protocols,
            purpose="live_preflight",
        )
        if authority_decision.status != "eligible":
            raise _LiveBlocked(authority_decision.issue_codes)

        basis_review = synthesis_plan.valuation_basis.build(
            scope="valuation_basis",
            graph=context.graph,
            research_bundle=bundle,
        )
        forward_review = synthesis_plan.forward_reoi.build(
            scope="forward_reoi",
            graph=context.graph,
            research_bundle=bundle,
        )
        selection_review = peer_plan.selection_review.build(
            scope="peer_set_selection",
            graph=context.graph,
            research_bundle=bundle,
        )
        forecast_review = peer_plan.forecast_review.build(
            scope="comparable_forecast",
            graph=context.graph,
            research_bundle=bundle,
        )
        peer_authorities: list[
            tuple[
                PeerExecutionPlan,
                FutuSecurityIdentityReceipt,
                FutuAuthoritySet,
                FutuAuthorityDecision,
            ]
        ] = []
        for peer in peer_plan.peers:
            peer_security = _load_signed_receipt(
                peer.security_receipt_file,
                "futu-security-identity-receipt",
                FutuSecurityIdentityReceipt,
            )
            peer_set = FutuAuthoritySet(
                legal=legal,
                account=account,
                supply_chain=supply,
                runtime_authorization=runtime_authorization,
                runtime=None,
                security_identity=peer_security,
            )
            peer_decision = evaluate_futu_authority(
                peer_set,
                verifier=keyring,
                now=datetime.fromisoformat(
                    stage_plan.authority_evaluated_at.replace("Z", "+00:00")
                ),
                run_id=stage_plan.run_id,
                policy_sha256=legal.policy_sha256,
                component_lock_sha256=_component_lock_sha256(context.graph),
                required_data_families=("market_price", "security_identity"),
                required_protocol_ids=(3103, 3202),
                purpose="live_preflight",
            )
            if peer_decision.status != "eligible":
                raise _LiveBlocked(
                    tuple(
                        f"peer:{peer_security.security_id}:{item}"
                        for item in peer_decision.issue_codes
                    )
                )
            peer_authorities.append((peer, peer_security, peer_set, peer_decision))
        if len({item[1].security_id for item in peer_authorities}) != len(peer_authorities):
            raise _LiveBlocked(("peer_security_identity_duplicated",))
        selected_payload = to_json_value(selection_review.reviewed_payload)
        selected_security_ids = tuple(
            item.get("security_id")
            for item in selected_payload.get("peers", [])
            if isinstance(item, Mapping)
        )
        configured_by_security_id = {
            item[1].security_id: item for item in peer_authorities
        }
        if (
            len(selected_security_ids) != len(peer_authorities)
            or len(set(selected_security_ids)) != len(selected_security_ids)
            or set(selected_security_ids) != set(configured_by_security_id)
            or security.security_id in configured_by_security_id
        ):
            raise _LiveBlocked(("peer_execution_plan_differs_from_frozen_selection",))
        peer_authorities = [
            configured_by_security_id[security_id]
            for security_id in selected_security_ids
        ]
        peer_times = tuple(
            datetime.fromisoformat(item[0].request_started_at.replace("Z", "+00:00"))
            for item in peer_authorities
        )
        if peer_times != tuple(sorted(peer_times)) or any(
            item <= datetime.fromisoformat(stage_plan.market_checkpoint_at.replace("Z", "+00:00"))
            for item in peer_times
        ):
            raise _LiveBlocked(("peer_request_chronology_invalid",))
        if any(
            item <= datetime.fromisoformat(selection_review.reviewed_at.replace("Z", "+00:00"))
            for item in peer_times
        ):
            raise _LiveBlocked(("peer_selection_not_frozen",))
        if (
            datetime.fromisoformat(forecast_review.reviewed_at.replace("Z", "+00:00"))
            > datetime.fromisoformat(selection_review.reviewed_at.replace("Z", "+00:00"))
            or any(
                item
                <= datetime.fromisoformat(forecast_review.reviewed_at.replace("Z", "+00:00"))
                for item in peer_times
            )
        ):
            raise _LiveBlocked(("peer_forecast_not_frozen",))

        expected_security_codes, expected_request_plan = _compile_expected_request_plan(
            context=context,
            stage_plan=stage_plan,
            target_security=security,
            optional_data_review=optional_data_review,
            peer_authorities=tuple(peer_authorities),
        )
        if (
            runtime_authorization.authorized_security_codes
            != expected_security_codes
            or runtime_authorization.request_plan != expected_request_plan
            or runtime_authorization.request_plan_fingerprint
            != canonical_sha256(to_json_value(expected_request_plan))
        ):
            raise _LiveBlocked(("runtime_authorization_request_plan_drift",))

        sidecar_signer_key_id = self._locator("sidecar_signer_key_id")
        if (
            sidecar_signer_key_id not in keyring.keys
            or sidecar_signer_key_id
            != runtime_authorization.sidecar_attestor_key_id
        ):
            raise _LiveBlocked(("sidecar_signer_key_not_in_keyring",))
        transport = AttestedFutuSidecarSession.open(
            socket_path=self._path("sidecar_socket"),
            expected_uid=self._locator("sidecar_expected_uid"),
            timeout_seconds=self._locator("sidecar_timeout_seconds"),
            run_id=stage_plan.run_id,
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            verifier=keyring,
            expected_signer_key_id=sidecar_signer_key_id,
        )
        self.keyring = keyring
        self.stage_plan = stage_plan
        self.synthesis_plan = synthesis_plan
        self.score_plan = score_plan
        self.peer_plan = peer_plan
        self.optional_data_review = optional_data_review
        self.authority_set = authority_set
        self.authority_decision = authority_decision
        self.transport = transport
        self.peer_authorities = tuple(peer_authorities)
        self.basis_review = basis_review
        self.forward_review = forward_review
        self.selection_review = selection_review
        self.forecast_review = forecast_review
        self.initialized = True

    def run_pre_price(
        self,
        request: OwnerEquityResearchRequest,
    ) -> FutuSidecarExecution:
        self.initialize(request)
        if self.pre_execution is not None:
            return self.pre_execution
        assert self.authority_set is not None
        assert self.authority_decision is not None
        assert self.transport is not None
        assert self.stage_plan is not None
        assert self.optional_data_review is not None
        security = self.authority_set.security_identity
        supply = self.authority_set.supply_chain
        runtime_authorization = self.authority_set.runtime_authorization
        assert security is not None
        assert supply is not None
        assert runtime_authorization is not None
        execution = _require_complete_execution(
            execute_futu_plan(
                transport=self.transport,
                authority=self.authority_decision,
                runtime_authorization=runtime_authorization,
                security_identity=security,
                supply_chain=supply,
                run_id=self.stage_plan.run_id,
                issuer_id=request.issuer_id,
                security_id=security.security_id,
                stage="valuation_pre_price_verification",
                data_cutoff_date=request.data_cutoff_date,
                request_started_at=self.stage_plan.pre_price_request_started_at,
                specs=(
                    *_pre_price_specs(security.mic),
                    *compile_futu_optional_data_request_specs(
                        self.optional_data_review
                    ),
                ),
            ),
            "futu_nonprice",
        )
        context = self.runtime.valuation_context
        assert context is not None
        freeze_transition = datetime.fromisoformat(
            context.expected_freeze.handoffs[-1].transitioned_at.replace("Z", "+00:00")
        )
        crosschecked_at = datetime.fromisoformat(
            self.stage_plan.crosscheck_created_at.replace("Z", "+00:00")
        )
        response_times = tuple(
            datetime.fromisoformat(item.retrieved_at.replace("Z", "+00:00"))
            for item in execution.responses
        )
        if (
            not response_times
            or max(response_times) > crosschecked_at
            or crosschecked_at > (freeze_transition)
        ):
            raise _LiveBlocked(("futu_nonprice:refreeze_chronology_invalid",))
        registry = load_reviewed_financial_field_registry(
            execution=execution,
            admission_payload=load_reviewed_financial_field_admission(
                self.optional_data_review
            ),
        )
        execution = reproject_execution_with_financial_field_registry(
            execution,
            registry=registry,
        )
        with reviewed_financial_field_registry_scope(registry):
            operands, receipts = _official_crosschecks(
                graph=context.graph,
                execution=execution,
                created_at=self.stage_plan.crosscheck_created_at,
            )
            dispositions = build_futu_optional_data_dispositions(
                execution=execution,
                review_authority=self.optional_data_review,
            )
        self.financial_field_registry = registry
        self.pre_execution = execution
        self.optional_data_dispositions = dispositions
        self.official_operands = operands
        self.cross_checks = receipts
        return execution

    def replay_price_blind(self) -> PriceBlindFreezeCompilationResult:
        if self.pre_execution is None:
            raise OwnerEquityRuntimeError("price-blind refreeze preceded Futu nonprice evidence")
        context = self.runtime.valuation_context
        assert context is not None
        from .valuation_price_blind_freeze import load_price_blind_input_artifact

        replayed = load_price_blind_input_artifact(
            self._path("price_blind_artifact_directory"),
            graph=context.graph,
            expected_result=context.expected_freeze,
        )
        if replayed != context.expected_freeze:
            raise _LiveBlocked(("price_blind_refreeze_identity_mismatch",))
        return replayed

    def cleanup(self) -> FutuSidecarAbortAttestation | None:
        """Close an opened, non-finalized quote-only session exactly once."""

        transport = self.transport
        if transport is None or self.sidecar_finalization is not None:
            return self.sidecar_abort
        if self.sidecar_abort is None:
            try:
                self.sidecar_abort = transport.abort(reason_code="caller_abort")
            except Exception as exc:
                # The normal abort is a remote signed close. If that exchange or
                # attestation fails, release any local transport/OS handle and
                # detach the unusable session before surfacing one closed error.
                raw_transport = getattr(transport, "_transport", None)
                for target in (transport, raw_transport):
                    close = getattr(target, "close", None)
                    if callable(close):
                        try:
                            close()
                        except Exception:
                            pass
                self.transport = None
                raise OwnerEquityRuntimeError("sidecar cleanup failed") from exc
        return self.sidecar_abort

    def run_market_reference(
        self,
        request: OwnerEquityResearchRequest,
    ) -> FutuMarketReferenceProvider:
        if self.market_provider is not None:
            return self.market_provider
        if self.pre_execution is None:
            raise OwnerEquityRuntimeError("market reference preceded Futu nonprice evidence")
        assert self.authority_set is not None
        assert self.authority_decision is not None
        assert self.transport is not None
        assert self.stage_plan is not None
        context = self.runtime.valuation_context
        assert context is not None
        security = self.authority_set.security_identity
        supply = self.authority_set.supply_chain
        runtime_authorization = self.authority_set.runtime_authorization
        assert security is not None
        assert supply is not None
        assert runtime_authorization is not None
        ticket = reserve_futu_market_reference(
            price_blind_artifact_directory=self._path("price_blind_artifact_directory"),
            graph=context.graph,
            expected_freeze=context.expected_freeze,
            expected_security=context.expected_security,
            authority_set=self.authority_set,
            authority_decision=self.authority_decision,
            security_identity=security,
            supply_chain=supply,
            request_started_at=self.stage_plan.market_request_started_at,
            verifier=self.keyring,
        )
        execution = _require_complete_execution(
            execute_futu_plan(
                transport=self.transport,
                authority=self.authority_decision,
                runtime_authorization=runtime_authorization,
                security_identity=security,
                supply_chain=supply,
                run_id=self.stage_plan.run_id,
                issuer_id=request.issuer_id,
                security_id=security.security_id,
                stage="market_reference",
                data_cutoff_date=request.data_cutoff_date,
                request_started_at=self.stage_plan.market_request_started_at,
                specs=(build_futu_daily_close_request_spec(ticket),),
            ),
            "futu_market_reference",
        )
        assert self.financial_field_registry is not None
        with reviewed_financial_field_registry_scope(self.financial_field_registry):
            evidence = finalize_futu_market_execution_evidence(
                authority_set=self.authority_set,
                authority_decision=self.authority_decision,
                executions=(self.pre_execution, execution),
                contract_graph=context.graph,
                official_operands=self.official_operands,
                cross_checks=self.cross_checks,
                checkpoint_at=self.stage_plan.market_checkpoint_at,
                verifier=self.keyring,
            )
        provider = bind_futu_market_reference_provider(
            ticket=ticket,
            market_execution_evidence=evidence,
            verifier=self.keyring,
        )
        self.ticket = ticket
        self.market_execution = execution
        self.market_evidence = evidence
        self.market_provider = provider
        return provider

    def run_kernel(self) -> ValuationRunResult:
        if self.run_result is not None:
            return self.run_result
        if self.market_provider is None:
            raise OwnerEquityRuntimeError("kernel execution preceded governed market reference")
        if self.kernel_calls != 0:
            raise _LiveBlocked(("kernel_multiple_invocation_attempt",))
        context = self.runtime.valuation_context
        assert context is not None
        assert self.stage_plan is not None
        authority = self._preflight_kernel_runtime_supply()
        self.kernel_calls += 1
        result = run_low_level_valuation(
            graph=context.graph,
            bundle_artifact_directory=(
                _require_research_authority(self.runtime).research.source_directory
            ),
            assumption_proposals=context.assumption_proposals,
            assumption_reviews=context.assumption_reviews,
            market_provider=self.market_provider,
            kernel_wheel=self._path("kernel_wheel"),
            output_directory=self._path("valuation_output_directory"),
            clock=context.clock,
            authority=authority,
            timeout_seconds=self.stage_plan.kernel_timeout_seconds,
        )
        self.run_result = result
        if result.status == "completed":
            assert result.archive is not None
            self.valuation_input = reload_valuation_input(
                result.archive.output_directory,
                component_lock_path=context.graph.component_lock_path,
            )
        return result

    def _run_peer_evidence(self, request: OwnerEquityResearchRequest) -> FutuPeerEvidenceSet:
        if self.peer_evidence_set is not None:
            return self.peer_evidence_set
        if self.run_result is None or self.run_result.status != "completed":
            raise OwnerEquityRuntimeError("peer evidence requires a completed kernel run")
        assert self.transport is not None
        assert self.stage_plan is not None
        assert self.keyring is not None
        context = self.runtime.valuation_context
        assert context is not None
        peers = []
        for plan, security, authority_set, decision in self.peer_authorities:
            supply = authority_set.supply_chain
            runtime_authorization = authority_set.runtime_authorization
            assert supply is not None
            assert runtime_authorization is not None
            execution = _require_complete_execution(
                execute_futu_plan(
                    transport=self.transport,
                    authority=decision,
                    runtime_authorization=runtime_authorization,
                    security_identity=security,
                    supply_chain=supply,
                    run_id=self.stage_plan.run_id,
                    issuer_id=security.issuer_id,
                    security_id=security.security_id,
                    stage="peer_comparable_reference",
                    data_cutoff_date=request.data_cutoff_date,
                    request_started_at=plan.request_started_at,
                    specs=_peer_specs(
                        expected_trading_date=plan.expected_trading_date,
                        price_blind_freeze_fingerprint=(
                            context.expected_freeze.artifact.fingerprint
                        ),
                    ),
                ),
                f"futu_peer:{security.security_id}",
            )
            daily_requests = tuple(item for item in execution.requests if item.protocol_id == 3103)
            if len(daily_requests) != 1:
                raise _LiveBlocked(("futu_peer:daily_close_request_missing",))
            daily_request = daily_requests[0]
            daily_responses = tuple(
                item
                for item in execution.responses
                if item.request_id == daily_request.request_id
                and item.request_fingerprint == daily_request.fingerprint
            )
            daily_observations = tuple(
                item
                for item in execution.observations
                if item.canonical_concept == "futu_unadjusted_daily_close_candidate"
                and daily_responses
                and item.response_fingerprint == daily_responses[0].fingerprint
            )
            if len(daily_responses) != 1 or len(daily_observations) != 1:
                raise _LiveBlocked(("futu_peer:daily_close_evidence_missing",))
            daily_close = adapt_futu_daily_close_to_market_reference(
                authority=decision,
                request=daily_request,
                response=daily_responses[0],
                observation=daily_observations[0],
            )
            peers.append(
                build_futu_peer_session_evidence(
                    authority_set=authority_set,
                    authority_decision=decision,
                    execution=execution,
                    daily_close=daily_close,
                    price_blind_freeze=context.expected_freeze,
                    verifier=self.keyring,
                )
            )
        evidence_set = build_futu_peer_evidence_set(
            target_security_id=self.authority_set.security_identity.security_id,
            price_blind_freeze=context.expected_freeze,
            peers=tuple(sorted(peers, key=lambda item: item.security_id)),
            verifier=self.keyring,
        )
        self.peer_evidence_set = evidence_set
        return evidence_set

    @retained_authority_replay_scope
    def run_synthesis(self, request: OwnerEquityResearchRequest) -> CompositeValuationResult:
        if self.composite is not None:
            return self.composite
        run_result = self.run_result
        if run_result is None or run_result.status != "completed":
            raise OwnerEquityRuntimeError("synthesis requires a completed kernel run")
        assert self.basis_review is not None
        assert self.forward_review is not None
        assert self.selection_review is not None
        assert self.forecast_review is not None
        assert self.peer_plan is not None
        assert self.keyring is not None
        peer_evidence = self._run_peer_evidence(request)
        basis = build_valuation_basis_receipt(
            run_result,
            review_authority=self.basis_review,
        )
        forward: ForwardReOIValuationResult | None = None
        try:
            forward = build_forward_reoi_valuation(
                run_result,
                basis_receipt=basis,
                review_authority=self.forward_review,
            )
        except ValuationSynthesisError as exc:
            if not _is_panel_qualification_gap(exc, panel="forward_reoi"):
                raise

        peer_authority: ReviewedPeerSetAuthority | None = None
        comparable: ComparableValuationResult | None = None
        try:
            peer_authority = build_reviewed_peer_set_authority(
                run_result=run_result,
                selection_review=self.selection_review,
                forecast_review=self.forecast_review,
                peer_graphs=tuple(
                    item.graph for item in self.peer_plan.peer_graph_contexts
                ),
                futu_peer_evidence_set=peer_evidence,
                verifier=self.keyring,
            )
            comparable = build_comparable_valuation(
                run_result,
                basis_receipt=basis,
                peer_authority=peer_authority,
            )
        except ValuationSynthesisError as exc:
            if not _is_panel_qualification_gap(exc, panel="comparables"):
                raise
            peer_authority = None
            comparable = None
        composite = build_composite_valuation(
            run_result,
            basis_receipt=basis,
            forward_reoi=forward,
            comparables=comparable,
        )
        self.basis_receipt = basis
        self.forward_reoi = forward
        self.peer_authority = peer_authority
        self.comparable = comparable
        self.composite = composite
        return composite

    @retained_authority_replay_scope
    def run_score(self) -> OwnerScorecard:
        if self.owner_scorecard is not None:
            return self.owner_scorecard
        if self.composite is None or self.score_plan is None:
            raise OwnerEquityRuntimeError("scorecard requires exact synthesis and reviews")
        context = self.runtime.valuation_context
        if context is None:
            raise OwnerEquityRuntimeError("scorecard requires exact valuation context")
        bundle = _require_research_authority(self.runtime).research.result.bundle
        planned_reviews = tuple(
            self.score_plan.lenses[lens].build(
                scope=f"score:{lens}",
                graph=context.graph,
                research_bundle=bundle,
            )
            for lens in _LENSES
        )
        score_reviews = tuple(
            resolve_score_review_authority(
                composite_valuation=self.composite,
                planned_review=review,
            )
            for review in planned_reviews
        )
        scores = tuple(
            build_score_v2(
                composite_valuation=self.composite,
                review_authority=review,
            )
            for review in score_reviews
        )
        scorecard = build_owner_scorecard(
            composite_valuation=self.composite,
            lens_scores=scores,
        )
        self.score_reviews = score_reviews
        self.lens_scores = scores
        self.owner_scorecard = scorecard
        assert self.stage_plan is not None
        assert self.authority_set is not None
        assert self.authority_set.security_identity is not None
        self.frozen_conclusion = build_futu_frozen_conclusion_receipt(
            run_id=self.stage_plan.run_id,
            security_id=self.authority_set.security_identity.security_id,
            composite_valuation=self.composite,
            owner_scorecard=scorecard,
            conclusion_frozen_at=self.stage_plan.conclusion_frozen_at,
        )
        return scorecard

    def _finalize_sidecar(
        self,
        *,
        post_execution: FutuSidecarExecution | None,
    ) -> tuple[FutuAttestedSessionFinalization, FutuAuthoritySet]:
        if self.sidecar_finalization is not None:
            runtime_receipt = self.sidecar_finalization.runtime_receipt
        else:
            if (
                self.transport is None
                or self.pre_execution is None
                or self.market_execution is None
                or self.peer_evidence_set is None
            ):
                raise OwnerEquityRuntimeError(
                    "sidecar finalization requires retained target and peer executions"
                )
            executions = (
                self.pre_execution,
                self.market_execution,
                *(peer.execution for peer in self.peer_evidence_set.peers),
                *((post_execution,) if post_execution is not None else ()),
            )
            self.sidecar_finalization = self.transport.finalize(
                expected_executions=executions,
                skipped_conditional_conclusion=(
                    self.frozen_conclusion if post_execution is None else None
                ),
            )
            runtime_receipt = self.sidecar_finalization.runtime_receipt
        assert self.authority_set is not None
        completed_authority = FutuAuthoritySet(
            legal=self.authority_set.legal,
            account=self.authority_set.account,
            supply_chain=self.authority_set.supply_chain,
            runtime_authorization=self.authority_set.runtime_authorization,
            runtime=runtime_receipt,
            security_identity=self.authority_set.security_identity,
        )
        assert self.keyring is not None
        assert self.stage_plan is not None
        assert self.authority_decision is not None
        registry = load_protocol_registry()
        retained_executions = (
            self.pre_execution,
            self.market_execution,
            *(peer.execution for peer in self.peer_evidence_set.peers),
            *((post_execution,) if post_execution is not None else ()),
        )
        supply_chain = completed_authority.supply_chain
        runtime_authorization = completed_authority.runtime_authorization
        if supply_chain is None or runtime_authorization is None:
            raise _LiveBlocked(("completed_runtime_authority_incomplete",))
        try:
            validate_futu_attested_session_finalization(
                self.sidecar_finalization,
                expected_executions=tuple(
                    item for item in retained_executions if item is not None
                ),
                supply_chain=supply_chain,
                runtime_authorization=runtime_authorization,
                verifier=self.keyring,
            )
        except (KeyError, OSError, TypeError, ValueError) as exc:
            raise _LiveBlocked(("sidecar_finalization_replay_failed",)) from exc
        all_protocols = tuple(
            sorted(
                {
                    item.protocol_id
                    for source in retained_executions
                    if source is not None
                    for item in source.requests
                }
            )
        )
        replay = evaluate_futu_authority(
            completed_authority,
            verifier=self.keyring,
            now=datetime.fromisoformat(runtime_receipt.issued_at.replace("Z", "+00:00")),
            run_id=self.stage_plan.run_id,
            policy_sha256=self.authority_decision.policy_sha256,
            component_lock_sha256=self.authority_decision.component_lock_sha256,
            required_data_families=tuple(
                sorted({registry[item]["data_family"] for item in all_protocols})
            ),
            required_protocol_ids=all_protocols,
            purpose="replay_only",
        )
        if replay.status != "eligible":
            raise _LiveBlocked(replay.issue_codes)
        return self.sidecar_finalization, completed_authority

    def run_market_expectations(
        self,
        request: OwnerEquityResearchRequest,
    ) -> MarketExpectationsComparison | RuntimeGapReceipt:
        if self.market_expectations is not None:
            return self.market_expectations
        if self.downstream_gap is not None:
            return self.downstream_gap
        if self.composite is None or self.owner_scorecard is None:
            raise OwnerEquityRuntimeError("market expectations preceded synthesis and score")
        if self.frozen_conclusion is None:
            raise OwnerEquityRuntimeError(
                "market expectations require the exact frozen internal conclusion"
            )
        if self.frozen_conclusion.composite_valuation.status in {
            "blocked",
            "contested",
        }:
            finalization, _ = self._finalize_sidecar(post_execution=None)
            gap = RuntimeGapReceipt.create(
                phase="futu_market_expectations",
                composite_valuation=self.composite,
                owner_scorecard=self.owner_scorecard,
                frozen_conclusion=self.frozen_conclusion,
                attested_finalization=finalization,
                issue_codes=("post_context_suppressed:conclusion_not_eligible",),
            )
            self.downstream_gap = gap
            return gap
        assert self.transport is not None
        assert self.authority_set is not None
        assert self.authority_decision is not None
        assert self.stage_plan is not None
        assert self.peer_evidence_set is not None
        assert self.keyring is not None
        security = self.authority_set.security_identity
        supply = self.authority_set.supply_chain
        runtime_authorization = self.authority_set.runtime_authorization
        assert security is not None
        assert supply is not None
        assert runtime_authorization is not None
        context = self.runtime.valuation_context
        assert context is not None
        execution = _require_complete_execution(
            execute_futu_plan(
                transport=self.transport,
                authority=self.authority_decision,
                runtime_authorization=runtime_authorization,
                security_identity=security,
                supply_chain=supply,
                run_id=self.stage_plan.run_id,
                issuer_id=request.issuer_id,
                security_id=security.security_id,
                stage="post_valuation_context",
                data_cutoff_date=request.data_cutoff_date,
                request_started_at=self.stage_plan.post_request_started_at,
                specs=_post_context_specs(
                    price_blind_freeze_fingerprint=(context.expected_freeze.artifact.fingerprint),
                    frozen_conclusion=self.frozen_conclusion,
                ),
            ),
            "futu_market_expectations",
        )
        attested_finalization, completed_authority = self._finalize_sidecar(
            post_execution=execution
        )
        acquisition = _market_acquisition(self.run_result)
        completion = complete_futu_market_session(
            acquisition=acquisition,
            authority_set=completed_authority,
            authority_decision=self.authority_decision,
            peer_evidence_set=self.peer_evidence_set,
            frozen_conclusion=self.frozen_conclusion,
            attested_finalization=attested_finalization,
            post_valuation_execution=execution,
            finalized_at=self.stage_plan.finalized_at,
            verifier=self.keyring,
        )
        comparison = build_market_expectations_comparison(
            session=completion.session_evidence,
            composite_valuation=self.composite,
            owner_scorecard=self.owner_scorecard,
            verifier=self.keyring,
        )
        self.post_execution = execution
        self.session = completion.session_evidence
        self.market_expectations = comparison
        return comparison

    def build_full_report(self) -> ReportBuildResult:
        if self.report is not None:
            return self.report
        if any(
            item is None
            for item in (
                self.valuation_input,
                self.market_evidence,
                self.peer_evidence_set,
                self.composite,
                self.owner_scorecard,
            )
        ):
            raise OwnerEquityRuntimeError("full report lacks exact downstream authorities")
        if self.runtime.report_spec is None or self.keyring is None:
            raise OwnerEquityRuntimeError("full report specification or verifier is unavailable")
        research_authority = _require_research_authority(self.runtime)
        common = {
            "profile": "full_valuation",
            "research": research_authority.research,
            "report_spec": self.runtime.report_spec,
            "research_source_index": research_authority.source_index,
            "renderer": LatexReportRenderer(),
            "valuation": self.valuation_input,
            "futu_verifier": self.keyring,
            "futu_optional_data_dispositions": self.optional_data_dispositions,
            "forward_reoi": self.forward_reoi,
            "comparable_valuation": self.comparable,
            "composite_valuation": self.composite,
            "score_v2": self.lens_scores,
            "owner_scorecard": self.owner_scorecard,
        }
        if self.downstream_gap is not None:
            report = build_research_report(
                **common,
                futu_market_execution_evidence=self.market_evidence,
                futu_peer_evidence_set=self.peer_evidence_set,
                runtime_gap=self.downstream_gap,
            )
        else:
            if self.session is None or self.market_expectations is None:
                raise OwnerEquityRuntimeError(
                    "complete full report lacks post-conclusion Futu authorities"
                )
            report = build_research_report(
                **common,
                futu_session_evidence=self.session,
                market_expectations=self.market_expectations,
            )
        self.report = report
        return report


def build_runtime_dependencies(runtime: OwnerEquityRuntime) -> OwnerEquityResearchDependencies:
    """Bind strict loaded objects to the closed high-level phase adapters."""

    if type(runtime) is not OwnerEquityRuntime:
        raise OwnerEquityRuntimeError("dependency factory requires the exact runtime")
    live = _LiveRuntimeState(runtime)
    bound_futu_input: OwnerEquityResearchInputReceipt | None = None
    admitted_receipts: dict[str, PhaseReceipt] = {}
    attempted_live_phases: set[str] = set()

    def retain_phase_receipt(receipt: PhaseReceipt, phase: str) -> None:
        if type(receipt) is not PhaseReceipt or receipt.phase != phase:
            raise OwnerEquityRuntimeError(f"{phase} did not produce its exact receipt")
        retained = admitted_receipts.get(phase)
        if retained is not None and retained is not receipt:
            raise OwnerEquityRuntimeError(f"{phase} was invoked more than once")
        admitted_receipts[phase] = receipt

    def has_retained_receipt(receipt: PhaseReceipt, phase: str) -> bool:
        return admitted_receipts.get(phase) is receipt

    def begin_live_phase(phase: str) -> None:
        if phase in attempted_live_phases:
            raise OwnerEquityRuntimeError(f"{phase} cannot be retried in one runtime")
        attempted_live_phases.add(phase)

    def require_futu_request(
        inputs: object,
        *,
        expected_type: type[object],
        phase: str,
        require_bound: bool,
    ) -> OwnerEquityResearchRequest:
        if type(inputs) is not expected_type:
            raise OwnerEquityRuntimeError(f"{phase} requires its exact typed phase input")
        request = inputs.request
        if type(request) is not OwnerEquityResearchRequest:
            raise OwnerEquityRuntimeError(f"{phase} requires the exact typed request")
        if (
            runtime.intent is not ResearchIntent.VALUATION
            or runtime.profile is not PublicationProfile.FULL_VALUATION
            or request.intent is not ResearchIntent.VALUATION
            or request.profile is not PublicationProfile.FULL_VALUATION
        ):
            raise OwnerEquityRuntimeError(
                f"{phase} is restricted to the runtime-bound full_valuation route"
            )
        candidate = OwnerEquityResearchInputReceipt.from_request(request)
        if require_bound:
            if bound_futu_input is None:
                raise OwnerEquityRuntimeError(
                    f"{phase} preceded the bound Futu nonprice phase"
                )
            if (
                candidate != bound_futu_input
                or candidate.request is not bound_futu_input.request
            ):
                raise OwnerEquityRuntimeError(
                    f"{phase} rebound the live Futu session to another request"
                )
        return request

    def require_same_bound_futu_request(
        request: OwnerEquityResearchRequest,
    ) -> OwnerEquityResearchInputReceipt:
        candidate = OwnerEquityResearchInputReceipt.from_request(request)
        if bound_futu_input is not None and (
            candidate != bound_futu_input
            or candidate.request is not bound_futu_input.request
        ):
            raise OwnerEquityRuntimeError(
                "Futu nonprice phase rebound the live Futu session to another request"
            )
        return candidate

    def bind_futu_request(request: OwnerEquityResearchRequest) -> None:
        nonlocal bound_futu_input
        candidate = require_same_bound_futu_request(request)
        if bound_futu_input is None:
            bound_futu_input = candidate

    def require_admitted_phase(
        value: object,
        *,
        expected_type: type[object],
        expected_phase: str,
        request: OwnerEquityResearchRequest,
        statuses: tuple[PhaseStatus, ...],
    ) -> PhaseReceipt:
        receipt = getattr(value, "receipt", None)
        if (
            type(value) is not expected_type
            or value.status not in statuses
            or value.issuer_id != request.issuer_id
            or value.data_cutoff_date != request.data_cutoff_date
            or type(receipt) is not PhaseReceipt
            or receipt.phase != expected_phase
            or receipt.input_receipt
            != OwnerEquityResearchInputReceipt.from_request(request)
            or receipt.input_receipt.request is not request
        ):
            raise OwnerEquityRuntimeError(
                f"{expected_phase} input is not the exact admitted predecessor"
            )
        return receipt

    def official(request: OwnerEquityResearchRequest) -> OfficialResearchPhaseResult:
        authority = _require_research_authority(runtime)
        bundle = authority.research.result.bundle
        if (
            bundle.issuer_id != request.issuer_id
            or bundle.data_cutoff_date != request.data_cutoff_date
        ):
            return OfficialResearchPhaseResult(
                status=PhaseStatus.BLOCKED,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=None,
                security_scope=None,
                research_input=None,
                source_index=None,
                price_blind=True,
                issue_codes=("official_research_blocked:identity_mismatch",),
            )
        missing_count = min(len(set(bundle.missing_evidence)), 999)
        if bundle.status == "blocked":
            return OfficialResearchPhaseResult(
                status=PhaseStatus.BLOCKED,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=None,
                security_scope=None,
                research_input=None,
                source_index=None,
                price_blind=True,
                issue_codes=(
                    "official_research_blocked:bundle_status",
                    f"official_research_blocked:missing_evidence_count:{missing_count}",
                ),
            )
        security_scope = _security_scope(runtime)
        scope_issue = security_scope.incomplete_issue
        phase_status = (
            PhaseStatus.COMPLETED
            if bundle.status == "complete" and scope_issue is None
            else PhaseStatus.PARTIAL
        )
        issue_codes = tuple(
            sorted(
                {
                    *((scope_issue,) if scope_issue is not None else ()),
                    *(
                        (
                            "official_research_partial:missing_evidence",
                            "official_research_partial:"
                            f"missing_evidence_count:{missing_count}",
                        )
                        if bundle.status != "complete"
                        else ()
                    ),
                }
            )
        )
        phase_result = OfficialResearchPhaseResult(
            status=phase_status,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=_phase_receipt(
                "official_research_freeze",
                request,
                authority.research,
                authority.source_index,
                security_scope,
            ),
            security_scope=security_scope,
            research_input=authority.research,
            source_index=authority.source_index,
            price_blind=True,
            issue_codes=issue_codes,
        )
        assert phase_result.receipt is not None
        if (
            request.intent is runtime.intent
            and request.profile is runtime.profile
            and "official_research_freeze" not in admitted_receipts
        ):
            retain_phase_receipt(
                phase_result.receipt,
                "official_research_freeze",
            )
        return phase_result

    def quarterly(request, official_result) -> QuarterlyPhaseResult:
        authority = _require_research_authority(runtime)
        candidates = tuple(
            item
            for item in authority.context.graph.quarterly_updates
            if item.issuer_id == request.issuer_id and item.as_of_date <= request.data_cutoff_date
        )
        if not candidates:
            return QuarterlyPhaseResult(
                status=PhaseStatus.BLOCKED,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=None,
                quarterly_result=None,
                issue_codes=("quarterly_blocked:update_missing",),
            )
        latest_date = max(item.as_of_date for item in candidates)
        latest = tuple(item for item in candidates if item.as_of_date == latest_date)
        if len(latest) != 1 or type(latest[0]) is not QuarterlyUpdate:
            return QuarterlyPhaseResult(
                status=PhaseStatus.BLOCKED,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=None,
                quarterly_result=None,
                issue_codes=("quarterly_blocked:update_ambiguous",),
            )
        return QuarterlyPhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=_phase_receipt(
                "quarterly",
                request,
                latest[0],
                upstream=(official_result.receipt,),
            ),
            quarterly_result=latest[0],
        )

    def futu_nonprice(inputs) -> FutuNonPricePhaseResult:
        request = require_futu_request(
            inputs,
            expected_type=NonPriceVerificationInput,
            phase="Futu nonprice phase",
            require_bound=False,
        )
        official_result = inputs.official_research
        official_receipt = require_admitted_phase(
            official_result,
            expected_type=OfficialResearchPhaseResult,
            expected_phase="official_research_freeze",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        require_same_bound_futu_request(request)
        authority = _require_research_authority(runtime)
        security_scope = _security_scope(runtime)
        expected_official_receipt = _phase_receipt(
            "official_research_freeze",
            request,
            authority.research,
            authority.source_index,
            security_scope,
        )
        if (
            official_result.research_input is not authority.research
            or official_result.source_index is not authority.source_index
            or official_result.security_scope != security_scope
            or official_receipt != expected_official_receipt
            or not has_retained_receipt(
                official_receipt,
                "official_research_freeze",
            )
            or not _has_exact_upstreams(official_receipt)
            or not _has_exact_authorities(
                official_receipt,
                official_result.research_input,
                official_result.source_index,
                official_result.security_scope,
            )
        ):
            raise OwnerEquityRuntimeError(
                "Futu nonprice phase rebound the runtime official research authority"
            )
        bind_futu_request(request)
        begin_live_phase("futu_nonprice_verification")
        try:
            execution = live.run_pre_price(request)
        except _LiveBlocked as exc:
            return FutuNonPricePhaseResult(
                status=PhaseStatus.BLOCKED,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=None,
                execution=None,
                optional_data_dispositions=(),
                has_material_conflict=any("conflict" in item for item in exc.issue_codes),
                quote_only_attested=False,
                sec_ir_authority_preserved=True,
                issue_codes=tuple(
                    item
                    if item.startswith("runtime_supply_blocked:")
                    else f"futu_runtime_blocked:{item}"
                    for item in exc.issue_codes
                ),
            )
        assert live.authority_decision is not None
        dispositions = live.optional_data_dispositions
        result = FutuNonPricePhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=_phase_receipt(
                "futu_nonprice_verification",
                request,
                execution,
                dispositions,
                upstream=(inputs.official_research.receipt,),
            ),
            execution=execution,
            optional_data_dispositions=dispositions,
            has_material_conflict=False,
            quote_only_attested=True,
            sec_ir_authority_preserved=True,
        )
        assert result.receipt is not None
        retain_phase_receipt(result.receipt, "futu_nonprice_verification")
        return result

    def refreeze(inputs) -> PriceBlindRefreezePhaseResult:
        request = require_futu_request(
            inputs,
            expected_type=PriceBlindRefreezeInput,
            phase="price-blind refreeze phase",
            require_bound=True,
        )
        official_receipt = require_admitted_phase(
            inputs.official_research,
            expected_type=OfficialResearchPhaseResult,
            expected_phase="official_research_freeze",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        nonprice_receipt = require_admitted_phase(
            inputs.futu_nonprice,
            expected_type=FutuNonPricePhaseResult,
            expected_phase="futu_nonprice_verification",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        authority = _require_research_authority(runtime)
        if (
            not has_retained_receipt(official_receipt, "official_research_freeze")
            or not has_retained_receipt(
                nonprice_receipt,
                "futu_nonprice_verification",
            )
            or inputs.official_research.research_input is not authority.research
            or inputs.futu_nonprice.execution is not live.pre_execution
            or not _same_exact_authority(
                inputs.futu_nonprice.optional_data_dispositions,
                live.optional_data_dispositions,
            )
        ):
            raise OwnerEquityRuntimeError(
                "price-blind refreeze phase is not bound to the exact nonprice sequence"
            )
        try:
            freeze_result = live.replay_price_blind()
        except _LiveBlocked as exc:
            return PriceBlindRefreezePhaseResult(
                status=PhaseStatus.BLOCKED,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=None,
                research_input=None,
                price_blind_input=None,
                sec_ir_authority_preserved=True,
                issue_codes=exc.issue_codes,
            )
        result = PriceBlindRefreezePhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=_phase_receipt(
                "price_blind_refreeze",
                request,
                authority.research,
                freeze_result,
                upstream=(
                    inputs.official_research.receipt,
                    inputs.futu_nonprice.receipt,
                ),
            ),
            research_input=authority.research,
            price_blind_input=freeze_result,
            sec_ir_authority_preserved=True,
        )
        assert result.receipt is not None
        retain_phase_receipt(result.receipt, "price_blind_refreeze")
        return result

    def market_reference(inputs) -> FutuMarketReferencePhaseResult:
        request = require_futu_request(
            inputs,
            expected_type=MarketReferenceInput,
            phase="Futu market-reference phase",
            require_bound=True,
        )
        nonprice_result = inputs.futu_nonprice
        nonprice_receipt = require_admitted_phase(
            nonprice_result,
            expected_type=FutuNonPricePhaseResult,
            expected_phase="futu_nonprice_verification",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        price_blind_result = inputs.price_blind
        price_blind_receipt = require_admitted_phase(
            price_blind_result,
            expected_type=PriceBlindRefreezePhaseResult,
            expected_phase="price_blind_refreeze",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        authority = _require_research_authority(runtime)
        context = runtime.valuation_context
        if context is None:
            raise OwnerEquityRuntimeError("Futu market-reference phase lacks valuation context")
        if (
            nonprice_result.execution is not live.pre_execution
            or not _same_exact_authority(
                nonprice_result.optional_data_dispositions,
                live.optional_data_dispositions,
            )
            or price_blind_result.research_input is not authority.research
            or price_blind_result.price_blind_input != context.expected_freeze
            or not has_retained_receipt(
                nonprice_receipt,
                "futu_nonprice_verification",
            )
            or not has_retained_receipt(
                price_blind_receipt,
                "price_blind_refreeze",
            )
            or not _has_exact_market_predecessor_topology(
                price_blind_receipt,
                nonprice_receipt,
            )
            or not _has_exact_authorities(
                nonprice_receipt,
                nonprice_result.execution,
                nonprice_result.optional_data_dispositions,
            )
            or not _has_exact_authorities(
                price_blind_receipt,
                price_blind_result.research_input,
                price_blind_result.price_blind_input,
            )
        ):
            raise OwnerEquityRuntimeError(
                "Futu market-reference phase is not bound to the exact refreeze sequence"
            )
        begin_live_phase("futu_market_reference")
        try:
            provider = live.run_market_reference(request)
        except _LiveBlocked as exc:
            return FutuMarketReferencePhaseResult(
                status=PhaseStatus.BLOCKED,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=None,
                evidence_bundle=None,
                market_reference=None,
                quote_only_attested=False,
                issue_codes=exc.issue_codes,
            )
        assert live.market_evidence is not None
        result = FutuMarketReferencePhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=_phase_receipt(
                "futu_market_reference",
                request,
                live.market_evidence,
                provider,
                upstream=(
                    inputs.price_blind.receipt,
                    inputs.futu_nonprice.receipt,
                ),
            ),
            evidence_bundle=live.market_evidence,
            market_reference=provider,
            quote_only_attested=True,
        )
        assert result.receipt is not None
        retain_phase_receipt(result.receipt, "futu_market_reference")
        return result

    def kernel_phase(inputs) -> KernelValuationPhaseResult:
        request = require_futu_request(
            inputs,
            expected_type=KernelValuationInput,
            phase="owner valuation kernel phase",
            require_bound=True,
        )
        price_blind_receipt = require_admitted_phase(
            inputs.price_blind,
            expected_type=PriceBlindRefreezePhaseResult,
            expected_phase="price_blind_refreeze",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        market_receipt = require_admitted_phase(
            inputs.market_reference,
            expected_type=FutuMarketReferencePhaseResult,
            expected_phase="futu_market_reference",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        authority = _require_research_authority(runtime)
        context = runtime.valuation_context
        if context is None:
            raise OwnerEquityRuntimeError("owner valuation kernel phase lacks valuation context")
        if (
            inputs.price_blind.research_input is not authority.research
            or inputs.price_blind.price_blind_input != context.expected_freeze
            or inputs.market_reference.evidence_bundle is not live.market_evidence
            or inputs.market_reference.market_reference is not live.market_provider
            or not has_retained_receipt(
                price_blind_receipt,
                "price_blind_refreeze",
            )
            or not has_retained_receipt(
                market_receipt,
                "futu_market_reference",
            )
            or not _has_exact_market_topology(
                price_blind_receipt,
                market_receipt,
            )
            or not _has_exact_authorities(
                price_blind_receipt,
                inputs.price_blind.research_input,
                inputs.price_blind.price_blind_input,
            )
            or not _has_exact_authorities(
                market_receipt,
                inputs.market_reference.evidence_bundle,
                inputs.market_reference.market_reference,
            )
        ):
            raise OwnerEquityRuntimeError(
                "owner valuation kernel phase is not bound to the exact market sequence"
            )
        try:
            result = live.run_kernel()
        except _LiveBlocked as exc:
            return KernelValuationPhaseResult(
                status=PhaseStatus.BLOCKED,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=None,
                valuation_run=None,
                six_file_archive=None,
                issue_codes=exc.issue_codes,
            )
        status = {
            "completed": PhaseStatus.COMPLETED,
            "blocked": PhaseStatus.BLOCKED,
            "specialist_required": PhaseStatus.SPECIALIST_REQUIRED,
        }[result.status]
        phase_result = KernelValuationPhaseResult(
            status=status,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=(
                _phase_receipt(
                    "owner_valuation_kernel",
                    request,
                    result,
                    result.archive,
                    upstream=(
                        inputs.price_blind.receipt,
                        inputs.market_reference.receipt,
                    ),
                )
                if result.status == "completed"
                else None
            ),
            valuation_run=result if result.status == "completed" else None,
            six_file_archive=result.archive if result.status == "completed" else None,
            issue_codes=result.issue_codes,
        )
        if phase_result.receipt is not None:
            retain_phase_receipt(phase_result.receipt, "owner_valuation_kernel")
        return phase_result

    def synthesis_phase(inputs) -> SynthesisPhaseResult:
        request = require_futu_request(
            inputs,
            expected_type=SynthesisInput,
            phase="valuation synthesis peer-Futu phase",
            require_bound=True,
        )
        price_blind_receipt = require_admitted_phase(
            inputs.price_blind,
            expected_type=PriceBlindRefreezePhaseResult,
            expected_phase="price_blind_refreeze",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        market_receipt = require_admitted_phase(
            inputs.market_reference,
            expected_type=FutuMarketReferencePhaseResult,
            expected_phase="futu_market_reference",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        kernel_receipt = require_admitted_phase(
            inputs.kernel,
            expected_type=KernelValuationPhaseResult,
            expected_phase="owner_valuation_kernel",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        authority = _require_research_authority(runtime)
        context = runtime.valuation_context
        if context is None:
            raise OwnerEquityRuntimeError(
                "valuation synthesis peer-Futu phase lacks valuation context"
            )
        if (
            inputs.price_blind.research_input is not authority.research
            or inputs.price_blind.price_blind_input != context.expected_freeze
            or inputs.market_reference.evidence_bundle is not live.market_evidence
            or inputs.market_reference.market_reference is not live.market_provider
            or inputs.kernel.valuation_run is not live.run_result
            or live.run_result is None
            or inputs.kernel.six_file_archive is not live.run_result.archive
            or not has_retained_receipt(
                price_blind_receipt,
                "price_blind_refreeze",
            )
            or not has_retained_receipt(
                market_receipt,
                "futu_market_reference",
            )
            or not has_retained_receipt(
                kernel_receipt,
                "owner_valuation_kernel",
            )
            or not _has_exact_kernel_topology(
                price_blind_receipt,
                market_receipt,
                kernel_receipt,
            )
            or not _has_exact_authorities(
                price_blind_receipt,
                inputs.price_blind.research_input,
                inputs.price_blind.price_blind_input,
            )
            or not _has_exact_authorities(
                market_receipt,
                inputs.market_reference.evidence_bundle,
                inputs.market_reference.market_reference,
            )
            or not _has_exact_authorities(
                kernel_receipt,
                inputs.kernel.valuation_run,
                inputs.kernel.six_file_archive,
            )
        ):
            raise OwnerEquityRuntimeError(
                "valuation synthesis peer-Futu phase is not bound to the exact valuation sequence"
            )
        begin_live_phase("three_panel_synthesis")
        composite = live.run_synthesis(request)
        assert live.run_result is not None
        assert live.peer_evidence_set is not None
        status = (
            PhaseStatus.CONTESTED
            if composite.status == "contested"
            else PhaseStatus.COMPLETED
            if composite.status == "complete"
            else PhaseStatus.PARTIAL
        )
        issues = composite.issue_codes
        phase_result = SynthesisPhaseResult(
            status=status,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=_phase_receipt(
                "three_panel_synthesis",
                request,
                *tuple(
                    item
                    for item in (
                        live.run_result,
                        live.forward_reoi,
                        live.comparable,
                        composite,
                        live.peer_evidence_set,
                    )
                    if item is not None
                ),
                upstream=(
                    inputs.price_blind.receipt,
                    inputs.market_reference.receipt,
                    inputs.kernel.receipt,
                ),
            ),
            mckinsey_panel=live.run_result,
            forward_reoi_panel=live.forward_reoi,
            comparable_panel=live.comparable,
            composite_valuation=composite,
            peer_evidence_set=live.peer_evidence_set,
            three_panel_complete=composite.status in {"complete", "contested"},
            current_value_available=composite.current_intrinsic_value is not None,
            twelve_month_target_available=composite.twelve_month_target is not None,
            recommendation_eligible=composite.recommendation_eligible,
            issue_codes=issues,
        )
        assert phase_result.receipt is not None
        retain_phase_receipt(phase_result.receipt, "three_panel_synthesis")
        return phase_result

    def score_phase(inputs) -> ScorePhaseResult:
        request = require_futu_request(
            inputs,
            expected_type=ScoringInput,
            phase="owner scorecard phase",
            require_bound=True,
        )
        price_blind_receipt = require_admitted_phase(
            inputs.price_blind,
            expected_type=PriceBlindRefreezePhaseResult,
            expected_phase="price_blind_refreeze",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        synthesis_receipt = require_admitted_phase(
            inputs.synthesis,
            expected_type=SynthesisPhaseResult,
            expected_phase="three_panel_synthesis",
            request=request,
            statuses=(
                PhaseStatus.COMPLETED,
                PhaseStatus.PARTIAL,
                PhaseStatus.CONTESTED,
            ),
        )
        if (
            not has_retained_receipt(
                price_blind_receipt,
                "price_blind_refreeze",
            )
            or not has_retained_receipt(
                synthesis_receipt,
                "three_panel_synthesis",
            )
        ):
            raise OwnerEquityRuntimeError(
                "owner scorecard phase is not bound to the exact synthesis sequence"
            )
        market_receipt = synthesis_receipt.upstream_receipts[1]
        context = runtime.valuation_context
        if context is None:
            raise OwnerEquityRuntimeError("owner scorecard phase lacks valuation context")
        if (
            inputs.price_blind.price_blind_input != context.expected_freeze
            or inputs.synthesis.mckinsey_panel is not live.run_result
            or inputs.synthesis.forward_reoi_panel is not live.forward_reoi
            or inputs.synthesis.comparable_panel is not live.comparable
            or inputs.synthesis.composite_valuation is not live.composite
            or inputs.synthesis.peer_evidence_set is not live.peer_evidence_set
            or not _has_exact_synthesis_topology(
                price_blind_receipt,
                market_receipt,
                synthesis_receipt,
            )
            or not _has_exact_authorities(
                price_blind_receipt,
                inputs.price_blind.research_input,
                inputs.price_blind.price_blind_input,
            )
            or not _has_exact_authorities(
                synthesis_receipt,
                *tuple(
                    item
                    for item in (
                        inputs.synthesis.mckinsey_panel,
                        inputs.synthesis.forward_reoi_panel,
                        inputs.synthesis.comparable_panel,
                        inputs.synthesis.composite_valuation,
                        inputs.synthesis.peer_evidence_set,
                    )
                    if item is not None
                ),
            )
        ):
            raise OwnerEquityRuntimeError(
                "owner scorecard phase is not bound to the exact synthesis sequence"
            )
        scorecard = live.run_score()
        status, issues = _score_phase_outcome(scorecard)
        phase_result = ScorePhaseResult(
            status=status,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=_phase_receipt(
                "owner_scorecard",
                request,
                live.lens_scores,
                scorecard,
                upstream=(inputs.synthesis.receipt,),
            ),
            lens_scores=live.lens_scores,
            scorecard=scorecard,
            recommendation=scorecard.recommendation,
            issue_codes=issues,
        )
        assert phase_result.receipt is not None
        retain_phase_receipt(phase_result.receipt, "owner_scorecard")
        return phase_result

    def expectations_phase(inputs) -> MarketExpectationsPhaseResult:
        request = require_futu_request(
            inputs,
            expected_type=MarketExpectationsInput,
            phase="Futu market-expectations phase",
            require_bound=True,
        )
        price_blind_receipt = require_admitted_phase(
            inputs.price_blind,
            expected_type=PriceBlindRefreezePhaseResult,
            expected_phase="price_blind_refreeze",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        market_receipt = require_admitted_phase(
            inputs.market_reference,
            expected_type=FutuMarketReferencePhaseResult,
            expected_phase="futu_market_reference",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        synthesis_receipt = require_admitted_phase(
            inputs.synthesis,
            expected_type=SynthesisPhaseResult,
            expected_phase="three_panel_synthesis",
            request=request,
            statuses=(
                PhaseStatus.COMPLETED,
                PhaseStatus.PARTIAL,
                PhaseStatus.CONTESTED,
            ),
        )
        score_receipt = require_admitted_phase(
            inputs.score,
            expected_type=ScorePhaseResult,
            expected_phase="owner_scorecard",
            request=request,
            statuses=(
                PhaseStatus.COMPLETED,
                PhaseStatus.PARTIAL,
                PhaseStatus.CONTESTED,
            ),
        )
        context = runtime.valuation_context
        if context is None:
            raise OwnerEquityRuntimeError("Futu market-expectations phase lacks valuation context")
        if (
            inputs.price_blind.price_blind_input
            != context.expected_freeze
            or inputs.market_reference.evidence_bundle is not live.market_evidence
            or inputs.market_reference.market_reference is not live.market_provider
            or inputs.synthesis.mckinsey_panel is not live.run_result
            or live.run_result is None
            or inputs.synthesis.forward_reoi_panel is not live.forward_reoi
            or inputs.synthesis.comparable_panel is not live.comparable
            or inputs.synthesis.composite_valuation is not live.composite
            or inputs.synthesis.peer_evidence_set is not live.peer_evidence_set
            or not _same_exact_authority(inputs.score.lens_scores, live.lens_scores)
            or inputs.score.scorecard is not live.owner_scorecard
            or not has_retained_receipt(
                price_blind_receipt,
                "price_blind_refreeze",
            )
            or not has_retained_receipt(
                market_receipt,
                "futu_market_reference",
            )
            or not has_retained_receipt(
                synthesis_receipt,
                "three_panel_synthesis",
            )
            or not has_retained_receipt(
                score_receipt,
                "owner_scorecard",
            )
            or not _has_exact_synthesis_topology(
                price_blind_receipt,
                market_receipt,
                synthesis_receipt,
            )
            or not _has_exact_upstreams(score_receipt, synthesis_receipt)
            or not _has_exact_authorities(
                price_blind_receipt,
                inputs.price_blind.research_input,
                inputs.price_blind.price_blind_input,
            )
            or not _has_exact_authorities(
                market_receipt,
                inputs.market_reference.evidence_bundle,
                inputs.market_reference.market_reference,
            )
            or not _has_exact_authorities(
                synthesis_receipt.upstream_receipts[2],
                inputs.synthesis.mckinsey_panel,
                live.run_result.archive,
            )
            or not _has_exact_authorities(
                synthesis_receipt,
                *tuple(
                    item
                    for item in (
                        inputs.synthesis.mckinsey_panel,
                        inputs.synthesis.forward_reoi_panel,
                        inputs.synthesis.comparable_panel,
                        inputs.synthesis.composite_valuation,
                        inputs.synthesis.peer_evidence_set,
                    )
                    if item is not None
                ),
            )
            or not _has_exact_authorities(
                score_receipt,
                inputs.score.lens_scores,
                inputs.score.scorecard,
            )
        ):
            raise OwnerEquityRuntimeError(
                "Futu market-expectations phase is not bound to the exact valuation sequence"
            )
        begin_live_phase("futu_market_expectations")
        try:
            value = live.run_market_expectations(request)
        except _LiveBlocked as exc:
            return MarketExpectationsPhaseResult(
                status=PhaseStatus.BLOCKED,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=None,
                session=None,
                comparison=None,
                gap=None,
                quote_only_attested=False,
                issue_codes=exc.issue_codes,
            )
        if type(value) is RuntimeGapReceipt:
            phase_result = MarketExpectationsPhaseResult(
                status=PhaseStatus.PARTIAL,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=_phase_receipt(
                    "futu_market_expectations",
                    request,
                    value,
                    upstream=(
                        inputs.market_reference.receipt,
                        inputs.synthesis.receipt,
                        inputs.score.receipt,
                    ),
                ),
                session=None,
                comparison=None,
                gap=value,
                quote_only_attested=True,
                issue_codes=value.issue_codes,
            )
        else:
            assert type(value) is MarketExpectationsComparison
            assert live.session is not None
            status = (
                PhaseStatus.COMPLETED
                if value.status == "complete"
                else PhaseStatus.PARTIAL
            )
            phase_result = MarketExpectationsPhaseResult(
                status=status,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=_phase_receipt(
                    "futu_market_expectations",
                    request,
                    live.session,
                    value,
                    upstream=(
                        inputs.market_reference.receipt,
                        inputs.synthesis.receipt,
                        inputs.score.receipt,
                    ),
                ),
                session=live.session,
                comparison=value,
                gap=None,
                quote_only_attested=True,
                issue_codes=value.issue_codes,
            )
        assert phase_result.receipt is not None
        retain_phase_receipt(phase_result.receipt, "futu_market_expectations")
        return phase_result

    def build_report_phase(inputs) -> ReportPhaseResult:
        if type(inputs) is not ReportBuildInput:
            raise OwnerEquityRuntimeError("report phase requires its exact typed input")
        request = inputs.request
        if (
            type(request) is not OwnerEquityResearchRequest
            or request.intent is not runtime.intent
            or request.profile is not runtime.profile
            or inputs.profile is not runtime.profile
        ):
            raise OwnerEquityRuntimeError("report phase rebound the runtime request")
        if runtime.report_spec is None:
            raise OwnerEquityRuntimeError("report specification is unavailable")
        if inputs.profile is PublicationProfile.FULL_VALUATION:
            official_receipt = require_admitted_phase(
                inputs.official_research,
                expected_type=OfficialResearchPhaseResult,
                expected_phase="official_research_freeze",
                request=request,
                statuses=(PhaseStatus.COMPLETED,),
            )
            price_blind_receipt = require_admitted_phase(
                inputs.price_blind,
                expected_type=PriceBlindRefreezePhaseResult,
                expected_phase="price_blind_refreeze",
                request=request,
                statuses=(PhaseStatus.COMPLETED,),
            )
            market_receipt = require_admitted_phase(
                inputs.market_reference,
                expected_type=FutuMarketReferencePhaseResult,
                expected_phase="futu_market_reference",
                request=request,
                statuses=(PhaseStatus.COMPLETED,),
            )
            kernel_receipt = require_admitted_phase(
                inputs.kernel,
                expected_type=KernelValuationPhaseResult,
                expected_phase="owner_valuation_kernel",
                request=request,
                statuses=(PhaseStatus.COMPLETED,),
            )
            synthesis_receipt = require_admitted_phase(
                inputs.synthesis,
                expected_type=SynthesisPhaseResult,
                expected_phase="three_panel_synthesis",
                request=request,
                statuses=(
                    PhaseStatus.COMPLETED,
                    PhaseStatus.PARTIAL,
                    PhaseStatus.CONTESTED,
                ),
            )
            score_receipt = require_admitted_phase(
                inputs.score,
                expected_type=ScorePhaseResult,
                expected_phase="owner_scorecard",
                request=request,
                statuses=(
                    PhaseStatus.COMPLETED,
                    PhaseStatus.PARTIAL,
                    PhaseStatus.CONTESTED,
                ),
            )
            expectations_receipt = require_admitted_phase(
                inputs.market_expectations,
                expected_type=MarketExpectationsPhaseResult,
                expected_phase="futu_market_expectations",
                request=request,
                statuses=(PhaseStatus.COMPLETED, PhaseStatus.PARTIAL),
            )
            if not all(
                has_retained_receipt(receipt, phase)
                for receipt, phase in (
                    (official_receipt, "official_research_freeze"),
                    (price_blind_receipt, "price_blind_refreeze"),
                    (market_receipt, "futu_market_reference"),
                    (kernel_receipt, "owner_valuation_kernel"),
                    (synthesis_receipt, "three_panel_synthesis"),
                    (score_receipt, "owner_scorecard"),
                    (expectations_receipt, "futu_market_expectations"),
                )
            ):
                raise OwnerEquityRuntimeError(
                    "full report phase is not bound to the exact valuation sequence"
                )
            report = live.build_full_report()
            status, issues = _report_phase_outcome(
                report,
                PublicationProfile.FULL_VALUATION,
            )
            contains_target = (
                live.composite is not None
                and live.composite.twelve_month_target is not None
            )
            phase_result = ReportPhaseResult(
                status=status,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=_phase_receipt(
                    "report",
                    request,
                    report,
                    report.receipt,
                    upstream=(
                        inputs.official_research.receipt,
                        inputs.price_blind.receipt,
                        inputs.market_reference.receipt,
                        inputs.kernel.receipt,
                        inputs.synthesis.receipt,
                        inputs.score.receipt,
                        inputs.market_expectations.receipt,
                    ),
                ),
                profile=PublicationProfile.FULL_VALUATION,
                report_build=report,
                report_build_receipt=report.receipt,
                contains_market_price=True,
                contains_target_price=contains_target,
                issue_codes=issues,
            )
            assert phase_result.receipt is not None
            retain_phase_receipt(phase_result.receipt, "report")
            return phase_result
        official_receipt = require_admitted_phase(
            inputs.official_research,
            expected_type=OfficialResearchPhaseResult,
            expected_phase="official_research_freeze",
            request=request,
            statuses=(PhaseStatus.COMPLETED,),
        )
        if not has_retained_receipt(
            official_receipt,
            "official_research_freeze",
        ):
            raise OwnerEquityRuntimeError(
                "research report phase is not bound to the exact official research"
            )
        authority = _require_research_authority(runtime)
        report = build_research_report(
            profile="research_only",
            research=authority.research,
            report_spec=runtime.report_spec,
            research_source_index=authority.source_index,
            # Score 2.0 belongs strictly downstream of explicit valuation.  Legacy graph
            # scores are evidence-domain objects, not authority for a price-blind report.
            scores=(),
            renderer=LatexReportRenderer(),
        )
        status, issues = _report_phase_outcome(
            report,
            PublicationProfile.RESEARCH_ONLY,
        )
        phase_result = ReportPhaseResult(
            status=status,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=_phase_receipt(
                "report",
                request,
                report,
                report.receipt,
                upstream=(inputs.official_research.receipt,),
            ),
            profile=PublicationProfile.RESEARCH_ONLY,
            report_build=report,
            report_build_receipt=report.receipt,
            contains_market_price=False,
            contains_target_price=False,
            issue_codes=issues,
        )
        assert phase_result.receipt is not None
        retain_phase_receipt(phase_result.receipt, "report")
        return phase_result

    def publish_phase(inputs) -> PublicationPhaseResult:
        request = inputs.request
        if runtime.publication_output is None:
            raise OwnerEquityRuntimeError("publication output is unavailable")
        if inputs.existing_only:
            source = inputs.source_package
            if (
                type(source) is not PublishedResearchPackage
                or source is not runtime.publication_source_package
            ):
                raise OwnerEquityRuntimeError(
                    "existing-only publication rebound its strictly reloaded source package"
                )
            if (
                source.profile != inputs.profile.value
                or source.report.issuer_id != request.issuer_id
                or source.report.data_cutoff_date != request.data_cutoff_date
            ):
                return PublicationPhaseResult(
                    status=PhaseStatus.BLOCKED,
                    issuer_id=request.issuer_id,
                    data_cutoff_date=request.data_cutoff_date,
                    receipt=None,
                    profile=inputs.profile,
                    published_package=None,
                    publication_manifest=None,
                    source_package=None,
                    issue_codes=("publication_blocked:identity_mismatch",),
                )
            package = republish_owner_research_package(
                source,
                output_directory=runtime.publication_output,
            )
            if (
                package.publication_manifest.fingerprint
                != source.publication_manifest.fingerprint
                or dict(package.file_bytes) != dict(source.file_bytes)
                or dict(package.file_sha256) != dict(source.file_sha256)
            ):
                raise OwnerEquityRuntimeError(
                    "existing-only publication changed the strictly reloaded package"
                )
            publication_status, publication_issues = _published_package_outcome(
                package,
                inputs.profile,
            )
            return PublicationPhaseResult(
                status=publication_status,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=_phase_receipt(
                    "publication",
                    request,
                    source,
                    package,
                    package.publication_manifest,
                ),
                profile=inputs.profile,
                published_package=package,
                publication_manifest=package.publication_manifest,
                source_package=source,
                issue_codes=publication_issues,
            )
        if type(inputs.report) is not ReportPhaseResult or (
            type(inputs.report.report_build) is not ReportBuildResult
        ):
            raise OwnerEquityRuntimeError("publication requires an exact report build")
        required_receipts = (
            (
                (inputs.official_research.receipt, "official_research_freeze"),
                (inputs.price_blind.receipt, "price_blind_refreeze"),
                (inputs.kernel.receipt, "owner_valuation_kernel"),
                (inputs.synthesis.receipt, "three_panel_synthesis"),
                (inputs.score.receipt, "owner_scorecard"),
                (
                    inputs.market_expectations.receipt,
                    "futu_market_expectations",
                ),
                (inputs.report.receipt, "report"),
            )
            if inputs.profile is PublicationProfile.FULL_VALUATION
            else (
                (inputs.official_research.receipt, "official_research_freeze"),
                (inputs.report.receipt, "report"),
            )
        )
        if any(
            type(receipt) is not PhaseReceipt
            or not has_retained_receipt(receipt, phase)
            for receipt, phase in required_receipts
        ):
            raise OwnerEquityRuntimeError(
                "publication phase is not bound to the exact report sequence"
            )
        authority = _require_research_authority(runtime)
        package = publish_owner_research(
            inputs.report.report_build,
            authority.research,
            output_directory=runtime.publication_output,
            valuation=(
                live.valuation_input
                if inputs.profile is PublicationProfile.FULL_VALUATION
                else None
            ),
            component_lock_path=authority.context.graph.component_lock_path,
            futu_verifier=(
                live.keyring if inputs.profile is PublicationProfile.FULL_VALUATION else None
            ),
        )
        publication_status, publication_issues = _published_package_outcome(
            package,
            inputs.profile,
        )
        return PublicationPhaseResult(
            status=publication_status,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=_phase_receipt(
                "publication",
                request,
                package,
                package.publication_manifest,
                upstream=(
                    inputs.official_research.receipt,
                    *((inputs.price_blind.receipt,) if inputs.price_blind is not None else ()),
                    *((inputs.kernel.receipt,) if inputs.kernel is not None else ()),
                    *((inputs.synthesis.receipt,) if inputs.synthesis is not None else ()),
                    *((inputs.score.receipt,) if inputs.score is not None else ()),
                    *(
                        (inputs.market_expectations.receipt,)
                        if inputs.market_expectations is not None
                        else ()
                    ),
                    inputs.report.receipt,
                ),
            ),
            profile=inputs.profile,
            published_package=package,
            publication_manifest=package.publication_manifest,
            source_package=None,
            issue_codes=publication_issues,
        )

    def audit(request: OwnerEquityResearchRequest) -> AuditPhaseResult:
        if runtime.audit_package is None:
            raise OwnerEquityRuntimeError("audit package is unavailable")
        package = runtime.audit_package
        if (
            package.report.issuer_id != request.issuer_id
            or package.report.data_cutoff_date != request.data_cutoff_date
        ):
            return AuditPhaseResult(
                status=PhaseStatus.BLOCKED,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                receipt=None,
                audit_result=None,
                read_only=True,
                issue_codes=("audit_blocked:identity_mismatch",),
            )
        return AuditPhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=_phase_receipt("audit", request, package),
            audit_result=package,
            read_only=True,
        )

    return OwnerEquityResearchDependencies(
        official_research=official,
        quarterly=quarterly,
        futu_nonprice=futu_nonprice,
        refreeze_price_blind=refreeze,
        futu_market_reference=market_reference,
        run_owner_valuation=kernel_phase,
        synthesize=synthesis_phase,
        score=score_phase,
        futu_market_expectations=expectations_phase,
        build_report=build_report_phase,
        publish=publish_phase,
        audit=audit,
        intent=runtime.intent,
        profile=runtime.profile,
        cleanup=live.cleanup,
        publication_source=runtime.publication_source_package,
    )


def runtime_request_time(value: str) -> datetime:
    """Parse the request time for live authority evaluation without reading wall time."""

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise OwnerEquityRuntimeError("runtime request time is invalid") from exc
    if parsed.tzinfo is None:
        raise OwnerEquityRuntimeError("runtime request time must include a timezone")
    return parsed.astimezone(UTC)


__all__ = (
    "Ed25519PublicKeyring",
    "OwnerEquityRuntime",
    "OwnerEquityRuntimeError",
    "ResearchRuntimeContext",
    "RuntimeResearchAuthority",
    "RuntimeValuationLocators",
    "build_runtime_dependencies",
    "load_owner_equity_runtime",
    "load_research_runtime_context",
    "runtime_request_time",
    "write_research_runtime_context",
)
