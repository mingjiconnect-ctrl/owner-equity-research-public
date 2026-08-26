from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from .fingerprints import FrozenMap, canonical_sha256, to_json_value
from .futu_crosscheck import (
    OfficialEvidenceOperand,
    _crosscheck_vendor_observation_with_graph_fingerprint,
    _premarket_contract_graph_fingerprint,
    resolve_crosscheck,
)
from .futu_receipts import (
    FUTU_SCHEMA_VERSION,
    FutuAuthorityDecision,
    FutuAuthoritySet,
    FutuContract,
    FutuCrossCheckReceipt,
    FutuFrozenConclusionReceipt,
    FutuObservationDispositionReceipt,
    FutuReceiptError,
    FutuSecurityIdentityReceipt,
    SignatureVerifier,
    content_identity,
    evaluate_futu_authority,
    validate_futu_payload,
)
from .futu_sidecar import (
    FutuAttestedSessionFinalization,
    FutuDailyCloseAdapterResult,
    FutuSidecarExecution,
    adapt_futu_daily_close_to_market_reference,
    load_protocol_registry,
    validate_futu_attested_session_finalization,
    validate_futu_execution_replay,
)
from .validation import ContractGraph
from .valuation_price_blind_freeze import PriceBlindFreezeCompilationResult
from .valuation_run import ValuationRunResult

_SESSION_STAGES = (
    "valuation_pre_price_verification",
    "market_reference",
    "post_valuation_context",
)


class FutuSessionEvidenceError(ValueError):
    """Raised when an allegedly complete Futu session cannot be replayed exactly."""


_STATIC_IDENTITY_FIELD_ORDER = (
    "vendor_security_market",
    "vendor_security_code",
    "security_type",
    "listing_mic",
    "listing_date",
    "delisting",
    "vendor_security_id",
    "lot_size",
    "security_name",
)
_STATIC_IDENTITY_EXCHANGE_CODES = {"XNYS": 4, "XNAS": 5}


def futu_static_identity_projection(
    *,
    vendor_security_market: str,
    vendor_security_code: str,
    security_type: str,
    listing_mic: str,
    listing_date: str,
    delisting: bool,
    vendor_security_id: str,
    lot_size: str,
    security_name: str,
    raw_exchange_type: int,
    raw_market_code: int,
    raw_security_type: int,
) -> FrozenMap:
    """Build the transport-independent normalized projection of one 3202 row.

    The projection deliberately excludes run, request, response, serial, retrieval, and
    encrypted-CAS identities.  It therefore remains stable when the same reviewed security
    is observed in another authorized session while still binding every semantic field and
    the three pinned SDK enum qualifiers emitted by the private parser.
    """
    if vendor_security_market != "US":
        raise FutuSessionEvidenceError("static identity market must be US")
    code = (
        vendor_security_code.removeprefix("US.")
        if isinstance(vendor_security_code, str)
        else ""
    )
    if (
        not code
        or len(code) > 32
        or not code.isascii()
        or not code[0].isalnum()
        or code != code.upper()
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
            for character in code
        )
    ):
        raise FutuSessionEvidenceError("static identity code is invalid")
    if security_type != "COMMON_EQUITY":
        raise FutuSessionEvidenceError("static identity is not common equity")
    if listing_mic not in _STATIC_IDENTITY_EXCHANGE_CODES:
        raise FutuSessionEvidenceError("static identity listing MIC is unsupported")
    try:
        parsed_listing_date = date.fromisoformat(listing_date)
    except (TypeError, ValueError) as exc:
        raise FutuSessionEvidenceError("static identity listing date is invalid") from exc
    if parsed_listing_date.isoformat() != listing_date:
        raise FutuSessionEvidenceError("static identity listing date is not canonical")
    if delisting is not False:
        raise FutuSessionEvidenceError("static identity is delisted")
    for value, label in (
        (vendor_security_id, "vendor security ID"),
        (lot_size, "lot size"),
    ):
        if (
            not isinstance(value, str)
            or not value.isascii()
            or not value.isdecimal()
            or str(int(value)) != value
            or int(value) <= 0
        ):
            raise FutuSessionEvidenceError(f"static identity {label} is invalid")
    if (
        not isinstance(security_name, str)
        or not security_name
        or security_name.strip() != security_name
    ):
        raise FutuSessionEvidenceError("static identity security name is invalid")
    expected_exchange_type = _STATIC_IDENTITY_EXCHANGE_CODES[listing_mic]
    if (
        type(raw_market_code) is not int
        or raw_market_code != 11
        or type(raw_security_type) is not int
        or raw_security_type != 3
        or type(raw_exchange_type) is not int
        or raw_exchange_type != expected_exchange_type
    ):
        raise FutuSessionEvidenceError("static identity raw SDK qualifiers are invalid")
    values: tuple[str | bool, ...] = (
        vendor_security_market,
        vendor_security_code,
        security_type,
        listing_mic,
        listing_date,
        delisting,
        vendor_security_id,
        lot_size,
        security_name,
    )
    return FrozenMap(
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "protocol_id": 3202,
            "ordered_fields": tuple(
                FrozenMap({"field_id": field_id, "value": value})
                for field_id, value in zip(_STATIC_IDENTITY_FIELD_ORDER, values, strict=True)
            ),
            "raw_qualifiers": FrozenMap(
                {
                    "raw_exchange_type": raw_exchange_type,
                    "raw_market_code": raw_market_code,
                    "raw_security_type": raw_security_type,
                }
            ),
        }
    )


def futu_static_identity_projection_fingerprint(**values: Any) -> str:
    """Return the canonical fingerprint committed by the signed identity receipt."""
    return canonical_sha256(futu_static_identity_projection(**values))


@dataclass(frozen=True, slots=True)
class FutuPeerSessionEvidence:
    """Exact post-freeze quote/static evidence for one named, reviewed peer."""

    schema_version: str
    authority_set: FutuAuthoritySet
    authority_decision: FutuAuthorityDecision
    execution: FutuSidecarExecution
    daily_close: FutuDailyCloseAdapterResult
    price_blind_freeze: PriceBlindFreezeCompilationResult
    peer_session_id: str
    peer_session_fingerprint: str

    def __post_init__(self) -> None:
        values = _peer_session_manifest_values(
            authority_set=self.authority_set,
            authority_decision=self.authority_decision,
            execution=self.execution,
            daily_close=self.daily_close,
            price_blind_freeze=self.price_blind_freeze,
        )
        expected_id, expected_fingerprint = content_identity(
            "futu-peer-session:",
            values,
            object_id_field="peer_session_id",
            fingerprint_field="peer_session_fingerprint",
        )
        if (
            self.schema_version != FUTU_SCHEMA_VERSION
            or self.peer_session_id != expected_id
            or self.peer_session_fingerprint != expected_fingerprint
        ):
            raise FutuSessionEvidenceError("peer session identity is invalid")
        try:
            validate_futu_payload("futu-peer-session-evidence", self.to_dict())
        except FutuReceiptError as exc:
            raise FutuSessionEvidenceError(str(exc)) from exc

    @property
    def run_id(self) -> str:
        return self.authority_decision.run_id

    @property
    def issuer_id(self) -> str:
        return self.execution.bundle.issuer_id

    @property
    def security_id(self) -> str:
        return self.execution.bundle.security_id

    @property
    def fingerprint(self) -> str:
        return self.peer_session_fingerprint

    @property
    def price_blind_freeze_fingerprint(self) -> str:
        return self.price_blind_freeze.artifact.fingerprint

    def to_dict(self) -> dict[str, Any]:
        return {
            **_peer_session_manifest_values(
                authority_set=self.authority_set,
                authority_decision=self.authority_decision,
                execution=self.execution,
                daily_close=self.daily_close,
                price_blind_freeze=self.price_blind_freeze,
            ),
            "peer_session_id": self.peer_session_id,
            "peer_session_fingerprint": self.peer_session_fingerprint,
        }


def _observation_disposition_reason(observation: Any) -> tuple[str, str]:
    qualifiers = observation.qualifiers
    if observation.field_id == "availability" or qualifiers.get("reason_code") == (
        "official_no_data"
    ):
        return "unavailable", "official_no_data"
    if (
        observation.data_family == "corporate_actions"
        and observation.field_id == "current_common_shares"
    ):
        return "not_applicable", "vendor_not_supported"
    if (
        observation.data_family == "corporate_actions"
        and observation.field_id == "dividend_event"
    ):
        return "verified_context_only", "official_event_set_consistent"
    if (
        observation.data_family == "financial_statements"
        and observation.field_id.startswith("financial_structure:")
    ):
        return "not_applicable", "structure_metadata_only"
    if observation.data_family == "revenue_breakdown":
        return "not_applicable", "no_reviewed_official_segment_mapping"
    if (
        observation.data_family == "financial_statements"
        and observation.canonical_concept is None
    ):
        return "not_applicable", "unknown_noncritical_statement_field"
    if observation.canonical_concept is None:
        return "not_applicable", "vendor_context_only"
    return "not_applicable", "no_reviewed_official_mapping"


def build_futu_observation_dispositions(
    *,
    executions: tuple[FutuSidecarExecution, ...],
    cross_checks: tuple[FutuCrossCheckReceipt, ...],
    created_at: str,
) -> tuple[FutuObservationDispositionReceipt, ...]:
    """Cover every non-cross-checked pre-price vendor observation with a typed reason."""

    preprice = tuple(
        execution
        for execution in executions
        if execution.bundle.stage == "valuation_pre_price_verification"
    )
    if len(preprice) != 1:
        raise FutuSessionEvidenceError(
            "observation dispositions require one pre-price execution"
        )
    execution = preprice[0]
    crosschecked_ids = tuple(item.vendor_observation_id for item in cross_checks)
    if len(set(crosschecked_ids)) != len(crosschecked_ids):
        raise FutuSessionEvidenceError("one vendor observation has duplicate cross-checks")
    crosschecked = set(crosschecked_ids)
    response_by_fingerprint = {item.fingerprint: item for item in execution.responses}
    request_by_fingerprint = {item.fingerprint: item for item in execution.requests}
    dispositions: list[FutuObservationDispositionReceipt] = []
    for observation in execution.observations:
        if observation.source_role != "vendor_secondary":
            continue
        if observation.observation_id in crosschecked:
            continue
        if observation.comparison_eligible:
            raise FutuSessionEvidenceError(
                "comparison-eligible vendor observation lacks an exact cross-check"
            )
        response = response_by_fingerprint.get(observation.response_fingerprint)
        request = (
            request_by_fingerprint.get(response.request_fingerprint)
            if response is not None
            else None
        )
        if request is None:
            raise FutuSessionEvidenceError(
                "observation disposition cannot replay its request protocol"
            )
        status, reason_code = _observation_disposition_reason(observation)
        values: dict[str, Any] = {
            "schema_version": FUTU_SCHEMA_VERSION,
            "run_id": execution.bundle.run_id,
            "issuer_id": execution.bundle.issuer_id,
            "security_id": execution.bundle.security_id,
            "execution_bundle_id": execution.bundle.bundle_id,
            "execution_bundle_fingerprint": execution.bundle.fingerprint,
            "vendor_observation_id": observation.observation_id,
            "vendor_observation_fingerprint": observation.fingerprint,
            "protocol_id": request.protocol_id,
            "data_family": observation.data_family,
            "field_id": observation.field_id,
            "status": status,
            "reason_code": reason_code,
            "created_at": created_at,
        }
        receipt_id, receipt_fingerprint = content_identity(
            "futu-observation-disposition:",
            values,
            object_id_field="receipt_id",
            fingerprint_field="receipt_fingerprint",
        )
        dispositions.append(
            FutuObservationDispositionReceipt(
                receipt_id=receipt_id,
                receipt_fingerprint=receipt_fingerprint,
                **values,
            )
        )
    return tuple(dispositions)


@dataclass(frozen=True, slots=True)
class FutuMarketExecutionEvidence:
    """Exact two-stage checkpoint allowed to feed the fixed kernel market bridge."""

    schema_version: str
    authority_set: FutuAuthoritySet
    authority_decision: FutuAuthorityDecision
    executions: tuple[FutuSidecarExecution, ...]
    contract_graph: ContractGraph
    official_operands: tuple[OfficialEvidenceOperand, ...]
    cross_checks: tuple[FutuCrossCheckReceipt, ...]
    observation_dispositions: tuple[FutuObservationDispositionReceipt, ...]
    checkpoint_at: str
    evidence_id: str
    evidence_fingerprint: str
    _contract_graph_fingerprint: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "executions", tuple(self.executions))
        object.__setattr__(self, "official_operands", tuple(self.official_operands))
        object.__setattr__(self, "cross_checks", tuple(self.cross_checks))
        object.__setattr__(
            self,
            "observation_dispositions",
            tuple(self.observation_dispositions),
        )
        graph_fingerprint = _premarket_contract_graph_fingerprint(self.contract_graph)
        object.__setattr__(
            self,
            "_contract_graph_fingerprint",
            graph_fingerprint,
        )
        values = _market_execution_manifest_values(
            authority_set=self.authority_set,
            authority_decision=self.authority_decision,
            executions=self.executions,
            contract_graph_fingerprint=graph_fingerprint,
            official_operands=self.official_operands,
            cross_checks=self.cross_checks,
            observation_dispositions=self.observation_dispositions,
            checkpoint_at=self.checkpoint_at,
        )
        expected_id, expected_fingerprint = content_identity(
            "futu-market-execution:",
            values,
            object_id_field="evidence_id",
            fingerprint_field="evidence_fingerprint",
        )
        if (
            self.schema_version != FUTU_SCHEMA_VERSION
            or self.evidence_id != expected_id
            or self.evidence_fingerprint != expected_fingerprint
        ):
            raise FutuSessionEvidenceError("market-execution checkpoint identity is invalid")
        try:
            validate_futu_payload("futu-market-execution-evidence", self.to_dict())
        except FutuReceiptError as exc:
            raise FutuSessionEvidenceError(str(exc)) from exc

    @property
    def fingerprint(self) -> str:
        return self.evidence_fingerprint

    @property
    def contract_graph_fingerprint(self) -> str:
        return self._contract_graph_fingerprint

    def to_dict(self) -> dict[str, Any]:
        return {
            **_market_execution_manifest_values(
                authority_set=self.authority_set,
                authority_decision=self.authority_decision,
                executions=self.executions,
                contract_graph_fingerprint=self.contract_graph_fingerprint,
                official_operands=self.official_operands,
                cross_checks=self.cross_checks,
                observation_dispositions=self.observation_dispositions,
                checkpoint_at=self.checkpoint_at,
            ),
            "evidence_id": self.evidence_id,
            "evidence_fingerprint": self.evidence_fingerprint,
        }


def finalize_futu_market_execution_evidence(
    *,
    authority_set: FutuAuthoritySet,
    authority_decision: FutuAuthorityDecision,
    executions: tuple[FutuSidecarExecution, ...],
    contract_graph: ContractGraph,
    official_operands: tuple[OfficialEvidenceOperand, ...],
    cross_checks: tuple[FutuCrossCheckReceipt, ...],
    checkpoint_at: str,
    verifier: SignatureVerifier | None,
) -> FutuMarketExecutionEvidence:
    if len(executions) != 2:
        raise FutuSessionEvidenceError(
            "market-execution checkpoint requires exactly two stages"
        )
    security = authority_set.security_identity
    if security is not None and executions[0].bundle.stage == (
        "valuation_pre_price_verification"
    ):
        _validate_static_security_identity(executions[0], security=security)
    graph_fingerprint = _premarket_contract_graph_fingerprint(contract_graph)
    observation_dispositions = build_futu_observation_dispositions(
        executions=executions,
        cross_checks=cross_checks,
        created_at=checkpoint_at,
    )
    values = _market_execution_manifest_values(
        authority_set=authority_set,
        authority_decision=authority_decision,
        executions=executions,
        contract_graph_fingerprint=graph_fingerprint,
        official_operands=official_operands,
        cross_checks=cross_checks,
        observation_dispositions=observation_dispositions,
        checkpoint_at=checkpoint_at,
    )
    evidence_id, evidence_fingerprint = content_identity(
        "futu-market-execution:",
        values,
        object_id_field="evidence_id",
        fingerprint_field="evidence_fingerprint",
    )
    evidence = FutuMarketExecutionEvidence(
        schema_version=FUTU_SCHEMA_VERSION,
        authority_set=authority_set,
        authority_decision=authority_decision,
        executions=executions,
        contract_graph=contract_graph,
        official_operands=official_operands,
        cross_checks=cross_checks,
        observation_dispositions=observation_dispositions,
        checkpoint_at=checkpoint_at,
        evidence_id=evidence_id,
        evidence_fingerprint=evidence_fingerprint,
    )
    validate_futu_market_execution_evidence(evidence, verifier=verifier)
    return evidence


def validate_futu_market_execution_evidence(
    evidence: FutuMarketExecutionEvidence,
    *,
    verifier: SignatureVerifier | None,
) -> None:
    authority_set = evidence.authority_set
    if authority_set.runtime is not None:
        raise FutuSessionEvidenceError(
            "market-execution checkpoint cannot retain a completed runtime receipt"
        )
    legal = authority_set.legal
    account = authority_set.account
    supply = authority_set.supply_chain
    runtime_authorization = authority_set.runtime_authorization
    security = authority_set.security_identity
    if any(item is None for item in (legal, account, supply, runtime_authorization, security)):
        raise FutuSessionEvidenceError("market-execution authority set is incomplete")
    assert legal is not None
    assert account is not None
    assert supply is not None
    assert runtime_authorization is not None
    assert security is not None
    if runtime_authorization.authorized_security_codes[0] != security.vendor_code:
        raise FutuSessionEvidenceError(
            "market-execution target escaped the signed security-code plan"
        )
    if tuple(item.bundle.stage for item in evidence.executions) != _SESSION_STAGES[:2]:
        raise FutuSessionEvidenceError(
            "market-execution checkpoint must contain pre-price then market only"
        )
    requests = tuple(item for execution in evidence.executions for item in execution.requests)
    protocols = tuple(sorted({item.protocol_id for item in requests}))
    families = tuple(sorted({item.data_family for item in requests}))
    decision = evidence.authority_decision
    replayed_decision = evaluate_futu_authority(
        authority_set,
        verifier=verifier,
        now=_utc_datetime(decision.evaluated_at, "authority evaluated_at"),
        run_id=decision.run_id,
        policy_sha256=decision.policy_sha256,
        component_lock_sha256=decision.component_lock_sha256,
        required_data_families=families,
        required_protocol_ids=protocols,
        purpose="live_preflight",
    )
    if replayed_decision.to_dict() != decision.to_dict() or decision.status != "eligible":
        raise FutuSessionEvidenceError("market-execution live authority no longer replays")
    for execution in evidence.executions:
        if (
            execution.bundle.status != "complete"
            or execution.bundle.issues
            or execution.bundle.run_id != decision.run_id
            or execution.bundle.issuer_id != security.issuer_id
            or execution.bundle.security_id != security.security_id
        ):
            raise FutuSessionEvidenceError("market-execution bundle scope is invalid")
        validate_futu_execution_replay(
            execution,
            authority=decision,
            security_identity=security,
            supply_chain=supply,
        )
        _validate_required_stage_protocols(execution, mic=security.mic)
        if execution.bundle.stage == "valuation_pre_price_verification":
            _validate_static_security_identity(execution, security=security)
    responses = tuple(item for execution in evidence.executions for item in execution.responses)
    if len(requests) != len(responses) or not responses:
        raise FutuSessionEvidenceError("market-execution request/response graph is incomplete")
    if any(not item.qot_logined or item.trd_logined for item in responses):
        raise FutuSessionEvidenceError("market-execution response violates quote-only state")
    checkpoint = _utc_datetime(evidence.checkpoint_at, "checkpoint_at")
    if any(
        _utc_datetime(item.retrieved_at, "response retrieved_at") > checkpoint
        for item in responses
    ):
        raise FutuSessionEvidenceError("market checkpoint precedes a retained response")
    _validate_graph_crosschecks(
        graph=evidence.contract_graph,
        graph_fingerprint=evidence.contract_graph_fingerprint,
        executions=evidence.executions,
        official_operands=evidence.official_operands,
        cross_checks=evidence.cross_checks,
        observation_dispositions=evidence.observation_dispositions,
        disposition_created_at=evidence.checkpoint_at,
    )
    values = _market_execution_manifest_values(
        authority_set=authority_set,
        authority_decision=decision,
        executions=evidence.executions,
        contract_graph_fingerprint=evidence.contract_graph_fingerprint,
        official_operands=evidence.official_operands,
        cross_checks=evidence.cross_checks,
        observation_dispositions=evidence.observation_dispositions,
        checkpoint_at=evidence.checkpoint_at,
    )
    expected_id, expected_fingerprint = content_identity(
        "futu-market-execution:",
        values,
        object_id_field="evidence_id",
        fingerprint_field="evidence_fingerprint",
    )
    if evidence.evidence_id != expected_id or evidence.fingerprint != expected_fingerprint:
        raise FutuSessionEvidenceError("market-execution retained objects were rebound")


@dataclass(frozen=True, slots=True)
class FutuPeerEvidenceSet:
    """Five-to-fifteen independently reviewed peer quote sessions."""

    schema_version: str
    target_security_id: str
    price_blind_freeze: PriceBlindFreezeCompilationResult
    peers: tuple[FutuPeerSessionEvidence, ...]
    evidence_set_id: str
    evidence_set_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "peers", tuple(self.peers))
        values = _peer_set_manifest_values(
            target_security_id=self.target_security_id,
            price_blind_freeze=self.price_blind_freeze,
            peers=self.peers,
        )
        expected_id, expected_fingerprint = content_identity(
            "futu-peer-set:",
            values,
            object_id_field="evidence_set_id",
            fingerprint_field="evidence_set_fingerprint",
        )
        if (
            self.schema_version != FUTU_SCHEMA_VERSION
            or self.evidence_set_id != expected_id
            or self.evidence_set_fingerprint != expected_fingerprint
        ):
            raise FutuSessionEvidenceError("peer evidence-set identity is invalid")
        try:
            validate_futu_payload("futu-peer-evidence-set", self.to_dict())
        except FutuReceiptError as exc:
            raise FutuSessionEvidenceError(str(exc)) from exc

    @property
    def run_id(self) -> str:
        return self.peers[0].run_id

    @property
    def fingerprint(self) -> str:
        return self.evidence_set_fingerprint

    @property
    def price_blind_freeze_fingerprint(self) -> str:
        return self.price_blind_freeze.artifact.fingerprint

    def to_dict(self) -> dict[str, Any]:
        return {
            **_peer_set_manifest_values(
                target_security_id=self.target_security_id,
                price_blind_freeze=self.price_blind_freeze,
                peers=self.peers,
            ),
            "evidence_set_id": self.evidence_set_id,
            "evidence_set_fingerprint": self.evidence_set_fingerprint,
        }


def build_futu_peer_session_evidence(
    *,
    authority_set: FutuAuthoritySet,
    authority_decision: FutuAuthorityDecision,
    execution: FutuSidecarExecution,
    daily_close: FutuDailyCloseAdapterResult,
    price_blind_freeze: PriceBlindFreezeCompilationResult,
    verifier: SignatureVerifier | None,
) -> FutuPeerSessionEvidence:
    values = _peer_session_manifest_values(
        authority_set=authority_set,
        authority_decision=authority_decision,
        execution=execution,
        daily_close=daily_close,
        price_blind_freeze=price_blind_freeze,
    )
    peer_session_id, peer_session_fingerprint = content_identity(
        "futu-peer-session:",
        values,
        object_id_field="peer_session_id",
        fingerprint_field="peer_session_fingerprint",
    )
    peer = FutuPeerSessionEvidence(
        schema_version=FUTU_SCHEMA_VERSION,
        authority_set=authority_set,
        authority_decision=authority_decision,
        execution=execution,
        daily_close=daily_close,
        price_blind_freeze=price_blind_freeze,
        peer_session_id=peer_session_id,
        peer_session_fingerprint=peer_session_fingerprint,
    )
    validate_futu_peer_session_evidence(peer, verifier=verifier)
    return peer


def validate_futu_peer_session_evidence(
    peer: FutuPeerSessionEvidence,
    *,
    verifier: SignatureVerifier | None,
) -> None:
    authority_set = peer.authority_set
    if authority_set.runtime is not None:
        raise FutuSessionEvidenceError(
            "peer checkpoint cannot retain a completed runtime receipt"
        )
    security = authority_set.security_identity
    supply = authority_set.supply_chain
    runtime_authorization = authority_set.runtime_authorization
    if any(
        item is None
        for item in (
            authority_set.legal,
            authority_set.account,
            supply,
            runtime_authorization,
            security,
        )
    ):
        raise FutuSessionEvidenceError("peer session authority set is incomplete")
    assert security is not None
    assert supply is not None
    assert runtime_authorization is not None
    decision = peer.authority_decision
    replayed_decision = evaluate_futu_authority(
        authority_set,
        verifier=verifier,
        now=_utc_datetime(decision.evaluated_at, "peer authority evaluated_at"),
        run_id=decision.run_id,
        policy_sha256=decision.policy_sha256,
        component_lock_sha256=decision.component_lock_sha256,
        required_data_families=("market_price", "security_identity"),
        required_protocol_ids=(3103, 3202),
        purpose="live_preflight",
    )
    if replayed_decision.to_dict() != decision.to_dict() or decision.status != "eligible":
        raise FutuSessionEvidenceError("peer live authority no longer replays")
    execution = peer.execution
    if (
        execution.bundle.stage != "peer_comparable_reference"
        or execution.bundle.status != "complete"
        or execution.bundle.issues
        or execution.bundle.issuer_id != security.issuer_id
        or execution.bundle.security_id != security.security_id
    ):
        raise FutuSessionEvidenceError("peer execution scope is invalid")
    validate_futu_execution_replay(
        execution,
        authority=decision,
        security_identity=security,
        supply_chain=supply,
    )
    _validate_required_stage_protocols(execution, mic=security.mic)
    _validate_static_security_identity(execution, security=security)
    if tuple(item.protocol_id for item in execution.requests) != (3202, 3103):
        raise FutuSessionEvidenceError("peer execution must contain exact static and close calls")
    if len(execution.responses) != 2:
        raise FutuSessionEvidenceError("peer execution response cardinality is invalid")
    if any(
        item.price_blind_freeze_fingerprint != peer.price_blind_freeze_fingerprint
        for item in execution.requests
    ):
        raise FutuSessionEvidenceError("peer execution is rebound from another price-blind freeze")
    request = execution.requests[1]
    response = execution.responses[1]
    close_candidates = tuple(
        item
        for item in execution.observations
        if item.canonical_concept == "futu_unadjusted_daily_close_candidate"
    )
    if len(close_candidates) != 1:
        raise FutuSessionEvidenceError("peer execution lacks one exact daily close")
    replayed_close = adapt_futu_daily_close_to_market_reference(
        authority=decision,
        request=request,
        response=response,
        observation=close_candidates[0],
    )
    if replayed_close.to_dict() != peer.daily_close.to_dict():
        raise FutuSessionEvidenceError("peer daily-close adapter no longer replays")
    values = _peer_session_manifest_values(
        authority_set=authority_set,
        authority_decision=decision,
        execution=execution,
        daily_close=peer.daily_close,
        price_blind_freeze=peer.price_blind_freeze,
    )
    expected_id, expected_fingerprint = content_identity(
        "futu-peer-session:",
        values,
        object_id_field="peer_session_id",
        fingerprint_field="peer_session_fingerprint",
    )
    if peer.peer_session_id != expected_id or peer.fingerprint != expected_fingerprint:
        raise FutuSessionEvidenceError("peer session retained objects were rebound")


def build_futu_peer_evidence_set(
    *,
    target_security_id: str,
    price_blind_freeze: PriceBlindFreezeCompilationResult,
    peers: tuple[FutuPeerSessionEvidence, ...],
    verifier: SignatureVerifier | None,
) -> FutuPeerEvidenceSet:
    values = _peer_set_manifest_values(
        target_security_id=target_security_id,
        price_blind_freeze=price_blind_freeze,
        peers=peers,
    )
    evidence_set_id, evidence_set_fingerprint = content_identity(
        "futu-peer-set:",
        values,
        object_id_field="evidence_set_id",
        fingerprint_field="evidence_set_fingerprint",
    )
    evidence_set = FutuPeerEvidenceSet(
        schema_version=FUTU_SCHEMA_VERSION,
        target_security_id=target_security_id,
        price_blind_freeze=price_blind_freeze,
        peers=peers,
        evidence_set_id=evidence_set_id,
        evidence_set_fingerprint=evidence_set_fingerprint,
    )
    validate_futu_peer_evidence_set(evidence_set, verifier=verifier)
    return evidence_set


def validate_futu_peer_evidence_set(
    evidence_set: FutuPeerEvidenceSet,
    *,
    verifier: SignatureVerifier | None,
) -> None:
    peers = evidence_set.peers
    if not 5 <= len(peers) <= 15:
        raise FutuSessionEvidenceError("peer evidence set requires five to fifteen peers")
    if tuple(item.security_id for item in peers) != tuple(
        sorted(item.security_id for item in peers)
    ):
        raise FutuSessionEvidenceError("peer evidence sessions must use canonical security order")
    if len({item.security_id for item in peers}) != len(peers) or len(
        {item.issuer_id for item in peers}
    ) != len(peers):
        raise FutuSessionEvidenceError("peer evidence identities must be unique")
    if evidence_set.target_security_id in {item.security_id for item in peers}:
        raise FutuSessionEvidenceError("target security cannot be rebound as its own peer")
    if len({item.run_id for item in peers}) != 1:
        raise FutuSessionEvidenceError("peer evidence sessions must share one run")
    shared_receipts: set[tuple[str, str, str, str]] = set()
    for peer in peers:
        validate_futu_peer_session_evidence(peer, verifier=verifier)
        if peer.price_blind_freeze != evidence_set.price_blind_freeze:
            raise FutuSessionEvidenceError("peer evidence set mixes price-blind freezes")
        authority_set = peer.authority_set
        assert authority_set.legal is not None
        assert authority_set.account is not None
        assert authority_set.supply_chain is not None
        assert authority_set.runtime_authorization is not None
        shared_receipts.add(
            (
                authority_set.legal.fingerprint,
                authority_set.account.fingerprint,
                authority_set.supply_chain.fingerprint,
                authority_set.runtime_authorization.fingerprint,
            )
        )
    if len(shared_receipts) != 1:
        raise FutuSessionEvidenceError("peer sessions do not share one runtime authority")
    runtime_authorization = peers[0].authority_set.runtime_authorization
    assert runtime_authorization is not None
    peer_codes = tuple(
        peer.authority_set.security_identity.vendor_code  # type: ignore[union-attr]
        for peer in peers
    )
    if (
        len(runtime_authorization.authorized_security_codes) != len(peers) + 1
        or peer_codes != runtime_authorization.authorized_security_codes[1:]
    ):
        raise FutuSessionEvidenceError(
            "peer evidence identities escaped the signed security-code plan"
        )
    values = _peer_set_manifest_values(
        target_security_id=evidence_set.target_security_id,
        price_blind_freeze=evidence_set.price_blind_freeze,
        peers=peers,
    )
    expected_id, expected_fingerprint = content_identity(
        "futu-peer-set:",
        values,
        object_id_field="evidence_set_id",
        fingerprint_field="evidence_set_fingerprint",
    )
    if (
        evidence_set.evidence_set_id != expected_id
        or evidence_set.fingerprint != expected_fingerprint
    ):
        raise FutuSessionEvidenceError("peer evidence set retained objects were rebound")


@dataclass(frozen=True, slots=True)
class FutuSessionEvidence:
    """Exact in-memory evidence for one completed, isolated, quote-only session.

    ``to_dict`` intentionally emits a public receipt manifest, not licensed raw vendor
    payloads.  Exact replay uses the retained typed objects and private-CAS receipts.
    """

    schema_version: str
    authority_set: FutuAuthoritySet
    authority_decision: FutuAuthorityDecision
    market_execution_evidence: FutuMarketExecutionEvidence
    peer_evidence_set: FutuPeerEvidenceSet
    frozen_conclusion: FutuFrozenConclusionReceipt
    attested_finalization: FutuAttestedSessionFinalization
    executions: tuple[FutuSidecarExecution, ...]
    contract_graph: ContractGraph
    official_operands: tuple[OfficialEvidenceOperand, ...]
    cross_checks: tuple[FutuCrossCheckReceipt, ...]
    finalized_at: str
    session_id: str
    session_fingerprint: str

    def __post_init__(self) -> None:
        if self.schema_version != FUTU_SCHEMA_VERSION:
            raise FutuSessionEvidenceError("Futu session schema version is invalid")
        object.__setattr__(self, "executions", tuple(self.executions))
        object.__setattr__(self, "official_operands", tuple(self.official_operands))
        object.__setattr__(self, "cross_checks", tuple(self.cross_checks))
        _utc_datetime(self.finalized_at, "finalized_at")
        values = _session_manifest_values(
            authority_set=self.authority_set,
            authority_decision=self.authority_decision,
            market_execution_evidence=self.market_execution_evidence,
            peer_evidence_set=self.peer_evidence_set,
            frozen_conclusion=self.frozen_conclusion,
            attested_finalization=self.attested_finalization,
            executions=self.executions,
            contract_graph=self.contract_graph,
            official_operands=self.official_operands,
            cross_checks=self.cross_checks,
            finalized_at=self.finalized_at,
        )
        expected_id, expected_fingerprint = content_identity(
            "futu-session:",
            values,
            object_id_field="session_id",
            fingerprint_field="session_fingerprint",
        )
        if self.session_id != expected_id or self.session_fingerprint != expected_fingerprint:
            raise FutuSessionEvidenceError("Futu session identity does not bind exact evidence")
        try:
            validate_futu_payload("futu-session-evidence", self.to_dict())
        except FutuReceiptError as exc:
            raise FutuSessionEvidenceError(str(exc)) from exc

    @property
    def run_id(self) -> str:
        return self.authority_decision.run_id

    @property
    def issuer_id(self) -> str:
        return self.executions[0].bundle.issuer_id

    @property
    def security_id(self) -> str:
        return self.executions[0].bundle.security_id

    @property
    def status(self) -> str:
        return "complete"

    @property
    def fingerprint(self) -> str:
        return self.session_fingerprint

    def to_dict(self) -> dict[str, Any]:
        return {
            **_session_manifest_values(
                authority_set=self.authority_set,
                authority_decision=self.authority_decision,
                market_execution_evidence=self.market_execution_evidence,
                peer_evidence_set=self.peer_evidence_set,
                frozen_conclusion=self.frozen_conclusion,
                attested_finalization=self.attested_finalization,
                executions=self.executions,
                contract_graph=self.contract_graph,
                official_operands=self.official_operands,
                cross_checks=self.cross_checks,
                finalized_at=self.finalized_at,
            ),
            "session_id": self.session_id,
            "session_fingerprint": self.session_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class FutuMarketExecutionPublicationManifest(FutuContract):
    """Disk-safe projection for a replayed two-stage, pre-kernel checkpoint."""

    SCHEMA_NAME = "futu-market-execution-publication-manifest"
    schema_version: str
    manifest_id: str
    evidence_id: str
    evidence_fingerprint: str
    run_id: str
    issuer_id: str
    security_id: str
    checkpoint_at: str
    authority_decision_fingerprint: str
    authority_receipts: FrozenMap
    runtime_authorization_fingerprint: str
    contract_graph_fingerprint: str
    execution_bundles: tuple[FrozenMap, ...]
    requests: tuple[FrozenMap, ...]
    responses: tuple[FrozenMap, ...]
    observations: tuple[FrozenMap, ...]
    official_operands: tuple[FrozenMap, ...]
    cross_checks: tuple[FrozenMap, ...]
    observation_dispositions: tuple[FrozenMap, ...]
    cas_objects: tuple[FrozenMap, ...]
    global_state_guards: tuple[FrozenMap, ...]
    manifest_fingerprint: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        values = self.to_dict()
        expected_id, expected_fingerprint = content_identity(
            "futu-market-execution-publication:",
            values,
            object_id_field="manifest_id",
            fingerprint_field="manifest_fingerprint",
        )
        if self.manifest_id != expected_id or self.manifest_fingerprint != expected_fingerprint:
            raise FutuSessionEvidenceError(
                "market-execution publication identity does not bind complete content"
            )
        source_values = self.to_dict()
        source_values.pop("manifest_id")
        source_values.pop("manifest_fingerprint")
        source_id, source_fingerprint = content_identity(
            "futu-market-execution:",
            source_values,
            object_id_field="evidence_id",
            fingerprint_field="evidence_fingerprint",
        )
        if self.evidence_id != source_id or self.evidence_fingerprint != source_fingerprint:
            raise FutuSessionEvidenceError(
                "market-execution publication does not replay its source checkpoint"
            )
        _validate_market_publication_projection(self)

    @property
    def fingerprint(self) -> str:
        return self.manifest_fingerprint

    @property
    def source_evidence_fingerprint(self) -> str:
        return self.evidence_fingerprint

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> FutuMarketExecutionPublicationManifest:
        if not isinstance(payload, dict):
            raise FutuSessionEvidenceError(
                "market-execution publication manifest must be a JSON object"
            )
        try:
            return cls(**payload)
        except (FutuReceiptError, TypeError, ValueError) as exc:
            if isinstance(exc, FutuSessionEvidenceError):
                raise
            raise FutuSessionEvidenceError(
                "market-execution publication manifest reload failed"
            ) from exc


def build_futu_market_execution_publication_manifest(
    evidence: FutuMarketExecutionEvidence,
    *,
    verifier: SignatureVerifier | None,
) -> FutuMarketExecutionPublicationManifest:
    """Project a replayed pre-kernel checkpoint without claiming runtime completion."""
    validate_futu_market_execution_evidence(evidence, verifier=verifier)
    values = evidence.to_dict()
    manifest_id, manifest_fingerprint = content_identity(
        "futu-market-execution-publication:",
        values,
        object_id_field="manifest_id",
        fingerprint_field="manifest_fingerprint",
    )
    return FutuMarketExecutionPublicationManifest(
        manifest_id=manifest_id,
        manifest_fingerprint=manifest_fingerprint,
        **values,
    )


def validate_futu_market_execution_publication_manifest(
    manifest: FutuMarketExecutionPublicationManifest,
    *,
    source_evidence: FutuMarketExecutionEvidence | None = None,
    verifier: SignatureVerifier | None = None,
) -> None:
    reloaded = FutuMarketExecutionPublicationManifest.from_dict(manifest.to_dict())
    if reloaded.to_dict() != manifest.to_dict():  # pragma: no cover - constructor gate
        raise FutuSessionEvidenceError(
            "market-execution publication manifest is not byte stable"
        )
    if source_evidence is not None:
        expected = build_futu_market_execution_publication_manifest(
            source_evidence,
            verifier=verifier,
        )
        if expected.to_dict() != manifest.to_dict():
            raise FutuSessionEvidenceError(
                "market-execution publication manifest was rebound"
            )


@dataclass(frozen=True, slots=True)
class FutuObservationDispositionPublicationBundle(FutuContract):
    """Credential-free, typed bodies for every non-cross-checked observation."""

    SCHEMA_NAME = "futu-observation-disposition-publication-bundle"
    schema_version: str
    bundle_id: str
    evidence_id: str
    evidence_fingerprint: str
    run_id: str
    issuer_id: str
    security_id: str
    dispositions: tuple[FrozenMap, ...]
    bundle_fingerprint: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        values = self.to_dict()
        expected_id, expected_fingerprint = content_identity(
            "futu-observation-disposition-publication:",
            values,
            object_id_field="bundle_id",
            fingerprint_field="bundle_fingerprint",
        )
        if self.bundle_id != expected_id or self.bundle_fingerprint != expected_fingerprint:
            raise FutuSessionEvidenceError(
                "observation-disposition publication identity does not replay"
            )
        receipts = self.receipt_objects()
        receipt_ids = tuple(item.receipt_id for item in receipts)
        if len(receipt_ids) != len(set(receipt_ids)):
            raise FutuSessionEvidenceError(
                "observation-disposition publication members are not unique"
            )
        if any(
            item.run_id != self.run_id
            or item.issuer_id != self.issuer_id
            or item.security_id != self.security_id
            for item in receipts
        ):
            raise FutuSessionEvidenceError(
                "observation-disposition publication escapes its market execution scope"
            )

    @property
    def fingerprint(self) -> str:
        return self.bundle_fingerprint

    def receipt_objects(self) -> tuple[FutuObservationDispositionReceipt, ...]:
        try:
            return tuple(
                FutuObservationDispositionReceipt(**to_json_value(item))
                for item in self.dispositions
            )
        except (FutuReceiptError, TypeError, ValueError) as exc:
            raise FutuSessionEvidenceError(
                "observation-disposition publication contains an invalid receipt"
            ) from exc

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> FutuObservationDispositionPublicationBundle:
        if not isinstance(payload, dict):
            raise FutuSessionEvidenceError(
                "observation-disposition publication bundle must be a JSON object"
            )
        try:
            return cls(**payload)
        except (FutuReceiptError, TypeError, ValueError) as exc:
            if isinstance(exc, FutuSessionEvidenceError):
                raise
            raise FutuSessionEvidenceError(
                "observation-disposition publication bundle reload failed"
            ) from exc


def build_futu_observation_disposition_publication_bundle(
    evidence: FutuMarketExecutionEvidence,
    *,
    verifier: SignatureVerifier | None,
) -> FutuObservationDispositionPublicationBundle:
    validate_futu_market_execution_evidence(evidence, verifier=verifier)
    dispositions = tuple(item.to_dict() for item in evidence.observation_dispositions)
    values: dict[str, Any] = {
        "schema_version": FUTU_SCHEMA_VERSION,
        "evidence_id": evidence.evidence_id,
        "evidence_fingerprint": evidence.evidence_fingerprint,
        "run_id": evidence.authority_decision.run_id,
        "issuer_id": evidence.executions[0].bundle.issuer_id,
        "security_id": evidence.executions[0].bundle.security_id,
        "dispositions": list(dispositions),
    }
    bundle_id, bundle_fingerprint = content_identity(
        "futu-observation-disposition-publication:",
        values,
        object_id_field="bundle_id",
        fingerprint_field="bundle_fingerprint",
    )
    return FutuObservationDispositionPublicationBundle(
        bundle_id=bundle_id,
        bundle_fingerprint=bundle_fingerprint,
        **values,
    )


def validate_futu_observation_disposition_publication_bundle(
    bundle: FutuObservationDispositionPublicationBundle,
    *,
    market_manifest: FutuMarketExecutionPublicationManifest,
) -> None:
    reloaded = FutuObservationDispositionPublicationBundle.from_dict(bundle.to_dict())
    if reloaded.to_dict() != bundle.to_dict():  # pragma: no cover - constructor gate
        raise FutuSessionEvidenceError(
            "observation-disposition publication bundle is not byte stable"
        )
    receipts = reloaded.receipt_objects()
    references = tuple(
        {
            "object_id": item.receipt_id,
            "fingerprint": item.fingerprint,
        }
        for item in receipts
    )
    if (
        bundle.evidence_id != market_manifest.evidence_id
        or bundle.evidence_fingerprint != market_manifest.evidence_fingerprint
        or bundle.run_id != market_manifest.run_id
        or bundle.issuer_id != market_manifest.issuer_id
        or bundle.security_id != market_manifest.security_id
        or references
        != tuple(
            to_json_value(item) for item in market_manifest.observation_dispositions
        )
    ):
        raise FutuSessionEvidenceError(
            "observation-disposition publication bundle was rebound from market evidence"
        )


@dataclass(frozen=True, slots=True)
class FutuPartialSessionPublicationManifest(FutuContract):
    """Disk-safe target+peer runtime completion that makes no post-context claim."""

    SCHEMA_NAME = "futu-partial-session-publication-manifest"
    schema_version: str
    manifest_id: str
    partial_session_id: str
    partial_session_fingerprint: str
    run_id: str
    issuer_id: str
    security_id: str
    status: str
    finalized_at: str
    authority_decision_fingerprint: str
    authority_receipts: FrozenMap
    runtime_authorization_fingerprint: str
    runtime_receipt_fingerprint: str
    attested_finalization_fingerprint: str
    skipped_conditional_conclusion: FrozenMap
    sidecar_boot_attestation: FrozenMap
    sidecar_execution_attestation: FrozenMap
    contract_graph_fingerprint: str
    market_execution_evidence: FrozenMap
    peer_evidence_set: FrozenMap
    execution_bundles: tuple[FrozenMap, ...]
    peer_sessions: tuple[FrozenMap, ...]
    requests: tuple[FrozenMap, ...]
    responses: tuple[FrozenMap, ...]
    observations: tuple[FrozenMap, ...]
    official_operands: tuple[FrozenMap, ...]
    cross_checks: tuple[FrozenMap, ...]
    cas_objects: tuple[FrozenMap, ...]
    global_state_guards: tuple[FrozenMap, ...]
    manifest_fingerprint: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        values = self.to_dict()
        expected_id, expected_fingerprint = content_identity(
            "futu-partial-session-publication:",
            values,
            object_id_field="manifest_id",
            fingerprint_field="manifest_fingerprint",
        )
        if self.manifest_id != expected_id or self.manifest_fingerprint != expected_fingerprint:
            raise FutuSessionEvidenceError(
                "partial-session publication identity does not bind complete content"
            )
        source_values = self.to_dict()
        source_values.pop("manifest_id")
        source_values.pop("manifest_fingerprint")
        source_id, source_fingerprint = content_identity(
            "futu-partial-session:",
            source_values,
            object_id_field="partial_session_id",
            fingerprint_field="partial_session_fingerprint",
        )
        if (
            self.partial_session_id != source_id
            or self.partial_session_fingerprint != source_fingerprint
        ):
            raise FutuSessionEvidenceError(
                "partial-session publication does not replay its source identity"
            )
        _validate_partial_publication_projection(self)

    @property
    def fingerprint(self) -> str:
        return self.manifest_fingerprint

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> FutuPartialSessionPublicationManifest:
        if not isinstance(payload, dict):
            raise FutuSessionEvidenceError(
                "partial-session publication manifest must be a JSON object"
            )
        try:
            return cls(**payload)
        except (FutuReceiptError, TypeError, ValueError) as exc:
            if isinstance(exc, FutuSessionEvidenceError):
                raise
            raise FutuSessionEvidenceError(
                "partial-session publication manifest reload failed"
            ) from exc


def build_futu_partial_session_publication_manifest(
    *,
    market_execution_evidence: FutuMarketExecutionEvidence,
    peer_evidence_set: FutuPeerEvidenceSet,
    attested_finalization: FutuAttestedSessionFinalization,
    verifier: SignatureVerifier,
) -> FutuPartialSessionPublicationManifest:
    """Project a signed target+peer completion without inventing a post stage."""
    values = _partial_session_manifest_values(
        market_execution_evidence=market_execution_evidence,
        peer_evidence_set=peer_evidence_set,
        attested_finalization=attested_finalization,
        verifier=verifier,
    )
    partial_session_id, partial_session_fingerprint = content_identity(
        "futu-partial-session:",
        values,
        object_id_field="partial_session_id",
        fingerprint_field="partial_session_fingerprint",
    )
    values.update(
        {
            "partial_session_id": partial_session_id,
            "partial_session_fingerprint": partial_session_fingerprint,
        }
    )
    manifest_id, manifest_fingerprint = content_identity(
        "futu-partial-session-publication:",
        values,
        object_id_field="manifest_id",
        fingerprint_field="manifest_fingerprint",
    )
    return FutuPartialSessionPublicationManifest(
        manifest_id=manifest_id,
        manifest_fingerprint=manifest_fingerprint,
        **values,
    )


def validate_futu_partial_session_publication_manifest(
    manifest: FutuPartialSessionPublicationManifest,
    *,
    market_execution_evidence: FutuMarketExecutionEvidence | None = None,
    peer_evidence_set: FutuPeerEvidenceSet | None = None,
    attested_finalization: FutuAttestedSessionFinalization | None = None,
    verifier: SignatureVerifier | None = None,
) -> None:
    reloaded = FutuPartialSessionPublicationManifest.from_dict(manifest.to_dict())
    if reloaded.to_dict() != manifest.to_dict():  # pragma: no cover - constructor gate
        raise FutuSessionEvidenceError(
            "partial-session publication manifest is not byte stable"
        )
    sources = (
        market_execution_evidence,
        peer_evidence_set,
        attested_finalization,
    )
    if any(item is not None for item in sources):
        if any(item is None for item in sources) or verifier is None:
            raise FutuSessionEvidenceError(
                "partial-session source replay requires all exact typed authorities"
            )
        assert market_execution_evidence is not None
        assert peer_evidence_set is not None
        assert attested_finalization is not None
        expected = build_futu_partial_session_publication_manifest(
            market_execution_evidence=market_execution_evidence,
            peer_evidence_set=peer_evidence_set,
            attested_finalization=attested_finalization,
            verifier=verifier,
        )
        if expected.to_dict() != manifest.to_dict():
            raise FutuSessionEvidenceError(
                "partial-session publication manifest was rebound"
            )


@dataclass(frozen=True, slots=True)
class FutuSessionPublicationManifest(FutuContract):
    """Disk-safe typed projection of a replay-validated live session."""

    SCHEMA_NAME = "futu-session-publication-manifest"
    schema_version: str
    manifest_id: str
    session_id: str
    session_fingerprint: str
    run_id: str
    issuer_id: str
    security_id: str
    status: str
    finalized_at: str
    authority_decision_fingerprint: str
    authority_receipts: FrozenMap
    runtime_authorization_fingerprint: str
    runtime_receipt_fingerprint: str
    attested_finalization_fingerprint: str
    sidecar_boot_attestation: FrozenMap
    sidecar_execution_attestation: FrozenMap
    contract_graph_fingerprint: str
    market_execution_evidence: FrozenMap
    peer_evidence_set: FrozenMap
    frozen_conclusion: FrozenMap
    execution_bundles: tuple[FrozenMap, ...]
    peer_sessions: tuple[FrozenMap, ...]
    requests: tuple[FrozenMap, ...]
    responses: tuple[FrozenMap, ...]
    observations: tuple[FrozenMap, ...]
    official_operands: tuple[FrozenMap, ...]
    cross_checks: tuple[FrozenMap, ...]
    cas_objects: tuple[FrozenMap, ...]
    global_state_guards: tuple[FrozenMap, ...]
    manifest_fingerprint: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        values = self.to_dict()
        expected_id, expected_fingerprint = content_identity(
            "futu-session-publication:",
            values,
            object_id_field="manifest_id",
            fingerprint_field="manifest_fingerprint",
        )
        if self.manifest_id != expected_id or self.manifest_fingerprint != expected_fingerprint:
            raise FutuSessionEvidenceError(
                "Futu publication manifest identity does not bind its complete content"
            )
        if self.status != "complete":
            raise FutuSessionEvidenceError("only a complete Futu session may be published")
        if len(self.execution_bundles) != len(_SESSION_STAGES):
            raise FutuSessionEvidenceError("publication manifest must bind all Futu stages")
        if not 5 <= len(self.peer_sessions) <= 15:
            raise FutuSessionEvidenceError(
                "publication manifest must bind five to fifteen peer sessions"
            )
        session_values = self.to_dict()
        session_values.pop("manifest_id")
        session_values.pop("manifest_fingerprint")
        session_values.pop("session_id")
        session_values.pop("session_fingerprint")
        expected_session_id, expected_session_fingerprint = content_identity(
            "futu-session:",
            session_values,
            object_id_field="session_id",
            fingerprint_field="session_fingerprint",
        )
        if (
            self.session_id != expected_session_id
            or self.session_fingerprint != expected_session_fingerprint
        ):
            raise FutuSessionEvidenceError(
                "publication manifest does not replay its source session identity"
            )
        _validate_publication_projection(self)

    @property
    def fingerprint(self) -> str:
        return self.manifest_fingerprint

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> FutuSessionPublicationManifest:
        """Strictly reload a closed manifest; unknown or rebound fields are rejected."""
        if not isinstance(payload, dict):
            raise FutuSessionEvidenceError("Futu publication manifest must be a JSON object")
        try:
            return cls(**payload)
        except (FutuReceiptError, TypeError, ValueError) as exc:
            if isinstance(exc, FutuSessionEvidenceError):
                raise
            raise FutuSessionEvidenceError("Futu publication manifest reload failed") from exc


def build_futu_session_publication_manifest(
    session: FutuSessionEvidence,
    *,
    verifier: SignatureVerifier | None,
) -> FutuSessionPublicationManifest:
    """Derive the only publishable Futu object after exact live-session replay."""
    validate_futu_session_evidence_replay(session, verifier=verifier)
    values = session.to_dict()
    values.pop("session_id")
    values.pop("session_fingerprint")
    values["session_id"] = session.session_id
    values["session_fingerprint"] = session.session_fingerprint
    manifest_id, manifest_fingerprint = content_identity(
        "futu-session-publication:",
        values,
        object_id_field="manifest_id",
        fingerprint_field="manifest_fingerprint",
    )
    return FutuSessionPublicationManifest(
        manifest_id=manifest_id,
        manifest_fingerprint=manifest_fingerprint,
        **values,
    )


def validate_futu_session_publication_manifest(
    manifest: FutuSessionPublicationManifest,
    *,
    source_session: FutuSessionEvidence | None = None,
    verifier: SignatureVerifier | None = None,
) -> None:
    """Validate content identity and, when retained, its exact source session."""
    reloaded = FutuSessionPublicationManifest.from_dict(manifest.to_dict())
    if reloaded.to_dict() != manifest.to_dict():  # pragma: no cover - immutable constructor gate
        raise FutuSessionEvidenceError("Futu publication manifest is not byte stable")
    if source_session is not None:
        expected = build_futu_session_publication_manifest(
            source_session,
            verifier=verifier,
        )
        if expected.to_dict() != manifest.to_dict():
            raise FutuSessionEvidenceError("publication manifest is rebound from another session")


def finalize_futu_session_evidence(
    *,
    authority_set: FutuAuthoritySet,
    authority_decision: FutuAuthorityDecision,
    market_execution_evidence: FutuMarketExecutionEvidence,
    peer_evidence_set: FutuPeerEvidenceSet,
    frozen_conclusion: FutuFrozenConclusionReceipt,
    attested_finalization: FutuAttestedSessionFinalization,
    post_valuation_execution: FutuSidecarExecution,
    finalized_at: str,
    verifier: SignatureVerifier | None,
) -> FutuSessionEvidence:
    """Extend the exact pre-kernel checkpoint after peer and post-context calls."""
    executions = (*market_execution_evidence.executions, post_valuation_execution)
    contract_graph = market_execution_evidence.contract_graph
    official_operands = market_execution_evidence.official_operands
    cross_checks = market_execution_evidence.cross_checks
    values = _session_manifest_values(
        authority_set=authority_set,
        authority_decision=authority_decision,
        market_execution_evidence=market_execution_evidence,
        peer_evidence_set=peer_evidence_set,
        frozen_conclusion=frozen_conclusion,
        attested_finalization=attested_finalization,
        executions=executions,
        contract_graph=contract_graph,
        official_operands=official_operands,
        cross_checks=cross_checks,
        finalized_at=finalized_at,
    )
    session_id, session_fingerprint = content_identity(
        "futu-session:",
        values,
        object_id_field="session_id",
        fingerprint_field="session_fingerprint",
    )
    session = FutuSessionEvidence(
        schema_version=FUTU_SCHEMA_VERSION,
        authority_set=authority_set,
        authority_decision=authority_decision,
        market_execution_evidence=market_execution_evidence,
        peer_evidence_set=peer_evidence_set,
        frozen_conclusion=frozen_conclusion,
        attested_finalization=attested_finalization,
        executions=executions,
        contract_graph=contract_graph,
        official_operands=official_operands,
        cross_checks=cross_checks,
        finalized_at=finalized_at,
        session_id=session_id,
        session_fingerprint=session_fingerprint,
    )
    validate_futu_session_evidence_replay(session, verifier=verifier)
    return session


def validate_futu_session_evidence_replay(
    session: FutuSessionEvidence,
    *,
    verifier: SignatureVerifier | None,
) -> None:
    """Replay the pre-kernel checkpoint, peer calls, post-context, and runtime."""
    if (
        type(session.market_execution_evidence) is not FutuMarketExecutionEvidence
        or type(session.peer_evidence_set) is not FutuPeerEvidenceSet
        or type(session.frozen_conclusion) is not FutuFrozenConclusionReceipt
        or type(session.attested_finalization) is not FutuAttestedSessionFinalization
    ):
        raise FutuSessionEvidenceError("session requires exact checkpoint and peer evidence types")
    authority_set = session.authority_set
    legal = authority_set.legal
    account = authority_set.account
    supply = authority_set.supply_chain
    runtime_authorization = authority_set.runtime_authorization
    runtime = authority_set.runtime
    security = authority_set.security_identity
    if any(
        item is None
        for item in (legal, account, supply, runtime_authorization, runtime, security)
    ):
        raise FutuSessionEvidenceError("complete session lacks an exact authority receipt")
    assert legal is not None
    assert account is not None
    assert supply is not None
    assert runtime_authorization is not None
    assert runtime is not None
    assert security is not None
    if (
        type(session.attested_finalization) is not FutuAttestedSessionFinalization
        or session.attested_finalization.runtime_receipt != runtime
        or runtime.runtime_authorization_fingerprint != runtime_authorization.fingerprint
        or runtime.request_plan_fingerprint != runtime_authorization.request_plan_fingerprint
        or runtime.authorization_window_seconds
        != runtime_authorization.authorization_window_seconds
    ):
        raise FutuSessionEvidenceError("Futu session lacks its signed sidecar finalization")

    decision = session.authority_decision
    market = session.market_execution_evidence
    peers = session.peer_evidence_set
    conclusion = session.frozen_conclusion
    validate_futu_market_execution_evidence(market, verifier=verifier)
    validate_futu_peer_evidence_set(peers, verifier=verifier)
    conclusion_run = conclusion.composite_valuation._run_result
    if (
        type(conclusion_run) is not ValuationRunResult
        or conclusion_run.status != "completed"
        or conclusion_run.input_receipt.expected_freeze != peers.price_blind_freeze
        or conclusion_run.input_receipt.price_blind_input_fingerprint
        != peers.price_blind_freeze_fingerprint
    ):
        raise FutuSessionEvidenceError(
            "proprietary conclusion is bound to another exact price-blind run"
        )
    market_authority = market.authority_set
    if (
        decision.status != "eligible"
        or decision.evaluation_scope != "live_preflight"
        or market.authority_decision != decision
        or market_authority.runtime is not None
        or market_authority.legal != legal
        or market_authority.account != account
        or market_authority.supply_chain != supply
        or market_authority.runtime_authorization != runtime_authorization
        or market_authority.security_identity != security
        or peers.run_id != decision.run_id
        or peers.target_security_id != security.security_id
        or peers.price_blind_freeze.artifact.payload["issuer_id"] != security.issuer_id
        or conclusion.run_id != decision.run_id
        or conclusion.issuer_id != security.issuer_id
        or conclusion.security_id != security.security_id
    ):
        raise FutuSessionEvidenceError(
            "completed session does not exactly extend its pre-kernel authority"
        )
    stages = tuple(execution.bundle.stage for execution in session.executions)
    if stages != _SESSION_STAGES:
        raise FutuSessionEvidenceError("Futu session stages are missing, duplicated, or reordered")
    if (
        session.executions[:2] != market.executions
        or session.contract_graph != market.contract_graph
        or session.official_operands != market.official_operands
        or session.cross_checks != market.cross_checks
    ):
        raise FutuSessionEvidenceError("completed session rebound its pre-kernel evidence")
    post_execution = session.executions[2]
    if not post_execution.requests or not post_execution.responses:
        raise FutuSessionEvidenceError("completed session lacks post-valuation live evidence")

    shared_authority = (legal, account, supply, runtime_authorization)
    for peer in peers.peers:
        peer_authority = peer.authority_set
        if (
            peer_authority.runtime is not None
            or (
                peer_authority.legal,
                peer_authority.account,
                peer_authority.supply_chain,
                peer_authority.runtime_authorization,
            )
            != shared_authority
        ):
            raise FutuSessionEvidenceError("peer evidence escaped the target runtime authority")

    ordered_executions = (
        session.executions[0],
        session.executions[1],
        *(peer.execution for peer in peers.peers),
        post_execution,
    )
    if session.attested_finalization.runtime_receipt != runtime:
        raise FutuSessionEvidenceError(
            "completed runtime is not the signed sidecar finalization receipt"
        )
    try:
        validate_futu_attested_session_finalization(
            session.attested_finalization,
            expected_executions=ordered_executions,
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            verifier=verifier,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise FutuSessionEvidenceError(
            "signed sidecar finalization no longer replays"
        ) from exc
    for execution in session.executions:
        if execution.bundle.status != "complete" or execution.bundle.issues:
            raise FutuSessionEvidenceError("complete session contains an incomplete execution")
        if (
            execution.bundle.run_id != decision.run_id
            or execution.bundle.issuer_id != security.issuer_id
            or execution.bundle.security_id != security.security_id
        ):
            raise FutuSessionEvidenceError("execution identity is outside the session scope")
        _validate_required_stage_protocols(execution, mic=security.mic)
        validate_futu_execution_replay(
            execution,
            authority=decision,
            security_identity=security,
            supply_chain=supply,
        )

    all_requests = tuple(
        request for execution in ordered_executions for request in execution.requests
    )
    all_responses = tuple(
        response for execution in ordered_executions for response in execution.responses
    )
    all_observations = tuple(
        observation for execution in ordered_executions for observation in execution.observations
    )
    if not all_requests or len(all_requests) != len(all_responses):
        raise FutuSessionEvidenceError("session request/response cardinality is incomplete")
    for values, label in (
        (tuple(item.request_id for item in all_requests), "request"),
        (tuple(item.response_id for item in all_responses), "response"),
        (tuple(item.observation_id for item in all_observations), "observation"),
    ):
        if len(set(values)) != len(values):
            raise FutuSessionEvidenceError(f"session repeats a {label} identity")
    response_by_request = {item.request_id: item for item in all_responses}
    for request in all_requests:
        response = response_by_request.get(request.request_id)
        if response is None or response.request_fingerprint != request.fingerprint:
            raise FutuSessionEvidenceError("session response graph is incomplete")
        if _utc_datetime(response.retrieved_at, "response retrieved_at") < _utc_datetime(
            request.request_started_at, "request_started_at"
        ):
            raise FutuSessionEvidenceError("session response predates its request")

    required_protocols = tuple(sorted({item.protocol_id for item in all_requests}))
    required_families = tuple(sorted({item.data_family for item in all_requests}))
    preflight = evaluate_futu_authority(
        authority_set,
        verifier=verifier,
        now=_utc_datetime(decision.evaluated_at, "authority evaluated_at"),
        run_id=decision.run_id,
        policy_sha256=decision.policy_sha256,
        component_lock_sha256=decision.component_lock_sha256,
        required_data_families=required_families,
        required_protocol_ids=required_protocols,
        purpose="live_preflight",
    )
    if preflight.to_dict() != decision.to_dict():
        raise FutuSessionEvidenceError("live preflight decision no longer replays")
    replay_authority = evaluate_futu_authority(
        authority_set,
        verifier=verifier,
        now=_utc_datetime(runtime.issued_at, "runtime issued_at"),
        run_id=decision.run_id,
        policy_sha256=decision.policy_sha256,
        component_lock_sha256=decision.component_lock_sha256,
        required_data_families=required_families,
        required_protocol_ids=required_protocols,
        purpose="replay_only",
    )
    if replay_authority.status != "eligible":
        raise FutuSessionEvidenceError("completed runtime receipt is not replay-eligible")

    request_times = tuple(
        _utc_datetime(item.request_started_at, "request_started_at") for item in all_requests
    )
    response_times = tuple(
        _utc_datetime(item.retrieved_at, "response retrieved_at") for item in all_responses
    )
    if request_times != tuple(sorted(request_times)):
        raise FutuSessionEvidenceError("session request chronology is reordered")
    checkpoint = _utc_datetime(market.checkpoint_at, "market checkpoint_at")
    peer_requests = tuple(
        item for peer in peers.peers for item in peer.execution.requests
    )
    peer_responses = tuple(
        item for peer in peers.peers for item in peer.execution.responses
    )
    post_requests = post_execution.requests
    if any(
        _utc_datetime(item.request_started_at, "peer request_started_at") <= checkpoint
        for item in peer_requests
    ) or any(
        _utc_datetime(item.request_started_at, "post request_started_at") <= checkpoint
        for item in post_requests
    ):
        raise FutuSessionEvidenceError("peer or post-context calls preceded the market checkpoint")
    latest_peer_response = max(
        _utc_datetime(item.retrieved_at, "peer response retrieved_at")
        for item in peer_responses
    )
    conclusion_frozen_at = _utc_datetime(
        conclusion.conclusion_frozen_at, "conclusion_frozen_at"
    )
    if latest_peer_response >= conclusion_frozen_at or any(
        _utc_datetime(item.request_started_at, "post request_started_at")
        <= conclusion_frozen_at
        for item in post_requests
    ):
        raise FutuSessionEvidenceError(
            "post-context calls are not strictly after the proprietary conclusion freeze"
        )
    if any(
        item.frozen_conclusion_receipt_id != conclusion.receipt_id
        or item.frozen_conclusion_fingerprint != conclusion.fingerprint
        for item in post_requests
    ):
        raise FutuSessionEvidenceError("post-context request rebound the frozen conclusion")
    post_freezes = {item.price_blind_freeze_fingerprint for item in post_requests}
    if post_freezes != {peers.price_blind_freeze_fingerprint}:
        raise FutuSessionEvidenceError("post-context and peer calls bind different freezes")

    started = _utc_datetime(runtime.started_at, "runtime started_at")
    ended = _utc_datetime(runtime.ended_at, "runtime ended_at")
    evaluated = _utc_datetime(decision.evaluated_at, "authority evaluated_at")
    finalized = _utc_datetime(session.finalized_at, "finalized_at")
    issued = _utc_datetime(runtime.issued_at, "runtime issued_at")
    expires = _utc_datetime(runtime.expires_at, "runtime expires_at")
    if not (
        started <= evaluated <= request_times[0]
        and all(started <= item <= ended for item in (*request_times, *response_times))
        and ended <= issued <= finalized < expires
    ):
        raise FutuSessionEvidenceError("completed session chronology is invalid")

    checkpoints = runtime.checkpoints
    if len(checkpoints) != 2 + (2 * len(all_responses)):
        raise FutuSessionEvidenceError("runtime receipt omits request GlobalState checkpoints")
    if checkpoints[0]["checkpoint"] != "startup" or checkpoints[-1]["checkpoint"] != "pre_shutdown":
        raise FutuSessionEvidenceError("runtime receipt boundary checkpoints are invalid")
    if (
        checkpoints[0]["global_state_response_fingerprint"]
        != account.global_state_response_fingerprint
    ):
        raise FutuSessionEvidenceError("account entitlement is not bound to runtime startup")
    expected_middle: list[dict[str, Any]] = []
    for response in all_responses:
        if not response.qot_logined or response.trd_logined:
            raise FutuSessionEvidenceError("response violates quote-only login invariants")
        expected_middle.extend(
            (
                {
                    "checkpoint": "pre_request",
                    "serial_number": response.pre_global_state_serial_number,
                    "global_state_request_fingerprint": (
                        response.pre_global_state_request_fingerprint
                    ),
                    "global_state_response_fingerprint": (
                        response.pre_global_state_response_fingerprint
                    ),
                },
                {
                    "checkpoint": "post_request",
                    "serial_number": response.post_global_state_serial_number,
                    "global_state_request_fingerprint": (
                        response.post_global_state_request_fingerprint
                    ),
                    "global_state_response_fingerprint": (
                        response.post_global_state_response_fingerprint
                    ),
                },
            )
        )
    for runtime_checkpoint, expected in zip(
        checkpoints[1:-1], expected_middle, strict=True
    ):
        if any(runtime_checkpoint[key] != value for key, value in expected.items()):
            raise FutuSessionEvidenceError("runtime GlobalState checkpoint was rebound")
    if any(not item["qot_logined"] or item["trd_logined"] for item in checkpoints):
        raise FutuSessionEvidenceError("runtime checkpoint violates quote-only login")
    serials = tuple(item["serial_number"] for item in checkpoints)
    if serials != tuple(sorted(serials)) or len(set(serials)) != len(serials):
        raise FutuSessionEvidenceError("runtime GlobalState sequence is not exact")

    expected_manifest = _session_manifest_values(
        authority_set=authority_set,
        authority_decision=decision,
        market_execution_evidence=market,
        peer_evidence_set=peers,
        frozen_conclusion=conclusion,
        attested_finalization=session.attested_finalization,
        executions=session.executions,
        contract_graph=session.contract_graph,
        official_operands=session.official_operands,
        cross_checks=session.cross_checks,
        finalized_at=session.finalized_at,
    )
    expected_id, expected_fingerprint = content_identity(
        "futu-session:",
        expected_manifest,
        object_id_field="session_id",
        fingerprint_field="session_fingerprint",
    )
    if session.session_id != expected_id or session.session_fingerprint != expected_fingerprint:
        raise FutuSessionEvidenceError("session manifest no longer binds exact retained objects")
    try:
        validate_futu_payload("futu-session-evidence", session.to_dict())
    except FutuReceiptError as exc:
        raise FutuSessionEvidenceError(str(exc)) from exc


def _partial_session_manifest_values(
    *,
    market_execution_evidence: FutuMarketExecutionEvidence,
    peer_evidence_set: FutuPeerEvidenceSet,
    attested_finalization: FutuAttestedSessionFinalization,
    verifier: SignatureVerifier,
) -> dict[str, Any]:
    if (
        type(market_execution_evidence) is not FutuMarketExecutionEvidence
        or type(peer_evidence_set) is not FutuPeerEvidenceSet
        or type(attested_finalization) is not FutuAttestedSessionFinalization
    ):
        raise FutuSessionEvidenceError(
            "partial-session publication requires exact typed live authorities"
        )
    validate_futu_market_execution_evidence(
        market_execution_evidence,
        verifier=verifier,
    )
    validate_futu_peer_evidence_set(peer_evidence_set, verifier=verifier)
    authority_set = market_execution_evidence.authority_set
    legal = authority_set.legal
    account = authority_set.account
    supply = authority_set.supply_chain
    runtime_authorization = authority_set.runtime_authorization
    security = authority_set.security_identity
    if authority_set.runtime is not None or any(
        item is None
        for item in (legal, account, supply, runtime_authorization, security)
    ):
        raise FutuSessionEvidenceError(
            "partial-session source must retain an in-progress live authority"
        )
    assert legal is not None
    assert account is not None
    assert supply is not None
    assert runtime_authorization is not None
    assert security is not None
    decision = market_execution_evidence.authority_decision
    if (
        peer_evidence_set.run_id != decision.run_id
        or peer_evidence_set.target_security_id != security.security_id
        or peer_evidence_set.price_blind_freeze.artifact.payload["issuer_id"]
        != security.issuer_id
    ):
        raise FutuSessionEvidenceError(
            "partial-session peer evidence is bound to another target"
        )
    shared_authority = (legal, account, supply, runtime_authorization)
    for peer in peer_evidence_set.peers:
        peer_authority = peer.authority_set
        if (
            peer_authority.runtime is not None
            or (
                peer_authority.legal,
                peer_authority.account,
                peer_authority.supply_chain,
                peer_authority.runtime_authorization,
            )
            != shared_authority
        ):
            raise FutuSessionEvidenceError(
                "partial-session peer escaped the target runtime authority"
            )
    ordered_executions = (
        *market_execution_evidence.executions,
        *(peer.execution for peer in peer_evidence_set.peers),
    )
    runtime = attested_finalization.runtime_receipt
    skipped_conclusion = attested_finalization.skipped_conditional_conclusion
    if (
        type(skipped_conclusion) is not FutuFrozenConclusionReceipt
        or skipped_conclusion.run_id != decision.run_id
        or skipped_conclusion.issuer_id != security.issuer_id
        or skipped_conclusion.security_id != security.security_id
    ):
        raise FutuSessionEvidenceError(
            "partial-session finalization lacks its exact target conclusion"
        )
    if (
        runtime.runtime_authorization_fingerprint != runtime_authorization.fingerprint
        or runtime.request_plan_fingerprint
        != runtime_authorization.request_plan_fingerprint
        or runtime.authorization_window_seconds
        != runtime_authorization.authorization_window_seconds
    ):
        raise FutuSessionEvidenceError(
            "partial-session runtime changed its pre-run authorization"
        )
    try:
        validate_futu_attested_session_finalization(
            attested_finalization,
            expected_executions=ordered_executions,
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            verifier=verifier,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise FutuSessionEvidenceError(
            "partial-session signed sidecar finalization no longer replays"
        ) from exc
    all_requests = tuple(
        request for execution in ordered_executions for request in execution.requests
    )
    all_responses = tuple(
        response for execution in ordered_executions for response in execution.responses
    )
    all_observations = tuple(
        observation
        for execution in ordered_executions
        for observation in execution.observations
    )
    if not all_requests or len(all_requests) != len(all_responses):
        raise FutuSessionEvidenceError(
            "partial-session request/response graph is incomplete"
        )
    for identities, label in (
        (tuple(item.request_id for item in all_requests), "request"),
        (tuple(item.response_id for item in all_responses), "response"),
        (tuple(item.observation_id for item in all_observations), "observation"),
    ):
        if len(set(identities)) != len(identities):
            raise FutuSessionEvidenceError(
                f"partial-session repeats a {label} identity"
            )
    response_by_request = {item.request_id: item for item in all_responses}
    for request in all_requests:
        response = response_by_request.get(request.request_id)
        if (
            response is None
            or response.request_fingerprint != request.fingerprint
            or _utc_datetime(response.retrieved_at, "response retrieved_at")
            < _utc_datetime(request.request_started_at, "request_started_at")
        ):
            raise FutuSessionEvidenceError(
                "partial-session response graph or chronology is invalid"
            )
    request_times = tuple(
        _utc_datetime(item.request_started_at, "request_started_at")
        for item in all_requests
    )
    response_times = tuple(
        _utc_datetime(item.retrieved_at, "response retrieved_at")
        for item in all_responses
    )
    if request_times != tuple(sorted(request_times)):
        raise FutuSessionEvidenceError("partial-session request chronology is reordered")
    checkpoint = _utc_datetime(
        market_execution_evidence.checkpoint_at,
        "market checkpoint_at",
    )
    peer_requests = tuple(
        request
        for peer in peer_evidence_set.peers
        for request in peer.execution.requests
    )
    if any(
        _utc_datetime(item.request_started_at, "peer request_started_at") <= checkpoint
        for item in peer_requests
    ):
        raise FutuSessionEvidenceError(
            "partial-session peer calls preceded the market checkpoint"
        )
    started = _utc_datetime(runtime.started_at, "runtime started_at")
    ended = _utc_datetime(runtime.ended_at, "runtime ended_at")
    evaluated = _utc_datetime(decision.evaluated_at, "authority evaluated_at")
    issued = _utc_datetime(runtime.issued_at, "runtime issued_at")
    expires = _utc_datetime(runtime.expires_at, "runtime expires_at")
    if not (
        started <= evaluated <= request_times[0]
        and all(started <= item <= ended for item in (*request_times, *response_times))
        and ended <= issued < expires
    ):
        raise FutuSessionEvidenceError("partial-session runtime chronology is invalid")
    completed_authority = FutuAuthoritySet(
        legal=legal,
        account=account,
        supply_chain=supply,
        runtime_authorization=runtime_authorization,
        runtime=runtime,
        security_identity=security,
    )
    protocols = tuple(sorted({item.protocol_id for item in all_requests}))
    families = tuple(sorted({item.data_family for item in all_requests}))
    replay_authority = evaluate_futu_authority(
        completed_authority,
        verifier=verifier,
        now=issued,
        run_id=decision.run_id,
        policy_sha256=decision.policy_sha256,
        component_lock_sha256=decision.component_lock_sha256,
        required_data_families=families,
        required_protocol_ids=protocols,
        purpose="replay_only",
    )
    if replay_authority.status != "eligible":
        raise FutuSessionEvidenceError(
            "partial-session completed runtime is not replay-eligible"
        )
    checkpoints = runtime.checkpoints
    if len(checkpoints) != 2 + (2 * len(all_responses)):
        raise FutuSessionEvidenceError(
            "partial-session runtime omits request guard checkpoints"
        )
    if (
        checkpoints[0]["checkpoint"] != "startup"
        or checkpoints[-1]["checkpoint"] != "pre_shutdown"
        or checkpoints[0]["global_state_response_fingerprint"]
        != account.global_state_response_fingerprint
    ):
        raise FutuSessionEvidenceError(
            "partial-session runtime boundary checkpoints are invalid"
        )
    expected_middle: list[dict[str, Any]] = []
    for response in all_responses:
        expected_middle.extend(
            (
                {
                    "checkpoint": "pre_request",
                    "serial_number": response.pre_global_state_serial_number,
                    "global_state_request_fingerprint": (
                        response.pre_global_state_request_fingerprint
                    ),
                    "global_state_response_fingerprint": (
                        response.pre_global_state_response_fingerprint
                    ),
                },
                {
                    "checkpoint": "post_request",
                    "serial_number": response.post_global_state_serial_number,
                    "global_state_request_fingerprint": (
                        response.post_global_state_request_fingerprint
                    ),
                    "global_state_response_fingerprint": (
                        response.post_global_state_response_fingerprint
                    ),
                },
            )
        )
    for actual, expected in zip(checkpoints[1:-1], expected_middle, strict=True):
        if any(actual[key] != value for key, value in expected.items()):
            raise FutuSessionEvidenceError(
                "partial-session runtime checkpoint was rebound"
            )
    if any(not item["qot_logined"] or item["trd_logined"] for item in checkpoints):
        raise FutuSessionEvidenceError(
            "partial-session runtime violates quote-only login"
        )
    serials = tuple(item["serial_number"] for item in checkpoints)
    if serials != tuple(sorted(serials)) or len(set(serials)) != len(serials):
        raise FutuSessionEvidenceError(
            "partial-session runtime GlobalState sequence is not exact"
        )
    cas_objects = [
        {
            "response_fingerprint": response.fingerprint,
            "raw_evidence_kind": response.raw_evidence_kind,
            "raw_plaintext_sha256": response.raw_plaintext_sha256,
            "encrypted_object_sha256": response.encrypted_object_sha256,
            "cas_locator": response.cas_locator,
            "raw_byte_count": response.raw_byte_count,
        }
        for response in all_responses
    ]
    global_state_guards = [
        {
            "checkpoint": item["checkpoint"],
            "serial_number": item["serial_number"],
            "request_fingerprint": item["global_state_request_fingerprint"],
            "response_fingerprint": item["global_state_response_fingerprint"],
            "qot_logined": item["qot_logined"],
            "trd_logined": item["trd_logined"],
        }
        for item in checkpoints
    ]
    first = market_execution_evidence.executions[0].bundle
    return {
        "schema_version": FUTU_SCHEMA_VERSION,
        "run_id": decision.run_id,
        "issuer_id": first.issuer_id,
        "security_id": first.security_id,
        "status": "post_context_not_run",
        "finalized_at": runtime.ended_at,
        "authority_decision_fingerprint": decision.fingerprint,
        "authority_receipts": {
            "legal": legal.fingerprint,
            "account": account.fingerprint,
            "supply_chain": supply.fingerprint,
            "security_identity": security.fingerprint,
        },
        "runtime_authorization_fingerprint": runtime_authorization.fingerprint,
        "runtime_receipt_fingerprint": runtime.fingerprint,
        "attested_finalization_fingerprint": attested_finalization.fingerprint,
        "skipped_conditional_conclusion": {
            "object_id": skipped_conclusion.receipt_id,
            "fingerprint": skipped_conclusion.fingerprint,
        },
        "sidecar_boot_attestation": {
            "object_id": attested_finalization.boot_attestation.receipt_id,
            "fingerprint": attested_finalization.boot_attestation.fingerprint,
        },
        "sidecar_execution_attestation": {
            "object_id": attested_finalization.execution_attestation.receipt_id,
            "fingerprint": attested_finalization.execution_attestation.fingerprint,
        },
        "contract_graph_fingerprint": (
            market_execution_evidence.contract_graph_fingerprint
        ),
        "market_execution_evidence": {
            "object_id": market_execution_evidence.evidence_id,
            "fingerprint": market_execution_evidence.fingerprint,
        },
        "peer_evidence_set": {
            "object_id": peer_evidence_set.evidence_set_id,
            "fingerprint": peer_evidence_set.fingerprint,
        },
        "execution_bundles": [
            {"object_id": item.bundle.bundle_id, "fingerprint": item.bundle.fingerprint}
            for item in market_execution_evidence.executions
        ],
        "peer_sessions": [
            {"object_id": item.peer_session_id, "fingerprint": item.fingerprint}
            for item in peer_evidence_set.peers
        ],
        "requests": [
            {"object_id": item.request_id, "fingerprint": item.fingerprint}
            for item in all_requests
        ],
        "responses": [
            {"object_id": item.response_id, "fingerprint": item.fingerprint}
            for item in all_responses
        ],
        "observations": [
            {"object_id": item.observation_id, "fingerprint": item.fingerprint}
            for item in all_observations
        ],
        "official_operands": [
            {"object_id": item.object_id, "fingerprint": item.fingerprint}
            for item in market_execution_evidence.official_operands
        ],
        "cross_checks": [
            {"object_id": item.receipt_id, "fingerprint": item.fingerprint}
            for item in market_execution_evidence.cross_checks
        ],
        "cas_objects": cas_objects,
        "global_state_guards": global_state_guards,
    }


def _session_manifest_values(
    *,
    authority_set: FutuAuthoritySet,
    authority_decision: FutuAuthorityDecision,
    market_execution_evidence: FutuMarketExecutionEvidence,
    peer_evidence_set: FutuPeerEvidenceSet,
    frozen_conclusion: FutuFrozenConclusionReceipt,
    attested_finalization: FutuAttestedSessionFinalization,
    executions: tuple[FutuSidecarExecution, ...],
    contract_graph: ContractGraph,
    official_operands: tuple[OfficialEvidenceOperand, ...],
    cross_checks: tuple[FutuCrossCheckReceipt, ...],
    finalized_at: str,
) -> dict[str, Any]:
    if len(executions) != len(_SESSION_STAGES):
        raise FutuSessionEvidenceError("Futu session must retain its three target executions")
    if (
        type(market_execution_evidence) is not FutuMarketExecutionEvidence
        or contract_graph is not market_execution_evidence.contract_graph
    ):
        raise FutuSessionEvidenceError(
            "Futu session must retain the exact market-execution ContractGraph"
        )
    legal = authority_set.legal
    account = authority_set.account
    supply = authority_set.supply_chain
    runtime_authorization = authority_set.runtime_authorization
    runtime = authority_set.runtime
    security = authority_set.security_identity
    if any(
        item is None
        for item in (legal, account, supply, runtime_authorization, runtime, security)
    ):
        raise FutuSessionEvidenceError("Futu session authority set is incomplete")
    assert legal is not None
    assert account is not None
    assert supply is not None
    assert runtime_authorization is not None
    assert runtime is not None
    assert security is not None
    if (
        type(attested_finalization) is not FutuAttestedSessionFinalization
        or attested_finalization.runtime_receipt != runtime
    ):
        raise FutuSessionEvidenceError("Futu session lacks its signed sidecar finalization")
    first = executions[0].bundle
    ordered_executions = (
        executions[0],
        executions[1],
        *(peer.execution for peer in peer_evidence_set.peers),
        executions[2],
    )
    cas_objects = [
        {
            "response_fingerprint": response.fingerprint,
            "raw_evidence_kind": response.raw_evidence_kind,
            "raw_plaintext_sha256": response.raw_plaintext_sha256,
            "encrypted_object_sha256": response.encrypted_object_sha256,
            "cas_locator": response.cas_locator,
            "raw_byte_count": response.raw_byte_count,
        }
        for execution in ordered_executions
        for response in execution.responses
    ]
    global_state_guards = [
        {
            "checkpoint": checkpoint["checkpoint"],
            "serial_number": checkpoint["serial_number"],
            "request_fingerprint": checkpoint["global_state_request_fingerprint"],
            "response_fingerprint": checkpoint["global_state_response_fingerprint"],
            "qot_logined": checkpoint["qot_logined"],
            "trd_logined": checkpoint["trd_logined"],
        }
        for checkpoint in runtime.checkpoints
    ]
    return {
        "schema_version": FUTU_SCHEMA_VERSION,
        "run_id": authority_decision.run_id,
        "issuer_id": first.issuer_id,
        "security_id": first.security_id,
        "status": "complete",
        "finalized_at": finalized_at,
        "authority_decision_fingerprint": authority_decision.fingerprint,
        "authority_receipts": {
            "legal": legal.fingerprint,
            "account": account.fingerprint,
            "supply_chain": supply.fingerprint,
            "security_identity": security.fingerprint,
        },
        "runtime_authorization_fingerprint": runtime_authorization.fingerprint,
        "runtime_receipt_fingerprint": runtime.fingerprint,
        "attested_finalization_fingerprint": attested_finalization.fingerprint,
        "sidecar_boot_attestation": {
            "object_id": attested_finalization.boot_attestation.receipt_id,
            "fingerprint": attested_finalization.boot_attestation.fingerprint,
        },
        "sidecar_execution_attestation": {
            "object_id": attested_finalization.execution_attestation.receipt_id,
            "fingerprint": attested_finalization.execution_attestation.fingerprint,
        },
        "contract_graph_fingerprint": (
            market_execution_evidence.contract_graph_fingerprint
        ),
        "market_execution_evidence": {
            "object_id": market_execution_evidence.evidence_id,
            "fingerprint": market_execution_evidence.fingerprint,
        },
        "peer_evidence_set": {
            "object_id": peer_evidence_set.evidence_set_id,
            "fingerprint": peer_evidence_set.fingerprint,
        },
        "frozen_conclusion": {
            "object_id": frozen_conclusion.receipt_id,
            "fingerprint": frozen_conclusion.fingerprint,
        },
        "execution_bundles": [
            {"object_id": item.bundle.bundle_id, "fingerprint": item.bundle.fingerprint}
            for item in executions
        ],
        "peer_sessions": [
            {"object_id": item.peer_session_id, "fingerprint": item.fingerprint}
            for item in peer_evidence_set.peers
        ],
        "requests": [
            {"object_id": item.request_id, "fingerprint": item.fingerprint}
            for execution in ordered_executions
            for item in execution.requests
        ],
        "responses": [
            {"object_id": item.response_id, "fingerprint": item.fingerprint}
            for execution in ordered_executions
            for item in execution.responses
        ],
        "observations": [
            {"object_id": item.observation_id, "fingerprint": item.fingerprint}
            for execution in ordered_executions
            for item in execution.observations
        ],
        "official_operands": [
            {"object_id": item.object_id, "fingerprint": item.fingerprint}
            for item in official_operands
        ],
        "cross_checks": [
            {"object_id": item.receipt_id, "fingerprint": item.fingerprint}
            for item in cross_checks
        ],
        "cas_objects": cas_objects,
        "global_state_guards": global_state_guards,
    }


def _market_execution_manifest_values(
    *,
    authority_set: FutuAuthoritySet,
    authority_decision: FutuAuthorityDecision,
    executions: tuple[FutuSidecarExecution, ...],
    contract_graph_fingerprint: str,
    official_operands: tuple[OfficialEvidenceOperand, ...],
    cross_checks: tuple[FutuCrossCheckReceipt, ...],
    observation_dispositions: tuple[FutuObservationDispositionReceipt, ...],
    checkpoint_at: str,
) -> dict[str, Any]:
    if len(executions) != 2:
        raise FutuSessionEvidenceError("market-execution checkpoint requires exactly two stages")
    legal = authority_set.legal
    account = authority_set.account
    supply = authority_set.supply_chain
    runtime_authorization = authority_set.runtime_authorization
    security = authority_set.security_identity
    if any(item is None for item in (legal, account, supply, runtime_authorization, security)):
        raise FutuSessionEvidenceError("market-execution authority set is incomplete")
    assert legal is not None
    assert account is not None
    assert supply is not None
    assert runtime_authorization is not None
    assert security is not None
    first = executions[0].bundle
    responses = tuple(item for execution in executions for item in execution.responses)
    guards: list[dict[str, Any]] = []
    for response in responses:
        guards.extend(
            (
                {
                    "phase": "pre_request",
                    "response_fingerprint": response.pre_global_state_response_fingerprint,
                    "serial_number": response.pre_global_state_serial_number,
                    "request_fingerprint": response.pre_global_state_request_fingerprint,
                    "qot_logined": response.qot_logined,
                    "trd_logined": response.trd_logined,
                },
                {
                    "phase": "post_request",
                    "response_fingerprint": response.post_global_state_response_fingerprint,
                    "serial_number": response.post_global_state_serial_number,
                    "request_fingerprint": response.post_global_state_request_fingerprint,
                    "qot_logined": response.qot_logined,
                    "trd_logined": response.trd_logined,
                },
            )
        )
    return {
        "schema_version": FUTU_SCHEMA_VERSION,
        "run_id": authority_decision.run_id,
        "issuer_id": first.issuer_id,
        "security_id": first.security_id,
        "checkpoint_at": checkpoint_at,
        "authority_decision_fingerprint": authority_decision.fingerprint,
        "authority_receipts": {
            "legal": legal.fingerprint,
            "account": account.fingerprint,
            "supply_chain": supply.fingerprint,
            "security_identity": security.fingerprint,
        },
        "runtime_authorization_fingerprint": runtime_authorization.fingerprint,
        "contract_graph_fingerprint": contract_graph_fingerprint,
        "execution_bundles": [
            {"object_id": item.bundle.bundle_id, "fingerprint": item.bundle.fingerprint}
            for item in executions
        ],
        "requests": [
            {"object_id": item.request_id, "fingerprint": item.fingerprint}
            for execution in executions
            for item in execution.requests
        ],
        "responses": [
            {"object_id": item.response_id, "fingerprint": item.fingerprint}
            for item in responses
        ],
        "observations": [
            {"object_id": item.observation_id, "fingerprint": item.fingerprint}
            for execution in executions
            for item in execution.observations
        ],
        "official_operands": [
            {"object_id": item.object_id, "fingerprint": item.fingerprint}
            for item in official_operands
        ],
        "cross_checks": [
            {"object_id": item.receipt_id, "fingerprint": item.fingerprint}
            for item in cross_checks
        ],
        "observation_dispositions": [
            {"object_id": item.receipt_id, "fingerprint": item.fingerprint}
            for item in observation_dispositions
        ],
        "cas_objects": [
            {
                "response_fingerprint": item.fingerprint,
                "raw_evidence_kind": item.raw_evidence_kind,
                "raw_plaintext_sha256": item.raw_plaintext_sha256,
                "encrypted_object_sha256": item.encrypted_object_sha256,
                "cas_locator": item.cas_locator,
                "raw_byte_count": item.raw_byte_count,
            }
            for item in responses
        ],
        "global_state_guards": guards,
    }


def _validate_graph_crosschecks(
    *,
    graph: ContractGraph,
    graph_fingerprint: str,
    executions: tuple[FutuSidecarExecution, ...],
    official_operands: tuple[OfficialEvidenceOperand, ...],
    cross_checks: tuple[FutuCrossCheckReceipt, ...],
    observation_dispositions: tuple[FutuObservationDispositionReceipt, ...],
    disposition_created_at: str,
) -> None:
    preprice = tuple(
        execution
        for execution in executions
        if execution.bundle.stage == "valuation_pre_price_verification"
    )
    if len(preprice) != 1:
        raise FutuSessionEvidenceError("graph cross-check requires one pre-price execution")
    official_dividend_dates = tuple(
        sorted(
            event.announcement_date
            for event in graph.capital_allocation_events
            if event.issuer_id == preprice[0].bundle.issuer_id
            and event.event_type == "dividend"
        )
    )
    vendor_dividend_dates = tuple(
        sorted(
            str(observation.qualifiers.get("publication_date"))
            for observation in preprice[0].observations
            if observation.data_family == "corporate_actions"
            and observation.field_id == "dividend_event"
        )
    )
    if (
        any(value in {"", "None"} for value in vendor_dividend_dates)
        or len(set(vendor_dividend_dates)) != len(vendor_dividend_dates)
        or official_dividend_dates != vendor_dividend_dates
    ):
        raise FutuSessionEvidenceError(
            "SEC/IR and Futu dividend event sets are not identical"
        )
    observation_index = {
        observation.observation_id: observation
        for execution in executions
        for observation in execution.observations
    }
    required_vendor_ids = {
        observation.observation_id
        for execution in executions
        if execution.bundle.stage == "valuation_pre_price_verification"
        for observation in execution.observations
        if observation.source_role == "vendor_secondary"
    }
    comparison_eligible_ids = {
        observation.observation_id
        for execution in executions
        if execution.bundle.stage == "valuation_pre_price_verification"
        for observation in execution.observations
        if observation.source_role == "vendor_secondary"
        and observation.comparison_eligible
    }
    crosschecked_vendor_ids = tuple(item.vendor_observation_id for item in cross_checks)
    disposition_vendor_ids = tuple(
        item.vendor_observation_id for item in observation_dispositions
    )
    if (
        len(set(crosschecked_vendor_ids)) != len(crosschecked_vendor_ids)
        or len(set(disposition_vendor_ids)) != len(disposition_vendor_ids)
        or set(crosschecked_vendor_ids) & set(disposition_vendor_ids)
        or set(crosschecked_vendor_ids) != comparison_eligible_ids
        or set(crosschecked_vendor_ids) | set(disposition_vendor_ids)
        != required_vendor_ids
    ):
        raise FutuSessionEvidenceError(
            "pre-price vendor observations lack disjoint cross-check or disposition coverage"
        )
    operands = {item.fingerprint: item for item in official_operands}
    if len(operands) != len(official_operands) or len(cross_checks) != len(official_operands):
        raise FutuSessionEvidenceError("graph cross-check evidence is not one-to-one")
    for operand in official_operands:
        if operand.contract_graph_fingerprint != graph_fingerprint:
            raise FutuSessionEvidenceError("official operand is bound to another graph")
    for receipt in cross_checks:
        operand = operands.get(receipt.official_operand_fingerprint)
        vendor = observation_index.get(receipt.vendor_observation_id)
        if operand is None or vendor is None:
            raise FutuSessionEvidenceError("cross-check references evidence outside executions")
        if (
            receipt.contract_graph_fingerprint != graph_fingerprint
            or receipt.official_object_id != operand.object_id
            or receipt.official_object_fingerprint != operand.object_fingerprint
            or receipt.vendor_observation_fingerprint != vendor.fingerprint
            or vendor.use_scope != "valuation_pre_price_verification"
        ):
            raise FutuSessionEvidenceError("cross-check evidence was rebound")
        if receipt.result == "conflict":
            raise FutuSessionEvidenceError(
                "vendor conflict requires corrected official evidence and a new run"
            )
        if receipt.materiality == "kernel_required" and receipt.result != "consistent":
            raise FutuSessionEvidenceError(
                "kernel-required vendor evidence did not confirm official evidence"
            )
        replayed = _crosscheck_vendor_observation_with_graph_fingerprint(
            graph=graph,
            graph_fingerprint=graph_fingerprint,
            official=operand,
            vendor=vendor,
            created_at=receipt.created_at,
        )
        if receipt.reviewer_id is not None:
            assert receipt.resolution is not None
            replayed = resolve_crosscheck(
                replayed,
                reviewer_id=receipt.reviewer_id,
                resolution=receipt.resolution,
            )
        if replayed.to_dict() != receipt.to_dict() or receipt.status == "review_required":
            raise FutuSessionEvidenceError("cross-check receipt no longer replays as resolved")
    replayed_dispositions = build_futu_observation_dispositions(
        executions=executions,
        cross_checks=cross_checks,
        created_at=disposition_created_at,
    )
    if tuple(item.to_dict() for item in replayed_dispositions) != tuple(
        item.to_dict() for item in observation_dispositions
    ):
        raise FutuSessionEvidenceError("observation dispositions no longer replay")
    for disposition in observation_dispositions:
        vendor = observation_index.get(disposition.vendor_observation_id)
        if (
            vendor is None
            or disposition.vendor_observation_fingerprint != vendor.fingerprint
            or disposition.issuer_id != vendor.issuer_id
            or disposition.security_id != vendor.security_id
            or disposition.data_family != vendor.data_family
            or disposition.field_id != vendor.field_id
        ):
            raise FutuSessionEvidenceError("observation disposition evidence was rebound")


def _peer_session_manifest_values(
    *,
    authority_set: FutuAuthoritySet,
    authority_decision: FutuAuthorityDecision,
    execution: FutuSidecarExecution,
    daily_close: FutuDailyCloseAdapterResult,
    price_blind_freeze: PriceBlindFreezeCompilationResult,
) -> dict[str, Any]:
    security = authority_set.security_identity
    if security is None or type(price_blind_freeze) is not PriceBlindFreezeCompilationResult:
        raise FutuSessionEvidenceError("peer security or typed price-blind freeze is missing")
    freeze_fingerprint = price_blind_freeze.artifact.fingerprint
    freeze_issuer = str(price_blind_freeze.artifact.payload["issuer_id"])
    if not freeze_issuer:
        raise FutuSessionEvidenceError("price-blind freeze issuer is invalid")
    return {
        "schema_version": FUTU_SCHEMA_VERSION,
        "run_id": authority_decision.run_id,
        "issuer_id": execution.bundle.issuer_id,
        "security_id": execution.bundle.security_id,
        "price_blind_freeze": {
            "object_id": f"price-blind-input:{freeze_issuer}:{freeze_fingerprint[:24]}",
            "fingerprint": freeze_fingerprint,
        },
        "price_blind_freeze_fingerprint": freeze_fingerprint,
        "security_identity_fingerprint": security.fingerprint,
        "authority_decision_fingerprint": authority_decision.fingerprint,
        "execution_bundle": {
            "object_id": execution.bundle.bundle_id,
            "fingerprint": execution.bundle.fingerprint,
        },
        "daily_close_adapter_fingerprint": daily_close.adapter_fingerprint,
        "requests": [
            {"object_id": item.request_id, "fingerprint": item.fingerprint}
            for item in execution.requests
        ],
        "responses": [
            {"object_id": item.response_id, "fingerprint": item.fingerprint}
            for item in execution.responses
        ],
        "observations": [
            {"object_id": item.observation_id, "fingerprint": item.fingerprint}
            for item in execution.observations
        ],
        "cas_objects": [
            {
                "response_fingerprint": item.fingerprint,
                "raw_evidence_kind": item.raw_evidence_kind,
                "raw_plaintext_sha256": item.raw_plaintext_sha256,
                "encrypted_object_sha256": item.encrypted_object_sha256,
                "cas_locator": item.cas_locator,
                "raw_byte_count": item.raw_byte_count,
            }
            for item in execution.responses
        ],
    }


def _peer_set_manifest_values(
    *,
    target_security_id: str,
    price_blind_freeze: PriceBlindFreezeCompilationResult,
    peers: tuple[FutuPeerSessionEvidence, ...],
) -> dict[str, Any]:
    if not peers or type(price_blind_freeze) is not PriceBlindFreezeCompilationResult:
        raise FutuSessionEvidenceError("peer evidence set lacks peers or typed freeze")
    freeze_fingerprint = price_blind_freeze.artifact.fingerprint
    freeze_issuer = str(price_blind_freeze.artifact.payload["issuer_id"])
    return {
        "schema_version": FUTU_SCHEMA_VERSION,
        "run_id": peers[0].run_id,
        "target_security_id": target_security_id,
        "price_blind_freeze": {
            "object_id": f"price-blind-input:{freeze_issuer}:{freeze_fingerprint[:24]}",
            "fingerprint": freeze_fingerprint,
        },
        "price_blind_freeze_fingerprint": freeze_fingerprint,
        "peer_sessions": [
            {"object_id": item.peer_session_id, "fingerprint": item.fingerprint}
            for item in peers
        ],
    }


def _validate_static_security_identity(
    execution: FutuSidecarExecution,
    *,
    security: FutuSecurityIdentityReceipt,
) -> None:
    static_requests = tuple(
        request for request in execution.requests if request.protocol_id == 3202
    )
    if len(static_requests) != 1:
        raise FutuSessionEvidenceError(
            "execution must contain exactly one static identity request"
        )
    request = static_requests[0]
    static_responses = tuple(
        response
        for response in execution.responses
        if response.request_id == request.request_id
    )
    if (
        len(static_responses) != 1
        or request.page_index != 0
        or static_responses[0].page_index != 0
        or static_responses[0].terminal is not True
        or static_responses[0].status != "completed"
    ):
        raise FutuSessionEvidenceError(
            "execution must contain exactly one completed static identity response"
        )
    response = static_responses[0]
    observations = tuple(
        observation
        for observation in execution.observations
        if observation.response_fingerprint == response.fingerprint
    )
    if (
        len(observations) != len(_STATIC_IDENTITY_FIELD_ORDER)
        or tuple(observation.field_id for observation in observations)
        != _STATIC_IDENTITY_FIELD_ORDER
    ):
        raise FutuSessionEvidenceError(
            "static identity response must contain the exact ordered nine fields"
    )
    raw_qualifiers = {
        "raw_exchange_type": _STATIC_IDENTITY_EXCHANGE_CODES[security.mic],
        "raw_market_code": 11,
        "raw_security_type": 3,
    }
    expected_value_types = (
        "text",
        "text",
        "text",
        "text",
        "text",
        "boolean",
        "number",
        "number",
        "text",
    )
    expected_units = (None, None, None, None, None, None, None, "shares", None)
    for observation, value_type, unit in zip(
        observations, expected_value_types, expected_units, strict=True
    ):
        if (
            observation.data_family != "security_identity"
            or observation.period != FrozenMap({"start": None, "end": None})
            or observation.qualifiers != FrozenMap(raw_qualifiers)
            or observation.value_type != value_type
            or observation.unit != unit
            or observation.currency is not None
            or observation.binary64_hex is not None
            or observation.exact_binary64_decimal is not None
            or observation.canonical_concept is not None
            or observation.comparison_eligible is not False
            or observation.point_in_time_status != "current_snapshot"
            or observation.source_role != "vendor_secondary"
            or observation.use_scope != execution.bundle.stage
        ):
            raise FutuSessionEvidenceError(
                "static identity observation semantics are invalid"
            )
    values = {observation.field_id: observation.value for observation in observations}
    projection = futu_static_identity_projection(
        vendor_security_market=values["vendor_security_market"],
        vendor_security_code=values["vendor_security_code"],
        security_type=values["security_type"],
        listing_mic=values["listing_mic"],
        listing_date=values["listing_date"],
        delisting=values["delisting"],
        vendor_security_id=values["vendor_security_id"],
        lot_size=values["lot_size"],
        security_name=values["security_name"],
        raw_exchange_type=raw_qualifiers["raw_exchange_type"],
        raw_market_code=raw_qualifiers["raw_market_code"],
        raw_security_type=raw_qualifiers["raw_security_type"],
    )
    listing_date = date.fromisoformat(str(values["listing_date"]))
    identity_effective_from = date.fromisoformat(security.effective_from)
    expected_vendor_exchange_types = {
        "XNAS": {"5", "NASDAQ", "XNAS"},
        "XNYS": {"4", "NYSE", "XNYS"},
    }
    if (
        values["vendor_security_market"] != security.vendor_market
        or values["vendor_security_code"] != security.vendor_code
        or security.vendor_code != f"US.{security.ticker}"
        or values["listing_mic"] != security.mic
        or values["security_type"] != "COMMON_EQUITY"
        or security.share_class != "common"
        or values["vendor_security_id"] != security.vendor_security_id
        or security.vendor_security_type not in {"COMMON_EQUITY", "STOCK"}
        or security.vendor_exchange_type
        not in expected_vendor_exchange_types[security.mic]
        or listing_date > identity_effective_from
    ):
        raise FutuSessionEvidenceError(
            "static Futu identity conflicts with the signed official identity"
        )
    if canonical_sha256(projection) != security.static_response_fingerprint:
        raise FutuSessionEvidenceError(
            "static identity projection does not match its signed fingerprint"
        )


def _validate_required_stage_protocols(
    execution: FutuSidecarExecution,
    *,
    mic: str,
) -> None:
    registry = load_protocol_registry()
    stage = execution.bundle.stage
    requested = {item.protocol_id for item in execution.requests}
    for request in execution.requests:
        protocol = registry.get(request.protocol_id)
        if protocol is None or mic not in protocol["market_scope"]:
            raise FutuSessionEvidenceError(
                "execution contains a protocol outside the security market scope"
            )
    if stage == "peer_comparable_reference":
        required = {3103, 3202}
    else:
        required = {
            protocol_id
            for protocol_id, protocol in registry.items()
            if protocol["stage"] == stage
            and protocol["required_for_complete"]
            and mic in protocol["market_scope"]
        }
    if not required.issubset(requested):
        raise FutuSessionEvidenceError("execution omits a required registered protocol")


def _validate_publication_projection(manifest: FutuSessionPublicationManifest) -> None:
    reference_groups = (
        (manifest.execution_bundles, "futu-bundle:"),
        (manifest.peer_sessions, "futu-peer-session:"),
        (manifest.requests, "futu-request:"),
        (manifest.responses, "futu-response:"),
        (manifest.observations, "futu-observation:"),
        (manifest.cross_checks, "futu-crosscheck:"),
    )
    for references, prefix in reference_groups:
        identities = tuple(
            (str(item["object_id"]), str(item["fingerprint"])) for item in references
        )
        if len(set(identities)) != len(identities) or any(
            not object_id.startswith(prefix) for object_id, _ in identities
        ):
            raise FutuSessionEvidenceError(
                "publication manifest contains invalid or repeated typed references"
            )
    if not str(manifest.market_execution_evidence["object_id"]).startswith(
        "futu-market-execution:"
    ) or not str(manifest.peer_evidence_set["object_id"]).startswith(
        "futu-peer-set:"
    ) or not str(manifest.frozen_conclusion["object_id"]).startswith(
        "futu-conclusion-freeze:"
    ):
        raise FutuSessionEvidenceError("publication manifest checkpoint references are invalid")
    response_fingerprints = tuple(str(item["fingerprint"]) for item in manifest.responses)
    cas_fingerprints = tuple(str(item["response_fingerprint"]) for item in manifest.cas_objects)
    if response_fingerprints != cas_fingerprints or any(
        item["cas_locator"] != f"cas://sha256/{item['encrypted_object_sha256']}"
        for item in manifest.cas_objects
    ):
        raise FutuSessionEvidenceError("publication manifest CAS projection was rebound")
    if len(manifest.global_state_guards) != 2 + (2 * len(manifest.responses)):
        raise FutuSessionEvidenceError("publication manifest omits runtime guard checkpoints")
    if (
        manifest.global_state_guards[0]["checkpoint"] != "startup"
        or manifest.global_state_guards[-1]["checkpoint"] != "pre_shutdown"
        or any(
            not item["qot_logined"] or item["trd_logined"]
            for item in manifest.global_state_guards
        )
    ):
        raise FutuSessionEvidenceError("publication manifest violates quote-only guards")
    serials = tuple(int(item["serial_number"]) for item in manifest.global_state_guards)
    if serials != tuple(sorted(serials)) or len(set(serials)) != len(serials):
        raise FutuSessionEvidenceError("publication runtime guard ordering is invalid")


def _validate_partial_publication_projection(
    manifest: FutuPartialSessionPublicationManifest,
) -> None:
    if manifest.status != "post_context_not_run":
        raise FutuSessionEvidenceError(
            "partial-session publication cannot claim a completed post-context stage"
        )
    reference_groups = (
        (manifest.execution_bundles, "futu-bundle:"),
        (manifest.peer_sessions, "futu-peer-session:"),
        (manifest.requests, "futu-request:"),
        (manifest.responses, "futu-response:"),
        (manifest.observations, "futu-observation:"),
        (manifest.cross_checks, "futu-crosscheck:"),
    )
    for references, prefix in reference_groups:
        identities = tuple(
            (str(item["object_id"]), str(item["fingerprint"])) for item in references
        )
        if len(set(identities)) != len(identities) or any(
            not object_id.startswith(prefix) for object_id, _ in identities
        ):
            raise FutuSessionEvidenceError(
                "partial-session publication contains invalid typed references"
            )
    if len(manifest.execution_bundles) != 2 or not 5 <= len(manifest.peer_sessions) <= 15:
        raise FutuSessionEvidenceError(
            "partial-session publication target or peer stage count is invalid"
        )
    if not str(manifest.market_execution_evidence["object_id"]).startswith(
        "futu-market-execution:"
    ) or not str(manifest.peer_evidence_set["object_id"]).startswith(
        "futu-peer-set:"
    ) or not str(manifest.skipped_conditional_conclusion["object_id"]).startswith(
        "futu-conclusion-freeze:"
    ):
        raise FutuSessionEvidenceError(
            "partial-session publication checkpoint references are invalid"
        )
    response_fingerprints = tuple(str(item["fingerprint"]) for item in manifest.responses)
    cas_fingerprints = tuple(str(item["response_fingerprint"]) for item in manifest.cas_objects)
    if response_fingerprints != cas_fingerprints or any(
        item["cas_locator"] != f"cas://sha256/{item['encrypted_object_sha256']}"
        for item in manifest.cas_objects
    ):
        raise FutuSessionEvidenceError(
            "partial-session publication CAS projection was rebound"
        )
    if len(manifest.global_state_guards) != 2 + (2 * len(manifest.responses)):
        raise FutuSessionEvidenceError(
            "partial-session publication omits runtime guard checkpoints"
        )
    if (
        manifest.global_state_guards[0]["checkpoint"] != "startup"
        or manifest.global_state_guards[-1]["checkpoint"] != "pre_shutdown"
        or any(
            not item["qot_logined"] or item["trd_logined"]
            for item in manifest.global_state_guards
        )
    ):
        raise FutuSessionEvidenceError(
            "partial-session publication violates quote-only guards"
        )
    serials = tuple(int(item["serial_number"]) for item in manifest.global_state_guards)
    if serials != tuple(sorted(serials)) or len(set(serials)) != len(serials):
        raise FutuSessionEvidenceError(
            "partial-session publication guard ordering is invalid"
        )


def _validate_market_publication_projection(
    manifest: FutuMarketExecutionPublicationManifest,
) -> None:
    reference_groups = (
        (manifest.execution_bundles, "futu-bundle:"),
        (manifest.requests, "futu-request:"),
        (manifest.responses, "futu-response:"),
        (manifest.observations, "futu-observation:"),
        (manifest.cross_checks, "futu-crosscheck:"),
        (
            manifest.observation_dispositions,
            "futu-observation-disposition:",
        ),
    )
    for references, prefix in reference_groups:
        identities = tuple(
            (str(item["object_id"]), str(item["fingerprint"])) for item in references
        )
        if len(set(identities)) != len(identities) or any(
            not object_id.startswith(prefix) for object_id, _ in identities
        ):
            raise FutuSessionEvidenceError(
                "market-execution publication contains invalid typed references"
            )
    if len(manifest.execution_bundles) != 2:
        raise FutuSessionEvidenceError(
            "market-execution publication must bind exactly two stages"
        )
    response_fingerprints = tuple(str(item["fingerprint"]) for item in manifest.responses)
    cas_fingerprints = tuple(str(item["response_fingerprint"]) for item in manifest.cas_objects)
    if response_fingerprints != cas_fingerprints or any(
        item["cas_locator"] != f"cas://sha256/{item['encrypted_object_sha256']}"
        for item in manifest.cas_objects
    ):
        raise FutuSessionEvidenceError(
            "market-execution publication CAS projection was rebound"
        )
    if len(manifest.global_state_guards) != 2 * len(manifest.responses):
        raise FutuSessionEvidenceError(
            "market-execution publication omits request guard checkpoints"
        )
    if any(
        not item["qot_logined"] or item["trd_logined"]
        for item in manifest.global_state_guards
    ):
        raise FutuSessionEvidenceError(
            "market-execution publication violates quote-only guards"
        )
    serials = tuple(int(item["serial_number"]) for item in manifest.global_state_guards)
    if serials != tuple(sorted(serials)) or len(set(serials)) != len(serials):
        raise FutuSessionEvidenceError(
            "market-execution publication guard ordering is invalid"
        )


def _utc_datetime(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise FutuSessionEvidenceError(f"{label} must be an RFC 3339 date-time") from exc
    if parsed.tzinfo is None:
        raise FutuSessionEvidenceError(f"{label} must include a UTC offset")
    return parsed.astimezone(UTC)


__all__ = [
    "FutuMarketExecutionEvidence",
    "FutuMarketExecutionPublicationManifest",
    "FutuObservationDispositionPublicationBundle",
    "FutuPartialSessionPublicationManifest",
    "FutuPeerEvidenceSet",
    "FutuPeerSessionEvidence",
    "FutuSessionEvidence",
    "FutuSessionEvidenceError",
    "FutuSessionPublicationManifest",
    "build_futu_peer_evidence_set",
    "build_futu_peer_session_evidence",
    "build_futu_market_execution_publication_manifest",
    "build_futu_observation_disposition_publication_bundle",
    "build_futu_partial_session_publication_manifest",
    "build_futu_session_publication_manifest",
    "finalize_futu_market_execution_evidence",
    "finalize_futu_session_evidence",
    "validate_futu_market_execution_evidence",
    "validate_futu_market_execution_publication_manifest",
    "validate_futu_observation_disposition_publication_bundle",
    "validate_futu_partial_session_publication_manifest",
    "validate_futu_peer_evidence_set",
    "validate_futu_peer_session_evidence",
    "validate_futu_session_evidence_replay",
    "validate_futu_session_publication_manifest",
]
