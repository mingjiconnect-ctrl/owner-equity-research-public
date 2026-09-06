"""Governed Futu market reference bridge for the fixed valuation path.

The Futu sidecar deliberately does not implement the legacy reviewed-file provider
protocol.  This module projects one completed, quote-only daily-close execution into
the existing immutable ``MarketAccessResult`` / ``PreparedMarketReference`` graph while
retaining ``governed_vendor`` authority.  It also reserves the price-blind Handoff
*before* the sidecar request so the existing durable one-use authorization remains the
only promotion path.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, fields, replace
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Literal

if TYPE_CHECKING:
    from .valuation_run import ValuationRunResult

from .calculation_integrity import build_calculation_result
from .component_lock import _read_bounded_regular_file_nofollow
from .contracts import Fact, MarketReferenceSnapshot, SourceDocument
from .fingerprints import FrozenMap, canonical_sha256, to_json_value
from .futu_crosscheck import _premarket_contract_graph_fingerprint
from .futu_receipts import (
    FUTU_SCHEMA_VERSION,
    FutuAuthorityDecision,
    FutuAuthoritySet,
    FutuDataRequestReceipt,
    FutuDataResponseReceipt,
    FutuFrozenConclusionReceipt,
    FutuObservation,
    FutuSecurityIdentityReceipt,
    FutuSupplyChainReceipt,
    SignatureVerifier,
    evaluate_futu_authority,
)
from .futu_session import (
    FutuMarketExecutionEvidence,
    FutuPeerEvidenceSet,
    FutuSessionEvidence,
    finalize_futu_session_evidence,
    validate_futu_market_execution_evidence,
    validate_futu_session_evidence_replay,
)
from .futu_sidecar import (
    FutuAttestedSessionFinalization,
    FutuDailyCloseAdapterResult,
    FutuRequestSpec,
    FutuSidecarExecution,
    adapt_futu_daily_close_to_market_reference,
    load_protocol_registry,
)
from .validation import ContractGraph
from .valuation_current_share_compiler import CurrentShareCompilationResult
from .valuation_handoff_policies import (
    MARKET_REFERENCE_POLICY_ID,
    MARKET_REFERENCE_POLICY_VERSION,
)
from .valuation_handoff_validation import (
    claim_control_fingerprint,
    future_request_v2_mapping_fingerprint,
    market_evidence_closure_sha256,
    parser_replay_fingerprint,
)
from .valuation_market_access import (
    GovernedMarketQuoteReceipt,
    MarketAccessResult,
    MarketProviderQuery,
    _current_authorization,
    _graph_already_consumed,
)
from .valuation_market_authority import load_market_access_authority
from .valuation_market_calendar import CalendarSelection, select_latest_completed_session
from .valuation_market_execution_policies import (
    MARKET_QUOTE_POLICY_ID,
    MARKET_QUOTE_POLICY_VERSION,
    phase5e_policy_sha256,
)
from .valuation_market_execution_types import MarketQuoteReceipt, MarketQuoteRequest
from .valuation_market_provider import (
    MarketAuthorizationConsumption,
    MarketAuthorizationReservation,
    MarketReferenceRequest,
    RunClock,
    _authorization_store_root,
    _complete_market_authorization,
    _reserve_market_authorization,
    _timestamp,
    _verify_authorization_consumption,
    exact_decimal_product,
)
from .valuation_market_reference_types import MarketReferenceValidationContext
from .valuation_market_runtime import assert_secret_free_surface
from .valuation_market_snapshot import (
    PreparedMarketReference,
    _append_unique,
    _fact_number,
    _graph_with_current_share_lineage,
)
from .valuation_price_blind_freeze import (
    PriceBlindFreezeCompilationResult,
    load_price_blind_input_artifact,
)
from .valuation_security_identity import (
    SecurityIdentityCompilationResult,
    compile_security_identity,
)
from .valuation_share_event_integration_types import CurrentShareEvidenceClosureV2

FUTU_MARKET_PROVIDER_ID = "provider:futu-opend-sidecar"
FUTU_MARKET_PROVIDER_VERSION = "1.0.0"
FUTU_MARKET_ENDPOINT_ID = "futu-opend-quote-only-sidecar"
FUTU_MARKET_AUTHORITY_KIND = "governed_vendor"
FUTU_MARKET_EVIDENCE_MODE = "governed_vendor"
FUTU_MARKET_USAGE_SCOPE = "production"
FUTU_MARKET_PRICE_BASIS = "official_unadjusted_close"
FUTU_MARKET_SESSION_KIND = "regular"
FUTU_MARKET_CONTENT_TYPE = "application/octet-stream"
FUTU_MARKET_PROTOCOL_ID = 3103
FUTU_MARKET_SOURCE_URL = (
    "https://openapi.futunn.com/futu-api-doc/en/quote/request-history-kline.html"
)
_RTH_REQUESTED_DAILY_CLOSE_QUALIFIERS = FrozenMap(
    {
        "autype": "NONE",
        "ktype": "K_DAY",
        "price_basis": "vendor_unadjusted_daily_close_rth_requested",
        "rth_semantics_attested": False,
        "session": "RTH",
    }
)
_PROTOCOL_REGISTRY_PATH = Path(__file__).parent / "resources" / "futu" / (
    "protocol-registry-v1.json"
)
_FUTU_POLICY_PATH = Path(__file__).parent / "resources" / "futu" / (
    "market-authority-policy-v2.json"
)
_SOURCE_FUTU_POLICY_NAME = "phase5e-futu-market-authority-policy-v2.json"


def _sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _bridge_code_sha256() -> str:
    return hashlib.sha256(
        _read_bounded_regular_file_nofollow(Path(__file__))
    ).hexdigest()


def _protocol_registry_sha256() -> str:
    return hashlib.sha256(
        _read_bounded_regular_file_nofollow(_PROTOCOL_REGISTRY_PATH)
    ).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate component-lock key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite component-lock value: {value}")


def _local_governance(component_lock_path: Path) -> tuple[str, str]:
    """Bind the bridge to the exact installed lock, policy, code, and registry bytes."""

    lock_raw = _read_bounded_regular_file_nofollow(Path(component_lock_path))
    lock = json.loads(
        lock_raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_json_constant,
    )
    try:
        manifest = lock["owner_equity_research"]["pr3_comprehensive"]
        modules = manifest["module_sha256"]
        resources = manifest["futu_resource_sha256"]
        policy = manifest["futu_authority_policy"]
    except (KeyError, TypeError) as exc:
        raise ValueError("component lock lacks the comprehensive Futu manifest") from exc
    try:
        policy_raw = _read_bounded_regular_file_nofollow(_FUTU_POLICY_PATH)
    except FileNotFoundError:
        policy_raw = _read_bounded_regular_file_nofollow(
            Path(component_lock_path).parent / "scripts" / _SOURCE_FUTU_POLICY_NAME
        )
    bridge_sha = _bridge_code_sha256()
    registry_sha = _protocol_registry_sha256()
    policy_sha = hashlib.sha256(policy_raw).hexdigest()
    if (
        modules.get(Path(__file__).name) != bridge_sha
        or resources.get("resources/futu/protocol-registry-v1.json") != registry_sha
        or policy.get("path") != "resources/futu/market-authority-policy-v2.json"
        or policy.get("sha256") != policy_sha
    ):
        raise ValueError("installed Futu bridge governance drifted from component lock")
    return hashlib.sha256(lock_raw).hexdigest(), policy_sha


@dataclass(frozen=True, slots=True)
class FutuMarketProviderRegistration:
    """Closed, component-owned projection of the signed Futu supply chain."""

    schema_version: str
    provider_id: str
    provider_version: str
    authority_kind: str
    evidence_mode: str
    endpoint_id: str
    price_basis: str
    session_kind: str
    protocol_id: int
    protocol_name: str
    supported_mics: tuple[str, ...]
    supported_currencies: tuple[str, ...]
    protocol_registry_sha256: str
    bridge_code_sha256: str
    component_lock_sha256: str
    authority_policy_sha256: str
    supply_chain_fingerprint: str
    adapter_sha256: str
    parser_sha256: str

    def __post_init__(self) -> None:
        protocol = load_protocol_registry().get(FUTU_MARKET_PROTOCOL_ID)
        if (
            self.schema_version != FUTU_SCHEMA_VERSION
            or self.provider_id != FUTU_MARKET_PROVIDER_ID
            or self.provider_version != FUTU_MARKET_PROVIDER_VERSION
            or self.authority_kind != FUTU_MARKET_AUTHORITY_KIND
            or self.evidence_mode != FUTU_MARKET_EVIDENCE_MODE
            or self.endpoint_id != FUTU_MARKET_ENDPOINT_ID
            or self.price_basis != FUTU_MARKET_PRICE_BASIS
            or self.session_kind != FUTU_MARKET_SESSION_KIND
            or self.protocol_id != FUTU_MARKET_PROTOCOL_ID
            or protocol is None
            or protocol["name"] != self.protocol_name
            or protocol["data_family"] != "market_price"
            or protocol["stage"] != "market_reference"
            or not protocol["required_for_complete"]
            or self.supported_mics != ("XNAS", "XNYS")
            or self.supported_currencies != ("USD",)
            or self.protocol_registry_sha256 != _protocol_registry_sha256()
            or self.bridge_code_sha256 != _bridge_code_sha256()
        ):
            raise ValueError("Futu market provider registration is outside the closed registry")
        for value, label in (
            (self.protocol_registry_sha256, "protocol registry SHA"),
            (self.bridge_code_sha256, "bridge code SHA"),
            (self.component_lock_sha256, "component lock SHA"),
            (self.authority_policy_sha256, "authority policy SHA"),
            (self.supply_chain_fingerprint, "supply-chain fingerprint"),
            (self.adapter_sha256, "adapter SHA"),
            (self.parser_sha256, "parser SHA"),
        ):
            _sha256(value, label)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _registration(
    supply_chain: FutuSupplyChainReceipt,
    *,
    component_lock_path: Path,
) -> FutuMarketProviderRegistration:
    if type(supply_chain) is not FutuSupplyChainReceipt:
        raise TypeError("Futu market registration requires the exact signed supply-chain receipt")
    if (
        supply_chain.provider_id != FUTU_MARKET_PROVIDER_ID
        or supply_chain.provider_version != FUTU_MARKET_PROVIDER_VERSION
        or supply_chain.daily_close_semantics_evidence_kind
        not in {"pinned_opend_proto_canary", "written_authority"}
        or supply_chain.daily_close_semantics_evidence_sha256 is None
    ):
        raise ValueError("Futu supply chain is not registered for governed daily close")
    component_lock_sha256, authority_policy_sha256 = _local_governance(
        component_lock_path
    )
    if (
        supply_chain.component_lock_sha256 != component_lock_sha256
        or supply_chain.policy_sha256 != authority_policy_sha256
    ):
        raise ValueError("Futu supply chain is bound to another installed authority")
    protocol = load_protocol_registry()[FUTU_MARKET_PROTOCOL_ID]
    return FutuMarketProviderRegistration(
        schema_version=FUTU_SCHEMA_VERSION,
        provider_id=supply_chain.provider_id,
        provider_version=supply_chain.provider_version,
        authority_kind=FUTU_MARKET_AUTHORITY_KIND,
        evidence_mode=FUTU_MARKET_EVIDENCE_MODE,
        endpoint_id=FUTU_MARKET_ENDPOINT_ID,
        price_basis=FUTU_MARKET_PRICE_BASIS,
        session_kind=FUTU_MARKET_SESSION_KIND,
        protocol_id=FUTU_MARKET_PROTOCOL_ID,
        protocol_name=str(protocol["name"]),
        supported_mics=("XNAS", "XNYS"),
        supported_currencies=("USD",),
        protocol_registry_sha256=_protocol_registry_sha256(),
        bridge_code_sha256=_bridge_code_sha256(),
        component_lock_sha256=component_lock_sha256,
        authority_policy_sha256=authority_policy_sha256,
        supply_chain_fingerprint=supply_chain.fingerprint,
        adapter_sha256=supply_chain.adapter_sha256,
        parser_sha256=supply_chain.parser_sha256,
    )


def _provider_registry_sha256(registration: FutuMarketProviderRegistration) -> str:
    return canonical_sha256(
        {
            "registry_id": "owner-research-futu-market-providers",
            "registry_version": FUTU_SCHEMA_VERSION,
            "unknown_provider_policy": "reject",
            "registrations": (registration.fingerprint,),
        }
    )


@dataclass(frozen=True, slots=True)
class FutuMarketAuthorizationTicket:
    """Durable pre-sidecar reservation for one price-blind market Handoff."""

    request: MarketReferenceRequest
    market_quote_request: MarketQuoteRequest
    calendar_selection: CalendarSelection
    registration: FutuMarketProviderRegistration
    provider_registry_sha256: str
    authority_set: FutuAuthoritySet
    authority_decision: FutuAuthorityDecision
    security_identity: FutuSecurityIdentityReceipt
    supply_chain: FutuSupplyChainReceipt
    expected_freeze_result: PriceBlindFreezeCompilationResult
    expected_security_result: SecurityIdentityCompilationResult
    contract_graph: ContractGraph = field(repr=False)
    reservation: MarketAuthorizationReservation
    _contract_graph_fingerprint: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.request) is not MarketReferenceRequest
            or type(self.market_quote_request) is not MarketQuoteRequest
            or type(self.calendar_selection) is not CalendarSelection
            or type(self.registration) is not FutuMarketProviderRegistration
            or type(self.authority_set) is not FutuAuthoritySet
            or type(self.authority_decision) is not FutuAuthorityDecision
            or type(self.security_identity) is not FutuSecurityIdentityReceipt
            or type(self.supply_chain) is not FutuSupplyChainReceipt
            or type(self.expected_freeze_result)
            is not PriceBlindFreezeCompilationResult
            or type(self.expected_security_result)
            is not SecurityIdentityCompilationResult
            or type(self.contract_graph) is not ContractGraph
            or type(self.reservation) is not MarketAuthorizationReservation
        ):
            raise TypeError("Futu market ticket requires exact component-owned authorities")
        _sha256(self.provider_registry_sha256, "Futu provider registry SHA")
        graph_fingerprint = _premarket_contract_graph_fingerprint(self.contract_graph)
        object.__setattr__(
            self,
            "_contract_graph_fingerprint",
            graph_fingerprint,
        )
        installed_lock_sha256, installed_policy_sha256 = _local_governance(
            self.contract_graph.component_lock_path
        )
        replayed_security = compile_security_identity(
            graph=self.contract_graph,
            expected_freeze=self.expected_freeze_result,
            proposal=self.expected_security_result.proposal,
        )
        request = self.request
        low = self.market_quote_request
        decision = self.authority_decision
        authority_set = self.authority_set
        legal = authority_set.legal
        account = authority_set.account
        runtime_authorization = authority_set.runtime_authorization
        if (
            authority_set.runtime is not None
            or legal is None
            or account is None
            or runtime_authorization is None
            or authority_set.security_identity != self.security_identity
            or authority_set.supply_chain != self.supply_chain
            or decision.status != "eligible"
            or decision.evaluation_scope != "live_preflight"
            or decision.receipt_fingerprints.get("legal") != legal.fingerprint
            or decision.receipt_fingerprints.get("account") != account.fingerprint
            or decision.receipt_fingerprints.get("runtime_authorization")
            != runtime_authorization.fingerprint
            or decision.security_identity_fingerprint != self.security_identity.fingerprint
            or decision.receipt_fingerprints.get("supply_chain")
            != self.supply_chain.fingerprint
            or decision.component_lock_sha256 != self.registration.component_lock_sha256
            or decision.policy_sha256 != self.registration.authority_policy_sha256
            or installed_lock_sha256 != self.registration.component_lock_sha256
            or installed_policy_sha256 != self.registration.authority_policy_sha256
            or self.security_identity.component_lock_sha256
            != self.registration.component_lock_sha256
            or self.security_identity.policy_sha256
            != self.registration.authority_policy_sha256
            or self.supply_chain.component_lock_sha256
            != self.registration.component_lock_sha256
            or self.supply_chain.policy_sha256
            != self.registration.authority_policy_sha256
            or decision.daily_close_semantics_evidence_fingerprint
            != self.supply_chain.daily_close_semantics_evidence_sha256
            or self.security_identity.official_evidence_fingerprint
            != self.expected_security_fingerprint
            or self.registration.supply_chain_fingerprint != self.supply_chain.fingerprint
            or self.provider_registry_sha256 != _provider_registry_sha256(self.registration)
            or self.expected_freeze_result.artifact.fingerprint
            != request.price_blind_input_fingerprint
            or self.expected_security_result.status != "eligible"
            or replayed_security != self.expected_security_result
            or self.expected_security_result.decision is None
            or self.expected_security_result.evidence_closure is None
            or self.expected_security_result.decision.issuer_id != request.issuer_id
            or self.expected_security_result.decision.security_id != request.security_id
            or request.expected_trading_date != self.calendar_selection.session.trading_date
            or request.mic != self.calendar_selection.mic
            or request.request_started_at != low.request_started_at
            or request.authorization_handoff_id != low.authorization_handoff_id
            or request.issuer_id != low.issuer_id
            or request.data_cutoff_date != low.data_cutoff_date
            or request.security_id != low.security_id
            or request.ticker != low.ticker
            or request.mic != low.exchange
            or request.share_class != low.share_class
            or request.quote_currency != low.quote_currency
            or request.quote_currency != low.reporting_currency
            or low.provider_id != self.registration.provider_id
            or low.provider_version != self.registration.provider_version
            or low.provider_registration_sha256 != self.registration.fingerprint
            or low.endpoint != self.registration.endpoint_id
            or low.trading_calendar_id != self.calendar_selection.calendar_id
            or low.price_basis != FUTU_MARKET_PRICE_BASIS
            or low.session_kind != FUTU_MARKET_SESSION_KIND
            or self.reservation.authorization_handoff_id
            != request.authorization_handoff_id
            or self.reservation.authorization_handoff_fingerprint
            != request.authorization_handoff_fingerprint
            or self.reservation.price_blind_input_fingerprint
            != request.price_blind_input_fingerprint
            or self.reservation.request_fingerprint != request.request_fingerprint
            or self.reservation.issuer_id != request.issuer_id
            or self.reservation.security_id != request.security_id
            or self.reservation.reserved_at != request.request_started_at
        ):
            raise ValueError("Futu market ticket authorities do not replay")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": to_json_value(self.request),
            "market_quote_request": self.market_quote_request.to_dict(),
            "calendar_selection": self.calendar_selection.to_dict(),
            "registration": self.registration.to_dict(),
            "provider_registry_sha256": self.provider_registry_sha256,
            "authority_receipt_fingerprints": to_json_value(
                self.authority_decision.receipt_fingerprints
            ),
            "authority_decision": self.authority_decision.to_dict(),
            "security_identity_fingerprint": self.security_identity.fingerprint,
            "supply_chain_fingerprint": self.supply_chain.fingerprint,
            "expected_freeze_result_fingerprint": self.expected_freeze_result.fingerprint,
            "expected_freeze_fingerprint": self.expected_freeze_fingerprint,
            "expected_security_result_fingerprint": self.expected_security_result.fingerprint,
            "expected_security_fingerprint": self.expected_security_fingerprint,
            "contract_graph_fingerprint": self.contract_graph_fingerprint,
            "reservation": self.reservation.to_dict(),
        }

    @property
    def contract_graph_fingerprint(self) -> str:
        return self._contract_graph_fingerprint

    @property
    def expected_freeze_fingerprint(self) -> str:
        return self.expected_freeze_result.fingerprint

    @property
    def expected_security_fingerprint(self) -> str:
        return self.expected_security_result.fingerprint

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _replay_market_ticket(
    ticket: FutuMarketAuthorizationTicket,
) -> FutuMarketAuthorizationTicket:
    if type(ticket) is not FutuMarketAuthorizationTicket:
        raise TypeError("Futu market ticket type is not component-owned")
    _sha256(ticket.contract_graph_fingerprint, "Futu ticket ContractGraph fingerprint")
    return ticket


def reserve_futu_market_reference(
    *,
    price_blind_artifact_directory: Path,
    graph: ContractGraph,
    expected_freeze: PriceBlindFreezeCompilationResult,
    expected_security: SecurityIdentityCompilationResult,
    authority_set: FutuAuthoritySet,
    authority_decision: FutuAuthorityDecision,
    security_identity: FutuSecurityIdentityReceipt,
    supply_chain: FutuSupplyChainReceipt,
    request_started_at: str,
    verifier: SignatureVerifier | None,
) -> FutuMarketAuthorizationTicket:
    """Reserve one Handoff before the caller performs the Futu daily-close request."""

    if type(authority_set) is not FutuAuthoritySet or authority_set.runtime is not None:
        raise TypeError("Futu reservation requires the exact pre-run authority set")
    if (
        authority_set.security_identity != security_identity
        or authority_set.supply_chain != supply_chain
    ):
        raise ValueError("Futu reservation authority set was rebound")
    replayed_authority = evaluate_futu_authority(
        authority_set,
        verifier=verifier,
        now=_timestamp(authority_decision.evaluated_at, "Futu authority evaluation"),
        run_id=authority_decision.run_id,
        policy_sha256=authority_decision.policy_sha256,
        component_lock_sha256=authority_decision.component_lock_sha256,
        required_data_families=("market_price",),
        required_protocol_ids=(FUTU_MARKET_PROTOCOL_ID,),
        purpose="live_preflight",
    )
    if replayed_authority.to_dict() != authority_decision.to_dict():
        raise ValueError("Futu live authority decision does not replay")
    if _graph_already_consumed(graph, expected_freeze):
        raise ValueError("market authorization was already consumed")
    loaded = load_price_blind_input_artifact(
        Path(price_blind_artifact_directory),
        graph=graph,
        expected_result=expected_freeze,
    )
    authorization = loaded.handoffs[-1]
    if authorization.state != "market_reference_allowed" or not _current_authorization(
        graph, loaded
    ):
        raise ValueError("market authorization is not current")
    replayed_security = compile_security_identity(
        graph=graph,
        expected_freeze=loaded,
        proposal=expected_security.proposal,
    )
    if (
        replayed_security != expected_security
        or replayed_security.status != "eligible"
        or replayed_security.decision is None
        or replayed_security.evidence_closure is None
    ):
        raise ValueError("official security identity does not replay")
    security = replayed_security.decision
    artifact = loaded.artifact.to_dict()
    if (
        security_identity.official_evidence_fingerprint != replayed_security.fingerprint
        or security_identity.issuer_id != security.issuer_id
        or security_identity.security_id != security.security_id
        or security_identity.ticker != security.ticker
        or security_identity.mic != security.exchange
        or security_identity.currency != security.quote_currency
        or security_identity.share_class != security.share_class
        or security.quote_currency != security.reporting_currency
        or authority_decision.status != "eligible"
        or authority_decision.evaluation_scope != "live_preflight"
        or authority_decision.security_identity_fingerprint != security_identity.fingerprint
        or authority_decision.receipt_fingerprints.get("supply_chain")
        != supply_chain.fingerprint
        or FUTU_MARKET_PROTOCOL_ID not in authority_decision.allowed_protocol_ids
        or "market_price" not in authority_decision.allowed_data_families
    ):
        raise ValueError("Futu and official security authority do not match")
    started = _timestamp(request_started_at, "Futu market request start")
    if started < _timestamp(authority_decision.evaluated_at, "Futu authority evaluation"):
        raise ValueError("Futu market request precedes its live authority decision")
    market_authority = load_market_access_authority(graph.component_lock_path)
    selection = select_latest_completed_session(
        market_authority,
        mic=security.exchange,
        cutoff_date=date.fromisoformat(authorization.data_cutoff_date),
        observed_at=started,
    )
    registration = _registration(
        supply_chain,
        component_lock_path=graph.component_lock_path,
    )
    request_values = {
        "authorization_handoff_id": authorization.handoff_id,
        "authorization_handoff_fingerprint": authorization.fingerprint,
        "authorization_transitioned_at": authorization.transitioned_at,
        "price_blind_input_fingerprint": artifact["price_blind_input_fingerprint"],
        "issuer_id": security.issuer_id,
        "data_cutoff_date": artifact["data_cutoff_date"],
        "security_id": security.security_id,
        "ticker": security.ticker,
        "mic": security.exchange,
        "share_class": security.share_class,
        "quote_currency": security.quote_currency,
        "expected_trading_date": selection.session.trading_date,
        "request_started_at": request_started_at,
    }
    request = MarketReferenceRequest(
        **request_values,
        request_fingerprint=canonical_sha256(request_values),
    )
    low_values = {
        "request_id": f"market-quote-request:{request.request_fingerprint[:24]}",
        "policy_id": MARKET_QUOTE_POLICY_ID,
        "policy_version": MARKET_QUOTE_POLICY_VERSION,
        "policy_sha256": phase5e_policy_sha256(),
        "authorization_handoff_id": authorization.handoff_id,
        "authorization_transitioned_at": authorization.transitioned_at,
        "issuer_id": security.issuer_id,
        "data_cutoff_date": artifact["data_cutoff_date"],
        "security_id": security.security_id,
        "ticker": security.ticker,
        "exchange": security.exchange,
        "share_class": security.share_class,
        "quote_currency": security.quote_currency,
        "reporting_currency": security.reporting_currency,
        "price_basis": FUTU_MARKET_PRICE_BASIS,
        "session_kind": FUTU_MARKET_SESSION_KIND,
        "provider_id": registration.provider_id,
        "provider_version": registration.provider_version,
        "provider_registration_sha256": registration.fingerprint,
        "endpoint": registration.endpoint_id,
        "trading_calendar_id": selection.calendar_id,
        "request_started_at": request_started_at,
    }
    low_request = MarketQuoteRequest(
        **low_values,
        request_fingerprint=canonical_sha256(low_values),
    )
    _, store_authority_sha256, store_instance_sha256 = _authorization_store_root(
        graph.component_lock_path,
        create=True,
    )
    reservation_identity = canonical_sha256(
        {
            "authorization_handoff_id": authorization.handoff_id,
            "authorization_handoff_fingerprint": authorization.fingerprint,
        }
    )
    reservation = MarketAuthorizationReservation(
        schema_version="1.0.0",
        reservation_id=f"market-authorization-reservation:{reservation_identity[:24]}",
        authorization_handoff_id=authorization.handoff_id,
        authorization_handoff_fingerprint=authorization.fingerprint,
        price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
        request_fingerprint=request.request_fingerprint,
        issuer_id=security.issuer_id,
        security_id=security.security_id,
        reserved_at=request_started_at,
        store_authority_sha256=store_authority_sha256,
        store_instance_sha256=store_instance_sha256,
    )
    _reserve_market_authorization(graph.component_lock_path, reservation)
    return FutuMarketAuthorizationTicket(
        request=request,
        market_quote_request=low_request,
        calendar_selection=selection,
        registration=registration,
        provider_registry_sha256=_provider_registry_sha256(registration),
        authority_set=authority_set,
        authority_decision=authority_decision,
        security_identity=security_identity,
        supply_chain=supply_chain,
        expected_freeze_result=loaded,
        expected_security_result=replayed_security,
        contract_graph=graph,
        reservation=reservation,
    )


def build_futu_daily_close_request_spec(
    ticket: FutuMarketAuthorizationTicket,
) -> FutuRequestSpec:
    """Build the only protocol/parameter shape admitted by a reserved market ticket."""

    if type(ticket) is not FutuMarketAuthorizationTicket:
        raise TypeError("Futu daily-close request requires the exact reserved ticket")
    trading_date = ticket.request.expected_trading_date
    return FutuRequestSpec(
        stage="market_reference",
        protocol_id=FUTU_MARKET_PROTOCOL_ID,
        parameters=FrozenMap(
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
        ),
        expected_trading_date=trading_date,
    )


# The pre-kernel execution projection remains here so no generic provider
# implementation can masquerade as the Futu bridge.


def _market_execution(
    evidence: FutuMarketExecutionEvidence,
) -> tuple[
    FutuSidecarExecution,
    FutuDataRequestReceipt,
    FutuDataResponseReceipt,
    FutuObservation,
]:
    executions = tuple(
        item for item in evidence.executions if item.bundle.stage == "market_reference"
    )
    if len(executions) != 1:
        raise ValueError("Futu checkpoint lacks one exact market-reference execution")
    execution = executions[0]
    requests = tuple(
        item for item in execution.requests if item.protocol_id == FUTU_MARKET_PROTOCOL_ID
    )
    if len(requests) != 1:
        raise ValueError("Futu market execution lacks one exact daily-close request")
    request = requests[0]
    responses = tuple(
        item
        for item in execution.responses
        if item.request_id == request.request_id
        and item.request_fingerprint == request.fingerprint
    )
    if len(responses) != 1:
        raise ValueError("Futu daily-close request lacks one exact response")
    response = responses[0]
    observations = tuple(
        item
        for item in execution.observations
        if item.response_fingerprint == response.fingerprint
        and item.field_id == "close"
        and item.canonical_concept == "futu_unadjusted_daily_close_candidate"
    )
    if len(observations) != 1:
        raise ValueError("Futu daily-close response lacks one exact close observation")
    return execution, request, response, observations[0]


def _validate_governed_rth_daily_close_semantics(
    *,
    ticket: FutuMarketAuthorizationTicket,
    request: FutuDataRequestReceipt,
    observation: FutuObservation,
) -> None:
    spec = build_futu_daily_close_request_spec(ticket)
    evidence = ticket.supply_chain.daily_close_semantics_evidence_sha256
    if (
        request.parameters != spec.parameters
        or request.expected_trading_date != spec.expected_trading_date
        or observation.qualifiers != _RTH_REQUESTED_DAILY_CLOSE_QUALIFIERS
        or evidence is None
        or ticket.authority_decision.daily_close_semantics_evidence_fingerprint
        != evidence
    ):
        raise ValueError(
            "Futu governed RTH daily close lacks its exact signed semantics authority"
        )


@dataclass(frozen=True, slots=True)
class FutuMarketReferenceProvider:
    """Exact completed Futu evidence admitted by a pre-sidecar reservation."""

    provider_id: ClassVar[str] = FUTU_MARKET_PROVIDER_ID
    authority_kind: ClassVar[Literal["governed_vendor"]] = FUTU_MARKET_AUTHORITY_KIND
    ticket: FutuMarketAuthorizationTicket
    market_execution_evidence: FutuMarketExecutionEvidence
    daily_close: FutuDailyCloseAdapterResult
    verifier: SignatureVerifier | None = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self.ticket) is not FutuMarketAuthorizationTicket
            or type(self.market_execution_evidence) is not FutuMarketExecutionEvidence
            or type(self.daily_close) is not FutuDailyCloseAdapterResult
        ):
            raise TypeError("Futu market provider requires exact typed evidence")
        _replay_market_ticket(self.ticket)
        evidence = self.market_execution_evidence
        if evidence.authority_set.runtime is not None:
            raise ValueError("Futu market bridge requires a pre-kernel runtime checkpoint")
        validate_futu_market_execution_evidence(evidence, verifier=self.verifier)
        ticket = self.ticket
        authority_set = evidence.authority_set
        if (
            evidence.authority_decision != ticket.authority_decision
            or authority_set != ticket.authority_set
            or authority_set.security_identity != ticket.security_identity
            or authority_set.supply_chain != ticket.supply_chain
            or evidence.contract_graph is not ticket.contract_graph
            or evidence.contract_graph_fingerprint
            != ticket.contract_graph_fingerprint
            or evidence.executions[0].bundle.issuer_id != ticket.request.issuer_id
            or evidence.executions[0].bundle.security_id != ticket.request.security_id
        ):
            raise ValueError("Futu market execution was rebound to another ticket")
        pre_price, _ = evidence.executions
        freeze_transition = _timestamp(
            ticket.request.authorization_transitioned_at,
            "freeze transition",
        )
        pre_request_times = tuple(item.request_started_at for item in pre_price.requests)
        pre_response_times = tuple(item.retrieved_at for item in pre_price.responses)
        if (
            not pre_request_times
            or not pre_response_times
            or any(
                _timestamp(item, "Futu pre-price request") > freeze_transition
                for item in pre_request_times
            )
            or any(
                _timestamp(item, "Futu pre-price response") > freeze_transition
                for item in pre_response_times
            )
        ):
            raise ValueError("Futu pre-price verification did not precede the frozen Handoff")
        _, request, response, observation = _market_execution(evidence)
        _validate_governed_rth_daily_close_semantics(
            ticket=ticket,
            request=request,
            observation=observation,
        )
        replayed_close = adapt_futu_daily_close_to_market_reference(
            authority=ticket.authority_decision,
            request=request,
            response=response,
            observation=observation,
        )
        if (
            replayed_close != self.daily_close
            or request.authority_decision_fingerprint
            != ticket.authority_decision.fingerprint
            or request.security_identity_fingerprint != ticket.security_identity.fingerprint
            or request.run_id != ticket.authority_decision.run_id
            or request.issuer_id != ticket.request.issuer_id
            or request.security_id != ticket.request.security_id
            or request.data_cutoff_date != ticket.request.data_cutoff_date
            or request.expected_trading_date != ticket.request.expected_trading_date
            or request.request_started_at != ticket.request.request_started_at
            or response.status != "completed"
            or not response.qot_logined
            or self.daily_close.issuer_id != ticket.request.issuer_id
            or self.daily_close.security_id != ticket.request.security_id
            or self.daily_close.trading_date != ticket.request.expected_trading_date
            or self.daily_close.currency != ticket.request.quote_currency
            or self.daily_close.market_reference_basis != FUTU_MARKET_PRICE_BASIS
        ):
            raise ValueError("Futu market provider daily-close evidence does not replay")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ticket_fingerprint": self.ticket.fingerprint,
            "market_execution_evidence_fingerprint": (
                self.market_execution_evidence.fingerprint
            ),
            "daily_close": self.daily_close.to_dict(),
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def bind_futu_market_reference_provider(
    *,
    ticket: FutuMarketAuthorizationTicket,
    market_execution_evidence: FutuMarketExecutionEvidence,
    verifier: SignatureVerifier | None,
) -> FutuMarketReferenceProvider:
    """Bind the signed two-stage pre-kernel checkpoint to its reservation."""

    _, request, response, observation = _market_execution(market_execution_evidence)
    _validate_governed_rth_daily_close_semantics(
        ticket=ticket,
        request=request,
        observation=observation,
    )
    daily_close = adapt_futu_daily_close_to_market_reference(
        authority=ticket.authority_decision,
        request=request,
        response=response,
        observation=observation,
    )
    return FutuMarketReferenceProvider(
        ticket=ticket,
        market_execution_evidence=market_execution_evidence,
        daily_close=daily_close,
        verifier=verifier,
    )


@dataclass(frozen=True, slots=True)
class FutuMarketReferenceAcquisition:
    """Replayable vendor acquisition retained by the Snapshot validation context."""

    ticket: FutuMarketAuthorizationTicket
    market_execution_evidence: FutuMarketExecutionEvidence
    execution: FutuSidecarExecution
    request: FutuDataRequestReceipt
    response: FutuDataResponseReceipt
    observation: FutuObservation
    daily_close: FutuDailyCloseAdapterResult
    access_result: MarketAccessResult
    authorization_consumption: MarketAuthorizationConsumption
    verifier: SignatureVerifier | None = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self.ticket) is not FutuMarketAuthorizationTicket
            or type(self.market_execution_evidence) is not FutuMarketExecutionEvidence
            or type(self.execution) is not FutuSidecarExecution
            or type(self.request) is not FutuDataRequestReceipt
            or type(self.response) is not FutuDataResponseReceipt
            or type(self.observation) is not FutuObservation
            or type(self.daily_close) is not FutuDailyCloseAdapterResult
            or type(self.access_result) is not MarketAccessResult
            or type(self.authorization_consumption) is not MarketAuthorizationConsumption
        ):
            raise TypeError("Futu acquisition requires exact typed authorities")
        provider = FutuMarketReferenceProvider(
            ticket=self.ticket,
            market_execution_evidence=self.market_execution_evidence,
            daily_close=self.daily_close,
            verifier=self.verifier,
        )
        expected_execution, expected_request, expected_response, expected_observation = (
            _market_execution(self.market_execution_evidence)
        )
        consumption = self.authorization_consumption
        access = self.access_result
        if (
            provider.fingerprint != canonical_sha256(provider.to_dict())
            or self.execution != expected_execution
            or self.request != expected_request
            or self.response != expected_response
            or self.observation != expected_observation
            or access.status != "eligible"
            or access.request != self.ticket.market_quote_request
            or access.receipt is None
            or access.receipt.evidence_mode != FUTU_MARKET_EVIDENCE_MODE
            or access.receipt.raw_response_sha256 != self.response.raw_plaintext_sha256
            or consumption.authorization_handoff_id
            != self.ticket.request.authorization_handoff_id
            or consumption.authorization_handoff_fingerprint
            != self.ticket.request.authorization_handoff_fingerprint
            or consumption.price_blind_input_fingerprint
            != self.ticket.request.price_blind_input_fingerprint
            or consumption.request_fingerprint != self.ticket.request.request_fingerprint
            or consumption.market_access_result_fingerprint != access.fingerprint
            or consumption.quote_fingerprint != self.daily_close.adapter_fingerprint
            or consumption.review_receipt_sha256
            != self.market_execution_evidence.fingerprint
            or consumption.raw_response_sha256 != self.response.raw_plaintext_sha256
            or consumption.consumed_at != self.response.retrieved_at
            or consumption.reservation_fingerprint != self.ticket.reservation.fingerprint
            or consumption.store_authority_sha256
            != self.ticket.reservation.store_authority_sha256
            or consumption.store_instance_sha256
            != self.ticket.reservation.store_instance_sha256
        ):
            raise ValueError("Futu market acquisition authorities do not replay")

    @property
    def market_execution_evidence_fingerprint(self) -> str:
        return self.market_execution_evidence.fingerprint

    @property
    def expected_freeze_fingerprint(self) -> str:
        return self.ticket.expected_freeze_fingerprint

    def to_dict(self) -> dict[str, Any]:
        return {
            "ticket_fingerprint": self.ticket.fingerprint,
            "market_execution_evidence_fingerprint": (
                self.market_execution_evidence.fingerprint
            ),
            "execution_bundle_fingerprint": self.execution.bundle.fingerprint,
            "request_fingerprint": self.request.fingerprint,
            "response_fingerprint": self.response.fingerprint,
            "observation_fingerprint": self.observation.fingerprint,
            "daily_close_adapter_fingerprint": self.daily_close.adapter_fingerprint,
            "access_result": self.access_result.to_dict(),
            "authorization_consumption": self.authorization_consumption.to_dict(),
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _governed_access(
    *,
    graph: ContractGraph,
    expected_freeze: PriceBlindFreezeCompilationResult,
    expected_security: SecurityIdentityCompilationResult,
    provider: FutuMarketReferenceProvider,
    clock: RunClock,
) -> tuple[
    MarketAccessResult,
    FutuSidecarExecution,
    FutuDataRequestReceipt,
    FutuDataResponseReceipt,
    FutuObservation,
]:
    ticket = provider.ticket
    execution, request, response, observation = _market_execution(
        provider.market_execution_evidence
    )
    if (
        type(clock) is not RunClock
        or clock.request_started_at != ticket.request.request_started_at
        or clock.retrieved_at != response.retrieved_at
    ):
        raise ValueError("Futu bridge clock does not replay the sidecar request and response")
    security = expected_security.decision
    closure = expected_security.evidence_closure
    if security is None or closure is None:
        raise ValueError("Futu market access lacks official security evidence")
    selection = ticket.calendar_selection
    registration = ticket.registration
    low_request = ticket.market_quote_request
    artifact = expected_freeze.artifact.to_dict()
    query = MarketProviderQuery(
        authorization_handoff_id=low_request.authorization_handoff_id,
        issuer_id=low_request.issuer_id,
        data_cutoff_date=low_request.data_cutoff_date,
        security_id=low_request.security_id,
        ticker=low_request.ticker,
        exchange=low_request.exchange,
        share_class=low_request.share_class,
        quote_currency=low_request.quote_currency,
        reporting_currency=low_request.reporting_currency,
        trading_calendar_id=low_request.trading_calendar_id,
        expected_trading_date=provider.daily_close.trading_date,
        price_basis=FUTU_MARKET_PRICE_BASIS,
        session_kind=FUTU_MARKET_SESSION_KIND,
    )
    receipt = MarketQuoteReceipt(
        receipt_id=f"market-quote-receipt:{response.fingerprint[:24]}",
        request_id=low_request.request_id,
        request_fingerprint=low_request.request_fingerprint,
        authorization_handoff_id=low_request.authorization_handoff_id,
        authorization_transitioned_at=low_request.authorization_transitioned_at,
        issuer_id=low_request.issuer_id,
        data_cutoff_date=low_request.data_cutoff_date,
        security_id=low_request.security_id,
        ticker=low_request.ticker,
        exchange=low_request.exchange,
        share_class=low_request.share_class,
        provider_id=registration.provider_id,
        provider_version=registration.provider_version,
        endpoint=registration.endpoint_id,
        trading_calendar_id=selection.calendar_id,
        request_started_at=low_request.request_started_at,
        retrieved_at=response.retrieved_at,
        trading_date=provider.daily_close.trading_date,
        latest_completed_session_date=selection.session.trading_date,
        quote_timestamp=selection.session.closed_at,
        session_kind=FUTU_MARKET_SESSION_KIND,
        session_status="completed",
        instrument_status="active",
        price_basis=FUTU_MARKET_PRICE_BASIS,
        quote_price=provider.daily_close.close_decimal,
        quote_currency=provider.daily_close.currency,
        raw_response_sha256=response.raw_plaintext_sha256,
    )
    market_authority = load_market_access_authority(graph.component_lock_path)
    governed = GovernedMarketQuoteReceipt(
        receipt=receipt,
        authority_sha256=canonical_sha256(
            {
                "live_authority_decision": ticket.authority_decision.fingerprint,
                "runtime_authorization": (
                    provider.market_execution_evidence.authority_set.runtime_authorization.fingerprint
                ),
                "market_execution_evidence": (
                    provider.market_execution_evidence.fingerprint
                ),
            }
        ),
        provider_registry_sha256=ticket.provider_registry_sha256,
        provider_registration_sha256=registration.fingerprint,
        adapter_sha256=registration.adapter_sha256,
        parser_sha256=registration.parser_sha256,
        calendar_registry_sha256=canonical_sha256(
            market_authority.calendar_registry.to_dict()
        ),
        calendar_dataset_sha256=selection.dataset_sha256,
        calendar_selection_fingerprint=selection.fingerprint,
        security_compilation_fingerprint=expected_security.fingerprint,
        security_evidence_closure_sha256=closure.closure_sha256,
        raw_response_sha256=response.raw_plaintext_sha256,
        evidence_mode=FUTU_MARKET_EVIDENCE_MODE,
    )
    access = MarketAccessResult(
        status="eligible",
        issuer_id=artifact["issuer_id"],
        data_cutoff_date=artifact["data_cutoff_date"],
        authorization_handoff_id=low_request.authorization_handoff_id,
        price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
        protected_mckinsey_sha256=artifact["protected_mckinsey_sha256"],
        protected_penman_assumptions_sha256=artifact[
            "protected_penman_assumptions_sha256"
        ],
        provider_call_count=1,
        query=query,
        request=low_request,
        receipt=governed,
        quarantined_raw_response_sha256=None,
        issue_codes=(),
    )
    assert_secret_free_surface(access.to_dict(), "governed Futu market access")
    return access, execution, request, response, observation


def acquire_futu_market_reference(
    *,
    price_blind_artifact_directory: Path,
    graph: ContractGraph,
    expected_freeze: PriceBlindFreezeCompilationResult,
    expected_security: SecurityIdentityCompilationResult,
    provider: FutuMarketReferenceProvider,
    clock: RunClock,
) -> FutuMarketReferenceAcquisition:
    """Consume one reserved Futu market execution without another provider call."""

    if (
        type(provider) is not FutuMarketReferenceProvider
        or type(provider.ticket) is not FutuMarketAuthorizationTicket
    ):
        raise TypeError("Futu provider implementation is not component-owned")
    ticket = provider.ticket
    _replay_market_ticket(ticket)
    if _graph_already_consumed(graph, expected_freeze):
        raise ValueError("market authorization was already consumed")
    loaded = load_price_blind_input_artifact(
        Path(price_blind_artifact_directory),
        graph=graph,
        expected_result=expected_freeze,
    )
    if (
        loaded.fingerprint != ticket.expected_freeze_fingerprint
        or graph is not ticket.contract_graph
        or not _current_authorization(graph, loaded)
    ):
        raise ValueError("Futu market ticket no longer matches price-blind authority")
    replayed_security = compile_security_identity(
        graph=graph,
        expected_freeze=loaded,
        proposal=expected_security.proposal,
    )
    if (
        replayed_security != expected_security
        or replayed_security.fingerprint != ticket.expected_security_fingerprint
    ):
        raise ValueError("Futu market ticket no longer matches official security authority")
    access, execution, request, response, observation = _governed_access(
        graph=graph,
        expected_freeze=loaded,
        expected_security=replayed_security,
        provider=provider,
        clock=clock,
    )
    consumption_identity = canonical_sha256(
        {
            "handoff": ticket.request.authorization_handoff_id,
            "request": ticket.request.request_fingerprint,
        }
    )
    consumption = MarketAuthorizationConsumption(
        schema_version="1.0.0",
        consumption_id=(
            f"market-authorization-consumption:{consumption_identity[:24]}"
        ),
        authorization_handoff_id=ticket.request.authorization_handoff_id,
        authorization_handoff_fingerprint=(
            ticket.request.authorization_handoff_fingerprint
        ),
        price_blind_input_fingerprint=ticket.request.price_blind_input_fingerprint,
        request_fingerprint=ticket.request.request_fingerprint,
        market_access_result_fingerprint=access.fingerprint,
        quote_fingerprint=provider.daily_close.adapter_fingerprint,
        # This legacy-named slot binds the exact signed Futu market checkpoint for
        # governed-vendor mode.  It is never represented as a human review receipt.
        review_receipt_sha256=provider.market_execution_evidence.fingerprint,
        raw_response_sha256=response.raw_plaintext_sha256,
        consumed_at=response.retrieved_at,
        reservation_fingerprint=ticket.reservation.fingerprint,
        store_authority_sha256=ticket.reservation.store_authority_sha256,
        store_instance_sha256=ticket.reservation.store_instance_sha256,
    )
    _complete_market_authorization(
        graph.component_lock_path,
        ticket.reservation,
        consumption,
    )
    acquisition = FutuMarketReferenceAcquisition(
        ticket=ticket,
        market_execution_evidence=provider.market_execution_evidence,
        execution=execution,
        request=request,
        response=response,
        observation=observation,
        daily_close=provider.daily_close,
        access_result=access,
        authorization_consumption=consumption,
        verifier=provider.verifier,
    )
    _verify_authorization_consumption(
        graph.component_lock_path,
        ticket.reservation,
        consumption,
    )
    return acquisition


def replay_futu_market_reference_acquisition(
    *,
    graph: ContractGraph,
    expected_acquisition: FutuMarketReferenceAcquisition,
) -> FutuMarketReferenceAcquisition:
    """Replay a retained Futu acquisition without reading licensed raw plaintext."""

    if type(expected_acquisition) is not FutuMarketReferenceAcquisition:
        raise TypeError("Futu replay requires the exact acquisition type")
    acquisition = expected_acquisition
    evidence_graph = acquisition.market_execution_evidence.contract_graph
    evidence_graph_fingerprint = _premarket_contract_graph_fingerprint(evidence_graph)
    if (
        evidence_graph is not acquisition.ticket.contract_graph
        or evidence_graph_fingerprint
        != acquisition.market_execution_evidence.contract_graph_fingerprint
        or evidence_graph_fingerprint != acquisition.ticket.contract_graph_fingerprint
        or graph.component_lock_path != evidence_graph.component_lock_path
        or any(
            any(item not in tuple(getattr(graph, graph_field.name)) for item in expected_items)
            for graph_field in fields(evidence_graph)
            if graph_field.name != "component_lock_path"
            for expected_items in (tuple(getattr(evidence_graph, graph_field.name)),)
        )
    ):
        raise ValueError("Futu acquisition ContractGraph was rebound")
    validate_futu_market_execution_evidence(
        acquisition.market_execution_evidence,
        verifier=acquisition.verifier,
    )
    _verify_authorization_consumption(
        graph.component_lock_path,
        acquisition.ticket.reservation,
        acquisition.authorization_consumption,
    )
    replayed = FutuMarketReferenceAcquisition(
        ticket=acquisition.ticket,
        market_execution_evidence=acquisition.market_execution_evidence,
        execution=acquisition.execution,
        request=acquisition.request,
        response=acquisition.response,
        observation=acquisition.observation,
        daily_close=acquisition.daily_close,
        access_result=acquisition.access_result,
        authorization_consumption=acquisition.authorization_consumption,
        verifier=acquisition.verifier,
    )
    if replayed.fingerprint != acquisition.fingerprint:
        raise ValueError("Futu market acquisition fingerprint changed during replay")
    return acquisition


def _futu_conclusion_run_binding(
    *,
    acquisition: FutuMarketReferenceAcquisition,
    frozen_conclusion: FutuFrozenConclusionReceipt,
) -> ValuationRunResult:
    """Return the exact retained result pair only when its run matches acquisition."""

    from .valuation_run import ValuationRunResult

    if type(frozen_conclusion) is not FutuFrozenConclusionReceipt:
        raise TypeError("Futu completion requires the exact frozen conclusion receipt")
    composite = frozen_conclusion.composite_valuation
    run_result = getattr(composite, "_run_result", None)
    if type(run_result) is not ValuationRunResult or run_result.status != "completed":
        raise ValueError("Futu conclusion lacks its exact completed valuation run")
    if (
        run_result.preparation is None
        or run_result.execution is None
        or run_result.archive is None
        or run_result.input_receipt.graph != acquisition.ticket.contract_graph
        or run_result.input_receipt.expected_freeze
        != acquisition.ticket.expected_freeze_result
        or run_result.input_receipt.expected_security
        != acquisition.ticket.expected_security_result
        or run_result.issuer_id != acquisition.ticket.request.issuer_id
        or run_result.data_cutoff_date != acquisition.ticket.request.data_cutoff_date
        or frozen_conclusion.run_id != acquisition.ticket.authority_decision.run_id
        or frozen_conclusion.issuer_id != acquisition.ticket.request.issuer_id
        or frozen_conclusion.security_id != acquisition.ticket.request.security_id
    ):
        raise ValueError("Futu conclusion was rebound from another valuation run")
    prepared = run_result.preparation.prepared_market_reference
    if prepared is None:
        raise ValueError("Futu conclusion run lacks its prepared market reference")
    contexts = prepared.graph.market_reference_validation_contexts
    if (
        len(contexts) != 1
        or contexts[0].vendor_market_acquisition != acquisition
        or contexts[0].market_access_result != acquisition.access_result
        or prepared.snapshot.market_access_result_fingerprint
        != acquisition.access_result.fingerprint
    ):
        raise ValueError("Futu conclusion was rebound from another valuation run")
    return run_result


def _replay_futu_conclusion_run_binding(
    *,
    acquisition: FutuMarketReferenceAcquisition,
    frozen_conclusion: FutuFrozenConclusionReceipt,
) -> None:
    """Prove the proprietary conclusion came from this exact consumed run."""

    _futu_conclusion_run_binding(
        acquisition=acquisition,
        frozen_conclusion=frozen_conclusion,
    )
    replayed_conclusion = replace(frozen_conclusion)
    if (
        replayed_conclusion != frozen_conclusion
        or replayed_conclusion.fingerprint != frozen_conclusion.fingerprint
    ):
        raise ValueError("Futu frozen conclusion changed during replay")


@dataclass(frozen=True, slots=True)
class FutuMarketSessionCompletion:
    """Post-conclusion proof that the final session extends the kernel checkpoint."""

    acquisition: FutuMarketReferenceAcquisition
    session_evidence: FutuSessionEvidence
    verifier: SignatureVerifier | None = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self.acquisition) is not FutuMarketReferenceAcquisition
            or type(self.session_evidence) is not FutuSessionEvidence
            or type(self.session_evidence.attested_finalization)
            is not FutuAttestedSessionFinalization
        ):
            raise TypeError("Futu session completion requires exact typed evidence")
        acquisition = replay_futu_market_reference_acquisition(
            graph=self.acquisition.market_execution_evidence.contract_graph,
            expected_acquisition=self.acquisition,
        )
        _replay_futu_conclusion_run_binding(
            acquisition=acquisition,
            frozen_conclusion=self.session_evidence.frozen_conclusion,
        )
        validate_futu_session_evidence_replay(
            self.session_evidence,
            verifier=self.verifier,
        )
        checkpoint = acquisition.market_execution_evidence
        session = self.session_evidence
        before = checkpoint.authority_set
        after = session.authority_set
        if (
            before.runtime is not None
            or after.runtime is None
            or session.market_execution_evidence != checkpoint
            or session.peer_evidence_set.price_blind_freeze
            != acquisition.ticket.expected_freeze_result
            or session.authority_decision != checkpoint.authority_decision
            or session.executions[:2] != checkpoint.executions
            or session.contract_graph != checkpoint.contract_graph
            or session.official_operands != checkpoint.official_operands
            or session.cross_checks != checkpoint.cross_checks
            or any(
                getattr(before, name) != getattr(after, name)
                for name in (
                    "legal",
                    "account",
                    "supply_chain",
                    "runtime_authorization",
                    "security_identity",
                )
            )
        ):
            raise ValueError("final Futu session does not extend the market checkpoint")
        post = session.executions[2]
        checkpoint_at = _timestamp(checkpoint.checkpoint_at, "Futu market checkpoint")
        if not post.requests or any(
            _timestamp(item.request_started_at, "Futu post-context request")
            <= checkpoint_at
            for item in post.requests
        ):
            raise ValueError("Futu post-context access did not occur after the checkpoint")
        final_market = _market_execution(checkpoint)[0]
        if final_market != acquisition.execution:
            raise ValueError("final Futu session changed the kernel market execution")

    def to_dict(self) -> dict[str, str]:
        return {
            "market_acquisition_fingerprint": self.acquisition.fingerprint,
            "market_execution_evidence_fingerprint": (
                self.acquisition.market_execution_evidence.fingerprint
            ),
            "final_session_id": self.session_evidence.session_id,
            "final_session_fingerprint": self.session_evidence.fingerprint,
            "attested_finalization_fingerprint": (
                self.session_evidence.attested_finalization.fingerprint
            ),
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def complete_futu_market_session(
    *,
    acquisition: FutuMarketReferenceAcquisition,
    authority_set: FutuAuthoritySet,
    authority_decision: FutuAuthorityDecision,
    peer_evidence_set: FutuPeerEvidenceSet,
    frozen_conclusion: FutuFrozenConclusionReceipt,
    attested_finalization: FutuAttestedSessionFinalization,
    post_valuation_execution: FutuSidecarExecution,
    finalized_at: str,
    verifier: SignatureVerifier | None,
) -> FutuMarketSessionCompletion:
    """Extend the consumed kernel checkpoint only after the conclusion is frozen."""

    if type(acquisition) is not FutuMarketReferenceAcquisition:
        raise TypeError("Futu session completion requires the exact acquisition type")
    if type(attested_finalization) is not FutuAttestedSessionFinalization:
        raise TypeError(
            "Futu session completion requires the exact signed sidecar finalization"
        )
    if authority_set.runtime != attested_finalization.runtime_receipt:
        raise ValueError("Futu signed finalization was rebound to another runtime")
    _futu_conclusion_run_binding(
        acquisition=acquisition,
        frozen_conclusion=frozen_conclusion,
    )
    session_evidence = finalize_futu_session_evidence(
        authority_set=authority_set,
        authority_decision=authority_decision,
        market_execution_evidence=acquisition.market_execution_evidence,
        peer_evidence_set=peer_evidence_set,
        frozen_conclusion=frozen_conclusion,
        attested_finalization=attested_finalization,
        post_valuation_execution=post_valuation_execution,
        finalized_at=finalized_at,
        verifier=verifier,
    )

    return FutuMarketSessionCompletion(
        acquisition=acquisition,
        session_evidence=session_evidence,
        verifier=verifier,
    )


def _futu_calculation_code_sha256() -> str:
    return _bridge_code_sha256()


def build_futu_market_reference_snapshot(
    *,
    graph: ContractGraph,
    expected_freeze: PriceBlindFreezeCompilationResult,
    expected_security: SecurityIdentityCompilationResult,
    acquisition: FutuMarketReferenceAcquisition,
    current_shares: CurrentShareCompilationResult,
) -> PreparedMarketReference:
    """Project the exact encrypted-CAS receipt graph into Snapshot v4."""

    acquisition = replay_futu_market_reference_acquisition(
        graph=graph,
        expected_acquisition=acquisition,
    )
    if current_shares.status != "eligible" or current_shares.share_basis_decision is None:
        raise ValueError("Futu Snapshot requires an eligible current-share compilation")
    access = acquisition.access_result
    request = access.request
    governed = access.receipt
    security = expected_security.decision
    security_closure = expected_security.evidence_closure
    if (
        access.status != "eligible"
        or request is None
        or governed is None
        or security is None
        or security_closure is None
        or expected_freeze.fingerprint != acquisition.expected_freeze_fingerprint
        or expected_security.fingerprint
        != acquisition.ticket.expected_security_fingerprint
    ):
        raise ValueError("Futu Snapshot requires exact market and security authority")
    receipt = governed.receipt
    close = acquisition.daily_close
    response = acquisition.response
    observation = acquisition.observation
    share_fact = current_shares.output_fact
    assert share_fact is not None
    quote_decimal = Decimal(close.close_decimal)
    shares_decimal = Decimal(str(share_fact.value))
    market_equity_decimal = exact_decimal_product(
        close.close_decimal,
        format(shares_decimal, "f"),
    )
    quote_value = _fact_number(quote_decimal, "Futu quote")
    market_equity_value = _fact_number(market_equity_decimal, "Futu market equity")
    raw_sha = response.raw_plaintext_sha256
    source = SourceDocument(
        schema_version="1.0.0",
        document_id=f"doc:{close.issuer_id}:futu-market:{raw_sha[:24]}",
        issuer_id=close.issuer_id,
        document_type="market-quote",
        period={"start": None, "end": close.trading_date},
        published_date=close.trading_date,
        retrieved_at=response.retrieved_at,
        source_url=FUTU_MARKET_SOURCE_URL,
        authority_level="market_reference",
        content_sha256=raw_sha,
    )
    quote_locator = (
        f"market://{request.request_id}/{receipt.receipt_id}/{governed.parser_sha256}"
    )
    quote_fact = Fact(
        schema_version="2.0.0",
        fact_id=(
            f"fact:{close.issuer_id}:futu-close:{close.trading_date}:{raw_sha[:16]}"
        ),
        issuer_id=close.issuer_id,
        concept="market_quote_close",
        value_type="number",
        value=quote_value,
        unit="currency_per_share",
        currency=close.currency,
        period={"start": None, "end": close.trading_date},
        source_document_id=source.document_id,
        source_locator=quote_locator,
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    calculation_payload = {
        "schema_version": "2.0.0",
        "calculation_id": (
            f"calc:{close.issuer_id}:futu-market-equity:"
            f"{close.trading_date}:{raw_sha[:16]}"
        ),
        "issuer_id": close.issuer_id,
        "concept": "market_equity_value",
        "value_type": "number",
        "value": market_equity_value,
        "unit": "currency_units",
        "currency": close.currency,
        "period": {"start": None, "end": close.trading_date},
        "calculator_id": "futu-governed-close-times-current-common-shares",
        "calculator_version": FUTU_SCHEMA_VERSION,
        "code_sha256": _futu_calculation_code_sha256(),
        "input_fact_ids": (quote_fact.fact_id, share_fact.fact_id),
        "input_assumption_ids": (),
        "input_calculation_ids": (),
        "input_period_ids": (),
        "input_bindings": {
            "quote": quote_fact.fact_id,
            "current_common_shares": share_fact.fact_id,
        },
        "generated_at": response.retrieved_at,
    }
    calculation = build_calculation_result(
        calculation_payload,
        facts={quote_fact.fact_id: quote_fact, share_fact.fact_id: share_fact},
        assumptions={},
        calculations={},
    )
    working = _graph_with_current_share_lineage(graph, current_shares)
    working = replace(
        working,
        documents=_append_unique(working.documents, source, "document_id"),
        facts=_append_unique(working.facts, quote_fact, "fact_id"),
        calculations=_append_unique(
            working.calculations,
            calculation,
            "calculation_id",
        ),
    )
    context = MarketReferenceValidationContext(
        context_id=(
            f"market-reference-context:{close.issuer_id}:"
            f"{close.trading_date}:{raw_sha[:16]}"
        ),
        price_blind_artifact=expected_freeze.artifact,
        security_compilation_result=expected_security,
        market_access_result=access,
        current_share_compilation_result=current_shares,
        raw_evidence_locator=response.cas_locator,
        provider_evidence_sha256=acquisition.market_execution_evidence.fingerprint,
        vendor_market_acquisition=acquisition,
    )
    authority = context.claim_control_authority
    share_closure = current_shares.evidence_closure
    assert share_closure is not None
    numeric_roots = tuple(
        sorted(
            share_closure.ultimate_numeric_root_fact_ids
            if isinstance(share_closure, CurrentShareEvidenceClosureV2)
            else share_closure.numeric_root_fact_ids
        )
    )
    excluded_roots = tuple(sorted(authority.excluded_option_root_fact_ids))
    claim_control = {
        "status": "passed",
        "current_share_numeric_root_fact_ids": numeric_roots,
        "included_claim_root_fact_ids": (),
        "excluded_claim_root_fact_ids": excluded_roots,
        "blocked_claim_root_fact_ids": (),
        "overlap_fact_ids": (),
        "check_fingerprint": claim_control_fingerprint(
            price_blind_input_fingerprint=access.price_blind_input_fingerprint,
            share_basis_decision_fingerprint=(
                current_shares.share_basis_decision.fingerprint
            ),
            claim_control_authority_fingerprint=authority.fingerprint,
            current_share_numeric_root_fact_ids=numeric_roots,
            excluded_claim_root_fact_ids=excluded_roots,
        ),
    }
    evidence_bindings = tuple(
        {
            "contract_type": contract_type,
            "object_id": object_id,
            "fingerprint": fingerprint,
        }
        for contract_type, object_id, fingerprint in share_closure.object_fingerprints
        if contract_type in {"SourceDocument", "Fact", "Claim"}
        and object_id
        in set(current_shares.share_basis_decision.corporate_action_evidence_ids)
    )
    authorization = expected_freeze.handoffs[-1]
    numeric_encoding = (
        "ieee754_binary64"
        if observation.binary64_hex is not None
        else "canonical_decimal"
    )
    payload: dict[str, Any] = {
        "schema_version": "4.0.0",
        "snapshot_id": (
            f"market-reference:{close.issuer_id}:{close.trading_date}:{raw_sha[:20]}"
        ),
        "issuer_id": close.issuer_id,
        "data_cutoff_date": access.data_cutoff_date,
        "status": "validated",
        "market_policy_id": MARKET_REFERENCE_POLICY_ID,
        "market_policy_version": MARKET_REFERENCE_POLICY_VERSION,
        "authorization_handoff_id": authorization.handoff_id,
        "authorization_handoff_fingerprint": authorization.fingerprint,
        "component_lock_sha256": acquisition.ticket.registration.component_lock_sha256,
        "market_access_result_fingerprint": access.fingerprint,
        "market_quote_request": {
            "request_id": request.request_id,
            "request_fingerprint": request.request_fingerprint,
        },
        "governed_market_quote_receipt": {
            "receipt_id": receipt.receipt_id,
            "receipt_fingerprint": governed.fingerprint,
        },
        "authority_lineage": {
            "authority_sha256": governed.authority_sha256,
            "provider_registry_sha256": governed.provider_registry_sha256,
            "provider_registration_sha256": governed.provider_registration_sha256,
            "adapter_sha256": governed.adapter_sha256,
            "parser_sha256": governed.parser_sha256,
            "calendar_registry_sha256": governed.calendar_registry_sha256,
            "calendar_dataset_sha256": governed.calendar_dataset_sha256,
            "calendar_selection_fingerprint": governed.calendar_selection_fingerprint,
            "provider_evidence_sha256": acquisition.market_execution_evidence.fingerprint,
        },
        "security": {
            "security_id": security.security_id,
            "ticker": security.ticker,
            "mic": security.exchange,
            "share_class": security.share_class,
            "security_compilation_fingerprint": expected_security.fingerprint,
            "security_evidence_closure_sha256": security_closure.closure_sha256,
        },
        "trading_date": close.trading_date,
        "quote_timestamp": receipt.quote_timestamp,
        "quote_retrieved_at": response.retrieved_at,
        "quote_price_decimal": close.close_decimal,
        "quote_unit": "currency_per_share",
        "quote_currency": close.currency,
        "source_authority_kind": FUTU_MARKET_AUTHORITY_KIND,
        "evidence_mode": FUTU_MARKET_EVIDENCE_MODE,
        "usage_scope": FUTU_MARKET_USAGE_SCOPE,
        "numeric_evidence": {
            "encoding": numeric_encoding,
            "authoritative_decimal": close.close_decimal,
            "binary64_hex": observation.binary64_hex,
        },
        "raw_evidence": {
            "store_kind": "content_addressed_store",
            "locator": response.cas_locator,
            "content_type": FUTU_MARKET_CONTENT_TYPE,
            "raw_response_sha256": response.raw_plaintext_sha256,
            "parser_replay_fingerprint": "0" * 64,
        },
        "quote_source_document_id": source.document_id,
        "quote_source_locator": quote_locator,
        "quote_fact_id": quote_fact.fact_id,
        "share_basis": {
            "decision_id": current_shares.share_basis_decision.decision_id,
            "decision_fingerprint": current_shares.share_basis_decision.fingerprint,
            "basis_kind": current_shares.share_basis_decision.basis_kind,
            "evidence_kind": current_shares.share_basis_decision.evidence_kind,
            "as_of_date": current_shares.share_basis_decision.as_of_date,
            "quote_date": current_shares.share_basis_decision.quote_date,
            "shares_outstanding_fact_id": share_fact.fact_id,
            "current_common_shares_outstanding_decimal": format(shares_decimal, "f"),
            "share_unit": "shares",
            "split_factor_decimal": current_shares.share_basis_decision.split_factor,
            "corporate_action_evidence_bindings": evidence_bindings,
            "claim_control_check": claim_control,
        },
        "market_equity": {
            "calculation_id": calculation.calculation_id,
            "value_decimal": format(market_equity_decimal, "f"),
            "unit": "currency_units",
            "currency": close.currency,
        },
        "price_blind_input_fingerprint": access.price_blind_input_fingerprint,
        "protected_mckinsey_sha256": access.protected_mckinsey_sha256,
        "protected_penman_assumptions_sha256": (
            access.protected_penman_assumptions_sha256
        ),
        "future_kernel_request_v2": {
            "share_denominator_fact_id": share_fact.fact_id,
            "share_denominator_kind": "current_common_shares_outstanding",
            "share_denominator_evidence_kind": (
                current_shares.share_basis_decision.evidence_kind
            ),
            "mapping_fingerprint": future_request_v2_mapping_fingerprint(
                price_blind_input_fingerprint=access.price_blind_input_fingerprint,
                shares_outstanding_fact_id=share_fact.fact_id,
                evidence_kind=current_shares.share_basis_decision.evidence_kind,
            ),
        },
        "market_evidence_closure_sha256": "0" * 64,
        "snapshot_fingerprint": "0" * 64,
    }
    payload["raw_evidence"]["parser_replay_fingerprint"] = parser_replay_fingerprint(
        payload,
        receipt,
    )
    working_with_context = replace(
        working,
        market_reference_validation_contexts=(
            *working.market_reference_validation_contexts,
            context,
        ),
    )
    payload["market_evidence_closure_sha256"] = market_evidence_closure_sha256(
        working_with_context,
        payload,
        authorization,
        context,
    )
    fingerprint_payload = dict(payload)
    fingerprint_payload.pop("snapshot_fingerprint")
    payload["snapshot_fingerprint"] = canonical_sha256(fingerprint_payload)
    snapshot = MarketReferenceSnapshot(**payload)
    final_graph = replace(
        working_with_context,
        market_reference_snapshots=(
            *working_with_context.market_reference_snapshots,
            snapshot,
        ),
    )
    final_graph.validate()
    return PreparedMarketReference(
        snapshot=snapshot,
        market_source=source,
        quote_fact=quote_fact,
        market_equity_calculation=calculation,
        current_shares=current_shares,
        graph=final_graph,
    )


def validate_futu_snapshot_projection(
    *,
    graph: ContractGraph,
    snapshot: MarketReferenceSnapshot,
    context: MarketReferenceValidationContext,
) -> None:
    """Validate Futu-specific fields that the frozen generic v4 contract cannot derive."""

    acquisition = replay_futu_market_reference_acquisition(
        graph=graph,
        expected_acquisition=context.vendor_market_acquisition,
    )
    _validate_replayed_futu_snapshot_projection(
        graph=graph,
        snapshot=snapshot,
        context=context,
        acquisition=acquisition,
    )


def _validate_replayed_futu_snapshot_projection(
    *,
    graph: ContractGraph,
    snapshot: MarketReferenceSnapshot,
    context: MarketReferenceValidationContext,
    acquisition: FutuMarketReferenceAcquisition | None,
) -> None:
    """Validate a projection from the exact acquisition replayed by the caller."""

    if (
        type(acquisition) is not FutuMarketReferenceAcquisition
        or acquisition is not context.vendor_market_acquisition
    ):
        raise ValueError("Futu Snapshot projection lacks its exact replayed acquisition")
    access = acquisition.access_result
    governed = access.receipt
    request = access.request
    if governed is None or request is None:
        raise ValueError("Futu Snapshot context is incomplete")
    receipt = governed.receipt
    ticket = acquisition.ticket
    selection = ticket.calendar_selection
    close = acquisition.daily_close
    response = acquisition.response
    observation = acquisition.observation
    expected_authority = canonical_sha256(
        {
            "live_authority_decision": ticket.authority_decision.fingerprint,
            "runtime_authorization": (
                acquisition.market_execution_evidence.authority_set.runtime_authorization.fingerprint
            ),
            "market_execution_evidence": (
                acquisition.market_execution_evidence.fingerprint
            ),
        }
    )
    if (
        snapshot.evidence_mode != FUTU_MARKET_EVIDENCE_MODE
        or snapshot.source_authority_kind != FUTU_MARKET_AUTHORITY_KIND
        or snapshot.usage_scope != FUTU_MARKET_USAGE_SCOPE
        or receipt.provider_id != FUTU_MARKET_PROVIDER_ID
        or receipt.provider_version != FUTU_MARKET_PROVIDER_VERSION
        or receipt.endpoint != FUTU_MARKET_ENDPOINT_ID
        or receipt.price_basis != FUTU_MARKET_PRICE_BASIS
        or receipt.session_kind != FUTU_MARKET_SESSION_KIND
        or governed.authority_sha256 != expected_authority
        or governed.provider_registry_sha256 != ticket.provider_registry_sha256
        or governed.provider_registration_sha256 != ticket.registration.fingerprint
        or governed.adapter_sha256 != ticket.supply_chain.adapter_sha256
        or governed.parser_sha256 != ticket.supply_chain.parser_sha256
        or governed.calendar_dataset_sha256 != selection.dataset_sha256
        or governed.calendar_selection_fingerprint != selection.fingerprint
        or receipt.trading_calendar_id != selection.calendar_id
        or receipt.trading_date != selection.session.trading_date
        or receipt.latest_completed_session_date != selection.session.trading_date
        or receipt.quote_timestamp != selection.session.closed_at
        or receipt.retrieved_at != response.retrieved_at
        or receipt.quote_price != close.close_decimal
        or receipt.quote_currency != close.currency
        or governed.raw_response_sha256 != response.raw_plaintext_sha256
        or snapshot.raw_evidence["locator"] != response.cas_locator
        or snapshot.raw_evidence["raw_response_sha256"]
        != response.raw_plaintext_sha256
        or snapshot.authority_lineage["provider_evidence_sha256"]
        != acquisition.market_execution_evidence.fingerprint
        or snapshot.numeric_evidence["authoritative_decimal"] != close.close_decimal
        or snapshot.numeric_evidence["binary64_hex"] != observation.binary64_hex
    ):
        raise ValueError("Futu Snapshot is not an exact session projection")
    expected_encoding = (
        "ieee754_binary64"
        if observation.binary64_hex is not None
        else "canonical_decimal"
    )
    if snapshot.numeric_evidence["encoding"] != expected_encoding:
        raise ValueError("Futu Snapshot numeric wire evidence was rebound")
    documents = {item.document_id: item for item in graph.documents}
    facts = {item.fact_id: item for item in graph.facts}
    calculations = {item.calculation_id: item for item in graph.calculations}
    source = documents.get(snapshot.quote_source_document_id)
    quote_fact = facts.get(snapshot.quote_fact_id)
    calculation = calculations.get(str(snapshot.market_equity["calculation_id"]))
    raw_sha = response.raw_plaintext_sha256
    if (
        source is None
        or quote_fact is None
        or calculation is None
        or source.document_id
        != f"doc:{snapshot.issuer_id}:futu-market:{raw_sha[:24]}"
        or source.source_url != FUTU_MARKET_SOURCE_URL
        or source.content_sha256 != raw_sha
        or quote_fact.fact_id
        != (
            f"fact:{snapshot.issuer_id}:futu-close:"
            f"{snapshot.trading_date}:{raw_sha[:16]}"
        )
        or calculation.calculation_id
        != (
            f"calc:{snapshot.issuer_id}:futu-market-equity:"
            f"{snapshot.trading_date}:{raw_sha[:16]}"
        )
        or calculation.calculator_id
        != "futu-governed-close-times-current-common-shares"
        or calculation.calculator_version != FUTU_SCHEMA_VERSION
        or calculation.code_sha256 != _futu_calculation_code_sha256()
        or calculation.generated_at != response.retrieved_at
    ):
        raise ValueError("Futu SourceDocument, Fact, or Calculation identity changed")


__all__ = (
    "FUTU_MARKET_AUTHORITY_KIND",
    "FUTU_MARKET_EVIDENCE_MODE",
    "FUTU_MARKET_PROVIDER_ID",
    "FutuMarketAuthorizationTicket",
    "FutuMarketProviderRegistration",
    "FutuMarketReferenceAcquisition",
    "FutuMarketReferenceProvider",
    "FutuMarketSessionCompletion",
    "acquire_futu_market_reference",
    "bind_futu_market_reference_provider",
    "build_futu_daily_close_request_spec",
    "build_futu_market_reference_snapshot",
    "complete_futu_market_session",
    "replay_futu_market_reference_acquisition",
    "reserve_futu_market_reference",
)
