"""Internal immutable Phase 5E market/request/execution boundary records.

The records define future input and receipt shapes but perform no market access,
request compilation, kernel execution, or persistence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from .fingerprints import FrozenMap, canonical_sha256, freeze, to_json_value
from .valuation_market_execution_policies import (
    FINAL_REQUEST_POLICY_ID,
    FINAL_REQUEST_POLICY_VERSION,
    KERNEL_EXECUTION_POLICY_ID,
    KERNEL_EXECUTION_POLICY_VERSION,
    MARKET_INSTRUMENT_STATUSES,
    MARKET_PRICE_BASES,
    MARKET_QUOTE_POLICY_ID,
    MARKET_QUOTE_POLICY_VERSION,
    MARKET_SESSION_KINDS,
    MARKET_SESSION_STATUSES,
    PHASE5E_REASON_CODES,
    PINNED_KERNEL_COMMIT,
    PINNED_KERNEL_PACKAGE_VERSION,
    PINNED_KERNEL_PLUGIN_VERSION,
    PINNED_KERNEL_REPOSITORY,
    PINNED_KERNEL_SCHEMA_SHA256,
    PINNED_KERNEL_TAG,
    SECURITY_DISPOSITIONS,
    SECURITY_IDENTITY_POLICY_ID,
    SECURITY_IDENTITY_POLICY_VERSION,
    SHARE_BASIS_DISPOSITIONS,
    SHARE_BASIS_EVIDENCE_KINDS,
    SHARE_BASIS_POLICY_ID,
    SHARE_BASIS_POLICY_VERSION,
    SUPPORTED_SECURITY_STRUCTURE,
    SUPPORTED_SHARE_BASIS,
    SUPPORTED_SHARE_CLASS,
    SUPPORTED_SPLIT_FACTOR,
    phase5e_policy_sha256,
)


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an offset")
    return parsed


def _sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _nonempty(value: str, label: str) -> None:
    if not value.strip():
        raise ValueError(f"{label} is required")


def _iso_currency(value: str, label: str) -> None:
    if len(value) != 3 or not value.isalpha() or value.upper() != value:
        raise ValueError(f"{label} must be an uppercase ISO currency code")


def _unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _registered_reasons(values: tuple[str, ...]) -> tuple[str, ...]:
    _unique(values, "reason codes")
    if not set(values).issubset(PHASE5E_REASON_CODES):
        raise ValueError("record contains an unregistered Phase 5E reason code")
    return tuple(sorted(values))


@dataclass(frozen=True, slots=True)
class MarketQuoteRequest:
    request_id: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    authorization_handoff_id: str
    authorization_transitioned_at: str
    issuer_id: str
    data_cutoff_date: str
    security_id: str
    ticker: str
    exchange: str
    share_class: str
    quote_currency: str
    reporting_currency: str
    price_basis: str
    session_kind: str
    provider_id: str
    provider_version: str
    provider_registration_sha256: str
    endpoint: str
    trading_calendar_id: str
    request_started_at: str
    request_fingerprint: str

    def __post_init__(self) -> None:
        if (self.policy_id, self.policy_version) != (
            MARKET_QUOTE_POLICY_ID,
            MARKET_QUOTE_POLICY_VERSION,
        ):
            raise ValueError("MarketQuoteRequest policy mismatch")
        if self.policy_sha256 != phase5e_policy_sha256():
            raise ValueError("MarketQuoteRequest policy SHA mismatch")
        for value, label in (
            (self.request_id, "request ID"),
            (self.authorization_handoff_id, "authorization Handoff ID"),
            (self.issuer_id, "issuer ID"),
            (self.security_id, "security ID"),
            (self.ticker, "ticker"),
            (self.exchange, "exchange"),
            (self.share_class, "share class"),
            (self.provider_id, "provider ID"),
            (self.provider_version, "provider version"),
            (self.endpoint, "endpoint"),
            (self.trading_calendar_id, "trading calendar ID"),
        ):
            _nonempty(value, label)
        if self.price_basis not in MARKET_PRICE_BASES:
            raise ValueError("adjusted or non-close price basis is forbidden")
        if self.session_kind not in MARKET_SESSION_KINDS:
            raise ValueError("only the regular trading session is permitted")
        if self.quote_currency != self.reporting_currency:
            raise ValueError("quote currency must equal the FactLedger reporting currency")
        _iso_currency(self.quote_currency, "quote currency")
        _iso_currency(self.reporting_currency, "reporting currency")
        date.fromisoformat(self.data_cutoff_date)
        if _timestamp(self.request_started_at) < _timestamp(self.authorization_transitioned_at):
            raise ValueError("market request started before Handoff authorization")
        _sha256(self.provider_registration_sha256, "provider registration SHA")
        expected = self.expected_fingerprint()
        if self.request_fingerprint != expected:
            raise ValueError("MarketQuoteRequest fingerprint mismatch")

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("request_fingerprint")
        return payload

    def expected_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class MarketQuoteReceipt:
    receipt_id: str
    request_id: str
    request_fingerprint: str
    authorization_handoff_id: str
    authorization_transitioned_at: str
    issuer_id: str
    data_cutoff_date: str
    security_id: str
    ticker: str
    exchange: str
    share_class: str
    provider_id: str
    provider_version: str
    endpoint: str
    trading_calendar_id: str
    request_started_at: str
    retrieved_at: str
    trading_date: str
    latest_completed_session_date: str
    quote_timestamp: str
    session_kind: str
    session_status: str
    instrument_status: str
    price_basis: str
    quote_price: str
    quote_currency: str
    raw_response_sha256: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.receipt_id, "receipt ID"),
            (self.request_id, "request ID"),
            (self.authorization_handoff_id, "authorization Handoff ID"),
            (self.provider_id, "provider ID"),
            (self.endpoint, "endpoint"),
            (self.trading_calendar_id, "trading calendar ID"),
        ):
            _nonempty(value, label)
        authorization = _timestamp(self.authorization_transitioned_at)
        started = _timestamp(self.request_started_at)
        retrieved = _timestamp(self.retrieved_at)
        quote_time = _timestamp(self.quote_timestamp)
        if not authorization <= started <= retrieved:
            raise ValueError("market access timing does not follow authorization")
        trading_day = date.fromisoformat(self.trading_date)
        latest_completed_day = date.fromisoformat(self.latest_completed_session_date)
        if trading_day > date.fromisoformat(self.data_cutoff_date):
            raise ValueError("market quote follows the data cutoff")
        if quote_time.date() != trading_day:
            raise ValueError("quote timestamp and trading date differ")
        if trading_day != latest_completed_day:
            raise ValueError("quote is not from the latest completed regular session")
        if quote_time > retrieved:
            raise ValueError("market quote timestamp follows retrieval")
        if self.session_kind not in MARKET_SESSION_KINDS:
            raise ValueError("only the regular trading session is permitted")
        if self.session_status not in MARKET_SESSION_STATUSES:
            raise ValueError("market session must be completed")
        if self.instrument_status not in MARKET_INSTRUMENT_STATUSES:
            raise ValueError("halted or suspended security quote is forbidden")
        if self.price_basis not in MARKET_PRICE_BASES:
            raise ValueError("adjusted or non-close price basis is forbidden")
        try:
            if Decimal(self.quote_price) <= 0:
                raise ValueError("quote price must be positive")
        except InvalidOperation as exc:
            raise ValueError("quote price must be an exact decimal string") from exc
        _sha256(self.request_fingerprint, "request fingerprint")
        _sha256(self.raw_response_sha256, "raw response SHA")
        _iso_currency(self.quote_currency, "quote currency")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class SecurityIdentityDecision:
    decision_id: str
    policy_id: str
    policy_version: str
    issuer_id: str
    security_id: str
    ticker: str
    exchange: str
    share_class: str
    security_structure: str
    quote_currency: str
    reporting_currency: str
    disposition: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if (self.policy_id, self.policy_version) != (
            SECURITY_IDENTITY_POLICY_ID,
            SECURITY_IDENTITY_POLICY_VERSION,
        ):
            raise ValueError("SecurityIdentityDecision policy mismatch")
        if self.disposition not in SECURITY_DISPOSITIONS:
            raise ValueError("security identity disposition is not registered")
        for value, label in (
            (self.decision_id, "decision ID"),
            (self.issuer_id, "issuer ID"),
            (self.security_id, "security ID"),
            (self.ticker, "ticker"),
            (self.exchange, "exchange"),
            (self.share_class, "share class"),
        ):
            _nonempty(value, label)
        _iso_currency(self.quote_currency, "quote currency")
        _iso_currency(self.reporting_currency, "reporting currency")
        reasons = _registered_reasons(self.reason_codes)
        if self.disposition == "eligible":
            if self.security_structure != SUPPORTED_SECURITY_STRUCTURE:
                raise ValueError("eligible security must be one primary common class")
            if self.share_class != SUPPORTED_SHARE_CLASS:
                raise ValueError("eligible security share class must be common")
            if self.quote_currency != self.reporting_currency:
                raise ValueError("eligible security must use the reporting currency")
            if reasons:
                raise ValueError("eligible security cannot retain blocking reasons")
        elif not reasons:
            raise ValueError("non-eligible security requires a reason code")
        object.__setattr__(self, "reason_codes", reasons)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class ShareBasisDecision:
    decision_id: str
    policy_id: str
    policy_version: str
    issuer_id: str
    security_id: str
    share_fact_id: str
    basis_kind: str
    evidence_kind: str | None
    as_of_date: str
    quote_date: str
    split_factor: str
    corporate_action_evidence_ids: tuple[str, ...]
    disposition: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if (self.policy_id, self.policy_version) != (
            SHARE_BASIS_POLICY_ID,
            SHARE_BASIS_POLICY_VERSION,
        ):
            raise ValueError("ShareBasisDecision policy mismatch")
        if self.disposition not in SHARE_BASIS_DISPOSITIONS:
            raise ValueError("share-basis disposition is not registered")
        date.fromisoformat(self.as_of_date)
        date.fromisoformat(self.quote_date)
        try:
            split_factor = Decimal(self.split_factor)
        except InvalidOperation as exc:
            raise ValueError("split factor must be an exact decimal string") from exc
        reasons = _registered_reasons(self.reason_codes)
        _unique(self.corporate_action_evidence_ids, "corporate-action evidence IDs")
        if self.disposition == "eligible":
            if self.basis_kind != SUPPORTED_SHARE_BASIS:
                raise ValueError("non-current shares are not valuation eligible")
            if self.evidence_kind not in SHARE_BASIS_EVIDENCE_KINDS:
                raise ValueError("current-share evidence kind is not registered")
            if self.as_of_date != self.quote_date:
                raise ValueError("current shares must be measured on the quote date")
            if split_factor != Decimal(SUPPORTED_SPLIT_FACTOR):
                raise ValueError("v0.5 alpha supports only split factor 1")
            if reasons:
                raise ValueError("eligible share basis cannot retain blocking reasons")
        else:
            if self.evidence_kind is not None:
                raise ValueError("non-eligible share basis cannot assert an evidence kind")
            if not reasons:
                raise ValueError("non-eligible share basis requires a reason code")
        object.__setattr__(
            self,
            "corporate_action_evidence_ids",
            tuple(sorted(self.corporate_action_evidence_ids)),
        )
        object.__setattr__(self, "reason_codes", reasons)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class FinalRequestCompilationReceipt:
    receipt_id: str
    policy_id: str
    policy_version: str
    issuer_id: str
    handoff_run_id: str
    market_reference_snapshot_id: str
    added_source_ids: tuple[str, ...]
    added_fact_ids: tuple[str, ...]
    price_blind_fact_ledger_sha256: str
    final_fact_ledger_sha256: str
    assumption_entries_before_sha256: str
    assumption_entries_after_sha256: str
    price_blind_input_before_sha256: str
    price_blind_input_after_sha256: str
    protected_mckinsey_before_sha256: str
    protected_mckinsey_after_sha256: str
    protected_penman_before_sha256: str
    protected_penman_after_sha256: str
    valuation_request_sha256: str
    status: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if (self.policy_id, self.policy_version) != (
            FINAL_REQUEST_POLICY_ID,
            FINAL_REQUEST_POLICY_VERSION,
        ):
            raise ValueError("FinalRequestCompilationReceipt policy mismatch")
        if self.status not in {"validated", "blocked"}:
            raise ValueError("final-request receipt status is not registered")
        for value, label in (
            (self.added_source_ids, "added SourceRef IDs"),
            (self.added_fact_ids, "added Fact IDs"),
        ):
            _unique(value, label)
        for name in (
            "price_blind_fact_ledger_sha256",
            "final_fact_ledger_sha256",
            "assumption_entries_before_sha256",
            "assumption_entries_after_sha256",
            "price_blind_input_before_sha256",
            "price_blind_input_after_sha256",
            "protected_mckinsey_before_sha256",
            "protected_mckinsey_after_sha256",
            "protected_penman_before_sha256",
            "protected_penman_after_sha256",
            "valuation_request_sha256",
        ):
            _sha256(getattr(self, name), name)
        reasons = _registered_reasons(self.reason_codes)
        if self.status == "validated":
            if len(self.added_source_ids) != 1 or len(self.added_fact_ids) != 2:
                raise ValueError("final request must add exactly one source and two market Facts")
            if self.price_blind_fact_ledger_sha256 == self.final_fact_ledger_sha256:
                raise ValueError("final FactLedger must reflect appended market evidence")
            protected_pairs = (
                (
                    self.assumption_entries_before_sha256,
                    self.assumption_entries_after_sha256,
                ),
                (self.price_blind_input_before_sha256, self.price_blind_input_after_sha256),
                (
                    self.protected_mckinsey_before_sha256,
                    self.protected_mckinsey_after_sha256,
                ),
                (
                    self.protected_penman_before_sha256,
                    self.protected_penman_after_sha256,
                ),
            )
            if any(before != after for before, after in protected_pairs):
                raise ValueError("price-blind or protected bytes changed after market access")
            if reasons:
                raise ValueError("validated request cannot retain blocking reasons")
        elif not reasons:
            raise ValueError("blocked request requires a reason code")
        object.__setattr__(self, "added_source_ids", tuple(sorted(self.added_source_ids)))
        object.__setattr__(self, "added_fact_ids", tuple(sorted(self.added_fact_ids)))
        object.__setattr__(self, "reason_codes", reasons)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class KernelExecutionReceipt:
    receipt_id: str
    policy_id: str
    policy_version: str
    repository: str
    tag: str
    commit: str
    package_version: str
    plugin_version: str
    schema_sha256: FrozenMap
    wheel_sha256: str
    dependency_wheelhouse_sha256: str
    execution_mode: str
    request_transport: str
    result_transport: str
    network_mode: str
    request_sha256: str
    result_sha256: str
    exit_code: int
    result_preserved: bool
    status: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if (self.policy_id, self.policy_version) != (
            KERNEL_EXECUTION_POLICY_ID,
            KERNEL_EXECUTION_POLICY_VERSION,
        ):
            raise ValueError("KernelExecutionReceipt policy mismatch")
        identity = (
            self.repository,
            self.tag,
            self.commit,
            self.package_version,
            self.plugin_version,
        )
        expected = (
            PINNED_KERNEL_REPOSITORY,
            PINNED_KERNEL_TAG,
            PINNED_KERNEL_COMMIT,
            PINNED_KERNEL_PACKAGE_VERSION,
            PINNED_KERNEL_PLUGIN_VERSION,
        )
        if identity != expected:
            raise ValueError("kernel execution identity drifted")
        schema_sha256 = freeze(self.schema_sha256)
        if dict(schema_sha256) != PINNED_KERNEL_SCHEMA_SHA256:
            raise ValueError("kernel execution Schema hashes drifted")
        for name in (
            "wheel_sha256",
            "dependency_wheelhouse_sha256",
            "request_sha256",
            "result_sha256",
        ):
            _sha256(getattr(self, name), name)
        if self.execution_mode != "isolated_subprocess":
            raise ValueError("kernel must execute in an isolated subprocess")
        if self.request_transport != "canonical_json_stdin":
            raise ValueError("kernel request transport must be canonical JSON over stdin")
        if self.result_transport != "canonical_json_stdout":
            raise ValueError("kernel result transport must be canonical JSON over stdout")
        if self.network_mode != "disabled":
            raise ValueError("kernel execution network must be disabled")
        if self.status not in {"succeeded", "blocked"}:
            raise ValueError("kernel execution status is not registered")
        reasons = _registered_reasons(self.reason_codes)
        if self.status == "succeeded":
            if self.exit_code != 0 or not self.result_preserved:
                raise ValueError("successful kernel execution must preserve a zero-exit result")
            if reasons:
                raise ValueError("successful kernel execution cannot retain blocking reasons")
        elif not reasons:
            raise ValueError("blocked kernel execution requires a reason code")
        object.__setattr__(self, "schema_sha256", schema_sha256)
        object.__setattr__(self, "reason_codes", reasons)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())
