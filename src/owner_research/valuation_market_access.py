"""Internal Phase 5E-1.1 governed market-access boundary.

The wheel owns provider registration, parsing, calendar selection, and security-identity replay.
The module performs one offline adapter call and returns only a governed receipt or a hash-only
quarantine. It does not create market evidence contracts, valuation inputs, or artifacts.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Protocol

from .fingerprints import canonical_sha256, to_json_value
from .validation import ContractGraph
from .valuation_market_authority import load_market_access_authority
from .valuation_market_authority_types import (
    MarketAccessAuthority,
    MarketProviderRegistration,
    ParsedMarketQuote,
    RawMarketResponse,
)
from .valuation_market_calendar import (
    CalendarSelection,
    MarketCalendarError,
    select_latest_completed_session,
)
from .valuation_market_execution_policies import (
    MARKET_QUOTE_POLICY_ID,
    MARKET_QUOTE_POLICY_VERSION,
    PHASE5E_REASON_CODES,
    phase5e_policy_sha256,
)
from .valuation_market_execution_types import MarketQuoteReceipt, MarketQuoteRequest
from .valuation_market_runtime import (
    assert_secret_free_surface,
    parse_canonical_quote_decimal,
    parse_locked_raw_response,
    resolve_locked_registration,
    validate_credential_free_endpoint,
)
from .valuation_price_blind_freeze import (
    PriceBlindFreezeCompilationResult,
    PriceBlindFreezeError,
    load_price_blind_input_artifact,
)
from .valuation_security_identity import (
    SecurityIdentityCompilationResult,
    compile_security_identity,
)

MARKET_ACCESS_STATUSES = ("eligible", "blocked", "specialist_required")
MARKET_ACCESS_ISSUE_CODES = frozenset(
    set(PHASE5E_REASON_CODES)
    | {
        "artifact_reload_failed",
        "authorization_not_current",
        "authorization_already_consumed",
        "authority_load_failed",
        "authority_lock_mismatch",
        "security_identity_mismatch",
        "calendar_unresolved",
        "clock_invalid",
        "provider_call_failed",
        "provider_response_invalid",
        "response_identity_mismatch",
        "raw_response_missing",
        "secret_material_detected",
    }
)


def _sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include an offset")
    return parsed.astimezone(UTC)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _sorted_unique(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if any(not value.strip() for value in values):
        raise ValueError(f"{label} cannot contain an empty value")
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return tuple(sorted(values))


def _validate_endpoint(endpoint: str, adapter_kind: str) -> None:
    """Compatibility helper retained only for independent adversarial tests."""

    validate_credential_free_endpoint(endpoint, adapter_kind)


@dataclass(frozen=True, slots=True)
class MarketProviderQuery:
    authorization_handoff_id: str
    issuer_id: str
    data_cutoff_date: str
    security_id: str
    ticker: str
    exchange: str
    share_class: str
    quote_currency: str
    reporting_currency: str
    trading_calendar_id: str
    expected_trading_date: str
    price_basis: str
    session_kind: str

    def __post_init__(self) -> None:
        date.fromisoformat(self.data_cutoff_date)
        date.fromisoformat(self.expected_trading_date)
        if self.quote_currency != self.reporting_currency:
            raise ValueError("market query currency must equal reporting currency")
        if self.price_basis != "official_unadjusted_close" or self.session_kind != "regular":
            raise ValueError("market query is outside the registered quote policy")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


class MarketQuoteProvider(Protocol):
    def request_official_close(self, request: MarketQuoteRequest) -> RawMarketResponse: ...


@dataclass(frozen=True, slots=True)
class GovernedMarketQuoteReceipt:
    receipt: MarketQuoteReceipt
    authority_sha256: str
    provider_registry_sha256: str
    provider_registration_sha256: str
    adapter_sha256: str
    parser_sha256: str
    calendar_registry_sha256: str
    calendar_dataset_sha256: str
    calendar_selection_fingerprint: str
    security_compilation_fingerprint: str
    security_evidence_closure_sha256: str
    raw_response_sha256: str
    evidence_mode: str

    def __post_init__(self) -> None:
        for name in (
            "authority_sha256",
            "provider_registry_sha256",
            "provider_registration_sha256",
            "adapter_sha256",
            "parser_sha256",
            "calendar_registry_sha256",
            "calendar_dataset_sha256",
            "calendar_selection_fingerprint",
            "security_compilation_fingerprint",
            "security_evidence_closure_sha256",
            "raw_response_sha256",
        ):
            _sha256(getattr(self, name), name)
        if self.receipt.raw_response_sha256 != self.raw_response_sha256:
            raise ValueError("governed Receipt raw-response SHA mismatch")
        if self.evidence_mode not in {"recorded_fixture", "loopback_fixture"}:
            raise ValueError("governed Receipt evidence mode is not registered")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class _ClockReading:
    wall_time: datetime
    monotonic_ns: int

    def __post_init__(self) -> None:
        if self.wall_time.tzinfo is None or self.monotonic_ns < 0:
            raise ValueError("clock reading must be timezone-aware and monotonic")
        object.__setattr__(self, "wall_time", self.wall_time.astimezone(UTC))


def _clock_reading() -> _ClockReading:
    return _ClockReading(datetime.now(UTC), time.monotonic_ns())


@dataclass(frozen=True, slots=True)
class MarketAccessResult:
    status: str
    issuer_id: str
    data_cutoff_date: str
    authorization_handoff_id: str
    price_blind_input_fingerprint: str
    protected_mckinsey_sha256: str
    protected_penman_assumptions_sha256: str
    provider_call_count: int
    query: MarketProviderQuery | None
    request: MarketQuoteRequest | None
    receipt: GovernedMarketQuoteReceipt | None
    quarantined_raw_response_sha256: str | None
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in MARKET_ACCESS_STATUSES:
            raise ValueError("market access status is not registered")
        if self.provider_call_count not in {0, 1}:
            raise ValueError("market access may invoke the provider at most once")
        issues = _sorted_unique(self.issue_codes, "market access issue codes")
        if not set(issues).issubset(MARKET_ACCESS_ISSUE_CODES):
            raise ValueError("market access result contains an unregistered issue code")
        for name in (
            "price_blind_input_fingerprint",
            "protected_mckinsey_sha256",
            "protected_penman_assumptions_sha256",
        ):
            _sha256(getattr(self, name), name)
        if self.quarantined_raw_response_sha256 is not None:
            _sha256(self.quarantined_raw_response_sha256, "quarantined response SHA")
        if self.status == "eligible":
            if (
                self.provider_call_count != 1
                or self.query is None
                or self.request is None
                or self.receipt is None
                or self.quarantined_raw_response_sha256 is not None
                or issues
            ):
                raise ValueError("eligible market access lacks its exact governed Receipt")
        elif self.status == "specialist_required":
            if (
                self.provider_call_count
                or self.query is not None
                or self.request is not None
                or self.receipt is not None
                or self.quarantined_raw_response_sha256 is not None
                or not issues
            ):
                raise ValueError("specialist route cannot perform market access")
        elif self.receipt is not None or not issues:
            raise ValueError("blocked market access cannot promote a Receipt")
        object.__setattr__(self, "issue_codes", issues)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _context(expected: PriceBlindFreezeCompilationResult) -> dict[str, str]:
    payload = expected.artifact.to_dict()
    authorization = expected.handoffs[-1]
    return {
        "issuer_id": payload["issuer_id"],
        "data_cutoff_date": payload["data_cutoff_date"],
        "authorization_handoff_id": authorization.handoff_id,
        "price_blind_input_fingerprint": payload["price_blind_input_fingerprint"],
        "protected_mckinsey_sha256": payload["protected_mckinsey_sha256"],
        "protected_penman_assumptions_sha256": payload[
            "protected_penman_assumptions_sha256"
        ],
    }


def _result(
    expected: PriceBlindFreezeCompilationResult,
    *,
    status: str,
    provider_call_count: int = 0,
    query: MarketProviderQuery | None = None,
    request: MarketQuoteRequest | None = None,
    receipt: GovernedMarketQuoteReceipt | None = None,
    quarantined_raw_response_sha256: str | None = None,
    issue_codes: tuple[str, ...] = (),
) -> MarketAccessResult:
    return MarketAccessResult(
        **_context(expected),
        status=status,
        provider_call_count=provider_call_count,
        query=query,
        request=request,
        receipt=receipt,
        quarantined_raw_response_sha256=quarantined_raw_response_sha256,
        issue_codes=issue_codes,
    )


def _graph_already_consumed(
    graph: ContractGraph, expected: PriceBlindFreezeCompilationResult
) -> bool:
    authorization = expected.handoffs[-1]
    if any(
        item.authorization_handoff_id == authorization.handoff_id
        for item in graph.market_reference_snapshots
    ):
        return True
    return any(
        item.handoff_run_id == authorization.handoff_run_id
        and (
            item.handoff_version > authorization.handoff_version
            or item.market_reference_snapshot_id is not None
            or item.valuation_request_sha256 is not None
            or item.valuation_result_sha256 is not None
        )
        for item in graph.valuation_handoffs
    )


def _current_authorization(
    graph: ContractGraph, loaded: PriceBlindFreezeCompilationResult
) -> bool:
    merged: dict[str, Any] = {item.handoff_id: item for item in graph.valuation_handoffs}
    for item in loaded.handoffs:
        prior = merged.get(item.handoff_id)
        if prior is not None and prior.fingerprint != item.fingerprint:
            return False
        merged[item.handoff_id] = item
    authorization = loaded.handoffs[-1]
    relevant = tuple(
        item
        for item in merged.values()
        if item.issuer_id == authorization.issuer_id
        and item.data_cutoff_date == authorization.data_cutoff_date
    )
    roots = tuple(item for item in relevant if item.predecessor_handoff_id is None)
    superseded_runs = {
        merged[item.supersedes_handoff_id].handoff_run_id
        for item in roots
        if item.supersedes_handoff_id in merged
    }
    active_runs = {item.handoff_run_id for item in roots} - superseded_runs
    if active_runs != {authorization.handoff_run_id}:
        return False
    active = tuple(
        sorted(
            (
                item
                for item in relevant
                if item.handoff_run_id == authorization.handoff_run_id
            ),
            key=lambda item: item.handoff_version,
        )
    )
    return bool(active) and active[-1].fingerprint == authorization.fingerprint


def _build_request(
    *,
    query: MarketProviderQuery,
    authorization_transitioned_at: str,
    registration: MarketProviderRegistration,
    started: _ClockReading,
) -> MarketQuoteRequest:
    identity = {
        "authorization_handoff_id": query.authorization_handoff_id,
        "issuer_id": query.issuer_id,
        "data_cutoff_date": query.data_cutoff_date,
        "security_id": query.security_id,
        "provider_registration_sha256": registration.fingerprint,
        "request_started_at": _timestamp_text(started.wall_time),
    }
    payload: dict[str, Any] = {
        "request_id": f"market-quote-request:{canonical_sha256(identity)[:24]}",
        "policy_id": MARKET_QUOTE_POLICY_ID,
        "policy_version": MARKET_QUOTE_POLICY_VERSION,
        "policy_sha256": phase5e_policy_sha256(),
        "authorization_handoff_id": query.authorization_handoff_id,
        "authorization_transitioned_at": authorization_transitioned_at,
        "issuer_id": query.issuer_id,
        "data_cutoff_date": query.data_cutoff_date,
        "security_id": query.security_id,
        "ticker": query.ticker,
        "exchange": query.exchange,
        "share_class": query.share_class,
        "quote_currency": query.quote_currency,
        "reporting_currency": query.reporting_currency,
        "price_basis": query.price_basis,
        "session_kind": query.session_kind,
        "provider_id": registration.provider_id,
        "provider_version": registration.provider_version,
        "provider_registration_sha256": registration.fingerprint,
        "endpoint": registration.endpoint_id,
        "trading_calendar_id": query.trading_calendar_id,
        "request_started_at": _timestamp_text(started.wall_time),
    }
    payload["request_fingerprint"] = canonical_sha256(payload)
    request = MarketQuoteRequest(**payload)
    assert_secret_free_surface(request, "market quote request")
    return request


def _valid_quote(
    quote: ParsedMarketQuote,
    *,
    request: MarketQuoteRequest,
    selection: CalendarSelection,
    retrieved_at: datetime,
) -> bool:
    try:
        parse_canonical_quote_decimal(quote.quote_price)
        quote_timestamp = _timestamp(quote.quote_timestamp, "quote timestamp")
    except ValueError:
        return False
    session = selection.session
    return (
        quote.security_id == request.security_id
        and quote.ticker == request.ticker
        and quote.exchange == request.exchange
        and quote.share_class == request.share_class
        and quote.trading_calendar_id == request.trading_calendar_id
        and quote.trading_date == session.trading_date
        and quote_timestamp == _timestamp(session.closed_at, "session close")
        and quote_timestamp <= retrieved_at
        and quote.session_kind == "regular"
        and quote.session_status == "completed"
        and quote.instrument_status == "active"
        and quote.price_basis == "official_unadjusted_close"
        and quote.quote_currency == request.reporting_currency
    )


def _governed_receipt(
    *,
    legacy_receipt: MarketQuoteReceipt,
    authority: MarketAccessAuthority,
    registration: MarketProviderRegistration,
    selection: CalendarSelection,
    security: SecurityIdentityCompilationResult,
    raw_response_sha256: str,
) -> GovernedMarketQuoteReceipt:
    assert security.evidence_closure is not None
    governed = GovernedMarketQuoteReceipt(
        receipt=legacy_receipt,
        authority_sha256=authority.authority_sha256,
        provider_registry_sha256=authority.provider_registry.fingerprint,
        provider_registration_sha256=registration.fingerprint,
        adapter_sha256=registration.adapter_sha256,
        parser_sha256=registration.parser_sha256,
        calendar_registry_sha256=canonical_sha256(authority.calendar_registry.to_dict()),
        calendar_dataset_sha256=selection.dataset_sha256,
        calendar_selection_fingerprint=selection.fingerprint,
        security_compilation_fingerprint=security.fingerprint,
        security_evidence_closure_sha256=security.evidence_closure.closure_sha256,
        raw_response_sha256=raw_response_sha256,
        evidence_mode=registration.evidence_mode,
    )
    assert_secret_free_surface(governed, "governed market quote receipt")
    return governed


def acquire_governed_market_quote(
    *,
    price_blind_artifact_directory: Path,
    graph: ContractGraph,
    expected_freeze: PriceBlindFreezeCompilationResult,
    expected_security: SecurityIdentityCompilationResult,
    provider: MarketQuoteProvider,
) -> MarketAccessResult:
    """Access exactly one quote after repository-owned authority replay."""

    if _graph_already_consumed(graph, expected_freeze):
        return _result(
            expected_freeze,
            status="blocked",
            issue_codes=("authorization_already_consumed",),
        )
    try:
        loaded = load_price_blind_input_artifact(
            price_blind_artifact_directory,
            graph=graph,
            expected_result=expected_freeze,
        )
    except (PriceBlindFreezeError, ValueError):
        return _result(
            expected_freeze,
            status="blocked",
            issue_codes=("artifact_reload_failed",),
        )
    authorization = loaded.handoffs[-1]
    if authorization.state != "market_reference_allowed" or not _current_authorization(
        graph, loaded
    ):
        return _result(
            loaded,
            status="blocked",
            issue_codes=("authorization_not_current",),
        )
    try:
        authority = load_market_access_authority(graph.component_lock_path)
    except (OSError, TypeError, ValueError):
        return _result(loaded, status="blocked", issue_codes=("authority_load_failed",))
    if loaded.artifact.to_dict()["component_lock_sha256"] != hashlib.sha256(
        Path(graph.component_lock_path).read_bytes()
    ).hexdigest():
        return _result(loaded, status="blocked", issue_codes=("authority_lock_mismatch",))
    replayed_security = compile_security_identity(
        graph=graph,
        expected_freeze=loaded,
        proposal=expected_security.proposal,
    )
    if replayed_security.fingerprint != expected_security.fingerprint:
        return _result(loaded, status="blocked", issue_codes=("security_identity_mismatch",))
    if replayed_security.status != "eligible" or replayed_security.decision is None:
        issues = tuple(
            item for item in replayed_security.issue_codes if item in MARKET_ACCESS_ISSUE_CODES
        ) or ("security_identity_unresolved",)
        return _result(
            loaded,
            status=(
                "specialist_required"
                if replayed_security.status == "specialist_required"
                else "blocked"
            ),
            issue_codes=issues,
        )
    security = replayed_security.decision
    registration = resolve_locked_registration(provider, authority)
    if registration is None:
        return _result(loaded, status="blocked", issue_codes=("unregistered_provider",))
    if security.exchange not in registration.supported_mics:
        return _result(loaded, status="blocked", issue_codes=("calendar_unresolved",))
    started = _clock_reading()
    if started.wall_time < _timestamp(authorization.transitioned_at, "authorization time"):
        return _result(
            loaded,
            status="blocked",
            issue_codes=("authorization_after_request_start",),
        )
    try:
        selection = select_latest_completed_session(
            authority,
            mic=security.exchange,
            cutoff_date=date.fromisoformat(authorization.data_cutoff_date),
            observed_at=started.wall_time,
        )
    except (MarketCalendarError, ValueError):
        return _result(loaded, status="blocked", issue_codes=("calendar_unresolved",))
    if selection.calendar_id not in registration.trading_calendar_ids:
        return _result(loaded, status="blocked", issue_codes=("calendar_unresolved",))
    query = MarketProviderQuery(
        authorization_handoff_id=authorization.handoff_id,
        issuer_id=authorization.issuer_id,
        data_cutoff_date=authorization.data_cutoff_date,
        security_id=security.security_id,
        ticker=security.ticker,
        exchange=security.exchange,
        share_class=security.share_class,
        quote_currency=security.quote_currency,
        reporting_currency=security.reporting_currency,
        trading_calendar_id=selection.calendar_id,
        expected_trading_date=selection.session.trading_date,
        price_basis=registration.price_basis,
        session_kind=registration.session_kind,
    )
    try:
        request = _build_request(
            query=query,
            authorization_transitioned_at=authorization.transitioned_at,
            registration=registration,
            started=started,
        )
    except ValueError:
        return _result(
            loaded,
            status="blocked",
            query=query,
            issue_codes=("secret_material_detected",),
        )
    response: object | None = None
    provider_failed = False
    try:
        response = provider.request_official_close(request)
    except Exception:
        provider_failed = True
    retrieved = _clock_reading()
    raw_hash = (
        hashlib.sha256(response.raw_response).hexdigest()
        if type(response) is RawMarketResponse and response.raw_response
        else None
    )
    if provider_failed:
        return _result(
            loaded,
            status="blocked",
            provider_call_count=1,
            query=query,
            request=request,
            issue_codes=("provider_call_failed",),
        )
    if retrieved.monotonic_ns < started.monotonic_ns or retrieved.wall_time < started.wall_time:
        return _result(
            loaded,
            status="blocked",
            provider_call_count=1,
            query=query,
            request=request,
            quarantined_raw_response_sha256=raw_hash,
            issue_codes=("clock_invalid",),
        )
    try:
        quote, parsed_raw_hash = parse_locked_raw_response(
            response,
            registration=registration,
        )
    except (TypeError, ValueError):
        return _result(
            loaded,
            status="blocked",
            provider_call_count=1,
            query=query,
            request=request,
            quarantined_raw_response_sha256=raw_hash,
            issue_codes=("provider_response_invalid",),
        )
    if parsed_raw_hash != raw_hash or not _valid_quote(
        quote,
        request=request,
        selection=selection,
        retrieved_at=retrieved.wall_time,
    ):
        return _result(
            loaded,
            status="blocked",
            provider_call_count=1,
            query=query,
            request=request,
            quarantined_raw_response_sha256=raw_hash,
            issue_codes=("provider_response_invalid",),
        )
    receipt_identity = canonical_sha256(
        {
            "request_fingerprint": request.request_fingerprint,
            "raw_response_sha256": parsed_raw_hash,
        }
    )
    try:
        legacy_receipt = MarketQuoteReceipt(
            receipt_id=f"market-quote-receipt:{receipt_identity[:24]}",
            request_id=request.request_id,
            request_fingerprint=request.request_fingerprint,
            authorization_handoff_id=request.authorization_handoff_id,
            authorization_transitioned_at=request.authorization_transitioned_at,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            security_id=request.security_id,
            ticker=request.ticker,
            exchange=request.exchange,
            share_class=request.share_class,
            provider_id=request.provider_id,
            provider_version=request.provider_version,
            endpoint=request.endpoint,
            trading_calendar_id=request.trading_calendar_id,
            request_started_at=request.request_started_at,
            retrieved_at=_timestamp_text(retrieved.wall_time),
            trading_date=quote.trading_date,
            latest_completed_session_date=selection.session.trading_date,
            quote_timestamp=quote.quote_timestamp,
            session_kind=quote.session_kind,
            session_status=quote.session_status,
            instrument_status=quote.instrument_status,
            price_basis=quote.price_basis,
            quote_price=quote.quote_price,
            quote_currency=quote.quote_currency,
            raw_response_sha256=parsed_raw_hash,
        )
        governed = _governed_receipt(
            legacy_receipt=legacy_receipt,
            authority=authority,
            registration=registration,
            selection=selection,
            security=replayed_security,
            raw_response_sha256=parsed_raw_hash,
        )
    except ValueError:
        return _result(
            loaded,
            status="blocked",
            provider_call_count=1,
            query=query,
            request=request,
            quarantined_raw_response_sha256=parsed_raw_hash,
            issue_codes=("provider_response_invalid",),
        )
    return _result(
        loaded,
        status="eligible",
        provider_call_count=1,
        query=query,
        request=request,
        receipt=governed,
    )


__all__ = ()
