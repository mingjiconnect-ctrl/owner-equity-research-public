from __future__ import annotations

from dataclasses import replace

import pytest

from owner_research.valuation_market_adapters import RecordedMarketQuoteProvider
from owner_research.valuation_market_authority import load_market_access_authority
from owner_research.valuation_market_authority_types import RawMarketResponse
from owner_research.valuation_market_runtime import (
    contains_secret_material,
    parse_canonical_quote_decimal,
    parse_locked_raw_response,
    resolve_locked_registration,
    validate_credential_free_endpoint,
)


def _raw(**changes: str) -> bytes:
    payload = {
        "security_id": "security:issuer-acme:XNYS:ACME:common",
        "ticker": "ACME",
        "exchange": "XNYS",
        "share_class": "common",
        "trading_calendar_id": "calendar:XNYS:2026:1.0.0",
        "trading_date": "2026-06-30",
        "quote_timestamp": "2026-06-30T20:00:00Z",
        "session_kind": "regular",
        "session_status": "completed",
        "instrument_status": "active",
        "price_basis": "official_unadjusted_close",
        "quote_price": "50.125",
        "quote_currency": "USD",
    }
    payload.update(changes)
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def test_exact_repository_adapter_and_pinned_raw_parser_are_required() -> None:
    authority = load_market_access_authority()
    provider = RecordedMarketQuoteProvider(_raw())
    registration = resolve_locked_registration(provider, authority)
    assert registration is not None
    response = provider.request_official_close  # the request shape is tested at the orchestrator
    assert callable(response)
    raw = RawMarketResponse(
        raw_response=_raw(),
        content_type="application/json",
        transport_metadata={
            "adapter_kind": registration.adapter_kind,
            "endpoint_id": registration.endpoint_id,
        },
    )
    parsed, raw_sha = parse_locked_raw_response(raw, registration=registration)
    assert parsed.quote_price == "50.125"
    assert len(raw_sha) == 64


def test_subclass_and_forged_registration_cannot_self_register() -> None:
    class Forged(RecordedMarketQuoteProvider):
        pass

    authority = load_market_access_authority()
    assert resolve_locked_registration(Forged(_raw()), authority) is None
    registered = authority.provider_registry.registrations[0]
    forged = replace(registered, endpoint_id="endpoint:forged")
    assert forged.fingerprint not in {
        item.fingerprint for item in authority.provider_registry.registrations
    }


@pytest.mark.parametrize(
    "value",
    ("NaN", "Infinity", "-1", "+1", "1e2", "01.0", "1,000", ".5", "1.", "0"),
)
def test_quote_decimal_rejects_nonfinite_nonpositive_and_noncanonical(value: str) -> None:
    with pytest.raises(ValueError):
        parse_canonical_quote_decimal(value)


def test_raw_bytes_are_the_only_quote_authority() -> None:
    authority = load_market_access_authority()
    registration = next(
        item
        for item in authority.provider_registry.registrations
        if item.adapter_kind == "recorded"
    )
    raw = RawMarketResponse(
        raw_response=_raw(quote_price="NaN"),
        content_type="application/json",
        transport_metadata={
            "adapter_kind": "recorded",
            "endpoint_id": registration.endpoint_id,
        },
    )
    with pytest.raises(ValueError):
        parse_locked_raw_response(raw, registration=registration)


@pytest.mark.parametrize(
    "value",
    (
        {"api_key": "value"},
        {"endpoint": "https://example.test/quote?token=value"},
        {"header": "Authorization: Bearer value"},
        "https://user:pass@example.test/quote",
    ),
)
def test_secret_scanner_rejects_credentials_on_serialized_surfaces(value: object) -> None:
    assert contains_secret_material(value)


@pytest.mark.parametrize(
    "endpoint",
    (
        "https://user:secret@example.test/quote",
        "https://example.test/quote?api_key=secret",
        "https://example.test/quote?token=secret",
    ),
)
def test_endpoint_validation_rejects_userinfo_and_query_secrets(endpoint: str) -> None:
    with pytest.raises(ValueError):
        validate_credential_free_endpoint(endpoint, "live")
