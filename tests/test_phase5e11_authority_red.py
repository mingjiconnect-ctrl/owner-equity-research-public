from __future__ import annotations

import inspect

import pytest

import owner_research.valuation_market_access as market_access


def test_market_access_signature_owns_registry_calendar_and_security_authority() -> None:
    signature = inspect.signature(market_access.acquire_governed_market_quote)
    assert tuple(signature.parameters) == (
        "price_blind_artifact_directory",
        "graph",
        "expected_freeze",
        "expected_security",
        "provider",
    )
    assert "provider_registry" not in signature.parameters
    assert "trading_calendar" not in signature.parameters
    assert "security_decision" not in signature.parameters


def test_provider_protocol_returns_raw_bytes_without_parsed_quote_fields() -> None:
    fields = market_access.RawMarketResponse.__dataclass_fields__
    assert set(fields) == {"raw_response", "content_type", "transport_metadata"}
    assert "quote_price" not in fields
    assert "ticker" not in fields


@pytest.mark.parametrize(
    "value",
    ("NaN", "Infinity", "-1", "+1", "1e2", "01.0", "1,000", ".5", "1."),
)
def test_noncanonical_quote_decimal_is_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        market_access.parse_canonical_quote_decimal(value)


@pytest.mark.parametrize(
    "endpoint",
    (
        "https://user:secret@example.test/quote",
        "https://example.test/quote?api_key=secret",
        "https://example.test/quote?token=secret",
    ),
)
def test_credential_bearing_endpoint_is_rejected(endpoint: str) -> None:
    with pytest.raises(ValueError):
        market_access._validate_endpoint(endpoint, "live")


def test_authority_resources_are_loaded_from_component_lock() -> None:
    authority = market_access.load_market_access_authority()
    assert authority.lock_version == "1.1.0"
    assert authority.provider_registry.registrations
    assert {dataset.mic for dataset in authority.calendar_registry.datasets} == {
        "XNYS",
        "XNAS",
    }

