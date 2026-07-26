"""Runtime enforcement for locked raw market evidence.

This module has no network client and never persists raw response bytes. It verifies an exact
repository-owned adapter class, selects a pinned parser, rejects secret-bearing metadata, and
validates a finite canonical decimal before any legacy Receipt can be built.
"""

from __future__ import annotations

import hashlib
import re
from decimal import Decimal, InvalidOperation
from typing import Any

from .valuation_market_adapters import (
    LoopbackMarketQuoteProvider,
    RecordedMarketQuoteProvider,
)
from .valuation_market_authority_types import (
    MarketAccessAuthority,
    MarketProviderRegistration,
    ParsedMarketQuote,
    RawMarketResponse,
)
from .valuation_market_parsers import parse_recorded_official_close

_CANONICAL_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
_SECRET_VALUE = re.compile(
    r"(?i)(authorization\s*:|bearer\s+|(?:api[_-]?key|token|secret|password)=|https?://[^/\s]+@)"
)
_SECRET_FIELD_FRAGMENTS = frozenset(
    {"credential", "secret", "token", "api_key", "apikey", "password", "bearer"}
)
_ADAPTER_CLASSES = {
    "owner_research.valuation_market_adapters.RecordedMarketQuoteProvider": (
        RecordedMarketQuoteProvider
    ),
    "owner_research.valuation_market_adapters.LoopbackMarketQuoteProvider": (
        LoopbackMarketQuoteProvider
    ),
}
_PARSERS = {
    "owner_research.valuation_market_parsers.parse_recorded_official_close": (
        parse_recorded_official_close
    )
}


def parse_canonical_quote_decimal(value: str) -> Decimal:
    if not isinstance(value, str) or _CANONICAL_DECIMAL.fullmatch(value) is None:
        raise ValueError("quote price is not a canonical decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("quote price is not a canonical decimal string") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ValueError("quote price must be finite and positive")
    return parsed


def contains_secret_material(value: object, *, field_name: str | None = None) -> bool:
    if field_name is not None:
        normalized = field_name.casefold().replace("-", "_")
        if any(fragment in normalized for fragment in _SECRET_FIELD_FRAGMENTS):
            return True
    if isinstance(value, str):
        return _SECRET_VALUE.search(value) is not None
    if isinstance(value, bytes):
        return _SECRET_VALUE.search(value.decode("utf-8", errors="ignore")) is not None
    if isinstance(value, dict):
        return any(
            contains_secret_material(item, field_name=str(key)) for key, item in value.items()
        )
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(contains_secret_material(item) for item in value)
    if hasattr(value, "to_dict"):
        return contains_secret_material(value.to_dict())
    return False


def validate_credential_free_endpoint(endpoint: str, adapter_kind: str) -> None:
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError("provider endpoint is required")
    if any(character.isspace() for character in endpoint) or "#" in endpoint or "?" in endpoint:
        raise ValueError("provider endpoint must be normalized and credential-free")
    expected_scheme = {
        "recorded": "recorded://",
        "loopback": "loopback://",
        "live": "https://",
    }.get(adapter_kind)
    if expected_scheme is None or not endpoint.startswith(expected_scheme):
        raise ValueError("provider endpoint scheme does not match adapter kind")
    authority = endpoint.split("://", 1)[1].split("/", 1)[0]
    if not authority or "@" in authority or contains_secret_material(endpoint):
        raise ValueError("provider endpoint must be normalized and credential-free")


def resolve_locked_registration(
    provider: object,
    authority: MarketAccessAuthority,
) -> MarketProviderRegistration | None:
    provider_type = type(provider)
    matches = tuple(
        registration
        for registration in authority.provider_registry.registrations
        if _ADAPTER_CLASSES.get(registration.adapter_class) is provider_type
    )
    if len(matches) != 1:
        return None
    registration = matches[0]
    exact_path = f"{provider_type.__module__}.{provider_type.__qualname__}"
    bound_method = getattr(provider, "request_official_close", None)
    if (
        exact_path != registration.adapter_class
        or getattr(bound_method, "__func__", None)
        is not getattr(provider_type, "request_official_close", None)
    ):
        return None
    return registration


def parse_locked_raw_response(
    response: object,
    *,
    registration: MarketProviderRegistration,
) -> tuple[ParsedMarketQuote, str]:
    if type(response) is not RawMarketResponse:
        raise ValueError("provider did not return the exact raw-response type")
    if response.content_type != registration.content_type:
        raise ValueError("raw-response content type does not match registration")
    metadata = dict(response.transport_metadata)
    if metadata != {
        "adapter_kind": registration.adapter_kind,
        "endpoint_id": registration.endpoint_id,
    }:
        raise ValueError("raw-response transport metadata does not match registration")
    if contains_secret_material(metadata):
        raise ValueError("raw-response metadata contains secret material")
    parser = _PARSERS.get(registration.parser_function)
    if parser is None:
        raise ValueError("registered parser is not repository-owned")
    quote = parser(response)
    parse_canonical_quote_decimal(quote.quote_price)
    raw_sha256 = hashlib.sha256(response.raw_response).hexdigest()
    return quote, raw_sha256


def assert_secret_free_surface(value: Any, label: str) -> None:
    if contains_secret_material(value):
        raise ValueError(f"{label} contains credential-like material")


__all__ = ()
