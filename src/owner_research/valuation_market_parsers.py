"""Pinned raw-response parser for offline Phase 5E-1.1 market evidence."""

from __future__ import annotations

import json

from .valuation_market_authority_types import ParsedMarketQuote, RawMarketResponse

_QUOTE_FIELDS = frozenset(
    {
        "security_id",
        "ticker",
        "exchange",
        "share_class",
        "trading_calendar_id",
        "trading_date",
        "quote_timestamp",
        "session_kind",
        "session_status",
        "instrument_status",
        "price_basis",
        "quote_price",
        "quote_currency",
    }
)


def parse_recorded_official_close(response: RawMarketResponse) -> ParsedMarketQuote:
    if response.content_type != "application/json":
        raise ValueError("market response content type is not registered")
    try:
        payload = json.loads(response.raw_response.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("market response is not canonical JSON") from exc
    if not isinstance(payload, dict) or set(payload) != _QUOTE_FIELDS:
        raise ValueError("market response fields do not match the pinned parser contract")
    if any(not isinstance(payload[field], str) for field in _QUOTE_FIELDS):
        raise ValueError("market response fields must be strings")
    return ParsedMarketQuote(**payload)

