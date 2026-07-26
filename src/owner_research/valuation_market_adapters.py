"""Repository-owned offline adapters for Phase 5E-1.1.

These adapters deliberately contain no network client, retry, redirect, logging, credential, or
artifact-writing behavior. A future live adapter requires a separately reviewed component lock.
"""

from __future__ import annotations

from typing import Any

from .valuation_market_authority_types import RawMarketResponse
from .valuation_market_execution_types import MarketQuoteRequest


class RecordedMarketQuoteProvider:
    def __init__(
        self,
        raw_response: bytes,
        *,
        content_type: str = "application/json",
        error: Exception | None = None,
    ) -> None:
        self._raw_response = raw_response
        self._content_type = content_type
        self._error = error
        self.calls = 0
        self.last_request: MarketQuoteRequest | None = None

    def request_official_close(self, request: MarketQuoteRequest) -> RawMarketResponse:
        self.calls += 1
        self.last_request = request
        if self._error is not None:
            raise self._error
        return RawMarketResponse(
            raw_response=self._raw_response,
            content_type=self._content_type,
            transport_metadata={
                "adapter_kind": "recorded",
                "endpoint_id": request.endpoint,
            },
        )


class LoopbackMarketQuoteProvider:
    def __init__(self, raw_response: bytes, *, content_type: str = "application/json") -> None:
        self._raw_response = raw_response
        self._content_type = content_type
        self.calls = 0
        self.last_request: MarketQuoteRequest | None = None

    def request_official_close(self, request: MarketQuoteRequest) -> RawMarketResponse:
        self.calls += 1
        self.last_request = request
        return RawMarketResponse(
            raw_response=self._raw_response,
            content_type=self._content_type,
            transport_metadata={
                "adapter_kind": "loopback",
                "endpoint_id": request.endpoint,
            },
        )


def adapter_public_state(provider: object) -> dict[str, Any]:
    """Return the deliberately tiny, secret-free state permitted in tests and audits."""

    return {
        "class": f"{type(provider).__module__}.{type(provider).__qualname__}",
        "calls": getattr(provider, "calls", None),
    }

