"""Closed internal records for the Phase 5E-1.1 market-access trust root."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from .fingerprints import FrozenMap, canonical_sha256, freeze, to_json_value


def _nonempty(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required")


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


@dataclass(frozen=True, slots=True)
class RawMarketResponse:
    raw_response: bytes
    content_type: str
    transport_metadata: FrozenMap

    def __post_init__(self) -> None:
        if not isinstance(self.raw_response, bytes) or not self.raw_response:
            raise ValueError("raw market response must contain bytes")
        _nonempty(self.content_type, "content type")
        object.__setattr__(self, "transport_metadata", freeze(self.transport_metadata))


@dataclass(frozen=True, slots=True)
class ParsedMarketQuote:
    security_id: str
    ticker: str
    exchange: str
    share_class: str
    trading_calendar_id: str
    trading_date: str
    quote_timestamp: str
    session_kind: str
    session_status: str
    instrument_status: str
    price_basis: str
    quote_price: str
    quote_currency: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.security_id, "security ID"),
            (self.ticker, "ticker"),
            (self.exchange, "exchange"),
            (self.share_class, "share class"),
            (self.trading_calendar_id, "trading calendar ID"),
            (self.quote_price, "quote price"),
        ):
            _nonempty(value, label)
        trading_day = date.fromisoformat(self.trading_date)
        if _timestamp(self.quote_timestamp, "quote timestamp").date() != trading_day:
            raise ValueError("quote timestamp and trading date differ")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class MarketProviderRegistration:
    provider_id: str
    provider_version: str
    adapter_kind: str
    adapter_class: str
    adapter_module: str
    adapter_sha256: str
    parser_function: str
    parser_module: str
    parser_sha256: str
    endpoint_id: str
    content_type: str
    supported_mics: tuple[str, ...]
    trading_calendar_ids: tuple[str, ...]
    price_basis: str
    session_kind: str
    evidence_mode: str

    def __post_init__(self) -> None:
        if self.adapter_kind not in {"recorded", "loopback"}:
            raise ValueError("Phase 5E-1.1 registers only offline adapters")
        if self.evidence_mode not in {"recorded_fixture", "loopback_fixture"}:
            raise ValueError("market provider evidence mode is not registered")
        for value, label in (
            (self.provider_id, "provider ID"),
            (self.provider_version, "provider version"),
            (self.adapter_class, "adapter class"),
            (self.adapter_module, "adapter module"),
            (self.parser_function, "parser function"),
            (self.parser_module, "parser module"),
            (self.endpoint_id, "endpoint ID"),
            (self.content_type, "content type"),
        ):
            _nonempty(value, label)
        _sha256(self.adapter_sha256, "adapter SHA")
        _sha256(self.parser_sha256, "parser SHA")
        if any(marker in self.endpoint_id.casefold() for marker in ("?", "@", "token", "key=")):
            raise ValueError("endpoint ID must be credential-free")
        mics = tuple(sorted(self.supported_mics))
        calendars = tuple(sorted(self.trading_calendar_ids))
        if not mics or len(mics) != len(set(mics)):
            raise ValueError("provider MIC coverage must be nonempty and unique")
        if not calendars or len(calendars) != len(set(calendars)):
            raise ValueError("provider calendar coverage must be nonempty and unique")
        if self.price_basis != "official_unadjusted_close" or self.session_kind != "regular":
            raise ValueError("provider registration violates the quote policy")
        object.__setattr__(self, "supported_mics", mics)
        object.__setattr__(self, "trading_calendar_ids", calendars)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class MarketProviderRegistry:
    registry_id: str
    registry_version: str
    registrations: tuple[MarketProviderRegistration, ...]

    def __post_init__(self) -> None:
        if (self.registry_id, self.registry_version) != (
            "market-provider-registry",
            "1.1.0",
        ):
            raise ValueError("provider registry identity mismatch")
        ordered = tuple(
            sorted(self.registrations, key=lambda item: (item.provider_id, item.provider_version))
        )
        identities = tuple((item.provider_id, item.provider_version) for item in ordered)
        if not ordered or len(identities) != len(set(identities)):
            raise ValueError("provider registry identities must be nonempty and unique")
        object.__setattr__(self, "registrations", ordered)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class TradingSession:
    mic: str
    trading_date: str
    opened_at: str
    closed_at: str
    early_close: bool

    def __post_init__(self) -> None:
        trading_day = date.fromisoformat(self.trading_date)
        opened = _timestamp(self.opened_at, "session opened_at")
        closed = _timestamp(self.closed_at, "session closed_at")
        if not opened < closed or opened.date() != trading_day or closed.date() != trading_day:
            raise ValueError("trading session UTC boundaries are invalid")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class TradingCalendarDataset:
    calendar_id: str
    mic: str
    timezone: str
    coverage_start: str
    coverage_end: str
    official_source_url: str
    official_source_record_sha256: str
    sessions: tuple[TradingSession, ...]
    dataset_sha256: str

    def __post_init__(self) -> None:
        if self.timezone != "America/New_York":
            raise ValueError("market calendar timezone must be America/New_York")
        start = date.fromisoformat(self.coverage_start)
        end = date.fromisoformat(self.coverage_end)
        if not start <= end:
            raise ValueError("market calendar coverage is invalid")
        _sha256(self.official_source_record_sha256, "official source record SHA")
        _sha256(self.dataset_sha256, "calendar dataset SHA")
        ordered = tuple(sorted(self.sessions, key=lambda item: item.trading_date))
        if not ordered or len({item.trading_date for item in ordered}) != len(ordered):
            raise ValueError("calendar sessions must be nonempty and unique")
        if any(item.mic != self.mic for item in ordered):
            raise ValueError("calendar session MIC mismatch")
        object.__setattr__(self, "sessions", ordered)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class TradingCalendarRegistry:
    registry_id: str
    registry_version: str
    datasets: tuple[TradingCalendarDataset, ...]

    def __post_init__(self) -> None:
        if (self.registry_id, self.registry_version) != (
            "trading-calendar-registry",
            "1.0.0",
        ):
            raise ValueError("trading calendar registry identity mismatch")
        ordered = tuple(sorted(self.datasets, key=lambda item: item.mic))
        if not ordered or len({item.mic for item in ordered}) != len(ordered):
            raise ValueError("calendar dataset MICs must be nonempty and unique")
        object.__setattr__(self, "datasets", ordered)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class MarketAccessAuthority:
    lock_version: str
    authority_version: str
    provider_registry: MarketProviderRegistry
    calendar_registry: TradingCalendarRegistry
    security_policy_sha256: str
    secret_policy_sha256: str
    authority_sha256: str

    def __post_init__(self) -> None:
        if self.lock_version != "1.1.0" or self.authority_version != "1.0.0":
            raise ValueError("market access authority version mismatch")
        for value, label in (
            (self.security_policy_sha256, "security policy SHA"),
            (self.secret_policy_sha256, "secret policy SHA"),
            (self.authority_sha256, "authority SHA"),
        ):
            _sha256(value, label)

