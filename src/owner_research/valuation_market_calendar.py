"""Content-addressed 2026 XNYS/XNAS calendar selection for Phase 5E-1.1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from .fingerprints import canonical_sha256, to_json_value
from .valuation_market_authority_types import (
    MarketAccessAuthority,
    TradingCalendarDataset,
    TradingSession,
)


class MarketCalendarError(ValueError):
    pass


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise MarketCalendarError("calendar session timestamp lacks an offset")
    return parsed.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class CalendarSelection:
    calendar_id: str
    mic: str
    dataset_sha256: str
    official_source_url: str
    official_source_record_sha256: str
    coverage_start: str
    coverage_end: str
    session: TradingSession

    def __post_init__(self) -> None:
        if self.session.mic != self.mic:
            raise ValueError("selected session MIC mismatch")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _dataset(authority: MarketAccessAuthority, mic: str) -> TradingCalendarDataset:
    matches = tuple(item for item in authority.calendar_registry.datasets if item.mic == mic)
    if len(matches) != 1:
        raise MarketCalendarError("market MIC has no unique locked calendar dataset")
    return matches[0]


def select_latest_completed_session(
    authority: MarketAccessAuthority,
    *,
    mic: str,
    cutoff_date: date,
    observed_at: datetime,
) -> CalendarSelection:
    if observed_at.tzinfo is None:
        raise MarketCalendarError("calendar observation time must include an offset")
    observed = observed_at.astimezone(UTC)
    dataset = _dataset(authority, mic)
    coverage_start = date.fromisoformat(dataset.coverage_start)
    coverage_end = date.fromisoformat(dataset.coverage_end)
    if not coverage_start <= cutoff_date <= coverage_end:
        raise MarketCalendarError("data cutoff is outside the locked calendar coverage")
    eligible = tuple(
        session
        for session in dataset.sessions
        if date.fromisoformat(session.trading_date) <= cutoff_date
        and _utc(session.closed_at) <= observed
    )
    if not eligible:
        raise MarketCalendarError("no completed regular session exists within calendar coverage")
    session = max(eligible, key=lambda item: item.trading_date)
    return CalendarSelection(
        calendar_id=dataset.calendar_id,
        mic=dataset.mic,
        dataset_sha256=dataset.dataset_sha256,
        official_source_url=dataset.official_source_url,
        official_source_record_sha256=dataset.official_source_record_sha256,
        coverage_start=dataset.coverage_start,
        coverage_end=dataset.coverage_end,
        session=session,
    )


__all__ = ()

