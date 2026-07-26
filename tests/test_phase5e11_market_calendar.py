from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from owner_research.valuation_market_authority import load_market_access_authority
from owner_research.valuation_market_calendar import (
    MarketCalendarError,
    select_latest_completed_session,
)


def _select(mic: str, cutoff: str, observed: str):
    return select_latest_completed_session(
        load_market_access_authority(),
        mic=mic,
        cutoff_date=date.fromisoformat(cutoff),
        observed_at=datetime.fromisoformat(observed.replace("Z", "+00:00")),
    )


@pytest.mark.parametrize("mic", ("XNYS", "XNAS"))
def test_weekend_and_independence_holiday_select_latest_completed_session(mic: str) -> None:
    selection = _select(mic, "2026-07-04", "2026-07-04T23:00:00Z")
    assert selection.session.trading_date == "2026-07-02"
    assert selection.session.closed_at == "2026-07-02T20:00:00Z"


@pytest.mark.parametrize("mic", ("XNYS", "XNAS"))
def test_early_close_is_explicit_and_completed_at_1800_utc(mic: str) -> None:
    before = _select(mic, "2026-11-27", "2026-11-27T17:59:59Z")
    after = _select(mic, "2026-11-27", "2026-11-27T18:00:00Z")
    assert before.session.trading_date == "2026-11-25"
    assert after.session.trading_date == "2026-11-27"
    assert after.session.early_close is True
    assert after.session.closed_at == "2026-11-27T18:00:00Z"


def test_dst_boundaries_are_stored_not_inferred_at_runtime() -> None:
    authority = load_market_access_authority()
    dataset = next(item for item in authority.calendar_registry.datasets if item.mic == "XNYS")
    by_date = {item.trading_date: item for item in dataset.sessions}
    assert by_date["2026-03-06"].opened_at == "2026-03-06T14:30:00Z"
    assert by_date["2026-03-06"].closed_at == "2026-03-06T21:00:00Z"
    assert by_date["2026-03-09"].opened_at == "2026-03-09T13:30:00Z"
    assert by_date["2026-03-09"].closed_at == "2026-03-09T20:00:00Z"


def test_cutoff_today_before_close_selects_prior_completed_session() -> None:
    selection = _select("XNYS", "2026-06-30", "2026-06-30T19:59:59Z")
    assert selection.session.trading_date == "2026-06-29"


@pytest.mark.parametrize(
    ("mic", "cutoff"),
    (("XLON", "2026-06-30"), ("XNYS", "2025-12-31"), ("XNAS", "2027-01-01")),
)
def test_unknown_mic_and_uncovered_year_fail_closed(mic: str, cutoff: str) -> None:
    with pytest.raises(MarketCalendarError):
        select_latest_completed_session(
            load_market_access_authority(),
            mic=mic,
            cutoff_date=date.fromisoformat(cutoff),
            observed_at=datetime(2026, 7, 14, tzinfo=UTC),
        )


def test_dataset_selection_is_content_addressed_and_replayable() -> None:
    first = _select("XNAS", "2026-06-30", "2026-07-01T00:00:00Z")
    second = _select("XNAS", "2026-06-30", "2026-07-01T00:00:00Z")
    assert first == second
    assert first.fingerprint == second.fingerprint
    assert len(first.dataset_sha256) == 64
    assert len(first.official_source_record_sha256) == 64

