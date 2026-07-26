from __future__ import annotations

import copy

import pytest
from quarterly_support import GOLDEN, load_case

from owner_research.contracts import FiscalPeriod
from owner_research.quarterly import QuarterlyComputationError, validate_fiscal_period


@pytest.mark.parametrize("path", sorted(GOLDEN.glob("*.json")))
def test_every_golden_fiscal_period_passes_semantic_validation(path) -> None:
    case = load_case(path.name)
    for payload in case["periods"]:
        validate_fiscal_period(FiscalPeriod(**payload))


def test_53_week_metadata_must_match_actual_quarter_dates() -> None:
    payload = copy.deepcopy(load_case("non-calendar-53-week.json")["periods"][1])
    payload["weeks"] = 13
    with pytest.raises(QuarterlyComputationError, match="week count"):
        validate_fiscal_period(FiscalPeriod(**payload))


def test_q1_cumulative_window_must_equal_quarter_window() -> None:
    payload = copy.deepcopy(load_case("non-calendar-53-week.json")["periods"][0])
    payload["cumulative_start"] = "2025-08-25"
    with pytest.raises(QuarterlyComputationError, match="Q1 cumulative"):
        validate_fiscal_period(FiscalPeriod(**payload))


def test_cumulative_end_must_equal_quarter_end() -> None:
    payload = copy.deepcopy(load_case("sbc-lease-heavy.json")["periods"][1])
    payload["cumulative_end"] = "2026-06-29"
    with pytest.raises(QuarterlyComputationError, match="cumulative end"):
        validate_fiscal_period(FiscalPeriod(**payload))
