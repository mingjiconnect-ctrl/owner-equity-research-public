from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path

from .calculation_integrity import build_calculation_result
from .contracts import CalculationResult, Fact, FiscalPeriod
from .fingerprints import canonical_sha256

CALCULATOR_ID = "owner-research-segments"
CALCULATOR_VERSION = "0.3.0-alpha.1"


class SegmentComputationError(ValueError):
    pass


def display_precision_tolerance(rounding_increment: float, displayed_values: int) -> float:
    if rounding_increment <= 0 or displayed_values < 1:
        raise SegmentComputationError("display precision inputs must be positive")
    return rounding_increment * displayed_values / 2.0


def _numeric(fact: Fact) -> float:
    if (
        fact.value_type != "number"
        or isinstance(fact.value, bool)
        or not isinstance(fact.value, (int, float))
    ):
        raise SegmentComputationError(f"{fact.fact_id} must be numeric")
    return float(fact.value)


def _require_compatible(facts: Sequence[Fact]) -> None:
    if not facts:
        raise SegmentComputationError("at least one Fact is required")
    first = facts[0]
    for fact in facts[1:]:
        if (
            fact.issuer_id != first.issuer_id
            or fact.unit != first.unit
            or fact.currency != first.currency
        ):
            raise SegmentComputationError("segment Facts have incompatible series metadata")


def _require_same_period(facts: Sequence[Fact]) -> None:
    _require_compatible(facts)
    first_period = dict(facts[0].period)
    if any(dict(fact.period) != first_period for fact in facts[1:]):
        raise SegmentComputationError("segment Facts have incompatible periods")


def _build(
    *,
    concept: str,
    value: float,
    facts: Sequence[Fact],
    periods: Sequence[FiscalPeriod],
    input_bindings: Mapping[str, str],
    unit: str | None,
    currency: str | None,
    period: Mapping[str, str | None],
    generated_at: str,
    require_same_fact_period: bool = True,
) -> CalculationResult:
    if require_same_fact_period:
        _require_same_period(facts)
    else:
        _require_compatible(facts)
    fact_map = {fact.fact_id: fact for fact in facts}
    period_map = {item.period_id: item for item in periods}
    code_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    identity = canonical_sha256(
        {
            "concept": concept,
            "facts": {key: value.fingerprint for key, value in sorted(fact_map.items())},
            "periods": {key: value.fingerprint for key, value in sorted(period_map.items())},
            "bindings": dict(input_bindings),
        }
    )[:20]
    payload = {
        "schema_version": "2.0.0",
        "calculation_id": f"calc:{facts[0].issuer_id}:{concept}:{identity}",
        "issuer_id": facts[0].issuer_id,
        "concept": concept,
        "value_type": "number",
        "value": value,
        "unit": unit,
        "currency": currency,
        "period": dict(period),
        "generator": "deterministic_program",
        "calculator_id": CALCULATOR_ID,
        "calculator_version": CALCULATOR_VERSION,
        "code_sha256": code_sha,
        "input_fact_ids": sorted(fact_map),
        "input_assumption_ids": [],
        "input_calculation_ids": [],
        "input_period_ids": sorted(period_map),
        "input_bindings": dict(input_bindings),
        "input_fingerprint": "0" * 64,
        "output_fingerprint": "0" * 64,
        "generated_at": generated_at,
    }
    return build_calculation_result(
        payload,
        facts=fact_map,
        assumptions={},
        calculations={},
        periods=period_map,
    )


def reconcile_segments(
    segment_facts: Sequence[Fact],
    consolidated_fact: Fact,
    fiscal_period: FiscalPeriod,
    *,
    rounding_increment: float,
    generated_at: str,
) -> tuple[CalculationResult, bool, float]:
    facts = (*segment_facts, consolidated_fact)
    _require_compatible(facts)
    value = sum(_numeric(fact) for fact in segment_facts) - _numeric(consolidated_fact)
    tolerance = display_precision_tolerance(rounding_increment, len(facts))
    result = _build(
        concept=f"{consolidated_fact.concept}.segment_reconciliation_delta",
        value=value,
        facts=facts,
        periods=(fiscal_period,),
        input_bindings={
            **{f"segment_{index}": fact.fact_id for index, fact in enumerate(segment_facts)},
            "consolidated": consolidated_fact.fact_id,
            "fiscal_period": fiscal_period.period_id,
        },
        unit=consolidated_fact.unit,
        currency=consolidated_fact.currency,
        period=consolidated_fact.period,
        generated_at=generated_at,
    )
    return result, abs(value) <= tolerance, tolerance


def ratio_metric(
    numerator: Fact,
    denominator: Fact,
    fiscal_period: FiscalPeriod,
    *,
    concept: str,
    generated_at: str,
) -> CalculationResult:
    _require_same_period((numerator, denominator))
    denominator_value = _numeric(denominator)
    if denominator_value == 0:
        raise SegmentComputationError("ratio denominator cannot be zero")
    return _build(
        concept=concept,
        value=_numeric(numerator) / denominator_value,
        facts=(numerator, denominator),
        periods=(fiscal_period,),
        input_bindings={
            "numerator": numerator.fact_id,
            "denominator": denominator.fact_id,
            "fiscal_period": fiscal_period.period_id,
        },
        unit="ratio",
        currency=None,
        period=numerator.period,
        generated_at=generated_at,
    )


def growth_metric(
    current: Fact,
    prior: Fact,
    current_period: FiscalPeriod,
    prior_period: FiscalPeriod,
    *,
    generated_at: str,
) -> CalculationResult:
    if (
        current.issuer_id != prior.issuer_id
        or current.concept != prior.concept
        or current.unit != prior.unit
        or current.currency != prior.currency
    ):
        raise SegmentComputationError("growth Facts are not comparable")
    prior_value = _numeric(prior)
    if prior_value == 0:
        raise SegmentComputationError("growth prior value cannot be zero")
    return _build(
        concept=f"{current.concept}.growth",
        value=_numeric(current) / prior_value - 1.0,
        facts=(current, prior),
        periods=(current_period, prior_period),
        input_bindings={
            "current": current.fact_id,
            "prior": prior.fact_id,
            "current_period": current_period.period_id,
            "prior_period": prior_period.period_id,
        },
        unit="ratio",
        currency=None,
        period=current.period,
        generated_at=generated_at,
        require_same_fact_period=False,
    )


def sum_metric(
    facts: Sequence[Fact],
    fiscal_period: FiscalPeriod,
    *,
    concept: str,
    generated_at: str,
) -> CalculationResult:
    """Add disclosed metric Facts without filling an undisclosed component."""
    _require_same_period(facts)
    first = facts[0]
    return _build(
        concept=concept,
        value=sum(_numeric(fact) for fact in facts),
        facts=facts,
        periods=(fiscal_period,),
        input_bindings={
            **{f"component_{index}": fact.fact_id for index, fact in enumerate(facts)},
            "fiscal_period": fiscal_period.period_id,
        },
        unit=first.unit,
        currency=first.currency,
        period=first.period,
        generated_at=generated_at,
    )


def share_metric(
    segment: Fact,
    consolidated: Fact,
    fiscal_period: FiscalPeriod,
    *,
    generated_at: str,
) -> CalculationResult:
    """Calculate a segment's disclosed share of a consolidated metric."""
    return ratio_metric(
        segment,
        consolidated,
        fiscal_period,
        concept=f"{segment.concept}.share",
        generated_at=generated_at,
    )


def margin_metric(
    profit_loss: Fact,
    revenue: Fact,
    fiscal_period: FiscalPeriod,
    *,
    generated_at: str,
) -> CalculationResult:
    """Calculate a segment margin only when both disclosed Facts exist."""
    if profit_loss.concept == revenue.concept:
        raise SegmentComputationError("margin requires distinct profit and revenue Facts")
    return ratio_metric(
        profit_loss,
        revenue,
        fiscal_period,
        concept=f"{profit_loss.concept}.margin",
        generated_at=generated_at,
    )


def capital_intensity_metric(
    assets: Fact,
    revenue: Fact,
    fiscal_period: FiscalPeriod,
    *,
    generated_at: str,
) -> CalculationResult:
    """Calculate disclosed segment assets per unit of revenue."""
    return ratio_metric(
        assets,
        revenue,
        fiscal_period,
        concept=f"{assets.concept}.capital_intensity",
        generated_at=generated_at,
    )
