from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

from .calculation_integrity import build_calculation_result
from .contracts import (
    CalculationResult,
    Claim,
    Fact,
    FiscalPeriod,
    QuarterlyReconciliation,
    QuarterlyUpdate,
    SourceDocument,
)
from .fingerprints import canonical_sha256

NumericEvidence = Fact | CalculationResult
CALCULATOR_ID = "owner-research-quarterly"
CALCULATOR_VERSION = "0.2.0-alpha.1"
COMPARABILITY_EVIDENCE_CONCEPTS = frozenset(
    {
        "material_acquisition",
        "acquisition_bridge_available",
        "fx_material",
        "one_time_tax",
    }
)


class QuarterlyComputationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ComparabilityAssessment:
    status: str
    reasons: tuple[str, ...]


def _code_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _numeric_value(item: NumericEvidence) -> float:
    if item.value_type != "number" or isinstance(item.value, bool) or not isinstance(
        item.value, (int, float)
    ):
        raise QuarterlyComputationError(f"{item.concept} must be a numeric evidence item")
    return float(item.value)


def _period_dict(item: NumericEvidence) -> dict[str, str | None]:
    return dict(item.period)


def _required_date(value: str | None, *, label: str) -> date:
    if value is None:
        raise QuarterlyComputationError(f"{label} date is required")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise QuarterlyComputationError(f"{label} date is invalid") from exc


def _require_same_series(left: NumericEvidence, right: NumericEvidence) -> None:
    if left.issuer_id != right.issuer_id:
        raise QuarterlyComputationError("issuer mismatch")
    if left.concept != right.concept:
        raise QuarterlyComputationError("concept mismatch")
    if left.unit != right.unit:
        raise QuarterlyComputationError("unit mismatch")
    if left.currency != right.currency:
        raise QuarterlyComputationError("currency mismatch")


def _require_period(
    item: NumericEvidence,
    *,
    start: str,
    end: str,
    label: str,
) -> None:
    period = _period_dict(item)
    if period != {"start": start, "end": end}:
        raise QuarterlyComputationError(f"{label} evidence period does not match fiscal metadata")


def _build_result(
    *,
    issuer_id: str,
    concept: str,
    value: float,
    unit: str | None,
    currency: str | None,
    period: Mapping[str, str | None],
    inputs: Sequence[NumericEvidence],
    fiscal_periods: Sequence[FiscalPeriod] = (),
    input_bindings: Mapping[str, str] | None = None,
    generated_at: str,
) -> CalculationResult:
    facts = {item.fact_id: item for item in inputs if isinstance(item, Fact)}
    calculations = {
        item.calculation_id: item for item in inputs if isinstance(item, CalculationResult)
    }
    periods = {item.period_id: item for item in fiscal_periods}
    bindings = dict(input_bindings or {})
    code_sha256 = _code_sha256()
    identity = canonical_sha256(
        {
            "calculator": {
                "id": CALCULATOR_ID,
                "version": CALCULATOR_VERSION,
                "code_sha256": code_sha256,
            },
            "issuer_id": issuer_id,
            "concept": concept,
            "period": period,
            "facts": [
                {"id": identifier, "fingerprint": facts[identifier].fingerprint}
                for identifier in sorted(facts)
            ],
            "calculations": [
                {
                    "id": identifier,
                    "output_fingerprint": calculations[identifier].output_fingerprint,
                }
                for identifier in sorted(calculations)
            ],
            "fiscal_periods": [
                {"id": identifier, "fingerprint": periods[identifier].fingerprint}
                for identifier in sorted(periods)
            ],
            "bindings": bindings,
        }
    )[:20]
    payload = {
        "schema_version": "2.0.0",
        "calculation_id": f"calc:{issuer_id}:{concept}:{identity}",
        "issuer_id": issuer_id,
        "concept": concept,
        "value_type": "number",
        "value": value,
        "unit": unit,
        "currency": currency,
        "period": dict(period),
        "generator": "deterministic_program",
        "calculator_id": CALCULATOR_ID,
        "calculator_version": CALCULATOR_VERSION,
        "code_sha256": code_sha256,
        "input_fact_ids": sorted(facts),
        "input_assumption_ids": [],
        "input_calculation_ids": sorted(calculations),
        "input_period_ids": sorted(periods),
        "input_bindings": bindings,
        "input_fingerprint": "0" * 64,
        "output_fingerprint": "0" * 64,
        "generated_at": generated_at,
    }
    return build_calculation_result(
        payload,
        facts=facts,
        assumptions={},
        calculations=calculations,
        periods=periods,
    )


def validate_fiscal_period(period: FiscalPeriod) -> None:
    quarter_start = date.fromisoformat(period.quarter_start)
    quarter_end = date.fromisoformat(period.quarter_end)
    cumulative_start = date.fromisoformat(period.cumulative_start)
    cumulative_end = date.fromisoformat(period.cumulative_end)
    ttm_start = date.fromisoformat(period.ttm_start)
    if quarter_start > quarter_end:
        raise QuarterlyComputationError("quarter start follows quarter end")
    if cumulative_start > quarter_start:
        raise QuarterlyComputationError("cumulative start follows quarter start")
    if cumulative_end != quarter_end:
        raise QuarterlyComputationError("cumulative end must equal quarter end")
    if period.fiscal_quarter == 1 and (
        cumulative_start != quarter_start or cumulative_end != quarter_end
    ):
        raise QuarterlyComputationError("Q1 cumulative window must equal quarter window")
    if ttm_start >= quarter_end:
        raise QuarterlyComputationError("TTM start must precede quarter end")
    ttm_days = (quarter_end - ttm_start).days + 1
    if not 364 <= ttm_days <= 371:
        raise QuarterlyComputationError("TTM window must contain 52 or 53 weeks")
    if period.calendar_type == "52_53_week":
        actual_days = (quarter_end - quarter_start).days + 1
        if actual_days != period.weeks * 7:
            raise QuarterlyComputationError("52/53-week count does not match quarter dates")
    if period.status == "restated" and period.restatement_version < 1:
        raise QuarterlyComputationError("restated period must have a positive version")
    if period.restatement_version > 0 and period.status != "restated":
        raise QuarterlyComputationError("positive restatement version requires restated status")


def derive_discrete_quarter(
    current_cumulative: NumericEvidence,
    previous_cumulative: NumericEvidence | None,
    current_period: FiscalPeriod,
    previous_period: FiscalPeriod | None,
    *,
    generated_at: str,
) -> CalculationResult:
    validate_fiscal_period(current_period)
    if current_cumulative.issuer_id != current_period.issuer_id:
        raise QuarterlyComputationError("issuer mismatch between evidence and fiscal period")
    _require_period(
        current_cumulative,
        start=current_period.cumulative_start,
        end=current_period.cumulative_end,
        label="current cumulative",
    )
    current_value = _numeric_value(current_cumulative)
    inputs: list[NumericEvidence] = [current_cumulative]
    if current_period.fiscal_quarter == 1:
        if previous_cumulative is not None or previous_period is not None:
            raise QuarterlyComputationError("Q1 must not subtract a previous cumulative period")
        value = current_value
    else:
        if previous_cumulative is None or previous_period is None:
            raise QuarterlyComputationError("previous cumulative period is required for Q2-Q4")
        validate_fiscal_period(previous_period)
        if (
            previous_period.issuer_id != current_period.issuer_id
            or previous_period.fiscal_year != current_period.fiscal_year
            or previous_period.fiscal_quarter != current_period.fiscal_quarter - 1
        ):
            raise QuarterlyComputationError("previous cumulative fiscal period is not adjacent")
        if previous_period.cumulative_start != current_period.cumulative_start:
            raise QuarterlyComputationError("cumulative fiscal-year starts do not match")
        if date.fromisoformat(current_period.quarter_start) != date.fromisoformat(
            previous_period.quarter_end
        ) + timedelta(days=1):
            raise QuarterlyComputationError("adjacent fiscal quarters are not contiguous")
        _require_same_series(current_cumulative, previous_cumulative)
        _require_period(
            previous_cumulative,
            start=previous_period.cumulative_start,
            end=previous_period.cumulative_end,
            label="previous cumulative",
        )
        value = current_value - _numeric_value(previous_cumulative)
        inputs.append(previous_cumulative)
    return _build_result(
        issuer_id=current_period.issuer_id,
        concept=f"{current_cumulative.concept}.single_quarter",
        value=value,
        unit=current_cumulative.unit,
        currency=current_cumulative.currency,
        period={"start": current_period.quarter_start, "end": current_period.quarter_end},
        inputs=inputs,
        fiscal_periods=tuple(
            item for item in (current_period, previous_period) if item is not None
        ),
        input_bindings={
            "current_cumulative": current_cumulative.fact_id
            if isinstance(current_cumulative, Fact)
            else current_cumulative.calculation_id,
            "current_period": current_period.period_id,
            **(
                {
                    "previous_cumulative": previous_cumulative.fact_id
                    if isinstance(previous_cumulative, Fact)
                    else previous_cumulative.calculation_id,
                    "previous_period": previous_period.period_id,
                }
                if previous_cumulative is not None and previous_period is not None
                else {}
            ),
        },
        generated_at=generated_at,
    )


def derive_ttm(
    current_ytd: NumericEvidence,
    prior_fiscal_year: NumericEvidence | None,
    prior_comparable_ytd: NumericEvidence | None,
    current_period: FiscalPeriod,
    *,
    generated_at: str,
) -> CalculationResult:
    validate_fiscal_period(current_period)
    if current_ytd.issuer_id != current_period.issuer_id:
        raise QuarterlyComputationError("issuer mismatch between TTM evidence and fiscal period")
    if prior_fiscal_year is None:
        raise QuarterlyComputationError("prior fiscal year is required for TTM")
    if prior_comparable_ytd is None:
        raise QuarterlyComputationError("prior comparable YTD is required for TTM")
    _require_same_series(current_ytd, prior_fiscal_year)
    _require_same_series(current_ytd, prior_comparable_ytd)
    _require_period(
        current_ytd,
        start=current_period.cumulative_start,
        end=current_period.cumulative_end,
        label="current YTD",
    )
    prior_fy_period = _period_dict(prior_fiscal_year)
    prior_ytd_period = _period_dict(prior_comparable_ytd)
    prior_fy_start = _required_date(
        prior_fy_period["start"], label="prior fiscal year start"
    )
    prior_fy_end = _required_date(prior_fy_period["end"], label="prior fiscal year end")
    prior_fy_days = (prior_fy_end - prior_fy_start).days + 1
    allowed_fy_days = (
        {364, 371} if current_period.calendar_type == "52_53_week" else {365, 366}
    )
    if prior_fy_days not in allowed_fy_days:
        raise QuarterlyComputationError(
            "prior fiscal year must cover a complete fiscal year"
        )
    if prior_fy_period["start"] != prior_ytd_period["start"]:
        raise QuarterlyComputationError("prior FY and prior comparable YTD starts do not match")
    prior_ytd_end = _required_date(
        prior_ytd_period["end"], label="prior comparable YTD end"
    )
    prior_ytd_days = (prior_ytd_end - prior_fy_start).days + 1
    minimum_ytd_days = current_period.fiscal_quarter * 12 * 7
    maximum_ytd_days = current_period.fiscal_quarter * 14 * 7
    if not minimum_ytd_days <= prior_ytd_days <= maximum_ytd_days:
        raise QuarterlyComputationError(
            "prior comparable YTD duration is inconsistent with the fiscal quarter"
        )
    if prior_ytd_end > prior_fy_end:
        raise QuarterlyComputationError("prior comparable YTD exceeds prior fiscal year")
    if prior_fy_end + timedelta(days=1) != date.fromisoformat(
        current_period.cumulative_start
    ):
        raise QuarterlyComputationError("prior fiscal year is not adjacent to current fiscal year")
    if prior_ytd_end + timedelta(days=1) != date.fromisoformat(current_period.ttm_start):
        raise QuarterlyComputationError("TTM start does not follow prior comparable YTD")
    value = (
        _numeric_value(current_ytd)
        + _numeric_value(prior_fiscal_year)
        - _numeric_value(prior_comparable_ytd)
    )
    return _build_result(
        issuer_id=current_period.issuer_id,
        concept=f"{current_ytd.concept}.ttm",
        value=value,
        unit=current_ytd.unit,
        currency=current_ytd.currency,
        period={"start": current_period.ttm_start, "end": current_period.quarter_end},
        inputs=[current_ytd, prior_fiscal_year, prior_comparable_ytd],
        fiscal_periods=[current_period],
        input_bindings={
            "current_ytd": _evidence_id(current_ytd),
            "prior_fiscal_year": _evidence_id(prior_fiscal_year),
            "prior_comparable_ytd": _evidence_id(prior_comparable_ytd),
            "current_period": current_period.period_id,
        },
        generated_at=generated_at,
    )


def per_week_growth_diagnostic(
    current_quarter: NumericEvidence,
    comparison_quarter: NumericEvidence,
    current_period: FiscalPeriod,
    comparison_period: FiscalPeriod,
    *,
    generated_at: str,
) -> CalculationResult:
    validate_fiscal_period(current_period)
    validate_fiscal_period(comparison_period)
    _require_same_series_for_derived(current_quarter, comparison_quarter)
    if (
        current_quarter.issuer_id != current_period.issuer_id
        or comparison_quarter.issuer_id != comparison_period.issuer_id
        or current_period.issuer_id != comparison_period.issuer_id
    ):
        raise QuarterlyComputationError("issuer mismatch in per-week comparison")
    if "52_53_week" not in {current_period.calendar_type, comparison_period.calendar_type}:
        raise QuarterlyComputationError("per-week diagnostic requires a 52/53-week calendar")
    _require_period(
        current_quarter,
        start=current_period.quarter_start,
        end=current_period.quarter_end,
        label="current quarter",
    )
    _require_period(
        comparison_quarter,
        start=comparison_period.quarter_start,
        end=comparison_period.quarter_end,
        label="comparison quarter",
    )
    if current_period.comparative_period_id != comparison_period.period_id:
        raise QuarterlyComputationError("comparison fiscal period does not match current metadata")
    comparison_per_week = _numeric_value(comparison_quarter) / comparison_period.weeks
    if comparison_per_week == 0:
        raise QuarterlyComputationError("comparison per-week value cannot be zero")
    value = (_numeric_value(current_quarter) / current_period.weeks) / comparison_per_week - 1
    return _build_result(
        issuer_id=current_period.issuer_id,
        concept=f"{_base_concept(current_quarter.concept)}.per_week_growth_diagnostic",
        value=value,
        unit="ratio",
        currency=None,
        period={"start": current_period.quarter_start, "end": current_period.quarter_end},
        inputs=[current_quarter, comparison_quarter],
        fiscal_periods=[current_period, comparison_period],
        input_bindings={
            "current_quarter": _evidence_id(current_quarter),
            "comparison_quarter": _evidence_id(comparison_quarter),
            "current_period": current_period.period_id,
            "comparison_period": comparison_period.period_id,
        },
        generated_at=generated_at,
    )


def _base_concept(concept: str) -> str:
    return concept.removesuffix(".single_quarter")


def _evidence_id(item: NumericEvidence) -> str:
    return item.fact_id if isinstance(item, Fact) else item.calculation_id


def _require_same_series_for_derived(
    left: NumericEvidence, right: NumericEvidence
) -> None:
    if left.issuer_id != right.issuer_id:
        raise QuarterlyComputationError("issuer mismatch")
    if _base_concept(left.concept) != _base_concept(right.concept):
        raise QuarterlyComputationError("concept mismatch")
    if left.unit != right.unit:
        raise QuarterlyComputationError("unit mismatch")
    if left.currency != right.currency:
        raise QuarterlyComputationError("currency mismatch")


def calculate_ratio(
    numerator: NumericEvidence,
    denominator: NumericEvidence,
    *,
    concept: str,
    result_period: Mapping[str, str | None],
    generated_at: str,
) -> CalculationResult:
    if numerator.issuer_id != denominator.issuer_id:
        raise QuarterlyComputationError("issuer mismatch")
    if numerator.currency != denominator.currency:
        raise QuarterlyComputationError("currency mismatch")
    if numerator.unit != denominator.unit:
        raise QuarterlyComputationError("unit mismatch")
    if _period_dict(numerator) != _period_dict(denominator):
        raise QuarterlyComputationError("ratio evidence periods do not match")
    if dict(result_period) != _period_dict(numerator):
        raise QuarterlyComputationError("ratio result period does not match evidence")
    denominator_value = _numeric_value(denominator)
    if denominator_value == 0:
        raise QuarterlyComputationError("ratio denominator cannot be zero")
    return _build_result(
        issuer_id=numerator.issuer_id,
        concept=concept,
        value=_numeric_value(numerator) / denominator_value,
        unit="ratio",
        currency=None,
        period=result_period,
        inputs=[numerator, denominator],
        input_bindings={
            "numerator": _evidence_id(numerator),
            "denominator": _evidence_id(denominator),
        },
        generated_at=generated_at,
    )


def calculate_change(
    current: NumericEvidence,
    prior: NumericEvidence,
    *,
    concept: str,
    as_ratio: bool,
    result_period: Mapping[str, str | None],
    fiscal_period: FiscalPeriod,
    generated_at: str,
) -> CalculationResult:
    _require_same_series(current, prior)
    validate_fiscal_period(fiscal_period)
    if current.issuer_id != fiscal_period.issuer_id:
        raise QuarterlyComputationError("change evidence issuer does not match fiscal period")
    normalized_result_period = dict(result_period)
    allowed_result_periods = (
        {"start": fiscal_period.quarter_start, "end": fiscal_period.quarter_end},
        {"start": fiscal_period.cumulative_start, "end": fiscal_period.cumulative_end},
    )
    if normalized_result_period not in allowed_result_periods:
        raise QuarterlyComputationError(
            "change result period must match the fiscal quarter or cumulative window"
        )
    current_period = _period_dict(current)
    point_in_time_at_end = {
        "start": normalized_result_period["end"],
        "end": normalized_result_period["end"],
    }
    if current_period not in (normalized_result_period, point_in_time_at_end):
        raise QuarterlyComputationError(
            "current change evidence does not match the result period"
        )
    prior_value = _numeric_value(prior)
    if as_ratio:
        if prior_value == 0:
            raise QuarterlyComputationError("change denominator cannot be zero")
        value = _numeric_value(current) / prior_value - 1
        unit = "ratio"
        currency = None
    else:
        value = _numeric_value(current) - prior_value
        unit = current.unit
        currency = current.currency
    return _build_result(
        issuer_id=current.issuer_id,
        concept=concept,
        value=value,
        unit=unit,
        currency=currency,
        period=normalized_result_period,
        inputs=[current, prior],
        fiscal_periods=[fiscal_period],
        input_bindings={
            "current": _evidence_id(current),
            "prior": _evidence_id(prior),
            "fiscal_period": fiscal_period.period_id,
        },
        generated_at=generated_at,
    )


def derive_free_cash_flow(
    operating_cash_flow: NumericEvidence,
    capital_expenditure_outflow: NumericEvidence,
    *,
    generated_at: str,
) -> CalculationResult:
    if operating_cash_flow.concept != "operating_cash_flow":
        raise QuarterlyComputationError("operating cash flow concept is required")
    if capital_expenditure_outflow.concept != "capital_expenditure_outflow":
        raise QuarterlyComputationError("capital expenditure outflow concept is required")
    if operating_cash_flow.issuer_id != capital_expenditure_outflow.issuer_id:
        raise QuarterlyComputationError("issuer mismatch")
    if operating_cash_flow.unit != capital_expenditure_outflow.unit:
        raise QuarterlyComputationError("unit mismatch")
    if operating_cash_flow.currency != capital_expenditure_outflow.currency:
        raise QuarterlyComputationError("currency mismatch")
    if _period_dict(operating_cash_flow) != _period_dict(capital_expenditure_outflow):
        raise QuarterlyComputationError("cash-flow periods do not match")
    capex = _numeric_value(capital_expenditure_outflow)
    if capex < 0:
        raise QuarterlyComputationError(
            "capital expenditure must use the positive outflow convention"
        )
    return _build_result(
        issuer_id=operating_cash_flow.issuer_id,
        concept="free_cash_flow",
        value=_numeric_value(operating_cash_flow) - capex,
        unit=operating_cash_flow.unit,
        currency=operating_cash_flow.currency,
        period=_period_dict(operating_cash_flow),
        inputs=[operating_cash_flow, capital_expenditure_outflow],
        input_bindings={
            "operating_cash_flow": _evidence_id(operating_cash_flow),
            "capital_expenditure_outflow": _evidence_id(capital_expenditure_outflow),
        },
        generated_at=generated_at,
    )


def reconcile_growth_bridge(
    reported_growth: NumericEvidence,
    components: Mapping[str, NumericEvidence],
    *,
    result_period: Mapping[str, str | None],
    generated_at: str,
) -> CalculationResult:
    required = {"fx", "acquisition", "price", "volume"}
    component_names = set(components)
    if component_names != required:
        missing = sorted(required - component_names)
        extra = sorted(component_names - required)
        raise QuarterlyComputationError(
            f"missing growth bridge components or unexpected growth bridge components; "
            f"missing={missing}, extra={extra}"
        )
    if reported_growth.unit != "ratio":
        raise QuarterlyComputationError("reported growth must use ratio units")
    if _period_dict(reported_growth) != dict(result_period):
        raise QuarterlyComputationError("reported growth period does not match bridge period")
    inputs: list[NumericEvidence] = [reported_growth]
    expected_concepts = {name: f"{name}_impact" for name in required}
    component_ids = [_evidence_id(components[name]) for name in sorted(required)]
    if len(component_ids) != len(set(component_ids)):
        raise QuarterlyComputationError("growth bridge components must use distinct evidence")
    if _evidence_id(reported_growth) in set(component_ids):
        raise QuarterlyComputationError("reported growth cannot also be a bridge component")
    for name in sorted(required):
        component = components[name]
        if component.concept != expected_concepts[name]:
            raise QuarterlyComputationError(
                f"{name} bridge concept mismatch; expected {expected_concepts[name]}"
            )
        if component.issuer_id != reported_growth.issuer_id or component.unit != "ratio":
            raise QuarterlyComputationError(f"invalid {name} growth bridge component")
        if component.currency != reported_growth.currency:
            raise QuarterlyComputationError(f"currency mismatch in {name} bridge component")
        if _period_dict(component) != dict(result_period):
            raise QuarterlyComputationError(f"period mismatch in {name} bridge component")
        inputs.append(component)
    value = _numeric_value(reported_growth) - sum(
        _numeric_value(components[name]) for name in required
    )
    return _build_result(
        issuer_id=reported_growth.issuer_id,
        concept="growth_bridge_residual",
        value=value,
        unit="ratio",
        currency=None,
        period=result_period,
        inputs=inputs,
        input_bindings={
            "reported_growth": _evidence_id(reported_growth),
            **{name: _evidence_id(components[name]) for name in sorted(required)},
        },
        generated_at=generated_at,
    )


def reconcile_metric(
    candidates: Sequence[Fact],
    documents: Mapping[str, SourceDocument],
    period: FiscalPeriod,
    *,
    basis: str,
    tolerance: float,
    generated_at: str,
) -> tuple[QuarterlyReconciliation, CalculationResult | None]:
    if len(candidates) < 2:
        raise QuarterlyComputationError("at least two candidate facts are required")
    if tolerance < 0:
        raise QuarterlyComputationError("reconciliation tolerance cannot be negative")
    validate_fiscal_period(period)
    if basis == "single_quarter":
        expected_period = {"start": period.quarter_start, "end": period.quarter_end}
    elif basis == "ytd":
        expected_period = {"start": period.cumulative_start, "end": period.cumulative_end}
    else:
        raise QuarterlyComputationError("reconciliation basis must be single_quarter or ytd")
    first = candidates[0]
    if first.issuer_id != period.issuer_id:
        raise QuarterlyComputationError("candidate issuer does not match fiscal period")
    for candidate in candidates:
        _numeric_value(candidate)
        if candidate.source_document_id not in documents:
            raise QuarterlyComputationError(
                f"candidate source document is missing: {candidate.source_document_id}"
            )
        if documents[candidate.source_document_id].issuer_id != candidate.issuer_id:
            raise QuarterlyComputationError(
                "candidate source document issuer does not match the Fact"
            )
        if _period_dict(candidate) != expected_period:
            basis_label = "single-quarter" if basis == "single_quarter" else "YTD"
            raise QuarterlyComputationError(
                f"candidate period does not match {basis_label} window"
            )
    for candidate in candidates[1:]:
        _require_same_series(first, candidate)
        if _period_dict(candidate) != _period_dict(first):
            raise QuarterlyComputationError("candidate periods do not match")
    regulatory = [
        candidate
        for candidate in candidates
        if candidate.source_document_id in documents
        and documents[candidate.source_document_id].authority_level == "primary_regulatory"
    ]
    candidate_ids = tuple(sorted(candidate.fact_id for candidate in candidates))
    identity = canonical_sha256(
        {"period_id": period.period_id, "basis": basis, "candidate_fact_ids": candidate_ids}
    )[:20]
    if not regulatory:
        reconciliation = QuarterlyReconciliation(
            schema_version="1.0.0",
            reconciliation_id=f"reconciliation:{period.issuer_id}:{first.concept}:{identity}",
            issuer_id=period.issuer_id,
            period_id=period.period_id,
            basis=basis,
            concept=first.concept,
            candidate_fact_ids=candidate_ids,
            authoritative_fact_id=None,
            delta_calculation_id=None,
            tolerance=tolerance,
            status="conflict",
            selection_rule="no_regulatory_authority",
            blocked=True,
            notes="No regulatory filing candidate is available.",
        )
        return reconciliation, None
    authoritative = max(
        regulatory,
        key=lambda item: (
            documents[item.source_document_id].document_type.endswith("/A"),
            documents[item.source_document_id].published_date,
            item.fact_id,
        ),
    )
    comparison_candidates = sorted(
        (item for item in candidates if item.fact_id != authoritative.fact_id),
        key=lambda item: item.fact_id,
    )
    maximum_absolute_delta = max(
        abs(_numeric_value(authoritative) - _numeric_value(item))
        for item in comparison_candidates
    )
    delta = _build_result(
        issuer_id=period.issuer_id,
        concept=f"{first.concept}.reconciliation_max_absolute_delta",
        value=maximum_absolute_delta,
        unit=first.unit,
        currency=first.currency,
        period=expected_period,
        inputs=list(candidates),
        fiscal_periods=[period],
        input_bindings={
            "authoritative": authoritative.fact_id,
            "period": period.period_id,
            **{
                f"candidate_{index}": item.fact_id
                for index, item in enumerate(comparison_candidates, start=1)
            },
        },
        generated_at=generated_at,
    )
    authoritative_document = documents[authoritative.source_document_id]
    amended = authoritative_document.document_type.endswith("/A")
    absolute_delta = float(delta.value)
    if amended:
        status = "restated_authority"
        rule = "latest_regulatory_amendment"
        blocked = False
    elif absolute_delta == 0:
        status = "exact_match"
        rule = "regulatory_over_company_release"
        blocked = False
    elif absolute_delta <= tolerance:
        status = "tolerance_match"
        rule = "regulatory_over_company_release"
        blocked = False
    else:
        status = "conflict"
        rule = "regulatory_over_company_release"
        blocked = True
    reconciliation = QuarterlyReconciliation(
        schema_version="1.0.0",
        reconciliation_id=f"reconciliation:{period.issuer_id}:{first.concept}:{identity}",
        issuer_id=period.issuer_id,
        period_id=period.period_id,
        basis=basis,
        concept=first.concept,
        candidate_fact_ids=candidate_ids,
        authoritative_fact_id=authoritative.fact_id,
        delta_calculation_id=delta.calculation_id,
        tolerance=tolerance,
        status=status,
        selection_rule=rule,
        blocked=blocked,
        notes=(
            "Regulatory authority selected by deterministic publication and amendment order; "
            "maximum absolute delta covers every non-authoritative candidate."
        ),
    )
    return reconciliation, delta


def assess_comparability(
    current_period: FiscalPeriod,
    comparison_period: FiscalPeriod,
    evidence_facts: Sequence[Fact],
) -> ComparabilityAssessment:
    validate_fiscal_period(current_period)
    validate_fiscal_period(comparison_period)
    if current_period.issuer_id != comparison_period.issuer_id:
        raise QuarterlyComputationError("issuer mismatch between comparison periods")
    if current_period.fiscal_quarter != comparison_period.fiscal_quarter:
        raise QuarterlyComputationError("fiscal quarter mismatch")
    if comparison_period.fiscal_year != current_period.fiscal_year - 1:
        raise QuarterlyComputationError("comparison must be the prior fiscal year")
    facts: dict[str, Fact] = {}
    for fact in evidence_facts:
        if fact.issuer_id != current_period.issuer_id or fact.value_type != "boolean":
            raise QuarterlyComputationError("comparability evidence must be issuer boolean Facts")
        if fact.concept in facts:
            raise QuarterlyComputationError(
                f"duplicate comparability evidence for {fact.concept}"
            )
        if fact.concept not in COMPARABILITY_EVIDENCE_CONCEPTS:
            raise QuarterlyComputationError(
                f"unsupported comparability evidence concept: {fact.concept}"
            )
        if _period_dict(fact) != {
            "start": current_period.quarter_start,
            "end": current_period.quarter_end,
        }:
            raise QuarterlyComputationError(
                "comparability evidence must match the current quarter"
            )
        facts[fact.concept] = fact
    reasons: list[str] = []
    if current_period.status == "restated" or current_period.restatement_version > 0:
        reasons.append("restatement")
    required_evidence = {
        "material_acquisition": "missing_material_acquisition_evidence",
        "fx_material": "missing_fx_evidence",
        "one_time_tax": "missing_one_time_tax_evidence",
    }
    missing = [
        missing_reason
        for concept, missing_reason in required_evidence.items()
        if concept not in facts
    ]
    reasons.extend(missing)
    material_acquisition = (
        bool(facts["material_acquisition"].value)
        if "material_acquisition" in facts
        else False
    )
    if material_acquisition:
        reasons.append("material_acquisition")
        if "acquisition_bridge_available" not in facts:
            reasons.append("missing_acquisition_bridge_evidence")
        elif not bool(facts["acquisition_bridge_available"].value):
            reasons.append("missing_acquisition_bridge")
    if current_period.weeks != comparison_period.weeks:
        reasons.append("53_week_difference")
    if current_period.calendar_type != comparison_period.calendar_type:
        reasons.append("fiscal_calendar_change")
    if "fx_material" in facts and bool(facts["fx_material"].value):
        reasons.append("fx")
    if "one_time_tax" in facts and bool(facts["one_time_tax"].value):
        reasons.append("one_time_tax")
    if missing or "missing_acquisition_bridge_evidence" in reasons:
        status = "unknown"
    elif "missing_acquisition_bridge" in reasons or "fiscal_calendar_change" in reasons:
        status = "not_comparable"
    elif reasons:
        status = "partially_comparable"
    else:
        status = "comparable"
    return ComparabilityAssessment(status=status, reasons=tuple(reasons))


def build_quarterly_update(
    *,
    update_id: str,
    as_of_date: str,
    current_period: FiscalPeriod,
    comparison_period: FiscalPeriod,
    status: str,
    comparability: ComparabilityAssessment,
    facts: Sequence[Fact],
    calculations: Sequence[CalculationResult],
    reconciliations: Sequence[QuarterlyReconciliation],
    what_changed_claims: Sequence[Claim],
    why_it_changed_claims: Sequence[Claim] = (),
    temporary_or_structural_claims: Sequence[Claim] = (),
    guidance_change_claims: Sequence[Claim] = (),
    long_term_thesis_impact_claims: Sequence[Claim] = (),
    valuation_assumption_impact_claims: Sequence[Claim] = (),
    valuation_assumption_review_required: bool = False,
    confidence: str = "low",
    missing_evidence: Sequence[str] = (),
    red_flags: Sequence[str] = (),
) -> QuarterlyUpdate:
    issuer = current_period.issuer_id
    if comparison_period.issuer_id != issuer:
        raise QuarterlyComputationError("issuer mismatch between quarterly update periods")
    if current_period.comparative_period_id != comparison_period.period_id:
        raise QuarterlyComputationError(
            "quarterly update comparison does not match FiscalPeriod metadata"
        )
    referenced = (
        *facts,
        *calculations,
        *reconciliations,
        *what_changed_claims,
        *why_it_changed_claims,
        *temporary_or_structural_claims,
        *guidance_change_claims,
        *long_term_thesis_impact_claims,
        *valuation_assumption_impact_claims,
    )
    if any(item.issuer_id != issuer for item in referenced):
        raise QuarterlyComputationError("quarterly update references multiple issuers")
    comparability_facts = [
        item
        for item in facts
        if item.concept in COMPARABILITY_EVIDENCE_CONCEPTS
    ]
    evidence_assessment = assess_comparability(
        current_period,
        comparison_period,
        comparability_facts,
    )
    if evidence_assessment != comparability:
        raise QuarterlyComputationError(
            "provided comparability assessment does not match referenced evidence"
        )
    if comparability.status in {"unknown", "not_comparable"} and status != "blocked":
        raise QuarterlyComputationError(
            f"{comparability.status} comparability requires a blocked update"
        )
    if any(item.blocked for item in reconciliations) and status != "blocked":
        raise QuarterlyComputationError("blocked reconciliation requires a blocked update")
    return QuarterlyUpdate(
        schema_version="1.0.0",
        update_id=update_id,
        issuer_id=issuer,
        as_of_date=as_of_date,
        current_period_id=current_period.period_id,
        comparison_period_id=comparison_period.period_id,
        status=status,
        comparability={"status": comparability.status, "reasons": list(comparability.reasons)},
        fact_ids=tuple(sorted(item.fact_id for item in facts)),
        calculation_result_ids=tuple(
            sorted(item.calculation_id for item in calculations)
        ),
        reconciliation_ids=tuple(
            sorted(item.reconciliation_id for item in reconciliations)
        ),
        what_changed_claim_ids=tuple(
            sorted(item.claim_id for item in what_changed_claims)
        ),
        why_it_changed_claim_ids=tuple(
            sorted(item.claim_id for item in why_it_changed_claims)
        ),
        temporary_or_structural_claim_ids=tuple(
            sorted(item.claim_id for item in temporary_or_structural_claims)
        ),
        guidance_change_claim_ids=tuple(
            sorted(item.claim_id for item in guidance_change_claims)
        ),
        long_term_thesis_impact_claim_ids=tuple(
            sorted(item.claim_id for item in long_term_thesis_impact_claims)
        ),
        impact_on_valuation_assumptions_claim_ids=tuple(
            sorted(item.claim_id for item in valuation_assumption_impact_claims)
        ),
        valuation_assumption_review_required=valuation_assumption_review_required,
        confidence=confidence,
        missing_evidence=tuple(missing_evidence),
        red_flags=tuple(red_flags),
    )
