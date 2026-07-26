from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Any

from .calculation_integrity import build_calculation_result
from .contracts import (
    CalculationResult,
    Claim,
    Fact,
    ManagementCommitment,
    ManagementOutcome,
    SourceDocument,
)
from .fingerprints import canonical_sha256, to_json_value
from .management_policies import policy
from .units import compatible_units, normalize_value, unit_spec


class OutcomeEvaluationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class OutcomeEvidence:
    component_id: str
    fact_ids: tuple[str, ...]
    calculation_result_id: str | None


@dataclass(frozen=True, slots=True)
class OutcomeEvaluationRequest:
    assessed_at: str
    evaluation_period: dict[str, str]
    evidence: tuple[OutcomeEvidence, ...]
    result_scope: dict[str, str]
    result_measurement_basis: dict[str, str]
    claim_ids: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    predecessor_outcome_id: str | None


@dataclass(frozen=True, slots=True)
class OutcomeEvaluation:
    outcome: ManagementOutcome
    generated_calculations: tuple[CalculationResult, ...]


def evaluate_outcome(
    *,
    commitment: ManagementCommitment,
    facts: Sequence[Fact],
    calculations: Sequence[CalculationResult],
    source_documents: Sequence[SourceDocument],
    claims: Sequence[Claim],
    request: OutcomeEvaluationRequest,
) -> OutcomeEvaluation:
    assessed_at = date.fromisoformat(request.assessed_at)
    period_start = date.fromisoformat(request.evaluation_period["start"])
    period_end = date.fromisoformat(request.evaluation_period["end"])
    if period_start > period_end or period_end > assessed_at:
        raise OutcomeEvaluationError("invalid Outcome evaluation period")
    if period_start < date.fromisoformat(commitment.start_date):
        raise OutcomeEvaluationError("Outcome period starts before Commitment")

    claim_issue = _claim_issue(commitment, claims, request)
    if commitment.status in {"withdrawn", "superseded"}:
        if claim_issue is not None:
            return _blocked(commitment, request, (claim_issue,))
        return OutcomeEvaluation(_outcome(commitment, request, commitment.status, (), ()), ())
    if commitment.status == "blocked":
        return _blocked(
            commitment,
            request,
            tuple(commitment.missing_evidence) or ("commitment_blocked",),
        )
    if assessed_at < date.fromisoformat(commitment.due_date):
        if claim_issue is not None:
            return _blocked(commitment, request, (claim_issue,))
        return OutcomeEvaluation(
            _outcome(commitment, request, "pending", (), ("commitment_not_due",)), ()
        )
    if claim_issue is not None:
        return _blocked(commitment, request, (claim_issue,))
    if not request.evidence:
        missing = tuple(request.missing_evidence) or ("official_result_not_disclosed",)
        return OutcomeEvaluation(_outcome(commitment, request, "unverifiable", (), missing), ())
    if to_json_value(commitment.scope) != request.result_scope:
        return _blocked(commitment, request, ("scope_mismatch",))
    if to_json_value(commitment.measurement_basis) != request.result_measurement_basis:
        return _blocked(commitment, request, ("measurement_basis_mismatch",))

    fact_map = {item.fact_id: item for item in facts}
    calculation_map = {item.calculation_id: item for item in calculations}
    document_map = {item.document_id: item for item in source_documents}
    components = _commitment_components(commitment)
    evidence_map = {item.component_id: item for item in request.evidence}
    if len(evidence_map) != len(request.evidence) or set(evidence_map) != components:
        return _blocked(commitment, request, ("component_mismatch",))

    generated: list[CalculationResult] = []
    bindings: list[dict[str, str | None]] = []
    results: dict[str, Fact | CalculationResult] = {}
    for component_id in sorted(components):
        try:
            value, binding, new_calculations = _resolve_component_result(
                commitment=commitment,
                component_id=component_id,
                evidence=evidence_map[component_id],
                request=request,
                facts=fact_map,
                calculations=calculation_map,
                documents=document_map,
            )
        except OutcomeEvaluationError as exc:
            return _blocked(commitment, request, (_reason_code(exc),))
        results[component_id] = value
        bindings.append(binding)
        for calculation in new_calculations:
            calculation_map[calculation.calculation_id] = calculation
            generated.append(calculation)

    if not _claims_cover_result_evidence(
        bindings=bindings,
        claim_ids=request.claim_ids,
        claims=claims,
        calculations=calculation_map,
    ):
        return _blocked(commitment, request, ("claim_result_coverage_missing",))

    passed = [
        _evaluate_component(commitment, component_id, results[component_id], fact_map)
        for component_id in sorted(components)
    ]
    if all(passed):
        status = "met"
    elif len(passed) > 1 and any(passed):
        status = "partially_met"
    else:
        status = "missed"
    return OutcomeEvaluation(
        _outcome(commitment, request, status, tuple(bindings), ()), tuple(generated)
    )


def recompute_outcome_status(
    *,
    commitment: ManagementCommitment,
    outcome: ManagementOutcome,
    facts: dict[str, Fact],
    calculations: dict[str, CalculationResult],
) -> str:
    if outcome.status not in {"met", "partially_met", "missed"}:
        raise OutcomeEvaluationError("only evaluated Outcomes have arithmetic status")
    components = _commitment_components(commitment)
    results: dict[str, Fact | CalculationResult] = {}
    for binding in outcome.result_bindings:
        component_id = binding["component_id"]
        if component_id in results:
            raise OutcomeEvaluationError("duplicate result component")
        if binding["fact_id"] is not None:
            results[component_id] = facts[binding["fact_id"]]
        else:
            results[component_id] = calculations[binding["calculation_result_id"]]
    if set(results) != components:
        raise OutcomeEvaluationError("result component set mismatch")
    passed = [
        _evaluate_component(commitment, component_id, results[component_id], facts)
        for component_id in sorted(components)
    ]
    if all(passed):
        return "met"
    if len(passed) > 1 and any(passed):
        return "partially_met"
    return "missed"


def _resolve_component_result(
    *,
    commitment: ManagementCommitment,
    component_id: str,
    evidence: OutcomeEvidence,
    request: OutcomeEvaluationRequest,
    facts: dict[str, Fact],
    calculations: dict[str, CalculationResult],
    documents: dict[str, SourceDocument],
) -> tuple[
    Fact | CalculationResult,
    dict[str, str | None],
    tuple[CalculationResult, ...],
]:
    if evidence.calculation_result_id is not None and evidence.fact_ids:
        raise OutcomeEvaluationError("evidence_shape_mismatch")
    if evidence.calculation_result_id is not None:
        calculation = calculations.get(evidence.calculation_result_id)
        if calculation is None:
            raise OutcomeEvaluationError("calculation_missing")
        _validate_calculation(
            commitment,
            component_id,
            calculation,
            request,
            facts,
            calculations,
            documents,
        )
        _validate_basis_calculator(commitment, calculation)
        if commitment.definition_reconciliation_calculation_ids and not (
            calculation.calculation_id in commitment.definition_reconciliation_calculation_ids
            or set(calculation.input_calculation_ids).intersection(
                commitment.definition_reconciliation_calculation_ids
            )
        ):
            raise OutcomeEvaluationError("kpi_bridge_missing")
        return (
            calculation,
            {
                "component_id": component_id,
                "role": _result_role(commitment),
                "fact_id": None,
                "calculation_result_id": calculation.calculation_id,
            },
            (),
        )
    actual_facts = []
    for fact_id in evidence.fact_ids:
        fact = facts.get(fact_id)
        if fact is None:
            raise OutcomeEvaluationError("result_fact_missing")
        if fact.issuer_id != commitment.issuer_id:
            raise OutcomeEvaluationError("cross_issuer_result")
        _validate_official_fact(fact, request, documents)
        actual_facts.append(fact)
    if not actual_facts:
        raise OutcomeEvaluationError("result_evidence_missing")
    if commitment.definition_reconciliation_calculation_ids:
        raise OutcomeEvaluationError("kpi_bridge_missing")
    if _requires_basis_calculation(commitment):
        raise OutcomeEvaluationError("basis_requires_deterministic_calculation")
    if commitment.evaluation_policy_id in {"growth_minimum", "growth_range"}:
        if len(actual_facts) != 1:
            raise OutcomeEvaluationError("growth_requires_single_actual")
        baseline = _baseline_fact(commitment, component_id, facts)
        calculation = _growth_calculation(
            commitment, component_id, baseline, actual_facts[0], request, facts, calculations
        )
        _validate_against_targets(commitment, component_id, calculation, facts)
        return (
            calculation,
            {
                "component_id": component_id,
                "role": "actual",
                "fact_id": None,
                "calculation_result_id": calculation.calculation_id,
            },
            (calculation,),
        )
    if commitment.evaluation_policy_id == "cumulative_minimum":
        calculation = _cumulative_calculation(
            commitment, component_id, actual_facts, request, facts, calculations
        )
        _validate_against_targets(commitment, component_id, calculation, facts)
        return (
            calculation,
            {
                "component_id": component_id,
                "role": "actual",
                "fact_id": None,
                "calculation_result_id": calculation.calculation_id,
            },
            (calculation,),
        )
    if len(actual_facts) != 1:
        raise OutcomeEvaluationError("policy_requires_single_actual")
    actual = actual_facts[0]
    expected_concept = commitment.metric_concept
    if actual.concept != expected_concept:
        raise OutcomeEvaluationError("metric_mismatch")
    _validate_period(actual.period, request.evaluation_period)
    _validate_against_targets(commitment, component_id, actual, facts)
    return (
        actual,
        {
            "component_id": component_id,
            "role": _result_role(commitment),
            "fact_id": actual.fact_id,
            "calculation_result_id": None,
        },
        (),
    )


def _growth_calculation(
    commitment: ManagementCommitment,
    component_id: str,
    baseline: Fact,
    actual: Fact,
    request: OutcomeEvaluationRequest,
    facts: dict[str, Fact],
    calculations: dict[str, CalculationResult],
) -> CalculationResult:
    if actual.concept != baseline.concept:
        raise OutcomeEvaluationError("metric_mismatch")
    _validate_period(actual.period, request.evaluation_period)
    if not compatible_units(actual.unit, baseline.unit) or actual.currency != baseline.currency:
        raise OutcomeEvaluationError("unit_or_currency_mismatch")
    base_value = normalize_value(_number(baseline.value), baseline.unit)
    if base_value == 0:
        raise OutcomeEvaluationError("growth_baseline_zero")
    growth = normalize_value(_number(actual.value), actual.unit) / base_value - Decimal(1)
    return _calculation(
        commitment=commitment,
        component_id=component_id,
        calculator_id="owner-research-management-growth",
        value=float(growth),
        unit="ratio",
        currency=None,
        request=request,
        input_facts=(baseline, actual),
        facts=facts,
        calculations=calculations,
    )


def _cumulative_calculation(
    commitment: ManagementCommitment,
    component_id: str,
    actual_facts: Sequence[Fact],
    request: OutcomeEvaluationRequest,
    facts: dict[str, Fact],
    calculations: dict[str, CalculationResult],
) -> CalculationResult:
    targets = _target_facts(commitment, component_id, facts)
    target = targets[0]
    total = Decimal(0)
    windows: list[tuple[date, date]] = []
    for actual in actual_facts:
        if actual.concept != commitment.metric_concept:
            raise OutcomeEvaluationError("metric_mismatch")
        if not compatible_units(actual.unit, target.unit) or actual.currency != target.currency:
            raise OutcomeEvaluationError("unit_or_currency_mismatch")
        actual_start = date.fromisoformat(actual.period["start"])
        actual_end = date.fromisoformat(actual.period["end"])
        if actual_start < date.fromisoformat(
            request.evaluation_period["start"]
        ) or actual_end > date.fromisoformat(request.evaluation_period["end"]):
            raise OutcomeEvaluationError("period_mismatch")
        if any(not (actual_end < start or actual_start > end) for start, end in windows):
            raise OutcomeEvaluationError("cumulative_period_overlap")
        windows.append((actual_start, actual_end))
        total += normalize_value(_number(actual.value), actual.unit)
    value = total / unit_spec(target.unit).scale
    return _calculation(
        commitment=commitment,
        component_id=component_id,
        calculator_id="owner-research-management-cumulative",
        value=float(value),
        unit=target.unit,
        currency=target.currency,
        request=request,
        input_facts=tuple(actual_facts),
        facts=facts,
        calculations=calculations,
    )


def _calculation(
    *,
    commitment: ManagementCommitment,
    component_id: str,
    calculator_id: str,
    value: float,
    unit: str,
    currency: str | None,
    request: OutcomeEvaluationRequest,
    input_facts: tuple[Fact, ...],
    facts: dict[str, Fact],
    calculations: dict[str, CalculationResult],
) -> CalculationResult:
    input_ids = tuple(sorted(item.fact_id for item in input_facts))
    digest = canonical_sha256(
        [
            commitment.commitment_id,
            component_id,
            calculator_id,
            input_ids,
            request.evaluation_period,
        ]
    )[:20]
    payload = {
        "schema_version": "2.0.0",
        "calculation_id": f"management-calculation:{commitment.issuer_id}:{digest}",
        "issuer_id": commitment.issuer_id,
        "concept": commitment.metric_concept,
        "value_type": "number",
        "value": value,
        "unit": unit,
        "currency": currency,
        "period": request.evaluation_period,
        "generator": "deterministic_program",
        "calculator_id": calculator_id,
        "calculator_version": "1.0.0",
        "code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "input_fact_ids": input_ids,
        "input_assumption_ids": [],
        "input_calculation_ids": [],
        "input_period_ids": [],
        "input_bindings": {f"input_{index}": fact_id for index, fact_id in enumerate(input_ids)},
        "input_fingerprint": "0" * 64,
        "output_fingerprint": "0" * 64,
        "generated_at": f"{request.assessed_at}T00:00:00Z",
    }
    return build_calculation_result(
        payload,
        facts=facts,
        assumptions={},
        calculations=calculations,
    )


def _evaluate_component(
    commitment: ManagementCommitment,
    component_id: str,
    actual: Fact | CalculationResult,
    facts: dict[str, Fact],
) -> bool:
    policy(commitment.evaluation_policy_id, commitment.evaluation_policy_version)
    value = actual.value
    targets = {
        item["role"]: facts[item["fact_id"]].value
        for item in commitment.target_bindings
        if item["component_id"] == component_id
    }
    policy_id = commitment.evaluation_policy_id
    if policy_id == "numeric_minimum":
        return _decimal(value) >= _decimal(targets["lower_bound"])
    if policy_id == "numeric_maximum":
        return _decimal(value) <= _decimal(targets["upper_bound"])
    if policy_id == "numeric_range" or policy_id == "growth_range":
        return (
            _decimal(targets["lower_bound"]) <= _decimal(value) <= _decimal(targets["upper_bound"])
        )
    if policy_id == "numeric_point":
        return _decimal(value) == _decimal(targets["point"])
    if policy_id in {"growth_minimum", "cumulative_minimum"}:
        return _decimal(value) >= _decimal(targets["lower_bound"])
    if policy_id == "maintain_or_improve":
        baseline = _baseline_fact(commitment, component_id, facts)
        if commitment.comparison_direction == "higher_is_better":
            return _decimal(value) >= _decimal(baseline.value)
        return _decimal(value) <= _decimal(baseline.value)
    if policy_id in {"milestone_by_date", "policy_compliance"}:
        return value is True and targets["milestone"] is True
    raise OutcomeEvaluationError("unsupported_policy")


def _validate_official_fact(
    fact: Fact,
    request: OutcomeEvaluationRequest,
    documents: dict[str, SourceDocument],
) -> None:
    document = documents.get(fact.source_document_id)
    if document is None or document.authority_level not in {
        "primary_regulatory",
        "company_primary",
    }:
        raise OutcomeEvaluationError("unofficial_result_source")
    if date.fromisoformat(document.published_date) > date.fromisoformat(request.assessed_at):
        raise OutcomeEvaluationError("result_published_after_assessment")


def _validate_calculation(
    commitment: ManagementCommitment,
    component_id: str,
    calculation: CalculationResult,
    request: OutcomeEvaluationRequest,
    facts: dict[str, Fact],
    calculations: dict[str, CalculationResult],
    documents: dict[str, SourceDocument],
) -> None:
    if calculation.issuer_id != commitment.issuer_id:
        raise OutcomeEvaluationError("cross_issuer_result")
    if calculation.generator != "deterministic_program" or calculation.input_assumption_ids:
        raise OutcomeEvaluationError("calculation_not_assumption_free")
    if calculation.concept != commitment.metric_concept:
        raise OutcomeEvaluationError("metric_mismatch")
    _validate_period(calculation.period, request.evaluation_period)
    for fact_id in calculation.input_fact_ids:
        fact = facts.get(fact_id)
        if fact is None:
            raise OutcomeEvaluationError("calculation_input_missing")
        if fact.issuer_id != commitment.issuer_id:
            raise OutcomeEvaluationError("cross_issuer_result")
        _validate_official_fact(fact, request, documents)
    for bridge_id in commitment.definition_reconciliation_calculation_ids:
        bridge = calculations.get(bridge_id)
        if bridge is None:
            raise OutcomeEvaluationError("kpi_bridge_missing")
        if bridge.generator != "deterministic_program" or bridge.input_assumption_ids:
            raise OutcomeEvaluationError("kpi_bridge_not_assumption_free")
        for fact_id in bridge.input_fact_ids:
            fact = facts.get(fact_id)
            if fact is None:
                raise OutcomeEvaluationError("kpi_bridge_input_missing")
            if fact.issuer_id != commitment.issuer_id:
                raise OutcomeEvaluationError("cross_issuer_result")
            _validate_official_fact(fact, request, documents)
    _validate_against_targets(commitment, component_id, calculation, facts)


def _validate_against_targets(
    commitment: ManagementCommitment,
    component_id: str | None,
    actual: Fact | CalculationResult,
    facts: dict[str, Fact],
) -> None:
    targets = (
        _target_facts(commitment, component_id, facts)
        if commitment.evaluation_policy_id != "maintain_or_improve"
        else [_baseline_fact(commitment, component_id, facts)]
    )
    for target in targets:
        if actual.value_type != target.value_type:
            raise OutcomeEvaluationError("value_type_mismatch")
        if actual.value_type == "number" and (
            not compatible_units(actual.unit, target.unit) or actual.currency != target.currency
        ):
            raise OutcomeEvaluationError("unit_or_currency_mismatch")


def _target_facts(
    commitment: ManagementCommitment,
    component_id: str | None,
    facts: dict[str, Fact],
) -> list[Fact]:
    targets = [
        facts[item["fact_id"]]
        for item in commitment.target_bindings
        if component_id is None or item["component_id"] == component_id
    ]
    if not targets:
        raise OutcomeEvaluationError("target_evidence_missing")
    return targets


def _baseline_fact(
    commitment: ManagementCommitment,
    component_id: str | None,
    facts: dict[str, Fact],
) -> Fact:
    matches = [
        facts[item["fact_id"]]
        for item in commitment.baseline_bindings
        if component_id is None or item["component_id"] == component_id
    ]
    if len(matches) != 1:
        raise OutcomeEvaluationError("baseline_evidence_mismatch")
    return matches[0]


def _commitment_components(commitment: ManagementCommitment) -> set[str]:
    bindings = (
        commitment.baseline_bindings
        if commitment.evaluation_policy_id == "maintain_or_improve"
        else commitment.target_bindings
    )
    return {item["component_id"] for item in bindings}


def _claim_issue(
    commitment: ManagementCommitment,
    claims: Sequence[Claim],
    request: OutcomeEvaluationRequest,
) -> str | None:
    claim_map = {item.claim_id: item for item in claims}
    if not request.claim_ids:
        return "outcome_claim_missing"
    for claim_id in request.claim_ids:
        claim = claim_map.get(claim_id)
        if claim is None or claim.issuer_id != commitment.issuer_id:
            return "outcome_claim_missing_or_cross_issuer"
        if date.fromisoformat(claim.as_of_date) > date.fromisoformat(request.assessed_at):
            return "outcome_claim_postdates_assessment"
    return None


def _claims_cover_result_evidence(
    *,
    bindings: Sequence[dict[str, str | None]],
    claim_ids: Sequence[str],
    claims: Sequence[Claim],
    calculations: dict[str, CalculationResult],
) -> bool:
    formal_fact_ids: set[str] = set()
    visited: set[str] = set()

    def collect(calculation_id: str) -> None:
        if calculation_id in visited:
            return
        visited.add(calculation_id)
        calculation = calculations[calculation_id]
        formal_fact_ids.update(calculation.input_fact_ids)
        for dependency_id in calculation.input_calculation_ids:
            collect(dependency_id)

    for binding in bindings:
        if binding["fact_id"] is not None:
            formal_fact_ids.add(binding["fact_id"])
        else:
            collect(binding["calculation_result_id"])
    claim_map = {item.claim_id: item for item in claims}
    supporting = {
        fact_id for claim_id in claim_ids for fact_id in claim_map[claim_id].supporting_fact_ids
    }
    return formal_fact_ids.issubset(supporting)


def _requires_basis_calculation(commitment: ManagementCommitment) -> bool:
    return commitment.measurement_basis[
        "currency_basis"
    ] == "constant_currency" or commitment.measurement_basis["growth_basis"] in {
        "organic",
        "inorganic",
    }


def _validate_basis_calculator(
    commitment: ManagementCommitment,
    calculation: CalculationResult,
) -> None:
    currency_basis = commitment.measurement_basis["currency_basis"]
    growth_basis = commitment.measurement_basis["growth_basis"]
    expected = None
    if currency_basis == "constant_currency" and growth_basis == "organic":
        expected = "owner-research-organic-constant-currency-growth"
    elif currency_basis == "constant_currency":
        expected = "owner-research-constant-currency-growth"
    elif growth_basis == "organic":
        expected = "owner-research-organic-growth"
    elif growth_basis == "inorganic":
        expected = "owner-research-inorganic-growth"
    if expected is not None and calculation.calculator_id != expected:
        raise OutcomeEvaluationError("basis_calculator_mismatch")


def _outcome(
    commitment: ManagementCommitment,
    request: OutcomeEvaluationRequest,
    status: str,
    result_bindings: tuple[dict[str, str | None], ...],
    missing_evidence: tuple[str, ...],
) -> ManagementOutcome:
    digest = canonical_sha256(
        [commitment.commitment_id, request.assessed_at, request.evaluation_period]
    )[:20]
    return ManagementOutcome(
        schema_version="2.0.0",
        outcome_id=f"management-outcome:{commitment.issuer_id}:{digest}",
        issuer_id=commitment.issuer_id,
        commitment_id=commitment.commitment_id,
        predecessor_outcome_id=request.predecessor_outcome_id,
        assessed_at=request.assessed_at,
        evaluation_period=request.evaluation_period,
        status=status,
        result_bindings=result_bindings,
        result_scope=request.result_scope,
        result_measurement_basis=request.result_measurement_basis,
        claim_ids=request.claim_ids if status != "blocked" else (),
        missing_evidence=missing_evidence,
    )


def _blocked(
    commitment: ManagementCommitment,
    request: OutcomeEvaluationRequest,
    reasons: tuple[str, ...],
) -> OutcomeEvaluation:
    missing = tuple(sorted(set((*request.missing_evidence, *reasons))))
    return OutcomeEvaluation(_outcome(commitment, request, "blocked", (), missing), ())


def _validate_period(actual: Any, expected: dict[str, str]) -> None:
    if to_json_value(actual) != expected:
        raise OutcomeEvaluationError("period_mismatch")


def _number(value: Any) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OutcomeEvaluationError("numeric_value_required")
    return value


def _decimal(value: Any) -> Decimal:
    return Decimal(str(_number(value)))


def _result_role(commitment: ManagementCommitment) -> str:
    return (
        "milestone_evidence"
        if commitment.evaluation_policy_id in {"milestone_by_date", "policy_compliance"}
        else "actual"
    )


def _reason_code(error: OutcomeEvaluationError) -> str:
    return str(error).replace(" ", "_").lower()
