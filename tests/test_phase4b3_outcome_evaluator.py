from __future__ import annotations

from dataclasses import replace

import pytest
from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.calculation_integrity import build_calculation_result
from owner_research.management_outcomes import (
    OutcomeEvaluationRequest,
    OutcomeEvidence,
    evaluate_outcome,
)
from owner_research.validation import ContractGraphError


def _request(**updates: object) -> OutcomeEvaluationRequest:
    values: dict[str, object] = {
        "assessed_at": "2027-01-15",
        "evaluation_period": {"start": "2026-01-01", "end": "2026-12-31"},
        "evidence": (),
        "result_scope": {
            "scope_type": "issuer",
            "scope_id": "issuer:acme",
            "scope_label": "Acme consolidated",
        },
        "result_measurement_basis": {
            "accounting_basis": "gaap",
            "currency_basis": "reported",
            "growth_basis": "reported",
            "aggregation_basis": "period",
        },
        "claim_ids": ("claim:acme:outcome-evaluation",),
        "missing_evidence": (),
        "predecessor_outcome_id": None,
    }
    values.update(updates)
    return OutcomeEvaluationRequest(**values)


def _claims_for(graph, *facts):
    outcome_claim = replace(
        graph.claims[0],
        claim_id="claim:acme:outcome-evaluation",
        supporting_fact_ids=tuple(
            dict.fromkeys((graph.facts[0].fact_id, *(item.fact_id for item in facts)))
        ),
    )
    return (
        graph.claims[0],
        outcome_claim,
    )


def _growth_evaluation(sample_payloads: dict[str, dict], actual_value: float | None = None):
    graph = valid_phase4a_graph(sample_payloads)
    baseline = graph.facts[0]
    resolved_actual = baseline.value * 1.06 if actual_value is None else actual_value
    actual = replace(
        baseline,
        fact_id="fact:acme:revenue:2026",
        value=resolved_actual,
        period={"start": "2026-01-01", "end": "2026-12-31"},
    )
    result = evaluate_outcome(
        commitment=graph.management_commitments[0],
        facts=(*graph.facts, actual),
        calculations=graph.calculations,
        source_documents=graph.documents,
        claims=_claims_for(graph, actual),
        request=_request(
            evidence=(OutcomeEvidence("primary", (actual.fact_id,), None),),
        ),
    )
    return graph, actual, result


def _calculation(
    *,
    actual,
    calculation_id: str,
    calculator_id: str,
    value: float,
    concept: str = "revenue_growth",
    input_calculations=(),
):
    known_calculations = {item.calculation_id: item for item in input_calculations}
    return build_calculation_result(
        {
            "schema_version": "2.0.0",
            "calculation_id": calculation_id,
            "issuer_id": "issuer:acme",
            "concept": concept,
            "value_type": "number",
            "value": value,
            "unit": "ratio",
            "currency": None,
            "period": {"start": "2026-01-01", "end": "2026-12-31"},
            "generator": "deterministic_program",
            "calculator_id": calculator_id,
            "calculator_version": "1.0.0",
            "code_sha256": "c" * 64,
            "input_fact_ids": [actual.fact_id],
            "input_assumption_ids": [],
            "input_calculation_ids": [item.calculation_id for item in input_calculations],
            "input_period_ids": [],
            "input_bindings": {"actual": actual.fact_id},
            "input_fingerprint": "0" * 64,
            "output_fingerprint": "0" * 64,
            "generated_at": "2027-01-15T00:00:00Z",
        },
        facts={actual.fact_id: actual},
        assumptions={},
        calculations=known_calculations,
    )


def test_growth_range_generates_assumption_free_calculation_and_met_status(
    sample_payloads: dict[str, dict],
) -> None:
    _, _, result = _growth_evaluation(sample_payloads)
    assert result.outcome.status == "met"
    assert len(result.generated_calculations) == 1
    calculation = result.generated_calculations[0]
    assert calculation.value == pytest.approx(0.06)
    assert calculation.input_assumption_ids == ()
    assert result.outcome.result_bindings[0]["calculation_result_id"] == (
        calculation.calculation_id
    )
    graph, actual, validated = _growth_evaluation(sample_payloads)
    replace_graph(
        graph,
        facts=(*graph.facts, actual),
        claims=_claims_for(graph, actual),
        calculations=(*graph.calculations, *validated.generated_calculations),
        management_outcomes=(validated.outcome,),
        management_reviews=(),
    ).validate()
    with pytest.raises(ContractGraphError, match="registered policy arithmetic"):
        replace_graph(
            graph,
            facts=(*graph.facts, actual),
            claims=_claims_for(graph, actual),
            calculations=(*graph.calculations, *validated.generated_calculations),
            management_outcomes=(replace(validated.outcome, status="missed"),),
            management_reviews=(),
        ).validate()


def test_claim_cannot_override_arithmetic_status(sample_payloads: dict[str, dict]) -> None:
    _, _, result = _growth_evaluation(sample_payloads, actual_value=1300.0)
    assert result.outcome.status == "missed"
    assert result.outcome.claim_ids == ("claim:acme:outcome-evaluation",)


def test_not_due_commitment_is_pending_even_with_result_evidence(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    actual = replace(
        graph.facts[0],
        fact_id="fact:actual",
        value=1325.0,
        period={"start": "2026-01-01", "end": "2026-06-30"},
    )
    result = evaluate_outcome(
        commitment=graph.management_commitments[0],
        facts=(*graph.facts, actual),
        calculations=graph.calculations,
        source_documents=graph.documents,
        claims=_claims_for(graph, actual),
        request=_request(
            assessed_at="2026-06-30",
            evaluation_period={"start": "2026-01-01", "end": "2026-06-30"},
            evidence=(OutcomeEvidence("primary", (actual.fact_id,), None),),
        ),
    )
    assert result.outcome.status == "pending"
    assert result.outcome.result_bindings == ()


def test_due_commitment_without_official_result_is_unverifiable(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    result = evaluate_outcome(
        commitment=graph.management_commitments[0],
        facts=graph.facts,
        calculations=graph.calculations,
        source_documents=graph.documents,
        claims=_claims_for(graph),
        request=_request(),
    )
    assert result.outcome.status == "unverifiable"
    assert "official_result_not_disclosed" in result.outcome.missing_evidence


@pytest.mark.parametrize(
    ("field", "replacement", "reason"),
    [
        (
            "result_scope",
            {
                "scope_type": "product",
                "scope_id": "product:other",
                "scope_label": "Other product",
            },
            "scope_mismatch",
        ),
        (
            "result_measurement_basis",
            {
                "accounting_basis": "gaap",
                "currency_basis": "constant_currency",
                "growth_basis": "reported",
                "aggregation_basis": "period",
            },
            "measurement_basis_mismatch",
        ),
    ],
)
def test_scope_or_basis_mismatch_is_blocked_not_compared(
    sample_payloads: dict[str, dict], field: str, replacement: object, reason: str
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    actual = replace(
        graph.facts[0],
        fact_id="fact:acme:revenue:2026",
        value=1060.0,
        period={"start": "2026-01-01", "end": "2026-12-31"},
    )
    result = evaluate_outcome(
        commitment=graph.management_commitments[0],
        facts=(*graph.facts, actual),
        calculations=graph.calculations,
        source_documents=graph.documents,
        claims=_claims_for(graph, actual),
        request=_request(
            evidence=(OutcomeEvidence("primary", (actual.fact_id,), None),),
            **{field: replacement},
        ),
    )
    assert result.outcome.status == "blocked"
    assert reason in result.outcome.missing_evidence


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"concept": "operating_margin"}, "metric_mismatch"),
        ({"unit": "shares", "currency": None}, "unit_or_currency_mismatch"),
        ({"issuer_id": "issuer:other"}, "cross_issuer"),
        (
            {"period": {"start": "2026-01-01", "end": "2026-09-30"}},
            "period_mismatch",
        ),
    ],
)
def test_incomparable_actual_fact_is_blocked(
    sample_payloads: dict[str, dict], changes: dict[str, object], reason: str
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    actual_changes = {
        "fact_id": "fact:actual",
        "value": 1325.0,
        "period": {"start": "2026-01-01", "end": "2026-12-31"},
    }
    actual_changes.update(changes)
    actual = replace(graph.facts[0], **actual_changes)
    result = evaluate_outcome(
        commitment=graph.management_commitments[0],
        facts=(*graph.facts, actual),
        calculations=graph.calculations,
        source_documents=graph.documents,
        claims=_claims_for(graph, actual),
        request=_request(evidence=(OutcomeEvidence("primary", (actual.fact_id,), None),)),
    )
    assert result.outcome.status == "blocked"
    assert any(reason in item for item in result.outcome.missing_evidence)


def test_unofficial_result_source_is_blocked(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    actual = replace(
        graph.facts[0],
        fact_id="fact:actual",
        value=1325.0,
        period={"start": "2026-01-01", "end": "2026-12-31"},
    )
    result = evaluate_outcome(
        commitment=graph.management_commitments[0],
        facts=(*graph.facts, actual),
        calculations=graph.calculations,
        source_documents=(replace(graph.documents[0], authority_level="secondary"),),
        claims=_claims_for(graph, actual),
        request=_request(evidence=(OutcomeEvidence("primary", (actual.fact_id,), None),)),
    )
    assert result.outcome.status == "blocked"
    assert "unofficial_result_source" in result.outcome.missing_evidence


@pytest.mark.parametrize(
    ("currency_basis", "growth_basis", "calculator_id"),
    [
        ("constant_currency", "reported", "owner-research-constant-currency-growth"),
        ("reported", "organic", "owner-research-organic-growth"),
    ],
)
def test_adjusted_growth_requires_named_deterministic_calculation(
    sample_payloads: dict[str, dict],
    currency_basis: str,
    growth_basis: str,
    calculator_id: str,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    actual = replace(
        graph.facts[0],
        fact_id="fact:actual",
        value=1325.0,
        period={"start": "2026-01-01", "end": "2026-12-31"},
    )
    basis = {
        **graph.management_commitments[0].to_dict()["measurement_basis"],
        "currency_basis": currency_basis,
        "growth_basis": growth_basis,
    }
    commitment = replace(graph.management_commitments[0], measurement_basis=basis)
    raw = evaluate_outcome(
        commitment=commitment,
        facts=(*graph.facts, actual),
        calculations=graph.calculations,
        source_documents=graph.documents,
        claims=_claims_for(graph, actual),
        request=_request(
            evidence=(OutcomeEvidence("primary", (actual.fact_id,), None),),
            result_measurement_basis=basis,
        ),
    )
    assert raw.outcome.status == "blocked"
    assert "basis_requires_deterministic_calculation" in raw.outcome.missing_evidence

    calculation = _calculation(
        actual=actual,
        calculation_id="calc:adjusted-growth",
        calculator_id=calculator_id,
        value=0.06,
    )
    evaluated = evaluate_outcome(
        commitment=commitment,
        facts=(*graph.facts, actual),
        calculations=(*graph.calculations, calculation),
        source_documents=graph.documents,
        claims=_claims_for(graph, actual),
        request=_request(
            evidence=(OutcomeEvidence("primary", (), calculation.calculation_id),),
            result_measurement_basis=basis,
        ),
    )
    assert evaluated.outcome.status == "met"


def test_kpi_bridge_must_be_deterministic_assumption_free_and_connected(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    actual = replace(
        graph.facts[0],
        fact_id="fact:actual",
        value=1325.0,
        period={"start": "2026-01-01", "end": "2026-12-31"},
    )
    bridge = _calculation(
        actual=actual,
        calculation_id="calc:kpi-bridge",
        calculator_id="owner-research-kpi-bridge",
        value=0.06,
        concept="kpi_bridge",
    )
    result_calculation = _calculation(
        actual=actual,
        calculation_id="calc:kpi-result",
        calculator_id="owner-research-kpi-result",
        value=0.06,
        input_calculations=(bridge,),
    )
    commitment = replace(
        graph.management_commitments[0],
        definition_reconciliation_calculation_ids=(bridge.calculation_id,),
    )
    evaluated = evaluate_outcome(
        commitment=commitment,
        facts=(*graph.facts, actual),
        calculations=(*graph.calculations, bridge, result_calculation),
        source_documents=graph.documents,
        claims=_claims_for(graph, actual),
        request=_request(
            evidence=(OutcomeEvidence("primary", (), result_calculation.calculation_id),),
        ),
    )
    assert evaluated.outcome.status == "met"


def test_withdrawn_and_superseded_are_lifecycle_outcomes(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    for status in ("withdrawn", "superseded"):
        commitment = replace(
            graph.management_commitments[0],
            status=status,
            withdrawal_statement_id=(
                graph.management_statements[0].statement_id if status == "withdrawn" else None
            ),
            superseded_by_commitment_id=(
                "commitment:successor" if status == "superseded" else None
            ),
        )
        result = evaluate_outcome(
            commitment=commitment,
            facts=graph.facts,
            calculations=graph.calculations,
            source_documents=graph.documents,
            claims=_claims_for(graph),
            request=_request(),
        )
        assert result.outcome.status == status
        assert result.outcome.result_bindings == ()


@pytest.mark.parametrize(
    ("policy_id", "roles", "direction", "target_values", "actual", "baseline", "kind"),
    [
        ("numeric_minimum", ("lower_bound",), "higher_is_better", (10.0,), 11.0, None, "numeric"),
        ("numeric_maximum", ("upper_bound",), "lower_is_better", (10.0,), 9.0, None, "numeric"),
        (
            "numeric_range",
            ("lower_bound", "upper_bound"),
            "exact",
            (5.0, 7.0),
            6.0,
            None,
            "numeric",
        ),
        ("numeric_point", ("point",), "exact", (6.0,), 6.0, None, "numeric"),
        ("growth_minimum", ("lower_bound",), "higher_is_better", (0.05,), 106.0, 100.0, "growth"),
        (
            "growth_range",
            ("lower_bound", "upper_bound"),
            "exact",
            (0.05, 0.07),
            106.0,
            100.0,
            "growth",
        ),
        (
            "cumulative_minimum",
            ("lower_bound",),
            "higher_is_better",
            (100.0,),
            110.0,
            None,
            "cumulative",
        ),
        ("milestone_by_date", ("milestone",), "not_applicable", (True,), True, None, "boolean"),
        ("maintain_or_improve", (), "higher_is_better", (), 0.91, 0.90, "maintain"),
        ("policy_compliance", ("milestone",), "not_applicable", (True,), True, None, "boolean"),
    ],
)
def test_all_registered_policies_evaluate_deterministically(
    sample_payloads: dict[str, dict],
    policy_id: str,
    roles: tuple[str, ...],
    direction: str,
    target_values: tuple[float | bool, ...],
    actual: float | bool,
    baseline: float | None,
    kind: str,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    template = graph.facts[1]
    concept = "retention" if kind == "maintain" else "test_metric"
    target_facts = tuple(
        replace(
            template,
            fact_id=f"fact:target:{index}",
            concept=concept,
            value_type="boolean" if kind == "boolean" else "number",
            value=value,
            unit=None if kind == "boolean" else "ratio",
            currency=None,
        )
        for index, value in enumerate(target_values)
    )
    baseline_fact = None
    if baseline is not None:
        baseline_fact = replace(
            template,
            fact_id="fact:baseline",
            concept="revenue" if kind == "growth" else concept,
            value=baseline,
            unit="ratio",
            currency=None,
            period={"start": "2025-01-01", "end": "2025-12-31"},
        )
    actual_facts = (
        replace(
            template,
            fact_id="fact:actual:one",
            concept=(baseline_fact.concept if kind == "growth" else concept),
            value_type="boolean" if kind == "boolean" else "number",
            value=(actual / 2 if kind == "cumulative" else actual),
            unit=None if kind == "boolean" else "ratio",
            currency=None,
        ),
    )
    if kind == "cumulative":
        actual_facts = (
            replace(
                actual_facts[0],
                period={"start": "2026-01-01", "end": "2026-06-30"},
            ),
        )
        actual_facts += (
            replace(
                actual_facts[0],
                fact_id="fact:actual:two",
                value=actual / 2,
                period={"start": "2026-07-01", "end": "2026-12-31"},
            ),
        )
    commitment = replace(
        graph.management_commitments[0],
        metric_concept=concept,
        evaluation_policy_id=policy_id,
        comparison_direction=direction,
        target_bindings=tuple(
            {
                "component_id": "primary",
                "role": role,
                "fact_id": fact.fact_id,
            }
            for role, fact in zip(roles, target_facts, strict=True)
        ),
        baseline_bindings=(
            ({"component_id": "primary", "fact_id": baseline_fact.fact_id},)
            if baseline_fact is not None
            else ()
        ),
    )
    result = evaluate_outcome(
        commitment=commitment,
        facts=(*graph.facts, *target_facts, *(filter(None, (baseline_fact,))), *actual_facts),
        calculations=graph.calculations,
        source_documents=graph.documents,
        claims=_claims_for(
            graph,
            *(filter(None, (baseline_fact,))),
            *actual_facts,
        ),
        request=_request(
            evidence=(
                OutcomeEvidence("primary", tuple(item.fact_id for item in actual_facts), None),
            ),
        ),
    )
    assert result.outcome.status == "met"
    if kind in {"growth", "cumulative"}:
        assert result.generated_calculations
    if kind == "maintain":
        case_facts = (
            *graph.facts,
            *target_facts,
            *(filter(None, (baseline_fact,))),
            *actual_facts,
        )
        replace_graph(
            graph,
            facts=case_facts,
            claims=_claims_for(
                graph,
                *(filter(None, (baseline_fact,))),
                *actual_facts,
            ),
            management_commitments=(commitment,),
            management_outcomes=(result.outcome,),
            management_reviews=(),
        ).validate()


def test_multicomponent_target_can_be_partially_met(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    template = graph.facts[1]
    targets = (
        replace(template, fact_id="fact:target:a", concept="metric", value=10.0),
        replace(template, fact_id="fact:target:b", concept="metric", value=10.0),
    )
    actuals = (
        replace(template, fact_id="fact:actual:a", concept="metric", value=11.0),
        replace(template, fact_id="fact:actual:b", concept="metric", value=9.0),
    )
    commitment = replace(
        graph.management_commitments[0],
        metric_concept="metric",
        evaluation_policy_id="numeric_minimum",
        comparison_direction="higher_is_better",
        baseline_bindings=(),
        target_bindings=(
            {"component_id": "a", "role": "lower_bound", "fact_id": targets[0].fact_id},
            {"component_id": "b", "role": "lower_bound", "fact_id": targets[1].fact_id},
        ),
    )
    result = evaluate_outcome(
        commitment=commitment,
        facts=(*graph.facts, *targets, *actuals),
        calculations=graph.calculations,
        source_documents=graph.documents,
        claims=_claims_for(graph, *actuals),
        request=_request(
            evidence=(
                OutcomeEvidence("a", (actuals[0].fact_id,), None),
                OutcomeEvidence("b", (actuals[1].fact_id,), None),
            ),
        ),
    )
    assert result.outcome.status == "partially_met"
