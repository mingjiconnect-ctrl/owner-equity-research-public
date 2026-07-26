from __future__ import annotations

import copy

import pytest
from quarterly_support import load_case, load_contracts

from owner_research.calculation_integrity import build_calculation_result
from owner_research.contracts import (
    Claim,
    Fact,
    FiscalPeriod,
    QuarterlyReconciliation,
    QuarterlyUpdate,
)
from owner_research.quarterly import (
    ComparabilityAssessment,
    QuarterlyComputationError,
    assess_comparability,
    build_quarterly_update,
    calculate_change,
    calculate_ratio,
    derive_discrete_quarter,
    per_week_growth_diagnostic,
    reconcile_growth_bridge,
    reconcile_metric,
)
from owner_research.validation import ContractGraph, ContractGraphError


def _boolean_fact(template: Fact, *, fact_id: str, concept: str, value: bool) -> Fact:
    payload = template.to_dict()
    payload.update(fact_id=fact_id, concept=concept, value_type="boolean", value=value)
    payload.update(unit=None, currency=None)
    return Fact(**payload)


def test_fiscal_period_metadata_changes_calculation_identity_and_fingerprint() -> None:
    case = load_case("non-calendar-53-week.json")
    _, periods, facts = load_contracts(case)
    current = periods["period:weekco:2026-q2"]
    quarter = derive_discrete_quarter(
        facts["fact:weekco:revenue:2026-q2-ytd"],
        facts["fact:weekco:revenue:2026-q1-ytd"],
        current,
        periods["period:weekco:2026-q1"],
        generated_at=case["generated_at"],
    )
    normal = per_week_growth_diagnostic(
        quarter,
        facts["fact:weekco:revenue:2025-q2-quarter"],
        current,
        periods["period:weekco:2025-q2"],
        generated_at=case["generated_at"],
    )
    changed_payload = current.to_dict()
    changed_payload.update(
        quarter_end="2026-03-01",
        cumulative_end="2026-03-01",
        weeks=13,
    )
    changed = FiscalPeriod(**changed_payload)
    changed_quarter_payload = quarter.to_dict()
    changed_quarter_payload["period"]["end"] = "2026-03-01"
    changed_quarter = type(quarter)(**changed_quarter_payload)
    alternate = per_week_growth_diagnostic(
        changed_quarter,
        facts["fact:weekco:revenue:2025-q2-quarter"],
        changed,
        periods["period:weekco:2025-q2"],
        generated_at=case["generated_at"],
    )
    assert set(normal.input_period_ids) == {
        "period:weekco:2026-q2",
        "period:weekco:2025-q2",
    }
    assert normal.calculation_id != alternate.calculation_id
    assert normal.input_fingerprint != alternate.input_fingerprint


def test_comparability_uses_unknown_not_false_for_missing_evidence() -> None:
    case = load_case("restatement-acquisition.json")
    _, periods, _ = load_contracts(case)
    assessment = assess_comparability(
        periods["period:buyco:2026-q2"],
        periods["period:buyco:2025-q2"],
        [],
    )
    assert assessment.status == "unknown"
    assert "missing_material_acquisition_evidence" in assessment.reasons
    assert "missing_fx_evidence" in assessment.reasons
    assert "missing_one_time_tax_evidence" in assessment.reasons


def test_comparability_evidence_must_match_current_quarter() -> None:
    case = load_case("restatement-acquisition.json")
    _, periods, facts = load_contracts(case)
    payload = facts["fact:buyco:acquisition-material:q2"].to_dict()
    payload["period"] = {"start": "2026-01-01", "end": "2026-03-31"}
    with pytest.raises(QuarterlyComputationError, match="current quarter"):
        assess_comparability(
            periods["period:buyco:2026-q2"],
            periods["period:buyco:2025-q2"],
            [Fact(**payload)],
        )


def test_ratio_rejects_mismatched_units() -> None:
    case = load_case("sbc-lease-heavy.json")
    _, periods, facts = load_contracts(case)
    bad = facts["fact:cloudlease:revenue:q2-ytd"].to_dict()
    bad["unit"] = "currency_thousands"
    period = periods["period:cloudlease:2026-q2"]
    with pytest.raises(QuarterlyComputationError, match="unit mismatch"):
        calculate_ratio(
            facts["fact:cloudlease:sbc:q2-ytd"],
            Fact(**bad),
            concept="sbc_to_revenue",
            result_period={"start": period.cumulative_start, "end": period.cumulative_end},
            generated_at=case["generated_at"],
        )


def test_growth_bridge_rejects_duplicate_wrong_role_and_extra_evidence() -> None:
    case = load_case("sbc-lease-heavy.json")
    _, _, facts = load_contracts(case)
    base_payload = facts["fact:cloudlease:revenue:q2-ytd"].to_dict()
    base_payload.update(
        fact_id="fact:bridge:reported",
        concept="reported_growth",
        value=0.20,
        unit="ratio",
        currency=None,
    )
    reported = Fact(**base_payload)
    component_payload = copy.deepcopy(base_payload)
    component_payload.update(fact_id="fact:bridge:fx", concept="fx_impact", value=-0.01)
    component = Fact(**component_payload)
    duplicate = {name: component for name in ("fx", "acquisition", "price", "volume")}
    with pytest.raises(QuarterlyComputationError, match="distinct"):
        reconcile_growth_bridge(
            reported,
            duplicate,
            result_period=base_payload["period"],
            generated_at=case["generated_at"],
        )

    components: dict[str, Fact] = {}
    for role in ("fx", "acquisition", "price", "volume"):
        payload = copy.deepcopy(base_payload)
        payload.update(
            fact_id=f"fact:bridge:{role}",
            concept=f"{role}_impact",
            value=0.01,
        )
        components[role] = Fact(**payload)
    wrong_role = dict(components)
    wrong_payload = components["volume"].to_dict()
    wrong_payload["fact_id"] = "fact:bridge:wrong-price-role"
    wrong_role["price"] = Fact(**wrong_payload)
    with pytest.raises(QuarterlyComputationError, match="price bridge concept"):
        reconcile_growth_bridge(
            reported,
            wrong_role,
            result_period=base_payload["period"],
            generated_at=case["generated_at"],
        )
    with pytest.raises(QuarterlyComputationError, match="unexpected growth bridge"):
        reconcile_growth_bridge(
            reported,
            {**components, "other": component},
            result_period=base_payload["period"],
            generated_at=case["generated_at"],
        )


def test_reconciliation_basis_matches_period_and_covers_every_candidate() -> None:
    case = load_case("restatement-acquisition.json")
    documents, periods, facts = load_contracts(case)
    candidates = [
        facts["fact:buyco:revenue:q2-original"],
        facts["fact:buyco:revenue:q2-restated"],
        facts["fact:buyco:revenue:q2-release"],
    ]
    reconciliation, delta = reconcile_metric(
        candidates,
        documents,
        periods["period:buyco:2026-q2"],
        basis="single_quarter",
        tolerance=0.01,
        generated_at=case["generated_at"],
    )
    assert reconciliation.basis == "single_quarter"
    assert delta is not None
    assert set(delta.input_fact_ids) == {item.fact_id for item in candidates}
    assert delta.value == pytest.approx(10.0)
    bad_payload = candidates[0].to_dict()
    bad_payload["period"] = {"start": "2026-01-01", "end": "2026-06-30"}
    with pytest.raises(QuarterlyComputationError, match="single-quarter window"):
        reconcile_metric(
            [Fact(**bad_payload), candidates[1]],
            documents,
            periods["period:buyco:2026-q2"],
            basis="single_quarter",
            tolerance=0.01,
            generated_at=case["generated_at"],
        )


def test_q3_and_q4_cumulative_differences() -> None:
    case = load_case("q3-q4-cumulative.json")
    _, periods, facts = load_contracts(case)
    q2 = periods["period:accumco:2026-q2"]
    q2_fact = facts["fact:accumco:revenue:2026-q2-ytd"]
    previous_period = q2
    previous_fact = q2_fact
    for quarter in (3, 4):
        period = periods[f"period:accumco:2026-q{quarter}"]
        fact = facts[f"fact:accumco:revenue:2026-q{quarter}-ytd"]
        result = derive_discrete_quarter(
            fact,
            previous_fact,
            period,
            previous_period,
            generated_at=case["generated_at"],
        )
        assert result.value == pytest.approx(case["expected"][f"q{quarter}_discrete"])
        previous_period, previous_fact = period, fact

    with pytest.raises(QuarterlyComputationError, match="previous cumulative"):
        derive_discrete_quarter(
            facts["fact:accumco:revenue:2026-q3-ytd"],
            None,
            periods["period:accumco:2026-q3"],
            None,
            generated_at=case["generated_at"],
        )


def test_period_comparison_must_be_prior_year_same_quarter() -> None:
    case = load_case("non-calendar-53-week.json")
    documents, periods, _ = load_contracts(case)
    invalid = periods["period:weekco:2025-q2"].to_dict()
    invalid["comparative_period_id"] = "period:weekco:2026-q2"
    with pytest.raises(ContractGraphError, match="prior fiscal year same quarter"):
        ContractGraph(
            documents=tuple(documents.values()),
            periods=(periods["period:weekco:2026-q2"], FiscalPeriod(**invalid)),
        ).validate()


def test_graph_rejects_blocked_reconciliation_in_nonblocked_update() -> None:
    case = load_case("restatement-acquisition.json")
    documents, periods, facts = load_contracts(case)
    reconciliation, delta = reconcile_metric(
        [
            facts["fact:buyco:revenue:q2-original"],
            facts["fact:buyco:revenue:q2-restated"],
            facts["fact:buyco:revenue:q2-release"],
        ],
        documents,
        periods["period:buyco:2026-q2"],
        basis="single_quarter",
        tolerance=0.01,
        generated_at=case["generated_at"],
    )
    assert delta is not None
    release = facts["fact:buyco:revenue:q2-release"]
    second_payload = release.to_dict()
    second_payload.update(fact_id="fact:buyco:revenue:q2-release-audit", value=201.0)
    second_release = Fact(**second_payload)
    blocked_reconciliation, blocked_delta = reconcile_metric(
        [release, second_release],
        documents,
        periods["period:buyco:2026-q2"],
        basis="single_quarter",
        tolerance=0.01,
        generated_at=case["generated_at"],
    )
    assert blocked_delta is None
    claim = Claim(
        schema_version="1.0.0",
        claim_id="claim:buyco:audit-change",
        issuer_id="issuer:buyco",
        statement="The regulatory filing changed the reported amount.",
        as_of_date="2026-08-10",
        supporting_fact_ids=("fact:buyco:revenue:q2-restated",),
        counterevidence_fact_ids=("fact:buyco:revenue:q2-original",),
        counterevidence_search_note=None,
        confidence="high",
        falsification_condition="A later amendment restores the original amount.",
    )
    material_not_acquired_payload = facts[
        "fact:buyco:acquisition-material:q2"
    ].to_dict()
    material_not_acquired_payload.update(
        fact_id="fact:buyco:no-material-acquisition:q2",
        value=False,
    )
    material_not_acquired = Fact(**material_not_acquired_payload)
    update_fact_ids = tuple(
        sorted(
            (
                "fact:buyco:revenue:q2-original",
                "fact:buyco:revenue:q2-restated",
                "fact:buyco:revenue:q2-release",
                material_not_acquired.fact_id,
                "fact:buyco:fx-material:q2",
                "fact:buyco:one-time-tax:q2",
            )
        )
    )
    update = QuarterlyUpdate(
        schema_version="1.0.0",
        update_id="quarterly-update:buyco:audit-invalid",
        issuer_id="issuer:buyco",
        as_of_date="2026-08-10",
        current_period_id="period:buyco:2026-q2",
        comparison_period_id="period:buyco:2025-q2",
        status="partial",
        comparability={"status": "partially_comparable", "reasons": ["restatement"]},
        fact_ids=update_fact_ids,
        calculation_result_ids=(delta.calculation_id,),
        reconciliation_ids=(blocked_reconciliation.reconciliation_id,),
        what_changed_claim_ids=(claim.claim_id,),
        why_it_changed_claim_ids=(),
        temporary_or_structural_claim_ids=(),
        guidance_change_claim_ids=(),
        long_term_thesis_impact_claim_ids=(),
        impact_on_valuation_assumptions_claim_ids=(),
        valuation_assumption_review_required=False,
        confidence="low",
        missing_evidence=("Resolve filing conflict",),
        red_flags=("Blocked reconciliation",),
    )
    with pytest.raises(ContractGraphError, match="Blocked reconciliation"):
        ContractGraph(
            documents=tuple(documents.values()),
            facts=(*facts.values(), second_release, material_not_acquired),
            claims=(claim,),
            calculations=(delta,),
            periods=tuple(periods.values()),
            reconciliations=(blocked_reconciliation,),
            quarterly_updates=(update,),
        ).validate()


def test_graph_rejects_authority_that_ignores_latest_amendment() -> None:
    case = load_case("restatement-acquisition.json")
    documents, periods, facts = load_contracts(case)
    reconciliation, delta = reconcile_metric(
        [
            facts["fact:buyco:revenue:q2-original"],
            facts["fact:buyco:revenue:q2-restated"],
            facts["fact:buyco:revenue:q2-release"],
        ],
        documents,
        periods["period:buyco:2026-q2"],
        basis="single_quarter",
        tolerance=0.01,
        generated_at=case["generated_at"],
    )
    assert delta is not None
    forged = reconciliation.to_dict()
    forged["authoritative_fact_id"] = "fact:buyco:revenue:q2-original"
    with pytest.raises(ContractGraphError, match="authority"):
        ContractGraph(
            documents=tuple(documents.values()),
            facts=tuple(facts.values()),
            calculations=(delta,),
            periods=tuple(periods.values()),
            reconciliations=(QuarterlyReconciliation(**forged),),
        ).validate()


def test_graph_rejects_reconciliation_status_that_contradicts_delta() -> None:
    case = load_case("restatement-acquisition.json")
    documents, periods, facts = load_contracts(case)
    reconciliation, delta = reconcile_metric(
        [
            facts["fact:buyco:revenue:q2-original"],
            facts["fact:buyco:revenue:q2-restated"],
            facts["fact:buyco:revenue:q2-release"],
        ],
        documents,
        periods["period:buyco:2026-q2"],
        basis="single_quarter",
        tolerance=0.01,
        generated_at=case["generated_at"],
    )
    assert delta is not None
    forged = reconciliation.to_dict()
    forged["status"] = "exact_match"
    with pytest.raises(ContractGraphError, match="status contradicts"):
        ContractGraph(
            documents=tuple(documents.values()),
            facts=tuple(facts.values()),
            calculations=(delta,),
            periods=tuple(periods.values()),
            reconciliations=(QuarterlyReconciliation(**forged),),
        ).validate()


def test_manual_comparability_assessment_cannot_bypass_missing_evidence() -> None:
    case = load_case("restatement-acquisition.json")
    documents, periods, facts = load_contracts(case)
    reconciliation, delta = reconcile_metric(
        [
            facts["fact:buyco:revenue:q2-original"],
            facts["fact:buyco:revenue:q2-restated"],
            facts["fact:buyco:revenue:q2-release"],
        ],
        documents,
        periods["period:buyco:2026-q2"],
        basis="single_quarter",
        tolerance=0.01,
        generated_at=case["generated_at"],
    )
    assert delta is not None
    claim = Claim(
        schema_version="1.0.0",
        claim_id="claim:buyco:manual-comparability",
        issuer_id="issuer:buyco",
        statement="The amended filing changed reported revenue.",
        as_of_date="2026-08-10",
        supporting_fact_ids=("fact:buyco:revenue:q2-restated",),
        counterevidence_fact_ids=("fact:buyco:revenue:q2-original",),
        counterevidence_search_note=None,
        confidence="high",
        falsification_condition="A later filing reverses the amendment.",
    )
    numeric_facts = [
        fact for fact in facts.values() if fact.concept == "revenue"
    ]
    forged_assessment = ComparabilityAssessment(status="comparable", reasons=())
    with pytest.raises(QuarterlyComputationError, match="does not match referenced evidence"):
        build_quarterly_update(
            update_id="quarterly-update:buyco:forged-comparability",
            as_of_date="2026-08-10",
            current_period=periods["period:buyco:2026-q2"],
            comparison_period=periods["period:buyco:2025-q2"],
            status="complete",
            comparability=forged_assessment,
            facts=numeric_facts,
            calculations=[delta],
            reconciliations=[reconciliation],
            what_changed_claims=[claim],
            why_it_changed_claims=[claim],
            temporary_or_structural_claims=[claim],
            guidance_change_claims=[claim],
            long_term_thesis_impact_claims=[claim],
            confidence="high",
        )

    forged_update = QuarterlyUpdate(
        schema_version="1.0.0",
        update_id="quarterly-update:buyco:direct-forged-comparability",
        issuer_id="issuer:buyco",
        as_of_date="2026-08-10",
        current_period_id="period:buyco:2026-q2",
        comparison_period_id="period:buyco:2025-q2",
        status="complete",
        comparability={"status": "comparable", "reasons": []},
        fact_ids=tuple(sorted(fact.fact_id for fact in numeric_facts)),
        calculation_result_ids=(delta.calculation_id,),
        reconciliation_ids=(reconciliation.reconciliation_id,),
        what_changed_claim_ids=(claim.claim_id,),
        why_it_changed_claim_ids=(claim.claim_id,),
        temporary_or_structural_claim_ids=(claim.claim_id,),
        guidance_change_claim_ids=(claim.claim_id,),
        long_term_thesis_impact_claim_ids=(claim.claim_id,),
        impact_on_valuation_assumptions_claim_ids=(),
        valuation_assumption_review_required=False,
        confidence="high",
        missing_evidence=(),
        red_flags=(),
    )
    with pytest.raises(ContractGraphError, match="comparability does not match"):
        ContractGraph(
            documents=tuple(documents.values()),
            facts=tuple(facts.values()),
            claims=(claim,),
            calculations=(delta,),
            periods=tuple(periods.values()),
            reconciliations=(reconciliation,),
            quarterly_updates=(forged_update,),
        ).validate()


@pytest.mark.parametrize(
    ("field", "value"), [("unit", "currency_thousands"), ("currency", "EUR")]
)
def test_graph_rejects_reconciliation_candidate_unit_or_currency_mismatch(
    field: str, value: str
) -> None:
    case = load_case("restatement-acquisition.json")
    documents, periods, facts = load_contracts(case)
    reconciliation, delta = reconcile_metric(
        [
            facts["fact:buyco:revenue:q2-original"],
            facts["fact:buyco:revenue:q2-restated"],
            facts["fact:buyco:revenue:q2-release"],
        ],
        documents,
        periods["period:buyco:2026-q2"],
        basis="single_quarter",
        tolerance=0.01,
        generated_at=case["generated_at"],
    )
    assert delta is not None
    bad_payload = facts["fact:buyco:revenue:q2-release"].to_dict()
    bad_payload[field] = value
    bad_fact = Fact(**bad_payload)
    bad_facts = dict(facts)
    bad_facts[bad_fact.fact_id] = bad_fact
    rebuilt_delta = build_calculation_result(
        delta.to_dict(),
        facts={identifier: bad_facts[identifier] for identifier in delta.input_fact_ids},
        assumptions={},
        calculations={},
        periods={
            identifier: periods[identifier] for identifier in delta.input_period_ids
        },
    )
    with pytest.raises(ContractGraphError, match="unit or currency mismatch"):
        ContractGraph(
            documents=tuple(documents.values()),
            facts=tuple(bad_facts.values()),
            calculations=(rebuilt_delta,),
            periods=tuple(periods.values()),
            reconciliations=(reconciliation,),
        ).validate()


def test_reconciliation_builder_rejects_non_numeric_candidates_without_authority() -> None:
    case = load_case("restatement-acquisition.json")
    documents, periods, facts = load_contracts(case)
    release_payload = facts["fact:buyco:revenue:q2-release"].to_dict()
    candidates = []
    for suffix, value in (("left", "reported"), ("right", "revised")):
        payload = copy.deepcopy(release_payload)
        payload.update(
            fact_id=f"fact:buyco:text-revenue:{suffix}",
            value_type="text",
            value=value,
            unit=None,
            currency=None,
        )
        candidates.append(Fact(**payload))
    with pytest.raises(QuarterlyComputationError, match="must be a numeric evidence item"):
        reconcile_metric(
            candidates,
            documents,
            periods["period:buyco:2026-q2"],
            basis="single_quarter",
            tolerance=0.01,
            generated_at=case["generated_at"],
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"value_type": "text", "value": "ten"}, "delta is not numeric"),
        ({"unit": "currency_thousands"}, "delta unit or currency mismatch"),
        ({"currency": "EUR"}, "delta unit or currency mismatch"),
    ],
)
def test_graph_rejects_invalid_reconciliation_delta_metadata(
    changes: dict[str, object], message: str
) -> None:
    case = load_case("restatement-acquisition.json")
    documents, periods, facts = load_contracts(case)
    reconciliation, delta = reconcile_metric(
        [
            facts["fact:buyco:revenue:q2-original"],
            facts["fact:buyco:revenue:q2-restated"],
            facts["fact:buyco:revenue:q2-release"],
        ],
        documents,
        periods["period:buyco:2026-q2"],
        basis="single_quarter",
        tolerance=0.01,
        generated_at=case["generated_at"],
    )
    assert delta is not None
    payload = delta.to_dict()
    payload.update(changes)
    rebuilt = build_calculation_result(
        payload,
        facts={identifier: facts[identifier] for identifier in delta.input_fact_ids},
        assumptions={},
        calculations={},
        periods={identifier: periods[identifier] for identifier in delta.input_period_ids},
    )
    with pytest.raises(ContractGraphError, match=message):
        ContractGraph(
            documents=tuple(documents.values()),
            facts=tuple(facts.values()),
            calculations=(rebuilt,),
            periods=tuple(periods.values()),
            reconciliations=(reconciliation,),
        ).validate()


def test_calculate_change_rejects_unrelated_result_period() -> None:
    case = load_case("sbc-lease-heavy.json")
    _, periods, facts = load_contracts(case)
    with pytest.raises(QuarterlyComputationError, match="fiscal quarter or cumulative"):
        calculate_change(
            facts["fact:cloudlease:diluted-shares:current"],
            facts["fact:cloudlease:diluted-shares:prior"],
            concept="diluted_share_change",
            as_ratio=True,
            result_period={"start": "1999-01-01", "end": "1999-03-31"},
            fiscal_period=periods["period:cloudlease:2026-q2"],
            generated_at=case["generated_at"],
        )
