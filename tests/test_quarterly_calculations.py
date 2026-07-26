from __future__ import annotations

import copy

import pytest
from quarterly_support import load_case, load_contracts

from owner_research.contracts import Claim, Fact
from owner_research.quarterly import (
    QuarterlyComputationError,
    assess_comparability,
    build_quarterly_update,
    calculate_change,
    calculate_ratio,
    derive_discrete_quarter,
    derive_free_cash_flow,
    derive_ttm,
    per_week_growth_diagnostic,
    reconcile_growth_bridge,
    reconcile_metric,
)
from owner_research.validation import ContractGraph, ContractGraphError


def test_discrete_quarter_ttm_and_week_diagnostic() -> None:
    case = load_case("non-calendar-53-week.json")
    _, periods, facts = load_contracts(case)
    quarter = derive_discrete_quarter(
        facts["fact:weekco:revenue:2026-q2-ytd"],
        facts["fact:weekco:revenue:2026-q1-ytd"],
        periods["period:weekco:2026-q2"],
        periods["period:weekco:2026-q1"],
        generated_at=case["generated_at"],
    )
    ttm = derive_ttm(
        facts["fact:weekco:revenue:2026-q2-ytd"],
        facts["fact:weekco:revenue:2025-fy"],
        facts["fact:weekco:revenue:2025-q2-ytd"],
        periods["period:weekco:2026-q2"],
        generated_at=case["generated_at"],
    )
    growth = per_week_growth_diagnostic(
        quarter,
        facts["fact:weekco:revenue:2025-q2-quarter"],
        periods["period:weekco:2026-q2"],
        periods["period:weekco:2025-q2"],
        generated_at=case["generated_at"],
    )
    assert quarter.value == pytest.approx(case["expected"]["discrete_quarter"])
    assert ttm.value == pytest.approx(case["expected"]["ttm"])
    assert growth.value == pytest.approx(case["expected"]["per_week_growth"])


def test_q1_ytd_is_already_the_discrete_quarter() -> None:
    case = load_case("non-calendar-53-week.json")
    _, periods, facts = load_contracts(case)
    quarter = derive_discrete_quarter(
        facts["fact:weekco:revenue:2026-q1-ytd"],
        None,
        periods["period:weekco:2026-q1"],
        None,
        generated_at=case["generated_at"],
    )
    assert quarter.value == pytest.approx(100.0)


def test_q2_requires_previous_ytd_and_matching_currency() -> None:
    case = load_case("non-calendar-53-week.json")
    _, periods, facts = load_contracts(case)
    with pytest.raises(QuarterlyComputationError, match="previous cumulative"):
        derive_discrete_quarter(
            facts["fact:weekco:revenue:2026-q2-ytd"],
            None,
            periods["period:weekco:2026-q2"],
            None,
            generated_at=case["generated_at"],
        )
    bad = copy.deepcopy(case["facts"][1])
    bad["currency"] = "EUR"
    with pytest.raises(QuarterlyComputationError, match="currency"):
        derive_discrete_quarter(
            facts["fact:weekco:revenue:2026-q2-ytd"],
            Fact(**bad),
            periods["period:weekco:2026-q2"],
            periods["period:weekco:2026-q1"],
            generated_at=case["generated_at"],
        )


def test_ttm_requires_prior_fy_and_prior_comparable_ytd() -> None:
    case = load_case("non-calendar-53-week.json")
    _, periods, facts = load_contracts(case)
    with pytest.raises(QuarterlyComputationError, match="prior fiscal year"):
        derive_ttm(
            facts["fact:weekco:revenue:2026-q2-ytd"],
            None,
            facts["fact:weekco:revenue:2025-q2-ytd"],
            periods["period:weekco:2026-q2"],
            generated_at=case["generated_at"],
        )


def test_ttm_rejects_missing_prior_period_dates_with_domain_error() -> None:
    case = load_case("non-calendar-53-week.json")
    _, periods, facts = load_contracts(case)
    bad_payload = facts["fact:weekco:revenue:2025-fy"].to_dict()
    bad_payload["period"] = {"start": bad_payload["period"]["start"], "end": None}
    with pytest.raises(QuarterlyComputationError, match="prior fiscal year end date is required"):
        derive_ttm(
            facts["fact:weekco:revenue:2026-q2-ytd"],
            Fact(**bad_payload),
            facts["fact:weekco:revenue:2025-q2-ytd"],
            periods["period:weekco:2026-q2"],
            generated_at=case["generated_at"],
        )


@pytest.mark.parametrize(
    ("prior_start", "prior_ytd_start"),
    [
        ("2025-03-02", "2025-03-02"),
        ("2024-08-01", "2024-08-01"),
    ],
)
def test_ttm_requires_a_complete_prior_fiscal_year(
    prior_start: str, prior_ytd_start: str
) -> None:
    case = load_case("non-calendar-53-week.json")
    _, periods, facts = load_contracts(case)
    prior_fy_payload = facts["fact:weekco:revenue:2025-fy"].to_dict()
    prior_fy_payload["period"]["start"] = prior_start
    prior_ytd_payload = facts["fact:weekco:revenue:2025-q2-ytd"].to_dict()
    prior_ytd_payload["period"]["start"] = prior_ytd_start
    with pytest.raises(QuarterlyComputationError, match="complete fiscal year"):
        derive_ttm(
            facts["fact:weekco:revenue:2026-q2-ytd"],
            Fact(**prior_fy_payload),
            Fact(**prior_ytd_payload),
            periods["period:weekco:2026-q2"],
            generated_at=case["generated_at"],
        )


def test_restatement_reconciliation_and_acquisition_comparability() -> None:
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
    assessment = assess_comparability(
        periods["period:buyco:2026-q2"],
        periods["period:buyco:2025-q2"],
        [
            facts["fact:buyco:acquisition-material:q2"],
            facts["fact:buyco:acquisition-bridge:q2"],
            facts["fact:buyco:fx-material:q2"],
            facts["fact:buyco:one-time-tax:q2"],
        ],
    )
    assert reconciliation.authoritative_fact_id == case["expected"]["authoritative_fact_id"]
    assert reconciliation.status == case["expected"]["reconciliation_status"]
    assert delta.value == pytest.approx(case["expected"]["max_absolute_delta"])
    assert assessment.status == case["expected"]["comparability_status"]
    assert list(assessment.reasons) == case["expected"]["comparability_reasons"]


def test_reconciliation_without_regulatory_authority_is_blocked() -> None:
    case = load_case("restatement-acquisition.json")
    documents, periods, facts = load_contracts(case)
    release = facts["fact:buyco:revenue:q2-release"]
    second_payload = release.to_dict()
    second_payload["fact_id"] = "fact:buyco:revenue:q2-release-2"
    second_payload["value"] = 201.0
    reconciliation, delta = reconcile_metric(
        [release, Fact(**second_payload)],
        documents,
        periods["period:buyco:2026-q2"],
        basis="single_quarter",
        tolerance=0.01,
        generated_at=case["generated_at"],
    )
    assert reconciliation.blocked is True
    assert reconciliation.selection_rule == "no_regulatory_authority"
    assert reconciliation.authoritative_fact_id is None
    assert delta is None


def test_sbc_lease_working_capital_and_fcf() -> None:
    case = load_case("sbc-lease-heavy.json")
    _, periods, facts = load_contracts(case)
    period = periods["period:cloudlease:2026-q2"]
    sbc = calculate_ratio(
        facts["fact:cloudlease:sbc:q2-ytd"],
        facts["fact:cloudlease:revenue:q2-ytd"],
        concept="sbc_to_revenue",
        result_period={"start": period.cumulative_start, "end": period.cumulative_end},
        generated_at=case["generated_at"],
    )
    dilution = calculate_change(
        facts["fact:cloudlease:diluted-shares:current"],
        facts["fact:cloudlease:diluted-shares:prior"],
        concept="diluted_share_change",
        as_ratio=True,
        result_period={"start": period.quarter_start, "end": period.quarter_end},
        fiscal_period=period,
        generated_at=case["generated_at"],
    )
    lease = calculate_change(
        facts["fact:cloudlease:lease-liability:current"],
        facts["fact:cloudlease:lease-liability:prior"],
        concept="lease_liability_change",
        as_ratio=False,
        result_period={"start": period.quarter_start, "end": period.quarter_end},
        fiscal_period=period,
        generated_at=case["generated_at"],
    )
    working_capital = calculate_change(
        facts["fact:cloudlease:working-capital:current"],
        facts["fact:cloudlease:working-capital:prior"],
        concept="working_capital_change",
        as_ratio=False,
        result_period={"start": period.quarter_start, "end": period.quarter_end},
        fiscal_period=period,
        generated_at=case["generated_at"],
    )
    current_fcf = derive_free_cash_flow(
        facts["fact:cloudlease:ocf:q2-ytd"],
        facts["fact:cloudlease:capex:q2-ytd"],
        generated_at=case["generated_at"],
    )
    prior_fcf = derive_free_cash_flow(
        facts["fact:cloudlease:ocf:q1-ytd"],
        facts["fact:cloudlease:capex:q1-ytd"],
        generated_at=case["generated_at"],
    )
    quarter_fcf = derive_discrete_quarter(
        current_fcf,
        prior_fcf,
        periods["period:cloudlease:2026-q2"],
        periods["period:cloudlease:2026-q1"],
        generated_at=case["generated_at"],
    )
    expected = case["expected"]
    assert sbc.value == pytest.approx(expected["sbc_ratio"])
    assert dilution.value == pytest.approx(expected["diluted_share_change"])
    assert lease.value == pytest.approx(expected["lease_liability_change"])
    assert working_capital.value == pytest.approx(expected["working_capital_change"])
    assert current_fcf.value == pytest.approx(expected["current_ytd_fcf"])
    assert prior_fcf.value == pytest.approx(expected["prior_ytd_fcf"])
    assert quarter_fcf.value == pytest.approx(expected["discrete_quarter_fcf"])
    for result in (dilution, lease, working_capital):
        assert result.input_period_ids == (period.period_id,)


def test_capex_must_use_positive_outflow_convention() -> None:
    case = load_case("sbc-lease-heavy.json")
    _, _, facts = load_contracts(case)
    bad = copy.deepcopy(case["facts"][7])
    bad["value"] = -80.0
    with pytest.raises(QuarterlyComputationError, match="positive outflow"):
        derive_free_cash_flow(
            facts["fact:cloudlease:ocf:q2-ytd"],
            Fact(**bad),
            generated_at=case["generated_at"],
        )


def test_growth_bridge_requires_fx_acquisition_price_and_volume() -> None:
    case = load_case("sbc-lease-heavy.json")
    _, _, facts = load_contracts(case)
    reported = copy.deepcopy(case["facts"][0])
    reported["fact_id"] = "fact:bridge:reported-growth"
    reported["concept"] = "reported_growth"
    reported["value"] = 0.20
    reported["unit"] = "ratio"
    reported["currency"] = None
    with pytest.raises(QuarterlyComputationError, match="missing growth bridge"):
        reconcile_growth_bridge(
            Fact(**reported),
            {"fx": facts["fact:cloudlease:sbc:q2-ytd"]},
            result_period=reported["period"],
            generated_at=case["generated_at"],
        )


def test_complete_growth_bridge_reconciles_residual() -> None:
    case = load_case("sbc-lease-heavy.json")
    reported_payload = copy.deepcopy(case["facts"][0])
    reported_payload.update(
        fact_id="fact:bridge:reported",
        concept="reported_growth",
        value=0.20,
        unit="ratio",
        currency=None,
    )
    reported = Fact(**reported_payload)
    values = {"fx": -0.01, "acquisition": 0.05, "price": 0.08, "volume": 0.06}
    components = {}
    for name, value in values.items():
        payload = copy.deepcopy(reported_payload)
        payload.update(fact_id=f"fact:bridge:{name}", concept=f"{name}_impact", value=value)
        components[name] = Fact(**payload)
    residual = reconcile_growth_bridge(
        reported,
        components,
        result_period=reported_payload["period"],
        generated_at=case["generated_at"],
    )
    assert residual.value == pytest.approx(0.02)


def test_reference_only_quarterly_update_and_graph_round_trip() -> None:
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
    assessment = assess_comparability(
        periods["period:buyco:2026-q2"],
        periods["period:buyco:2025-q2"],
        [
            facts["fact:buyco:acquisition-material:q2"],
            facts["fact:buyco:acquisition-bridge:q2"],
            facts["fact:buyco:fx-material:q2"],
            facts["fact:buyco:one-time-tax:q2"],
        ],
    )
    claim = Claim(
        schema_version="1.0.0",
        claim_id="claim:buyco:q2-revenue-restated",
        issuer_id="issuer:buyco",
        statement="The amended filing reduced reported quarterly revenue.",
        as_of_date="2026-08-10",
        supporting_fact_ids=("fact:buyco:revenue:q2-restated",),
        counterevidence_fact_ids=("fact:buyco:revenue:q2-original",),
        counterevidence_search_note=None,
        confidence="high",
        falsification_condition="A later regulatory amendment restores the original amount.",
    )
    update = build_quarterly_update(
        update_id="quarterly-update:buyco:2026-q2",
        as_of_date="2026-08-10",
        current_period=periods["period:buyco:2026-q2"],
        comparison_period=periods["period:buyco:2025-q2"],
        status="blocked",
        comparability=assessment,
        facts=list(facts.values()),
        calculations=[delta],
        reconciliations=[reconciliation],
        what_changed_claims=[claim],
        confidence="high",
        missing_evidence=["Comparable organic acquisition bridge"],
        red_flags=["Restatement"],
    )
    graph = ContractGraph(
        documents=tuple(documents.values()),
        facts=tuple(facts.values()),
        claims=(claim,),
        calculations=(delta,),
        periods=tuple(periods.values()),
        reconciliations=(reconciliation,),
        quarterly_updates=(update,),
    )
    graph.validate()

    release = facts["fact:buyco:revenue:q2-release"]
    second_release_payload = release.to_dict()
    second_release_payload.update(
        fact_id="fact:buyco:revenue:q2-release-conflict", value=201.0
    )
    second_release = Fact(**second_release_payload)
    blocked_reconciliation, blocked_delta = reconcile_metric(
        [release, second_release],
        documents,
        periods["period:buyco:2026-q2"],
        basis="single_quarter",
        tolerance=0.01,
        generated_at=case["generated_at"],
    )
    assert blocked_delta is None
    invalid_complete_payload = update.to_dict()
    invalid_complete_payload.update(
        status="complete",
        comparability={"status": "comparable", "reasons": []},
        reconciliation_ids=[blocked_reconciliation.reconciliation_id],
        why_it_changed_claim_ids=[claim.claim_id],
        temporary_or_structural_claim_ids=[claim.claim_id],
        guidance_change_claim_ids=[claim.claim_id],
        long_term_thesis_impact_claim_ids=[claim.claim_id],
        missing_evidence=[],
    )
    invalid_complete = type(update)(**invalid_complete_payload)
    with pytest.raises(
        ContractGraphError, match="comparability does not match|Blocked reconciliation"
    ):
        ContractGraph(
            documents=tuple(documents.values()),
            facts=(*facts.values(), second_release),
            claims=(claim,),
            calculations=(delta,),
            periods=tuple(periods.values()),
            reconciliations=(blocked_reconciliation,),
            quarterly_updates=(invalid_complete,),
        ).validate()

    wrong_binding_payload = delta.to_dict()
    wrong_binding_payload["input_bindings"]["authoritative"] = (
        "fact:buyco:revenue:q2-original"
    )
    wrong_binding = type(delta)(**wrong_binding_payload)
    with pytest.raises(ContractGraphError, match="authority binding"):
        ContractGraph(
            documents=tuple(documents.values()),
            facts=tuple(facts.values()),
            calculations=(wrong_binding,),
            periods=tuple(periods.values()),
            reconciliations=(reconciliation,),
        ).validate()

    invalid = update.to_dict()
    invalid["fact_ids"] = ["fact:missing"]
    with pytest.raises(ContractGraphError, match="dangling"):
        ContractGraph(
            documents=tuple(documents.values()),
            facts=tuple(facts.values()),
            claims=(claim,),
            calculations=(delta,),
            periods=tuple(periods.values()),
            reconciliations=(reconciliation,),
            quarterly_updates=(type(update)(**invalid),),
        ).validate()
