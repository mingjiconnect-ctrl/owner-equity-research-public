from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest
from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.capital_allocation_policies import economic_event_key, policy_for
from owner_research.contracts import contract_from_dict
from owner_research.fingerprints import canonical_sha256
from owner_research.validation import ContractGraphError

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "phase4a" / "adversarial-cases.json"


EXPECTED_CASES = {
    "pricing-volume-collapse",
    "subsidized-user-growth",
    "sticky-claim-worsening-churn",
    "revenue-up-unit-cost-worse",
    "kpi-definition-change",
    "unexpired-commitment",
    "buyback-offset-by-sbc",
    "debt-buyback-eps",
    "acquisition-revenue-organic",
    "synergy-then-impairment",
    "duplicate-capital-event",
    "missing-outcome-evidence",
}
EXPECTED_FIXTURE_SEMANTICS = {
    "pricing-volume-collapse": (
        "brand_pricing_power_supported",
        "contested",
        "unresolved counterevidence",
    ),
    "subsidized-user-growth": (
        "network_effect_supported",
        "contested",
        "unresolved counterevidence",
    ),
    "sticky-claim-worsening-churn": (
        "switching_cost_supported",
        "contested",
        "unresolved counterevidence",
    ),
    "revenue-up-unit-cost-worse": (
        "scale_cost_advantage_supported",
        "contested",
        "unresolved counterevidence",
    ),
    "kpi-definition-change": (
        "direct_cross_definition_comparison",
        "blocked_without_deterministic_bridge",
        "crosses a KPI definition change",
    ),
    "unexpired-commitment": ("missed", "pending", "unexpired"),
    "buyback-offset-by-sbc": (
        "buyback_effective_from_gross_spend",
        "partial_or_observed_with_all_roles",
        "net shares",
    ),
    "debt-buyback-eps": (
        "capital_allocation_effective_from_eps_only",
        "partial",
        "EPS accretion alone",
    ),
    "acquisition-revenue-organic": (
        "organic_growth",
        "inorganic_or_mixed",
        "cannot be classified as organic",
    ),
    "synergy-then-impairment": (
        "acquisition_effective_without_impairment_review",
        "partial_or_observed_with_both_roles",
        "impairment or synergy",
    ),
    "duplicate-capital-event": (
        "two_events",
        "one_event_multiple_sources",
        "duplicate CapitalAllocationEvent",
    ),
    "missing-outcome-evidence": (
        "negative_conclusion",
        "unverifiable_or_blocked",
        "requires result evidence",
    ),
}


def _fact(sample_payloads: dict[str, dict], fact_id: str, concept: str, value: float = 1.0):
    payload = copy.deepcopy(sample_payloads["fact"])
    payload.update(
        {
            "fact_id": fact_id,
            "concept": concept,
            "value": value,
            "period": {"start": "2026-02-15", "end": "2026-06-30"},
        }
    )
    return contract_from_dict("fact", payload)


def _claim(sample_payloads: dict[str, dict], claim_id: str, fact_id: str):
    payload = copy.deepcopy(sample_payloads["claim"])
    payload.update(
        {
            "claim_id": claim_id,
            "supporting_fact_ids": [fact_id],
            "counterevidence_search_note": "Reviewed official filings for contradictory evidence.",
            "falsification_condition": "A later official filing contradicts the result.",
        }
    )
    return contract_from_dict("claim", payload)


def _reviewed_claim(sample_payloads: dict[str, dict], claim_id: str, fact_id: str):
    claim = _claim(sample_payloads, claim_id, fact_id)
    candidate_payload = copy.deepcopy(sample_payloads["analytical-claim-candidate"])
    candidate_payload.update(
        {
            "candidate_id": f"analytical-candidate:{claim_id}",
            "proposed_statement": claim.statement,
            "business_attribute_role": None,
            "business_component_type": None,
            "supporting_evidence_bindings": [
                {
                    "binding_id": f"analytical-binding:{claim_id}",
                    "fact_id": fact_id,
                    "calculation_result_id": None,
                    "context_observation_id": None,
                }
            ],
            "counterevidence_search_note": claim.counterevidence_search_note,
            "falsification_condition": claim.falsification_condition,
        }
    )
    candidate_payload["evidence_graph_sha256"] = canonical_sha256(
        {
            "supporting_evidence_bindings": candidate_payload[
                "supporting_evidence_bindings"
            ],
            "counterevidence_bindings": candidate_payload["counterevidence_bindings"],
        }
    )
    candidate = contract_from_dict("analytical-claim-candidate", candidate_payload)
    decision_payload = copy.deepcopy(sample_payloads["analytical-claim-review-decision"])
    decision_payload.update(
        {
            "decision_id": f"analytical-decision:{claim_id}",
            "candidate_id": candidate.candidate_id,
            "candidate_fingerprint": candidate.fingerprint,
            "evidence_graph_sha256": candidate.evidence_graph_sha256,
            "output_claim_id": claim.claim_id,
        }
    )
    decision = contract_from_dict("analytical-claim-review-decision", decision_payload)
    return claim, candidate, decision


def _claim_binding(decision, binding_id: str, role_id: str) -> dict[str, str]:
    return {
        "binding_id": binding_id,
        "claim_id": decision.output_claim_id,
        "review_decision_id": decision.decision_id,
        "role_id": role_id,
    }


def test_all_twelve_adversarial_fixtures_are_present_and_explicit() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    cases = payload["cases"]

    assert payload["schema_version"] == "1.0.0"
    assert {item["case_id"] for item in cases} == EXPECTED_CASES
    assert len(cases) == len(EXPECTED_CASES)
    assert all(item["evidence"] for item in cases)
    assert all(item["forbidden_inference"] for item in cases)
    assert all(item["required_state"] for item in cases)
    assert all(item["expected_error_pattern"] for item in cases)


def test_observed_buyback_requires_execution_sbc_issuance_and_net_shares(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    executed = _fact(sample_payloads, "fact:acme:buyback-executed", "buyback_executed")
    sbc = replace(
        _fact(sample_payloads, "fact:acme:sbc", "stock_based_compensation"),
        unit="shares",
        currency=None,
    )
    issuance = replace(
        _fact(sample_payloads, "fact:acme:issuance", "equity_issuance"),
        unit="shares",
        currency=None,
    )
    outcome_claim, candidate, decision = _reviewed_claim(
        sample_payloads, "claim:acme:buyback-outcome", executed.fact_id
    )
    claim_binding = _claim_binding(decision, "claim-binding:buyback", "absence_search")
    role_facts = {
        "cash_spent": executed,
        "shares_repurched": sbc,
        "sbc_shares_issued": issuance,
    }
    result_bindings = tuple(
        {
            "binding_id": f"result-binding:{role}",
            "role_id": role,
            "fact_id": fact.fact_id,
            "calculation_result_id": None,
        }
        for role, fact in role_facts.items()
    )
    incomplete = replace(
        graph.capital_allocation_outcomes[0],
        status="observed",
        result_bindings=result_bindings,
        result_role_coverage=tuple(
            {
                **dict(item),
                "status": (
                    "observed" if item["role_id"] in role_facts else "not_disclosed"
                ),
                "binding_ids": [
                    binding["binding_id"]
                    for binding in result_bindings
                    if binding["role_id"] == item["role_id"]
                ],
                "claim_binding_ids": [claim_binding["binding_id"]],
            }
            for item in graph.capital_allocation_outcomes[0].result_role_coverage
        ),
        claim_bindings=(claim_binding,),
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="incomplete role coverage"):
        replace_graph(
            graph,
            facts=(*graph.facts, executed, sbc, issuance),
            claims=(*graph.claims, outcome_claim),
            analytical_claim_candidates=(*graph.analytical_claim_candidates, candidate),
            analytical_claim_review_decisions=(
                *graph.analytical_claim_review_decisions,
                decision,
            ),
            capital_allocation_outcomes=(incomplete,),
            capital_allocation_reviews=(),
        ).validate()


def test_observed_acquisition_requires_synergy_and_impairment_evidence(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    identity_components = (
        {"role": "target_entity", "value": "TargetCo"},
        {"role": "transaction_id", "value": "agreement-2026"},
    )
    key = economic_event_key(
        issuer_id="issuer:acme",
        event_type="acquisition",
        event_subtype="business_combination",
        identity_components=identity_components,
    )
    capital_candidate = replace(
        graph.capital_allocation_event_candidates[0],
        proposed_event_type="acquisition",
        proposed_event_subtype="business_combination",
        proposed_identity_components=identity_components,
        proposed_growth_classification="inorganic",
    )
    capital_decision = replace(
        graph.capital_allocation_event_review_decisions[0],
        candidate_fingerprint=capital_candidate.fingerprint,
        output_economic_event_key=key,
    )
    event = replace(
        graph.capital_allocation_events[0],
        event_policy_id="capital-allocation-event/acquisition",
        economic_event_key=key,
        event_type="acquisition",
        event_subtype="business_combination",
        identity_components=identity_components,
        growth_classification="inorganic",
    )
    result = _fact(sample_payloads, "fact:acme:acquisition-result", "acquisition_result")
    claim, candidate, decision = _reviewed_claim(
        sample_payloads, "claim:acme:acquisition-outcome", result.fact_id
    )
    claim_binding = _claim_binding(decision, "claim-binding:acquisition", "absence_search")
    result_binding = {
        "binding_id": "result-binding:acquired-revenue",
        "role_id": "acquired_revenue",
        "fact_id": result.fact_id,
        "calculation_result_id": None,
    }
    acquisition_roles = policy_for("acquisition").outcome_roles
    outcome = replace(
        graph.capital_allocation_outcomes[0],
        outcome_policy_id="capital-allocation-outcome/acquisition",
        status="observed",
        result_bindings=(result_binding,),
        result_role_coverage=tuple(
            {
                "role_id": role,
                "status": "observed" if role == "acquired_revenue" else "not_disclosed",
                "binding_ids": (
                    [result_binding["binding_id"]] if role == "acquired_revenue" else []
                ),
                "claim_binding_ids": [claim_binding["binding_id"]],
                "missing_evidence": [],
            }
            for role in sorted(acquisition_roles)
        ),
        claim_bindings=(claim_binding,),
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="incomplete role coverage"):
        replace_graph(
            graph,
            facts=(*graph.facts, result),
            claims=(*graph.claims, claim),
            analytical_claim_candidates=(*graph.analytical_claim_candidates, candidate),
            analytical_claim_review_decisions=(
                *graph.analytical_claim_review_decisions,
                decision,
            ),
            capital_allocation_event_candidates=(capital_candidate,),
            capital_allocation_event_review_decisions=(capital_decision,),
            capital_allocation_events=(event,),
            capital_allocation_outcomes=(outcome,),
            capital_allocation_reviews=(),
        ).validate()


def test_eps_accretion_alone_cannot_confirm_capital_allocation_outcome(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    executed = _fact(sample_payloads, "fact:acme:buyback-executed", "buyback_executed")
    sbc = _fact(sample_payloads, "fact:acme:sbc", "stock_based_compensation")
    issuance = _fact(sample_payloads, "fact:acme:issuance", "equity_issuance")
    net_shares = _fact(sample_payloads, "fact:acme:net-shares", "net_share_change")
    eps = _fact(sample_payloads, "fact:acme:eps", "earnings_per_share")
    claim, candidate, decision = _reviewed_claim(
        sample_payloads, "claim:acme:eps-only", eps.fact_id
    )
    claim_binding = _claim_binding(decision, "claim-binding:eps-only", "result_interpretation")
    result_binding = {
        "binding_id": "result-binding:eps-only",
        "role_id": "cash_spent",
        "fact_id": eps.fact_id,
        "calculation_result_id": None,
    }
    outcome = replace(
        graph.capital_allocation_outcomes[0],
        status="observed",
        result_bindings=(result_binding,),
        result_role_coverage=tuple(
            {
                **dict(item),
                "status": (
                    "observed"
                    if item["role_id"] == "cash_spent"
                    else "none_recognized_after_review"
                ),
                "binding_ids": (
                    [result_binding["binding_id"]]
                    if item["role_id"] == "cash_spent"
                    else []
                ),
                "claim_binding_ids": [claim_binding["binding_id"]],
            }
            for item in graph.capital_allocation_outcomes[0].result_role_coverage
        ),
        claim_bindings=(claim_binding,),
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="EPS accretion alone"):
        replace_graph(
            graph,
            facts=(*graph.facts, executed, sbc, issuance, net_shares, eps),
            claims=(*graph.claims, claim),
            analytical_claim_candidates=(*graph.analytical_claim_candidates, candidate),
            analytical_claim_review_decisions=(
                *graph.analytical_claim_review_decisions,
                decision,
            ),
            capital_allocation_outcomes=(outcome,),
            capital_allocation_reviews=(),
        ).validate()


def test_missing_outcome_evidence_stays_unverifiable_not_negative(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    outcome = replace(
        graph.capital_allocation_outcomes[0],
        status="unverifiable",
        result_role_coverage=tuple(
            {**dict(item), "status": "not_disclosed"}
            for item in graph.capital_allocation_outcomes[0].result_role_coverage
        ),
        missing_evidence=("Net share change not disclosed",),
    )
    replace_graph(
        graph,
        capital_allocation_outcomes=(outcome,),
        capital_allocation_reviews=(),
    ).validate()

    decision = graph.analytical_claim_review_decisions[0]
    claim_binding = _claim_binding(decision, "claim-binding:false-negative", "absence_search")
    falsely_negative = replace(
        outcome,
        status="observed",
        claim_bindings=(claim_binding,),
        result_role_coverage=tuple(
            {
                **dict(item),
                "claim_binding_ids": [claim_binding["binding_id"]],
            }
            for item in outcome.result_role_coverage
        ),
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="incomplete role coverage"):
        replace_graph(
            graph,
            capital_allocation_outcomes=(falsely_negative,),
            capital_allocation_reviews=(),
        ).validate()


def test_phase4a_has_no_production_judgment_engines_or_persona_agents() -> None:
    forbidden_modules = {
        "business_quality.py",
        "management.py",
        "capital_allocation.py",
        "publisher.py",
    }
    existing = {path.name for path in (ROOT / "src" / "owner_research").glob("*.py")}
    assert forbidden_modules.isdisjoint(existing)

    repository_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for base in (ROOT / "src", ROOT / "plugins")
        for path in base.rglob("*")
        if path.is_file()
    ).lower()
    assert "buffett agent" not in repository_text
    assert "management persona" not in repository_text
    assert "implicit publisher" not in repository_text


def _assert_counterevidence_blocks_supported_hypothesis(
    sample_payloads: dict[str, dict], mechanism: str, error_pattern: str
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    durability = _claim(
        sample_payloads,
        f"claim:acme:{mechanism}:durability",
        graph.facts[0].fact_id,
    )
    reinvestment = _claim(
        sample_payloads,
        f"claim:acme:{mechanism}:reinvestment",
        graph.facts[0].fact_id,
    )
    counterevidence = _claim(
        sample_payloads,
        f"claim:acme:{mechanism}:counterevidence",
        graph.facts[0].fact_id,
    )
    hypothesis = replace(
        graph.competitive_advantage_hypotheses[0],
        mechanism=mechanism,
        mechanism_policy_id=mechanism,
        status="supported",
        durability_claim_id=durability.claim_id,
        reinvestment_claim_id=reinvestment.claim_id,
        counterevidence_claim_ids=(counterevidence.claim_id,),
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError):
        replace_graph(
            graph,
            claims=(*graph.claims, durability, reinvestment, counterevidence),
            competitive_advantage_hypotheses=(hypothesis,),
            business_quality_reviews=(),
        ).validate()


@pytest.mark.parametrize(
    "case",
    json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"],
    ids=lambda case: case["case_id"],
)
def test_each_adversarial_fixture_executes_its_contract_boundary(
    case: dict, sample_payloads: dict[str, dict]
) -> None:
    semantics = (
        case["forbidden_inference"],
        case["required_state"],
        case["expected_error_pattern"],
    )
    assert semantics == EXPECTED_FIXTURE_SEMANTICS[case["case_id"]]

    if case["case_id"] in {
        "pricing-volume-collapse",
        "subsidized-user-growth",
        "sticky-claim-worsening-churn",
        "revenue-up-unit-cost-worse",
    }:
        mechanism = {
            "pricing-volume-collapse": "brand_pricing_power",
            "subsidized-user-growth": "network_effect",
            "sticky-claim-worsening-churn": "switching_cost",
            "revenue-up-unit-cost-worse": "scale_cost_advantage",
        }[case["case_id"]]
        _assert_counterevidence_blocks_supported_hypothesis(
            sample_payloads, mechanism, case["expected_error_pattern"]
        )
        return

    if case["case_id"] == "kpi-definition-change":
        from test_phase4a_graph import (
            test_kpi_successor_after_commitment_requires_bridge_at_outcome,
        )

        test_kpi_successor_after_commitment_requires_bridge_at_outcome(sample_payloads)
    elif case["case_id"] == "unexpired-commitment":
        from test_phase4a_graph import test_unexpired_commitment_cannot_be_marked_missed

        test_unexpired_commitment_cannot_be_marked_missed(sample_payloads)
    elif case["case_id"] == "buyback-offset-by-sbc":
        test_observed_buyback_requires_execution_sbc_issuance_and_net_shares(sample_payloads)
    elif case["case_id"] == "debt-buyback-eps":
        test_eps_accretion_alone_cannot_confirm_capital_allocation_outcome(sample_payloads)
    elif case["case_id"] == "acquisition-revenue-organic":
        from test_phase4a_graph import (
            test_event_key_is_deterministic_and_acquisition_cannot_be_organic,
        )

        test_event_key_is_deterministic_and_acquisition_cannot_be_organic(sample_payloads)
    elif case["case_id"] == "synergy-then-impairment":
        test_observed_acquisition_requires_synergy_and_impairment_evidence(sample_payloads)
    elif case["case_id"] == "duplicate-capital-event":
        from test_phase4a_graph import (
            test_duplicate_event_key_and_duplicate_outcome_windows_are_rejected,
        )

        test_duplicate_event_key_and_duplicate_outcome_windows_are_rejected(sample_payloads)
    elif case["case_id"] == "missing-outcome-evidence":
        test_missing_outcome_evidence_stays_unverifiable_not_negative(sample_payloads)
