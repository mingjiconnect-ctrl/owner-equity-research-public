from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from jsonschema import ValidationError
from phase4a_support import contract, replace_graph, valid_phase4a_graph

from owner_research.capital_allocation_policies import economic_event_key
from owner_research.contracts import contract_from_dict
from owner_research.validation import ContractGraphError


def _confirmation_for(graph, statement, suffix: str):
    candidate = replace(
        graph.management_statement_candidates[0],
        candidate_id=f"management-candidate:issuer:acme:{suffix}",
        source_locator=statement.source_locator,
        excerpt_sha256=statement.statement_sha256,
        statement_text=statement.statement_text,
        statement_sha256=statement.statement_sha256,
        statement_date=statement.statement_date,
        statement_type=statement.statement_type,
        kpi_concept=statement.kpi_concept,
        metric_mentions=(
            graph.management_statement_candidates[0].metric_mentions
            if statement.metric_bindings
            else ()
        ),
    )
    decision = replace(
        graph.management_statement_review_decisions[0],
        decision_id=f"statement-review:issuer:acme:{suffix}",
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=candidate.fingerprint,
        output_statement_id=statement.statement_id,
        output_fact_ids=tuple(item["fact_id"] for item in statement.metric_bindings),
    )
    return candidate, decision


def test_valid_phase4a_contract_graph(sample_payloads: dict[str, dict]) -> None:
    valid_phase4a_graph(sample_payloads).validate()


def test_phase4a_graph_rejects_dangling_and_cross_issuer_references(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    dangling = replace(graph.management_commitments[0], statement_id="statement:missing")
    with pytest.raises(ContractGraphError, match="dangling reference"):
        replace_graph(graph, management_commitments=(dangling,)).validate()

    foreign = replace(graph.management_statements[0], issuer_id="issuer:other")
    with pytest.raises(ContractGraphError, match="multiple issuers"):
        replace_graph(graph, management_statements=(foreign,)).validate()


def test_unconfirmed_statement_cannot_create_commitment_or_enter_review(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    unconfirmed = replace(
        graph.management_statements[0],
        verification_status="pending",
        reviewer_id=None,
        reviewed_at=None,
        missing_evidence=("Human review",),
    )
    with pytest.raises(ContractGraphError, match="human-confirmed Statement"):
        replace_graph(graph, management_statements=(unconfirmed,)).validate()


def test_unexpired_commitment_cannot_be_marked_missed(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    missed = replace(
        graph.management_outcomes[0],
        status="missed",
        result_bindings=(
            {
                "component_id": "primary",
                "role": "actual",
                "fact_id": graph.facts[1].fact_id,
                "calculation_result_id": None,
            },
        ),
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="unexpired"):
        replace_graph(graph, management_outcomes=(missed,)).validate()


def test_expired_commitment_without_results_is_unverifiable_not_missed(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    expired = replace(
        graph.management_outcomes[0],
        assessed_at="2027-01-15",
        evaluation_period={"start": "2026-01-01", "end": "2026-12-31"},
        status="missed",
        missing_evidence=("Outcome evidence unavailable",),
    )
    with pytest.raises(ContractGraphError, match="lacks result evidence"):
        replace_graph(graph, management_outcomes=(expired,)).validate()


def test_statement_text_hash_and_predecessor_cycles_are_enforced(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    changed = replace(graph.management_statements[0], statement_text="Changed text")
    with pytest.raises(ContractGraphError, match="text hash mismatch"):
        replace_graph(graph, management_statements=(changed,)).validate()

    first = graph.management_statements[0]
    second_payload = first.to_dict()
    second_payload.update(
        {
            "statement_id": "statement:acme:guidance:2025",
            "statement_date": "2026-02-14",
            "source_locator": "Item 7, outlook paragraph 1",
            "predecessor_statement_ids": [first.statement_id],
        }
    )
    second = contract_from_dict("management-statement", second_payload)
    cyclic_first = replace(first, predecessor_statement_ids=(second.statement_id,))
    with pytest.raises(ContractGraphError):
        replace_graph(graph, management_statements=(cyclic_first, second)).validate()


def test_kpi_definition_change_requires_deterministic_bridge(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    old_text = "We define active customers as paying accounts."
    old_statement = replace(
        graph.management_statements[0],
        statement_id="statement:acme:kpi:old",
        statement_date="2026-02-14",
        statement_type="kpi_definition",
        kpi_concept="active_customers",
        definition_change="initial",
        source_locator="text:100:150",
        statement_text=old_text,
        statement_sha256=hashlib.sha256(old_text.encode()).hexdigest(),
        kpi_definition_fact_ids=(graph.facts[0].fact_id,),
        commitment_eligibility="narrative_only",
        metric_bindings=(),
    )
    new_text = "We now include trial accounts in active customers."
    new_statement = replace(
        old_statement,
        statement_id="statement:acme:kpi:new",
        statement_date="2026-02-15",
        definition_change="redefined",
        statement_text=new_text,
        statement_sha256=hashlib.sha256(new_text.encode()).hexdigest(),
        predecessor_statement_ids=(old_statement.statement_id,),
        source_locator="text:10:67",
        commitment_eligibility="measurable",
        metric_bindings=graph.management_statements[0].metric_bindings,
    )
    commitment = replace(
        graph.management_commitments[0],
        statement_id=new_statement.statement_id,
        commitment_type="kpi_definition",
        metric_concept="active_customers",
        definition_reconciliation_calculation_ids=(),
    )
    old_candidate, old_decision = _confirmation_for(graph, old_statement, "kpi-old")
    new_candidate, new_decision = _confirmation_for(graph, new_statement, "kpi-new")
    with pytest.raises(ContractGraphError, match="deterministic bridge"):
        replace_graph(
            graph,
            management_statements=(old_statement, new_statement),
            management_statement_candidates=(old_candidate, new_candidate),
            management_statement_review_decisions=(old_decision, new_decision),
            management_commitments=(commitment,),
            management_outcomes=(),
            management_reviews=(),
        ).validate()


def test_kpi_successor_after_commitment_requires_bridge_at_outcome(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    old_text = "We define revenue users as paid accounts."
    old_statement = replace(
        graph.management_statements[0],
        statement_id="statement:acme:kpi:old",
        statement_date="2026-02-14",
        statement_type="kpi_definition",
        kpi_concept="revenue_growth",
        definition_change="initial",
        statement_text=old_text,
        statement_sha256=hashlib.sha256(old_text.encode()).hexdigest(),
        kpi_definition_fact_ids=(graph.facts[0].fact_id,),
        source_locator="text:10:67",
    )
    new_text = "We now include trial accounts in revenue users."
    new_statement = replace(
        old_statement,
        statement_id="statement:acme:kpi:new",
        statement_date="2026-02-15",
        definition_change="redefined",
        source_locator="text:151:210",
        statement_text=new_text,
        statement_sha256=hashlib.sha256(new_text.encode()).hexdigest(),
        predecessor_statement_ids=(old_statement.statement_id,),
        commitment_eligibility="narrative_only",
        metric_bindings=(),
    )
    commitment = replace(
        graph.management_commitments[0],
        statement_id=old_statement.statement_id,
        commitment_type="kpi_definition",
        due_date="2026-06-30",
        definition_reconciliation_calculation_ids=(),
    )
    outcome = replace(
        graph.management_outcomes[0],
        commitment_id=commitment.commitment_id,
        assessed_at="2026-07-15",
        evaluation_period={"start": "2026-01-01", "end": "2026-06-30"},
        status="met",
        result_bindings=(
            {
                "component_id": "primary",
                "role": "actual",
                "fact_id": graph.facts[1].fact_id,
                "calculation_result_id": None,
            },
        ),
        missing_evidence=(),
    )
    old_candidate, old_decision = _confirmation_for(graph, old_statement, "kpi-old")
    new_candidate, new_decision = _confirmation_for(graph, new_statement, "kpi-new")

    with pytest.raises(ContractGraphError, match="crosses a KPI definition change"):
        replace_graph(
            graph,
            management_statements=(old_statement, new_statement),
            management_statement_candidates=(old_candidate, new_candidate),
            management_statement_review_decisions=(old_decision, new_decision),
            management_commitments=(commitment,),
            management_outcomes=(outcome,),
            management_reviews=(),
        ).validate()


def test_hypothesis_requires_role_claims_and_separate_counterevidence(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    payload = graph.competitive_advantage_hypotheses[0].to_dict()
    payload.update(
        {
            "status": "supported",
            "durability_claim_id": None,
            "reinvestment_claim_id": None,
            "missing_evidence": [],
        }
    )
    with pytest.raises(ValidationError):
        contract_from_dict("competitive-advantage-hypothesis", payload)

    contested = replace(
        graph.competitive_advantage_hypotheses[0],
        status="contested",
        durability_claim_id=graph.claims[0].claim_id,
        reinvestment_claim_id=graph.claims[0].claim_id,
        counterevidence_claim_ids=(graph.claims[0].claim_id,),
    )
    with pytest.raises(ContractGraphError, match="mixes support and counterevidence"):
        replace_graph(graph, competitive_advantage_hypotheses=(contested,)).validate()


def test_complete_review_cannot_be_supported_only_by_third_party(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    third_party_document = replace(graph.documents[0], authority_level="secondary")
    with pytest.raises(ContractGraphError, match="third-party|official"):
        replace_graph(graph, documents=(third_party_document,)).validate()


def test_duplicate_event_key_and_duplicate_outcome_windows_are_rejected(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    duplicate_event = replace(
        graph.capital_allocation_events[0], event_id="capital-event:acme:duplicate"
    )
    with pytest.raises(ContractGraphError, match="duplicate CapitalAllocationEvent"):
        replace_graph(
            graph,
            capital_allocation_events=(graph.capital_allocation_events[0], duplicate_event),
        ).validate()

    duplicate_outcome = replace(
        graph.capital_allocation_outcomes[0], outcome_id="capital-outcome:acme:duplicate"
    )
    with pytest.raises(ContractGraphError, match="duplicate CapitalAllocationOutcome"):
        replace_graph(
            graph,
            capital_allocation_outcomes=(graph.capital_allocation_outcomes[0], duplicate_outcome),
        ).validate()


def test_event_key_is_deterministic_and_acquisition_cannot_be_organic(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    bad_key = replace(graph.capital_allocation_events[0], economic_event_key="0" * 64)
    with pytest.raises(ContractGraphError, match="economic key mismatch"):
        replace_graph(graph, capital_allocation_events=(bad_key,)).validate()

    identity_components = (
        {"role": "target_entity", "value": "TargetCo"},
        {"role": "transaction_id", "value": "agreement-2026"},
    )
    event_key = economic_event_key(
        issuer_id="issuer:acme",
        event_type="acquisition",
        event_subtype="business_combination",
        identity_components=identity_components,
    )
    candidate = replace(
        graph.capital_allocation_event_candidates[0],
        proposed_event_type="acquisition",
        proposed_event_subtype="business_combination",
        proposed_identity_components=identity_components,
        proposed_growth_classification="organic",
    )
    decision = replace(
        graph.capital_allocation_event_review_decisions[0],
        candidate_fingerprint=candidate.fingerprint,
        output_economic_event_key=event_key,
    )
    acquisition = replace(
        graph.capital_allocation_events[0],
        event_policy_id="capital-allocation-event/acquisition",
        economic_event_key=event_key,
        event_type="acquisition",
        event_subtype="business_combination",
        identity_components=identity_components,
        growth_classification="organic",
    )
    with pytest.raises(ContractGraphError, match="cannot be classified as organic"):
        replace_graph(
            graph,
            capital_allocation_event_candidates=(candidate,),
            capital_allocation_event_review_decisions=(decision,),
            capital_allocation_events=(acquisition,),
        ).validate()


def test_nonblocked_outcomes_and_reviews_require_claims(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    for item in (
        graph.management_outcomes[0],
        graph.capital_allocation_outcomes[0],
        graph.business_quality_reviews[0],
        graph.management_reviews[0],
        graph.capital_allocation_reviews[0],
    ):
        if item.status == "blocked":
            continue
        payload = item.to_dict()
        payload["claim_ids"] = []
        with pytest.raises(ValidationError):
            contract_from_dict(item.SCHEMA_NAME, payload)


def test_phase4_calculation_cannot_depend_on_assumptions(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    calculation = contract(sample_payloads, "calculation-result")
    hypothesis = replace(
        graph.competitive_advantage_hypotheses[0],
        evidence_bindings=(
            {
                "binding_id": "binding:acme:retention",
                "role_id": "retention_churn",
                "polarity": "support",
                "fact_id": None,
                "calculation_result_id": calculation.calculation_id,
                "context_observation_id": None,
            },
        ),
    )
    with pytest.raises(ContractGraphError, match="depends on an Assumption"):
        replace_graph(
            graph,
            calculations=(calculation,),
            assumptions=(contract(sample_payloads, "assumption"),),
            competitive_advantage_hypotheses=(hypothesis,),
        ).validate()
