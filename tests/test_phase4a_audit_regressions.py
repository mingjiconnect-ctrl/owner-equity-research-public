from __future__ import annotations

import copy
from dataclasses import replace

import pytest
from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.contracts import contract_from_dict
from owner_research.validation import ContractGraphError


def _fact(
    sample_payloads: dict[str, dict],
    fact_id: str,
    concept: str,
    *,
    source_document_id: str | None = None,
):
    payload = copy.deepcopy(sample_payloads["fact"])
    payload.update({"fact_id": fact_id, "concept": concept})
    if source_document_id is not None:
        payload["source_document_id"] = source_document_id
    return contract_from_dict("fact", payload)


def _claim(sample_payloads: dict[str, dict], claim_id: str, fact_ids: list[str]):
    payload = copy.deepcopy(sample_payloads["claim"])
    payload.update({"claim_id": claim_id, "supporting_fact_ids": fact_ids})
    return contract_from_dict("claim", payload)


def test_event_and_outcome_formal_roles_reject_third_party_facts(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    secondary_document = replace(
        graph.documents[0],
        document_id="doc:acme:third-party",
        authority_level="secondary",
        source_url="https://example.com/third-party",
    )
    secondary_candidate = replace(
        graph.capital_allocation_event_candidates[0],
        candidate_id="capital-candidate:acme:third-party",
        source_document_id=secondary_document.document_id,
    )
    secondary_decision = replace(
        graph.capital_allocation_event_review_decisions[0],
        decision_id="capital-decision:acme:third-party",
        candidate_id=secondary_candidate.candidate_id,
        candidate_fingerprint=secondary_candidate.fingerprint,
        output_event_id="capital-event:acme:third-party",
    )
    with pytest.raises(ContractGraphError, match="requires an official source"):
        replace_graph(
            graph,
            documents=(*graph.documents, secondary_document),
            capital_allocation_event_candidates=(
                *graph.capital_allocation_event_candidates,
                secondary_candidate,
            ),
            capital_allocation_event_review_decisions=(
                *graph.capital_allocation_event_review_decisions,
                secondary_decision,
            ),
        ).validate()

    management_result = _fact(
        sample_payloads,
        "fact:acme:third-party-result",
        "revenue_growth",
        source_document_id=secondary_document.document_id,
    )
    management_result = replace(
        management_result,
        value=0.06,
        unit="ratio",
        currency=None,
        period={"start": "2026-01-01", "end": "2026-06-30"},
    )
    result_claim = _claim(
        sample_payloads,
        "claim:acme:third-party-result",
        [management_result.fact_id],
    )
    commitment = replace(graph.management_commitments[0], due_date="2026-06-30")
    outcome = replace(
        graph.management_outcomes[0],
        assessed_at="2026-07-15",
        evaluation_period={"start": "2026-01-01", "end": "2026-06-30"},
        status="met",
        result_bindings=(
            {
                "component_id": "primary",
                "role": "actual",
                "fact_id": management_result.fact_id,
                "calculation_result_id": None,
            },
        ),
        claim_ids=(result_claim.claim_id,),
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="official result Facts"):
        replace_graph(
            graph,
            documents=(*graph.documents, secondary_document),
            facts=(*graph.facts, management_result),
            claims=(*graph.claims, result_claim),
            management_commitments=(commitment,),
            management_outcomes=(outcome,),
            management_reviews=(),
        ).validate()


def test_reviews_reject_future_objects_and_evidence(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    future_hypothesis = replace(
        graph.competitive_advantage_hypotheses[0], as_of_date="2027-01-15"
    )
    with pytest.raises(ContractGraphError, match="future hypothesis"):
        replace_graph(
            graph,
            competitive_advantage_hypotheses=(future_hypothesis,),
        ).validate()


def test_management_review_rejects_late_published_or_confirmed_evidence(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    late_document = replace(
        graph.documents[0],
        published_date="2027-01-15",
        retrieved_at="2027-01-16T01:02:03Z",
    )
    late_statement = replace(
        graph.management_statements[0],
        reviewed_at="2027-01-16T03:00:00Z",
    )
    late_decision = replace(
        graph.management_statement_review_decisions[0],
        reviewed_at=late_statement.reviewed_at,
    )
    review = replace(
        graph.management_reviews[0],
        as_of_date="2026-12-31",
        review_period={"start": "2026-01-01", "end": "2026-12-31"},
        outcome_ids=(),
        coverage={
            "statement_count": 1,
            "confirmed_count": 1,
            "open_count": 1,
            "not_due_count": 0,
            "due_count": 1,
            "evaluated_due_count": 0,
            "pending_count": 0,
            "met_count": 0,
            "partially_met_count": 0,
            "missed_count": 0,
            "unverifiable_count": 0,
            "blocked_count": 0,
            "withdrawn_count": 0,
            "superseded_count": 0,
        },
    )

    with pytest.raises(ContractGraphError, match="published after cutoff"):
        replace_graph(
            graph,
            documents=(late_document,),
            context_observations=(),
            competitive_context_snapshots=(),
            analytical_claim_candidates=(),
            analytical_claim_review_decisions=(),
            business_model_snapshots=(),
            competitive_advantage_hypotheses=(),
            business_quality_reviews=(),
            management_statements=(late_statement,),
            management_statement_review_decisions=(late_decision,),
            management_outcomes=(),
            management_reviews=(review,),
            capital_allocation_event_candidates=(),
            capital_allocation_event_review_decisions=(),
            capital_allocation_events=(),
            capital_allocation_outcomes=(),
            capital_allocation_reviews=(),
        ).validate()

    timely_document = replace(late_document, published_date="2026-02-15")
    with pytest.raises(ContractGraphError, match="confirmed after cutoff"):
        replace_graph(
            graph,
            documents=(timely_document,),
            context_observations=(),
            competitive_context_snapshots=(),
            analytical_claim_candidates=(),
            analytical_claim_review_decisions=(),
            business_model_snapshots=(),
            competitive_advantage_hypotheses=(),
            business_quality_reviews=(),
            management_statements=(late_statement,),
            management_statement_review_decisions=(late_decision,),
            management_outcomes=(),
            management_reviews=(review,),
            capital_allocation_event_candidates=(),
            capital_allocation_event_review_decisions=(),
            capital_allocation_events=(),
            capital_allocation_outcomes=(),
            capital_allocation_reviews=(),
        ).validate()

    commitment = replace(graph.management_commitments[0], due_date="2026-12-31")
    future_claim = replace(
        graph.claims[0],
        claim_id="claim:acme:future-result",
        supporting_fact_ids=(graph.facts[1].fact_id,),
    )
    future_outcome = replace(
        graph.management_outcomes[0],
        assessed_at="2027-01-15",
        evaluation_period={"start": "2026-01-01", "end": "2026-12-31"},
        status="met",
        result_bindings=(
            {
                "component_id": "primary",
                "role": "actual",
                "fact_id": graph.facts[1].fact_id,
                "calculation_result_id": None,
            },
        ),
        claim_ids=(future_claim.claim_id,),
        missing_evidence=(),
    )
    management_review = replace(
        graph.management_reviews[0],
        outcome_ids=(future_outcome.outcome_id,),
        coverage={
            "statement_count": 1,
            "confirmed_count": 1,
            "open_count": 1,
            "not_due_count": 1,
            "due_count": 0,
            "evaluated_due_count": 0,
            "pending_count": 0,
            "met_count": 1,
            "partially_met_count": 0,
            "missed_count": 0,
            "unverifiable_count": 0,
            "blocked_count": 0,
            "withdrawn_count": 0,
            "superseded_count": 0,
        },
    )
    with pytest.raises(ContractGraphError, match="future Outcome"):
        replace_graph(
            graph,
            claims=(*graph.claims, future_claim),
            management_commitments=(commitment,),
            management_outcomes=(future_outcome,),
            management_reviews=(management_review,),
        ).validate()

    future_capital_outcome = replace(
        graph.capital_allocation_outcomes[0],
        assessed_at="2027-01-15",
        observation_period={"start": "2026-02-15", "end": "2026-12-31"},
    )
    with pytest.raises(ContractGraphError, match="future Outcome"):
        replace_graph(
            graph,
            capital_allocation_outcomes=(future_capital_outcome,),
        ).validate()


def test_observed_outcome_requires_post_event_results(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    decision = graph.analytical_claim_review_decisions[0]
    claim_binding = {
        "binding_id": "capital-claim:missing-results",
        "claim_id": decision.output_claim_id,
        "review_decision_id": decision.decision_id,
        "role_id": "absence_search",
    }
    outcome = replace(
        graph.capital_allocation_outcomes[0],
        status="observed",
        result_role_coverage=tuple(
            {
                **dict(item),
                "status": "not_disclosed",
                "claim_binding_ids": [claim_binding["binding_id"]],
            }
            for item in graph.capital_allocation_outcomes[0].result_role_coverage
        ),
        claim_bindings=(claim_binding,),
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="observed.*incomplete role coverage"):
        replace_graph(
            graph,
            capital_allocation_outcomes=(outcome,),
            capital_allocation_reviews=(),
        ).validate()


def test_observed_outcome_rejects_pre_event_result_fact(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    pre_event_document = replace(
        graph.documents[0],
        document_id="doc:acme:pre-event",
        published_date="2026-01-15",
        retrieved_at="2026-01-16T01:02:03Z",
    )
    pre_event_fact = _fact(
        sample_payloads,
        "fact:acme:pre-event-result",
        "dividend_result",
        source_document_id=pre_event_document.document_id,
    )
    decision = graph.analytical_claim_review_decisions[0]
    claim_binding = {
        "binding_id": "capital-claim:pre-event",
        "claim_id": decision.output_claim_id,
        "review_decision_id": decision.decision_id,
        "role_id": "result_interpretation",
    }
    result_binding = {
        "binding_id": "capital-result:pre-event",
        "role_id": "cash_spent",
        "fact_id": pre_event_fact.fact_id,
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
                    "observed" if item["role_id"] == "cash_spent"
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

    with pytest.raises(ContractGraphError, match="pre-Event result evidence"):
        replace_graph(
            graph,
            documents=(*graph.documents, pre_event_document),
            facts=(*graph.facts, pre_event_fact),
            capital_allocation_outcomes=(outcome,),
            capital_allocation_reviews=(),
        ).validate()


def test_complete_management_review_includes_old_statement_commitment_due_in_period(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    old_statement = replace(
        graph.management_statements[0],
        statement_date="2025-12-31",
    )
    commitment = replace(
        graph.management_commitments[0],
        start_date="2025-12-31",
        due_date="2026-06-30",
    )
    old_candidate = replace(
        graph.management_statement_candidates[0],
        statement_date=old_statement.statement_date,
    )
    old_decision = replace(
        graph.management_statement_review_decisions[0],
        candidate_fingerprint=old_candidate.fingerprint,
    )
    review = replace(
        graph.management_reviews[0],
        status="complete",
        statement_ids=(),
        commitment_ids=(),
        outcome_ids=(),
        coverage={
            "statement_count": 0,
            "confirmed_count": 0,
            "open_count": 0,
            "not_due_count": 0,
            "due_count": 0,
            "evaluated_due_count": 0,
            "pending_count": 0,
            "met_count": 0,
            "partially_met_count": 0,
            "missed_count": 0,
            "unverifiable_count": 0,
            "blocked_count": 0,
            "withdrawn_count": 0,
            "superseded_count": 0,
        },
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="omits an in-period Commitment"):
        replace_graph(
            graph,
            management_statements=(old_statement,),
            management_statement_candidates=(old_candidate,),
            management_statement_review_decisions=(old_decision,),
            management_commitments=(commitment,),
            management_outcomes=(),
            management_reviews=(review,),
        ).validate()


def test_complete_capital_review_includes_current_outcome_of_old_event(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    review = graph.capital_allocation_reviews[0]
    tampered = replace(
        review,
        event_ids=(),
        outcome_ids=(),
        coverage={**dict(review.coverage), "logical_event_count": 0, "outcome_count": 0},
    )
    with pytest.raises(ContractGraphError, match="deterministic replay"):
        replace_graph(
            graph,
            capital_allocation_reviews=(tampered,),
        ).validate()


def test_announced_event_accepts_unknown_execution_period_but_active_event_does_not(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    announced = replace(
        graph.capital_allocation_events[0],
        execution_period={"start": None, "end": None},
    )
    replace_graph(graph, capital_allocation_events=(announced,)).validate()

    active = replace(announced, lifecycle_status="in_progress")
    with pytest.raises(ContractGraphError, match="requires an execution start"):
        replace_graph(
            graph,
            capital_allocation_events=(active,),
            capital_allocation_outcomes=(),
            capital_allocation_reviews=(),
        ).validate()


def test_outcome_lineage_and_parent_time_boundaries(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    early_management = replace(
        graph.management_outcomes[0],
        evaluation_period={"start": "2025-12-01", "end": "2026-06-30"},
    )
    with pytest.raises(ContractGraphError, match="starts before its Commitment"):
        replace_graph(graph, management_outcomes=(early_management,)).validate()

    early_capital = replace(
        graph.capital_allocation_outcomes[0],
        observation_period={"start": "2026-01-01", "end": "2026-06-30"},
    )
    with pytest.raises(ContractGraphError, match="predates its Event"):
        replace_graph(graph, capital_allocation_outcomes=(early_capital,)).validate()


def test_hypothesis_roles_and_scope_are_semantically_distinct(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    hypothesis = graph.competitive_advantage_hypotheses[0]
    empty_segment_scope = replace(
        hypothesis,
        scope={
            "scope_type": "segment_specific",
            "segment_definition_ids": [],
            "business_unit": "all",
            "product_service": None,
            "geography": "all",
            "customer_group": "all",
            "channel": None,
        },
    )
    with pytest.raises(ContractGraphError, match="lacks a segment"):
        replace_graph(
            graph,
            competitive_advantage_hypotheses=(empty_segment_scope,),
        ).validate()

    one_claim = replace(
        hypothesis,
        status="supported",
        durability_claim_id=graph.claims[0].claim_id,
        reinvestment_claim_id=graph.claims[0].claim_id,
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="positive role Claims must be distinct"):
        replace_graph(graph, competitive_advantage_hypotheses=(one_claim,)).validate()
