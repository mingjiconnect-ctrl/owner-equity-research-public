from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace

import pytest
from jsonschema import ValidationError
from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.capital_allocation_policies import (
    CAPITAL_ALLOCATION_POLICIES,
    EVENT_POLICY_VERSION,
    OUTCOME_POLICY_VERSION,
    SOURCE_ROLES,
    economic_event_key,
)
from owner_research.contracts import contract_from_dict
from owner_research.validation import ContractGraphError


def test_phase4d0_contracts_are_versioned_immutable_and_reject_v1(
    sample_payloads,
) -> None:
    for name, version in (
        ("capital-allocation-event-candidate", "2.0.0"),
        ("capital-allocation-event-review-decision", "1.0.0"),
        ("capital-allocation-event", "2.0.0"),
        ("capital-allocation-outcome", "2.0.0"),
        ("source-search-receipt", "1.0.0"),
        ("capital-allocation-review", "3.0.0"),
    ):
        instance = contract_from_dict(name, sample_payloads[name])
        assert instance.schema_version == version
        assert instance.fingerprint == contract_from_dict(name, sample_payloads[name]).fingerprint
        with pytest.raises((FrozenInstanceError, AttributeError)):
            instance.schema_version = "changed"
        legacy = copy.deepcopy(sample_payloads[name])
        legacy["schema_version"] = "1.0.0" if version in {"2.0.0", "3.0.0"} else "0.9.0"
        with pytest.raises(ValidationError):
            contract_from_dict(name, legacy)


def test_policy_registry_is_closed_and_identity_is_economic_not_disclosure_based() -> None:
    assert set(CAPITAL_ALLOCATION_POLICIES) == {
        "organic_capex", "research_and_development", "acquisition", "divestiture",
        "buyback", "dividend", "debt_issuance", "debt_repayment", "equity_issuance",
        "stock_based_compensation", "pension_funding", "restructuring", "cash_accumulation",
    }
    assert EVENT_POLICY_VERSION == OUTCOME_POLICY_VERSION == "1.0.0"
    assert "authorization" in SOURCE_ROLES
    identity = (
        {"role": "program_id", "value": "2026 authorization"},
        {"role": "approval_date", "value": "2026-02-15"},
        {"role": "security_class", "value": "Common Stock"},
    )
    first = economic_event_key(
        issuer_id="issuer:acme", event_type="buyback", event_subtype="open_market",
        identity_components=identity,
    )
    assert first == economic_event_key(
        issuer_id="issuer:acme", event_type="buyback", event_subtype="open_market",
        identity_components=tuple(reversed(identity)),
    )
    changed = tuple(
        {**item, "value": "2027 authorization"} if item["role"] == "program_id" else item
        for item in identity
    )
    assert first != economic_event_key(
        issuer_id="issuer:acme", event_type="buyback", event_subtype="open_market",
        identity_components=changed,
    )


def test_unreviewed_or_tampered_candidate_cannot_create_event(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    with pytest.raises(ContractGraphError, match="confirmed Event Decision"):
        replace_graph(graph, capital_allocation_event_review_decisions=()).validate()
    decision = graph.capital_allocation_event_review_decisions[0]
    tampered = replace(decision, candidate_fingerprint="0" * 64)
    with pytest.raises(ContractGraphError, match="fingerprint"):
        replace_graph(
            graph, capital_allocation_event_review_decisions=(tampered,)
        ).validate()


def test_event_rejects_free_policy_fact_reuse_and_partial_completion(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    event = graph.capital_allocation_events[0]
    with pytest.raises(ContractGraphError, match="event policy"):
        replace_graph(
            graph,
            capital_allocation_events=(replace(event, event_policy_id="free-policy"),),
        ).validate()
    duplicated = (
        {
            "binding_id": "binding:authorization",
            "candidate_id": graph.capital_allocation_event_candidates[0].candidate_id,
            "decision_id": graph.capital_allocation_event_review_decisions[0].decision_id,
            "fact_id": graph.facts[0].fact_id,
            "role_id": "authorization_limit",
        },
        {
            "binding_id": "binding:cash-spent",
            "candidate_id": graph.capital_allocation_event_candidates[0].candidate_id,
            "decision_id": graph.capital_allocation_event_review_decisions[0].decision_id,
            "fact_id": graph.facts[0].fact_id,
            "role_id": "cash_spent",
        },
    )
    with pytest.raises(ContractGraphError, match="reuses a Fact"):
        replace_graph(
            graph, capital_allocation_events=(replace(event, fact_bindings=duplicated),)
        ).validate()
    completed_candidate = replace(
        graph.capital_allocation_event_candidates[0],
        proposed_execution_period={"start": "2026-02-15", "end": "2026-02-16"},
    )
    completed_decision = replace(
        graph.capital_allocation_event_review_decisions[0],
        candidate_fingerprint=completed_candidate.fingerprint,
    )
    with pytest.raises(ContractGraphError, match="completed.*execution evidence"):
        replace_graph(
            graph,
            capital_allocation_event_candidates=(completed_candidate,),
            capital_allocation_event_review_decisions=(completed_decision,),
            capital_allocation_events=(
                replace(
                    event,
                    lifecycle_status="completed",
                    execution_period={"start": "2026-02-15", "end": "2026-02-16"},
                ),
            ),
        ).validate()


def test_event_versions_are_contiguous_and_do_not_duplicate_logical_events(
    sample_payloads,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    event = graph.capital_allocation_events[0]
    duplicate = replace(event, event_id="capital-event:duplicate")
    with pytest.raises(ContractGraphError, match="version chain"):
        replace_graph(graph, capital_allocation_events=(event, duplicate)).validate()

    successor_candidate = replace(
        graph.capital_allocation_event_candidates[0],
        candidate_id="capital-candidate:successor",
        proposed_source_role="periodic_recap",
    )
    successor_decision = replace(
        graph.capital_allocation_event_review_decisions[0],
        decision_id="capital-decision:successor",
        candidate_id=successor_candidate.candidate_id,
        candidate_fingerprint=successor_candidate.fingerprint,
        output_event_id="capital-event:successor",
    )
    successor = replace(
        event,
        event_id="capital-event:successor",
        event_version=2,
        predecessor_event_id=event.event_id,
        source_bindings=(
            {
                "binding_id": "capital-source:successor",
                "candidate_id": successor_candidate.candidate_id,
                "decision_id": successor_decision.decision_id,
                "source_document_id": successor_candidate.source_document_id,
                "role_id": "periodic_recap",
            },
        ),
    )
    with pytest.raises(ContractGraphError, match="silently deletes predecessor evidence"):
        replace_graph(
            graph,
            capital_allocation_event_candidates=(
                *graph.capital_allocation_event_candidates,
                successor_candidate,
            ),
            capital_allocation_event_review_decisions=(
                *graph.capital_allocation_event_review_decisions,
                successor_decision,
            ),
            capital_allocation_events=(event, successor),
            capital_allocation_outcomes=(),
            capital_allocation_reviews=(),
        ).validate()


def test_fact_roles_enforce_unit_families_and_event_currency_consistency(
    sample_payloads,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    candidate = graph.capital_allocation_event_candidates[0]
    decision = graph.capital_allocation_event_review_decisions[0]
    event = graph.capital_allocation_events[0]
    wrong_unit_candidate = replace(
        candidate,
        proposed_fact_bindings=(
            {
                "binding_id": "capital-fact:shares",
                "role_id": "shares_repurched",
                "fact_id": graph.facts[0].fact_id,
            },
        ),
    )
    wrong_unit_decision = replace(
        decision,
        candidate_fingerprint=wrong_unit_candidate.fingerprint,
    )
    with pytest.raises(ContractGraphError, match="fact role unit mismatch"):
        replace_graph(
            graph,
            capital_allocation_event_candidates=(wrong_unit_candidate,),
            capital_allocation_event_review_decisions=(wrong_unit_decision,),
        ).validate()

    euro_fact = replace(graph.facts[0], fact_id="fact:acme:eur", currency="EUR")
    proposed = (
        {
            "binding_id": "capital-fact:authorization",
            "role_id": "authorization_limit",
            "fact_id": graph.facts[0].fact_id,
        },
        {
            "binding_id": "capital-fact:cash",
            "role_id": "cash_spent",
            "fact_id": euro_fact.fact_id,
        },
    )
    currency_candidate = replace(candidate, proposed_fact_bindings=proposed)
    currency_decision = replace(
        decision,
        candidate_fingerprint=currency_candidate.fingerprint,
    )
    bindings = tuple(
        {
            **item,
            "candidate_id": currency_candidate.candidate_id,
            "decision_id": currency_decision.decision_id,
        }
        for item in proposed
    )
    with pytest.raises(ContractGraphError, match="mixes currencies"):
        replace_graph(
            graph,
            facts=(*graph.facts, euro_fact),
            capital_allocation_event_candidates=(currency_candidate,),
            capital_allocation_event_review_decisions=(currency_decision,),
            capital_allocation_events=(replace(event, fact_bindings=bindings),),
        ).validate()


def test_outcome_rejects_free_policy_future_evidence_and_incomplete_buyback(
    sample_payloads,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    outcome = graph.capital_allocation_outcomes[0]
    with pytest.raises(ContractGraphError, match="outcome policy"):
        replace_graph(
            graph,
            capital_allocation_outcomes=(replace(outcome, outcome_policy_id="free-policy"),),
        ).validate()
    decision = graph.analytical_claim_review_decisions[0]
    claim_binding = {
        "binding_id": "capital-outcome-claim:incomplete",
        "claim_id": decision.output_claim_id,
        "review_decision_id": decision.decision_id,
        "role_id": "absence_search",
    }
    observed = replace(
        outcome,
        status="observed",
        result_role_coverage=tuple(
            {
                **dict(item),
                "status": "not_disclosed",
                "claim_binding_ids": [claim_binding["binding_id"]],
            }
            for item in outcome.result_role_coverage
        ),
        claim_bindings=(claim_binding,),
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="observed.*role coverage"):
        replace_graph(graph, capital_allocation_outcomes=(observed,)).validate()


def test_cancelled_event_requires_cancellation_source_and_lifecycle_outcome(
    sample_payloads,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    event = replace(graph.capital_allocation_events[0], lifecycle_status="cancelled")
    with pytest.raises(ContractGraphError, match="lacks cancellation source"):
        replace_graph(
            graph,
            capital_allocation_events=(event,),
        ).validate()

    candidate = replace(
        graph.capital_allocation_event_candidates[0],
        proposed_source_role="cancellation",
    )
    decision = replace(
        graph.capital_allocation_event_review_decisions[0],
        candidate_fingerprint=candidate.fingerprint,
    )
    cancelled = replace(
        event,
        source_bindings=(
            {
                **dict(event.source_bindings[0]),
                "role_id": "cancellation",
            },
        ),
    )
    with pytest.raises(ContractGraphError, match="cannot receive an ordinary Outcome"):
        replace_graph(
            graph,
            capital_allocation_event_candidates=(candidate,),
            capital_allocation_event_review_decisions=(decision,),
            capital_allocation_events=(cancelled,),
        ).validate()


def test_review_cannot_treat_zero_counts_or_blocked_sources_as_complete(
    sample_payloads,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    review = graph.capital_allocation_reviews[0]
    tampered_counts = {**dict(review.coverage), "logical_event_count": 0}
    with pytest.raises(ContractGraphError, match="deterministic replay"):
        replace_graph(
            graph,
            capital_allocation_reviews=(
                replace(review, coverage=tampered_counts),
            ),
        ).validate()
    with pytest.raises(ContractGraphError, match="deterministic replay"):
        replace_graph(
            graph,
            source_search_receipts=(),
        ).validate()


def test_phase4d_contracts_forbid_value_verdict_fields(sample_payloads) -> None:
    for name in (
        "capital-allocation-event",
        "capital-allocation-outcome",
        "capital-allocation-review",
    ):
        for field in (
            "score", "value_created", "npv", "roic", "valuation", "market_price",
            "target_price", "recommendation", "publisher",
        ):
            payload = copy.deepcopy(sample_payloads[name])
            payload[field] = 1
            with pytest.raises(ValidationError):
                contract_from_dict(name, payload)
