from __future__ import annotations

import copy
import hashlib
from dataclasses import replace

from owner_research.capital_allocation_policies import SOURCE_FAMILIES
from owner_research.capital_allocation_reviews import build_capital_allocation_review
from owner_research.contracts import Contract, contract_from_dict
from owner_research.source_search_receipts import build_source_search_receipt
from owner_research.validation import ContractGraph


def contract(sample_payloads: dict[str, dict], name: str, **updates: object) -> Contract:
    payload = copy.deepcopy(sample_payloads[name])
    payload.update(updates)
    return contract_from_dict(name, payload)


def valid_phase4a_graph(sample_payloads: dict[str, dict]) -> ContractGraph:
    document = contract(sample_payloads, "source-document")
    period = contract(sample_payloads, "fiscal-period")
    segment = contract(sample_payloads, "segment-definition")
    segment_snapshot = contract(sample_payloads, "segment-snapshot")
    fact = contract(sample_payloads, "fact")
    lower_target = replace(
        fact,
        fact_id="fact:acme:revenue-growth-lower:2026",
        concept="revenue_growth",
        value=0.05,
        unit="ratio",
        currency=None,
        period={"start": "2026-01-01", "end": "2026-12-31"},
        source_locator="text:10:67",
    )
    upper_target = replace(
        lower_target,
        fact_id="fact:acme:revenue-growth-upper:2026",
        value=0.07,
    )
    claim = contract(sample_payloads, "claim")
    context_observation = contract(sample_payloads, "context-observation")
    competitive_context = contract(sample_payloads, "competitive-context-snapshot")
    analytical_candidate = contract(sample_payloads, "analytical-claim-candidate")
    analytical_decision = contract(sample_payloads, "analytical-claim-review-decision")

    business_model = contract(sample_payloads, "business-model-snapshot")
    hypothesis = contract(sample_payloads, "competitive-advantage-hypothesis")
    business_review = contract(sample_payloads, "business-quality-review")

    statement_text = "We expect revenue growth of 5% to 7% in fiscal 2026."
    statement = contract(
        sample_payloads,
        "management-statement",
        statement_sha256=hashlib.sha256(statement_text.encode("utf-8")).hexdigest(),
        statement_text=statement_text,
        verification_status="human_confirmed",
        reviewer_id="reviewer:phase4a",
        reviewed_at="2026-02-16T03:00:00Z",
        missing_evidence=[],
    )
    candidate = contract(
        sample_payloads,
        "management-statement-candidate",
        excerpt_sha256=hashlib.sha256(statement_text.encode("utf-8")).hexdigest(),
        statement_sha256=hashlib.sha256(statement_text.encode("utf-8")).hexdigest(),
    )
    decision = contract(
        sample_payloads,
        "management-statement-review-decision",
        candidate_fingerprint=candidate.fingerprint,
    )
    commitment = contract(sample_payloads, "management-commitment")
    management_outcome = contract(sample_payloads, "management-outcome")
    management_review_payload = copy.deepcopy(sample_payloads["management-review"])
    management_review_payload["coverage"]["confirmed_count"] = 1
    management_review = contract_from_dict("management-review", management_review_payload)

    capital_candidate = contract(sample_payloads, "capital-allocation-event-candidate")
    capital_decision = contract(
        sample_payloads,
        "capital-allocation-event-review-decision",
        candidate_fingerprint=capital_candidate.fingerprint,
    )
    capital_event = contract(sample_payloads, "capital-allocation-event")
    capital_outcome = contract(sample_payloads, "capital-allocation-outcome")
    search_receipts = tuple(
        build_source_search_receipt(
            issuer_id=document.issuer_id,
            source_family_id=family,
            query_scope=sample_payloads["source-search-receipt"]["query_scope"],
            period={"start": "2026-01-01", "end": "2026-06-30"},
            cutoff_date="2026-06-30",
            searched_endpoints=(f"fixture:{family}",),
            result_documents=(document,) if family == "10-K" else (),
            completed_at="2026-07-01T00:00:00Z",
            tool_version="phase4d5-fixture/1.0.0",
        )
        for family in sorted(SOURCE_FAMILIES)
    )
    capital_review = build_capital_allocation_review(
        issuer_id=document.issuer_id,
        review_period={"start": "2026-01-01", "end": "2026-06-30"},
        as_of_date="2026-06-30",
        source_documents=(document,),
        source_search_receipts=search_receipts,
        events=(capital_event,),
        outcomes=(capital_outcome,),
        calculations=(),
    )

    return ContractGraph(
        documents=(document,),
        periods=(period,),
        facts=(fact, lower_target, upper_target),
        claims=(claim,),
        segment_definitions=(segment,),
        segment_snapshots=(segment_snapshot,),
        context_observations=(context_observation,),
        competitive_context_snapshots=(competitive_context,),
        analytical_claim_candidates=(analytical_candidate,),
        analytical_claim_review_decisions=(analytical_decision,),
        business_model_snapshots=(business_model,),
        competitive_advantage_hypotheses=(hypothesis,),
        business_quality_reviews=(business_review,),
        management_statements=(statement,),
        management_statement_candidates=(candidate,),
        management_statement_review_decisions=(decision,),
        management_commitments=(commitment,),
        management_outcomes=(management_outcome,),
        capital_allocation_event_candidates=(capital_candidate,),
        capital_allocation_event_review_decisions=(capital_decision,),
        capital_allocation_events=(capital_event,),
        capital_allocation_outcomes=(capital_outcome,),
        source_search_receipts=search_receipts,
        management_reviews=(management_review,),
        capital_allocation_reviews=(capital_review,),
    )


def replace_graph(graph: ContractGraph, **updates: object) -> ContractGraph:
    return replace(graph, **updates)
