from __future__ import annotations

from dataclasses import replace

import pytest
from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.capital_allocation_policies import EVENT_TYPES, SOURCE_FAMILIES
from owner_research.capital_allocation_reviews import (
    CapitalAllocationReviewError,
    build_capital_allocation_review,
)
from owner_research.source_search_receipts import (
    SourceSearchReceiptError,
    build_source_search_receipt,
)

PERIOD = {"start": "2026-01-01", "end": "2026-06-30"}
CUTOFF = "2026-06-30"


def _receipts(graph, *, blocked_family: str | None = None):
    document = graph.documents[0]
    return tuple(
        build_source_search_receipt(
            issuer_id="issuer:acme",
            source_family_id=family,
            query_scope={"cik": "0000000123", "event_types": sorted(EVENT_TYPES)},
            period=PERIOD,
            cutoff_date=CUTOFF,
            searched_endpoints=(f"fixture:{family}",),
            result_documents=(document,) if family == "10-K" else (),
            completed_at="2026-07-01T00:00:00Z",
            tool_version="phase4d5-test/1.0.0",
            status="blocked" if family == blocked_family else "completed",
            issues=(f"{family}_search_blocked",) if family == blocked_family else (),
        )
        for family in sorted(SOURCE_FAMILIES)
    )


def _build(graph, **overrides):
    arguments = {
        "issuer_id": "issuer:acme",
        "review_period": PERIOD,
        "as_of_date": CUTOFF,
        "source_documents": graph.documents,
        "source_search_receipts": _receipts(graph),
        "events": graph.capital_allocation_events,
        "outcomes": graph.capital_allocation_outcomes,
        "calculations": graph.calculations,
    }
    arguments.update(overrides)
    return build_capital_allocation_review(**arguments)


def test_review_builder_recomputes_v3_complete_coverage(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    review = _build(graph)
    assert review.schema_version == "3.0.0"
    assert review.review_policy_version == "2.0.0"
    assert review.status == "complete"
    assert review.event_ids == (graph.capital_allocation_events[0].event_id,)
    assert review.outcome_ids == (graph.capital_allocation_outcomes[0].outcome_id,)
    assert review.coverage["reviewed_present_source_count"] == 1
    assert review.coverage["searched_not_found_source_count"] == 7
    replace_graph(
        graph,
        source_search_receipts=_receipts(graph),
        capital_allocation_reviews=(review,),
    ).validate()


def test_prior_announcement_with_current_execution_is_selected(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    event = replace(
        graph.capital_allocation_events[0],
        announcement_date="2025-01-01",
        execution_period={"start": "2026-02-01", "end": None},
        lifecycle_status="in_progress",
    )
    review = _build(graph, events=(event,), outcomes=())
    assert review.event_ids == (event.event_id,)
    assert review.status == "partial"


def test_prior_event_with_current_outcome_is_selected(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    event = replace(
        graph.capital_allocation_events[0],
        announcement_date="2025-01-01",
        event_type="acquisition",
        event_subtype="business_combination",
        event_policy_id="capital-allocation-event/acquisition",
    )
    outcome = replace(
        graph.capital_allocation_outcomes[0],
        outcome_policy_id="capital-allocation-outcome/acquisition",
    )
    review = _build(graph, events=(event,), outcomes=(outcome,))
    assert review.event_ids == (event.event_id,)
    assert review.outcome_ids == (outcome.outcome_id,)


def test_prior_debt_event_with_current_repayment_is_selected(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    event = replace(
        graph.capital_allocation_events[0],
        announcement_date="2025-01-01",
        event_type="debt_repayment",
        event_subtype="scheduled",
        event_policy_id="capital-allocation-event/debt_repayment",
        execution_period={"start": "2026-03-01", "end": "2026-03-01"},
        lifecycle_status="completed",
    )
    review = _build(graph, events=(event,), outcomes=())
    assert review.event_ids == (event.event_id,)
    assert review.status == "partial"


def test_inactive_historical_event_is_not_selected(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    event = replace(graph.capital_allocation_events[0], announcement_date="2025-01-01")
    review = _build(graph, events=(event,), outcomes=())
    assert review.event_ids == ()
    assert review.outcome_ids == ()
    assert review.status == "complete"


def test_latest_event_and_latest_outcome_are_selected_across_version_chain(
    sample_payloads,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    original = replace(graph.capital_allocation_events[0], announcement_date="2025-01-01")
    successor = replace(
        original,
        event_id=f"{original.event_id}:v2",
        event_version=2,
        predecessor_event_id=original.event_id,
    )
    review = _build(graph, events=(original, successor))
    assert review.event_ids == (successor.event_id,)
    assert review.outcome_ids == (graph.capital_allocation_outcomes[0].outcome_id,)
    assert review.coverage["event_version_count"] == 2


def test_missing_or_blocked_receipt_prevents_complete(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    missing = _receipts(graph)[:-1]
    review = _build(graph, source_search_receipts=missing)
    assert review.status == "blocked"
    assert any(item.startswith("search_receipt_missing:") for item in review.missing_evidence)

    blocked = _build(
        graph,
        source_search_receipts=_receipts(graph, blocked_family="official_ir"),
    )
    assert blocked.status == "blocked"
    assert "official_ir_search_blocked" in blocked.missing_evidence


def test_tampered_or_incomplete_receipt_is_rejected(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    receipts = list(_receipts(graph))
    receipts[0] = replace(receipts[0], request_fingerprint="0" * 64)
    with pytest.raises(CapitalAllocationReviewError, match="fingerprint"):
        _build(graph, source_search_receipts=tuple(receipts))

    receipts = list(_receipts(graph))
    receipts[0] = replace(
        receipts[0],
        query_scope={"cik": "0000000123", "event_types": ["buyback"]},
    )
    with pytest.raises(CapitalAllocationReviewError, match="event coverage"):
        _build(graph, source_search_receipts=tuple(receipts))


def test_one_10k_cannot_prove_all_source_families_searched(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    only_10k = tuple(item for item in _receipts(graph) if item.source_family == "10-K")
    review = _build(graph, source_search_receipts=only_10k)
    assert review.status == "blocked"
    assert review.coverage["blocked_source_count"] == 7
    assert review.coverage["blocked_type_count"] == len(EVENT_TYPES) - 1


def test_future_outcome_is_not_selected(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    future = replace(graph.capital_allocation_outcomes[0], assessed_at="2026-07-01")
    review = _build(graph, outcomes=(future,))
    assert review.outcome_ids == ()
    assert review.status == "partial"


def test_receipt_scope_cutoff_and_result_family_are_enforced(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    receipt = _receipts(graph)[0]
    with pytest.raises(CapitalAllocationReviewError, match="scope mismatch"):
        _build(graph, source_search_receipts=(replace(receipt, cutoff_date="2026-06-29"),))

    with pytest.raises(SourceSearchReceiptError, match="result document is invalid"):
        build_source_search_receipt(
            issuer_id="issuer:acme",
            source_family_id="8-K",
            query_scope={"cik": "0000000123", "event_types": sorted(EVENT_TYPES)},
            period=PERIOD,
            cutoff_date=CUTOFF,
            searched_endpoints=("fixture:8-K",),
            result_documents=graph.documents,
            completed_at="2026-07-01T00:00:00Z",
            tool_version="phase4d5-test/1.0.0",
        )
