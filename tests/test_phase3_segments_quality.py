from __future__ import annotations

import copy
from pathlib import Path

import pytest

from owner_research.accounting_quality import (
    AccountingQualityError,
    build_review,
    confirm_finding,
    evaluate_ratio_rule,
    validate_rule_registry,
)
from owner_research.contracts import contract_from_dict
from owner_research.footnotes import REQUIRED_TOPICS, discover_note_headings, discover_topic_codes
from owner_research.segments import display_precision_tolerance, reconcile_segments
from owner_research.validation import ContractGraph, ContractGraphError

ROOT = Path(__file__).parents[1]


def _fact(payloads: dict[str, dict], identifier: str, value: float, concept: str = "revenue"):
    payload = copy.deepcopy(payloads["fact"])
    payload.update(fact_id=identifier, value=value, concept=concept)
    return contract_from_dict("fact", payload)


def test_segment_reconciliation_tolerance_comes_from_display_precision(
    sample_payloads: dict[str, dict],
) -> None:
    cloud = _fact(sample_payloads, "fact:cloud", 1250)
    commerce = _fact(sample_payloads, "fact:commerce", 800)
    elimination = _fact(sample_payloads, "fact:elimination", -50)
    consolidated = _fact(sample_payloads, "fact:consolidated", 2000)
    period = contract_from_dict("fiscal-period", sample_payloads["fiscal-period"])
    result, passes, tolerance = reconcile_segments(
        (cloud, commerce, elimination),
        consolidated,
        period,
        rounding_increment=1,
        generated_at="2026-02-16T02:00:00Z",
    )
    assert result.value == 0
    assert passes
    assert tolerance == display_precision_tolerance(1, 4) == 2


def test_geography_cannot_be_used_as_reportable_segment(sample_payloads: dict[str, dict]) -> None:
    geography_payload = copy.deepcopy(sample_payloads["segment-definition"])
    geography_payload["segment_type"] = "geographic"
    geography = contract_from_dict("segment-definition", geography_payload)
    snapshot = contract_from_dict("segment-snapshot", sample_payloads["segment-snapshot"])
    graph = ContractGraph(
        documents=(contract_from_dict("source-document", sample_payloads["source-document"]),),
        facts=(contract_from_dict("fact", sample_payloads["fact"]),),
        periods=(contract_from_dict("fiscal-period", sample_payloads["fiscal-period"]),),
        segment_definitions=(geography,),
        segment_snapshots=(snapshot,),
    )
    with pytest.raises(ContractGraphError, match="geography"):
        graph.validate()


def test_note_discovery_covers_present_topics_without_inventing_absent_ones() -> None:
    raw = (ROOT / "evals/golden/sec/complex-filing.html").read_bytes()
    assert discover_note_headings(raw) == (
        "Note 8 — Segment information",
        "Note 2 — Revenue and contract balances",
        "Note 6 — Leases",
    )
    topics = discover_topic_codes(raw)
    assert "revenue_contract_balances" in topics
    assert "leases" in topics
    assert "supplier_finance" not in topics


def test_accounting_rules_only_suggest_and_claim_confirms(sample_payloads: dict[str, dict]) -> None:
    validate_rule_registry()
    sbc = _fact(sample_payloads, "fact:sbc", 125, "sbc_expense")
    revenue = _fact(sample_payloads, "fact:revenue", 1250, "revenue")
    period = contract_from_dict("fiscal-period", sample_payloads["fiscal-period"])
    suggestion = evaluate_ratio_rule(
        "sbc-dilution", sbc, revenue, period, generated_at="2026-02-16T02:00:00Z"
    )
    assert suggestion.severity == "red_flag"
    claim_payload = copy.deepcopy(sample_payloads["claim"])
    claim_payload["supporting_fact_ids"] = [sbc.fact_id, revenue.fact_id]
    claim = contract_from_dict("claim", claim_payload)
    finding = confirm_finding(suggestion, claim=claim, classification="structural")
    assert finding.status == "confirmed"
    assert finding.claim_ids == (claim.claim_id,)


def test_review_requires_every_mandatory_topic(sample_payloads: dict[str, dict]) -> None:
    template = sample_payloads["footnote-review"]
    reviews = []
    for topic in REQUIRED_TOPICS:
        payload = copy.deepcopy(template)
        payload.update(review_id=f"footnote:{topic}", topic_code=topic)
        reviews.append(contract_from_dict("footnote-review", payload))
    review = build_review(
        issuer_id="issuer:acme",
        fiscal_period_id="period:acme:2025-q4",
        reviews=reviews,
        findings=(),
    )
    assert review.status == "complete"
    assert review.coverage["required_count"] == 15
    with pytest.raises(AccountingQualityError, match="coverage mismatch"):
        build_review(
            issuer_id="issuer:acme",
            fiscal_period_id="period:acme:2025-q4",
            reviews=reviews[:-1],
            findings=(),
        )
