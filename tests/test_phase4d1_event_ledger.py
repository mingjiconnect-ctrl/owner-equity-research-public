from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from owner_research.capital_allocation_ledger import (
    CapitalAllocationLedgerError,
    build_event_candidate,
    compile_event,
    review_event_candidate,
    select_capital_allocation_filings,
    source_family,
)
from owner_research.contracts import Fact, SourceDocument
from owner_research.validation import ContractGraph

SCOPE = {
    "scope_type": "issuer_wide",
    "segment_definition_ids": [],
    "business_unit": None,
    "product_service": None,
    "geography": None,
    "customer_group": None,
    "channel": None,
}
IDENTITY = (
    {"role": "program_id", "value": "2026 repurchase authorization"},
    {"role": "approval_date", "value": "2026-02-15"},
    {"role": "security_class", "value": "common stock"},
)


def _document(
    document_id: str,
    raw: bytes,
    *,
    document_type: str,
    published_date: str,
    authority_level: str = "primary_regulatory",
) -> SourceDocument:
    return SourceDocument(
        schema_version="1.0.0",
        document_id=document_id,
        issuer_id="issuer:acme",
        document_type=document_type,
        period={"start": "2026-01-01", "end": published_date},
        published_date=published_date,
        retrieved_at=f"{published_date}T20:00:00Z",
        source_url=f"https://www.sec.gov/Archives/{document_id}.htm",
        authority_level=authority_level,
        content_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _fact(
    fact_id: str,
    source: SourceDocument,
    *,
    concept: str,
    value: float,
    unit: str,
    currency: str | None,
    period: dict[str, str],
) -> Fact:
    return Fact(
        schema_version="2.0.0",
        fact_id=fact_id,
        issuer_id=source.issuer_id,
        concept=concept,
        value_type="number",
        value=value,
        unit=unit,
        currency=currency,
        period=period,
        source_document_id=source.document_id,
        source_locator="table:repurchases",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )


def _candidate(
    raw: bytes,
    source: SourceDocument,
    *,
    source_role: str,
    execution_period: dict[str, str | None],
    fact_bindings: tuple[dict[str, str], ...] = (),
    facts: tuple[Fact, ...] = (),
    existing_candidates=(),
    extraction_method: str = "deterministic",
):
    text = " ".join(raw.decode().split())
    return build_event_candidate(
        raw=raw,
        source_document=source,
        start=0,
        end=len(text),
        as_of_date=source.published_date,
        event_type="buyback",
        event_subtype="open_market",
        scope=SCOPE,
        identity_components=IDENTITY,
        announcement_date="2026-02-15",
        execution_period=execution_period,
        growth_classification="not_applicable",
        source_role=source_role,
        fact_bindings=fact_bindings,
        extraction_method=extraction_method,
        facts=facts,
        existing_candidates=existing_candidates,
    )


def _decision(candidate, source, *, reviewed_at: str, existing_decisions=()):
    return review_event_candidate(
        candidate,
        source_document=source,
        decision="confirmed",
        reviewer_id="reviewer:phase4d1",
        reviewed_at=reviewed_at,
        rationale="Official source, identity, dates, and evidence roles confirmed.",
        existing_decisions=existing_decisions,
    )


def test_capital_allocation_filing_selection_preserves_lifecycle_history() -> None:
    submissions = {
        "filings": {
            "recent": {
                "accessionNumber": [
                    "0000000001-26-000001",
                    "0000000001-26-000002",
                    "0000000001-26-000003",
                ],
                "form": ["8-K", "S-4", "10-Q"],
                "filingDate": ["2026-02-15", "2026-03-01", "2026-08-01"],
                "reportDate": ["2026-02-15", "2026-03-01", "2026-06-30"],
                "primaryDocument": ["event.htm", "merger.htm", "future.htm"],
            }
        }
    }
    selected = select_capital_allocation_filings(submissions, cik="1", cutoff_date="2026-07-11")
    assert [(item.form, item.accession) for item in selected] == [
        ("8-K", "0000000001-26-000001"),
        ("S-4", "0000000001-26-000002"),
    ]
    with pytest.raises(CapitalAllocationLedgerError, match="unsupported"):
        select_capital_allocation_filings(
            submissions,
            cik="1",
            cutoff_date="2026-07-11",
            forms=frozenset({"13F-HR"}),
        )


def test_source_family_is_formal_and_company_ir_is_explicit() -> None:
    raw = b"official source"
    assert (
        source_family(_document("doc:8k", raw, document_type="8-K", published_date="2026-02-15"))
        == "8-K"
    )
    assert (
        source_family(
            _document(
                "doc:ir",
                raw,
                document_type="earnings-release",
                published_date="2026-02-15",
                authority_level="company_primary",
            )
        )
        == "official_ir"
    )
    with pytest.raises(CapitalAllocationLedgerError, match="source family"):
        source_family(
            _document(
                "doc:unknown",
                raw,
                document_type="blog",
                published_date="2026-02-15",
            )
        )


def test_language_model_stops_at_candidate_and_requires_human_decision() -> None:
    raw = b"The board authorized a common-stock repurchase program."
    source = _document("doc:announcement", raw, document_type="8-K", published_date="2026-02-15")
    candidate = _candidate(
        raw,
        source,
        source_role="authorization",
        execution_period={"start": None, "end": None},
        extraction_method="language_model",
    )
    assert candidate.extraction_method == "language_model"
    with pytest.raises(CapitalAllocationLedgerError, match="confirmed Decision"):
        compile_event(
            candidates=(candidate,),
            decisions=(),
            source_documents=(source,),
            as_of_date="2026-02-15",
        )
    blocked = review_event_candidate(
        candidate,
        source_document=source,
        decision="blocked",
        reviewer_id="reviewer:phase4d1",
        reviewed_at="2026-02-15T21:00:00Z",
        rationale="Identity requires clarification.",
    )
    assert blocked.output_event_id is None


def test_repeated_disclosures_compile_one_versioned_economic_event() -> None:
    announcement_raw = b"The board authorized a common-stock repurchase program."
    execution_raw = b"The company spent 25 million dollars under the repurchase program."
    completion_raw = b"The company completed the repurchase program and acquired 2 million shares."
    announcement_doc = _document(
        "doc:announcement", announcement_raw, document_type="8-K", published_date="2026-02-15"
    )
    execution_doc = _document(
        "doc:execution", execution_raw, document_type="10-Q", published_date="2026-05-01"
    )
    completion_doc = _document(
        "doc:completion", completion_raw, document_type="8-K", published_date="2026-06-30"
    )
    cash_fact = _fact(
        "fact:cash-spent",
        execution_doc,
        concept="repurchase_cash_spent",
        value=25,
        unit="currency_millions",
        currency="USD",
        period={"start": "2026-03-01", "end": "2026-03-31"},
    )
    shares_fact = _fact(
        "fact:shares-repurchased",
        completion_doc,
        concept="shares_repurchased",
        value=2,
        unit="shares",
        currency=None,
        period={"start": "2026-03-01", "end": "2026-06-15"},
    )
    announcement = _candidate(
        announcement_raw,
        announcement_doc,
        source_role="authorization",
        execution_period={"start": None, "end": None},
    )
    announcement_decision = _decision(
        announcement,
        announcement_doc,
        reviewed_at="2026-02-15T21:00:00Z",
    )
    first = compile_event(
        candidates=(announcement,),
        decisions=(announcement_decision,),
        source_documents=(announcement_doc,),
        as_of_date="2026-02-15",
    )
    assert first.event.lifecycle_status == "announced"
    assert first.event.event_version == 1

    execution = _candidate(
        execution_raw,
        execution_doc,
        source_role="execution_update",
        execution_period={"start": "2026-03-01", "end": None},
        fact_bindings=(
            {
                "binding_id": "candidate-binding:cash",
                "role_id": "cash_spent",
                "fact_id": cash_fact.fact_id,
            },
        ),
        facts=(cash_fact,),
        existing_candidates=(announcement,),
    )
    assert execution.potential_duplicate_candidate_ids == (announcement.candidate_id,)
    execution_decision = _decision(
        execution,
        execution_doc,
        reviewed_at="2026-05-01T21:00:00Z",
        existing_decisions=(announcement_decision,),
    )
    second = compile_event(
        candidates=(announcement, execution),
        decisions=(announcement_decision, execution_decision),
        source_documents=(announcement_doc, execution_doc),
        facts=(cash_fact,),
        existing_events=(first.event,),
        as_of_date="2026-05-01",
    )
    assert second.event.lifecycle_status == "in_progress"
    assert second.event.event_version == 2
    assert second.event.predecessor_event_id == first.event.event_id
    assert len(second.event.source_bindings) == 2

    completion = _candidate(
        completion_raw,
        completion_doc,
        source_role="completion",
        execution_period={"start": "2026-03-01", "end": "2026-06-15"},
        fact_bindings=(
            {
                "binding_id": "candidate-binding:shares",
                "role_id": "shares_repurched",
                "fact_id": shares_fact.fact_id,
            },
        ),
        facts=(shares_fact,),
        existing_candidates=(announcement, execution),
    )
    completion_decision = _decision(
        completion,
        completion_doc,
        reviewed_at="2026-06-30T21:00:00Z",
        existing_decisions=(announcement_decision, execution_decision),
    )
    third = compile_event(
        candidates=(announcement, execution, completion),
        decisions=(announcement_decision, execution_decision, completion_decision),
        source_documents=(announcement_doc, execution_doc, completion_doc),
        facts=(cash_fact, shares_fact),
        existing_events=(first.event, second.event),
        as_of_date="2026-06-30",
    )
    assert third.event.lifecycle_status == "completed"
    assert third.event.event_version == 3
    assert len({item.economic_event_key for item in (first.event, second.event, third.event)}) == 1
    ContractGraph(
        documents=(announcement_doc, execution_doc, completion_doc),
        facts=(cash_fact, shares_fact),
        capital_allocation_event_candidates=(announcement, execution, completion),
        capital_allocation_event_review_decisions=(
            announcement_decision,
            execution_decision,
            completion_decision,
        ),
        capital_allocation_events=(first.event, second.event, third.event),
    ).validate()

    repeated = compile_event(
        candidates=(announcement, execution, completion),
        decisions=(announcement_decision, execution_decision, completion_decision),
        source_documents=(announcement_doc, execution_doc, completion_doc),
        facts=(cash_fact, shares_fact),
        existing_events=(first.event, second.event, third.event),
        as_of_date="2026-06-30",
    )
    assert repeated.no_change is True
    assert repeated.event.event_id == third.event.event_id


def test_compiler_rejects_stale_decisions_omitted_history_and_future_evidence() -> None:
    raw = b"The board authorized a common-stock repurchase program."
    source = _document("doc:announcement", raw, document_type="8-K", published_date="2026-02-15")
    candidate = _candidate(
        raw,
        source,
        source_role="authorization",
        execution_period={"start": None, "end": None},
    )
    decision = _decision(candidate, source, reviewed_at="2026-02-15T21:00:00Z")
    blocked_candidate = replace(
        candidate,
        validation_status="blocked",
        validation_issues=("identity_conflict",),
    )
    forged_blocked_decision = replace(
        decision,
        candidate_fingerprint=blocked_candidate.fingerprint,
    )
    with pytest.raises(CapitalAllocationLedgerError, match="blocked Candidate"):
        compile_event(
            candidates=(blocked_candidate,),
            decisions=(forged_blocked_decision,),
            source_documents=(source,),
            as_of_date="2026-02-15",
        )
    with pytest.raises(CapitalAllocationLedgerError, match="fingerprint is stale"):
        compile_event(
            candidates=(replace(candidate, proposed_growth_classification="unknown"),),
            decisions=(decision,),
            source_documents=(source,),
            as_of_date="2026-02-15",
        )
    first = compile_event(
        candidates=(candidate,),
        decisions=(decision,),
        source_documents=(source,),
        as_of_date="2026-02-15",
    )
    unrelated_raw = b"The company reiterated its repurchase authorization."
    unrelated_doc = _document(
        "doc:recap", unrelated_raw, document_type="10-Q", published_date="2026-05-01"
    )
    recap = _candidate(
        unrelated_raw,
        unrelated_doc,
        source_role="periodic_recap",
        execution_period={"start": None, "end": None},
        existing_candidates=(candidate,),
    )
    recap_decision = _decision(recap, unrelated_doc, reviewed_at="2026-05-01T21:00:00Z")
    with pytest.raises(CapitalAllocationLedgerError, match="omits predecessor"):
        compile_event(
            candidates=(recap,),
            decisions=(recap_decision,),
            source_documents=(unrelated_doc,),
            existing_events=(first.event,),
            as_of_date="2026-05-01",
        )
    with pytest.raises(CapitalAllocationLedgerError, match="follows compilation cutoff"):
        compile_event(
            candidates=(candidate, recap),
            decisions=(decision, recap_decision),
            source_documents=(source, unrelated_doc),
            existing_events=(first.event,),
            as_of_date="2026-04-30",
        )


def test_cancellation_is_a_lifecycle_event_not_an_operating_outcome() -> None:
    announcement_raw = b"The board authorized a common-stock repurchase program."
    cancellation_raw = b"The board cancelled the repurchase program before execution."
    announcement_doc = _document(
        "doc:announcement",
        announcement_raw,
        document_type="8-K",
        published_date="2026-02-15",
    )
    cancellation_doc = _document(
        "doc:cancellation",
        cancellation_raw,
        document_type="8-K",
        published_date="2026-03-15",
    )
    announcement = _candidate(
        announcement_raw,
        announcement_doc,
        source_role="authorization",
        execution_period={"start": None, "end": None},
    )
    cancellation = _candidate(
        cancellation_raw,
        cancellation_doc,
        source_role="cancellation",
        execution_period={"start": None, "end": None},
        existing_candidates=(announcement,),
    )
    announcement_decision = _decision(
        announcement,
        announcement_doc,
        reviewed_at="2026-02-15T21:00:00Z",
    )
    cancellation_decision = _decision(
        cancellation,
        cancellation_doc,
        reviewed_at="2026-03-15T21:00:00Z",
        existing_decisions=(announcement_decision,),
    )
    compiled = compile_event(
        candidates=(announcement, cancellation),
        decisions=(announcement_decision, cancellation_decision),
        source_documents=(announcement_doc, cancellation_doc),
        as_of_date="2026-03-15",
    )
    assert compiled.event.lifecycle_status == "cancelled"
    assert compiled.event.fact_bindings == ()


def test_explicit_supersession_can_correct_reviewed_evidence_without_silent_deletion() -> None:
    original_raw = b"The board announced a common-stock repurchase program."
    corrected_raw = b"The issuer corrected the terms of the common-stock repurchase program."
    original_doc = _document(
        "doc:original",
        original_raw,
        document_type="8-K",
        published_date="2026-02-15",
    )
    corrected_doc = _document(
        "doc:corrected",
        corrected_raw,
        document_type="8-K/A",
        published_date="2026-02-16",
    )
    original = _candidate(
        original_raw,
        original_doc,
        source_role="announcement",
        execution_period={"start": None, "end": None},
    )
    original_decision = _decision(
        original,
        original_doc,
        reviewed_at="2026-02-15T21:00:00Z",
    )
    first = compile_event(
        candidates=(original,),
        decisions=(original_decision,),
        source_documents=(original_doc,),
        as_of_date="2026-02-15",
    )
    corrected = build_event_candidate(
        raw=corrected_raw,
        source_document=corrected_doc,
        start=0,
        end=len(" ".join(corrected_raw.decode().split())),
        as_of_date="2026-02-16",
        event_type="buyback",
        event_subtype="open_market",
        scope=SCOPE,
        identity_components=IDENTITY,
        announcement_date="2026-02-15",
        execution_period={"start": None, "end": None},
        growth_classification="not_applicable",
        source_role="announcement",
        supersedes_candidate_ids=(original.candidate_id,),
        existing_candidates=(original,),
    )
    corrected_decision = _decision(
        corrected,
        corrected_doc,
        reviewed_at="2026-02-16T21:00:00Z",
        existing_decisions=(original_decision,),
    )
    assert corrected_decision.supersedes_decision_ids == (original_decision.decision_id,)
    second = compile_event(
        candidates=(original, corrected),
        decisions=(original_decision, corrected_decision),
        source_documents=(original_doc, corrected_doc),
        existing_events=(first.event,),
        as_of_date="2026-02-16",
    )
    assert second.event.event_version == 2
    assert second.event.predecessor_event_id == first.event.event_id
    assert {item["decision_id"] for item in second.event.source_bindings} == {
        corrected_decision.decision_id
    }


def test_compiler_rejects_same_key_with_conflicting_reviewed_scope() -> None:
    raw_one = b"The board authorized a common-stock repurchase program."
    raw_two = b"The company repeated the common-stock repurchase announcement."
    doc_one = _document("doc:one", raw_one, document_type="8-K", published_date="2026-02-15")
    doc_two = _document("doc:two", raw_two, document_type="10-Q", published_date="2026-05-01")
    first = _candidate(
        raw_one,
        doc_one,
        source_role="authorization",
        execution_period={"start": None, "end": None},
    )
    second = build_event_candidate(
        raw=raw_two,
        source_document=doc_two,
        start=0,
        end=len(" ".join(raw_two.decode().split())),
        as_of_date="2026-05-01",
        event_type="buyback",
        event_subtype="open_market",
        scope={**SCOPE, "scope_type": "product_market", "product_service": "Cloud"},
        identity_components=IDENTITY,
        announcement_date="2026-02-15",
        execution_period={"start": None, "end": None},
        growth_classification="not_applicable",
        source_role="periodic_recap",
        existing_candidates=(first,),
    )
    first_decision = _decision(first, doc_one, reviewed_at="2026-02-15T21:00:00Z")
    second_decision = _decision(second, doc_two, reviewed_at="2026-05-01T21:00:00Z")
    with pytest.raises(CapitalAllocationLedgerError, match="conflicting reviewed semantics"):
        compile_event(
            candidates=(first, second),
            decisions=(first_decision, second_decision),
            source_documents=(doc_one, doc_two),
            as_of_date="2026-05-01",
        )
