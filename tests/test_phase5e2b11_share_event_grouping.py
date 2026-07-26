from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from phase4a_support import replace_graph
from phase5e2b_support import current_share_compile_context

import owner_research
from owner_research.capital_allocation_ledger import (
    build_event_candidate,
    compile_event,
    review_event_candidate,
)
from owner_research.contracts import Fact, SourceDocument
from owner_research.validation import ContractGraph
from owner_research.valuation_share_event_grouping import (
    ShareEventGroupingError,
    group_governed_completed_share_events,
)

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
    {"role": "program_id", "value": "repurchase-program-2026"},
    {"role": "approval_date", "value": "2026-01-15"},
    {"role": "security_class", "value": "common"},
)
EVENT_DATE = "2026-06-15"


def _source(
    suffix: str,
    *,
    document_type: str,
    authority_level: str = "primary_regulatory",
) -> tuple[SourceDocument, bytes]:
    raw = f"Official completion disclosure {suffix}".encode()
    source = SourceDocument(
        schema_version="1.0.0",
        document_id=f"doc:acme:share-event:{suffix}",
        issuer_id="issuer:acme",
        document_type=document_type,
        period={"start": "2026-01-01", "end": EVENT_DATE},
        published_date="2026-06-20",
        retrieved_at="2026-06-20T20:00:00Z",
        source_url=(
            f"https://www.sec.gov/Archives/{suffix}.htm"
            if authority_level == "primary_regulatory"
            else f"https://investor.acme.example/{suffix}"
        ),
        authority_level=authority_level,
        content_sha256=hashlib.sha256(raw).hexdigest(),
    )
    return source, raw


def _fact(source: SourceDocument, suffix: str, *, value: int = 5_000_000) -> Fact:
    return Fact(
        schema_version="2.0.0",
        fact_id=f"fact:acme:share-event:{suffix}",
        issuer_id="issuer:acme",
        concept="common_shares_repurchased_completed",
        value_type="number",
        value=value,
        unit="shares",
        currency=None,
        period={"start": None, "end": EVENT_DATE},
        source_document_id=source.document_id,
        source_locator=f"share-event:{suffix}:completion",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )


def _event_chain(
    disclosures: tuple[tuple[str, str, str], ...],
    *,
    values: tuple[int, ...] | None = None,
    identity=IDENTITY,
    execution_period: dict[str, str] | None = None,
):
    sources: list[SourceDocument] = []
    facts: list[Fact] = []
    candidates = []
    decisions = []
    for index, (suffix, document_type, authority_level) in enumerate(disclosures):
        source, raw = _source(
            suffix,
            document_type=document_type,
            authority_level=authority_level,
        )
        fact = _fact(source, suffix, value=(values or (5_000_000,) * len(disclosures))[index])
        candidate = build_event_candidate(
            raw=raw,
            source_document=source,
            start=0,
            end=len(raw.decode()),
            as_of_date=source.published_date,
            event_type="buyback",
            event_subtype="open_market",
            scope=SCOPE,
            identity_components=identity,
            announcement_date="2026-01-15",
            execution_period=execution_period or {"start": EVENT_DATE, "end": EVENT_DATE},
            growth_classification="not_applicable",
            source_role="completion",
            fact_bindings=(
                {
                    "binding_id": f"capital-binding:{suffix}",
                    "fact_id": fact.fact_id,
                    "role_id": "shares_repurched",
                },
            ),
            extraction_method="deterministic",
            facts=(fact,),
            existing_candidates=tuple(candidates),
        )
        decision = review_event_candidate(
            candidate,
            source_document=source,
            decision="confirmed",
            reviewer_id=f"human:{suffix}",
            reviewed_at="2026-06-20T21:00:00Z",
            rationale="Named human confirmed the legal event, execution date, and share role.",
            existing_decisions=tuple(decisions),
        )
        sources.append(source)
        facts.append(fact)
        candidates.append(candidate)
        decisions.append(decision)
    compilation = compile_event(
        candidates=tuple(candidates),
        decisions=tuple(decisions),
        source_documents=tuple(sources),
        facts=tuple(facts),
        as_of_date="2026-06-30",
    )
    assert compilation.event.lifecycle_status == "completed"
    return tuple(sources), tuple(facts), tuple(candidates), tuple(decisions), compilation.event


def _minimal_graph(base_graph, security, *chains) -> ContractGraph:
    assert security.evidence_closure is not None
    closure = security.evidence_closure
    sources = tuple(item for chain in chains for item in chain[0])
    facts = tuple(item for chain in chains for item in chain[1])
    candidates = tuple(item for chain in chains for item in chain[2])
    decisions = tuple(item for chain in chains for item in chain[3])
    events = tuple(chain[4] for chain in chains)
    return ContractGraph(
        documents=tuple(
            item for item in base_graph.documents if item.document_id in closure.source_document_ids
        )
        + sources,
        facts=tuple(item for item in base_graph.facts if item.fact_id in closure.fact_ids) + facts,
        claims=tuple(item for item in base_graph.claims if item.claim_id == closure.claim_id),
        analytical_claim_candidates=tuple(
            item
            for item in base_graph.analytical_claim_candidates
            if item.candidate_id == closure.candidate_id
        ),
        analytical_claim_review_decisions=tuple(
            item
            for item in base_graph.analytical_claim_review_decisions
            if item.decision_id == closure.review_decision_id
        ),
        capital_allocation_event_candidates=candidates,
        capital_allocation_event_review_decisions=decisions,
        capital_allocation_events=events,
        component_lock_path=base_graph.component_lock_path,
    )


def _grouping_context(sample_payloads, monkeypatch, tmp_path, disclosures, **chain_kwargs):
    base_graph, _, _, security, access, _ = current_share_compile_context(
        sample_payloads, monkeypatch, tmp_path
    )
    assert access.receipt is not None
    chain = _event_chain(disclosures, **chain_kwargs)
    graph = _minimal_graph(base_graph, security, chain)
    result = group_governed_completed_share_events(
        graph=graph,
        issuer_id="issuer:acme",
        security_compilation_result=security,
        opening_date="2026-03-31",
        quote_date=access.receipt.receipt.trading_date,
        data_cutoff_date=security.proposal.data_cutoff_date,
    )
    return graph, security, access, result


@pytest.mark.parametrize(
    "disclosures",
    (
        (("8k", "8-K", "primary_regulatory"), ("10q", "10-Q", "primary_regulatory")),
        (
            ("8k", "8-K", "primary_regulatory"),
            ("10q", "10-Q", "primary_regulatory"),
            ("ir", "earnings-release", "company_primary"),
        ),
    ),
)
def test_cross_source_disclosures_form_one_canonical_event_group(
    sample_payloads, monkeypatch, tmp_path, disclosures
) -> None:
    graph, _, _, result = _grouping_context(
        sample_payloads, monkeypatch, tmp_path, disclosures
    )
    assert result.status == "grouped"
    assert len(result.groups) == 1
    assert len(result.members) == len(disclosures)
    assert result.groups[0].identity.canonical_share_magnitude == "5000000"
    assert result.groups[0].canonical_event_fact_id is not None
    assert result.groups[0].canonical_event_fact_id not in {
        item.fact_id for item in graph.facts
    }


def test_corroborating_source_changes_evidence_not_canonical_value(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    _, _, _, first = _grouping_context(
        sample_payloads,
        monkeypatch,
        tmp_path / "two",
        (("8k", "8-K", "primary_regulatory"), ("10q", "10-Q", "primary_regulatory")),
    )
    _, _, _, second = _grouping_context(
        sample_payloads,
        monkeypatch,
        tmp_path / "three",
        (
            ("8k", "8-K", "primary_regulatory"),
            ("10q", "10-Q", "primary_regulatory"),
            ("ir", "earnings-release", "company_primary"),
        ),
    )
    assert (
        first.groups[0].identity.canonical_share_magnitude
        == second.groups[0].identity.canonical_share_magnitude
    )
    assert first.groups[0].canonical_event_fact_id == second.groups[0].canonical_event_fact_id
    assert first.groups[0].fingerprint != second.groups[0].fingerprint
    assert first.fingerprint != second.fingerprint


def test_input_order_does_not_change_grouping(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, security, access, expected = _grouping_context(
        sample_payloads,
        monkeypatch,
        tmp_path,
        (("8k", "8-K", "primary_regulatory"), ("10q", "10-Q", "primary_regulatory")),
    )
    assert access.receipt is not None
    replay = group_governed_completed_share_events(
        graph=replace_graph(
            graph,
            documents=tuple(reversed(graph.documents)),
            facts=tuple(reversed(graph.facts)),
            capital_allocation_event_candidates=tuple(
                reversed(graph.capital_allocation_event_candidates)
            ),
            capital_allocation_event_review_decisions=tuple(
                reversed(graph.capital_allocation_event_review_decisions)
            ),
            capital_allocation_events=tuple(reversed(graph.capital_allocation_events)),
        ),
        issuer_id="issuer:acme",
        security_compilation_result=security,
        opening_date="2026-03-31",
        quote_date=access.receipt.receipt.trading_date,
        data_cutoff_date=security.proposal.data_cutoff_date,
    )
    assert replay.to_dict() == expected.to_dict()


def test_same_legal_occurrence_magnitude_conflict_fails_closed(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    with pytest.raises(ShareEventGroupingError) as raised:
        _grouping_context(
            sample_payloads,
            monkeypatch,
            tmp_path,
            (("8k", "8-K", "primary_regulatory"), ("10q", "10-Q", "primary_regulatory")),
            values=(5_000_000, 6_000_000),
        )
    assert raised.value.issue_code == "blocked_share_event_conflict"


def test_same_source_unpartitioned_duplicate_is_ambiguous(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, security, access, _ = _grouping_context(
        sample_payloads,
        monkeypatch,
        tmp_path,
        (("8k", "8-K", "primary_regulatory"), ("10q", "10-Q", "primary_regulatory")),
    )
    event_facts = tuple(
        item for item in graph.facts if item.concept == "common_shares_repurchased_completed"
    )
    duplicate = replace(
        event_facts[0],
        fact_id="fact:acme:share-event:8k-duplicate",
        source_locator="share-event:8k:second-unpartitioned-occurrence",
    )
    candidate = next(
        item
        for item in graph.capital_allocation_event_candidates
        if item.source_document_id == duplicate.source_document_id
    )
    new_binding = {
        "binding_id": "capital-binding:8k-duplicate",
        "fact_id": duplicate.fact_id,
        "role_id": "shares_repurched",
    }
    changed_candidate = replace(
        candidate,
        proposed_fact_bindings=candidate.proposed_fact_bindings + (new_binding,),
    )
    decision = next(
        item
        for item in graph.capital_allocation_event_review_decisions
        if item.candidate_id == candidate.candidate_id
    )
    changed_decision = replace(decision, candidate_fingerprint=changed_candidate.fingerprint)
    event = next(
        item
        for item in graph.capital_allocation_events
        if item.economic_event_key == decision.output_economic_event_key
    )
    event_binding = {
        "binding_id": new_binding["binding_id"],
        "candidate_id": candidate.candidate_id,
        "decision_id": decision.decision_id,
        "fact_id": duplicate.fact_id,
        "role_id": "shares_repurched",
    }
    changed_event = replace(event, fact_bindings=event.fact_bindings + (event_binding,))
    changed_graph = replace_graph(
        graph,
        facts=graph.facts + (duplicate,),
        capital_allocation_event_candidates=tuple(
            changed_candidate if item.candidate_id == candidate.candidate_id else item
            for item in graph.capital_allocation_event_candidates
        ),
        capital_allocation_event_review_decisions=tuple(
            changed_decision if item.decision_id == decision.decision_id else item
            for item in graph.capital_allocation_event_review_decisions
        ),
        capital_allocation_events=tuple(
            changed_event if item.event_id == event.event_id else item
            for item in graph.capital_allocation_events
        ),
    )
    assert access.receipt is not None
    result = group_governed_completed_share_events(
        graph=changed_graph,
        issuer_id="issuer:acme",
        security_compilation_result=security,
        opening_date="2026-03-31",
        quote_date=access.receipt.receipt.trading_date,
        data_cutoff_date=security.proposal.data_cutoff_date,
    )
    assert result.status == "blocked"
    assert result.conflicts[0].conflict_code == "blocked_share_event_identity_ambiguous"


def test_distinct_reviewed_legal_ids_remain_two_events(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    base_graph, _, _, security, access, _ = current_share_compile_context(
        sample_payloads, monkeypatch, tmp_path
    )
    first = _event_chain(
        (("program-a", "8-K", "primary_regulatory"),),
        identity=(
            {"role": "program_id", "value": "program-a"},
            {"role": "approval_date", "value": "2026-01-15"},
            {"role": "security_class", "value": "common"},
        ),
    )
    second = _event_chain(
        (("program-b", "10-Q", "primary_regulatory"),),
        identity=(
            {"role": "program_id", "value": "program-b"},
            {"role": "approval_date", "value": "2026-01-16"},
            {"role": "security_class", "value": "common"},
        ),
    )
    graph = _minimal_graph(base_graph, security, first, second)
    assert access.receipt is not None
    result = group_governed_completed_share_events(
        graph=graph,
        issuer_id="issuer:acme",
        security_compilation_result=security,
        opening_date="2026-03-31",
        quote_date=access.receipt.receipt.trading_date,
        data_cutoff_date=security.proposal.data_cutoff_date,
    )
    assert result.status == "grouped"
    assert len(result.groups) == 2
    assert len({item.identity.legal_event_key for item in result.groups}) == 2


def test_period_wide_cumulative_execution_fails_closed(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    with pytest.raises(ShareEventGroupingError) as raised:
        _grouping_context(
            sample_payloads,
            monkeypatch,
            tmp_path,
            (("10q", "10-Q", "primary_regulatory"),),
            execution_period={"start": "2026-04-01", "end": EVENT_DATE},
        )
    assert raised.value.issue_code == "blocked_share_event_cumulative_amount"


def test_fact_and_reviewed_legal_effective_date_conflict_fails_closed(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, security, access, _ = _grouping_context(
        sample_payloads,
        monkeypatch,
        tmp_path,
        (("8k", "8-K", "primary_regulatory"),),
    )
    fact = next(
        item for item in graph.facts if item.concept == "common_shares_repurchased_completed"
    )
    changed_fact = replace(fact, period={"start": None, "end": "2026-06-16"})
    changed = replace_graph(
        graph,
        facts=tuple(changed_fact if item.fact_id == fact.fact_id else item for item in graph.facts),
    )
    assert access.receipt is not None
    with pytest.raises(ShareEventGroupingError) as raised:
        group_governed_completed_share_events(
            graph=changed,
            issuer_id="issuer:acme",
            security_compilation_result=security,
            opening_date="2026-03-31",
            quote_date=access.receipt.receipt.trading_date,
            data_cutoff_date=security.proposal.data_cutoff_date,
        )
    assert raised.value.issue_code == "blocked_share_event_conflict"


def test_unreviewed_or_cross_security_identity_fails_closed(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, security, access, _ = _grouping_context(
        sample_payloads,
        monkeypatch,
        tmp_path,
        (("8k", "8-K", "primary_regulatory"),),
    )
    decision = graph.capital_allocation_event_review_decisions[0]
    unreviewed_graph = replace_graph(
        graph,
        capital_allocation_event_review_decisions=(
            replace(decision, reviewer_id="llm:reviewer"),
        ),
    )
    assert access.receipt is not None
    with pytest.raises(ShareEventGroupingError) as unreviewed:
        group_governed_completed_share_events(
            graph=unreviewed_graph,
            issuer_id="issuer:acme",
            security_compilation_result=security,
            opening_date="2026-03-31",
            quote_date=access.receipt.receipt.trading_date,
            data_cutoff_date=security.proposal.data_cutoff_date,
        )
    assert unreviewed.value.issue_code == "blocked_share_event_identity_ambiguous"

    with pytest.raises(ShareEventGroupingError) as cross_security:
        _grouping_context(
            sample_payloads,
            monkeypatch,
            tmp_path / "preferred",
            (("preferred", "8-K", "primary_regulatory"),),
            identity=(
                {"role": "program_id", "value": "preferred-program"},
                {"role": "approval_date", "value": "2026-01-15"},
                {"role": "security_class", "value": "preferred"},
            ),
        )
    assert cross_security.value.issue_code == "blocked_share_event_identity_ambiguous"


def test_ineligible_event_evidence_never_becomes_a_group_member(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    graph, security, access, expected = _grouping_context(
        sample_payloads,
        monkeypatch,
        tmp_path,
        (("8k", "8-K", "primary_regulatory"),),
    )
    event_fact = next(
        item for item in graph.facts if item.concept == "common_shares_repurchased_completed"
    )
    low_confidence = replace(event_fact, confidence="low")
    changed = replace_graph(
        graph,
        facts=tuple(
            low_confidence if item.fact_id == event_fact.fact_id else item
            for item in graph.facts
        ),
    )
    assert access.receipt is not None
    result = group_governed_completed_share_events(
        graph=changed,
        issuer_id="issuer:acme",
        security_compilation_result=security,
        opening_date="2026-03-31",
        quote_date=access.receipt.receipt.trading_date,
        data_cutoff_date=security.proposal.data_cutoff_date,
    )
    assert expected.members
    assert result.members == ()
    assert result.groups == ()


def test_grouping_surface_remains_internal_and_does_not_create_downstream_artifacts() -> None:
    assert "group_governed_completed_share_events" not in owner_research.__all__
    assert not hasattr(owner_research, "group_governed_completed_share_events")
