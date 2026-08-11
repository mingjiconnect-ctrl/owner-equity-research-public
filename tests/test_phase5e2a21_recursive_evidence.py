from __future__ import annotations

import inspect
from dataclasses import replace

import pytest
from phase4a_support import replace_graph
from phase5e2a_support import OPTION_ROOT_ID, valid_snapshot_graph

from owner_research.contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    Claim,
    Fact,
    SourceDocument,
)
from owner_research.fingerprints import canonical_sha256
from owner_research.valuation_current_share_evidence import (
    COMPLETED_SHARE_EVENT_SIGNS,
    CORPORATE_ACTION_COVERAGE_CATEGORIES,
    CurrentShareEvidenceClosure,
    CurrentShareEvidenceError,
    derive_current_share_evidence_closure,
)
from owner_research.valuation_market_reference_types import MarketReferenceValidationContext


def _derive(graph, context, share, evidence_kind):
    share_basis = replace(context.share_basis_decision, evidence_kind=evidence_kind)
    return derive_current_share_evidence_closure(
        graph=graph,
        share_fact=share,
        evidence_kind=evidence_kind,
        trading_date="2026-06-30",
        data_cutoff_date=context.data_cutoff_date,
        security_compilation_result=context.security_compilation_result,
        share_basis_decision=share_basis,
        claim_control_authority=context.claim_control_authority,
    )


def _base(sample_payloads, monkeypatch, tmp_path):
    graph, snapshot, context, _, _ = valid_snapshot_graph(sample_payloads, monkeypatch, tmp_path)
    share_id = snapshot.share_basis["shares_outstanding_fact_id"]
    share = next(item for item in graph.facts if item.fact_id == share_id)
    return graph, context, share


def _replace_share_graph(graph, share, *evidence):
    return replace_graph(
        graph,
        facts=tuple(item for item in graph.facts if item.fact_id != share.fact_id)
        + tuple(evidence),
    )


def _rollforward_graph(
    graph,
    share,
    *,
    opening_value=98_000_000,
    event_concepts=(
        ("common_shares_issued_completed", 3_000_000, "2026-05-01"),
        ("common_shares_repurchased_completed", 1_000_000, "2026-06-01"),
    ),
    omit_zero_category=None,
):
    opening = replace(
        share,
        fact_id="fact:acme:current-common-shares:2026-03-31",
        value=opening_value,
        period={"start": None, "end": "2026-03-31"},
    )
    events = tuple(
        replace(
            share,
            fact_id=f"fact:acme:{concept}:{event_date}",
            concept=concept,
            value=value,
            period={"start": None, "end": event_date},
        )
        for concept, value, event_date in event_concepts
    )
    result = opening_value + sum(
        int(COMPLETED_SHARE_EVENT_SIGNS[event.concept] * event.value) for event in events
    )
    output = replace(
        share,
        value=result,
        parent_fact_ids=(opening.fact_id, *(item.fact_id for item in events)),
        derivation="completed-event-rollforward/1.0.0",
    )
    observed = {
        {
            "common_shares_issued_completed": "issuance",
            "common_shares_repurchased_completed": "repurchase",
            "common_shares_retired_or_cancelled_completed": "retirement_or_cancellation",
            "option_shares_exercised_completed": "option_exercise",
            "rsu_shares_settled_completed": "rsu_settlement",
            "convertible_shares_converted_completed": "convertible_conversion",
            "warrant_shares_exercised_completed": "warrant_exercise",
            "acquisition_consideration_shares_issued_completed": "acquisition_consideration",
        }[item.concept]
        for item in events
    }
    zero_facts = tuple(
        Fact(
            schema_version="2.0.0",
            fact_id=f"fact:acme:share-activity:{category}:2026-06-30",
            issuer_id=share.issuer_id,
            concept=f"share_activity_{category}_count",
            value_type="number",
            value=0,
            unit="count",
            currency=None,
            period={"start": "2026-03-31", "end": "2026-06-30"},
            source_document_id=share.source_document_id,
            source_locator=f"share-activity-coverage:{category}",
            derivation=None,
            parent_fact_ids=(),
            confidence="high",
        )
        for category in CORPORATE_ACTION_COVERAGE_CATEGORIES
        if category not in observed and category != omit_zero_category
    )
    return (
        _replace_share_graph(graph, share, opening, *events, *zero_facts, output),
        output,
        opening,
        events,
        zero_facts,
    )


@pytest.mark.parametrize("root_concept", ("authorized_shares", "potential_conversion_shares"))
def test_issued_less_treasury_rejects_nested_forbidden_roots(
    sample_payloads,
    monkeypatch,
    tmp_path,
    root_concept,
) -> None:
    graph, context, share = _base(sample_payloads, monkeypatch, tmp_path)
    forbidden = replace(
        share,
        fact_id=f"fact:acme:{root_concept}:2026-06-30",
        concept=root_concept,
        value=110_000_000,
    )
    issued_alias = replace(
        share,
        fact_id="fact:acme:common-shares-issued-alias:2026-06-30",
        concept="common_shares_issued",
        value=110_000_000,
        parent_fact_ids=(forbidden.fact_id,),
        derivation="unregistered-alias/1.0.0",
    )
    treasury = replace(
        share,
        fact_id="fact:acme:treasury-shares:2026-06-30",
        concept="treasury_shares",
        value=10_000_000,
    )
    output = replace(
        share,
        parent_fact_ids=(issued_alias.fact_id, treasury.fact_id),
        derivation="issued-less-treasury/1.0.0",
    )
    test_graph = _replace_share_graph(graph, share, forbidden, issued_alias, treasury, output)
    with pytest.raises(CurrentShareEvidenceError, match="numeric root"):
        _derive(test_graph, context, output, "issued_less_treasury")


def test_rollforward_rejects_derived_event_and_invalid_opening(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, context, share = _base(sample_payloads, monkeypatch, tmp_path)
    graph, output, opening, events, zero_facts = _rollforward_graph(graph, share)
    forbidden = replace(
        events[0],
        fact_id="fact:acme:authorized-event-root",
        concept="authorized_shares",
    )
    derived_event = replace(
        events[0],
        parent_fact_ids=(forbidden.fact_id,),
        derivation="unregistered-alias/1.0.0",
    )
    forged_output = replace(
        output,
        parent_fact_ids=(opening.fact_id, derived_event.fact_id, events[1].fact_id),
    )
    test_graph = _replace_share_graph(
        graph,
        share,
        opening,
        forbidden,
        derived_event,
        events[1],
        *zero_facts,
        forged_output,
    )
    with pytest.raises(CurrentShareEvidenceError, match="numeric root"):
        _derive(test_graph, context, forged_output, "completed_event_rollforward")

    invalid_opening = replace(
        opening,
        parent_fact_ids=(forbidden.fact_id,),
        derivation="unregistered-alias/1.0.0",
    )
    forged_output = replace(
        output,
        parent_fact_ids=(invalid_opening.fact_id, *(item.fact_id for item in events)),
    )
    test_graph = _replace_share_graph(
        graph,
        share,
        forbidden,
        invalid_opening,
        *events,
        *zero_facts,
        forged_output,
    )
    with pytest.raises(CurrentShareEvidenceError, match="opening must be direct"):
        _derive(test_graph, context, forged_output, "completed_event_rollforward")


def test_current_share_roots_require_cutoff_safe_high_confidence_sources(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, context, share = _base(sample_payloads, monkeypatch, tmp_path)
    source = next(item for item in graph.documents if item.document_id == share.source_document_id)
    future = replace(source, published_date="2026-07-15")
    with pytest.raises(CurrentShareEvidenceError, match="cutoff-safe"):
        _derive(
            replace_graph(
                graph,
                documents=tuple(
                    future if item.document_id == source.document_id else item
                    for item in graph.documents
                ),
            ),
            context,
            share,
            "direct_point_in_time",
        )
    with pytest.raises(CurrentShareEvidenceError, match="high-confidence"):
        _derive(
            replace_graph(
                graph,
                facts=tuple(
                    replace(item, confidence="low") if item.fact_id == share.fact_id else item
                    for item in graph.facts
                ),
            ),
            context,
            replace(share, confidence="low"),
            "direct_point_in_time",
        )


def test_ultimate_root_source_is_inside_the_computed_closure(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, context, share = _base(sample_payloads, monkeypatch, tmp_path)
    issued = replace(
        share,
        fact_id="fact:acme:common-shares-issued:2026-06-30",
        concept="common_shares_issued",
        value=110_000_000,
    )
    treasury = replace(
        share,
        fact_id="fact:acme:treasury-shares:2026-06-30",
        concept="treasury_shares",
        value=10_000_000,
    )
    output = replace(
        share,
        parent_fact_ids=(issued.fact_id, treasury.fact_id),
        derivation="issued-less-treasury/1.0.0",
    )
    test_graph = _replace_share_graph(graph, share, issued, treasury, output)
    closure = _derive(test_graph, context, output, "issued_less_treasury")
    assert closure.numeric_root_source_document_ids == (share.source_document_id,)
    assert ("Fact", issued.fact_id, issued.fingerprint) in closure.object_fingerprints
    assert any(
        item[0] == "SourceDocument" and item[1] == share.source_document_id
        for item in closure.object_fingerprints
    )


def test_rollforward_requires_receipts_and_every_category_state(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, context, share = _base(sample_payloads, monkeypatch, tmp_path)
    valid_graph, output, _, _, _ = _rollforward_graph(graph, share)
    closure = _derive(valid_graph, context, output, "completed_event_rollforward")
    assert len(closure.coverage_receipt_ids) == 8
    assert closure.event_fact_ids

    with pytest.raises(CurrentShareEvidenceError, match="SourceSearchReceipt"):
        _derive(
            replace_graph(valid_graph, source_search_receipts=()),
            context,
            output,
            "completed_event_rollforward",
        )

    missing_graph, missing_output, _, _, _ = _rollforward_graph(
        graph,
        share,
        omit_zero_category="warrant_exercise",
    )
    with pytest.raises(CurrentShareEvidenceError, match="search silence as zero"):
        _derive(missing_graph, context, missing_output, "completed_event_rollforward")


def test_rollforward_proof_must_be_returned_by_the_completed_search(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, context, share = _base(sample_payloads, monkeypatch, tmp_path)
    valid_graph, output, _, _, zeros = _rollforward_graph(graph, share)
    zero = zeros[0]
    original = next(
        item for item in valid_graph.documents if item.document_id == zero.source_document_id
    )
    unsearched = SourceDocument(
        schema_version=original.schema_version,
        document_id="doc:acme:unsearched-share-activity",
        issuer_id=original.issuer_id,
        document_type=original.document_type,
        period=original.period,
        published_date=original.published_date,
        retrieved_at=original.retrieved_at,
        source_url="https://example.invalid/unsearched-share-activity",
        authority_level=original.authority_level,
        content_sha256="f" * 64,
    )
    unsearched_zero = replace(zero, source_document_id=unsearched.document_id)
    test_graph = replace_graph(
        valid_graph,
        documents=valid_graph.documents + (unsearched,),
        facts=tuple(
            unsearched_zero if item.fact_id == zero.fact_id else item for item in valid_graph.facts
        ),
    )
    with pytest.raises(CurrentShareEvidenceError, match="outside the completed source-search"):
        _derive(test_graph, context, output, "completed_event_rollforward")


def test_repurchased_spelling_is_canonical_and_legacy_typo_is_rejected(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, context, share = _base(sample_payloads, monkeypatch, tmp_path)
    valid_graph, output, _, _, _ = _rollforward_graph(graph, share)
    assert _derive(valid_graph, context, output, "completed_event_rollforward").event_fact_ids
    _, typo_output, opening, events, zeros = _rollforward_graph(graph, share)
    typo = replace(
        events[1],
        fact_id="fact:acme:common_shares_repurched_completed:2026-06-01",
        concept="common_shares_repurched_completed",
    )
    typo_output = replace(
        typo_output,
        parent_fact_ids=(opening.fact_id, events[0].fact_id, typo.fact_id),
    )
    typo_graph = _replace_share_graph(
        graph,
        share,
        opening,
        events[0],
        typo,
        *zeros,
        typo_output,
    )
    with pytest.raises(CurrentShareEvidenceError, match="unregistered completed event"):
        _derive(typo_graph, context, typo_output, "completed_event_rollforward")


def test_other_share_class_cannot_enter_the_common_security_closure(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, context, share = _base(sample_payloads, monkeypatch, tmp_path)
    class_b = replace(share, concept="class_b_common_shares_outstanding")
    with pytest.raises(CurrentShareEvidenceError, match="quote-date"):
        _derive(
            replace_graph(
                graph,
                facts=tuple(
                    class_b if item.fact_id == share.fact_id else item for item in graph.facts
                ),
            ),
            context,
            class_b,
            "direct_point_in_time",
        )


def test_share_basis_decision_must_bind_the_exact_compiled_security(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, context, share = _base(sample_payloads, monkeypatch, tmp_path)
    wrong_security = replace(
        context.share_basis_decision,
        security_id="security:issuer:acme:XNYS:ACME:other-common-class",
    )
    with pytest.raises(CurrentShareEvidenceError, match="exact eligible common security"):
        derive_current_share_evidence_closure(
            graph=graph,
            share_fact=share,
            evidence_kind="direct_point_in_time",
            trading_date="2026-06-30",
            data_cutoff_date=context.data_cutoff_date,
            security_compilation_result=context.security_compilation_result,
            share_basis_decision=wrong_security,
            claim_control_authority=context.claim_control_authority,
        )


def _transition_chain(event, option_root, remaining, security_id):
    statement = f"Completed claim transition for event {event.fact_id} and security {security_id}."
    claim = Claim(
        schema_version="1.0.0",
        claim_id=f"claim:transition:{event.fact_id}",
        issuer_id=event.issuer_id,
        statement=statement,
        as_of_date="2026-06-30",
        supporting_fact_ids=(event.fact_id, option_root.fact_id, remaining.fact_id),
        counterevidence_fact_ids=(),
        counterevidence_search_note="Reviewed all formal claim-transition evidence.",
        confidence="high",
        falsification_condition="A later formal filing shows a different remaining claim.",
    )
    bindings = tuple(
        {
            "binding_id": f"binding:{fact_id}",
            "fact_id": fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
        for fact_id in claim.supporting_fact_ids
    )
    candidate_payload = {
        "schema_version": "2.0.0",
        "candidate_id": f"candidate:transition:{event.fact_id}",
        "issuer_id": event.issuer_id,
        "as_of_date": "2026-06-30",
        "proposed_statement": statement,
        "scope": {
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        "claim_role": "support",
        "business_attribute_role": None,
        "business_component_type": None,
        "supporting_evidence_bindings": bindings,
        "counterevidence_bindings": (),
        "counterevidence_search_note": "Reviewed all formal claim-transition evidence.",
        "proposed_confidence": "high",
        "falsification_condition": claim.falsification_condition,
        "generation_method": "manual",
        "evidence_graph_sha256": canonical_sha256(bindings),
        "validation_status": "ready",
        "validation_issues": (),
    }
    candidate = AnalyticalClaimCandidate(**candidate_payload)
    decision = AnalyticalClaimReviewDecision(
        schema_version="1.0.0",
        decision_id=f"decision:transition:{event.fact_id}",
        issuer_id=event.issuer_id,
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=candidate.fingerprint,
        evidence_graph_sha256=candidate.evidence_graph_sha256,
        decision="confirmed",
        output_claim_id=claim.claim_id,
        reviewer_id="human:reviewer",
        reviewed_at="2026-07-01T00:00:00Z",
        rationale="The completed event and remaining claim are formally reconciled.",
        issues=(),
    )
    return claim, candidate, decision


def test_completed_exercise_cannot_leave_the_old_claim_in_the_bridge(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, context, share = _base(sample_payloads, monkeypatch, tmp_path)
    roll_graph, output, _, events, zeros = _rollforward_graph(
        graph,
        share,
        event_concepts=(("option_shares_exercised_completed", 2_000_000, "2026-05-01"),),
    )
    event = events[0]
    option_root = replace(
        share,
        fact_id=OPTION_ROOT_ID,
        concept="option_or_dilution_claim",
        value=2_000_000,
        period={"start": None, "end": "2026-03-31"},
    )
    remaining = replace(
        share,
        fact_id="fact:acme:option-claim-remaining:2026-06-30",
        concept="option_claim_remaining_outstanding",
        value=0,
    )
    claim, candidate, decision = _transition_chain(
        event,
        option_root,
        remaining,
        context.security_compilation_result.decision.security_id,
    )
    test_graph = replace_graph(
        roll_graph,
        facts=tuple(item for item in roll_graph.facts if item.fact_id != output.fact_id)
        + (option_root, remaining, output),
        claims=roll_graph.claims + (claim,),
        analytical_claim_candidates=roll_graph.analytical_claim_candidates + (candidate,),
        analytical_claim_review_decisions=roll_graph.analytical_claim_review_decisions
        + (decision,),
    )
    with pytest.raises(CurrentShareEvidenceError, match="extinguished claim remains"):
        _derive(test_graph, context, output, "completed_event_rollforward")


def test_completed_claim_transition_must_replay_the_event_magnitude(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    graph, context, share = _base(sample_payloads, monkeypatch, tmp_path)
    roll_graph, output, _, events, _ = _rollforward_graph(
        graph,
        share,
        event_concepts=(("option_shares_exercised_completed", 2_000_000, "2026-05-01"),),
    )
    event = events[0]
    option_root = replace(
        share,
        fact_id="fact:acme:unbound-option-claim:2025",
        concept="option_or_dilution_claim",
        value=3_000_000,
        period={"start": None, "end": "2026-03-31"},
    )
    remaining = replace(
        share,
        fact_id="fact:acme:unbound-option-claim-remaining:2026-06-30",
        concept="option_claim_remaining_outstanding",
        value=0,
    )
    claim, candidate, decision = _transition_chain(
        event,
        option_root,
        remaining,
        context.security_compilation_result.decision.security_id,
    )
    test_graph = replace_graph(
        roll_graph,
        facts=roll_graph.facts + (option_root, remaining),
        claims=roll_graph.claims + (claim,),
        analytical_claim_candidates=roll_graph.analytical_claim_candidates + (candidate,),
        analytical_claim_review_decisions=roll_graph.analytical_claim_review_decisions
        + (decision,),
    )
    with pytest.raises(CurrentShareEvidenceError, match="transition arithmetic"):
        _derive(test_graph, context, output, "completed_event_rollforward")


def test_callers_cannot_submit_final_roots_coverage_or_status() -> None:
    context_parameters = inspect.signature(MarketReferenceValidationContext).parameters
    derive_parameters = inspect.signature(derive_current_share_evidence_closure).parameters
    assert not {
        "current_share_evidence_closure",
        "numeric_root_fact_ids",
        "coverage_ledger",
        "coverage_status",
        "claim_transition_reconciliation",
    }.intersection(context_parameters)
    assert not {
        "numeric_root_fact_ids",
        "coverage_ledger",
        "coverage_status",
        "claim_transition_reconciliation",
    }.intersection(derive_parameters)
    assert CurrentShareEvidenceClosure.__module__.endswith("valuation_current_share_evidence")
