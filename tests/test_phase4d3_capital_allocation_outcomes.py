from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from owner_research.analytical_claims import review_analytical_claim_candidate
from owner_research.capital_allocation_ledger import (
    build_event_candidate,
    compile_event,
    review_event_candidate,
)
from owner_research.capital_allocation_outcomes import (
    CapitalAllocationOutcomeError,
    CapitalOutcomeClaimEvidence,
    CapitalOutcomeEvaluationRequest,
    CapitalOutcomeRoleEvidence,
    evaluate_capital_allocation_outcome,
)
from owner_research.capital_allocation_policies import policy_for
from owner_research.contracts import (
    AnalyticalClaimCandidate,
    Fact,
    SourceDocument,
)
from owner_research.fingerprints import canonical_sha256
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
PERIOD = {"start": "2026-01-01", "end": "2026-06-30"}


def _document(raw: bytes) -> SourceDocument:
    return SourceDocument(
        schema_version="1.0.0",
        document_id="doc:acme:2026-q2",
        issuer_id="issuer:acme",
        document_type="10-Q",
        period=PERIOD,
        published_date="2026-07-01",
        retrieved_at="2026-07-01T20:00:00Z",
        source_url="https://www.sec.gov/Archives/acme-2026-q2.htm",
        authority_level="primary_regulatory",
        content_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _fact(role: str, document: SourceDocument, value: float) -> Fact:
    share_roles = {
        "shares_repurched",
        "sbc_shares_issued",
        "other_equity_shares_issued",
        "basic_shares_change",
        "diluted_shares_change",
    }
    return Fact(
        schema_version="2.0.0",
        fact_id=f"fact:acme:{role}",
        issuer_id="issuer:acme",
        concept=role,
        value_type="number",
        value=value,
        unit="shares" if role in share_roles else "currency_millions",
        currency=None if role in share_roles else "USD",
        period=PERIOD,
        source_document_id=document.document_id,
        source_locator=f"table:{role}",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )


def _reviewed_claim(facts: tuple[Fact, ...]):
    supporting = tuple(
        {
            "binding_id": f"claim-evidence:{fact.fact_id}",
            "fact_id": fact.fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
        for fact in facts
    )
    candidate = AnalyticalClaimCandidate(
        schema_version="2.0.0",
        candidate_id="analytical-candidate:acme:capital-outcome",
        issuer_id="issuer:acme",
        as_of_date="2026-07-01",
        proposed_statement="The official filing supports the disclosed result-role evidence.",
        scope=SCOPE,
        claim_role="support",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=supporting,
        counterevidence_bindings=(),
        counterevidence_search_note="Reviewed the official filing for contrary result evidence.",
        proposed_confidence="high",
        falsification_condition="A restatement or later filing changes a bound result Fact.",
        generation_method="manual",
        evidence_graph_sha256=canonical_sha256(
            {
                "supporting_evidence_bindings": supporting,
                "counterevidence_bindings": (),
            }
        ),
        validation_status="ready",
        validation_issues=(),
    )
    claim, decision = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id="reviewer:phase4d3",
        reviewed_at="2026-07-01T21:00:00Z",
        rationale="Official result roles and counterevidence search confirmed.",
    )
    assert claim is not None
    return claim, candidate, decision


def _setup_buyback():
    raw = b"The company completed its repurchase program and disclosed all share effects."
    document = _document(raw)
    values = {
        "cash_spent": 100,
        "shares_repurched": 10,
        "sbc_shares_issued": 3,
        "other_equity_shares_issued": 1,
        "basic_shares_change": -6,
        "diluted_shares_change": -5,
    }
    facts = tuple(_fact(role, document, value) for role, value in values.items())
    fact_map = {fact.fact_id: fact for fact in facts}
    cash = next(fact for fact in facts if fact.concept == "cash_spent")
    text = " ".join(raw.decode().split())
    candidate = build_event_candidate(
        raw=raw,
        source_document=document,
        start=0,
        end=len(text),
        as_of_date="2026-07-01",
        event_type="buyback",
        event_subtype="open_market",
        scope=SCOPE,
        identity_components=(
            {"role": "program_id", "value": "2026 repurchase program"},
            {"role": "approval_date", "value": "2026-01-01"},
            {"role": "security_class", "value": "common stock"},
        ),
        announcement_date="2026-01-01",
        execution_period=PERIOD,
        growth_classification="not_applicable",
        source_role="completion",
        fact_bindings=(
            {
                "binding_id": "event-fact:cash-spent",
                "role_id": "cash_spent",
                "fact_id": cash.fact_id,
            },
        ),
        facts=(cash,),
    )
    event_decision = review_event_candidate(
        candidate,
        source_document=document,
        decision="confirmed",
        reviewer_id="reviewer:phase4d3",
        reviewed_at="2026-07-01T21:00:00Z",
        rationale="Completion source, event identity, and cash role confirmed.",
    )
    event = compile_event(
        candidates=(candidate,),
        decisions=(event_decision,),
        source_documents=(document,),
        facts=(cash,),
        as_of_date="2026-07-01",
    ).event
    claim, analytical_candidate, analytical_decision = _reviewed_claim(facts)
    return {
        "document": document,
        "facts": facts,
        "fact_map": fact_map,
        "candidate": candidate,
        "event_decision": event_decision,
        "event": event,
        "claim": claim,
        "analytical_candidate": analytical_candidate,
        "analytical_decision": analytical_decision,
    }


def _request(setup, *, missing_role: str | None = None, all_not_disclosed: bool = False):
    claim = setup["claim"]
    evidence = []
    for role in sorted(policy_for("buyback").outcome_roles):
        fact = next(item for item in setup["facts"] if item.concept == role)
        if all_not_disclosed or role == missing_role:
            evidence.append(
                CapitalOutcomeRoleEvidence(
                    role_id=role,
                    coverage_status="not_disclosed",
                    search_source_document_ids=(setup["document"].document_id,),
                    search_note="Reviewed the official completion filing through the cutoff.",
                    missing_evidence=(f"{role}_not_disclosed",),
                )
            )
        else:
            evidence.append(
                CapitalOutcomeRoleEvidence(
                    role_id=role,
                    coverage_status="observed",
                    fact_id=fact.fact_id,
                    claim_ids=(claim.claim_id,),
                )
            )
    claim_evidence = () if all_not_disclosed else (
        CapitalOutcomeClaimEvidence(
            claim_id=claim.claim_id,
            review_decision_id=setup["analytical_decision"].decision_id,
            role_id="result_interpretation",
        ),
    )
    return CapitalOutcomeEvaluationRequest(
        assessed_at="2026-07-01",
        observation_period=PERIOD,
        role_evidence=tuple(evidence),
        claim_evidence=claim_evidence,
    )


def _evaluate(setup, request, **overrides):
    arguments = {
        "event": setup["event"],
        "event_versions": (setup["event"],),
        "facts": setup["facts"],
        "calculations": (),
        "fiscal_periods": (),
        "source_documents": (setup["document"],),
        "claims": (setup["claim"],),
        "analytical_candidates": (setup["analytical_candidate"],),
        "analytical_decisions": (setup["analytical_decision"],),
        "request": request,
    }
    arguments.update(overrides)
    return evaluate_capital_allocation_outcome(**arguments)


def test_evaluator_builds_replayable_observed_outcome_from_complete_reviewed_roles() -> None:
    setup = _setup_buyback()
    evaluation = _evaluate(setup, _request(setup))
    assert evaluation.outcome.status == "observed"
    assert len(evaluation.outcome.result_bindings) == 6
    assert evaluation.outcome.missing_evidence == ()
    ContractGraph(
        documents=(setup["document"],),
        facts=setup["facts"],
        claims=(setup["claim"],),
        analytical_claim_candidates=(setup["analytical_candidate"],),
        analytical_claim_review_decisions=(setup["analytical_decision"],),
        capital_allocation_event_candidates=(setup["candidate"],),
        capital_allocation_event_review_decisions=(setup["event_decision"],),
        capital_allocation_events=(setup["event"],),
        capital_allocation_outcomes=(evaluation.outcome,),
    ).validate()
    replay = _evaluate(
        setup,
        _request(setup),
        existing_outcomes=(evaluation.outcome,),
    )
    assert replay.no_change is True
    assert replay.outcome.fingerprint == evaluation.outcome.fingerprint


def test_evaluator_derives_partial_and_unverifiable_without_failure_labels() -> None:
    setup = _setup_buyback()
    partial = _evaluate(setup, _request(setup, missing_role="diluted_shares_change"))
    assert partial.outcome.status == "partial"
    assert "diluted_shares_change_not_disclosed" in partial.outcome.missing_evidence

    unverifiable = _evaluate(setup, _request(setup, all_not_disclosed=True))
    assert unverifiable.outcome.status == "unverifiable"
    assert unverifiable.outcome.result_bindings == ()
    assert not any(
        token in unverifiable.outcome.to_dict()
        for token in ("failed", "value_created", "score", "valuation")
    )


def test_evaluator_derives_not_due_cancelled_and_superseded_lifecycle_outcomes() -> None:
    setup = _setup_buyback()
    empty_request = CapitalOutcomeEvaluationRequest(
        assessed_at="2026-07-01",
        observation_period=PERIOD,
    )
    announced = replace(
        setup["event"],
        lifecycle_status="announced",
        execution_period={"start": None, "end": None},
    )
    assert _evaluate(setup, empty_request, event=announced).outcome.status == "not_due"

    cancelled = replace(setup["event"], lifecycle_status="cancelled")
    assert _evaluate(setup, empty_request, event=cancelled).outcome.status == "cancelled"

    successor = replace(
        setup["event"],
        event_id=f"{setup['event'].event_id}:v2",
        event_version=2,
        predecessor_event_id=setup["event"].event_id,
    )
    superseded = _evaluate(
        setup,
        empty_request,
        event_versions=(setup["event"], successor),
    )
    assert superseded.outcome.status == "superseded"


def test_evaluator_rejects_unreviewed_claims_and_claims_that_do_not_cover_results() -> None:
    setup = _setup_buyback()
    request = _request(setup)
    with pytest.raises(CapitalAllocationOutcomeError, match="valid human review"):
        _evaluate(
            setup,
            request,
            analytical_decisions=(
                replace(
                    setup["analytical_decision"],
                    decision="blocked",
                    output_claim_id=None,
                    issues=("review_blocked",),
                ),
            ),
        )
    disconnected_claim = replace(
        setup["claim"],
        supporting_fact_ids=(setup["facts"][0].fact_id,),
    )
    with pytest.raises(CapitalAllocationOutcomeError, match="evidence graph is invalid"):
        _evaluate(setup, request, claims=(disconnected_claim,))


def test_evaluator_rejects_future_cross_unit_and_duplicate_result_evidence() -> None:
    setup = _setup_buyback()
    request = _request(setup)
    future_document = replace(setup["document"], published_date="2026-07-02")
    with pytest.raises(CapitalAllocationOutcomeError, match="cutoff-safe|future evidence"):
        _evaluate(setup, request, source_documents=(future_document,))

    wrong_unit_fact = replace(
        setup["facts"][0],
        unit="currency_per_share",
    )
    wrong_facts = (wrong_unit_fact, *setup["facts"][1:])
    with pytest.raises(CapitalAllocationOutcomeError, match="role or unit mismatch"):
        _evaluate(setup, request, facts=wrong_facts)

    roles = list(request.role_evidence)
    duplicate = replace(roles[1], fact_id=roles[0].fact_id)
    roles[1] = duplicate
    with pytest.raises(CapitalAllocationOutcomeError, match="reuses result evidence"):
        _evaluate(setup, replace(request, role_evidence=tuple(roles)))


def test_not_disclosed_requires_completed_official_search_and_blocked_requires_reason() -> None:
    setup = _setup_buyback()
    request = _request(setup, missing_role="diluted_shares_change")
    roles = list(request.role_evidence)
    index = next(
        index for index, item in enumerate(roles) if item.role_id == "diluted_shares_change"
    )
    roles[index] = replace(roles[index], search_note=None)
    with pytest.raises(CapitalAllocationOutcomeError, match="completed official search"):
        _evaluate(setup, replace(request, role_evidence=tuple(roles)))

    roles[index] = CapitalOutcomeRoleEvidence(
        role_id="diluted_shares_change",
        coverage_status="blocked",
    )
    with pytest.raises(CapitalAllocationOutcomeError, match="requires missing evidence"):
        _evaluate(setup, replace(request, role_evidence=tuple(roles)))
