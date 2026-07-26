from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError, replace

import pytest
from test_phase5c1_accounting_reconciliation import KERNEL
from test_phase5d0_assumption_policies import _supplemental_graph
from test_phase5d1_assumption_candidates import _proposal, _ready_context

import owner_research
from owner_research.valuation_assumption_candidates import (
    _compile_with_readiness as compile_candidates,
)
from owner_research.valuation_assumption_ledger import (
    AssumptionLedgerCompilationError,
    _augment_fact_ledger,
    _compile_with_readiness,
    compile_reviewed_assumption_ledger,
)
from owner_research.valuation_assumption_types import (
    AssumptionReviewRequest,
)


def _candidate_context():
    graph, bundle, readiness, fact_id, review_id = _ready_context()
    candidate_result = compile_candidates(
        graph=graph,
        bundle=bundle,
        readiness=readiness,
        proposals=(_proposal(fact_id, review_id),),
        supplemental_reference_closure=None,
    )
    candidate = candidate_result.candidates[0]
    request = AssumptionReviewRequest(
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=candidate.fingerprint,
        evidence_graph_sha256=candidate.evidence_graph_sha256,
        decision="confirmed",
        reviewer_id="human:mingji",
        reviewed_at="2026-07-14T01:30:00Z",
        rationale="The named reviewer confirms the evidence-bound terminal-return proposal.",
    )
    return graph, bundle, readiness, candidate_result, request


def test_named_human_confirmation_compiles_kernel_compatible_assumption_ledger() -> None:
    graph, bundle, readiness, candidates, request = _candidate_context()
    result = _compile_with_readiness(
        graph=graph,
        bundle=bundle,
        readiness=readiness,
        kernel_repository=KERNEL,
        candidate_result=candidates,
        review_requests=(request,),
        supplemental_reference_closure=None,
    )

    decision = result.decisions[0]
    assumption = result.assumption_ledger_payload["assumptions"][0]
    assert decision.decision == "confirmed"
    assert assumption["assumption_id"] == decision.reserved_kernel_assumption_id
    assert assumption["concept"] == "terminal_ronic"
    assert assumption["scope"] == "mckinsey"
    assert assumption["scenario"] == "base"
    assert assumption["unit"] == "decimal"
    assert assumption["source_fact_ids"]
    assert result.assumption_entries_sha256
    with pytest.raises(FrozenInstanceError):
        result.issuer_id = "changed"  # type: ignore[misc]


def test_review_must_bind_exact_candidate_and_named_human() -> None:
    graph, bundle, readiness, candidates, request = _candidate_context()
    with pytest.raises(ValueError, match="named human"):
        replace(request, reviewer_id="llm")
    stale = replace(request, candidate_fingerprint="0" * 64)
    with pytest.raises(AssumptionLedgerCompilationError, match="exact Candidate"):
        _compile_with_readiness(
            graph=graph,
            bundle=bundle,
            readiness=readiness,
            kernel_repository=KERNEL,
            candidate_result=candidates,
            review_requests=(stale,),
            supplemental_reference_closure=None,
        )


def test_blocked_or_rejected_candidate_never_becomes_kernel_assumption() -> None:
    graph, bundle, readiness, candidates, request = _candidate_context()
    blocked = replace(
        request,
        decision="blocked",
        issues=("material evidence remains unresolved",),
    )
    result = _compile_with_readiness(
        graph=graph,
        bundle=bundle,
        readiness=readiness,
        kernel_repository=KERNEL,
        candidate_result=candidates,
        review_requests=(blocked,),
        supplemental_reference_closure=None,
    )
    assert result.decisions[0].reserved_kernel_assumption_id is None
    assert result.assumption_ledger_payload["assumptions"] == ()


def test_duplicate_review_and_candidate_context_drift_fail_closed() -> None:
    graph, bundle, readiness, candidates, request = _candidate_context()
    with pytest.raises(AssumptionLedgerCompilationError, match="only once"):
        _compile_with_readiness(
            graph=graph,
            bundle=bundle,
            readiness=readiness,
            kernel_repository=KERNEL,
            candidate_result=candidates,
            review_requests=(request, request),
            supplemental_reference_closure=None,
        )
    stale = replace(candidates, phase5c_readiness_fingerprint="0" * 64)
    with pytest.raises(AssumptionLedgerCompilationError, match="does not replay"):
        _compile_with_readiness(
            graph=graph,
            bundle=bundle,
            readiness=readiness,
            kernel_repository=KERNEL,
            candidate_result=stale,
            review_requests=(request,),
            supplemental_reference_closure=None,
        )


def test_supplemental_price_blind_facts_are_augmented_as_evidence(sample_payloads) -> None:
    graph, closure = _supplemental_graph(sample_payloads)
    base_ledger = {
        "schema_version": "1.0.0",
        "entity_id": closure.target_issuer_id,
        "valuation_date": closure.data_cutoff_date,
        "reporting_currency": "USD",
        "sources": [],
        "facts": [],
    }
    augmented, mapped = _augment_fact_ledger(
        ledger_payload=base_ledger,
        closure=closure,
        supplemental_fact_ids={item.fact_id for item in closure.facts},
    )
    assert set(mapped) == {item.fact_id for item in closure.facts}
    assert {item["category"] for item in augmented["facts"]} == {"evidence"}
    assert {item["unit"] for item in augmented["facts"]} == {"decimal"}
    assert all(item["source_id"].startswith("supplemental:") for item in augmented["facts"])
    assert not graph.market_reference_snapshots


def test_decision_and_ledger_compilers_remain_internal_and_stop_before_methods() -> None:
    signature = inspect.signature(compile_reviewed_assumption_ledger)
    assert tuple(signature.parameters) == (
        "bundle_artifact_directory",
        "graph",
        "kernel_repository",
        "candidate_result",
        "review_requests",
        "supplemental_reference_closure",
        "prior_decisions",
    )
    assert all(
        item.kind is inspect.Parameter.KEYWORD_ONLY
        for item in signature.parameters.values()
    )
    assert not hasattr(owner_research, "compile_reviewed_assumption_ledger")
    assert not hasattr(owner_research, "compile_mckinsey_scenarios")
    assert not hasattr(owner_research, "compile_penman_inputs")
    assert not hasattr(owner_research, "write_price_blind_input")
