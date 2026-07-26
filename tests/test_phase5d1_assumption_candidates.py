from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from test_phase5c0_accounting_bridge_policies import _readiness_case
from test_phase5c1_accounting_reconciliation import KERNEL, _accounting_graph, _artifacts
from test_phase5c4_equity_bridge import _with_diluted_shares

import owner_research
from owner_research.research_bundle_validation import dependency_closure
from owner_research.valuation_assumption_candidates import (
    AssumptionCandidateCompilationError,
    _compile_with_readiness,
    compile_valuation_assumption_candidates,
)
from owner_research.valuation_assumption_types import (
    AssumptionCandidateProposal,
    AssumptionEvidenceRequest,
)
from owner_research.valuation_phase5c_readiness import _compile_phase5c_readiness_result


def _ready_context():
    fields, graph = _readiness_case()
    readiness = _compile_phase5c_readiness_result(
        bridge=fields["equity_bridge_result"],
        graph=graph,
    )
    bundle = graph.research_bundles[0]
    closure = dependency_closure(
        graph,
        tuple(
            object_id
            for reference in bundle.module_references
            for object_id in reference["object_ids"]
        ),
    )
    ledger_ids = {
        item["fact_id"] for item in readiness.equity_bridge_result.ledger_payload["facts"]
    }
    fact_id = next(
        identifier
        for identifier, (kind, _) in sorted(closure.items())
        if kind == "Fact" and identifier in ledger_ids
    )
    business_review_id = next(
        identifier
        for identifier, (kind, _) in sorted(closure.items())
        if kind == "BusinessQualityReview"
    )
    return graph, bundle, readiness, fact_id, business_review_id


def _proposal(fact_id: str, business_review_id: str) -> AssumptionCandidateProposal:
    return AssumptionCandidateProposal(
        assumption_slot_id="mckinsey.base.terminal_ronic",
        value=0.12,
        unit="ratio",
        currency=None,
        horizon={"kind": "terminal", "start_date": None, "end_date": "2035-12-31"},
        scenario="base",
        rationale="A human-reviewable terminal return proposal grounded in mapped history.",
        generation_method="human",
        evidence=(
            AssumptionEvidenceRequest(
                role="support",
                slot_evidence_role="mapped_historical_fact",
                evidence_domain="research_bundle",
                contract_type="Fact",
                object_id=fact_id,
            ),
            AssumptionEvidenceRequest(
                role="support",
                slot_evidence_role="reviewed_business_quality",
                evidence_domain="research_bundle",
                contract_type="BusinessQualityReview",
                object_id=business_review_id,
            ),
        ),
    )


def test_ready_evidence_compiles_one_unreviewed_candidate() -> None:
    graph, bundle, readiness, fact_id, review_id = _ready_context()
    result = _compile_with_readiness(
        graph=graph,
        bundle=bundle,
        readiness=readiness,
        proposals=(_proposal(fact_id, review_id),),
        supplemental_reference_closure=None,
    )

    candidate = result.candidates[0]
    assert candidate.validation_status == "eligible"
    assert candidate.assumption_slot_id == "mckinsey.base.terminal_ronic"
    assert candidate.evidence_graph_sha256 != "0" * 64
    assert not graph.valuation_assumption_review_decisions
    assert "reserved_kernel_assumption_id" not in result.to_dict()


def test_candidate_compilation_is_order_independent_and_immutable() -> None:
    graph, bundle, readiness, fact_id, review_id = _ready_context()
    proposal = _proposal(fact_id, review_id)
    reversed_proposal = replace(proposal, evidence=tuple(reversed(proposal.evidence)))
    first = _compile_with_readiness(
        graph=graph,
        bundle=bundle,
        readiness=readiness,
        proposals=(proposal,),
        supplemental_reference_closure=None,
    )
    second = _compile_with_readiness(
        graph=graph,
        bundle=bundle,
        readiness=readiness,
        proposals=(reversed_proposal,),
        supplemental_reference_closure=None,
    )

    assert first.fingerprint == second.fingerprint
    assert first.to_dict() == second.to_dict()
    with pytest.raises(FrozenInstanceError):
        first.issuer_id = "changed"  # type: ignore[misc]


def test_duplicate_slot_and_unmapped_historical_evidence_fail_closed() -> None:
    graph, bundle, readiness, fact_id, review_id = _ready_context()
    proposal = _proposal(fact_id, review_id)
    with pytest.raises(AssumptionCandidateCompilationError, match="repeats"):
        _compile_with_readiness(
            graph=graph,
            bundle=bundle,
            readiness=readiness,
            proposals=(proposal, proposal),
            supplemental_reference_closure=None,
        )
    unmapped = replace(
        proposal,
        evidence=(
            replace(proposal.evidence[0], object_id="fact:sec-sic-code"),
            proposal.evidence[1],
        ),
    )
    with pytest.raises(AssumptionCandidateCompilationError, match="not mapped"):
        _compile_with_readiness(
            graph=graph,
            bundle=bundle,
            readiness=readiness,
            proposals=(unmapped,),
            supplemental_reference_closure=None,
        )


def test_deterministic_value_must_round_trip_numeric_evidence() -> None:
    graph, bundle, readiness, fact_id, review_id = _ready_context()
    proposal = replace(
        _proposal(fact_id, review_id),
        generation_method="deterministic",
    )
    with pytest.raises(AssumptionCandidateCompilationError, match="round-trip"):
        _compile_with_readiness(
            graph=graph,
            bundle=bundle,
            readiness=readiness,
            proposals=(proposal,),
            supplemental_reference_closure=None,
        )


def test_market_evidence_and_existing_phase5d_objects_are_rejected() -> None:
    graph, bundle, readiness, fact_id, review_id = _ready_context()
    proposal = _proposal(fact_id, review_id)
    market_document = replace(
        graph.documents[0],
        document_id="doc:market:forbidden",
        authority_level="market_reference",
    )
    with pytest.raises(AssumptionCandidateCompilationError, match="market-reference"):
        _compile_with_readiness(
            graph=replace(graph, documents=(*graph.documents, market_document)),
            bundle=bundle,
            readiness=readiness,
            proposals=(proposal,),
            supplemental_reference_closure=None,
        )


def test_production_entry_replays_phase5c_and_rejects_unready_method(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _with_diluted_shares(_accounting_graph(sample_payloads))
    proposal = AssumptionCandidateProposal(
        assumption_slot_id="mckinsey.base.terminal_ronic",
        value=0.12,
        unit="ratio",
        currency=None,
        horizon={"kind": "terminal", "start_date": None, "end_date": "2035-12-31"},
        scenario="base",
        rationale="This method is not ready in the production replay fixture.",
        generation_method="human",
        evidence=(
            AssumptionEvidenceRequest(
                role="support",
                slot_evidence_role="mapped_historical_fact",
                evidence_domain="research_bundle",
                contract_type="Fact",
                object_id="fact:operating-assets",
            ),
        ),
    )
    with pytest.raises(AssumptionCandidateCompilationError, match="not ready"):
        compile_valuation_assumption_candidates(
            bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
            graph=graph,
            kernel_repository=KERNEL,
            proposals=(proposal,),
        )


def test_candidate_compiler_is_internal_and_stops_before_decisions() -> None:
    signature = inspect.signature(compile_valuation_assumption_candidates)
    assert tuple(signature.parameters) == (
        "bundle_artifact_directory",
        "graph",
        "kernel_repository",
        "proposals",
        "supplemental_reference_closure",
    )
    assert all(
        item.kind is inspect.Parameter.KEYWORD_ONLY
        for item in signature.parameters.values()
    )
    assert not hasattr(owner_research, "compile_valuation_assumption_candidates")
    assert not hasattr(owner_research, "compile_assumption_ledger")
    assert not hasattr(owner_research, "write_price_blind_input")
