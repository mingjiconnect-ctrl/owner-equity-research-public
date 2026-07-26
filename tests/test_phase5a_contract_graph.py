from __future__ import annotations

import copy
from dataclasses import replace

import pytest
from phase4a_support import replace_graph
from test_phase4e0_research_bundle import _bundle_graph

from owner_research.contracts import contract_from_dict
from owner_research.research_bundle_validation import dependency_closure
from owner_research.validation import ContractGraph, ContractGraphError
from owner_research.valuation_handoff_validation import candidate_evidence_graph_sha256


def _candidate_and_decision(graph: ContractGraph, sample_payloads: dict[str, dict]):
    bundle = graph.research_bundles[0]
    closure = dependency_closure(
        graph,
        tuple(object_id for item in bundle.module_references for object_id in item["object_ids"]),
    )
    fact_id = next(
        object_id for object_id, (contract_type, _) in closure.items() if contract_type == "Fact"
    )
    candidate_payload = copy.deepcopy(sample_payloads["valuation-assumption-candidate"])
    candidate_payload.update(
        {
            "data_cutoff_date": bundle.data_cutoff_date,
            "research_bundle_id": bundle.bundle_id,
            "research_bundle_fingerprint": bundle.bundle_fingerprint,
            "research_bundle_dependency_sha256": bundle.dependency_closure_sha256,
            "horizon": {
                "kind": "period",
                "start_date": "2026-07-01",
                "end_date": "2027-06-30",
            },
            "evidence_bindings": [
                {
                    "binding_id": "valuation-evidence:acme:base-revenue",
                    "role": "support",
                    "slot_evidence_role": "mapped_historical_fact",
                    "evidence_domain": "research_bundle",
                    "contract_type": "Fact",
                    "object_id": fact_id,
                }
            ],
            "evidence_graph_sha256": "0" * 64,
        }
    )
    candidate = contract_from_dict("valuation-assumption-candidate", candidate_payload)
    candidate = replace(
        candidate,
        evidence_graph_sha256=candidate_evidence_graph_sha256(graph, candidate),
    )
    decision_payload = copy.deepcopy(sample_payloads["valuation-assumption-review-decision"])
    decision_payload.update(
        {
            "candidate_id": candidate.candidate_id,
            "candidate_fingerprint": candidate.fingerprint,
            "evidence_graph_sha256": candidate.evidence_graph_sha256,
        }
    )
    decision = contract_from_dict("valuation-assumption-review-decision", decision_payload)
    return candidate, decision


def _handoff_chain(graph, candidate, decision, sample_payloads):
    bundle = graph.research_bundles[0]
    root_payload = copy.deepcopy(sample_payloads["valuation-handoff"])
    root_payload.update(
        {
            "data_cutoff_date": bundle.data_cutoff_date,
            "research_bundle_id": bundle.bundle_id,
            "research_bundle_fingerprint": bundle.bundle_fingerprint,
            "research_bundle_dependency_sha256": bundle.dependency_closure_sha256,
            "research_run_manifest_id": bundle.run_id,
            "component_lock_sha256": bundle.component_lock_sha256,
        }
    )
    root = contract_from_dict("valuation-handoff", root_payload)
    reviewed = replace(
        root,
        handoff_id="valuation-handoff:acme:run-1:v2",
        handoff_version=2,
        transitioned_at="2026-02-16T03:06:00Z",
        state="price_blind_candidates_reviewed",
        predecessor_handoff_id=root.handoff_id,
        assumption_candidate_ids=(candidate.candidate_id,),
        assumption_review_decision_ids=(decision.decision_id,),
        missing_evidence=("Price-blind input has not been frozen",),
    )
    frozen = replace(
        reviewed,
        handoff_id="valuation-handoff:acme:run-1:v3",
        handoff_version=3,
        transitioned_at="2026-02-16T03:07:00Z",
        state="price_blind_input_frozen",
        predecessor_handoff_id=reviewed.handoff_id,
        price_blind_input_fingerprint="2" * 64,
        protected_mckinsey_sha256="3" * 64,
        protected_penman_assumptions_sha256="4" * 64,
        missing_evidence=(),
    )
    allowed = replace(
        frozen,
        handoff_id="valuation-handoff:acme:run-1:v4",
        handoff_version=4,
        transitioned_at="2026-02-16T03:08:00Z",
        state="market_reference_allowed",
        predecessor_handoff_id=frozen.handoff_id,
    )
    return root, reviewed, frozen, allowed


def _valid_graph(sample_payloads):
    graph, _ = _bundle_graph(sample_payloads)
    candidate, decision = _candidate_and_decision(graph, sample_payloads)
    chain = _handoff_chain(graph, candidate, decision, sample_payloads)
    return replace_graph(
        graph,
        valuation_assumption_candidates=(candidate,),
        valuation_assumption_review_decisions=(decision,),
        valuation_handoffs=chain,
    )


def _valid_market_graph(sample_payloads, monkeypatch, tmp_path):
    from phase5e2a_support import valid_snapshot_graph

    graph, _, _, _, _ = valid_snapshot_graph(sample_payloads, monkeypatch, tmp_path)
    return graph


def test_phase5a_contract_graph_accepts_price_blind_authorization_chain(sample_payloads) -> None:
    _valid_graph(sample_payloads).validate()


def test_candidate_evidence_must_be_in_bound_bundle_closure(sample_payloads) -> None:
    graph = _valid_graph(sample_payloads)
    outside_fact = replace(
        graph.facts[0],
        fact_id="fact:acme:outside-bundle",
        concept="outside_bundle_metric",
    )
    candidate = replace(
        graph.valuation_assumption_candidates[0],
        evidence_bindings=(
            {
                "binding_id": "valuation-evidence:outside",
                "role": "support",
                "slot_evidence_role": "mapped_historical_fact",
                "evidence_domain": "research_bundle",
                "contract_type": "Fact",
                "object_id": outside_fact.fact_id,
            },
        ),
        evidence_graph_sha256="0" * 64,
    )
    augmented = replace_graph(graph, facts=(*graph.facts, outside_fact))
    decision = replace(
        graph.valuation_assumption_review_decisions[0],
        candidate_fingerprint=candidate.fingerprint,
        evidence_graph_sha256=candidate.evidence_graph_sha256,
    )
    broken = replace_graph(
        augmented,
        valuation_assumption_candidates=(candidate,),
        valuation_assumption_review_decisions=(decision,),
    )
    with pytest.raises(ContractGraphError, match="outside the ResearchBundle"):
        broken.validate()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("candidate_fingerprint", "f" * 64, "exact Candidate"),
        ("evidence_graph_sha256", "e" * 64, "exact Candidate"),
        ("reviewer_type", "llm", "human"),
    ),
)
def test_decision_cannot_bypass_human_exact_payload_review(
    sample_payloads, field, value, message
) -> None:
    graph = _valid_graph(sample_payloads)
    payload = graph.valuation_assumption_review_decisions[0].to_dict()
    payload[field] = value
    if field == "reviewer_type":
        with pytest.raises(Exception, match=message):
            contract_from_dict("valuation-assumption-review-decision", payload)
        return
    decision = contract_from_dict("valuation-assumption-review-decision", payload)
    broken = replace_graph(graph, valuation_assumption_review_decisions=(decision,))
    with pytest.raises(ContractGraphError, match=message):
        broken.validate()


def test_candidate_cannot_have_two_active_confirmations(sample_payloads) -> None:
    graph = _valid_graph(sample_payloads)
    duplicate = replace(
        graph.valuation_assumption_review_decisions[0],
        decision_id="valuation-decision:acme:duplicate",
        reserved_kernel_assumption_id="kernel-assumption:acme:duplicate",
    )
    broken = replace_graph(
        graph,
        valuation_assumption_review_decisions=(
            graph.valuation_assumption_review_decisions[0],
            duplicate,
        ),
    )
    with pytest.raises(ContractGraphError, match="multiple active confirmed"):
        broken.validate()


def test_reserved_kernel_assumption_id_is_globally_unique(sample_payloads) -> None:
    graph = _valid_graph(sample_payloads)
    original_candidate = graph.valuation_assumption_candidates[0]
    second_candidate = replace(
        original_candidate,
        candidate_id="valuation-candidate:acme:bull-revenue:2026",
        assumption_slot_id="mckinsey.bull.forecast.2026.revenue",
        scenario="bull",
    )
    original_decision = graph.valuation_assumption_review_decisions[0]
    second_decision = replace(
        original_decision,
        decision_id="valuation-decision:acme:bull-revenue:2026",
        candidate_id=second_candidate.candidate_id,
        candidate_fingerprint=second_candidate.fingerprint,
    )
    broken = replace_graph(
        graph,
        valuation_assumption_candidates=(original_candidate, second_candidate),
        valuation_assumption_review_decisions=(original_decision, second_decision),
        valuation_handoffs=(),
    )
    with pytest.raises(ContractGraphError, match="not unique"):
        broken.validate()


def test_handoff_rejects_nonadjacent_transition_and_protected_hash_drift(sample_payloads) -> None:
    graph = _valid_graph(sample_payloads)
    root, reviewed, frozen, allowed = graph.valuation_handoffs
    skipped = replace(
        allowed,
        handoff_version=3,
        predecessor_handoff_id=reviewed.handoff_id,
    )
    with pytest.raises(ContractGraphError, match="not adjacent"):
        replace_graph(graph, valuation_handoffs=(root, reviewed, skipped)).validate()

    changed = replace(allowed, protected_mckinsey_sha256="9" * 64)
    with pytest.raises(ContractGraphError, match="protected price-blind hashes"):
        replace_graph(graph, valuation_handoffs=(root, reviewed, frozen, changed)).validate()


def test_market_reference_cannot_appear_before_authorization(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    from phase5e2a_support import resign_snapshot

    graph = _valid_market_graph(sample_payloads, monkeypatch, tmp_path)
    snapshot = resign_snapshot(
        graph.market_reference_snapshots[0],
        authorization_handoff_id=graph.valuation_handoffs[-2].handoff_id,
        authorization_handoff_fingerprint=graph.valuation_handoffs[-2].fingerprint,
    )
    with pytest.raises(ContractGraphError, match="price-blind authorization"):
        replace_graph(graph, market_reference_snapshots=(snapshot,)).validate()


def test_market_reference_round_trips_quote_shares_and_calculation(
    sample_payloads, monkeypatch, tmp_path
) -> None:
    _valid_market_graph(sample_payloads, monkeypatch, tmp_path).validate()


@pytest.mark.parametrize(
    ("target", "changes", "message"),
    (
        (
            "snapshot",
            {"market_equity": {"value_decimal": "4999999999"}},
            "exact round-trip",
        ),
        ("snapshot", {"quote_currency": "EUR"}, "Market quote"),
        ("quote", {"source_locator": "wrong locator"}, "input_fingerprint"),
        (
            "calculation",
            {"input_assumption_ids": ("assumption:acme:base",)},
            "input_assumption_ids",
        ),
    ),
)
def test_market_reference_rejects_hand_authored_or_inconsistent_values(
    sample_payloads, monkeypatch, tmp_path, target, changes, message
) -> None:
    from phase5e2a_support import replace_calculation, resign_snapshot

    graph = _valid_market_graph(sample_payloads, monkeypatch, tmp_path)
    if target == "snapshot":
        snapshot = graph.market_reference_snapshots[0]
        if "market_equity" in changes:
            changes = {
                **changes,
                "market_equity": {**snapshot.market_equity, **changes["market_equity"]},
            }
        item = resign_snapshot(snapshot, **changes)
        graph = replace_graph(graph, market_reference_snapshots=(item,))
    elif target == "quote":
        quote_id = graph.market_reference_snapshots[0].quote_fact_id
        facts = tuple(
            replace(item, **changes) if item.fact_id == quote_id else item for item in graph.facts
        )
        graph = replace_graph(graph, facts=facts)
    else:
        calculation_id = graph.market_reference_snapshots[0].market_equity["calculation_id"]
        calculation = next(
            item for item in graph.calculations if item.calculation_id == calculation_id
        )
        graph = replace_calculation(graph, replace(calculation, **changes))
    with pytest.raises(ContractGraphError, match=message):
        graph.validate()


def test_phase5a_exposes_no_builder_fetch_kernel_or_artifact_writer() -> None:
    import owner_research

    for name in (
        "build_valuation_handoff",
        "compile_fact_ledger",
        "compile_assumption_ledger",
        "fetch_market_reference",
        "run_valuation_kernel",
        "write_valuation_artifacts",
    ):
        assert not hasattr(owner_research, name)
