from __future__ import annotations

import copy
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from jsonschema import ValidationError
from phase4a_support import replace_graph
from test_phase5a_contract_graph import _valid_graph

from owner_research.contracts import contract_from_dict
from owner_research.schema_store import SCHEMA_NAMES
from owner_research.validation import ContractGraphError
from owner_research.valuation_assumption_types import PriceBlindReferenceClosure
from owner_research.valuation_handoff_policies import (
    ASSUMPTION_CANDIDATE_POLICY_VERSION,
    HANDOFF_POLICY_VERSION,
    assumption_evidence_policy_sha256,
    assumption_slot_policy,
    assumption_slot_policy_sha256,
    empty_supplemental_reference_closure_sha256,
    price_blind_freeze_policy_sha256,
)
from owner_research.valuation_handoff_validation import candidate_evidence_graph_sha256

ROOT = Path(__file__).parents[1]


def _supplemental_graph(sample_payloads):
    base = _valid_graph(sample_payloads)
    bundle = base.research_bundles[0]
    policy_document = replace(
        base.documents[0],
        document_id="doc:owner-policy:hurdle",
        issuer_id="reference:owner-policy",
        document_type="owner-hurdle-policy",
        period={"start": None, "end": bundle.data_cutoff_date},
        published_date=bundle.data_cutoff_date,
        retrieved_at=f"{bundle.data_cutoff_date}T12:00:00Z",
        source_url=(
            "https://github.com/mingjiconnect-ctrl/owner-equity-research/blob/"
            + "a" * 40
            + "/docs/owner-hurdle-policy.md"
        ),
        authority_level="secondary",
        content_sha256="b" * 64,
    )
    opportunity_document = replace(
        policy_document,
        document_id="doc:official:opportunity-cost",
        issuer_id="reference:official-macro",
        document_type="official-opportunity-cost",
        source_url="https://official.example.gov/opportunity-cost",
        authority_level="primary_regulatory",
        content_sha256="c" * 64,
    )
    policy_fact = replace(
        base.facts[0],
        fact_id="fact:owner-policy:hurdle",
        issuer_id=policy_document.issuer_id,
        concept="owner_hurdle_rate",
        value=0.1,
        unit="ratio",
        currency=None,
        period={"start": None, "end": bundle.data_cutoff_date},
        source_document_id=policy_document.document_id,
        source_locator="policy:hurdle-rate",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    opportunity_fact = replace(
        policy_fact,
        fact_id="fact:official:opportunity-cost",
        issuer_id=opportunity_document.issuer_id,
        concept="long_run_opportunity_cost",
        value=0.06,
        source_document_id=opportunity_document.document_id,
        source_locator="table:opportunity-cost",
    )
    closure = PriceBlindReferenceClosure(
        closure_id="price-blind-reference:acme:base",
        policy_id="price-blind-reference",
        policy_version="1.0.0",
        target_issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        documents=(policy_document, opportunity_document),
        facts=(policy_fact, opportunity_fact),
    )
    candidate = replace(
        base.valuation_assumption_candidates[0],
        candidate_id="valuation-candidate:acme:penman-primary-hurdle",
        supplemental_reference_closure_sha256=closure.fingerprint,
        assumption_slot_id="penman.primary_hurdle",
        method_scope="penman",
        kernel_concept="hurdle_rate",
        value=0.1,
        unit="ratio",
        currency=None,
        horizon={"kind": "point_in_time", "start_date": None, "end_date": bundle.data_cutoff_date},
        scenario=None,
        evidence_bindings=(
            {
                "binding_id": "evidence:owner-policy",
                "role": "support",
                "slot_evidence_role": "owner_hurdle_policy",
                "evidence_domain": "supplemental_price_blind",
                "contract_type": "Fact",
                "object_id": policy_fact.fact_id,
            },
            {
                "binding_id": "evidence:opportunity-cost",
                "role": "support",
                "slot_evidence_role": "opportunity_cost",
                "evidence_domain": "supplemental_price_blind",
                "contract_type": "Fact",
                "object_id": opportunity_fact.fact_id,
            },
        ),
        evidence_graph_sha256="0" * 64,
    )
    graph = replace_graph(
        base,
        valuation_assumption_candidates=(),
        valuation_assumption_review_decisions=(),
        market_reference_snapshots=(),
        valuation_handoffs=(),
        price_blind_reference_closures=(closure,),
    )
    candidate = replace(
        candidate,
        evidence_graph_sha256=candidate_evidence_graph_sha256(graph, candidate),
    )
    return replace_graph(graph, valuation_assumption_candidates=(candidate,)), closure


def test_phase5d0_keeps_43_public_contracts_and_upgrades_only_two(sample_payloads) -> None:
    assert len(SCHEMA_NAMES) == 43
    assert ASSUMPTION_CANDIDATE_POLICY_VERSION == "2.0.0"
    assert HANDOFF_POLICY_VERSION == "2.0.0"
    assert sample_payloads["valuation-assumption-candidate"]["schema_version"] == "2.0.0"
    assert sample_payloads["valuation-handoff"]["schema_version"] == "2.0.0"


def test_phase5d0_policy_hashes_and_empty_closure_are_stable() -> None:
    values = (
        assumption_slot_policy_sha256(),
        assumption_evidence_policy_sha256(),
        price_blind_freeze_policy_sha256(),
        empty_supplemental_reference_closure_sha256(),
    )
    assert all(len(value) == 64 for value in values)
    assert len(set(values)) == len(values)


@pytest.mark.parametrize(
    ("slot_id", "method", "concept", "kind"),
    (
        ("mckinsey.base.forecast.2027.revenue", "mckinsey", "revenue", "period"),
        ("mckinsey.bear.wacc", "mckinsey", "wacc", "point_in_time"),
        ("mckinsey.bull.terminal_ronic", "mckinsey", "terminal_ronic", "terminal"),
        ("penman.forecast.2027.sales", "penman", "sales", "period"),
        ("penman.primary_hurdle", "penman", "hurdle_rate", "point_in_time"),
        ("penman.hurdle_grid.00", "penman", "hurdle_rate", "point_in_time"),
        ("penman.growth_grid.03", "penman", "growth_rate", "terminal"),
        ("penman.challenge.2030.ending_noa", "penman", "ending_noa", "period"),
    ),
)
def test_assumption_slot_registry_is_closed(slot_id, method, concept, kind) -> None:
    policy = assumption_slot_policy(slot_id)
    assert (policy.method_scope, policy.kernel_concept, policy.horizon_kind) == (
        method,
        concept,
        kind,
    )
    with pytest.raises(KeyError):
        assumption_slot_policy("penman.free_form_slot")


def test_supplemental_price_blind_closure_is_immutable_and_order_independent(
    sample_payloads,
) -> None:
    graph, closure = _supplemental_graph(sample_payloads)
    graph.validate()
    reversed_closure = replace(
        closure,
        documents=tuple(reversed(closure.documents)),
        facts=tuple(reversed(closure.facts)),
    )
    assert closure.fingerprint == reversed_closure.fingerprint
    with pytest.raises(FrozenInstanceError):
        closure.closure_id = "changed"  # type: ignore[misc]


def test_candidate_v1_and_handoff_v1_cannot_be_silently_migrated(sample_payloads) -> None:
    for name in ("valuation-assumption-candidate", "valuation-handoff"):
        payload = copy.deepcopy(sample_payloads[name])
        payload["schema_version"] = "1.0.0"
        with pytest.raises(ValidationError):
            contract_from_dict(name, payload)


def test_candidate_rejects_slot_semantic_mismatch(sample_payloads) -> None:
    graph = _valid_graph(sample_payloads)
    candidate = replace(
        graph.valuation_assumption_candidates[0],
        assumption_slot_id="mckinsey.bull.forecast.2026.revenue",
    )
    decision = replace(
        graph.valuation_assumption_review_decisions[0],
        candidate_fingerprint=candidate.fingerprint,
    )
    broken = replace_graph(
        graph,
        valuation_assumption_candidates=(candidate,),
        valuation_assumption_review_decisions=(decision,),
        valuation_handoffs=(),
    )
    with pytest.raises(ContractGraphError, match="slot scenario"):
        broken.validate()


def test_candidate_rejects_target_security_market_reference(sample_payloads) -> None:
    graph, closure = _supplemental_graph(sample_payloads)
    candidate = graph.valuation_assumption_candidates[0]
    poisoned_fact = replace(closure.facts[1], concept="target_share_price")
    poisoned_closure = replace(
        closure,
        facts=(closure.facts[0], poisoned_fact),
    )
    poisoned_candidate = replace(
        candidate,
        supplemental_reference_closure_sha256=poisoned_closure.fingerprint,
        evidence_graph_sha256="0" * 64,
    )
    poisoned_graph = replace_graph(
        graph,
        price_blind_reference_closures=(poisoned_closure,),
        valuation_assumption_candidates=(),
    )
    poisoned_candidate = replace(
        poisoned_candidate,
        evidence_graph_sha256=candidate_evidence_graph_sha256(
            poisoned_graph, poisoned_candidate
        ),
    )
    poisoned_graph = replace_graph(
        poisoned_graph,
        valuation_assumption_candidates=(poisoned_candidate,),
    )
    with pytest.raises(ContractGraphError, match="target-security market evidence"):
        poisoned_graph.validate()


def test_candidate_rejects_supplemental_authority_or_unpinned_owner_policy(
    sample_payloads,
) -> None:
    graph, closure = _supplemental_graph(sample_payloads)
    candidate = graph.valuation_assumption_candidates[0]
    bad_document = replace(
        closure.documents[0],
        source_url="https://github.com/mingjiconnect-ctrl/owner-equity-research/main/policy.md",
    )
    bad_closure = replace(
        closure,
        documents=(bad_document, closure.documents[1]),
    )
    bad_candidate = replace(
        candidate,
        supplemental_reference_closure_sha256=bad_closure.fingerprint,
        evidence_graph_sha256="0" * 64,
    )
    bad_graph = replace_graph(
        graph,
        price_blind_reference_closures=(bad_closure,),
        valuation_assumption_candidates=(),
    )
    bad_candidate = replace(
        bad_candidate,
        evidence_graph_sha256=candidate_evidence_graph_sha256(bad_graph, bad_candidate),
    )
    with pytest.raises(ContractGraphError, match="commit-pinned"):
        replace_graph(
            bad_graph,
            valuation_assumption_candidates=(bad_candidate,),
        ).validate()


def test_duplicate_active_confirmation_for_same_slot_is_rejected(sample_payloads) -> None:
    graph, _ = _supplemental_graph(sample_payloads)
    first = graph.valuation_assumption_candidates[0]
    second = replace(first, candidate_id="valuation-candidate:acme:penman-primary-hurdle:2")
    decision_payload = copy.deepcopy(sample_payloads["valuation-assumption-review-decision"])
    decision_payload.update(
        {
            "decision_id": "valuation-decision:acme:penman-primary-hurdle:1",
            "candidate_id": first.candidate_id,
            "candidate_fingerprint": first.fingerprint,
            "evidence_graph_sha256": first.evidence_graph_sha256,
            "reserved_kernel_assumption_id": "kernel-assumption:penman:hurdle:1",
        }
    )
    first_decision = contract_from_dict("valuation-assumption-review-decision", decision_payload)
    decision_payload.update(
        {
            "decision_id": "valuation-decision:acme:penman-primary-hurdle:2",
            "candidate_id": second.candidate_id,
            "candidate_fingerprint": second.fingerprint,
            "reserved_kernel_assumption_id": "kernel-assumption:penman:hurdle:2",
        }
    )
    second_decision = contract_from_dict("valuation-assumption-review-decision", decision_payload)
    with pytest.raises(ContractGraphError, match="slot has multiple active"):
        replace_graph(
            graph,
            valuation_assumption_candidates=(first, second),
            valuation_assumption_review_decisions=(first_decision, second_decision),
        ).validate()


def test_handoff_rejects_policy_hash_or_transition_time_drift(sample_payloads) -> None:
    graph = _valid_graph(sample_payloads)
    root, reviewed, frozen, allowed = graph.valuation_handoffs
    with pytest.raises(ContractGraphError, match="policy hash"):
        replace_graph(
            graph,
            valuation_handoffs=(replace(root, assumption_slot_policy_sha256="f" * 64),),
        ).validate()
    nonchronological = replace(allowed, transitioned_at=frozen.transitioned_at)
    with pytest.raises(ContractGraphError, match="not chronological"):
        replace_graph(
            graph,
            valuation_handoffs=(root, reviewed, frozen, nonchronological),
        ).validate()


def test_phase5d0_adversarial_fixture_and_forbidden_surfaces() -> None:
    payload = json.loads(
        (ROOT / "tests/fixtures/phase5d0/adversarial-cases.json").read_text(encoding="utf-8")
    )
    assert len(payload["cases"]) >= 36
    assert len(payload["cases"]) == len(set(payload["cases"]))
    import owner_research

    for name in (
        "build_valuation_assumption_candidate",
        "compile_assumption_ledger",
        "fetch_market_reference",
        "run_valuation_kernel",
        "write_price_blind_input",
    ):
        assert not hasattr(owner_research, name)
    assert not hasattr(owner_research, "PriceBlindReferenceClosure")
