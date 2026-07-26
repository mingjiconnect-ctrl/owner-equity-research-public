from __future__ import annotations

from dataclasses import replace

import pytest
from jsonschema import ValidationError
from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.analytical_claims import review_analytical_claim_candidate
from owner_research.business_quality_policies import MECHANISM_POLICIES
from owner_research.business_quality_reviews import (
    BusinessQualityReviewError,
    MechanismNotApplicableInput,
    build_business_quality_review,
)
from owner_research.contracts import contract_from_dict
from owner_research.fingerprints import canonical_sha256
from owner_research.validation import ContractGraphError

SCOPE = {
    "scope_type": "issuer_wide",
    "segment_definition_ids": [],
    "business_unit": None,
    "product_service": None,
    "geography": None,
    "customer_group": None,
    "channel": None,
}


def _arguments(graph):
    return {
        "issuer_id": "issuer:acme",
        "review_period": {"start": "2025-01-01", "end": "2025-12-31"},
        "as_of_date": "2026-02-16",
        "scope": SCOPE,
        "business_models": graph.business_model_snapshots,
        "competitive_contexts": graph.competitive_context_snapshots,
        "hypotheses": graph.competitive_advantage_hypotheses,
        "claims": graph.claims,
        "analytical_candidates": graph.analytical_claim_candidates,
        "claim_review_decisions": graph.analytical_claim_review_decisions,
        "observations": graph.context_observations,
        "calculations": graph.calculations,
    }


def _not_applicable(graph, mechanism):
    binding = graph.analytical_claim_candidates[0].supporting_evidence_bindings
    candidate = replace(
        graph.analytical_claim_candidates[0],
        candidate_id=f"analytical-candidate:acme:na:{mechanism}",
        proposed_statement=f"The {mechanism} mechanism is not applicable to this scope.",
        claim_role="not_applicable",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=binding,
        counterevidence_bindings=(),
        evidence_graph_sha256=canonical_sha256(
            {
                "supporting_evidence_bindings": binding,
                "counterevidence_bindings": (),
            }
        ),
    )
    claim, decision = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id="reviewer:phase4c5",
        reviewed_at="2026-02-16T05:00:00Z",
        rationale="Not-applicable boundary reviewed for this mechanism and scope.",
    )
    assert claim is not None
    return candidate, claim, decision


def test_builder_selects_objects_and_recomputes_blocked_coverage(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    review = build_business_quality_review(**_arguments(graph))
    assert review.status == "blocked"
    assert review.hypothesis_ids == (
        graph.competitive_advantage_hypotheses[0].hypothesis_id,
    )
    assert review.coverage["blocked_hypothesis_count"] == 1
    assert review.coverage["blocked_component_count"] == 8
    assert review.coverage["supported_hypothesis_count"] == 0
    assert len(review.mechanism_coverage) == 10


def test_latest_valid_hypothesis_is_selected_deterministically(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    current = graph.competitive_advantage_hypotheses[0]
    older = replace(
        current,
        hypothesis_id="hypothesis:acme:switching-cost:older",
        as_of_date="2026-01-15",
    )
    review = build_business_quality_review(
        **{**_arguments(graph), "hypotheses": (current, older)}
    )
    assert review.hypothesis_ids == (current.hypothesis_id,)


def test_complete_review_can_have_zero_supported_hypotheses(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    model = graph.business_model_snapshots[0]
    complete_model = replace(
        model,
        status="complete",
        component_coverage=tuple(
            {
                **dict(item),
                "status": "reviewed",
                "missing_evidence": (),
            }
            for item in model.component_coverage
        ),
        missing_evidence=(),
    )
    context = graph.competitive_context_snapshots[0]
    complete_context = replace(
        context,
        status="complete",
        coverage=tuple(
            {
                **dict(item),
                "status": "reviewed",
                "observation_ids": context.observation_ids,
                "claim_ids": (),
                "missing_evidence": (),
            }
            for item in context.coverage
        ),
        missing_evidence=(),
    )
    proposed = replace(
        graph.competitive_advantage_hypotheses[0],
        status="proposed",
        business_model_snapshot_id=complete_model.snapshot_id,
        competitive_context_snapshot_id=complete_context.context_snapshot_id,
    )
    additions = [
        _not_applicable(graph, mechanism)
        for mechanism in MECHANISM_POLICIES
        if mechanism != "switching_cost"
    ]
    candidates = (*graph.analytical_claim_candidates, *(item[0] for item in additions))
    claims = (*graph.claims, *(item[1] for item in additions))
    decisions = (*graph.analytical_claim_review_decisions, *(item[2] for item in additions))
    inputs = tuple(
        MechanismNotApplicableInput(mechanism, claim.claim_id)
        for mechanism, (_, claim, _) in zip(
            (item for item in MECHANISM_POLICIES if item != "switching_cost"),
            additions,
            strict=True,
        )
    )
    review = build_business_quality_review(
        **{
            **_arguments(graph),
            "business_models": (complete_model,),
            "competitive_contexts": (complete_context,),
            "hypotheses": (proposed,),
            "claims": claims,
            "analytical_candidates": candidates,
            "claim_review_decisions": decisions,
            "not_applicable_inputs": inputs,
        }
    )
    assert review.status == "complete"
    assert review.coverage["supported_hypothesis_count"] == 0
    assert review.coverage["proposed_hypothesis_count"] == 1
    assert sum(item["status"] == "not_applicable" for item in review.mechanism_coverage) == 9


def test_scope_selects_matching_context_instead_of_newer_issuer_context(
    sample_payloads,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    product_scope = {**SCOPE, "scope_type": "product_market", "product_service": "Cloud"}
    product_context = replace(
        graph.competitive_context_snapshots[0],
        context_snapshot_id="competitive-context:acme:cloud",
        as_of_date="2026-01-31",
        scope=product_scope,
    )
    model = graph.business_model_snapshots[0]
    product_material_scope = {
        **dict(model.material_scopes[0]),
        "scope_id": "business-scope:acme:cloud",
        "scope": product_scope,
        "derivation": "confirmed_product_market",
        "segment_snapshot_id": None,
        "segment_definition_ids": (),
        "materiality_claim_id": graph.claims[0].claim_id,
    }
    product_model = replace(
        model,
        snapshot_id="business-model:acme:cloud",
        material_scopes=(product_material_scope,),
        component_coverage=tuple(
            {**dict(item), "scope_id": "business-scope:acme:cloud"}
            for item in model.component_coverage
        ),
    )
    review = build_business_quality_review(
        **{
            **_arguments(graph),
            "scope": product_scope,
            "business_models": (model, product_model),
            "competitive_contexts": (
                graph.competitive_context_snapshots[0],
                product_context,
            ),
            "hypotheses": (),
        }
    )
    assert review.competitive_context_snapshot_id == product_context.context_snapshot_id
    assert review.business_model_snapshot_id == product_model.snapshot_id


def test_not_applicable_mapping_requires_reviewed_role_and_exact_scope(
    sample_payloads,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    with pytest.raises(BusinessQualityReviewError, match="confirmed analytical"):
        build_business_quality_review(
            **{
                **_arguments(graph),
                "not_applicable_inputs": (
                    MechanismNotApplicableInput(
                        "network_effect", "claim:acme:missing"
                    ),
                ),
            }
        )


def test_contract_graph_rejects_review_status_and_latest_selection_tampering(
    sample_payloads,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    review = graph.business_quality_reviews[0]
    with pytest.raises(ContractGraphError, match="status was not deterministically"):
        replace_graph(
            graph,
            business_quality_reviews=(replace(review, status="partial"),),
        ).validate()

    current = graph.competitive_advantage_hypotheses[0]
    older = replace(
        current,
        hypothesis_id="hypothesis:acme:switching-cost:older",
        as_of_date="2026-01-15",
    )
    coverage = tuple(
        (
            {
                **dict(item),
                "hypothesis_ids": (older.hypothesis_id,),
            }
            if item["mechanism"] == "switching_cost"
            else dict(item)
        )
        for item in review.mechanism_coverage
    )
    forged = replace(
        review,
        hypothesis_ids=(older.hypothesis_id,),
        mechanism_coverage=coverage,
    )
    with pytest.raises(ContractGraphError, match="latest hypotheses"):
        replace_graph(
            graph,
            competitive_advantage_hypotheses=(current, older),
            business_quality_reviews=(forged,),
        ).validate()


def test_nonblocked_business_quality_review_schema_requires_a_claim(
    sample_payloads,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    payload = graph.business_quality_reviews[0].to_dict()
    payload["status"] = "partial"
    payload["claim_ids"] = []
    with pytest.raises(ValidationError):
        contract_from_dict("business-quality-review", payload)
