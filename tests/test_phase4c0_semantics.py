from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace

import pytest
from jsonschema import ValidationError
from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.business_quality_policies import MECHANISM_POLICIES, POLICY_VERSION
from owner_research.contracts import contract_from_dict
from owner_research.fingerprints import canonical_sha256
from owner_research.schema_store import validate_payload
from owner_research.validation import ContractGraph, ContractGraphError

PHASE4C0_SCHEMAS = {
    "context-observation",
    "competitive-context-snapshot",
    "analytical-claim-candidate",
    "analytical-claim-review-decision",
    "business-model-snapshot",
    "competitive-advantage-hypothesis",
    "business-quality-review",
}


@pytest.mark.parametrize("schema_name", sorted(PHASE4C0_SCHEMAS))
def test_phase4c0_contracts_are_immutable_and_reject_unknown_fields(
    schema_name: str, sample_payloads: dict[str, dict]
) -> None:
    payload = copy.deepcopy(sample_payloads[schema_name])
    instance = contract_from_dict(schema_name, payload)
    assert instance.fingerprint == contract_from_dict(
        schema_name, dict(reversed(list(payload.items())))
    ).fingerprint
    with pytest.raises((FrozenInstanceError, AttributeError)):
        instance.schema_version = "changed"
    payload["score"] = 100
    with pytest.raises(ValidationError):
        validate_payload(schema_name, payload)


def test_fact_cannot_masquerade_as_target_evidence_from_external_document(
    sample_payloads: dict[str, dict]
) -> None:
    document = replace(
        contract_from_dict("source-document", sample_payloads["source-document"]),
        issuer_id="issuer:competitor",
    )
    fact = contract_from_dict("fact", sample_payloads["fact"])
    with pytest.raises(ContractGraphError, match="Fact issuer must match"):
        ContractGraph(documents=(document,), facts=(fact,)).validate()


def test_external_document_can_only_enter_context_observation(
    sample_payloads: dict[str, dict]
) -> None:
    document = replace(
        contract_from_dict("source-document", sample_payloads["source-document"]),
        document_id="doc:competitor:2025-10k",
        issuer_id="issuer:competitor",
        source_url="https://example.com/competitor-10k",
    )
    observation = replace(
        contract_from_dict("context-observation", sample_payloads["context-observation"]),
        observation_id="context-observation:acme:competitor",
        subject={
            "entity_id": "issuer:competitor",
            "entity_name": "Competitor",
            "role": "competitor",
        },
        source_document_id=document.document_id,
    )
    ContractGraph(documents=(document,), context_observations=(observation,)).validate()


def test_language_model_cannot_emit_confirmed_context_observation(
    sample_payloads: dict[str, dict]
) -> None:
    payload = copy.deepcopy(sample_payloads["context-observation"])
    payload["extraction_method"] = "language_model"
    with pytest.raises(ValidationError):
        validate_payload("context-observation", payload)


def test_candidate_evidence_graph_hash_is_recomputed(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    changed = replace(graph.analytical_claim_candidates[0], evidence_graph_sha256="f" * 64)
    with pytest.raises(ContractGraphError, match="evidence graph hash mismatch"):
        replace_graph(graph, analytical_claim_candidates=(changed,)).validate()


def test_review_decision_is_bound_to_candidate_fingerprint(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    changed = replace(
        graph.analytical_claim_review_decisions[0], candidate_fingerprint="f" * 64
    )
    with pytest.raises(ContractGraphError, match="candidate fingerprint mismatch"):
        replace_graph(graph, analytical_claim_review_decisions=(changed,)).validate()


def test_confirmed_claim_cannot_have_multiple_review_decisions(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    duplicate = replace(
        graph.analytical_claim_review_decisions[0],
        decision_id="analytical-review:acme:duplicate",
    )
    with pytest.raises(ContractGraphError, match="multiple review decisions"):
        replace_graph(
            graph,
            analytical_claim_review_decisions=(
                *graph.analytical_claim_review_decisions,
                duplicate,
            ),
        ).validate()


def test_unreviewed_claim_cannot_enter_business_quality_graph(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    with pytest.raises(ContractGraphError, match="lacks analytical human review"):
        replace_graph(graph, analytical_claim_review_decisions=()).validate()


def test_typed_evidence_binding_must_reference_exactly_one_domain(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    candidate = graph.analytical_claim_candidates[0]
    binding = dict(candidate.supporting_evidence_bindings[0])
    binding["context_observation_id"] = graph.context_observations[0].observation_id
    bindings = (binding,)
    changed = replace(
        candidate,
        supporting_evidence_bindings=bindings,
        evidence_graph_sha256=canonical_sha256(
            {
                "supporting_evidence_bindings": bindings,
                "counterevidence_bindings": candidate.counterevidence_bindings,
            }
        ),
    )
    with pytest.raises(ContractGraphError, match="exactly one evidence object"):
        replace_graph(graph, analytical_claim_candidates=(changed,)).validate()


def test_complete_business_model_cannot_invent_missing_components(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    coverage = tuple(
        {
            **dict(item),
            "status": "reviewed",
            "component_ids": (),
            "missing_evidence": (),
        }
        for item in graph.business_model_snapshots[0].component_coverage
    )
    changed = replace(
        graph.business_model_snapshots[0],
        status="complete",
        component_coverage=coverage,
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="lacks real component"):
        replace_graph(graph, business_model_snapshots=(changed,)).validate()


def test_complete_context_requires_target_and_independent_primary_sources(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    context = graph.competitive_context_snapshots[0]
    coverage = tuple(
        {
            **dict(item),
            "status": "reviewed",
            "observation_ids": (graph.context_observations[0].observation_id,),
            "missing_evidence": (),
        }
        for item in context.coverage
    )
    changed = replace(context, status="complete", coverage=coverage, missing_evidence=())
    with pytest.raises(ContractGraphError, match="independent source diversity"):
        replace_graph(graph, competitive_context_snapshots=(changed,)).validate()


def test_hypothesis_rejects_free_or_unregistered_evidence_role(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    changed = replace(
        graph.competitive_advantage_hypotheses[0],
        evidence_bindings=(
            {
                "binding_id": "binding:acme:growth",
                "role_id": "high_growth_alone",
                "polarity": "support",
                "fact_id": graph.facts[0].fact_id,
                "calculation_result_id": None,
                "context_observation_id": None,
            },
        ),
    )
    with pytest.raises(ContractGraphError, match="unregistered evidence role"):
        replace_graph(graph, competitive_advantage_hypotheses=(changed,)).validate()


def test_hypothesis_scope_must_match_competitive_context(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    changed = replace(
        graph.competitive_advantage_hypotheses[0],
        scope={
            "scope_type": "product_market",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": "Different product",
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
    )
    with pytest.raises(ContractGraphError, match="context scope mismatch"):
        replace_graph(graph, competitive_advantage_hypotheses=(changed,)).validate()


def test_non_unknown_trend_requires_predecessor_and_reviewed_trend_claim(
    sample_payloads: dict[str, dict]
) -> None:
    payload = copy.deepcopy(sample_payloads["competitive-advantage-hypothesis"])
    payload["trend"] = "stable"
    with pytest.raises(ValidationError):
        validate_payload("competitive-advantage-hypothesis", payload)


def test_context_rejects_evidence_published_after_cutoff(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    late = replace(graph.documents[0], published_date="2026-02-17")
    with pytest.raises(ContractGraphError, match="future source evidence"):
        replace_graph(graph, documents=(late,)).validate()


def test_business_quality_review_coverage_is_not_caller_controlled(
    sample_payloads: dict[str, dict]
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    forged = dict(graph.business_quality_reviews[0].coverage)
    forged["supported_hypothesis_count"] = 99
    changed = replace(graph.business_quality_reviews[0], coverage=forged)
    with pytest.raises(ContractGraphError, match="coverage counts mismatch"):
        replace_graph(graph, business_quality_reviews=(changed,)).validate()


def test_all_mechanisms_have_fixed_v1_roles_and_forbidden_shortcuts() -> None:
    assert len(MECHANISM_POLICIES) == 10
    assert all(item.version == POLICY_VERSION for item in MECHANISM_POLICIES.values())
    assert all(
        item.support_roles and item.counterevidence_roles
        for item in MECHANISM_POLICIES.values()
    )
    assert all(
        "high_roic_alone" in item.forbidden_single_indicators
        for item in MECHANISM_POLICIES.values()
    )


def test_calculation_result_cannot_add_context_observation_inputs(
    sample_payloads: dict[str, dict]
) -> None:
    payload = copy.deepcopy(sample_payloads["calculation-result"])
    payload["input_context_observation_ids"] = ["context-observation:acme:product-market"]
    with pytest.raises(ValidationError):
        validate_payload("calculation-result", payload)
