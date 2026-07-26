from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace

import pytest
from jsonschema import ValidationError
from phase4a_support import valid_phase4a_graph

from owner_research.business_models import (
    BUSINESS_ATTRIBUTE_ROLES,
    AttributeEvidenceInput,
    BusinessComponentInput,
    BusinessModelBuildError,
    NotApplicableInput,
    SharedScopeInput,
    build_business_model_snapshot,
)
from owner_research.contracts import contract_from_dict
from owner_research.fingerprints import canonical_sha256
from owner_research.schema_store import validate_payload

ISSUER_SCOPE = {
    "scope_type": "issuer_wide",
    "segment_definition_ids": [],
    "business_unit": None,
    "product_service": None,
    "geography": None,
    "customer_group": None,
    "channel": None,
}


def _evidence(graph, scope=ISSUER_SCOPE):
    facts = []
    claims = []
    candidates = []
    decisions = []
    components = []
    for component_type, roles in BUSINESS_ATTRIBUTE_ROLES.items():
        bindings = []
        for role in sorted(roles):
            fact = replace(
                graph.facts[0],
                fact_id=f"fact:acme:{role}",
                concept=f"business_model.{role}",
                source_locator=f"Item 1/{role}",
            )
            statement = f"Reviewed evidence describes {role}."
            claim = replace(
                graph.claims[0],
                claim_id=f"claim:acme:{role}",
                statement=statement,
                supporting_fact_ids=(fact.fact_id,),
            )
            support = ({
                "binding_id": f"candidate-binding:acme:{role}",
                "fact_id": fact.fact_id,
                "calculation_result_id": None,
                "context_observation_id": None,
            },)
            candidate = replace(
                graph.analytical_claim_candidates[0],
                candidate_id=f"analytical-candidate:acme:{role}",
                proposed_statement=statement,
                scope=scope,
                business_attribute_role=role,
                business_component_type=component_type,
                supporting_evidence_bindings=support,
                evidence_graph_sha256=canonical_sha256(
                    {
                        "supporting_evidence_bindings": support,
                        "counterevidence_bindings": (),
                    }
                ),
            )
            decision = replace(
                graph.analytical_claim_review_decisions[0],
                decision_id=f"analytical-review:acme:{role}",
                candidate_id=candidate.candidate_id,
                candidate_fingerprint=candidate.fingerprint,
                evidence_graph_sha256=candidate.evidence_graph_sha256,
                output_claim_id=claim.claim_id,
            )
            facts.append(fact)
            claims.append(claim)
            candidates.append(candidate)
            decisions.append(decision)
            bindings.append(
                AttributeEvidenceInput(
                    role=role,
                    fact_ids=(fact.fact_id,),
                    claim_ids=(claim.claim_id,),
                    review_decision_ids=(decision.decision_id,),
                )
            )
        components.append(
            BusinessComponentInput(
                component_type=component_type,
                scope=scope,
                attribute_evidence_bindings=tuple(bindings),
            )
        )
    return tuple(facts), tuple(claims), tuple(candidates), tuple(decisions), tuple(components)


def _complete_snapshot(graph):
    return replace(
        graph.segment_snapshots[0],
        status="complete",
        reconciliation_calculation_ids=("calc:synthetic:reconciliation",),
        missing_evidence=(),
    )


def _build(graph, **overrides):
    facts, claims, candidates, decisions, components = _evidence(graph)
    arguments = {
        "issuer_id": "issuer:acme",
        "as_of_date": "2026-02-16",
        "source_documents": graph.documents,
        "fiscal_periods": graph.periods,
        "segment_definitions": graph.segment_definitions,
        "segment_snapshots": (_complete_snapshot(graph),),
        "facts": facts,
        "claims": claims,
        "analytical_candidates": candidates,
        "claim_review_decisions": decisions,
        "components": components,
    }
    arguments.update(overrides)
    return build_business_model_snapshot(**arguments)


def test_complete_builder_binds_each_attribute_to_reviewed_evidence(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    snapshot = _build(graph)
    assert snapshot.status == "complete"
    assert len(snapshot.material_scopes) == 1
    assert len(snapshot.component_coverage) == 8
    for component in snapshot.components:
        binding_facts = {
            fact_id
            for binding in component["attribute_evidence_bindings"]
            for fact_id in binding["fact_ids"]
        }
        assert binding_facts == set(component["fact_ids"])


def test_one_revenue_claim_cannot_support_thirteen_attributes(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    facts, claims, candidates, decisions, components = _evidence(graph)
    first = components[0].attribute_evidence_bindings[0]
    bad_components = tuple(
        replace(
            component,
            attribute_evidence_bindings=tuple(
                replace(
                    binding,
                    fact_ids=first.fact_ids,
                    claim_ids=first.claim_ids,
                    review_decision_ids=first.review_decision_ids,
                )
                for binding in component.attribute_evidence_bindings
            ),
        )
        for component in components
    )
    with pytest.raises(BusinessModelBuildError, match="semantic role"):
        _build(
            graph,
            facts=facts,
            claims=claims,
            analytical_candidates=candidates,
            claim_review_decisions=decisions,
            components=bad_components,
        )


def test_missing_attribute_binding_blocks_its_scope(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    _, _, _, _, components = _evidence(graph)
    changed = tuple(
        replace(
            item,
            attribute_evidence_bindings=tuple(
                binding
                for binding in item.attribute_evidence_bindings
                if binding.role != "pricing_method"
            ),
        )
        if item.component_type == "revenue_model"
        else item
        for item in components
    )
    snapshot = _build(graph, components=changed)
    assert snapshot.status == "blocked"


def test_candidate_scope_must_equal_component_scope(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    facts, claims, candidates, decisions, components = _evidence(graph)
    changed_candidate = replace(
        candidates[0],
        scope={**ISSUER_SCOPE, "scope_type": "product_market", "product_service": "Other"},
    )
    changed_decision = replace(
        decisions[0],
        candidate_fingerprint=changed_candidate.fingerprint,
    )
    with pytest.raises(BusinessModelBuildError, match="scope mismatch"):
        _build(
            graph,
            facts=facts,
            claims=claims,
            analytical_candidates=(changed_candidate, *candidates[1:]),
            claim_review_decisions=(changed_decision, *decisions[1:]),
            components=components,
        )


def test_latest_partial_or_future_segment_snapshot_fails_closed(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    partial = _build(graph, segment_snapshots=graph.segment_snapshots)
    assert partial.status == "blocked"
    future_period = replace(
        graph.periods[0],
        period_id="period:future",
        cumulative_end="2027-12-31",
        quarter_end="2027-12-31",
    )
    future_snapshot = replace(
        graph.segment_snapshots[0],
        fiscal_period_id=future_period.period_id,
    )
    future = _build(
        graph,
        fiscal_periods=(future_period,),
        segment_snapshots=(future_snapshot,),
    )
    assert future.status == "blocked"
    assert not future.material_scopes


def test_all_reportable_segments_are_derived_as_material_scopes(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    second = replace(
        graph.segment_definitions[0],
        segment_id="segment:acme:commerce",
        disclosed_name="Commerce",
        normalized_name="commerce",
    )
    snapshot = replace(
        _complete_snapshot(graph),
        segment_definition_ids=(graph.segment_definitions[0].segment_id, second.segment_id),
    )
    result = _build(
        graph,
        segment_definitions=(*graph.segment_definitions, second),
        segment_snapshots=(snapshot,),
        components=(),
    )
    assert {item["segment_definition_ids"][0] for item in result.material_scopes} == {
        graph.segment_definitions[0].segment_id,
        second.segment_id,
    }
    assert result.status == "blocked"


def test_issuer_wide_shared_resource_requires_explicit_scope_relation(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    second = replace(
        graph.segment_definitions[0],
        segment_id="segment:acme:commerce",
        disclosed_name="Commerce",
        normalized_name="commerce",
    )
    snapshot = replace(
        _complete_snapshot(graph),
        segment_definition_ids=(graph.segment_definitions[0].segment_id, second.segment_id),
    )
    facts, claims, candidates, decisions, components = _evidence(graph)
    resource = next(item for item in components if item.component_type == "key_resource")
    resource_binding = resource.attribute_evidence_bindings[0]
    scopes = tuple(
        {
            **ISSUER_SCOPE,
            "scope_type": "segment_specific",
            "segment_definition_ids": [segment.segment_id],
            "business_unit": segment.normalized_name,
        }
        for segment in (graph.segment_definitions[0], second)
    )
    result = _build(
        graph,
        segment_definitions=(*graph.segment_definitions, second),
        segment_snapshots=(snapshot,),
        facts=facts,
        claims=claims,
        analytical_candidates=candidates,
        claim_review_decisions=decisions,
        components=(resource,),
        shared_scope_inputs=(
            SharedScopeInput(
                component_type="key_resource",
                covered_scopes=scopes,
                claim_id=resource_binding.claim_ids[0],
                review_decision_id=resource_binding.review_decision_ids[0],
            ),
        ),
    )
    resource_coverage = [
        item
        for item in result.component_coverage
        if item["component_type"] == "key_resource"
    ]
    assert len(resource_coverage) == 2
    assert all(item["status"] == "reviewed" for item in resource_coverage)


def _not_applicable_evidence(graph, component_type: str, scope=ISSUER_SCOPE):
    fact = replace(
        graph.facts[0],
        fact_id=f"fact:acme:{component_type}:na",
        concept=f"business_model.{component_type}.not_applicable",
    )
    statement = f"{component_type} is not applicable within the reviewed scope."
    claim = replace(
        graph.claims[0],
        claim_id=f"claim:acme:{component_type}:na",
        statement=statement,
        supporting_fact_ids=(fact.fact_id,),
    )
    support = ({
        "binding_id": f"binding:acme:{component_type}:na",
        "fact_id": fact.fact_id,
        "calculation_result_id": None,
        "context_observation_id": None,
    },)
    candidate = replace(
        graph.analytical_claim_candidates[0],
        candidate_id=f"candidate:acme:{component_type}:na",
        proposed_statement=statement,
        scope=scope,
        claim_role="not_applicable",
        business_attribute_role=None,
        business_component_type=component_type,
        supporting_evidence_bindings=support,
        evidence_graph_sha256=canonical_sha256(
            {"supporting_evidence_bindings": support, "counterevidence_bindings": ()}
        ),
    )
    decision = replace(
        graph.analytical_claim_review_decisions[0],
        decision_id=f"decision:acme:{component_type}:na",
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=candidate.fingerprint,
        evidence_graph_sha256=candidate.evidence_graph_sha256,
        output_claim_id=claim.claim_id,
    )
    return fact, claim, candidate, decision


def test_support_claim_or_wrong_scope_cannot_mark_component_not_applicable(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    facts, claims, candidates, decisions, components = _evidence(graph)
    with pytest.raises(BusinessModelBuildError, match="not-applicable Claim"):
        _build(
            graph,
            facts=facts,
            claims=claims,
            analytical_candidates=candidates,
            claim_review_decisions=decisions,
            components=tuple(item for item in components if item.component_type != "key_partner"),
            not_applicable_inputs=(
                NotApplicableInput(
                    "key_partner", ISSUER_SCOPE, claims[0].claim_id, decisions[0].decision_id
                ),
            ),
        )

    fact, claim, candidate, decision = _not_applicable_evidence(
        graph,
        "key_partner",
        {**ISSUER_SCOPE, "scope_type": "product_market", "product_service": "Other"},
    )
    with pytest.raises(BusinessModelBuildError, match="scope is not material"):
        _build(
            graph,
            facts=(*facts, fact),
            claims=(*claims, claim),
            analytical_candidates=(*candidates, candidate),
            claim_review_decisions=(*decisions, decision),
            components=tuple(item for item in components if item.component_type != "key_partner"),
            not_applicable_inputs=(
                NotApplicableInput(
                    "key_partner",
                    candidate.scope,
                    claim.claim_id,
                    decision.decision_id,
                ),
            ),
        )


def test_only_partner_and_regulatory_components_can_be_not_applicable(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    fact, claim, candidate, decision = _not_applicable_evidence(graph, "value_proposition")
    with pytest.raises(BusinessModelBuildError, match="cannot be not-applicable"):
        _build(
            graph,
            facts=(fact,),
            claims=(claim,),
            analytical_candidates=(candidate,),
            claim_review_decisions=(decision,),
            components=(),
            not_applicable_inputs=(
                NotApplicableInput(
                    "value_proposition", ISSUER_SCOPE, claim.claim_id, decision.decision_id
                ),
            ),
        )


def test_contract_graph_rejects_aggregate_evidence_tampering(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    snapshot = graph.business_model_snapshots[0]
    components = tuple(
        {**dict(item), "fact_ids": ()} if index == 0 else dict(item)
        for index, item in enumerate(snapshot.components)
    )
    with pytest.raises(Exception, match="non-empty|aggregate evidence"):
        replace(snapshot, components=components)


def test_v2_business_model_cannot_be_silently_validated_as_v3(
    sample_payloads: dict[str, dict],
) -> None:
    payload = copy.deepcopy(sample_payloads["business-model-snapshot"])
    payload["schema_version"] = "2.0.0"
    with pytest.raises(ValidationError):
        validate_payload("business-model-snapshot", payload)


def test_candidate_and_snapshot_contracts_remain_immutable(
    sample_payloads: dict[str, dict],
) -> None:
    candidate = contract_from_dict(
        "analytical-claim-candidate", sample_payloads["analytical-claim-candidate"]
    )
    snapshot = contract_from_dict(
        "business-model-snapshot", sample_payloads["business-model-snapshot"]
    )
    assert candidate.schema_version == "2.0.0"
    assert snapshot.schema_version == "3.0.0"
    with pytest.raises((FrozenInstanceError, AttributeError)):
        candidate.claim_role = "changed"
