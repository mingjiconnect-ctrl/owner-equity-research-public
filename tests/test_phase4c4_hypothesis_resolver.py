from __future__ import annotations

import inspect
from dataclasses import dataclass, replace

import pytest
from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.analytical_claims import (
    AnalyticalClaimReviewError,
    review_analytical_claim_candidate,
)
from owner_research.competitive_advantages import (
    CompetitiveAdvantageResolutionError,
    CounterevidenceResolutionInput,
    resolve_competitive_advantage_hypothesis,
)
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


@dataclass(frozen=True)
class EvidenceBundle:
    business_model: object
    context: object
    documents: tuple
    facts: tuple
    observations: tuple
    claims: tuple
    candidates: tuple
    decisions: tuple
    bindings: tuple
    core_claim_id: str
    durability_claim_id: str
    reinvestment_claim_id: str
    counter_claim_id: str
    resolution_claim_id: str


def _candidate(graph, *, name, fact, role="support", observation=None):
    bindings = [
        {
            "binding_id": f"candidate-binding:{name}:fact",
            "fact_id": fact.fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
    ]
    if observation is not None:
        bindings.append(
            {
                "binding_id": f"candidate-binding:{name}:observation",
                "fact_id": None,
                "calculation_result_id": None,
                "context_observation_id": observation.observation_id,
            }
        )
    support = tuple(bindings)
    candidate = replace(
        graph.analytical_claim_candidates[0],
        candidate_id=f"analytical-candidate:acme:{name}",
        proposed_statement=f"Reviewed analytical statement for {name}.",
        scope=SCOPE,
        claim_role=role,
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=support,
        counterevidence_bindings=(),
        generation_method="language_model",
        evidence_graph_sha256=canonical_sha256(
            {
                "supporting_evidence_bindings": support,
                "counterevidence_bindings": (),
            }
        ),
        validation_status="ready",
        validation_issues=(),
    )
    claim, decision = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id="reviewer:phase4c4",
        reviewed_at="2026-02-16T04:00:00Z",
        rationale="Evidence, counterevidence search, and falsification boundary reviewed.",
    )
    assert claim is not None
    return candidate, claim, decision


def _bundle(sample_payloads, *, counter_role="counterevidence") -> EvidenceBundle:
    graph = valid_phase4a_graph(sample_payloads)
    target_document = graph.documents[0]
    external_document = replace(
        target_document,
        document_id="doc:competitor:2025-10k",
        issuer_id="issuer:competitor",
        source_url="https://www.sec.gov/Archives/competitor-10k.htm",
        authority_level="primary_regulatory",
        content_sha256="e" * 64,
    )
    external_observation = replace(
        graph.context_observations[0],
        observation_id="context-observation:acme:competitor-multihoming",
        subject={
            "entity_id": "issuer:competitor",
            "entity_name": "Competitor",
            "role": "competitor",
        },
        observation_type="competitor_behavior",
        statement="Competitor evidence describes customer multihoming.",
        source_document_id=external_document.document_id,
        source_locator="Item 1 / competition",
    )
    names = (
        "retention",
        "migration-cost",
        "counter",
        "core",
        "durability",
        "reinvestment",
        "resolution",
    )
    facts = tuple(
        replace(
            graph.facts[0],
            fact_id=f"fact:acme:{name}",
            concept=f"business_quality.{name}",
            source_locator=f"Item 1 / {name}",
        )
        for name in names
    )
    fact_by_name = dict(zip(names, facts, strict=True))
    reviewed = {
        name: _candidate(graph, name=name, fact=fact_by_name[name])
        for name in ("core", "durability", "reinvestment", "resolution")
    }
    reviewed["counter"] = _candidate(
        graph,
        name="counter",
        fact=fact_by_name["counter"],
        role=counter_role,
        observation=external_observation,
    )
    candidates = tuple(item[0] for item in reviewed.values())
    claims = tuple(item[1] for item in reviewed.values())
    decisions = tuple(item[2] for item in reviewed.values())
    claim_by_name = {name: item[1] for name, item in reviewed.items()}
    bindings = (
        {
            "binding_id": "binding:retention",
            "role_id": "retention_churn",
            "polarity": "support",
            "fact_id": fact_by_name["retention"].fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        },
        {
            "binding_id": "binding:migration",
            "role_id": "migration_integration_cost",
            "polarity": "support",
            "fact_id": fact_by_name["migration-cost"].fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        },
        {
            "binding_id": "binding:counter-fact",
            "role_id": "multihoming_substitution",
            "polarity": "counterevidence",
            "fact_id": fact_by_name["counter"].fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        },
        {
            "binding_id": "binding:counter-observation",
            "role_id": "multihoming_substitution",
            "polarity": "counterevidence",
            "fact_id": None,
            "calculation_result_id": None,
            "context_observation_id": external_observation.observation_id,
        },
        {
            "binding_id": "binding:core",
            "role_id": "retention_churn",
            "polarity": "support",
            "fact_id": fact_by_name["core"].fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        },
        {
            "binding_id": "binding:durability",
            "role_id": "retention_churn",
            "polarity": "support",
            "fact_id": fact_by_name["durability"].fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        },
        {
            "binding_id": "binding:reinvestment",
            "role_id": "retention_churn",
            "polarity": "support",
            "fact_id": fact_by_name["reinvestment"].fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        },
    )
    return EvidenceBundle(
        business_model=replace(
            graph.business_model_snapshots[0], status="complete", missing_evidence=()
        ),
        context=replace(
            graph.competitive_context_snapshots[0], status="complete", missing_evidence=()
        ),
        documents=(target_document, external_document),
        facts=facts,
        observations=(external_observation,),
        claims=claims,
        candidates=candidates,
        decisions=decisions,
        bindings=bindings,
        core_claim_id=claim_by_name["core"].claim_id,
        durability_claim_id=claim_by_name["durability"].claim_id,
        reinvestment_claim_id=claim_by_name["reinvestment"].claim_id,
        counter_claim_id=claim_by_name["counter"].claim_id,
        resolution_claim_id=claim_by_name["resolution"].claim_id,
    )


def _resolve(bundle, **overrides):
    arguments = {
        "issuer_id": "issuer:acme",
        "as_of_date": "2026-02-16",
        "assessment_period": {"start": "2025-01-01", "end": "2025-12-31"},
        "mechanism": "switching_cost",
        "scope": SCOPE,
        "business_model": bundle.business_model,
        "competitive_context": bundle.context,
        "documents": bundle.documents,
        "facts": bundle.facts,
        "calculations": (),
        "observations": bundle.observations,
        "segment_snapshots": (),
        "claims": bundle.claims,
        "analytical_candidates": bundle.candidates,
        "claim_review_decisions": bundle.decisions,
        "evidence_bindings": bundle.bindings,
        "hypothesis_claim_id": bundle.core_claim_id,
        "durability_claim_id": bundle.durability_claim_id,
        "reinvestment_claim_id": bundle.reinvestment_claim_id,
        "reinvestment_relevance": "direct",
        "counterevidence_resolutions": (
            CounterevidenceResolutionInput(
                bundle.counter_claim_id, "resolved", bundle.resolution_claim_id
            ),
        ),
    }
    arguments.update(overrides)
    return resolve_competitive_advantage_hypothesis(**arguments)


def test_human_review_promotes_candidate_but_model_cannot_confirm_directly(
    sample_payloads,
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    candidate = graph.analytical_claim_candidates[0]
    claim, decision = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id="reviewer:human",
        reviewed_at="2026-02-16T04:00:00Z",
        rationale="Human reviewed the evidence graph.",
    )
    assert claim is not None
    assert decision.output_claim_id == claim.claim_id
    assert decision.candidate_fingerprint == candidate.fingerprint
    with pytest.raises(AnalyticalClaimReviewError, match="only a ready"):
        review_analytical_claim_candidate(
            replace(candidate, validation_status="blocked", validation_issues=("gap",)),
            decision="confirmed",
            reviewer_id="reviewer:human",
            reviewed_at="2026-02-16T04:00:00Z",
            rationale="Attempted confirmation.",
        )


def test_resolver_recomputes_supported_and_does_not_accept_status(sample_payloads) -> None:
    bundle = _bundle(sample_payloads)
    hypothesis = _resolve(bundle)
    assert hypothesis.status == "supported"
    assert hypothesis.counterevidence_claim_ids == (bundle.counter_claim_id,)
    assert "status" not in inspect.signature(resolve_competitive_advantage_hypothesis).parameters


def test_contract_graph_rejects_caller_filled_hypothesis_status(sample_payloads) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    forged = replace(graph.competitive_advantage_hypotheses[0], status="proposed")
    with pytest.raises(ContractGraphError, match="deterministically resolved"):
        replace_graph(graph, competitive_advantage_hypotheses=(forged,)).validate()


@pytest.mark.parametrize(
    ("resolution_status", "expected"),
    (("unresolved", "contested"), ("falsifying", "falsified")),
)
def test_status_priority_for_reviewed_counterevidence(
    sample_payloads, resolution_status, expected
) -> None:
    bundle = _bundle(
        sample_payloads,
        counter_role=("falsification" if resolution_status == "falsifying" else "counterevidence"),
    )
    result = _resolve(
        bundle,
        counterevidence_resolutions=(
            CounterevidenceResolutionInput(bundle.counter_claim_id, resolution_status),
        ),
    )
    assert result.status == expected


def test_blocked_scope_precedes_falsification_and_missing_roles_remain_proposed(
    sample_payloads,
) -> None:
    bundle = _bundle(sample_payloads, counter_role="falsification")
    blocked = _resolve(
        bundle,
        competitive_context=replace(
            bundle.context, status="blocked", missing_evidence=("market boundary",)
        ),
        counterevidence_resolutions=(
            CounterevidenceResolutionInput(bundle.counter_claim_id, "falsifying"),
        ),
    )
    assert blocked.status == "blocked"
    proposed = _resolve(
        bundle,
        durability_claim_id=None,
        reinvestment_claim_id=None,
    )
    assert proposed.status == "proposed"


def test_source_independence_and_forbidden_shortcuts_fail_closed(sample_payloads) -> None:
    bundle = _bundle(sample_payloads)
    secondary = replace(bundle.documents[1], authority_level="secondary")
    assert _resolve(bundle, documents=(bundle.documents[0], secondary)).status == "proposed"
    shortcut_fact = replace(bundle.facts[0], concept="high_growth_alone")
    with pytest.raises(CompetitiveAdvantageResolutionError, match="shortcut"):
        _resolve(bundle, facts=(shortcut_fact, *bundle.facts[1:]))


def test_claim_tampering_and_observation_scope_mismatch_are_rejected(sample_payloads) -> None:
    bundle = _bundle(sample_payloads)
    tampered = replace(bundle.claims[0], statement="Caller-overridden conclusion.")
    with pytest.raises(CompetitiveAdvantageResolutionError, match="reproduce"):
        _resolve(bundle, claims=(tampered, *bundle.claims[1:]))
    mismatched_observation = replace(
        bundle.observations[0],
        scope={**SCOPE, "scope_type": "product_market", "product_service": "Other"},
    )
    with pytest.raises(CompetitiveAdvantageResolutionError, match="scope mismatch"):
        _resolve(bundle, observations=(mismatched_observation,))


def test_every_counter_binding_requires_reviewed_counter_claim_coverage(
    sample_payloads,
) -> None:
    bundle = _bundle(sample_payloads)
    graph = valid_phase4a_graph(sample_payloads)
    counter_fact = next(item for item in bundle.facts if item.concept.endswith("counter"))
    candidate, claim, decision = _candidate(
        graph,
        name="counter-fact-only",
        fact=counter_fact,
        role="counterevidence",
    )
    retained_claims = tuple(
        item for item in bundle.claims if item.claim_id != bundle.counter_claim_id
    )
    retained_candidates = tuple(
        item
        for item in bundle.candidates
        if item.candidate_id
        != next(
            current.candidate_id
            for current, reviewed in zip(bundle.candidates, bundle.claims, strict=True)
            if reviewed.claim_id == bundle.counter_claim_id
        )
    )
    retained_decisions = tuple(
        item
        for item in bundle.decisions
        if item.output_claim_id != bundle.counter_claim_id
    )
    result = _resolve(
        bundle,
        claims=(*retained_claims, claim),
        analytical_candidates=(*retained_candidates, candidate),
        claim_review_decisions=(*retained_decisions, decision),
        counterevidence_resolutions=(
            CounterevidenceResolutionInput(
                claim.claim_id, "resolved", bundle.resolution_claim_id
            ),
        ),
    )
    assert result.status == "blocked"
    assert "Counterevidence binding lacks" in result.missing_evidence[0]


def test_counterevidence_cannot_be_deleted_from_comparable_predecessor(
    sample_payloads,
) -> None:
    bundle = _bundle(sample_payloads)
    supported = _resolve(bundle)
    predecessor = replace(
        supported,
        hypothesis_id="hypothesis:acme:switching-cost:2024",
        assessment_period={"start": "2024-01-01", "end": "2024-12-31"},
        as_of_date="2025-02-16",
    )
    without_counter = tuple(
        item for item in bundle.bindings if item["polarity"] != "counterevidence"
    )
    with pytest.raises(CompetitiveAdvantageResolutionError, match="resolutions|deleted"):
        _resolve(
            bundle,
            evidence_bindings=without_counter,
            counterevidence_resolutions=(),
            predecessor=predecessor,
        )


def test_trend_requires_comparable_predecessor_and_matching_reviewed_role(
    sample_payloads,
) -> None:
    bundle = _bundle(sample_payloads)
    supported = _resolve(bundle)
    predecessor = replace(
        supported,
        hypothesis_id="hypothesis:acme:switching-cost:2024",
        assessment_period={"start": "2024-01-01", "end": "2024-12-31"},
        as_of_date="2025-02-16",
    )
    graph = valid_phase4a_graph(sample_payloads)
    trend_candidate, trend_claim, trend_decision = _candidate(
        graph, name="trend", fact=bundle.facts[0], role="stable"
    )
    trended = _resolve(
        bundle,
        predecessor=predecessor,
        claims=(*bundle.claims, trend_claim),
        analytical_candidates=(*bundle.candidates, trend_candidate),
        claim_review_decisions=(*bundle.decisions, trend_decision),
        trend_claim_id=trend_claim.claim_id,
    )
    assert trended.trend == "stable"
    with pytest.raises(CompetitiveAdvantageResolutionError, match="predecessor"):
        _resolve(
            bundle,
            claims=(*bundle.claims, trend_claim),
            analytical_candidates=(*bundle.candidates, trend_candidate),
            claim_review_decisions=(*bundle.decisions, trend_decision),
            trend_claim_id=trend_claim.claim_id,
        )
