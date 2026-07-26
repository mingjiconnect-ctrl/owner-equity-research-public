from __future__ import annotations

import copy
from dataclasses import replace

from phase4a_support import contract, valid_phase4a_graph

from owner_research.business_models import BUSINESS_ATTRIBUTE_ROLES
from owner_research.calculation_integrity import build_calculation_result
from owner_research.component_lock import file_sha256
from owner_research.contracts import Contract, contract_from_dict
from owner_research.fingerprints import canonical_sha256, to_json_value
from owner_research.footnotes import REQUIRED_TOPICS
from owner_research.validation import CONTEXT_TOPICS, PHASE4_MECHANISMS, ContractGraph


def _analytical_chain(
    sample_payloads: dict[str, dict],
    *,
    slug: str,
    fact_id: str,
    scope: dict,
    claim_role: str,
    business_attribute_role: str | None,
    business_component_type: str | None,
):
    statement = f"Reviewed evidence supports {slug}."
    claim = contract(
        sample_payloads,
        "claim",
        claim_id=f"claim:acme:{slug}",
        statement=statement,
        as_of_date="2026-02-16",
        supporting_fact_ids=[fact_id],
        counterevidence_fact_ids=[],
        counterevidence_search_note=f"Reviewed official evidence for {slug} counterevidence.",
        falsification_condition=f"Verified contrary evidence falsifies {slug}.",
    )
    supporting = [
        {
            "binding_id": f"binding:acme:{slug}",
            "fact_id": fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
    ]
    evidence_hash = canonical_sha256(
        {
            "supporting_evidence_bindings": supporting,
            "counterevidence_bindings": [],
        }
    )
    candidate = contract(
        sample_payloads,
        "analytical-claim-candidate",
        candidate_id=f"analytical-candidate:acme:{slug}",
        proposed_statement=statement,
        scope=scope,
        claim_role=claim_role,
        business_attribute_role=business_attribute_role,
        business_component_type=business_component_type,
        supporting_evidence_bindings=supporting,
        counterevidence_bindings=[],
        counterevidence_search_note=claim.counterevidence_search_note,
        proposed_confidence=claim.confidence,
        falsification_condition=claim.falsification_condition,
        evidence_graph_sha256=evidence_hash,
    )
    decision = contract(
        sample_payloads,
        "analytical-claim-review-decision",
        decision_id=f"analytical-review:acme:{slug}",
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=candidate.fingerprint,
        evidence_graph_sha256=evidence_hash,
        output_claim_id=claim.claim_id,
    )
    return claim, candidate, decision


def complete_phase4e_graph(sample_payloads: dict[str, dict]) -> ContractGraph:
    base = valid_phase4a_graph(sample_payloads)
    target_document = base.documents[0]
    external_document = replace(
        target_document,
        document_id="doc:industry:2025",
        issuer_id="issuer:industry",
        document_type="industry-report",
        source_url="https://industry.example.com/report",
        authority_level="audited_secondary",
        content_sha256="8" * 64,
    )
    fact = base.facts[0]
    prior_period = replace(
        base.periods[0],
        period_id="period:acme:2024-q4",
        fiscal_year=2024,
        quarter_start="2024-10-01",
        quarter_end="2024-12-31",
        cumulative_start="2024-01-01",
        cumulative_end="2024-12-31",
        ttm_start="2024-01-01",
        comparative_period_id=None,
    )
    current_period = replace(
        base.periods[0],
        comparative_period_id=prior_period.period_id,
    )
    comparability_facts = tuple(
        replace(
            fact,
            fact_id=f"fact:acme:{concept}:2025-q4",
            concept=concept,
            value_type="boolean",
            value=False,
            unit=None,
            currency=None,
            period={
                "start": current_period.quarter_start,
                "end": current_period.quarter_end,
            },
        )
        for concept in ("material_acquisition", "fx_material", "one_time_tax")
    )
    calculation = build_calculation_result(
        {
            **copy.deepcopy(sample_payloads["calculation-result"]),
            "calculation_id": "calc:acme:revenue-segment-reconciliation",
            "concept": "revenue.segment_reconciliation_delta",
            "value": 0.0,
            "unit": fact.unit,
            "currency": fact.currency,
            "period": {
                "start": current_period.cumulative_start,
                "end": current_period.cumulative_end,
            },
            "calculator_id": "segment-reconciliation",
            "calculator_version": "1.0.0",
            "input_fact_ids": [fact.fact_id],
            "input_assumption_ids": [],
            "input_calculation_ids": [],
            "input_period_ids": [current_period.period_id],
            "input_bindings": {"consolidated": fact.fact_id, "segment": fact.fact_id},
        },
        facts={fact.fact_id: fact},
        assumptions={},
        calculations={},
        periods={current_period.period_id: current_period},
    )
    segment_snapshot = replace(
        base.segment_snapshots[0],
        status="complete",
        reconciliation_calculation_ids=(calculation.calculation_id,),
        missing_evidence=(),
    )
    quarterly_update = contract(
        sample_payloads,
        "quarterly-update",
        update_id="quarterly-update:acme:2025-q4",
        as_of_date="2026-02-16",
        current_period_id=current_period.period_id,
        comparison_period_id=prior_period.period_id,
        status="complete",
        comparability={"status": "comparable", "reasons": []},
        fact_ids=[fact.fact_id, *(item.fact_id for item in comparability_facts)],
        calculation_result_ids=[calculation.calculation_id],
        reconciliation_ids=[],
        what_changed_claim_ids=[base.claims[0].claim_id],
        why_it_changed_claim_ids=[base.claims[0].claim_id],
        temporary_or_structural_claim_ids=[base.claims[0].claim_id],
        guidance_change_claim_ids=[base.claims[0].claim_id],
        long_term_thesis_impact_claim_ids=[base.claims[0].claim_id],
        impact_on_valuation_assumptions_claim_ids=[],
        valuation_assumption_review_required=False,
        missing_evidence=[],
        red_flags=[],
    )

    footnotes = tuple(
        contract(
            sample_payloads,
            "footnote-review",
            review_id=f"footnote:acme:{topic}",
            topic_code=topic,
            status="reviewed",
            source_document_ids=[target_document.document_id],
            candidate_ids=[],
            fact_ids=[fact.fact_id],
            claim_ids=[base.claims[0].claim_id],
            calculation_result_ids=[],
            missing_evidence=[],
        )
        for topic in sorted(REQUIRED_TOPICS)
    )
    accounting_review = contract(
        sample_payloads,
        "accounting-quality-review",
        review_id="quality-review:acme:2025-complete",
        status="complete",
        required_topic_codes=sorted(REQUIRED_TOPICS),
        footnote_review_ids=[item.review_id for item in footnotes],
        finding_ids=[],
        coverage={
            "required_count": len(REQUIRED_TOPICS),
            "reviewed_count": len(REQUIRED_TOPICS),
            "not_disclosed_count": 0,
            "not_applicable_count": 0,
            "blocked_count": 0,
        },
        missing_evidence=[],
    )

    scope = to_json_value(base.business_model_snapshots[0].material_scopes[0]["scope"])
    claims = list(base.claims)
    candidates = list(base.analytical_claim_candidates)
    decisions = list(base.analytical_claim_review_decisions)
    components = []
    coverage = []
    scope_id = base.business_model_snapshots[0].material_scopes[0]["scope_id"]
    for component_type, roles in BUSINESS_ATTRIBUTE_ROLES.items():
        bindings = []
        component_claim_ids = []
        for role in sorted(roles):
            slug = f"business-{component_type}-{role}"
            claim, candidate, decision = _analytical_chain(
                sample_payloads,
                slug=slug,
                fact_id=fact.fact_id,
                scope=scope,
                claim_role="support",
                business_attribute_role=role,
                business_component_type=component_type,
            )
            claims.append(claim)
            candidates.append(candidate)
            decisions.append(decision)
            component_claim_ids.append(claim.claim_id)
            bindings.append(
                {
                    "binding_id": f"attribute-binding:acme:{component_type}:{role}",
                    "role": role,
                    "fact_ids": [fact.fact_id],
                    "claim_ids": [claim.claim_id],
                    "review_decision_ids": [decision.decision_id],
                }
            )
        component_id = f"component:acme:{component_type}:complete"
        components.append(
            {
                "component_id": component_id,
                "component_type": component_type,
                "scope_id": scope_id,
                "scope": scope,
                "attribute_roles": sorted(roles),
                "attribute_evidence_bindings": bindings,
                "fact_ids": [fact.fact_id],
                "claim_ids": component_claim_ids,
            }
        )
        coverage.append(
            {
                "scope_id": scope_id,
                "component_type": component_type,
                "status": "reviewed",
                "component_ids": [component_id],
                "claim_ids": [],
                "review_decision_ids": [],
                "missing_evidence": [],
            }
        )
    business_model = replace(
        base.business_model_snapshots[0],
        status="complete",
        source_document_ids=(target_document.document_id,),
        segment_snapshot_ids=(segment_snapshot.snapshot_id,),
        components=tuple(components),
        component_coverage=tuple(coverage),
        missing_evidence=(),
    )

    external_observation = replace(
        base.context_observations[0],
        observation_id="context-observation:acme:industry",
        subject={"entity_id": "issuer:industry", "entity_name": "Industry", "role": "industry"},
        statement="Independent industry evidence was reviewed.",
        source_document_id=external_document.document_id,
        source_locator="section:industry",
    )
    competitor_claim_id = components[0]["claim_ids"][0]
    context = replace(
        base.competitive_context_snapshots[0],
        status="complete",
        source_document_ids=(target_document.document_id, external_document.document_id),
        observation_ids=(
            base.context_observations[0].observation_id,
            external_observation.observation_id,
        ),
        competitor_selection_claim_ids=(competitor_claim_id,),
        coverage=tuple(
            {
                "topic": topic,
                "status": "reviewed",
                "observation_ids": [external_observation.observation_id],
                "claim_ids": [],
                "missing_evidence": [],
            }
            for topic in sorted(CONTEXT_TOPICS)
        ),
        missing_evidence=(),
    )
    na_claim, na_candidate, na_decision = _analytical_chain(
        sample_payloads,
        slug="mechanisms-not-applicable",
        fact_id=fact.fact_id,
        scope=scope,
        claim_role="not_applicable",
        business_attribute_role=None,
        business_component_type=None,
    )
    claims.append(na_claim)
    candidates.append(na_candidate)
    decisions.append(na_decision)
    business_review = replace(
        base.business_quality_reviews[0],
        status="complete",
        business_model_snapshot_id=business_model.snapshot_id,
        competitive_context_snapshot_id=context.context_snapshot_id,
        hypothesis_ids=(),
        mechanism_coverage=tuple(
            {
                "mechanism": mechanism,
                "status": "not_applicable",
                "hypothesis_ids": [],
                "claim_ids": [na_claim.claim_id],
                "missing_evidence": [],
            }
            for mechanism in sorted(PHASE4_MECHANISMS)
        ),
        claim_ids=(na_claim.claim_id,),
        analytical_claim_review_decision_ids=(na_decision.decision_id,),
        context_observation_ids=(
            base.context_observations[0].observation_id,
            external_observation.observation_id,
        ),
        calculation_result_ids=(),
        coverage={
            "reviewed_component_count": len(BUSINESS_ATTRIBUTE_ROLES),
            "not_applicable_component_count": 0,
            "blocked_component_count": 0,
            "proposed_hypothesis_count": 0,
            "supported_hypothesis_count": 0,
            "contested_hypothesis_count": 0,
            "falsified_hypothesis_count": 0,
            "blocked_hypothesis_count": 0,
            "strengthening_count": 0,
            "stable_count": 0,
            "eroding_count": 0,
            "unknown_trend_count": 0,
            "confirmed_claim_count": 1,
            "unresolved_counterevidence_count": 0,
        },
        missing_evidence=(),
    )
    management_review = replace(
        base.management_reviews[0],
        status="complete",
        missing_evidence=(),
    )
    manifest_payload = copy.deepcopy(sample_payloads["run-manifest"])
    manifest_payload.update(
        {
            "run_id": "run:acme:phase4e2-complete",
            "data_cutoff_date": "2026-06-30",
            "started_at": "2026-07-01T00:00:00Z",
            "completed_at": "2026-07-01T01:00:00Z",
            "component_lock_sha256": file_sha256(base.component_lock_path),
            "component_versions": {"owner-equity-research": "0.4.0-alpha.1"},
            "input_document_hashes": {
                target_document.document_id: target_document.content_sha256,
                external_document.document_id: external_document.content_sha256,
            },
            "output_artifact_hashes": {},
            "missing_evidence": [],
        }
    )
    manifest = contract_from_dict("run-manifest", manifest_payload)
    assert isinstance(manifest, Contract)
    return ContractGraph(
        documents=(target_document, external_document),
        facts=(*base.facts, *comparability_facts),
        claims=tuple(claims),
        calculations=(calculation,),
        periods=(prior_period, current_period),
        quarterly_updates=(quarterly_update,),
        segment_definitions=base.segment_definitions,
        segment_snapshots=(segment_snapshot,),
        footnote_reviews=footnotes,
        accounting_quality_reviews=(accounting_review,),
        context_observations=(base.context_observations[0], external_observation),
        competitive_context_snapshots=(context,),
        analytical_claim_candidates=tuple(candidates),
        analytical_claim_review_decisions=tuple(decisions),
        business_model_snapshots=(business_model,),
        competitive_advantage_hypotheses=(),
        business_quality_reviews=(business_review,),
        management_statements=base.management_statements,
        management_statement_candidates=base.management_statement_candidates,
        management_statement_review_decisions=base.management_statement_review_decisions,
        management_commitments=base.management_commitments,
        management_outcomes=base.management_outcomes,
        capital_allocation_event_candidates=base.capital_allocation_event_candidates,
        capital_allocation_event_review_decisions=base.capital_allocation_event_review_decisions,
        capital_allocation_events=base.capital_allocation_events,
        capital_allocation_outcomes=base.capital_allocation_outcomes,
        source_search_receipts=base.source_search_receipts,
        management_reviews=(management_review,),
        capital_allocation_reviews=base.capital_allocation_reviews,
        manifests=(manifest,),
        component_lock_path=base.component_lock_path,
    )
