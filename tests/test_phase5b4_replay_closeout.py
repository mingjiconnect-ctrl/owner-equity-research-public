from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from test_phase5b3_readiness_routing import (
    KERNEL,
    _compile_and_bind,
    _research_graph,
)

from owner_research.analytical_claims import review_analytical_claim_candidate
from owner_research.fingerprints import canonical_sha256, to_json_value
from owner_research.quarterly import reconcile_metric
from owner_research.research_bundle_artifacts import write_research_bundle_artifacts
from owner_research.research_bundle_builder import build_research_bundle
from owner_research.valuation_fact_mapping import compile_price_blind_fact_ledger
from owner_research.valuation_readiness import (
    _classification,
    _method_readiness,
    _reviewed_specialist_claims,
    _validated_closure,
    assess_method_readiness,
)

ROOT = Path(__file__).parents[1]
GOLDEN = ROOT / "tests/fixtures/phase5b/golden-readiness-cases.json"


def _direct_panels(classification, *, ledger_facts, closure):
    mckinsey, _ = _method_readiness(
        "mckinsey",
        classification=classification,
        ledger_facts=ledger_facts,
        closure=closure,
    )
    penman, _ = _method_readiness(
        "penman",
        classification=classification,
        ledger_facts=ledger_facts,
        closure=closure,
    )
    return mckinsey.status, penman.status


def _multi_segment_classification(*, closure, ledger_facts, issuer_id, cutoff):
    model_key, model = next(
        (identifier, item)
        for identifier, (kind, item) in closure.items()
        if kind == "BusinessModelSnapshot"
    )
    first = to_json_value(model.material_scopes[0])
    scopes = tuple(
        {
            **first,
            "scope_id": f"scope:segment:{slug}",
            "scope": {
                **first["scope"],
                "scope_type": "segment_specific",
                "segment_definition_ids": [f"segment:{slug}"],
                "business_unit": slug,
            },
        }
        for slug in ("a", "b")
    )
    replay = {
        **closure,
        model_key: (
            "BusinessModelSnapshot",
            replace(model, material_scopes=scopes),
        ),
    }
    return _classification(
        closure=replay,
        ledger_facts=ledger_facts,
        issuer_id=issuer_id,
        cutoff=cutoff,
    ), replay


def _with_specialist_claim(graph, statement: str):
    base_candidate = next(
        item for item in graph.analytical_claim_candidates if item.claim_role == "support"
    )
    evidence_fact_id = next(
        item.fact_id
        for item in graph.facts
        if item.fact_id.startswith("fact:acme:operating_income:2025-12-31")
    )
    supporting = (
        {
            "binding_id": f"binding:phase5:{canonical_sha256(statement)[:12]}",
            "fact_id": evidence_fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        },
    )
    candidate = replace(
        base_candidate,
        candidate_id=f"analytical-candidate:acme:{canonical_sha256(statement)[:12]}",
        proposed_statement=statement,
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        claim_role="support",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=supporting,
        counterevidence_bindings=(),
        counterevidence_search_note="Reviewed official evidence for contrary classifications.",
        falsification_condition="Verified contrary operating evidence changes this route.",
        evidence_graph_sha256=canonical_sha256(
            {
                "supporting_evidence_bindings": supporting,
                "counterevidence_bindings": (),
            }
        ),
    )
    claim, decision = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id="human:phase5-golden-reviewer",
        reviewed_at="2026-06-30T12:00:00Z",
        rationale="Official evidence and mapped financial context were reviewed.",
    )
    assert claim is not None
    review = graph.business_quality_reviews[0]
    coverage = dict(review.coverage)
    coverage["confirmed_claim_count"] += 1
    review = replace(
        review,
        claim_ids=tuple(sorted({*review.claim_ids, claim.claim_id})),
        analytical_claim_review_decision_ids=tuple(
            sorted(
                {
                    *review.analytical_claim_review_decision_ids,
                    decision.decision_id,
                }
            )
        ),
        coverage=coverage,
    )
    return replace(
        graph,
        claims=(*graph.claims, claim),
        analytical_claim_candidates=(*graph.analytical_claim_candidates, candidate),
        analytical_claim_review_decisions=(
            *graph.analytical_claim_review_decisions,
            decision,
        ),
        business_quality_reviews=(review,),
    )


def test_all_eight_golden_readiness_cases_replay(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    payload = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0.0"
    assert len(payload["cases"]) == 8
    for case in payload["cases"]:
        source = _research_graph(
            sample_payloads,
            sic=case["sic"],
            omit=frozenset(case["omit"]),
        )
        if case["mode"] == "specialist_claim":
            source = _with_specialist_claim(source, case["statement"])
        graph, mapping = _compile_and_bind(source, tmp_path / case["case_id"])
        if case["mode"] in {"public", "specialist_claim"}:
            if case["mode"] == "specialist_claim":
                _, specialist_closure = _validated_closure(graph, mapping)
                assert any(
                    kind == "Claim" and item.statement == case["statement"]
                    for kind, item in specialist_closure.values()
                )
                specialist_claim = next(
                    item
                    for kind, item in specialist_closure.values()
                    if kind == "Claim" and item.statement == case["statement"]
                )
                mapped_ids = {
                    item["fact_id"] for item in mapping.ledger_payload["facts"]
                }
                assert set(specialist_claim.supporting_fact_ids).intersection(mapped_ids)
                matching_candidates = [
                    item
                    for kind, item in specialist_closure.values()
                    if kind == "AnalyticalClaimCandidate"
                    and item.proposed_statement == case["statement"]
                ]
                assert matching_candidates, {
                    "review_decision_ids": list(
                        graph.business_quality_reviews[0].analytical_claim_review_decision_ids
                    ),
                    "closure_decisions": [
                        (item.decision_id, item.candidate_id, item.output_claim_id)
                        for kind, item in specialist_closure.values()
                        if kind == "AnalyticalClaimReviewDecision"
                    ],
                }
                specialist_candidate = matching_candidates[0]
                specialist_decision = next(
                    item
                    for kind, item in specialist_closure.values()
                    if kind == "AnalyticalClaimReviewDecision"
                    and item.output_claim_id == specialist_claim.claim_id
                )
                gates = {
                    "decision_confirmed": specialist_decision.decision == "confirmed",
                    "candidate_linked": (
                        specialist_decision.candidate_id
                        == specialist_candidate.candidate_id
                    ),
                    "claim_registered": specialist_claim.statement == case["statement"],
                    "support_role": specialist_candidate.claim_role == "support",
                    "issuer_scope": (
                        specialist_candidate.scope["scope_type"] == "issuer_wide"
                    ),
                    "no_attribute_role": (
                        specialist_candidate.business_attribute_role is None
                    ),
                    "no_component_type": (
                        specialist_candidate.business_component_type is None
                    ),
                    "cutoff_safe": (
                        specialist_claim.as_of_date
                        <= graph.research_bundles[0].data_cutoff_date
                    ),
                }
                assert all(gates.values()), gates
                reviewed = _reviewed_specialist_claims(
                    closure=specialist_closure,
                    mapped_fact_ids=mapped_ids,
                    cutoff=graph.research_bundles[0].data_cutoff_date,
                )
                assert reviewed
            result = assess_method_readiness(graph=graph, mapping_result=mapping)
            classification = result.classification
            statuses = (result.mckinsey.status, result.penman.status)
        else:
            bundle, closure = _validated_closure(graph, mapping)
            ledger_facts = tuple(
                dict(item) for item in to_json_value(mapping.ledger_payload)["facts"]
            )
            if case["mode"] == "multi_segment":
                classification, replay = _multi_segment_classification(
                    closure=closure,
                    ledger_facts=ledger_facts,
                    issuer_id=bundle.issuer_id,
                    cutoff=bundle.data_cutoff_date,
                )
            statuses = _direct_panels(
                classification,
                ledger_facts=ledger_facts,
                closure=replay,
            )
        assert classification.company_type == case["company_type"]
        assert classification.specialist_route == case["specialist_route"]
        assert statuses == (case["mckinsey"], case["penman"])


def test_full_mapping_and_readiness_replay_is_byte_stable_and_history_independent(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    source = _research_graph(sample_payloads)
    build = build_research_bundle(source, run_id=source.manifests[0].run_id)
    output = tmp_path / "bundle"
    write_research_bundle_artifacts(source, build, output_directory=output)
    first_mapping = compile_price_blind_fact_ledger(
        bundle_artifact_directory=output,
        graph=source,
        kernel_repository=KERNEL,
    )
    second_mapping = compile_price_blind_fact_ledger(
        bundle_artifact_directory=output,
        graph=replace(
            source,
            documents=tuple(reversed(source.documents)),
            facts=tuple(reversed(source.facts)),
        ),
        kernel_repository=KERNEL,
    )
    assert first_mapping.ledger_payload == second_mapping.ledger_payload
    assert first_mapping.fingerprint == second_mapping.fingerprint

    bound = replace(
        source,
        manifests=(build.run_manifest,),
        research_bundles=(build.bundle,),
    )
    first_readiness = assess_method_readiness(graph=bound, mapping_result=first_mapping)
    historical = replace(
        source.facts[0],
        fact_id="fact:acme:unreferenced-history",
        period={"start": "2010-01-01", "end": "2010-12-31"},
    )
    replay = assess_method_readiness(
        graph=replace(bound, facts=(*reversed(bound.facts), historical)),
        mapping_result=first_mapping,
    )
    assert first_readiness.to_dict() == replay.to_dict()
    assert first_readiness.fingerprint == replay.fingerprint


def _amended_graph(graph, original_id: str):
    current_period = next(
        item
        for item in graph.periods
        if item.period_id == graph.quarterly_updates[0].current_period_id
    )
    original = next(item for item in graph.facts if item.fact_id == original_id)
    amendment_document = replace(
        graph.documents[0],
        document_id="doc:acme:2025-10ka",
        document_type="10-K/A",
        published_date="2026-03-01",
        content_sha256="d" * 64,
    )
    amended = replace(
        original,
        fact_id="fact:acme:revenue:2025-amended",
        value=float(original.value) + 25.0,
        source_document_id=amendment_document.document_id,
        source_locator="10-K/A income statement",
    )
    documents = {item.document_id: item for item in (*graph.documents, amendment_document)}
    reconciliation, delta = reconcile_metric(
        (original, amended),
        documents,
        current_period,
        basis="ytd",
        tolerance=0.01,
        generated_at="2026-03-01T12:00:00Z",
    )
    assert delta is not None and reconciliation.status == "restated_authority"
    update = replace(
        graph.quarterly_updates[0],
        fact_ids=tuple(sorted({*graph.quarterly_updates[0].fact_ids, amended.fact_id})),
        calculation_result_ids=tuple(
            sorted({*graph.quarterly_updates[0].calculation_result_ids, delta.calculation_id})
        ),
        reconciliation_ids=(reconciliation.reconciliation_id,),
    )
    manifest = replace(
        graph.manifests[0],
        input_document_hashes={
            **dict(graph.manifests[0].input_document_hashes),
            amendment_document.document_id: amendment_document.content_sha256,
        },
    )
    return replace(
        graph,
        documents=(*graph.documents, amendment_document),
        facts=(*graph.facts, amended),
        calculations=(*graph.calculations, delta),
        reconciliations=(reconciliation,),
        quarterly_updates=(update,),
        manifests=(manifest,),
    ), original, amended


def test_valid_amendment_changes_selection_while_unversioned_conflict_blocks(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    base = _research_graph(sample_payloads)
    _, base_mapping = _compile_and_bind(base, tmp_path / "base")
    original_id = next(
        item["fact_id"]
        for item in base_mapping.ledger_payload["facts"]
        if item["concept"] == "revenue"
    )
    amended_graph, original, amended = _amended_graph(base, original_id)
    amended_bound, amended_mapping = _compile_and_bind(amended_graph, tmp_path / "amended")
    amended_ids = {item["fact_id"] for item in amended_mapping.ledger_payload["facts"]}
    assert amended.fact_id in amended_ids
    assert original.fact_id not in amended_ids
    assert amended_mapping.fingerprint != base_mapping.fingerprint
    amended_readiness = assess_method_readiness(
        graph=amended_bound,
        mapping_result=amended_mapping,
    )
    assert amended_readiness.mckinsey.status == "ready"

    conflict = replace(
        original,
        fact_id="fact:acme:revenue:2025-conflict",
        value=float(original.value) + 10.0,
    )
    update = replace(
        base.quarterly_updates[0],
        fact_ids=tuple(sorted({*base.quarterly_updates[0].fact_ids, conflict.fact_id})),
    )
    conflict_graph = replace(
        base,
        facts=(*base.facts, conflict),
        quarterly_updates=(update,),
    )
    conflict_bound, conflict_mapping = _compile_and_bind(
        conflict_graph,
        tmp_path / "conflict",
    )
    decisions = {
        item.object_id: item
        for item in conflict_mapping.decisions
        if item.object_type == "Fact"
    }
    assert decisions[original.fact_id].disposition == "blocked"
    assert decisions[conflict.fact_id].disposition == "blocked"
    readiness = assess_method_readiness(
        graph=conflict_bound,
        mapping_result=conflict_mapping,
    )
    assert readiness.mckinsey.status == readiness.penman.status == "partial"
