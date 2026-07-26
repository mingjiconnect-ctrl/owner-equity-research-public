from __future__ import annotations

import os
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from phase4e2_support import complete_phase4e_graph

from owner_research.analytical_claims import review_analytical_claim_candidate
from owner_research.fingerprints import canonical_sha256, to_json_value
from owner_research.research_bundle_artifacts import write_research_bundle_artifacts
from owner_research.research_bundle_builder import build_research_bundle
from owner_research.valuation_fact_mapping import compile_price_blind_fact_ledger
from owner_research.valuation_readiness import (
    ValuationReadinessError,
    _classification,
    _validated_closure,
    assess_method_readiness,
)

KERNEL = Path(
    os.environ.get(
        "OWNER_VALUATION_REPO",
        str(Path(__file__).parents[2] / "owner-valuation-kernel"),
    )
)


def _fact(seed, concept: str, value: float, *, prior: bool = False):
    stock = concept in {
        "total_assets",
        "total_liabilities",
        "common_equity",
        "cash_and_cash_equivalents",
        "interest_bearing_debt",
        "beginning_common_equity",
        "ending_common_equity",
        "sec_sic_code",
    }
    end = "2024-12-31" if prior or concept == "beginning_common_equity" else "2025-12-31"
    period = {"start": None, "end": end} if stock else {
        "start": "2025-01-01",
        "end": "2025-12-31",
    }
    unit = "currency_millions"
    currency = "USD"
    if concept == "diluted_shares":
        unit = "shares"
        currency = None
    elif concept == "sec_sic_code":
        unit = "count"
        currency = None
    return replace(
        seed,
        fact_id=f"fact:acme:{concept}:{end}{':prior' if prior else ''}",
        concept=concept,
        value=value,
        unit=unit,
        currency=currency,
        period=period,
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )


def _research_graph(
    sample_payloads: dict[str, dict],
    *,
    sic: int | None = 7372,
    omit: frozenset[str] = frozenset(),
):
    graph = complete_phase4e_graph(sample_payloads)
    official = replace(
        graph.documents[0],
        source_url="https://www.sec.gov/Archives/edgar/data/1/acme-20251231.htm",
    )
    seed = graph.facts[0]
    values = {
        "revenue": 1500.0,
        "operating_income": 225.0,
        "pretax_income": 210.0,
        "income_tax_expense": 42.0,
        "net_income": 168.0,
        "comprehensive_income": 175.0,
        "total_assets": 2500.0,
        "total_liabilities": 1500.0,
        "common_equity": 1000.0,
        "beginning_common_equity": 900.0,
        "ending_common_equity": 1000.0,
        "cash_and_cash_equivalents": 350.0,
        "interest_bearing_debt": 500.0,
        "diluted_shares": 100_000_000.0,
    }
    facts = [
        _fact(seed, concept, value)
        for concept, value in values.items()
        if concept not in omit
    ]
    if "interest_bearing_debt" not in omit:
        facts.append(_fact(seed, "interest_bearing_debt", 480.0, prior=True))
    if sic is not None:
        facts.append(_fact(seed, "sec_sic_code", float(sic)))
    update = replace(
        graph.quarterly_updates[0],
        fact_ids=tuple(
            sorted(
                {
                    *graph.quarterly_updates[0].fact_ids,
                    *(item.fact_id for item in facts),
                }
            )
        ),
    )
    return replace(
        graph,
        documents=(official, *graph.documents[1:]),
        facts=(*graph.facts, *facts),
        quarterly_updates=(update,),
    )


def _compile_and_bind(graph, path: Path):
    build = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    output = path / "bundle"
    write_research_bundle_artifacts(graph, build, output_directory=output)
    mapping = compile_price_blind_fact_ledger(
        bundle_artifact_directory=output,
        graph=graph,
        kernel_repository=KERNEL,
    )
    bound = replace(
        graph,
        manifests=(build.run_manifest,),
        research_bundles=(build.bundle,),
    )
    return bound, mapping


def test_standard_nonfinancial_recomputes_separate_ready_panels(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph, mapping = _compile_and_bind(_research_graph(sample_payloads), tmp_path)
    result = assess_method_readiness(graph=graph, mapping_result=mapping)

    assert result.classification.company_type == "nonfinancial_operating_company"
    assert result.specialist_route == "none"
    assert result.mckinsey.status == "ready"
    assert result.penman.status == "ready"
    assert set(result.classification.routing_assessments) == {
        "required_data_complete",
        "stable_capital_structure",
        "operating_financing_separable",
        "credible_noa",
        "credible_near_term_earnings",
        "equity_bridge_complete",
    }
    assert (
        result.classification.routing_assessments["required_data_complete"]["value"]
        is False
    )
    assert (
        result.classification.routing_assessments["equity_bridge_complete"]["status"]
        == "blocked"
    )
    assert all(not fact_id.startswith("fact:acme:sec_sic_code") for fact_id in (
        item["fact_id"] for item in mapping.ledger_payload["facts"]
    ))
    with pytest.raises(FrozenInstanceError):
        result.mckinsey.status = "partial"  # type: ignore[misc]


def test_method_readiness_can_be_asymmetric_and_bundle_complete_is_not_ready(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    asymmetric_graph, asymmetric_mapping = _compile_and_bind(
        _research_graph(sample_payloads, omit=frozenset({"diluted_shares"})),
        tmp_path / "asymmetric",
    )
    asymmetric = assess_method_readiness(
        graph=asymmetric_graph,
        mapping_result=asymmetric_mapping,
    )
    assert asymmetric.mckinsey.status == "partial"
    assert asymmetric.mckinsey.missing_roles == ("diluted_shares",)
    assert asymmetric.penman.status == "ready"

    sparse_graph, sparse_mapping = _compile_and_bind(
        _research_graph(
            sample_payloads,
            omit=frozenset(
                {
                    "pretax_income",
                    "income_tax_expense",
                    "net_income",
                    "comprehensive_income",
                    "total_assets",
                    "total_liabilities",
                    "common_equity",
                    "beginning_common_equity",
                    "ending_common_equity",
                    "cash_and_cash_equivalents",
                    "interest_bearing_debt",
                    "diluted_shares",
                }
            ),
        ),
        tmp_path / "sparse",
    )
    sparse = assess_method_readiness(graph=sparse_graph, mapping_result=sparse_mapping)
    assert sparse_graph.research_bundles[0].status == "complete"
    assert sparse.mckinsey.status == sparse.penman.status == "partial"


@pytest.mark.parametrize(
    ("sic", "company_type"),
    ((6021, "bank"), (6331, "insurer")),
)
def test_financial_issuers_require_specialist_route(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
    sic: int,
    company_type: str,
) -> None:
    graph, mapping = _compile_and_bind(
        _research_graph(sample_payloads, sic=sic),
        tmp_path / company_type,
    )
    result = assess_method_readiness(graph=graph, mapping_result=mapping)
    assert result.classification.company_type == company_type
    assert result.specialist_route == "financial_institution"
    assert result.mckinsey.status == result.penman.status == "specialist_required"
    assert (
        result.classification.routing_assessments["operating_financing_separable"]["value"]
        is False
    )


def test_missing_official_classification_blocks_both_methods(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph, mapping = _compile_and_bind(
        _research_graph(sample_payloads, sic=None),
        tmp_path,
    )
    result = assess_method_readiness(graph=graph, mapping_result=mapping)
    assert result.classification.company_type == "unresolved"
    assert result.specialist_route == "unresolved"
    assert result.mckinsey.status == result.penman.status == "blocked"
    assert "official_classification_missing" in result.mckinsey.reason_codes


def test_unregistered_financial_sic_cannot_be_forced_into_core_route(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph, mapping = _compile_and_bind(
        _research_graph(sample_payloads, sic=6211),
        tmp_path,
    )
    result = assess_method_readiness(graph=graph, mapping_result=mapping)
    assert result.classification.company_type == "unresolved"
    assert result.specialist_route == "unresolved"
    assert result.mckinsey.status == result.penman.status == "blocked"


def test_multiple_material_segments_and_reviewed_specialist_claims_route_deterministically(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph, mapping = _compile_and_bind(_research_graph(sample_payloads), tmp_path)
    bundle, closure = _validated_closure(graph, mapping)
    ledger_facts = tuple(dict(item) for item in to_json_value(mapping.ledger_payload)["facts"])
    model_key, model = next(
        (identifier, item)
        for identifier, (kind, item) in closure.items()
        if kind == "BusinessModelSnapshot"
    )
    first = to_json_value(model.material_scopes[0])
    segment_a = {
        **first,
        "scope_id": "scope:segment:a",
        "scope": {
            **first["scope"],
            "scope_type": "segment_specific",
            "segment_definition_ids": ["segment:a"],
            "business_unit": "a",
        },
    }
    segment_b = {
        **segment_a,
        "scope_id": "scope:segment:b",
        "scope": {
            **segment_a["scope"],
            "segment_definition_ids": ["segment:b"],
            "business_unit": "b",
        },
    }
    segment_model = replace(model, material_scopes=(segment_a, segment_b))
    segment_closure = {**closure, model_key: ("BusinessModelSnapshot", segment_model)}
    segment_result = _classification(
        closure=segment_closure,
        ledger_facts=ledger_facts,
        issuer_id=bundle.issuer_id,
        cutoff=bundle.data_cutoff_date,
    )
    assert segment_result.company_type == "conglomerate"
    assert segment_result.specialist_route == "sum_of_parts"

    base_candidate = next(
        item for item in graph.analytical_claim_candidates if item.claim_role == "support"
    )
    revenue_id = next(
        item["fact_id"] for item in ledger_facts if item["concept"] == "revenue"
    )
    supporting = (
        {
            "binding_id": "binding:phase5:asset",
            "fact_id": revenue_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        },
    )
    candidate = replace(
        base_candidate,
        candidate_id="analytical-candidate:acme:phase5-asset",
        proposed_statement="Phase 5 routing classification: asset-based company.",
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
        falsification_condition="Verified operating evidence would falsify the asset route.",
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
        reviewer_id="human:phase5-reviewer",
        reviewed_at="2026-06-30T12:00:00Z",
        rationale="Official evidence and mapped financial context were reviewed.",
    )
    assert claim is not None
    specialist_closure = {
        **closure,
        candidate.candidate_id: ("AnalyticalClaimCandidate", candidate),
        decision.decision_id: ("AnalyticalClaimReviewDecision", decision),
        claim.claim_id: ("Claim", claim),
    }
    specialist = _classification(
        closure=specialist_closure,
        ledger_facts=ledger_facts,
        issuer_id=bundle.issuer_id,
        cutoff=bundle.data_cutoff_date,
    )
    assert specialist.company_type == "asset_based"
    assert specialist.specialist_route == "nav_or_asset"


def test_readiness_rejects_unbound_or_tampered_mapping_result(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    unbound = _research_graph(sample_payloads)
    graph, mapping = _compile_and_bind(unbound, tmp_path)
    with pytest.raises(ValuationReadinessError, match="bound ResearchBundle"):
        assess_method_readiness(graph=unbound, mapping_result=mapping)
    with pytest.raises(ValuationReadinessError, match="differ"):
        assess_method_readiness(
            graph=graph,
            mapping_result=replace(mapping, research_bundle_fingerprint="0" * 64),
        )


def test_readiness_entrypoint_is_internal_and_has_no_market_or_kernel_runtime_import() -> None:
    import owner_research
    import owner_research.valuation_readiness as module

    assert not hasattr(owner_research, "assess_method_readiness")
    assert "MarketReferenceSnapshot" not in module.__dict__
    assert "owner_valuation" not in module.__dict__
