from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from test_phase5b1_raw_fact_compiler import (
    KERNEL,
    _artifacts,
    _decision,
    _graph_with_raw_facts,
)

from owner_research.calculation_integrity import build_calculation_result
from owner_research.contracts import Assumption, contract_from_dict
from owner_research.quarterly import derive_discrete_quarter, derive_ttm
from owner_research.research_bundle_builder import ResearchBundleBuildError, build_research_bundle
from owner_research.validation import ContractGraph, ContractGraphError
from owner_research.valuation_fact_mapping import compile_price_blind_fact_ledger


def _registered_calculation_graph(
    sample_payloads: dict[str, dict],
    *,
    split_discrete_source: bool = False,
    low_confidence_discrete_parent: bool = False,
) -> tuple[ContractGraph, str, str]:
    graph = _graph_with_raw_facts(sample_payloads)
    current_period = next(item for item in graph.periods if item.fiscal_year == 2025)
    official = graph.documents[0]
    q3_document = replace(
        official,
        document_id="doc:acme:2025-q3-10q",
        document_type="10-Q",
        period={"start": "2025-07-01", "end": "2025-09-30"},
        published_date="2025-11-01",
        source_url="https://www.sec.gov/Archives/edgar/data/1/acme-20250930.htm",
        content_sha256="9" * 64,
    )
    q3_period = replace(
        current_period,
        period_id="period:acme:2025-q3",
        fiscal_quarter=3,
        quarter_start="2025-07-01",
        quarter_end="2025-09-30",
        cumulative_end="2025-09-30",
        ttm_start="2024-10-01",
        comparative_period_id=None,
        source_document_ids=(
            (q3_document.document_id,) if split_discrete_source else (official.document_id,)
        ),
    )
    current_operating_income = next(
        item for item in graph.facts if item.fact_id == "fact:acme:operating-income:2025"
    )
    q3_operating_income = replace(
        current_operating_income,
        fact_id="fact:acme:operating-income:2025-q3-ytd",
        value=150.0,
        period={"start": "2025-01-01", "end": "2025-09-30"},
        source_document_id=(
            q3_document.document_id if split_discrete_source else official.document_id
        ),
        confidence="low" if low_confidence_discrete_parent else "high",
    )
    discrete = derive_discrete_quarter(
        current_operating_income,
        q3_operating_income,
        current_period,
        q3_period,
        generated_at="2026-06-29T00:00:00Z",
    )
    current_revenue_ytd = replace(
        current_operating_income,
        fact_id="fact:acme:revenue:2025-q3-ytd-input",
        concept="revenue",
        value=180.0,
        period={"start": "2025-01-01", "end": "2025-09-30"},
    )
    prior_revenue_fy = replace(
        current_revenue_ytd,
        fact_id="fact:acme:revenue:2024-fy-input",
        value=200.0,
        period={"start": "2024-01-01", "end": "2024-12-31"},
    )
    prior_revenue_ytd = replace(
        current_revenue_ytd,
        fact_id="fact:acme:revenue:2024-q3-ytd-input",
        value=140.0,
        period={"start": "2024-01-01", "end": "2024-09-30"},
    )
    ttm = derive_ttm(
        current_revenue_ytd,
        prior_revenue_fy,
        prior_revenue_ytd,
        q3_period,
        generated_at="2026-06-29T00:00:00Z",
    )
    update = replace(
        graph.quarterly_updates[0],
        calculation_result_ids=tuple(
            sorted(
                {
                    *graph.quarterly_updates[0].calculation_result_ids,
                    discrete.calculation_id,
                    ttm.calculation_id,
                }
            )
        ),
    )
    manifest = graph.manifests[0]
    if split_discrete_source:
        manifest = replace(
            manifest,
            input_document_hashes={
                **dict(manifest.input_document_hashes),
                q3_document.document_id: q3_document.content_sha256,
            },
        )
    return (
        replace(
            graph,
            documents=(
                (*graph.documents, q3_document)
                if split_discrete_source
                else graph.documents
            ),
            facts=(
                *graph.facts,
                q3_operating_income,
                current_revenue_ytd,
                prior_revenue_fy,
                prior_revenue_ytd,
            ),
            calculations=(*graph.calculations, discrete, ttm),
            periods=(*graph.periods, q3_period),
            quarterly_updates=(update,),
            manifests=(manifest,),
        ),
        discrete.calculation_id,
        ttm.calculation_id,
    )


def test_registered_single_quarter_and_ttm_results_map_with_full_lineage(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    graph, discrete_id, ttm_id = _registered_calculation_graph(sample_payloads)
    result = compile_price_blind_fact_ledger(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )
    facts = {item["fact_id"]: item for item in result.ledger_payload["facts"]}
    discrete = facts[f"derived:{discrete_id}"]
    ttm = facts[f"derived:{ttm_id}"]

    assert discrete["value"] == 75
    assert discrete["concept"] == "operating_income"
    assert discrete["period_start"] == "2025-10-01"
    assert discrete["period_end"] == "2025-12-31"
    assert discrete["parent_fact_ids"] == (
        "fact:acme:operating-income:2025",
        "fact:acme:operating-income:2025-q3-ytd",
    )
    assert discrete["derivation"] == (
        "owner-research-quarterly@0.2.0-alpha.1:single_quarter"
    )
    assert ttm["value"] == 240
    assert ttm["concept"] == "revenue"
    assert ttm["period_start"] == "2024-10-01"
    assert ttm["period_end"] == "2025-09-30"
    assert ttm["raw"] is False
    assert _decision(result, "CalculationResult", discrete_id).output_id == (
        f"derived:{discrete_id}"
    )
    assert _decision(result, "CalculationResult", ttm_id).disposition == "mapped"


def test_unregistered_diagnostic_calculation_stays_outside_kernel_ledger(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    graph, _, _ = _registered_calculation_graph(sample_payloads)
    result = compile_price_blind_fact_ledger(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )
    diagnostic = graph.calculations[0]
    decision = _decision(result, "CalculationResult", diagnostic.calculation_id)

    assert decision.disposition == "excluded"
    assert decision.reason_codes == ("calculation_not_registered",)
    assert not any(
        item["fact_id"] == f"derived:{diagnostic.calculation_id}"
        for item in result.ledger_payload["facts"]
    )


def test_derived_fact_requires_one_official_source_lineage(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    graph, discrete_id, ttm_id = _registered_calculation_graph(
        sample_payloads,
        split_discrete_source=True,
    )
    result = compile_price_blind_fact_ledger(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )

    assert _decision(result, "CalculationResult", discrete_id).reason_codes == (
        "calculation_source_ambiguous",
    )
    assert _decision(result, "CalculationResult", ttm_id).disposition == "mapped"


def test_unmapped_parent_blocks_derived_lineage_without_guessing(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    graph, discrete_id, _ = _registered_calculation_graph(
        sample_payloads,
        low_confidence_discrete_parent=True,
    )
    result = compile_price_blind_fact_ledger(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )

    assert _decision(result, "CalculationResult", discrete_id).reason_codes == (
        "lineage_incomplete",
    )


def test_registered_calculation_with_wrong_semantic_period_is_blocked(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    graph, _, ttm_id = _registered_calculation_graph(sample_payloads)
    ttm = next(item for item in graph.calculations if item.calculation_id == ttm_id)
    q3 = next(item for item in graph.periods if item.period_id == "period:acme:2025-q3")
    facts = {item.fact_id: item for item in graph.facts}
    calculations = {item.calculation_id: item for item in graph.calculations}
    payload = ttm.to_dict()
    payload["period"] = {"start": q3.cumulative_start, "end": q3.cumulative_end}
    wrong_period = build_calculation_result(
        payload,
        facts={identifier: facts[identifier] for identifier in ttm.input_fact_ids},
        assumptions={},
        calculations={
            identifier: calculations[identifier]
            for identifier in ttm.input_calculation_ids
        },
        periods={q3.period_id: q3},
    )
    changed = replace(
        graph,
        calculations=tuple(
            wrong_period if item.calculation_id == ttm_id else item
            for item in graph.calculations
        ),
    )
    result = compile_price_blind_fact_ledger(
        bundle_artifact_directory=_artifacts(changed, tmp_path / "bundle"),
        graph=changed,
        kernel_repository=KERNEL,
    )

    assert _decision(result, "CalculationResult", ttm_id).reason_codes == (
        "period_invalid",
    )


def test_tampered_calculation_fingerprint_and_assumption_lineage_fail_before_mapping(
    sample_payloads: dict[str, dict],
) -> None:
    graph, discrete_id, _ = _registered_calculation_graph(sample_payloads)
    tampered = replace(
        graph,
        calculations=tuple(
            replace(item, output_fingerprint="0" * 64)
            if item.calculation_id == discrete_id
            else item
            for item in graph.calculations
        ),
    )
    with pytest.raises(ContractGraphError, match="output_fingerprint"):
        tampered.validate()

    registered = next(item for item in graph.calculations if item.calculation_id == discrete_id)
    payload = registered.to_dict()
    payload["input_assumption_ids"] = ["assumption:acme:base-growth"]
    facts = {item.fact_id: item for item in graph.facts}
    periods = {item.period_id: item for item in graph.periods}
    research_assumption = contract_from_dict("assumption", sample_payloads["assumption"])
    assert isinstance(research_assumption, Assumption)
    with_assumption = build_calculation_result(
        payload,
        facts={identifier: facts[identifier] for identifier in registered.input_fact_ids},
        assumptions={research_assumption.assumption_id: research_assumption},
        calculations={},
        periods={identifier: periods[identifier] for identifier in registered.input_period_ids},
    )
    invalid_bundle_graph = replace(
        graph,
        assumptions=(research_assumption,),
        calculations=tuple(
            with_assumption if item.calculation_id == discrete_id else item
            for item in graph.calculations
        ),
    )
    with pytest.raises(ResearchBundleBuildError, match="Assumption"):
        build_research_bundle(
            invalid_bundle_graph,
            run_id=invalid_bundle_graph.manifests[0].run_id,
        )
