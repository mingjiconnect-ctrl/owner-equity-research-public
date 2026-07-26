from __future__ import annotations

import inspect
import os
from dataclasses import replace
from pathlib import Path

import pytest
from phase4e2_support import complete_phase4e_graph

from owner_research.research_bundle_artifacts import write_research_bundle_artifacts
from owner_research.research_bundle_builder import build_research_bundle
from owner_research.validation import ContractGraph
from owner_research.valuation_fact_mapping import (
    FactLedgerMappingError,
    compile_price_blind_fact_ledger,
)

KERNEL = Path(
    os.environ.get(
        "OWNER_VALUATION_REPO",
        str(Path(__file__).parents[2] / "owner-valuation-kernel"),
    )
)


def _graph_with_raw_facts(
    sample_payloads: dict[str, dict],
    *,
    extra_facts: tuple = (),
) -> ContractGraph:
    graph = complete_phase4e_graph(sample_payloads)
    official = replace(
        graph.documents[0],
        source_url="https://www.sec.gov/Archives/edgar/data/1/acme-20251231.htm",
    )
    base = graph.facts[0]
    operating_income = replace(
        base,
        fact_id="fact:acme:operating-income:2025",
        concept="operating_income",
        value=225.0,
    )
    update = replace(
        graph.quarterly_updates[0],
        fact_ids=tuple(
            sorted(
                {
                    *graph.quarterly_updates[0].fact_ids,
                    operating_income.fact_id,
                    *(item.fact_id for item in extra_facts),
                }
            )
        ),
    )
    return replace(
        graph,
        documents=(official, *graph.documents[1:]),
        facts=(*graph.facts, operating_income, *extra_facts),
        quarterly_updates=(update,),
    )


def _artifacts(graph: ContractGraph, path: Path) -> Path:
    result = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    write_research_bundle_artifacts(graph, result, output_directory=path)
    return path


def _decision(result, object_type: str, object_id: str):
    return next(
        item
        for item in result.decisions
        if item.object_type == object_type and item.object_id == object_id
    )


def test_compiler_reloads_bundle_and_maps_only_eligible_official_raw_facts(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    graph = _graph_with_raw_facts(sample_payloads)
    result = compile_price_blind_fact_ledger(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )
    ledger = result.ledger_payload

    assert ledger["schema_version"] == "1.0.0"
    assert ledger["entity_id"] == "issuer:acme"
    assert ledger["valuation_date"] == "2026-06-30"
    assert ledger["reporting_currency"] == "USD"
    assert [item["fact_id"] for item in ledger["facts"]] == [
        "fact:acme:operating-income:2025"
    ]
    mapped = ledger["facts"][0]
    assert mapped["value"] == 225
    assert mapped["unit"] == "USD millions"
    assert mapped["period_start"] == "2025-01-01"
    assert mapped["period_end"] == mapped["as_of_date"] == "2025-12-31"
    assert mapped["raw"] is True
    assert mapped["parent_fact_ids"] == ()
    assert mapped["derivation"] is None
    assert mapped["equity_bridge_role"] is None
    source = ledger["sources"][0]
    assert source["source_id"] == graph.documents[0].document_id
    assert source["publisher"] == "U.S. Securities and Exchange Commission"
    assert graph.documents[0].content_sha256 in source["locator"]
    assert result.kernel_fact_ledger_schema_sha256 == (
        "55be5aadad21629db1cdbe7fce386656eb930b52af8644d1314ba7404e384706"
    )
    assert _decision(result, "Fact", mapped["fact_id"]).disposition == "mapped"
    assert _decision(
        result, "CalculationResult", graph.calculations[0].calculation_id
    ).reason_codes == ("calculation_not_registered",)


def test_compiler_is_order_independent_and_ignores_objects_outside_bundle_closure(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    graph = _graph_with_raw_facts(sample_payloads)
    output = _artifacts(graph, tmp_path / "bundle")
    first = compile_price_blind_fact_ledger(
        bundle_artifact_directory=output,
        graph=graph,
        kernel_repository=KERNEL,
    )
    historical = replace(
        graph.facts[-1],
        fact_id="fact:acme:historical-outside-closure",
        concept="net_income",
        value=1.0,
        period={"start": "2010-01-01", "end": "2010-12-31"},
    )
    reordered = replace(
        graph,
        documents=tuple(reversed(graph.documents)),
        facts=(*tuple(reversed(graph.facts)), historical),
    )
    replay = compile_price_blind_fact_ledger(
        bundle_artifact_directory=output,
        graph=reordered,
        kernel_repository=KERNEL,
    )

    assert replay.fingerprint == first.fingerprint
    assert replay.ledger_payload == first.ledger_payload


def test_low_confidence_unknown_concept_and_derived_fact_fail_closed_per_object(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    seed = complete_phase4e_graph(sample_payloads).facts[0]
    low = replace(
        seed,
        fact_id="fact:acme:low-confidence",
        concept="net_income",
        confidence="low",
    )
    unknown = replace(seed, fact_id="fact:acme:revenue-near-name", concept="revenues")
    derived = replace(
        seed,
        fact_id="fact:acme:raw-derived",
        concept="net_income",
        derivation="caller supplied",
        parent_fact_ids=(seed.fact_id,),
    )
    graph = _graph_with_raw_facts(sample_payloads, extra_facts=(low, unknown, derived))
    result = compile_price_blind_fact_ledger(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )

    assert _decision(result, "Fact", low.fact_id).reason_codes == ("confidence_too_low",)
    assert _decision(result, "Fact", unknown.fact_id).reason_codes == (
        "concept_not_registered",
    )
    assert _decision(result, "Fact", derived.fact_id).reason_codes == (
        "raw_derivation_not_allowed",
    )


def test_unreconciled_same_period_conflict_is_blocked_not_arbitrarily_selected(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    seed = complete_phase4e_graph(sample_payloads).facts[0]
    first = replace(seed, fact_id="fact:acme:net-income:a", concept="net_income", value=50.0)
    second = replace(seed, fact_id="fact:acme:net-income:b", concept="net_income", value=55.0)
    graph = _graph_with_raw_facts(sample_payloads, extra_facts=(first, second))
    result = compile_price_blind_fact_ledger(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )

    assert all(
        _decision(result, "Fact", item.fact_id).disposition == "blocked"
        for item in (first, second)
    )
    assert {item["concept"] for item in result.ledger_payload["facts"]} == {
        "operating_income"
    }


def test_stock_period_and_unit_scaling_are_deterministic(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    seed = complete_phase4e_graph(sample_payloads).facts[0]
    assets = replace(
        seed,
        fact_id="fact:acme:total-assets:2025",
        concept="total_assets",
        value=2_500_000_000,
        unit="currency_units",
        period={"start": None, "end": "2025-12-31"},
    )
    graph = _graph_with_raw_facts(sample_payloads, extra_facts=(assets,))
    result = compile_price_blind_fact_ledger(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )
    mapped = next(
        item for item in result.ledger_payload["facts"] if item["fact_id"] == assets.fact_id
    )

    assert mapped["value"] == 2500
    assert mapped["unit"] == "USD millions"
    assert mapped["period_start"] is None
    assert mapped["period_end"] == mapped["as_of_date"] == "2025-12-31"


def test_per_share_and_mixed_currency_facts_cannot_enter_price_blind_ledger(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    seed = complete_phase4e_graph(sample_payloads).facts[0]
    per_share = replace(
        seed,
        fact_id="fact:acme:net-income-per-share",
        concept="net_income",
        value=3.5,
        unit="currency_per_share",
    )
    graph = _graph_with_raw_facts(sample_payloads, extra_facts=(per_share,))
    result = compile_price_blind_fact_ledger(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "per-share"),
        graph=graph,
        kernel_repository=KERNEL,
    )
    assert _decision(result, "Fact", per_share.fact_id).reason_codes == (
        "unit_semantics_mismatch",
    )

    foreign = replace(
        seed,
        fact_id="fact:acme:net-income-eur",
        concept="net_income",
        value=50.0,
        currency="EUR",
    )
    mixed = _graph_with_raw_facts(sample_payloads, extra_facts=(foreign,))
    with pytest.raises(FactLedgerMappingError, match="reporting currency"):
        compile_price_blind_fact_ledger(
            bundle_artifact_directory=_artifacts(mixed, tmp_path / "mixed"),
            graph=mixed,
            kernel_repository=KERNEL,
        )


def test_compiler_rejects_noncanonical_or_graph_mismatched_artifacts(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    graph = _graph_with_raw_facts(sample_payloads)
    output = _artifacts(graph, tmp_path / "bundle")
    mismatch = replace(
        graph,
        facts=(
            *graph.facts[:-1],
            replace(graph.facts[-1], value=float(graph.facts[-1].value) + 1.0),
        ),
    )
    with pytest.raises(FactLedgerMappingError, match="do not replay"):
        compile_price_blind_fact_ledger(
            bundle_artifact_directory=output,
            graph=mismatch,
            kernel_repository=KERNEL,
        )


def test_compiler_requires_exact_pinned_kernel_checkout(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    graph = _graph_with_raw_facts(sample_payloads)
    output = _artifacts(graph, tmp_path / "bundle")
    with pytest.raises(FactLedgerMappingError, match="kernel checkout"):
        compile_price_blind_fact_ledger(
            bundle_artifact_directory=output,
            graph=graph,
            kernel_repository=tmp_path,
        )


def test_compiler_has_no_caller_selection_status_currency_or_writer_controls() -> None:
    signature = inspect.signature(compile_price_blind_fact_ledger)
    assert tuple(signature.parameters) == (
        "bundle_artifact_directory",
        "graph",
        "kernel_repository",
    )
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    import owner_research

    assert not hasattr(owner_research, "compile_price_blind_fact_ledger")
    assert not hasattr(owner_research, "compile_assumption_ledger")
    assert not hasattr(owner_research, "run_valuation_kernel")
