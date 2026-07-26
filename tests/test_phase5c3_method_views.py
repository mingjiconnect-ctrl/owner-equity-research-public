from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path

import pytest
from test_phase5c1_accounting_reconciliation import KERNEL, _accounting_graph, _artifacts
from test_phase5c2_accounting_quality_adjustments import _quality_graph

import owner_research
from owner_research.fingerprints import FrozenMap
from owner_research.valuation_method_views import compile_method_views


def _compile(graph, tmp_path: Path):
    return compile_method_views(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )


def test_method_views_compile_empty_registered_views_without_inventing_adjustments(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    result = _compile(_accounting_graph(sample_payloads), tmp_path)

    assert dict(result.status_by_method) == {"mckinsey": "pass", "penman": "pass"}
    assert dict(result.method_views) == {"mckinsey": (), "penman": ()}
    assert result.reason_codes == ()
    assert {item["method"] for item in result.consumption_records} == {
        "mckinsey",
        "penman",
    }
    assert all(item["consumption_kind"] == "method_base" for item in result.consumption_records)


def test_registered_lease_adjustment_enters_only_mckinsey_view(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    result = _compile(
        _accounting_graph(sample_payloads, financial_components=True),
        tmp_path,
    )

    assert len(result.method_views["mckinsey"]) == 1
    assert result.method_views["mckinsey"][0]["target_concept"] == "invested_capital"
    assert result.method_views["penman"] == ()
    lease_records = [
        item
        for item in result.consumption_records
        if item["economic_identity"] == "lease_liability"
    ]
    assert {(item["method"], item["consumption_kind"]) for item in lease_records} == {
        ("mckinsey", "economic_deduction"),
        ("penman", "method_base"),
    }


def test_accounting_quality_method_asymmetry_is_preserved(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _quality_graph(
        sample_payloads,
        category="cash_conversion",
        severity="red_flag",
    )
    result = _compile(graph, tmp_path)

    assert dict(result.status_by_method) == {
        "mckinsey": "blocked",
        "penman": "pass",
    }
    assert "accounting_quality_material_unresolved" in result.reason_codes


def test_caller_cannot_add_or_remove_method_view_entries(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    result = _compile(
        _accounting_graph(sample_payloads, financial_components=True),
        tmp_path,
    )
    with pytest.raises(ValueError, match="does not match compiled decisions"):
        replace(result, method_views=FrozenMap({"mckinsey": (), "penman": ()}))


def test_caller_cannot_delete_or_relabel_root_consumption(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    result = _compile(_accounting_graph(sample_payloads), tmp_path)
    with pytest.raises(ValueError, match="root consumption does not replay"):
        replace(result, consumption_records=result.consumption_records[1:])
    mutated = [dict(item) for item in result.consumption_records]
    mutated[0]["channel"] = "mckinsey_equity_bridge"
    with pytest.raises(ValueError):
        replace(result, consumption_records=tuple(mutated))


def test_method_view_replay_is_order_independent(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(sample_payloads, financial_components=True)
    first = _compile(graph, tmp_path / "first")
    reordered = replace(
        graph,
        facts=tuple(reversed(graph.facts)),
        claims=tuple(reversed(graph.claims)),
        analytical_claim_candidates=tuple(reversed(graph.analytical_claim_candidates)),
        analytical_claim_review_decisions=tuple(
            reversed(graph.analytical_claim_review_decisions)
        ),
    )
    second = _compile(reordered, tmp_path / "second")

    assert first.to_dict() == second.to_dict()
    assert first.fingerprint == second.fingerprint


def test_method_view_compiler_rejects_non_kernel_checkout(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(sample_payloads)
    with pytest.raises(ValueError):
        compile_method_views(
            bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
            graph=graph,
            kernel_repository=tmp_path / "not-the-kernel",
        )


def test_method_view_compiler_is_internal_and_stops_before_bridge() -> None:
    signature = inspect.signature(compile_method_views)
    assert tuple(signature.parameters) == (
        "bundle_artifact_directory",
        "graph",
        "kernel_repository",
    )
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    assert not hasattr(owner_research, "compile_method_views")
    assert not hasattr(owner_research, "compile_equity_bridge")
    assert not hasattr(owner_research, "assess_phase5c_readiness")
    assert not hasattr(owner_research, "build_valuation_request")
    assert not hasattr(owner_research, "run_valuation_kernel")
