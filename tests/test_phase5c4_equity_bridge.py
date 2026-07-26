from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path

import pytest
from test_phase5c0_accounting_bridge_policies import (
    _empty_method_view,
    _reconciliation_ledger,
)
from test_phase5c1_accounting_reconciliation import KERNEL, _accounting_graph, _artifacts

import owner_research
from owner_research.valuation_accounting_types import _economic_binding_index
from owner_research.valuation_equity_bridge import (
    EquityBridgeCompilationError,
    _compile_equity_bridge_result,
    _role_decision,
    compile_equity_bridge,
)


def _with_diluted_shares(graph):
    seed = next(item for item in graph.facts if item.concept == "total_assets")
    diluted = replace(
        seed,
        fact_id="fact:acme:phase5c4:diluted-shares",
        concept="diluted_shares",
        value=100_000_000,
        value_type="number",
        unit="shares",
        currency=None,
        period={"start": "2025-01-01", "end": "2025-12-31"},
        confidence="high",
        derivation=None,
        parent_fact_ids=(),
        source_locator="10-K:diluted-shares",
    )
    update = replace(
        graph.quarterly_updates[0],
        fact_ids=tuple(sorted({*graph.quarterly_updates[0].fact_ids, diluted.fact_id})),
    )
    return replace(graph, facts=(*graph.facts, diluted), quarterly_updates=(update,))


def test_bridge_compiles_nine_roles_from_frozen_method_view() -> None:
    result = _compile_equity_bridge_result(
        method_view=_empty_method_view(_reconciliation_ledger()),
        kernel_repository=KERNEL,
    )

    assert result.status == "complete"
    assert result.kernel_request_compatible is True
    assert len(result.role_decisions) == 9
    assert {item.role: item.status for item in result.role_decisions} == {
        "nonoperating_asset": "explicitly_absent",
        "debt": "modeled",
        "debt_equivalent": "explicitly_absent",
        "lease_liability": "explicitly_absent",
        "unfunded_pension": "explicitly_absent",
        "preferred_stock": "explicitly_absent",
        "noncontrolling_interest": "explicitly_absent",
        "option_or_dilution_claim": "explicitly_absent",
        "other_senior_claim": "explicitly_absent",
    }
    assert tuple(result.bridge_items) == (
        {"item_id": "bridge:debt", "fact_id": "derived:phase5c:equity-bridge:debt:2025-12-31"},
    )
    debt = next(
        item
        for item in result.ledger_payload["facts"]
        if item["fact_id"] == "derived:phase5c:equity-bridge:debt:2025-12-31"
    )
    assert debt["value"] == 60
    assert debt["parent_fact_ids"] == ("fact:debt:current", "fact:debt:noncurrent")
    assert debt["equity_bridge_role"] == "debt"


def test_missing_roles_remain_partial_and_are_never_fabricated(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _accounting_graph(sample_payloads)
    with pytest.raises(EquityBridgeCompilationError, match="diluted shares"):
        compile_equity_bridge(
            bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
            graph=graph,
            kernel_repository=KERNEL,
        )


def test_internal_entrypoint_returns_partial_when_bridge_roles_are_missing(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _with_diluted_shares(_accounting_graph(sample_payloads))
    result = compile_equity_bridge(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )

    assert result.status == "partial"
    assert result.kernel_request_compatible is False
    assert result.bridge_items == ()
    assert "kernel_bridge_item_required" in result.reason_codes
    assert all(item.status == "unresolved" for item in result.role_decisions)


def test_positive_components_require_same_frozen_source() -> None:
    method_view = _empty_method_view(_reconciliation_ledger())
    candidates = tuple(
        dict(item)
        for item in method_view.ledger_payload["facts"]
        if item["fact_id"] in {"fact:debt:current", "fact:debt:noncurrent"}
    )
    candidates[1]["source_id"] = "source:second"
    debt, addition = _role_decision(
        role="debt",
        candidates=candidates,
        binding_index=_economic_binding_index(method_view.reconciliation_result),
        diluted_roots={"fact:diluted-shares"},
        preconsumed_claims=set(),
        reporting_currency="USD",
        measurement_end="2025-12-31",
    )
    assert debt.status == "unresolved"
    assert debt.reason_codes == ("bridge_multi_source_aggregation",)
    assert addition is None


def test_bridge_cannot_reuse_diluted_share_or_method_view_claim() -> None:
    method_view = _empty_method_view(_reconciliation_ledger())
    first = dict(method_view.consumption_records[0])
    debt_binding = next(
        item
        for item in method_view.reconciliation_result.economic_claim_bindings
        if item["economic_identity"] == "debt"
    )
    first.update(
        {
            "root_fact_id": debt_binding["root_fact_ids"][0],
            "economic_claim_key": debt_binding["economic_claim_key"],
            "economic_identity": "debt",
            "channel": "mckinsey_equity_bridge",
            "method": "mckinsey",
            "group_id": "adjustment-group:existing-debt",
            "consumption_kind": "economic_deduction",
        }
    )
    records = (*method_view.consumption_records, first)
    with pytest.raises(ValueError, match="root consumption does not replay"):
        replace(method_view, consumption_records=records)


def test_caller_cannot_promote_or_remove_bridge_roles() -> None:
    result = _compile_equity_bridge_result(
        method_view=_empty_method_view(_reconciliation_ledger()),
        kernel_repository=KERNEL,
    )
    with pytest.raises(ValueError, match="exactly nine"):
        replace(result, role_decisions=result.role_decisions[:-1])
    with pytest.raises(ValueError, match="bridge items must equal"):
        replace(result, bridge_items=())
    with pytest.raises(ValueError, match="status does not replay"):
        replace(result, status="partial")


def test_bridge_compiler_rejects_non_kernel_checkout() -> None:
    with pytest.raises(EquityBridgeCompilationError):
        _compile_equity_bridge_result(
            method_view=_empty_method_view(_reconciliation_ledger()),
            kernel_repository=Path("/not-a-kernel"),
        )


def test_bridge_compiler_is_internal_and_stops_before_successor_readiness() -> None:
    signature = inspect.signature(compile_equity_bridge)
    assert tuple(signature.parameters) == (
        "bundle_artifact_directory",
        "graph",
        "kernel_repository",
    )
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    assert not hasattr(owner_research, "compile_equity_bridge")
    assert not hasattr(owner_research, "assess_phase5c_readiness")
    assert not hasattr(owner_research, "build_valuation_request")
    assert not hasattr(owner_research, "run_valuation_kernel")
