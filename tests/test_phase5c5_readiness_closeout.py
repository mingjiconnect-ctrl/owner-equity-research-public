from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_phase5c0_accounting_bridge_policies import _readiness_case
from test_phase5c1_accounting_reconciliation import KERNEL, _accounting_graph, _artifacts
from test_phase5c4_equity_bridge import _with_diluted_shares

import owner_research
from owner_research.valuation_phase5c_readiness import (
    _compile_phase5c_readiness_result,
    _routing_assessments,
    assess_phase5c_readiness,
)


def test_full_typed_evidence_compiles_two_ready_successor_panels() -> None:
    fields, graph = _readiness_case()
    result = _compile_phase5c_readiness_result(
        bridge=fields["equity_bridge_result"],
        graph=graph,
    )

    assert result.routing_assessments["stable_capital_structure"]["status"] == "satisfied"
    assert result.routing_assessments["required_data_complete"]["value"] is False
    assert (
        result.routing_assessments["credible_near_term_earnings"]["status"]
        == "pending_phase5d"
    )
    assert {item["status"] for item in result.method_panels.values()} == {
        "ready_for_phase5d"
    }
    assert "status" not in result.to_dict()
    assert "model_weight" not in str(result.to_dict())


def test_successor_replay_is_order_independent() -> None:
    fields, graph = _readiness_case()
    bridge = fields["equity_bridge_result"]
    first = _compile_phase5c_readiness_result(bridge=bridge, graph=graph)
    reordered = replace(
        graph,
        periods=tuple(reversed(graph.periods)),
        footnote_reviews=tuple(reversed(graph.footnote_reviews)),
        claims=tuple(reversed(graph.claims)),
        analytical_claim_candidates=tuple(reversed(graph.analytical_claim_candidates)),
        analytical_claim_review_decisions=tuple(
            reversed(graph.analytical_claim_review_decisions)
        ),
    )
    second = _compile_phase5c_readiness_result(bridge=bridge, graph=reordered)

    assert second.fingerprint == first.fingerprint
    assert second.to_dict() == first.to_dict()


def test_unresolved_specialist_route_blocks_both_panels() -> None:
    fields, graph = _readiness_case(specialist_route="unresolved")
    result = _compile_phase5c_readiness_result(
        bridge=fields["equity_bridge_result"],
        graph=graph,
    )

    assert result.specialist_route == "unresolved"
    assert {item["status"] for item in result.method_panels.values()} == {"blocked"}


def test_missing_stable_capital_proof_blocks_only_the_method_that_requires_it() -> None:
    fields, graph = _readiness_case()
    graph = replace(
        graph,
        claims=tuple(item for item in graph.claims if item.claim_id != "claim:stable-capital"),
        analytical_claim_candidates=tuple(
            item
            for item in graph.analytical_claim_candidates
            if item.candidate_id != "analytical-candidate:stable-capital"
        ),
        analytical_claim_review_decisions=tuple(
            item
            for item in graph.analytical_claim_review_decisions
            if item.decision_id != "analytical-decision:stable-capital"
        ),
    )
    result = _compile_phase5c_readiness_result(
        bridge=fields["equity_bridge_result"],
        graph=graph,
    )

    assert result.routing_assessments["stable_capital_structure"]["status"] == "blocked"
    assert result.method_panels["mckinsey"]["status"] == "blocked"
    assert result.method_panels["penman"]["status"] == "ready_for_phase5d"


def test_unrelated_historical_claim_does_not_change_successor_fingerprint() -> None:
    fields, graph = _readiness_case()
    bridge = fields["equity_bridge_result"]
    first = _compile_phase5c_readiness_result(bridge=bridge, graph=graph)
    seed = next(item for item in graph.claims if item.supporting_fact_ids)
    historical = replace(
        seed,
        claim_id="claim:unrelated-history",
        statement="An unrelated historical observation outside the selected evidence extension.",
        as_of_date="2020-02-01",
    )
    second = _compile_phase5c_readiness_result(
        bridge=bridge,
        graph=replace(graph, claims=(*graph.claims, historical)),
    )

    assert second.fingerprint == first.fingerprint


def test_production_entry_replays_partial_bridge_without_promoting_it(
    sample_payloads: dict[str, dict], tmp_path: Path
) -> None:
    graph = _with_diluted_shares(_accounting_graph(sample_payloads))
    result = assess_phase5c_readiness(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )

    assert result.equity_bridge_result.status == "partial"
    assert result.routing_assessments["equity_bridge_complete"]["status"] == "unsatisfied"
    assert result.routing_assessments["stable_capital_structure"]["status"] == "blocked"
    assert result.method_panels["mckinsey"]["status"] != "ready_for_phase5d"


def test_empty_account_set_never_satisfies_separability() -> None:
    bridge = SimpleNamespace(
        status="partial",
        kernel_request_compatible=False,
        reason_codes=("bridge_role_coverage_incomplete",),
        fingerprint="b" * 64,
        role_decisions=(),
        method_view_result=SimpleNamespace(
            reconciliation_result=SimpleNamespace(
                account_decisions=(),
                checks={
                    "noa_nfo_common_equity": {
                        "status": "blocked",
                        "fact_ids": (),
                    }
                },
                fingerprint="r" * 64,
            )
        ),
    )
    assessments = _routing_assessments(bridge=bridge, stable=None)

    assert assessments["operating_financing_separable"]["status"] == "blocked"
    assert assessments["operating_financing_separable"]["value"] is None


def test_caller_cannot_forge_successor_panel_or_routing_assessment() -> None:
    fields, graph = _readiness_case()
    result = _compile_phase5c_readiness_result(
        bridge=fields["equity_bridge_result"],
        graph=graph,
    )
    panels = result.to_dict()["method_panels"]
    panels["mckinsey"]["status"] = "partial"
    with pytest.raises(ValueError, match="non-ready|not deterministic"):
        replace(result, method_panels=panels, validation_graph=graph)
    assessments = result.to_dict()["routing_assessments"]
    assessments["required_data_complete"]["status"] = "satisfied"
    assessments["required_data_complete"]["value"] = True
    assessments["required_data_complete"]["reason_codes"] = []
    with pytest.raises(ValueError, match="complete valuation-request data"):
        replace(result, routing_assessments=assessments, validation_graph=graph)


def test_readiness_entrypoint_is_internal_and_stops_before_phase5d() -> None:
    signature = inspect.signature(assess_phase5c_readiness)
    assert tuple(signature.parameters) == (
        "bundle_artifact_directory",
        "graph",
        "kernel_repository",
    )
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    assert not hasattr(owner_research, "assess_phase5c_readiness")
    assert not hasattr(owner_research, "compile_assumption_ledger")
    assert not hasattr(owner_research, "build_valuation_request")
    assert not hasattr(owner_research, "run_valuation_kernel")
