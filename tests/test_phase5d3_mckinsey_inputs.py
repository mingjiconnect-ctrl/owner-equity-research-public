from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest
from test_phase5c1_accounting_reconciliation import KERNEL

import owner_research
from owner_research.fingerprints import canonical_sha256
from owner_research.valuation_mckinsey_inputs import (
    McKinseyScenarioCompilationError,
    _compile_from_ledger,
    compile_mckinsey_scenario_inputs,
)

SCENARIOS = ("black_swan", "bear", "base", "bull")


def _scenario_context(*, mutate=None):
    candidates = []
    decisions = []
    assumptions = []
    values = {
        "wacc": 0.12,
        "terminal_growth": 0.10,
        "terminal_ronic": 0.20,
        "terminal_margin": 0.10,
        "terminal_roic": 0.20,
        "steady_state_tolerance": 0.001,
    }
    forecasts = {
        "2034": {"revenue": 200.0, "nopat": 20.0, "ending_invested_capital": 110.0},
        "2035": {"revenue": 220.0, "nopat": 22.0, "ending_invested_capital": 121.0},
    }

    def add(slot, concept, scenario, value, unit, horizon):
        candidate_id = f"candidate:{slot}"
        assumption_id = f"assumption:{slot}"
        candidates.append(
            SimpleNamespace(
                candidate_id=candidate_id,
                assumption_slot_id=slot,
                kernel_concept=concept,
                method_scope="mckinsey",
                scenario=scenario,
                horizon=horizon,
            )
        )
        decisions.append(
            SimpleNamespace(
                candidate_id=candidate_id,
                decision_id=f"decision:{slot}",
                decision="confirmed",
                reserved_kernel_assumption_id=assumption_id,
                supersedes_decision_id=None,
            )
        )
        assumptions.append(
            {
                "assumption_id": assumption_id,
                "value": value,
                "unit": unit,
                "concept": concept,
                "scope": "mckinsey",
                "rationale": "Named-human-confirmed price-blind scenario input.",
                "source_fact_ids": ["fact:support"],
                "scenario": scenario,
            }
        )

    for scenario in SCENARIOS:
        for year, row in forecasts.items():
            for concept, value in row.items():
                add(
                    f"mckinsey.{scenario}.forecast.{year}.{concept}",
                    concept,
                    scenario,
                    value,
                    "USD millions",
                    {
                        "kind": "period",
                        "start_date": f"{year}-01-01",
                        "end_date": f"{year}-12-31",
                    },
                )
        for concept, value in values.items():
            add(
                f"mckinsey.{scenario}.{concept}",
                concept,
                scenario,
                value,
                "decimal",
                {"kind": "terminal", "start_date": None, "end_date": "2035-12-31"},
            )
    if mutate is not None:
        mutate(candidates, decisions, assumptions)
    candidate_result = SimpleNamespace(
        issuer_id="issuer:fixture",
        data_cutoff_date="2025-12-31",
        candidates=tuple(candidates),
        fingerprint="c" * 64,
    )
    ledger = {
        "schema_version": "1.0.0",
        "entity_id": "issuer:fixture",
        "valuation_date": "2025-12-31",
        "reporting_currency": "USD",
        "sources": [],
        "facts": [
            {
                "fact_id": "derived:invested_capital",
                "entity_id": "issuer:fixture",
                "concept": "invested_capital",
                "value": 100.0,
                "unit": "USD millions",
                "currency": "USD",
                "period_start": None,
                "period_end": "2025-12-31",
                "as_of_date": "2025-12-31",
                "raw": False,
                "parent_fact_ids": ["fact:support"],
                "derivation": "fixture",
                "source_id": "doc:10k",
                "source_location": "fixture",
                "confidence": "high",
                "category": "operating",
                "equity_bridge_role": None,
            }
        ],
    }
    ledger_result = SimpleNamespace(
        issuer_id="issuer:fixture",
        data_cutoff_date="2025-12-31",
        candidate_compilation_fingerprint="c" * 64,
        decisions=tuple(decisions),
        assumption_ledger_payload={
            "schema_version": "1.0.0",
            "fact_ledger_fingerprint": canonical_sha256(ledger),
            "assumptions": assumptions,
        },
        augmented_fact_ledger_payload=ledger,
        assumption_entries_sha256=canonical_sha256(assumptions),
        fingerprint="l" * 64,
    )
    return candidate_result, ledger_result


def test_four_scenarios_compile_to_kernel_shape_and_pass_steady_state() -> None:
    candidates, ledger = _scenario_context()
    result = _compile_from_ledger(
        kernel_repository=KERNEL,
        candidate_result=candidates,
        ledger_result=ledger,
    )

    assert result.base_invested_capital_fact_id == "derived:invested_capital"
    assert [item["name"] for item in result.scenario_payload["scenarios"]] == list(
        SCENARIOS
    )
    assert all(len(item["forecast"]) == 2 for item in result.scenario_payload["scenarios"])
    assert all(
        item["evidence"]["terminal_reinvestment_rate"] == pytest.approx(0.5)
        for item in result.steady_state_evidence
    )
    assert result.fingerprint
    with pytest.raises(FrozenInstanceError):
        result.issuer_id = "changed"  # type: ignore[misc]


def test_missing_scenario_slot_and_timeline_drift_fail_closed() -> None:
    def missing(_candidates, decisions, assumptions):
        target = "assumption:mckinsey.bull.terminal_roic"
        decisions[:] = [
            item for item in decisions if item.reserved_kernel_assumption_id != target
        ]
        assumptions[:] = [item for item in assumptions if item["assumption_id"] != target]

    candidates, ledger = _scenario_context(mutate=missing)
    with pytest.raises(McKinseyScenarioCompilationError, match="missing required slot"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )

    def drift(candidates, _decisions, _assumptions):
        candidate = next(
            item
            for item in candidates
            if item.assumption_slot_id
            == "mckinsey.bull.forecast.2035.ending_invested_capital"
        )
        candidate.horizon = {
            "kind": "period",
            "start_date": "2034-02-01",
            "end_date": "2035-12-31",
        }

    candidates, ledger = _scenario_context(mutate=drift)
    with pytest.raises(McKinseyScenarioCompilationError, match="exact annual periods"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )


def test_terminal_economics_and_steady_state_are_not_caller_assertions() -> None:
    def invalid_growth(_candidates, _decisions, assumptions):
        item = next(
            item
            for item in assumptions
            if item["assumption_id"] == "assumption:mckinsey.base.terminal_growth"
        )
        item["value"] = 0.13

    candidates, ledger = _scenario_context(mutate=invalid_growth)
    with pytest.raises(McKinseyScenarioCompilationError, match="terminal economics"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )

    def not_stable(_candidates, _decisions, assumptions):
        item = next(
            item
            for item in assumptions
            if item["assumption_id"] == "assumption:mckinsey.bear.terminal_margin"
        )
        item["value"] = 0.20

    candidates, ledger = _scenario_context(mutate=not_stable)
    with pytest.raises(McKinseyScenarioCompilationError, match="steady-state preflight"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )


def test_assumption_context_and_current_invested_capital_must_replay() -> None:
    candidates, ledger = _scenario_context()
    ledger.candidate_compilation_fingerprint = "x" * 64
    with pytest.raises(McKinseyScenarioCompilationError, match="does not replay"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )

    candidates, ledger = _scenario_context()
    ledger.augmented_fact_ledger_payload["facts"][0]["period_end"] = "2026-12-31"
    with pytest.raises(McKinseyScenarioCompilationError, match="invested-capital"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )


def test_mckinsey_compiler_remains_internal_and_stops_before_valuation() -> None:
    signature = inspect.signature(compile_mckinsey_scenario_inputs)
    assert tuple(signature.parameters) == (
        "bundle_artifact_directory",
        "graph",
        "kernel_repository",
        "candidate_result",
        "review_requests",
        "supplemental_reference_closure",
        "prior_decisions",
    )
    assert all(
        item.kind is inspect.Parameter.KEYWORD_ONLY
        for item in signature.parameters.values()
    )
    assert not hasattr(owner_research, "compile_mckinsey_scenario_inputs")
    assert not hasattr(owner_research, "calculate_enterprise_dcf")
    assert not hasattr(owner_research, "calculate_economic_profit")
    assert not hasattr(owner_research, "write_price_blind_input")
