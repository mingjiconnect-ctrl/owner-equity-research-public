from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest
from test_phase5c1_accounting_reconciliation import KERNEL

import owner_research
from owner_research.fingerprints import canonical_sha256
from owner_research.valuation_penman_inputs import (
    PenmanInputCompilationError,
    _compile_from_ledger,
    compile_penman_price_blind_inputs,
)


def _penman_context(*, mutate=None):
    candidates = []
    decisions = []
    assumptions = []

    def add(slot, concept, value, unit, horizon):
        candidate_id = f"candidate:{slot}"
        assumption_id = f"assumption:{slot}"
        candidates.append(
            SimpleNamespace(
                candidate_id=candidate_id,
                assumption_slot_id=slot,
                kernel_concept=concept,
                method_scope="penman",
                scenario=None,
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
                "scope": "penman",
                "rationale": "Named-human-confirmed price-blind Penman input.",
                "source_fact_ids": ["fact:support"],
                "scenario": None,
            }
        )

    forecasts = {
        "2026": {"sales": 120.0, "operating_income_after_tax": 18.0, "ending_noa": 108.0},
        "2027": {"sales": 132.0, "operating_income_after_tax": 19.8, "ending_noa": 116.0},
    }
    for year, row in forecasts.items():
        for concept, value in row.items():
            add(
                f"penman.forecast.{year}.{concept}",
                concept,
                value,
                "USD millions",
                {
                    "kind": "period",
                    "start_date": f"{year}-01-01",
                    "end_date": f"{year}-12-31",
                },
            )
    add(
        "penman.primary_hurdle",
        "hurdle_rate",
        0.10,
        "decimal",
        {"kind": "point_in_time", "start_date": None, "end_date": "2025-12-31"},
    )
    for index, value in enumerate((0.08, 0.10, 0.12)):
        add(
            f"penman.hurdle_grid.{index:02d}",
            "hurdle_rate",
            value,
            "decimal",
            {"kind": "point_in_time", "start_date": None, "end_date": "2025-12-31"},
        )
    for index, value in enumerate((-0.02, 0.00, 0.04)):
        add(
            f"penman.growth_grid.{index:02d}",
            "growth_rate",
            value,
            "decimal",
            {"kind": "terminal", "start_date": None, "end_date": "2027-12-31"},
        )
    add(
        "penman.long_run_growth",
        "growth_rate",
        0.02,
        "decimal",
        {"kind": "terminal", "start_date": None, "end_date": "2027-12-31"},
    )
    challenges = {
        "2028": {"sales": 145.0, "ending_noa": 124.0},
        "2029": {"sales": 157.0, "ending_noa": 131.0},
    }
    for year, row in challenges.items():
        for concept, value in row.items():
            add(
                f"penman.challenge.{year}.{concept}",
                concept,
                value,
                "USD millions",
                {
                    "kind": "period",
                    "start_date": f"{year}-01-01",
                    "end_date": f"{year}-12-31",
                },
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
                "fact_id": "derived:noa",
                "entity_id": "issuer:fixture",
                "concept": "net_operating_assets",
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
                "category": "accounting",
                "equity_bridge_role": None,
            },
            {
                "fact_id": "derived:nfo",
                "entity_id": "issuer:fixture",
                "concept": "net_financial_obligations",
                "value": 25.0,
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
                "category": "financing",
                "equity_bridge_role": None,
            },
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


def test_penman_nonmarket_fragment_compiles_and_passes_shape_preflight() -> None:
    candidates, ledger = _penman_context()
    result = _compile_from_ledger(
        kernel_repository=KERNEL,
        candidate_result=candidates,
        ledger_result=ledger,
    )

    assert result.current_noa_fact_id == "derived:noa"
    assert result.net_financial_obligations_fact_id == "derived:nfo"
    assert len(result.penman_payload["forecast"]) == 2
    assert len(result.penman_payload["market_challenge_path"]) == 2
    assert result.penman_payload["include_cap_diagnostic"] is False
    assert "market_equity_value_fact_id" not in result.penman_payload
    assert [item["label"] for item in result.forecast_preflight] == ["2026", "2027"]
    assert result.fingerprint
    with pytest.raises(FrozenInstanceError):
        result.issuer_id = "changed"  # type: ignore[misc]


def test_forecast_and_challenge_periods_must_be_complete_and_contiguous() -> None:
    def missing(_candidates, decisions, assumptions):
        target = "assumption:penman.forecast.2027.ending_noa"
        decisions[:] = [
            item for item in decisions if item.reserved_kernel_assumption_id != target
        ]
        assumptions[:] = [item for item in assumptions if item["assumption_id"] != target]

    candidates, ledger = _penman_context(mutate=missing)
    with pytest.raises(PenmanInputCompilationError, match="each Penman forecast year"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )

    def drift(candidates, _decisions, _assumptions):
        candidate = next(
            item
            for item in candidates
            if item.assumption_slot_id == "penman.challenge.2028.sales"
        )
        candidate.horizon = {
            "kind": "period",
            "start_date": "2028-02-01",
            "end_date": "2028-12-31",
        }

    candidates, ledger = _penman_context(mutate=drift)
    with pytest.raises(PenmanInputCompilationError, match="exact annual period"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )


def test_hurdle_and_growth_grids_are_governed_not_caller_sorted() -> None:
    def free_grid(_candidates, _decisions, assumptions):
        item = next(
            item
            for item in assumptions
            if item["assumption_id"] == "assumption:penman.hurdle_grid.01"
        )
        item["value"] = 0.13

    candidates, ledger = _penman_context(mutate=free_grid)
    with pytest.raises(PenmanInputCompilationError, match="strictly increasing"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )

    def invalid_growth(_candidates, _decisions, assumptions):
        item = next(
            item
            for item in assumptions
            if item["assumption_id"] == "assumption:penman.long_run_growth"
        )
        item["value"] = 0.11

    candidates, ledger = _penman_context(mutate=invalid_growth)
    with pytest.raises(PenmanInputCompilationError, match="below the primary hurdle"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )


def test_current_noa_and_nfo_require_same_derived_measurement_date() -> None:
    candidates, ledger = _penman_context()
    ledger.augmented_fact_ledger_payload["facts"][1]["period_end"] = "2024-12-31"
    with pytest.raises(PenmanInputCompilationError, match="one measurement date"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )

    candidates, ledger = _penman_context()
    ledger.augmented_fact_ledger_payload["facts"][0]["raw"] = True
    with pytest.raises(PenmanInputCompilationError, match="current derived"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )


def test_penman_candidate_and_ledger_semantics_must_replay() -> None:
    candidates, ledger = _penman_context()
    ledger.candidate_compilation_fingerprint = "x" * 64
    with pytest.raises(PenmanInputCompilationError, match="does not replay"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )

    candidates, ledger = _penman_context()
    target = next(
        item
        for item in candidates.candidates
        if item.assumption_slot_id == "penman.primary_hurdle"
    )
    target.scenario = "base"
    with pytest.raises(PenmanInputCompilationError, match="semantics"):
        _compile_from_ledger(
            kernel_repository=KERNEL,
            candidate_result=candidates,
            ledger_result=ledger,
        )


def test_penman_compiler_remains_internal_and_stops_before_market_or_valuation() -> None:
    signature = inspect.signature(compile_penman_price_blind_inputs)
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
    assert not hasattr(owner_research, "compile_penman_price_blind_inputs")
    assert not hasattr(owner_research, "fetch_market_reference")
    assert not hasattr(owner_research, "compile_valuation_request")
    assert not hasattr(owner_research, "run_valuation_kernel")
