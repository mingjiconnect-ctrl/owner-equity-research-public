from __future__ import annotations

import inspect
import json
from dataclasses import FrozenInstanceError, dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest
from phase4a_support import replace_graph
from test_phase5a_contract_graph import _valid_graph
from test_phase5c1_accounting_reconciliation import KERNEL

import owner_research
import owner_research.valuation_price_blind_freeze as freeze_module
from owner_research.fingerprints import canonical_json, canonical_sha256
from owner_research.valuation_assumption_types import (
    AssumptionCandidateCompilationResult,
    AssumptionLedgerCompilationResult,
)
from owner_research.valuation_handoff_policies import (
    assumption_evidence_policy_sha256,
    assumption_slot_policy_sha256,
)
from owner_research.valuation_price_blind_freeze import (
    PriceBlindFreezeAuthorization,
    PriceBlindFreezeError,
    PriceBlindInputArtifact,
    compile_price_blind_input_freeze,
    load_price_blind_input_artifact,
    write_price_blind_input_artifact,
)


@dataclass(frozen=True)
class _FakeResult:
    payload: dict

    def to_dict(self):
        return self.payload


def _context(sample_payloads, monkeypatch):
    graph = replace_graph(_valid_graph(sample_payloads), valuation_handoffs=())
    bundle = graph.research_bundles[0]
    candidate = graph.valuation_assumption_candidates[0]
    decision = graph.valuation_assumption_review_decisions[0]
    candidate_result = AssumptionCandidateCompilationResult(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        research_bundle_id=bundle.bundle_id,
        research_bundle_fingerprint=bundle.bundle_fingerprint,
        research_bundle_dependency_sha256=bundle.dependency_closure_sha256,
        phase5c_readiness_fingerprint="a" * 64,
        supplemental_reference_closure_sha256=(
            candidate.supplemental_reference_closure_sha256
        ),
        assumption_slot_policy_sha256=assumption_slot_policy_sha256(),
        assumption_evidence_policy_sha256=assumption_evidence_policy_sha256(),
        candidates=(candidate,),
    )
    fact_ledger = {
        "schema_version": "1.0.0",
        "entity_id": bundle.issuer_id,
        "valuation_date": bundle.data_cutoff_date,
        "reporting_currency": "USD",
        "sources": [],
        "facts": [],
    }
    assumptions = [
        {
            "assumption_id": decision.reserved_kernel_assumption_id,
            "value": candidate.value,
            "unit": "decimal",
            "concept": candidate.kernel_concept,
            "scope": candidate.method_scope,
            "rationale": candidate.rationale,
            "source_fact_ids": [],
            "scenario": candidate.scenario,
        }
    ]
    ledger = AssumptionLedgerCompilationResult(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        research_bundle_id=bundle.bundle_id,
        research_bundle_fingerprint=bundle.bundle_fingerprint,
        research_bundle_dependency_sha256=bundle.dependency_closure_sha256,
        phase5c_readiness_fingerprint="a" * 64,
        candidate_compilation_fingerprint=candidate_result.fingerprint,
        supplemental_reference_closure_sha256=(
            candidate_result.supplemental_reference_closure_sha256
        ),
        decisions=(decision,),
        augmented_fact_ledger_payload=fact_ledger,
        assumption_ledger_payload={
            "schema_version": "1.0.0",
            "fact_ledger_fingerprint": canonical_sha256(fact_ledger),
            "assumptions": assumptions,
        },
        assumption_entries_sha256=canonical_sha256(assumptions),
        kernel_assumption_schema_sha256="b" * 64,
    )
    readiness = SimpleNamespace(
        fingerprint="a" * 64,
        to_dict=lambda: {
            "issuer_id": bundle.issuer_id,
            "data_cutoff_date": bundle.data_cutoff_date,
            "routing": {"mckinsey": "ready_for_phase5d", "penman": "ready_for_phase5d"},
        },
    )
    mckinsey = _FakeResult(
        {
            "issuer_id": bundle.issuer_id,
            "data_cutoff_date": bundle.data_cutoff_date,
            "assumption_ledger_fingerprint": ledger.fingerprint,
            "scenario_payload": {"scenarios": ["black_swan", "bear", "base", "bull"]},
        }
    )
    penman = _FakeResult(
        {
            "issuer_id": bundle.issuer_id,
            "data_cutoff_date": bundle.data_cutoff_date,
            "assumption_ledger_fingerprint": ledger.fingerprint,
            "penman_payload": {
                "forecast": ["2026", "2027"],
                "market_challenge_path": ["2028"],
                "include_cap_diagnostic": False,
            },
        }
    )
    monkeypatch.setattr(freeze_module, "compile_reviewed_assumption_ledger", lambda **_: ledger)
    monkeypatch.setattr(freeze_module, "assess_phase5c_readiness", lambda **_: readiness)
    monkeypatch.setattr(freeze_module, "_compile_mckinsey", lambda **_: mckinsey)
    monkeypatch.setattr(freeze_module, "_compile_penman", lambda **_: penman)
    authorization = PriceBlindFreezeAuthorization(
        reviewer_id="human:mingji",
        handoff_opened_at="2026-02-15T00:00:00Z",
        authorized_at="2026-02-17T00:00:00Z",
        rationale="All price-blind evidence and assumptions were reviewed before market access.",
    )
    return graph, candidate_result, ledger, authorization


def _compile(sample_payloads, monkeypatch):
    graph, candidates, _ledger, authorization = _context(sample_payloads, monkeypatch)
    result = compile_price_blind_input_freeze(
        bundle_artifact_directory=Path("/unused/bundle"),
        graph=graph,
        kernel_repository=KERNEL,
        candidate_result=candidates,
        review_requests=(),
        freeze_authorization=authorization,
    )
    return graph, result


def test_canonical_freeze_binds_protected_hashes_and_adjacent_handoffs(
    sample_payloads, monkeypatch
) -> None:
    graph, result = _compile(sample_payloads, monkeypatch)

    assert tuple(item.state for item in result.handoffs) == (
        "evidence_open",
        "price_blind_candidates_reviewed",
        "price_blind_input_frozen",
        "market_reference_allowed",
    )
    assert result.artifact.payload["price_blind_input_fingerprint"]
    assert result.artifact.payload["protected_mckinsey_sha256"]
    assert result.artifact.payload["protected_penman_assumptions_sha256"]
    assert "market_equity_value_fact_id" not in canonical_json(result.artifact.to_dict())
    assert result.handoffs[-1].market_reference_snapshot_id is None
    assert not graph.market_reference_snapshots
    with pytest.raises(FrozenInstanceError):
        result.artifact.payload = {}  # type: ignore[misc]


def test_protected_subtree_or_full_payload_tampering_fails_closed(
    sample_payloads, monkeypatch
) -> None:
    _graph, result = _compile(sample_payloads, monkeypatch)
    payload = result.artifact.to_dict()
    payload["mckinsey_inputs"]["scenario_payload"]["scenarios"] = ["base"]
    with pytest.raises(ValueError, match="protected McKinsey"):
        PriceBlindInputArtifact(payload)

    payload = result.artifact.to_dict()
    payload["freeze_authorization"]["rationale"] = "changed after freeze"
    with pytest.raises(ValueError, match="fingerprint"):
        PriceBlindInputArtifact(payload)


def test_writer_and_reloader_are_atomic_canonical_and_strict(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, result = _compile(sample_payloads, monkeypatch)
    output = tmp_path / "price-blind"
    first = write_price_blind_input_artifact(graph, result, output_directory=output)
    second = write_price_blind_input_artifact(graph, result, output_directory=output)
    assert first == second
    assert {item.name for item in output.iterdir()} == {"price-blind-input.json"}
    assert load_price_blind_input_artifact(
        output, graph=graph, expected_result=result
    ).fingerprint == result.fingerprint

    path = output / "price-blind-input.json"
    path.write_text(
        json.dumps(result.artifact.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(PriceBlindFreezeError, match="canonically"):
        load_price_blind_input_artifact(output, graph=graph, expected_result=result)


def test_freeze_rejects_nonhuman_or_nonchronological_authorization() -> None:
    with pytest.raises(ValueError, match="named human"):
        PriceBlindFreezeAuthorization(
            reviewer_id="llm",
            handoff_opened_at="2026-02-15T00:00:00Z",
            authorized_at="2026-02-17T00:00:00Z",
            rationale="invalid",
        )
    with pytest.raises(ValueError, match="chronological"):
        PriceBlindFreezeAuthorization(
            reviewer_id="human:mingji",
            handoff_opened_at="2026-02-18T00:00:00Z",
            authorized_at="2026-02-17T00:00:00Z",
            rationale="invalid",
        )


def test_freeze_surface_remains_internal_and_cannot_fetch_or_value() -> None:
    signature = inspect.signature(compile_price_blind_input_freeze)
    assert all(
        item.kind is inspect.Parameter.KEYWORD_ONLY
        for item in signature.parameters.values()
    )
    assert not hasattr(owner_research, "compile_price_blind_input_freeze")
    assert not hasattr(owner_research, "write_price_blind_input_artifact")
    assert not hasattr(owner_research, "load_price_blind_input_artifact")
    assert not hasattr(owner_research, "fetch_market_reference")
    assert not hasattr(owner_research, "compile_valuation_request")
    assert not hasattr(owner_research, "run_valuation_kernel")
