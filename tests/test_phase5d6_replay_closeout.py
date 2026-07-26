from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from phase4a_support import replace_graph
from test_phase5d5_price_blind_freeze import KERNEL, _context, _FakeResult

import owner_research
import owner_research.valuation_price_blind_freeze as freeze_module
from owner_research.valuation_price_blind_freeze import (
    PriceBlindFreezeCompilationResult,
    PriceBlindFreezeError,
    compile_price_blind_input_freeze,
    load_price_blind_input_artifact,
    write_price_blind_input_artifact,
)


def _compile(
    *,
    graph,
    candidates,
    authorization,
) -> PriceBlindFreezeCompilationResult:
    return compile_price_blind_input_freeze(
        bundle_artifact_directory=Path("/unused/bundle"),
        graph=graph,
        kernel_repository=KERNEL,
        candidate_result=candidates,
        review_requests=(),
        freeze_authorization=authorization,
    )


def test_clean_room_replay_is_byte_identical_and_order_independent(
    sample_payloads, monkeypatch, tmp_path: Path
) -> None:
    graph, candidates, _ledger, authorization = _context(sample_payloads, monkeypatch)
    first = _compile(
        graph=graph,
        candidates=candidates,
        authorization=authorization,
    )
    second = _compile(
        graph=graph,
        candidates=candidates,
        authorization=authorization,
    )
    reordered = PriceBlindFreezeCompilationResult(
        artifact=second.artifact,
        handoffs=tuple(reversed(second.handoffs)),
        candidates=tuple(reversed(second.candidates)),
        decisions=tuple(reversed(second.decisions)),
        supplemental_reference_closure=second.supplemental_reference_closure,
    )

    assert first.fingerprint == reordered.fingerprint
    first_receipt = write_price_blind_input_artifact(
        graph,
        first,
        output_directory=tmp_path / "clean-room-a",
    )
    second_receipt = write_price_blind_input_artifact(
        graph,
        reordered,
        output_directory=tmp_path / "clean-room-b",
    )
    assert first_receipt.file_sha256 == second_receipt.file_sha256
    assert first_receipt.artifact_path.read_bytes() == second_receipt.artifact_path.read_bytes()
    assert load_price_blind_input_artifact(
        tmp_path / "clean-room-b",
        graph=graph,
        expected_result=first,
    ).fingerprint == first.fingerprint


def test_unrelated_historical_source_does_not_change_the_frozen_artifact(
    sample_payloads, monkeypatch
) -> None:
    graph, candidates, _ledger, authorization = _context(sample_payloads, monkeypatch)
    first = _compile(
        graph=graph,
        candidates=candidates,
        authorization=authorization,
    )
    historical_source = replace(
        graph.documents[0],
        document_id="source:unrelated-history",
        published_date="2020-01-01",
        retrieved_at="2020-01-02T00:00:00Z",
        content_sha256="9" * 64,
    )
    historical_manifest = replace(
        graph.manifests[0],
        input_document_hashes={
            **dict(graph.manifests[0].input_document_hashes),
            historical_source.document_id: historical_source.content_sha256,
        },
    )
    historical_graph = replace_graph(
        graph,
        documents=graph.documents + (historical_source,),
        manifests=(historical_manifest,),
    )
    replay = _compile(
        graph=historical_graph,
        candidates=candidates,
        authorization=authorization,
    )

    assert replay.artifact.to_dict() == first.artifact.to_dict()
    assert replay.fingerprint == first.fingerprint


def test_protected_input_drift_cannot_rewrite_an_existing_handoff_run(
    sample_payloads, monkeypatch
) -> None:
    graph, candidates, _ledger, authorization = _context(sample_payloads, monkeypatch)
    first = _compile(
        graph=graph,
        candidates=candidates,
        authorization=authorization,
    )
    graph_with_frozen_run = replace_graph(
        graph,
        valuation_assumption_candidates=first.candidates,
        valuation_assumption_review_decisions=first.decisions,
        valuation_handoffs=first.handoffs,
    )
    changed_mckinsey = first.artifact.to_dict()["mckinsey_inputs"]
    changed_mckinsey["scenario_payload"]["scenarios"] = [
        "black_swan",
        "bear",
        "base",
        "bull",
        "forbidden_drift",
    ]
    monkeypatch.setattr(
        freeze_module,
        "_compile_mckinsey",
        lambda **_: _FakeResult(changed_mckinsey),
    )

    with pytest.raises(PriceBlindFreezeError, match="collision|immutable"):
        _compile(
            graph=graph_with_frozen_run,
            candidates=candidates,
            authorization=authorization,
        )

    restarted = _compile(
        graph=graph,
        candidates=candidates,
        authorization=replace(
            authorization,
            authorized_at="2026-02-18T00:00:00Z",
            rationale="Protected input drift was quarantined and reviewed in a new run.",
        ),
    )
    assert restarted.handoffs[0].handoff_run_id != first.handoffs[0].handoff_run_id
    assert restarted.artifact.fingerprint != first.artifact.fingerprint


def test_missing_active_human_confirmation_blocks_the_freeze(
    sample_payloads, monkeypatch
) -> None:
    graph, candidates, ledger, authorization = _context(sample_payloads, monkeypatch)
    blocked_ledger = SimpleNamespace(
        decisions=(),
        phase5c_readiness_fingerprint=ledger.phase5c_readiness_fingerprint,
        research_bundle_id=ledger.research_bundle_id,
        research_bundle_fingerprint=ledger.research_bundle_fingerprint,
    )
    monkeypatch.setattr(
        freeze_module,
        "compile_reviewed_assumption_ledger",
        lambda **_: blocked_ledger,
    )

    with pytest.raises(PriceBlindFreezeError, match="active confirmed named-human"):
        _compile(
            graph=graph,
            candidates=candidates,
            authorization=authorization,
        )


def test_phase5d_closeout_has_no_market_or_valuation_execution_surface() -> None:
    forbidden = {
        "fetch_market_reference",
        "build_market_reference_snapshot",
        "compile_valuation_request",
        "run_valuation_kernel",
        "write_valuation_result",
    }
    assert not forbidden.intersection(dir(owner_research))
    assert not hasattr(freeze_module, "MarketReferenceSnapshot")
    assert not hasattr(freeze_module, "valuation_request")
    assert not hasattr(freeze_module, "valuation_result")
