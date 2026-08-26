from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_phase5e1_market_access import _security_context

import owner_research.valuation_run_context as context_module
from owner_research.fingerprints import canonical_json
from owner_research.valuation_market_provider import RunClock
from owner_research.valuation_owner_execution import OwnerValuationExecutionClock
from owner_research.valuation_run import ValuationRunClock
from owner_research.valuation_run_context import (
    VALUATION_RUN_INPUT_FILENAME,
    ValuationRunContextError,
    load_valuation_run_input_context,
    write_valuation_run_input_context,
)


def _context_inputs(sample_payloads, monkeypatch, tmp_path: Path):
    graph, freeze, price_blind, security = _security_context(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    graph = replace(
        graph,
        valuation_handoffs=freeze.handoffs,
        valuation_assumption_candidates=freeze.candidates,
        valuation_assumption_review_decisions=freeze.decisions,
        price_blind_reference_closures=(
            ()
            if freeze.supplemental_reference_closure is None
            else (freeze.supplemental_reference_closure,)
        ),
    )
    graph.validate()
    bundle = graph.research_bundles[0]
    manifest = next(item for item in graph.manifests if item.run_id == bundle.run_id)
    bundle_directory = tmp_path / "bundle"
    bundle_directory.mkdir()
    (bundle_directory / "research-bundle.json").write_bytes(
        (canonical_json(bundle.to_dict()) + "\n").encode("utf-8")
    )
    (bundle_directory / "run-manifest.json").write_bytes(
        (canonical_json(manifest.to_dict()) + "\n").encode("utf-8")
    )
    clock = ValuationRunClock(
        market=RunClock("2026-07-14T01:00:00Z", "2026-07-14T01:00:01Z"),
        execution=OwnerValuationExecutionClock(
            "2026-07-14T01:00:02Z",
            "2026-07-14T01:00:03Z",
        ),
    )
    return graph, freeze, price_blind, security, bundle_directory, clock


def test_canonical_run_input_round_trips_graph_freeze_security_and_clocks(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    graph, freeze, price_blind, security, bundle_directory, clock = _context_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    output = price_blind.parent / VALUATION_RUN_INPUT_FILENAME
    write_valuation_run_input_context(
        graph=graph,
        bundle_artifact_directory=bundle_directory,
        expected_freeze=freeze,
        security_proposal=security.proposal,
        assumption_proposals=(),
        assumption_reviews=(),
        clock=clock,
        output_file=output,
    )

    loaded = load_valuation_run_input_context(
        output,
        price_blind_artifact_directory=price_blind,
    )

    assert loaded.graph == graph
    assert loaded.expected_freeze == freeze
    assert loaded.expected_security == security
    assert loaded.clock == clock
    assert set(loaded.research_bundle_contents) == {
        "research-bundle.json",
        "run-manifest.json",
    }
    with pytest.raises(ValueError, match="does not replay typed inputs"):
        replace(loaded, context_fingerprint="f" * 64)
    assert (
        write_valuation_run_input_context(
            graph=graph,
            bundle_artifact_directory=bundle_directory,
            expected_freeze=freeze,
            security_proposal=security.proposal,
            assumption_proposals=(),
            assumption_reviews=(),
            clock=clock,
            output_file=output,
        )
        == output
    )


def test_context_rejects_mutation_extra_graph_kind_and_price_blind_drift(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    graph, freeze, price_blind, security, bundle_directory, clock = _context_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    output = price_blind.parent / VALUATION_RUN_INPUT_FILENAME
    write_valuation_run_input_context(
        graph=graph,
        bundle_artifact_directory=bundle_directory,
        expected_freeze=freeze,
        security_proposal=security.proposal,
        assumption_proposals=(),
        assumption_reviews=(),
        clock=clock,
        output_file=output,
    )
    payload = json.loads(output.read_bytes())
    payload["context_fingerprint"] = "f" * 64
    output.write_bytes((canonical_json(payload) + "\n").encode("utf-8"))
    with pytest.raises(ValuationRunContextError, match="fingerprint"):
        load_valuation_run_input_context(
            output,
            price_blind_artifact_directory=price_blind,
        )

    with pytest.raises(ValuationRunContextError, match="different content"):
        write_valuation_run_input_context(
            graph=graph,
            bundle_artifact_directory=bundle_directory,
            expected_freeze=freeze,
            security_proposal=security.proposal,
            assumption_proposals=(),
            assumption_reviews=(),
            clock=clock,
            output_file=output,
            overwrite=True,
        )
    output.unlink()
    write_valuation_run_input_context(
        graph=graph,
        bundle_artifact_directory=bundle_directory,
        expected_freeze=freeze,
        security_proposal=security.proposal,
        assumption_proposals=(),
        assumption_reviews=(),
        clock=clock,
        output_file=output,
    )
    price_blind_path = price_blind / "price-blind-input.json"
    price_blind_path.write_bytes(price_blind_path.read_bytes() + b"\n")
    with pytest.raises((ValuationRunContextError, ValueError)):
        load_valuation_run_input_context(
            output,
            price_blind_artifact_directory=price_blind,
        )


def test_context_loader_never_reopens_price_blind_input_with_path_helpers(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    graph, freeze, price_blind, security, bundle_directory, clock = _context_inputs(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    output = price_blind.parent / VALUATION_RUN_INPUT_FILENAME
    write_valuation_run_input_context(
        graph=graph,
        bundle_artifact_directory=bundle_directory,
        expected_freeze=freeze,
        security_proposal=security.proposal,
        assumption_proposals=(),
        assumption_reviews=(),
        clock=clock,
        output_file=output,
    )
    original_read_text = Path.read_text
    original_read_bytes = Path.read_bytes

    def guarded_read_text(path: Path, *args, **kwargs):
        if path.name == "price-blind-input.json":
            raise AssertionError("unbounded price-blind read_text reopened the artifact")
        return original_read_text(path, *args, **kwargs)

    def guarded_read_bytes(path: Path, *args, **kwargs):
        if path.name == "price-blind-input.json":
            raise AssertionError("unbounded price-blind read_bytes reopened the artifact")
        return original_read_bytes(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    loaded = context_module.load_valuation_run_input_context(
        output,
        price_blind_artifact_directory=price_blind,
    )
    assert loaded.expected_freeze == freeze
