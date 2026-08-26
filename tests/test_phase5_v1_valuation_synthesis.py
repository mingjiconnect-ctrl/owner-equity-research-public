from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import test_phase5_v1_dual_panel_e2e as dual_panel_fixtures
import test_phase5_v1_owner_execution as owner_execution_fixtures
from test_phase5_v1_run_orchestration import (
    _authority,
    _candidate_compilation,
    _run_clock,
    _typed_runtime_authority,
)

import owner_research.valuation_owner_execution as owner_execution_module
import owner_research.valuation_run as run_module
from owner_research.contracts import Fact, SourceDocument
from owner_research.fingerprints import canonical_json, canonical_sha256, to_json_value
from owner_research.owner_scorecard import (
    LENS_COMPONENTS,
    build_owner_scorecard,
    build_score_v2,
)
from owner_research.research_bundle_validation import dependency_closure
from owner_research.validation import ContractGraph
from owner_research.valuation_owner_preparation import OwnerValuationPreparationResult
from owner_research.valuation_run import ValuationRunResult, run_owner_valuation
from owner_research.valuation_synthesis import (
    ReviewedPeerSetAuthority,
    ValuationSynthesisError,
    build_comparable_valuation,
    build_composite_valuation,
    build_forward_reoi_valuation,
    build_reviewed_peer_set_authority,
    build_valuation_basis_receipt,
)
from owner_research.valuation_synthesis_types import (
    CompositeValuationResult,
    NamedHumanReviewAuthority,
    build_named_human_review_authority,
)

_SYNTHESIS_CACHE: tuple[Any, ...] | None = None
_SYNTHESIS_CACHE_STATE_BASE: Path | None = None


def _pinned_kernel_fixture() -> tuple[Path, dict[str, Any]]:
    candidates = []
    configured = os.environ.get("OWNER_VALUATION_REPO")
    if configured:
        candidates.append(Path(configured))
    candidates.extend(
        (
            Path("/Users/mingji/Documents/New project/owner-valuation-kernel"),
            Path("/Users/mingji/dev/owner-valuation-kernel"),
        )
    )
    for candidate in candidates:
        example = candidate / "examples/synthetic_nonfinancial.json"
        if example.is_file():
            return candidate, json.loads(example.read_text(encoding="utf-8"))
    pytest.fail("exact pinned kernel checkout with its synthetic oracle is unavailable")


def _run_pinned_kernel_oracle(
    request: dict[str, Any],
    *,
    kernel_repository: Path,
) -> dict[str, Any]:
    completed = subprocess.run(
        (
            sys.executable,
            "-c",
            (
                "import json,sys; "
                "from owner_valuation import run_dual_panel; "
                "from owner_valuation.contracts import validate_result; "
                "request=json.load(sys.stdin); result=run_dual_panel(request); "
                "validate_result(result); "
                "sys.stdout.write(json.dumps(result,sort_keys=True,separators=(',',':')))"
            ),
        ),
        input=canonical_json(request),
        text=True,
        capture_output=True,
        check=True,
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(kernel_repository / "src"),
        },
    )
    payload = json.loads(completed.stdout)
    assert canonical_json(payload) == completed.stdout
    return payload


def _activate_cached_run_replay(
    monkeypatch: pytest.MonkeyPatch,
    run_result: ValuationRunResult,
) -> None:
    assert _SYNTHESIS_CACHE_STATE_BASE is not None
    monkeypatch.setattr(
        "owner_research.valuation_market_provider._AUTHORIZATION_STATE_BASE",
        _SYNTHESIS_CACHE_STATE_BASE,
    )
    monkeypatch.setattr(
        "owner_research.valuation_kernel_projection._source_is_registered",
        lambda _document: True,
    )
    graph = run_result.input_receipt.graph
    company_fact = next(item for item in graph.facts if item.concept == "issuer_legal_name")
    company_source = next(
        item
        for item in graph.documents
        if item.document_id == company_fact.source_document_id
    )
    monkeypatch.setattr(
        owner_execution_module,
        "_governed_company_name",
        lambda _prepared: (company_fact.value, company_fact, company_source),
    )


def _completed_run(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[ValuationRunResult, str, str, str, str, str]:
    kernel_repository, kernel_example = _pinned_kernel_fixture()
    captured: dict[str, Any] = {}
    build_snapshot = dual_panel_fixtures.build_reviewed_market_reference_snapshot

    def capture_snapshot(**kwargs: Any) -> Any:
        captured["price_blind_artifact_directory"] = kwargs[
            "price_blind_artifact_directory"
        ]
        prepared = build_snapshot(**kwargs)
        captured["prepared_market_reference"] = prepared
        return prepared

    monkeypatch.setattr(
        dual_panel_fixtures,
        "build_reviewed_market_reference_snapshot",
        capture_snapshot,
    )
    compiled, freeze = dual_panel_fixtures._compile_pr1_request(
        sample_payloads=sample_payloads,
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        kernel=kernel_repository,
        example=kernel_example,
    )
    prepared_market_reference = captured["prepared_market_reference"]
    artifact = freeze.artifact.payload
    preparation = OwnerValuationPreparationResult(
        status="prepared",
        issuer_id=artifact["issuer_id"],
        data_cutoff_date=artifact["data_cutoff_date"],
        price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
        prepared_market_reference=prepared_market_reference,
        issue_codes=(),
    )
    request = to_json_value(compiled.request_payload)
    share_fact_id = request["mckinsey"]["equity_bridge"][
        "share_denominator_fact_id"
    ]
    nfo_fact_id = request["penman"]["net_financial_obligations_fact_id"]
    current_noa_fact_id = request["penman"]["current_noa_fact_id"]
    facts = {item["fact_id"]: item for item in request["fact_ledger"]["facts"]}
    share_value = str(facts[share_fact_id]["value"])
    nfo_value = str(facts[nfo_fact_id]["value"])
    result_payload = _run_pinned_kernel_oracle(
        request,
        kernel_repository=kernel_repository,
    )
    result_bytes = canonical_json(result_payload).encode("utf-8")
    base = owner_execution_fixtures._runner_result(compiled)
    runtime_authority = _typed_runtime_authority()
    runner = SimpleNamespace(
        **{
            **base.__dict__,
            "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
            "result_bytes": result_bytes,
            "runtime_authority_sha256": runtime_authority.runtime_authority_sha256,
            "runtime_manifest_file_sha256": (
                runtime_authority.runtime_manifest_file_sha256
            ),
            "runtime_manifest_fingerprint": (
                runtime_authority.runtime_manifest_fingerprint
            ),
            "wheel_inventory_sha256": runtime_authority.wheel_inventory_sha256,
        }
    )
    monkeypatch.setattr(
        owner_execution_module,
        "compile_final_valuation_request",
        lambda **_kwargs: compiled,
    )
    monkeypatch.setattr(
        owner_execution_module,
        "execute_pinned_kernel",
        lambda *_args, **_kwargs: runner,
    )
    execution = owner_execution_module.execute_owner_valuation(
        preparation=preparation,
        expected_freeze=freeze,
        kernel_repository=kernel_repository,
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256=(
            owner_execution_fixtures.TEST_RUNTIME_MANIFEST_FILE_SHA256
        ),
        cas_root=Path("/runtime/cas"),
        clock=owner_execution_fixtures._clock(preparation),
    )
    assert execution.status == "completed"

    monkeypatch.setattr(
        run_module,
        "_replay_assumption_inputs",
        lambda **_kwargs: _candidate_compilation(freeze),
    )
    monkeypatch.setattr(run_module, "prepare_owner_valuation", lambda **_kwargs: preparation)
    monkeypatch.setattr(
        run_module,
        "_verify_runtime_supply",
        lambda **_kwargs: runtime_authority,
    )
    monkeypatch.setattr(run_module, "execute_owner_valuation", lambda **_kwargs: execution)
    authority = replace(
        _authority(preparation, freeze, tmp_path),
        price_blind_artifact_directory=captured["price_blind_artifact_directory"],
        kernel_repository=kernel_repository,
    )
    result = run_owner_valuation(
        graph=preparation.prepared_market_reference.graph,
        bundle_artifact_directory=tmp_path / "bundle",
        assumption_proposals=(),
        assumption_reviews=(),
        market_provider=object(),
        kernel_wheel=Path("/runtime/cas/sha256") / ("f" * 64),
        output_directory=tmp_path / "archive",
        clock=_run_clock(preparation),
        authority=authority,
    )
    assert result.status == "completed"
    return (
        result,
        share_fact_id,
        nfo_fact_id,
        current_noa_fact_id,
        share_value,
        nfo_value,
    )


def _bundle_fact_binding(run_result: ValuationRunResult) -> dict[str, str]:
    graph = run_result.input_receipt.graph
    bundle = graph.research_bundles[0]
    roots = tuple(
        object_id
        for reference in bundle.module_references
        for object_id in reference["object_ids"]
    )
    closure = dependency_closure(graph, roots)
    object_type, item = next(
        (object_type, item)
        for object_type, item in closure.values()
        if object_type == "Fact"
    )
    return {
        "object_type": object_type,
        "object_id": item.fact_id,
        "fingerprint": item.fingerprint,
    }


def _review(
    run_result: ValuationRunResult,
    *,
    scope: str,
    reviewed_at: str,
    reviewed_payload: dict[str, Any],
) -> NamedHumanReviewAuthority:
    graph = run_result.input_receipt.graph
    return build_named_human_review_authority(
        scope=scope,
        graph=graph,
        research_bundle=graph.research_bundles[0],
        reviewer_id="human:phase5-synthesis-reviewer",
        reviewed_at=reviewed_at,
        rationale="Named-human review of the retained price-blind evidence authority.",
        reviewed_payload=reviewed_payload,
        evidence_bindings=(_bundle_fact_binding(run_result),),
    )


def _basis_and_forward(
    run_result: ValuationRunResult,
    *,
    current_noa_fact_id: str,
    nfo_fact_id: str,
    share_value: str,
    nfo_value: str,
):
    basis_review = _review(
        run_result,
        scope="valuation_basis",
        reviewed_at="2026-07-01T01:00:00Z",
        reviewed_payload={
            "current_net_financial_obligations_fact_id": nfo_fact_id,
            "twelve_month_shares": share_value,
            "twelve_month_nonoperating_assets": "0",
            "twelve_month_nonequity_claims": nfo_value,
            "twelve_month_net_financial_obligations": nfo_value,
        },
    )
    basis = build_valuation_basis_receipt(
        run_result,
        review_authority=basis_review,
    )
    scenarios = []
    for name, hurdle, growth, incomes in (
        ("black_swan", "0.12", "0.01", ("42", "43.2", "44.4")),
        ("base", "0.10", "0.03", ("40", "41", "42")),
        ("bull", "0.09", "0.04", ("39", "39.9", "40.8")),
    ):
        scenarios.append(
            {
                "name": name,
                "hurdle_rate": hurdle,
                "terminal_growth": growth,
                "forecast": [
                    {
                        "period_end": period_end,
                        "operating_income_after_tax": income,
                        "ending_noa": ending_noa,
                    }
                    for period_end, income, ending_noa in zip(
                        ("2027-06-30", "2028-06-30", "2029-06-30"),
                        incomes,
                        ("110", "120", "130"),
                        strict=True,
                    )
                ],
            }
        )
    forward_review = _review(
        run_result,
        scope="forward_reoi",
        reviewed_at="2026-07-01T01:01:00Z",
        reviewed_payload={
            "current_noa_fact_id": current_noa_fact_id,
            "scenarios": scenarios,
        },
    )
    forward = build_forward_reoi_valuation(
        run_result,
        basis_receipt=basis,
        review_authority=forward_review,
    )
    return basis, forward


def _peer_graphs_and_inputs(peer_evidence_set):
    peer_graphs: list[ContractGraph] = []
    selected_peers: list[dict[str, Any]] = []
    bindings: dict[str, dict[str, dict[str, str]]] = {}
    for index, session in enumerate(peer_evidence_set.peers, 1):
        source = SourceDocument(
            schema_version="1.0.0",
            document_id=f"document:peer:{index:02d}:10-k",
            issuer_id=session.issuer_id,
            document_type="10-K",
            period={"start": "2025-01-01", "end": "2025-12-31"},
            published_date="2026-02-15",
            retrieved_at="2026-02-16T01:02:03Z",
            source_url=(
                "https://www.sec.gov/Archives/edgar/data/"
                f"{1000 + index}/peer-{index:02d}-20251231.htm"
            ),
            authority_level="primary_regulatory",
            content_sha256=canonical_sha256({"peer": index, "document": "10-k"}),
        )
        facts = tuple(
            Fact(
                schema_version="2.0.0",
                fact_id=f"fact:peer:{index:02d}:{suffix}",
                issuer_id=session.issuer_id,
                concept=concept,
                value_type="number",
                value=value,
                unit=unit,
                currency=currency,
                period={"start": "2025-01-01", "end": "2025-12-31"},
                source_document_id=source.document_id,
                source_locator=f"xbrl:test:{concept}",
                derivation=None,
                parent_fact_ids=(),
                confidence="high",
            )
            for suffix, concept, value, unit, currency in (
                ("earnings", "net_income", 1000 + index, "currency_units", "USD"),
                ("fcf", "free_cash_flow", 900 + index, "currency_units", "USD"),
                (
                    "shares",
                    "weighted_average_diluted_shares",
                    100,
                    "shares",
                    None,
                ),
            )
        )
        graph = ContractGraph(
            documents=(source,),
            facts=facts,
        )
        graph.validate()
        peer_bindings = {
            fact.concept: {
                "object_type": "Fact",
                "object_id": fact.fact_id,
                "fingerprint": fact.fingerprint,
            }
            for fact in facts
        }
        peer_id = f"peer:{index:02d}"
        bindings[peer_id] = peer_bindings
        peer_graphs.append(graph)
        security = session.authority_set.security_identity
        assert security is not None
        selected_peers.append(
            {
                "peer_id": peer_id,
                "company_name": f"Peer {index:02d}",
                "issuer_id": session.issuer_id,
                "security_id": session.security_id,
                "ticker": security.ticker,
                "listing_mic": security.mic,
                "currency": session.daily_close.currency,
                "fact_bindings": list(peer_bindings.values()),
            }
        )
    metrics: list[dict[str, Any]] = []
    for metric, measure_concept in (
        ("price_earnings", "net_income"),
        ("price_fcf", "free_cash_flow"),
    ):
        metrics.append(
            {
                "metric": metric,
                "peer_inputs": [
                    {
                        "peer_id": peer["peer_id"],
                        "measure_fact_binding": bindings[peer["peer_id"]][
                            measure_concept
                        ],
                        "share_fact_binding": bindings[peer["peer_id"]][
                            "weighted_average_diluted_shares"
                        ],
                        "twelve_month_measure_per_share": "11",
                    }
                    for peer in selected_peers
                ],
                "scenarios": [
                    {
                        "name": name,
                        "current_target_measure_per_share": current_measure,
                        "twelve_month_target_measure_per_share": future_measure,
                        "current_net_debt_per_share": "0",
                        "twelve_month_net_debt_per_share": "0",
                    }
                    for name, current_measure, future_measure in (
                        ("black_swan", "0.17", "0.22"),
                        ("base", "0.21", "0.27"),
                        ("bull", "0.25", "0.32"),
                    )
                ],
            }
        )
    return tuple(peer_graphs), selected_peers, metrics


def _complete_synthesis_from_run(run_result: ValuationRunResult) -> tuple[Any, ...]:
    """Build the exact downstream chain without executing another kernel run."""

    from test_phase5_v1_futu_data_plane import build_futu_peer_evidence_fixture

    request = to_json_value(run_result.archive.request_payload)
    facts = {item["fact_id"]: item for item in request["fact_ledger"]["facts"]}
    share_id = request["mckinsey"]["equity_bridge"]["share_denominator_fact_id"]
    penman = request["penman"]
    nfo_id = penman.get("net_financial_obligations_fact_id") or penman[
        "market_equity_value_fact_id"
    ]
    current_noa_id = penman.get("current_noa_fact_id") or share_id
    share = str(facts[share_id]["value"])
    nfo = str(facts[nfo_id]["value"])
    basis, forward = _basis_and_forward(
        run_result,
        current_noa_fact_id=current_noa_id,
        nfo_fact_id=nfo_id,
        share_value=share,
        nfo_value=nfo,
    )
    futu = build_futu_peer_evidence_fixture(
        run_result.input_receipt.expected_freeze,
        target_security_id=basis.security_id,
        trading_date=run_result.archive.market_reference.trading_date,
        data_cutoff_date=run_result.data_cutoff_date,
    )
    peer_graphs, selected_peers, metric_inputs = _peer_graphs_and_inputs(
        futu.peer_evidence_set
    )
    selection_review = _review(
        run_result,
        scope="peer_set_selection",
        reviewed_at="2026-08-15T01:00:30Z",
        reviewed_payload={
            "selection_frozen_at": "2026-08-15T01:00:30Z",
            "peers": selected_peers,
            "registered_metrics": ["price_earnings", "price_fcf"],
            "missing_data_policy": "complete_case_all_preselected_peers",
        },
    )
    forecast_review = _review(
        run_result,
        scope="comparable_forecast",
        reviewed_at="2026-08-15T01:00:20Z",
        reviewed_payload={"metric_inputs": metric_inputs},
    )
    peer_authority = build_reviewed_peer_set_authority(
        run_result=run_result,
        selection_review=selection_review,
        forecast_review=forecast_review,
        peer_graphs=peer_graphs,
        futu_peer_evidence_set=futu.peer_evidence_set,
        verifier=futu.verifier,
    )
    comparables = build_comparable_valuation(
        run_result,
        basis_receipt=basis,
        peer_authority=peer_authority,
    )
    composite = build_composite_valuation(
        run_result,
        basis_receipt=basis,
        forward_reoi=forward,
        comparables=comparables,
    )
    binding = _bundle_fact_binding(run_result)
    scores = []
    for lens, component_ids in LENS_COMPONENTS.items():
        components = [
            {
                "component_id": component_id,
                "status": "complete",
                "score": "17",
                "confidence_percent": "90",
                "rationale": "Bound evidence supports the fixed component score.",
                "evidence_bindings": [binding],
                "missing_evidence": [],
                "red_flags": [],
            }
            for component_id in component_ids
        ]
        score_review = _review(
            run_result,
            scope=f"score:{lens}",
            reviewed_at="2026-08-15T01:07:00Z",
            reviewed_payload={
                "composite_valuation_fingerprint": composite.fingerprint,
                "components": components,
            },
        )
        scores.append(
            build_score_v2(
                composite_valuation=composite,
                review_authority=score_review,
            )
        )
    scorecard = build_owner_scorecard(
        composite_valuation=composite,
        lens_scores=tuple(scores),
    )
    return (
        basis,
        forward,
        peer_authority,
        comparables,
        composite,
        tuple(scores),
        scorecard,
    )


def _complete_synthesis(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    global _SYNTHESIS_CACHE, _SYNTHESIS_CACHE_STATE_BASE
    if _SYNTHESIS_CACHE is not None:
        _activate_cached_run_replay(monkeypatch, _SYNTHESIS_CACHE[0])
        return _SYNTHESIS_CACHE
    run_result, _share_id, _nfo_id, _current_noa_id, _share, _nfo = _completed_run(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    downstream = _complete_synthesis_from_run(run_result)
    _SYNTHESIS_CACHE = (run_result, *downstream)
    _SYNTHESIS_CACHE_STATE_BASE = tmp_path / "owner-research-state"
    _activate_cached_run_replay(monkeypatch, run_result)
    return _SYNTHESIS_CACHE


def _rebuild_peer_authority_with_graphs(
    run_result: ValuationRunResult,
    original: ReviewedPeerSetAuthority,
    peer_graphs: tuple[ContractGraph, ...],
    *,
    additional_reviewed_facts: dict[str, tuple[Fact, ...]] | None = None,
) -> ReviewedPeerSetAuthority:
    fingerprints = {
        fact.fact_id: fact.fingerprint
        for graph in peer_graphs
        for fact in graph.facts
    }
    selection_payload = to_json_value(original.selection_review.reviewed_payload)
    for peer in selection_payload["peers"]:
        for binding in peer["fact_bindings"]:
            binding["fingerprint"] = fingerprints[binding["object_id"]]
        for fact in (additional_reviewed_facts or {}).get(peer["issuer_id"], ()):
            peer["fact_bindings"].append(
                {
                    "object_type": "Fact",
                    "object_id": fact.fact_id,
                    "fingerprint": fact.fingerprint,
                }
            )
    forecast_payload = to_json_value(original.forecast_review.reviewed_payload)
    for metric in forecast_payload["metric_inputs"]:
        for peer_input in metric["peer_inputs"]:
            for key in ("measure_fact_binding", "share_fact_binding"):
                binding = peer_input[key]
                binding["fingerprint"] = fingerprints[binding["object_id"]]
    return build_reviewed_peer_set_authority(
        run_result=run_result,
        selection_review=_review(
            run_result,
            scope="peer_set_selection",
            reviewed_at=original.selection_review.reviewed_at,
            reviewed_payload=selection_payload,
        ),
        forecast_review=_review(
            run_result,
            scope="comparable_forecast",
            reviewed_at=original.forecast_review.reviewed_at,
            reviewed_payload=forecast_payload,
        ),
        peer_graphs=peer_graphs,
        futu_peer_evidence_set=original.futu_peer_evidence_set,
        verifier=original.verifier,
    )


def _contested_composite(
    run_result: ValuationRunResult,
    basis,
    forward,
    comparables,
) -> CompositeValuationResult:
    reviewed = to_json_value(forward._input_authority._review_authority.reviewed_payload)
    for scenario in reviewed["scenarios"]:
        for row in scenario["forecast"]:
            row["operating_income_after_tax"] = str(
                Decimal(row["operating_income_after_tax"]) * Decimal("100")
            )
    extreme_review = _review(
        run_result,
        scope="forward_reoi",
        reviewed_at="2026-08-15T01:06:00Z",
        reviewed_payload=reviewed,
    )
    extreme_forward = build_forward_reoi_valuation(
        run_result,
        basis_receipt=basis,
        review_authority=extreme_review,
    )
    return build_composite_valuation(
        run_result,
        basis_receipt=basis,
        forward_reoi=extreme_forward,
        comparables=comparables,
    )


def test_real_completed_run_builds_basis_and_forward_reoi(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_result, _share_id, nfo_id, current_noa_id, share, nfo = _completed_run(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    basis, forward = _basis_and_forward(
        run_result,
        current_noa_fact_id=current_noa_id,
        nfo_fact_id=nfo_id,
        share_value=share,
        nfo_value=nfo,
    )

    assert basis._run_result is run_result
    assert forward._run_result is run_result
    assert forward.status == "complete"
    assert tuple(item["name"] for item in forward.scenarios) == (
        "black_swan",
        "base",
        "bull",
    )


def test_real_completed_run_builds_full_retained_authority_chain(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    *_, peer_authority, comparables, composite, scores, scorecard = _complete_synthesis(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )

    assert isinstance(peer_authority, ReviewedPeerSetAuthority)
    assert comparables.status == "complete"
    assert isinstance(composite, CompositeValuationResult)
    assert composite.status == "complete"
    assert composite.recommendation_eligible is True
    base_rows = tuple(
        next(row for row in composite.panel_scenarios[panel] if row["name"] == "base")
        for panel in ("mckinsey", "forward_reoi", "comparables")
    )
    current_values = sorted(Decimal(row["current_value_per_share"]) for row in base_rows)
    future_values = sorted(
        Decimal(row["twelve_month_value_per_share"]) for row in base_rows
    )
    assert Decimal(composite.current_intrinsic_value) == current_values[1]
    assert Decimal(composite.twelve_month_target) == future_values[1]
    assert len(scores) == 4
    assert scorecard.composite_valuation_fingerprint == composite.fingerprint


def test_downstream_replay_uses_retained_archive_without_reopening_path(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_result, *_identities = _completed_run(sample_payloads, monkeypatch, tmp_path)
    reload_calls = 0

    def forbidden_reload(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal reload_calls
        reload_calls += 1
        raise AssertionError("downstream replay reopened the six-file archive")

    monkeypatch.setattr(run_module, "load_valuation_run_archive", forbidden_reload)
    archive_path = run_result.archive.output_directory
    moved_path = archive_path.with_name(f"{archive_path.name}-retained-source")
    os.chmod(archive_path, 0o755)
    archive_path.rename(moved_path)
    archive_path.mkdir(mode=0o555)
    try:
        (
            _basis,
            _forward,
            _peer_authority,
            _comparables,
            composite,
            scores,
            scorecard,
        ) = _complete_synthesis_from_run(run_result)
    finally:
        os.chmod(archive_path, 0o755)
        archive_path.rmdir()
        os.chmod(moved_path, 0o755)
        moved_path.rename(archive_path)
        os.chmod(archive_path, 0o555)

    assert reload_calls == 0
    assert composite.status == "complete"
    assert len(scores) == 4
    assert scorecard.composite_valuation_fingerprint == composite.fingerprint


def test_missing_or_legitimately_mismatched_panel_returns_typed_null_without_fallback(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_result, basis, forward, _peer_authority, comparables, *_ = _complete_synthesis(
        sample_payloads, monkeypatch, tmp_path
    )
    missing = build_composite_valuation(
        run_result,
        basis_receipt=basis,
        forward_reoi=None,
        comparables=comparables,
    )
    assert missing.status == "blocked"
    assert missing.current_intrinsic_value is None
    assert missing.twelve_month_target is None
    assert missing.recommendation_eligible is False
    assert missing.issue_codes == ("missing_forward_reoi_panel",)

    basis_payload = to_json_value(basis._review_authority.reviewed_payload)
    basis_payload["twelve_month_shares"] = str(
        Decimal(basis_payload["twelve_month_shares"]) * Decimal("2")
    )
    alternate_basis = build_valuation_basis_receipt(
        run_result,
        review_authority=_review(
            run_result,
            scope="valuation_basis",
            reviewed_at="2026-08-15T01:05:00Z",
            reviewed_payload=basis_payload,
        ),
    )
    alternate_forward = build_forward_reoi_valuation(
        run_result,
        basis_receipt=alternate_basis,
        review_authority=forward._input_authority._review_authority,
    )
    mismatched = build_composite_valuation(
        run_result,
        basis_receipt=basis,
        forward_reoi=alternate_forward,
        comparables=comparables,
    )
    assert mismatched.status == "blocked"
    assert mismatched.current_intrinsic_value is None
    assert mismatched.twelve_month_target is None
    assert mismatched.recommendation_eligible is False
    assert mismatched.issue_codes == ("mismatched_forward_reoi_panel",)


def test_dispersion_above_fifty_percent_is_contested_and_ineligible(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_result, basis, forward, _peer_authority, comparables, *_ = _complete_synthesis(
        sample_payloads, monkeypatch, tmp_path
    )
    composite = _contested_composite(run_result, basis, forward, comparables)

    assert composite.status == "contested"
    assert composite.contested is True
    assert composite.recommendation_eligible is False
    assert max(
        Decimal(composite.current_relative_dispersion),
        Decimal(composite.twelve_month_relative_dispersion),
    ) > Decimal("0.50")
    assert composite.issue_codes == ("panel_dispersion_exceeds_50_percent",)


def test_extension_schema_set_is_separate_from_frozen_root_schemas() -> None:
    from owner_research.schema_store import SCHEMA_NAMES
    from owner_research.valuation_synthesis_types import EXTENSION_SCHEMA_NAMES

    assert len(SCHEMA_NAMES) == 43
    assert len(EXTENSION_SCHEMA_NAMES) == 10


def test_replace_cannot_rebind_composite_arithmetic(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    *_, composite, _scores, _scorecard = _complete_synthesis(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    payload = composite.to_dict()
    payload["current_intrinsic_value"] = "999"
    payload.pop("result_id")
    payload["result_id"] = (
        f"composite-valuation-result:{composite.issuer_id}:"
        f"{canonical_sha256(payload)[:24]}"
    )

    with pytest.raises(ValueError, match="does not replay"):
        replace(
            composite,
            current_intrinsic_value="999",
            result_id=payload["result_id"],
        )


@pytest.mark.parametrize("violation", ("instant_share", "mismatched_period", "stale"))
def test_comparable_current_period_policy_rejects_ineligible_preselected_peer(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    violation: str,
) -> None:
    run_result, _basis, _forward, peer_authority, *_rest = _complete_synthesis(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    peer_graphs = list(peer_authority.peer_graphs)
    first = peer_graphs[0]
    changed_facts = []
    for fact in first.facts:
        if violation == "instant_share" and fact.concept == "weighted_average_diluted_shares":
            fact = replace(fact, concept="current_common_shares_outstanding")
        elif violation == "mismatched_period" and fact.concept == "weighted_average_diluted_shares":
            fact = replace(
                fact,
                period={"start": "2025-01-02", "end": "2025-12-31"},
            )
        elif violation == "stale" and fact.concept in {
            "net_income",
            "weighted_average_diluted_shares",
        }:
            fact = replace(
                fact,
                period={"start": "2020-01-01", "end": "2020-12-31"},
            )
        changed_facts.append(fact)
    peer_graphs[0] = replace(first, facts=tuple(changed_facts))
    peer_graphs[0].validate()

    with pytest.raises(
        ValuationSynthesisError,
        match="peer multiple operands do not have registered SEC/IR semantics",
    ):
        _rebuild_peer_authority_with_graphs(
            run_result,
            peer_authority,
            tuple(peer_graphs),
        )


def test_comparable_current_period_policy_requires_latest_reviewed_duration_measure(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_result, _basis, _forward, peer_authority, *_rest = _complete_synthesis(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    peer_graphs = list(peer_authority.peer_graphs)
    first = peer_graphs[0]
    changed_facts = []
    selected_measure = next(item for item in first.facts if item.concept == "net_income")
    for fact in first.facts:
        if fact.concept in {"net_income", "weighted_average_diluted_shares"}:
            fact = replace(
                fact,
                period={"start": "2024-07-01", "end": "2025-06-30"},
            )
        changed_facts.append(fact)
    latest_measure = replace(
        selected_measure,
        fact_id=f"{selected_measure.fact_id}:latest-reviewed",
        concept="net_income_loss",
        period={"start": "2025-01-01", "end": "2025-12-31"},
    )
    changed_facts.append(latest_measure)
    peer_graphs[0] = replace(first, facts=tuple(changed_facts))
    peer_graphs[0].validate()

    with pytest.raises(
        ValuationSynthesisError,
        match="peer multiple operands do not have registered SEC/IR semantics",
    ):
        _rebuild_peer_authority_with_graphs(
            run_result,
            peer_authority,
            tuple(peer_graphs),
            additional_reviewed_facts={first.facts[0].issuer_id: (latest_measure,)},
        )


@pytest.mark.parametrize("operand", ("metric", "shares"))
def test_comparable_current_period_policy_rejects_old_fact_after_reviewed_amendment(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    operand: str,
) -> None:
    run_result, _basis, _forward, peer_authority, *_rest = _complete_synthesis(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    peer_graphs = list(peer_authority.peer_graphs)
    first = peer_graphs[0]
    original_source = first.documents[0]
    amended_source = replace(
        original_source,
        document_id=f"{original_source.document_id}:amendment",
        document_type="10-K/A",
        published_date="2026-03-01",
        retrieved_at="2026-03-02T01:02:03Z",
        source_url=original_source.source_url.replace(".htm", "-amendment.htm"),
        content_sha256=canonical_sha256(
            {"document_id": original_source.document_id, "kind": "amendment"}
        ),
    )
    selected = next(
        fact
        for fact in first.facts
        if fact.concept
        == ("net_income" if operand == "metric" else "weighted_average_diluted_shares")
    )
    amended = replace(
        selected,
        fact_id=f"{selected.fact_id}:amendment",
        source_document_id=amended_source.document_id,
        source_locator=f"{selected.source_locator}:amendment",
    )
    peer_graphs[0] = replace(
        first,
        documents=(*first.documents, amended_source),
        facts=(*first.facts, amended),
    )
    peer_graphs[0].validate()

    with pytest.raises(
        ValuationSynthesisError,
        match="peer multiple operands do not have registered SEC/IR semantics",
    ):
        _rebuild_peer_authority_with_graphs(
            run_result,
            peer_authority,
            tuple(peer_graphs),
            additional_reviewed_facts={selected.issuer_id: (amended,)},
        )


@pytest.mark.parametrize(
    ("operand", "conflict_kind"),
    (("metric", "value"), ("metric", "basis"), ("shares", "value")),
)
def test_comparable_current_period_policy_rejects_conflict_at_latest_key(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    operand: str,
    conflict_kind: str,
) -> None:
    run_result, _basis, _forward, peer_authority, *_rest = _complete_synthesis(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    peer_graphs = list(peer_authority.peer_graphs)
    first = peer_graphs[0]
    selected = next(
        fact
        for fact in first.facts
        if fact.concept
        == ("net_income" if operand == "metric" else "weighted_average_diluted_shares")
    )
    conflicting = replace(
        selected,
        fact_id=f"{selected.fact_id}:same-day-conflict",
        concept=(
            "net_income_loss"
            if conflict_kind == "basis"
            else selected.concept
        ),
        value=(selected.value + 1 if conflict_kind == "value" else selected.value),
        source_locator=f"{selected.source_locator}:same-day-conflict",
    )
    peer_graphs[0] = replace(first, facts=(*first.facts, conflicting))
    peer_graphs[0].validate()

    with pytest.raises(
        ValuationSynthesisError,
        match="peer multiple operands do not have registered SEC/IR semantics",
    ):
        _rebuild_peer_authority_with_graphs(
            run_result,
            peer_authority,
            tuple(peer_graphs),
            additional_reviewed_facts={selected.issuer_id: (conflicting,)},
        )


@pytest.mark.parametrize(("age_days", "accepted"), ((456, True), (457, False)))
def test_comparable_current_period_policy_enforces_456_day_boundary(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    age_days: int,
    accepted: bool,
) -> None:
    run_result, _basis, _forward, peer_authority, *_rest = _complete_synthesis(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    period_end = date.fromisoformat(run_result.data_cutoff_date) - timedelta(days=age_days)
    period_start = period_end - timedelta(days=364)
    period = {"start": period_start.isoformat(), "end": period_end.isoformat()}
    peer_graphs = list(peer_authority.peer_graphs)
    first = peer_graphs[0]
    peer_graphs[0] = replace(
        first,
        facts=tuple(replace(fact, period=period) for fact in first.facts),
    )
    peer_graphs[0].validate()

    if accepted:
        rebuilt = _rebuild_peer_authority_with_graphs(
            run_result,
            peer_authority,
            tuple(peer_graphs),
        )
        assert rebuilt.metric_inputs[0]["peer_observations"]
    else:
        with pytest.raises(
            ValuationSynthesisError,
            match="peer multiple operands do not have registered SEC/IR semantics",
        ):
            _rebuild_peer_authority_with_graphs(
                run_result,
                peer_authority,
                tuple(peer_graphs),
            )


def test_peer_selection_and_forecast_authority_reject_outcome_filtering_and_rebinds(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_result, _basis, _forward, peer_authority, *_rest = _complete_synthesis(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    forecast_payload = to_json_value(peer_authority.forecast_review.reviewed_payload)
    forecast_payload["metric_inputs"][0]["peer_inputs"].pop()
    dropped_review = _review(
        run_result,
        scope="comparable_forecast",
        reviewed_at=peer_authority.forecast_review.reviewed_at,
        reviewed_payload=forecast_payload,
    )
    with pytest.raises(ValuationSynthesisError, match="dropping a preselected peer"):
        build_reviewed_peer_set_authority(
            run_result=run_result,
            selection_review=peer_authority.selection_review,
            forecast_review=dropped_review,
            peer_graphs=peer_authority.peer_graphs,
            futu_peer_evidence_set=peer_authority.futu_peer_evidence_set,
            verifier=peer_authority.verifier,
        )

    free_multiple = to_json_value(peer_authority.forecast_review.reviewed_payload)
    free_multiple["metric_inputs"][0]["peer_inputs"][0]["current_multiple"] = "1"
    free_review = _review(
        run_result,
        scope="comparable_forecast",
        reviewed_at=peer_authority.forecast_review.reviewed_at,
        reviewed_payload=free_multiple,
    )
    with pytest.raises(ValuationSynthesisError, match="fields are not closed"):
        build_reviewed_peer_set_authority(
            run_result=run_result,
            selection_review=peer_authority.selection_review,
            forecast_review=free_review,
            peer_graphs=peer_authority.peer_graphs,
            futu_peer_evidence_set=peer_authority.futu_peer_evidence_set,
            verifier=peer_authority.verifier,
        )

    rebound_metrics = to_json_value(peer_authority.metric_inputs)
    rebound_metrics[0]["peer_observations"][0]["current_multiple"] = "1"
    with pytest.raises(ValuationSynthesisError, match="public projection does not replay"):
        replace(peer_authority, metric_inputs=tuple(rebound_metrics))

    selection_payload = to_json_value(peer_authority.selection_review.reviewed_payload)
    first_request_at = min(
        request.request_started_at
        for peer in peer_authority.futu_peer_evidence_set.peers
        for request in peer.execution.requests
    )
    selection_payload["selection_frozen_at"] = first_request_at
    late_selection = _review(
        run_result,
        scope="peer_set_selection",
        reviewed_at=first_request_at,
        reviewed_payload=selection_payload,
    )
    with pytest.raises(ValuationSynthesisError, match="before peer selection froze"):
        build_reviewed_peer_set_authority(
            run_result=run_result,
            selection_review=late_selection,
            forecast_review=peer_authority.forecast_review,
            peer_graphs=peer_authority.peer_graphs,
            futu_peer_evidence_set=peer_authority.futu_peer_evidence_set,
            verifier=peer_authority.verifier,
        )
