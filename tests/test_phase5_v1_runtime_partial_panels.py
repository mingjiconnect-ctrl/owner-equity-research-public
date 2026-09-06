from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import test_phase5_v1_valuation_synthesis as synthesis_fixtures
from phase4a_support import replace_graph
from phase4e2_support import complete_phase4e_graph
from test_phase4e1_research_bundle_builder import _completed_graph, _input_graph

import owner_research.owner_equity_runtime as runtime_module
from owner_research.fingerprints import canonical_json, canonical_sha256
from owner_research.owner_equity_research import (
    OfficialResearchPhaseResult,
    OwnerEquityResearchDependencies,
    OwnerEquityResearchRequest,
    PhaseStatus,
    PublicationProfile,
    ResearchIntent,
    run_owner_equity_research,
)
from owner_research.owner_equity_runtime import (
    LiveStagePlan,
    OwnerEquityRuntimeError,
    _LiveBlocked,
    _LiveRuntimeState,
    _validate_stage_plan_request_time,
    build_runtime_dependencies,
    load_owner_equity_runtime,
    write_research_runtime_context,
)
from owner_research.owner_scorecard import (
    CompositeScoreGapAuthority,
    build_owner_scorecard,
    build_score_v2,
    resolve_score_review_authority,
)
from owner_research.research_bundle_artifacts import write_research_bundle_artifacts
from owner_research.research_bundle_builder import ResearchBundleBuildResult, build_research_bundle
from owner_research.valuation_synthesis import ValuationSynthesisError
from owner_research.workflow_cli import WorkflowService
from owner_research.workflow_cli import main as workflow_main


def _request(run_result: Any, *, requested_at: str = "2026-08-15T01:00:00Z"):
    return OwnerEquityResearchRequest(
        issuer_id=run_result.issuer_id,
        data_cutoff_date=run_result.data_cutoff_date,
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
        requested_by="human:runtime-partial-reviewer",
        requested_at=requested_at,
    )


def _live_state(chain: tuple[Any, ...]) -> _LiveRuntimeState:
    (
        run_result,
        basis,
        forward,
        peer_authority,
        _comparable,
        _composite,
        scores,
        _scorecard,
    ) = chain
    state = _LiveRuntimeState(runtime=SimpleNamespace())
    state.run_result = run_result
    state.basis_review = basis._review_authority
    state.forward_review = forward._input_authority._review_authority
    state.selection_review = peer_authority.selection_review
    state.forecast_review = peer_authority.forecast_review
    state.peer_plan = SimpleNamespace(
        peer_graph_contexts=tuple(
            SimpleNamespace(graph=graph) for graph in peer_authority.peer_graphs
        )
    )
    state.keyring = peer_authority.verifier
    state.peer_evidence_set = peer_authority.futu_peer_evidence_set
    state.score_reviews = tuple(score._review_authority for score in scores)
    return state


@pytest.mark.parametrize(
    ("missing_forward", "missing_comparable", "expected_issues"),
    (
        (True, False, ("missing_forward_reoi_panel",)),
        (False, True, ("missing_comparable_panel",)),
        (
            True,
            True,
            ("missing_comparable_panel", "missing_forward_reoi_panel"),
        ),
    ),
)
def test_runtime_qualification_gaps_produce_typed_partial_without_fallback(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    missing_forward: bool,
    missing_comparable: bool,
    expected_issues: tuple[str, ...],
) -> None:
    chain = synthesis_fixtures._complete_synthesis(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    state = _live_state(chain)
    _, basis, forward, peer_authority, comparable, *_ = chain
    monkeypatch.setattr(
        runtime_module,
        "build_valuation_basis_receipt",
        lambda *_args, **_kwargs: basis,
    )
    monkeypatch.setattr(
        runtime_module,
        "build_forward_reoi_valuation",
        lambda *_args, **_kwargs: forward,
    )
    monkeypatch.setattr(
        runtime_module,
        "build_reviewed_peer_set_authority",
        lambda *_args, **_kwargs: peer_authority,
    )
    monkeypatch.setattr(
        runtime_module,
        "build_comparable_valuation",
        lambda *_args, **_kwargs: comparable,
    )

    if missing_forward:
        def unavailable_forward(*_args: Any, **_kwargs: Any) -> None:
            raise ValuationSynthesisError(
                "forward ReOI review lacks current NOA Fact authority"
            )

        monkeypatch.setattr(
            runtime_module,
            "build_forward_reoi_valuation",
            unavailable_forward,
        )
    if missing_comparable:
        def unavailable_comparable(*_args: Any, **_kwargs: Any) -> None:
            raise ValuationSynthesisError(
                "complete-case policy forbids dropping a preselected peer"
            )

        monkeypatch.setattr(
            runtime_module,
            "build_comparable_valuation",
            unavailable_comparable,
        )

    composite = state.run_synthesis(_request(chain[0]))

    assert composite.status == "blocked"
    assert composite.issue_codes == expected_issues
    assert composite.current_intrinsic_value is None
    assert composite.twelve_month_target is None
    assert composite.margin_of_safety is None
    assert composite.twelve_month_upside is None
    assert composite.recommendation_eligible is False
    assert (state.forward_reoi is None) is missing_forward
    assert (state.comparable is None) is missing_comparable

    original_composite = chain[5]
    assert original_composite.fingerprint != composite.fingerprint
    assert {
        review.reviewed_payload["composite_valuation_fingerprint"]
        for review in state.score_reviews
    } == {original_composite.fingerprint}
    score_authorities = tuple(
        resolve_score_review_authority(
            composite_valuation=composite,
            planned_review=review,
        )
        for review in state.score_reviews
    )
    assert all(type(item) is CompositeScoreGapAuthority for item in score_authorities)
    scores = tuple(
        build_score_v2(
            composite_valuation=composite,
            review_authority=authority,
        )
        for authority in score_authorities
    )
    scorecard = build_owner_scorecard(
        composite_valuation=composite,
        lens_scores=scores,
    )
    assert all(score.status == "partial" for score in scores)
    assert all(score.total_score is None for score in scores)
    assert all(
        component["status"] == "unknown"
        and component["score"] is None
        and component["confidence_percent"] is None
        and "another composite" in component["rationale"]
        and "recommendation-ineligible" not in component["rationale"]
        for score in scores
        for component in score.components
    )
    assert scorecard.status == "blocked"
    assert scorecard.overall_score is None
    assert scorecard.confidence_percent is None
    assert scorecard.recommendation == "无法评级"


def test_runtime_does_not_downgrade_replay_or_tamper_errors(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    chain = synthesis_fixtures._complete_synthesis(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    state = _live_state(chain)
    _, basis, _forward, _peer_authority, _comparable, *_ = chain
    monkeypatch.setattr(
        runtime_module,
        "build_valuation_basis_receipt",
        lambda *_args, **_kwargs: basis,
    )

    def rebound_forward(*_args: Any, **_kwargs: Any) -> None:
        raise ValuationSynthesisError("forward ReOI input authority changed")

    monkeypatch.setattr(
        runtime_module,
        "build_forward_reoi_valuation",
        rebound_forward,
    )
    with pytest.raises(
        ValuationSynthesisError,
        match="forward ReOI input authority changed",
    ):
        state.run_synthesis(_request(chain[0]))
    assert state.composite is None


def _stage_plan(authority_evaluated_at: str) -> LiveStagePlan:
    payload = {
        "run_id": "run:request-time-bound",
        "authority_evaluated_at": authority_evaluated_at,
        "pre_price_request_started_at": "2026-08-15T01:06:00Z",
        "crosscheck_created_at": "2026-08-15T01:07:00Z",
        "market_request_started_at": "2026-08-15T01:08:00Z",
        "market_checkpoint_at": "2026-08-15T01:09:00Z",
        "conclusion_frozen_at": "2026-08-15T01:10:00Z",
        "post_request_started_at": "2026-08-15T01:11:00Z",
        "finalized_at": "2026-08-15T01:12:00Z",
        "kernel_timeout_seconds": 30,
        "runtime_receipt_wait_seconds": 1.0,
    }
    return LiveStagePlan(**payload, plan_fingerprint=canonical_sha256(payload))


@pytest.mark.parametrize(
    "authority_evaluated_at",
    ("2026-08-15T00:59:59Z", "2026-08-15T01:05:01Z"),
)
def test_stage_plan_authority_time_cannot_replay_outside_typed_request_window(
    authority_evaluated_at: str,
) -> None:
    request = OwnerEquityResearchRequest(
        issuer_id="issuer:request-time-bound",
        data_cutoff_date="2026-08-14",
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
        requested_by="human:runtime-partial-reviewer",
        requested_at="2026-08-15T01:00:00Z",
    )
    with pytest.raises(_LiveBlocked) as caught:
        _validate_stage_plan_request_time(_stage_plan(authority_evaluated_at), request)
    assert caught.value.issue_codes == ("stage_plan_request_time_mismatch",)


def test_stage_plan_authority_time_accepts_exact_typed_request_window() -> None:
    request = OwnerEquityResearchRequest(
        issuer_id="issuer:request-time-bound",
        data_cutoff_date="2026-08-14",
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
        requested_by="human:runtime-partial-reviewer",
        requested_at="2026-08-15T01:00:00Z",
    )
    _validate_stage_plan_request_time(_stage_plan("2026-08-15T01:05:00Z"), request)


def _runtime_with_bundle(graph, output: Path):
    output.mkdir(parents=True)
    if graph.research_bundles:
        assert len(graph.research_bundles) == 1
        bundle = graph.research_bundles[0]
        manifest = next(item for item in graph.manifests if item.run_id == bundle.run_id)
        result = ResearchBundleBuildResult(bundle=bundle, run_manifest=manifest)
        completed = graph
    else:
        result = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
        completed = _completed_graph(graph, result)
    bundle_directory = output / "bundle"
    write_research_bundle_artifacts(
        completed,
        result,
        output_directory=bundle_directory,
    )
    graph_file = write_research_runtime_context(
        graph=completed,
        output_file=output / "research-context.json",
    )
    config = {
        "schema_version": "1.0.0",
        "artifact_type": "owner-equity-runtime-config",
        "research": {
            "research_graph_file": str(graph_file),
            "research_bundle_directory": str(bundle_directory),
        },
        "report": None,
        "publication": None,
        "audit": None,
        "valuation": None,
    }
    config_file = output / "runtime.json"
    config_file.write_bytes((canonical_json(config) + "\n").encode("utf-8"))
    config_file.chmod(0o600)
    runtime = load_owner_equity_runtime(
        config_file,
        intent=ResearchIntent.RESEARCH,
        profile=None,
    )
    return runtime, result


def _partial_bundle_graph(sample_payloads: dict[str, dict[str, Any]]):
    graph = complete_phase4e_graph(sample_payloads)
    target_document = next(item for item in graph.documents if item.issuer_id == "issuer:acme")
    target_observation = next(
        item
        for item in graph.context_observations
        if item.source_document_id == target_document.document_id
    )
    context = replace(
        graph.competitive_context_snapshots[0],
        status="partial",
        source_document_ids=(target_document.document_id,),
        observation_ids=(target_observation.observation_id,),
        coverage=tuple(
            {
                **dict(item),
                "status": "blocked",
                "observation_ids": [],
                "missing_evidence": ["independent context evidence unavailable"],
            }
            for item in graph.competitive_context_snapshots[0].coverage
        ),
        missing_evidence=("independent context evidence unavailable",),
    )
    business_review = replace(
        graph.business_quality_reviews[0],
        status="partial",
        context_observation_ids=(target_observation.observation_id,),
        missing_evidence=("independent context evidence unavailable",),
    )
    manifest = replace(
        graph.manifests[0],
        input_document_hashes={
            target_document.document_id: target_document.content_sha256,
        },
    )
    graph = replace_graph(
        graph,
        documents=(target_document,),
        context_observations=(target_observation,),
        competitive_context_snapshots=(context,),
        business_quality_reviews=(business_review,),
        manifests=(manifest,),
    )
    newer_source = replace(
        graph.documents[0],
        document_id="doc:acme:2026-q1-10q-runtime-partial",
        document_type="10-Q",
        period={"start": "2026-01-01", "end": "2026-03-31"},
        published_date="2026-04-30",
        source_url="https://www.sec.gov/Archives/acme-2026-q1-runtime-partial",
        content_sha256="9" * 64,
    )
    manifest = replace(
        graph.manifests[0],
        input_document_hashes={
            **dict(graph.manifests[0].input_document_hashes),
            newer_source.document_id: newer_source.content_sha256,
        },
    )
    return replace_graph(
        graph,
        documents=(*graph.documents, newer_source),
        manifests=(manifest,),
    )


def _research_request(bundle, intent: ResearchIntent):
    return OwnerEquityResearchRequest(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        intent=intent,
        profile=(
            PublicationProfile.RESEARCH_ONLY
            if intent is ResearchIntent.REPORT
            else None
        ),
        requested_by="human:bundle-status-reviewer",
        requested_at="2026-08-15T01:00:00Z",
    )


def test_official_bundle_status_stops_research_and_report_before_downstream(
    sample_payloads: dict[str, dict[str, Any]],
    tmp_path: Path,
) -> None:
    cases = (
        (
            "partial",
            _partial_bundle_graph(sample_payloads),
            PhaseStatus.PARTIAL,
            "official_research_partial:missing_evidence",
        ),
        (
            "blocked",
            _input_graph(sample_payloads),
            PhaseStatus.BLOCKED,
            "official_research_blocked:bundle_status",
        ),
    )
    for label, graph, expected_status, issue in cases:
        runtime, build_result = _runtime_with_bundle(graph, tmp_path / label)
        assert build_result.bundle.status == label
        calls: list[str] = []

        def forbidden_downstream(
            *_args: Any,
            _calls: list[str] = calls,
            **_kwargs: Any,
        ) -> None:
            _calls.append("downstream")
            raise AssertionError("stopped official research invoked a downstream adapter")

        base_dependencies = build_runtime_dependencies(runtime)
        for intent in (
            ResearchIntent.RESEARCH,
            ResearchIntent.REPORT,
        ):
            profile = (
                PublicationProfile.RESEARCH_ONLY
                if intent is ResearchIntent.REPORT
                else None
            )
            dependencies = replace(
                base_dependencies,
                quarterly=forbidden_downstream,
                futu_nonprice=forbidden_downstream,
                refreeze_price_blind=forbidden_downstream,
                futu_market_reference=forbidden_downstream,
                run_owner_valuation=forbidden_downstream,
                synthesize=forbidden_downstream,
                score=forbidden_downstream,
                futu_market_expectations=forbidden_downstream,
                build_report=forbidden_downstream,
                publish=forbidden_downstream,
                audit=forbidden_downstream,
                intent=intent,
                profile=profile,
            )
            result = run_owner_equity_research(
                request=_research_request(build_result.bundle, intent),
                dependencies=dependencies,
            )
            assert result.status is expected_status
            assert result.issue_codes[0] == issue
            assert tuple(item.phase for item in result.trace) == (
                "official_research_freeze",
            )
            assert result.report is None
            assert result.publication is None
            assert result.futu_evidence_bundle is None
            assert result.official_research is not None
            if expected_status is PhaseStatus.PARTIAL:
                assert result.official_research.research_input is not None
                assert result.official_research.source_index is not None
                assert result.official_research.security_scope is not None
            else:
                assert result.official_research.receipt is None
                assert result.official_research.research_input is None
                assert result.official_research.source_index is None
                assert result.official_research.security_scope is None
        assert calls == []


def test_cleanup_failure_closes_local_transport_and_cli_emits_controlled_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class LocalTransport:
        closed = False

        def close(self) -> None:
            self.closed = True

    class FailedAbortSession:
        def __init__(self, local: LocalTransport) -> None:
            self._transport = local

        def abort(self, *, reason_code: str) -> None:
            assert reason_code == "caller_abort"
            raise RuntimeError("untrusted external cleanup details")

    local = LocalTransport()
    state = _LiveRuntimeState(runtime=SimpleNamespace())
    state.transport = FailedAbortSession(local)

    def blocked_official(request: OwnerEquityResearchRequest) -> OfficialResearchPhaseResult:
        return OfficialResearchPhaseResult(
            status=PhaseStatus.BLOCKED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=None,
            security_scope=None,
            research_input=None,
            source_index=None,
            price_blind=True,
            issue_codes=("official_research_blocked:test",),
        )

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("blocked official route invoked downstream work")

    dependencies = OwnerEquityResearchDependencies(
        official_research=blocked_official,
        quarterly=forbidden,
        futu_nonprice=forbidden,
        refreeze_price_blind=forbidden,
        futu_market_reference=forbidden,
        run_owner_valuation=forbidden,
        synthesize=forbidden,
        score=forbidden,
        futu_market_expectations=forbidden,
        build_report=forbidden,
        publish=forbidden,
        audit=forbidden,
        intent=ResearchIntent.RESEARCH,
        profile=None,
        cleanup=state.cleanup,
    )
    exit_code = workflow_main(
        (
            "research",
            "--issuer-id",
            "issuer:cleanup-test",
            "--data-cutoff-date",
            "2026-08-14",
            "--requested-by",
            "human:cleanup-reviewer",
            "--requested-at",
            "2026-08-15T01:00:00Z",
        ),
        service=WorkflowService(dependencies),
    )

    captured = capsys.readouterr()
    error = json.loads(captured.err)
    assert exit_code == 2
    assert captured.out == ""
    assert error == {
        "artifact_type": "owner-equity-research-cli-error",
        "error": "runtime cleanup failed",
        "status": "invalid_request",
    }
    assert "Traceback" not in captured.err
    assert "untrusted external cleanup details" not in captured.err
    assert local.closed is True
    assert state.transport is None


def test_direct_cleanup_failure_uses_closed_runtime_error() -> None:
    class FailedSession:
        def abort(self, *, reason_code: str) -> None:
            raise RuntimeError("external secret")

    state = _LiveRuntimeState(runtime=SimpleNamespace())
    state.transport = FailedSession()
    with pytest.raises(OwnerEquityRuntimeError, match="^sidecar cleanup failed$") as caught:
        state.cleanup()
    assert "external secret" not in str(caught.value)
    assert state.transport is None
