from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from phase5_v1_scope_support import formal_scope_graph, typed_research_inputs_for_graph
from test_phase5_v1_owner_equity_runtime import (
    _config,
    _request_args,
    _runtime_fixture,
    _write_canonical,
)
from test_phase5_v1_report_publisher import _typed_report_inputs

from owner_research.owner_equity_research import (
    OfficialResearchPhaseResult,
    OwnerEquityResearchDependencies,
    OwnerEquityResearchError,
    OwnerEquityResearchInputReceipt,
    OwnerEquityResearchRequest,
    OwnerEquityResearchResult,
    PhaseReceipt,
    PhaseStatus,
    PublicationProfile,
    ResearchIntent,
    SecurityScope,
    run_owner_equity_research,
    validate_owner_equity_research_result_projection,
    validate_owner_equity_research_schema_payload,
)
from owner_research.owner_equity_runtime import (
    build_runtime_dependencies,
    load_owner_equity_runtime,
    write_research_runtime_context,
)


def _request(
    graph,
    *,
    requested_at: str = "2026-08-15T09:00:00+08:00",
    intent: ResearchIntent = ResearchIntent.RESEARCH,
    profile: PublicationProfile | None = None,
) -> OwnerEquityResearchRequest:
    bundle = graph.research_bundles[0]
    return OwnerEquityResearchRequest(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        intent=intent,
        profile=profile,
        requested_by="human:runtime-reviewer",
        requested_at=requested_at,
    )


def _ordinary_runtime(sample_payloads, monkeypatch, tmp_path, *, research_graph=None):
    if research_graph is None:
        research_input, source_index, _, _ = _typed_report_inputs(sample_payloads, tmp_path)
        graph = source_index.graph
    else:
        research_input, source_index = typed_research_inputs_for_graph(
            research_graph,
            tmp_path / "strict-research-input",
        )
        graph = source_index.graph
    graph_file = write_research_runtime_context(
        graph=graph,
        output_file=tmp_path / "ordinary-research-graph.json",
    )
    research = {
        "research_graph_file": str(graph_file),
        "research_bundle_directory": str(research_input.source_directory),
    }
    config_file = _write_canonical(tmp_path / "research-runtime.json", _config(research))
    runtime = load_owner_equity_runtime(
        config_file,
        intent=ResearchIntent.RESEARCH,
        profile=None,
    )
    return graph, runtime


def _ordinary_result(sample_payloads, monkeypatch, tmp_path):
    graph, runtime = _ordinary_runtime(sample_payloads, monkeypatch, tmp_path)
    request = _request(graph)
    result = run_owner_equity_research(
        request=request,
        dependencies=build_runtime_dependencies(runtime),
    )
    return graph, runtime, request, result


def _result_values(result: OwnerEquityResearchResult) -> dict[str, object]:
    return {
        "status": result.status,
        "input_receipt": result.input_receipt,
        "official_research": result.official_research,
        "quarterly": result.quarterly,
        "futu_nonprice": result.futu_nonprice,
        "price_blind": result.price_blind,
        "market_reference": result.market_reference,
        "kernel": result.kernel,
        "synthesis": result.synthesis,
        "score": result.score,
        "market_expectations": result.market_expectations,
        "report": result.report,
        "publication": result.publication,
        "audit": result.audit,
        "quarantine_receipt": result.quarantine_receipt,
        "trace": result.trace,
        "issue_codes": result.issue_codes,
    }


def test_ordinary_research_retains_exact_authority_and_makes_zero_futu_calls(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    graph, runtime = _ordinary_runtime(sample_payloads, monkeypatch, tmp_path)
    transport_constructed = False

    def forbidden_transport(*args, **kwargs):
        nonlocal transport_constructed
        transport_constructed = True
        raise AssertionError("ordinary research constructed Futu transport")

    monkeypatch.setattr(
        "owner_research.futu_sidecar.AttestedFutuSidecarSession.open",
        forbidden_transport,
    )
    result = run_owner_equity_research(
        request=_request(graph),
        dependencies=build_runtime_dependencies(runtime),
    )

    assert runtime.valuation_context is None
    assert result.status is PhaseStatus.PARTIAL
    assert result.issue_codes == (
        "official_research_partial:security_scope_unresolved",
    )
    assert [item.phase for item in result.trace] == ["official_research_freeze"]
    assert result.trace[0].status is PhaseStatus.PARTIAL
    assert result.futu_evidence_bundle is None
    assert result.six_file_archive is None
    assert transport_constructed is False
    assert result.official_research is not None
    assert result.official_research.security_scope.sec_reporting is True
    assert (
        result.official_research.security_scope.incomplete_issue
        == "official_research_partial:security_scope_unresolved"
    )
    assert result.official_research.security_scope.specialist_issue is None
    assert result.official_research.receipt is not None
    assert result.official_research.receipt.authorities == (
        runtime.research_authority.research,
        runtime.research_authority.source_index,
        result.official_research.security_scope,
    )
    validate_owner_equity_research_result_projection(result.to_dict())


def test_ordinary_research_completes_from_formal_scope_facts_without_futu_or_valuation(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    graph, runtime = _ordinary_runtime(
        sample_payloads,
        monkeypatch,
        tmp_path,
        research_graph=formal_scope_graph(sample_payloads),
    )
    transport_constructed = False

    def forbidden_transport(*args, **kwargs):
        nonlocal transport_constructed
        transport_constructed = True
        raise AssertionError("ordinary research constructed Futu transport")

    monkeypatch.setattr(
        "owner_research.futu_sidecar.AttestedFutuSidecarSession.open",
        forbidden_transport,
    )
    result = run_owner_equity_research(
        request=_request(graph),
        dependencies=build_runtime_dependencies(runtime),
    )

    assert runtime.valuation_context is None
    assert result.status is PhaseStatus.COMPLETED
    assert result.issue_codes == ()
    assert result.futu_evidence_bundle is None
    assert result.six_file_archive is None
    assert transport_constructed is False
    assert result.official_research is not None
    scope = result.official_research.security_scope
    assert scope == SecurityScope(
        listing_mics=("XNYS",),
        currency="USD",
        security_kind="single_common_stock",
        share_classes=("common",),
        sec_reporting=True,
        industry_kind="general_operating_company",
    )
    assert scope.incomplete_issue is None
    assert scope.specialist_issue is None


def test_formal_unsupported_scope_requires_specialist_on_ordinary_route(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    graph, runtime = _ordinary_runtime(
        sample_payloads,
        monkeypatch,
        tmp_path,
        research_graph=formal_scope_graph(
            sample_payloads,
            security_structure="adr_or_depositary_receipt",
        ),
    )
    result = run_owner_equity_research(
        request=_request(graph),
        dependencies=build_runtime_dependencies(runtime),
    )

    assert runtime.valuation_context is None
    assert result.status is PhaseStatus.SPECIALIST_REQUIRED
    assert result.issue_codes == ("specialist_required:adr",)
    assert [item.phase for item in result.trace] == ["official_research_freeze"]
    assert result.official_research is not None
    assert result.official_research.security_scope.incomplete_issue is None
    assert result.official_research.security_scope.specialist_issue == (
        "specialist_required:adr"
    )
    assert result.futu_evidence_bundle is None


def test_report_route_stops_partial_before_report_or_futu_when_scope_is_incomplete(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    graph, runtime = _ordinary_runtime(sample_payloads, monkeypatch, tmp_path)
    downstream_called = False

    def forbidden_downstream(*args):
        nonlocal downstream_called
        downstream_called = True
        raise AssertionError("incomplete scope crossed a downstream capability")

    dependencies = replace(
        build_runtime_dependencies(runtime),
        build_report=forbidden_downstream,
        futu_nonprice=forbidden_downstream,
        intent=ResearchIntent.REPORT,
        profile=PublicationProfile.RESEARCH_ONLY,
    )
    result = run_owner_equity_research(
        request=_request(
            graph,
            intent=ResearchIntent.REPORT,
            profile=PublicationProfile.RESEARCH_ONLY,
        ),
        dependencies=dependencies,
    )

    assert runtime.valuation_context is None
    assert result.status is PhaseStatus.PARTIAL
    assert result.issue_codes == (
        "official_research_partial:security_scope_unresolved",
    )
    assert [item.phase for item in result.trace] == ["official_research_freeze"]
    assert result.report is None
    assert result.futu_evidence_bundle is None
    assert downstream_called is False


@pytest.mark.parametrize("unsafe", (object(), SimpleNamespace(fingerprint="a" * 64)))
def test_phase_receipt_rejects_generic_or_duck_typed_authority(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    unsafe,
) -> None:
    _, _, _, result = _ordinary_result(sample_payloads, monkeypatch, tmp_path)
    official = result.official_research
    assert official is not None and official.receipt is not None

    with pytest.raises(OwnerEquityResearchError, match="authority tuple"):
        replace(official.receipt, authorities=(unsafe,))


def test_phase_result_rejects_arbitrary_payload_even_with_existing_receipt(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    _, _, _, result = _ordinary_result(sample_payloads, monkeypatch, tmp_path)
    official = result.official_research
    assert official is not None

    with pytest.raises(OwnerEquityResearchError, match="strict-load authorities"):
        replace(official, research_input=SimpleNamespace(fingerprint="b" * 64))


def test_official_phase_replays_captured_bytes_without_reopening_rebound_path(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    _, _, _, result = _ordinary_result(sample_payloads, monkeypatch, tmp_path)
    official = result.official_research
    assert official is not None and official.research_input is not None
    source = official.research_input.source_directory
    moved = source.with_name(f"{source.name}-original")
    source.rename(moved)
    source.mkdir()
    (source / "research-bundle.json").write_text("{}\n", encoding="utf-8")
    (source / "run-manifest.json").write_text("{}\n", encoding="utf-8")

    assert replace(official) == official

    captured = dict(official.research_input.file_bytes)
    captured["research-bundle.json"] += b" "
    with pytest.raises(ValueError, match="typed snapshot does not replay"):
        replace(official.research_input, file_bytes=captured)


def test_phase_receipt_cannot_follow_a_changed_exact_payload(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    _, _, _, result = _ordinary_result(sample_payloads, monkeypatch, tmp_path)
    official = result.official_research
    assert official is not None and official.receipt is not None
    specialist_scope = SecurityScope(
        listing_mics=("XNAS",),
        currency="USD",
        security_kind="adr",
        share_classes=("common",),
        sec_reporting=True,
        industry_kind="general_operating_company",
    )

    with pytest.raises(OwnerEquityResearchError, match="receipt was rebound"):
        replace(official, security_scope=specialist_scope)


def test_same_issuer_foreign_request_phase_cannot_be_coordinated_into_result(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    graph, runtime, _, first = _ordinary_result(sample_payloads, monkeypatch, tmp_path)
    second_request = _request(graph, requested_at="2026-08-15T09:01:00+08:00")
    second = run_owner_equity_research(
        request=second_request,
        dependencies=build_runtime_dependencies(runtime),
    )
    assert first.input_receipt != second.input_receipt
    assert second.official_research is not None
    values = _result_values(first)
    values["official_research"] = second.official_research

    with pytest.raises(OwnerEquityResearchError, match="another owner-equity request"):
        OwnerEquityResearchResult.create(**values)


def test_result_rejects_stale_fingerprint_after_trace_replacement(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    _, _, _, result = _ordinary_result(sample_payloads, monkeypatch, tmp_path)

    with pytest.raises(OwnerEquityResearchError, match="trace status differs"):
        replace(
            result,
            trace=(replace(result.trace[0], status=PhaseStatus.COMPLETED),),
        )

    with pytest.raises(OwnerEquityResearchError, match="effective recommendation"):
        replace(result, effective_recommendation="观察")


def test_input_receipt_rejects_same_issuer_different_request_rebinding(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    graph, _, _, result = _ordinary_result(sample_payloads, monkeypatch, tmp_path)
    changed = _request(graph, requested_at="2026-08-15T09:02:00+08:00")

    with pytest.raises(OwnerEquityResearchError, match="ID is not deterministic"):
        replace(result.input_receipt, request=changed)


def test_high_level_schemas_reject_unknown_members(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    _, _, _, result = _ordinary_result(sample_payloads, monkeypatch, tmp_path)
    result_payload = result.to_dict()
    result_payload["caller_authority_hash"] = "c" * 64
    input_payload = result.input_receipt.to_dict()
    input_payload["path"] = "/tmp/rebound"

    with pytest.raises(OwnerEquityResearchError, match="schema validation failed"):
        validate_owner_equity_research_result_projection(result_payload)
    with pytest.raises(OwnerEquityResearchError, match="schema validation failed"):
        validate_owner_equity_research_schema_payload(
            "owner-equity-research-input-receipt",
            input_payload,
        )


def test_cleanup_runs_exactly_once_after_success_and_adapter_failure(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    graph, runtime = _ordinary_runtime(sample_payloads, monkeypatch, tmp_path)
    dependencies = build_runtime_dependencies(runtime)
    cleanup_calls: list[str] = []
    successful = replace(dependencies, cleanup=lambda: cleanup_calls.append("success"))

    result = run_owner_equity_research(request=_request(graph), dependencies=successful)
    assert result.status is PhaseStatus.PARTIAL
    assert cleanup_calls == ["success"]

    def failed_official(request):
        raise OSError("private filesystem detail")

    failed = replace(
        dependencies,
        official_research=failed_official,
        cleanup=lambda: cleanup_calls.append("failure"),
    )
    blocked = run_owner_equity_research(request=_request(graph), dependencies=failed)
    assert blocked.status is PhaseStatus.BLOCKED
    assert cleanup_calls == ["success", "failure"]


@pytest.mark.parametrize(
    ("intent", "profile"),
    (
        (ResearchIntent.RESEARCH, None),
        (ResearchIntent.QUARTERLY, None),
        (ResearchIntent.REPORT, PublicationProfile.RESEARCH_ONLY),
        (ResearchIntent.VALUATION, PublicationProfile.FULL_VALUATION),
    ),
)
def test_specialist_scope_stops_before_any_downstream_capability(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    intent: ResearchIntent,
    profile: PublicationProfile | None,
) -> None:
    graph, runtime = _ordinary_runtime(sample_payloads, monkeypatch, tmp_path)
    base = build_runtime_dependencies(runtime)
    downstream_called = False

    def specialist(request):
        phase = base.official_research(request)
        assert phase.research_input is not None and phase.source_index is not None
        scope = SecurityScope(
            listing_mics=("XNAS",),
            currency="USD",
            security_kind="adr",
            share_classes=("common",),
            sec_reporting=True,
            industry_kind="general_operating_company",
        )
        input_receipt = OwnerEquityResearchInputReceipt.from_request(request)
        return OfficialResearchPhaseResult(
            status=PhaseStatus.PARTIAL,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=PhaseReceipt.create(
                phase="official_research_freeze",
                input_receipt=input_receipt,
                upstream_receipts=(),
                authorities=(phase.research_input, phase.source_index, scope),
            ),
            security_scope=scope,
            research_input=phase.research_input,
            source_index=phase.source_index,
            price_blind=True,
            issue_codes=("official_research_partial:missing_evidence",),
        )

    def forbidden_downstream(*args):
        nonlocal downstream_called
        downstream_called = True
        raise AssertionError("specialist route crossed a downstream capability")

    dependencies = replace(
        base,
        official_research=specialist,
        quarterly=forbidden_downstream,
        futu_nonprice=forbidden_downstream,
        build_report=forbidden_downstream,
        intent=intent,
        profile=profile,
    )
    request = _request(
        graph,
        intent=intent,
        profile=profile,
    )
    result = run_owner_equity_research(request=request, dependencies=dependencies)

    assert result.status is PhaseStatus.SPECIALIST_REQUIRED
    assert result.issue_codes == ("specialist_required:adr",)
    assert [item.phase for item in result.trace] == ["official_research_freeze"]
    assert downstream_called is False


def test_request_args_helper_remains_bound_to_same_typed_request(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    graph, research, _, _ = _runtime_fixture(sample_payloads, monkeypatch, tmp_path)
    config_file = _write_canonical(tmp_path / "research-runtime.json", _config(research))
    args = _request_args(graph, config_file, "research")
    assert args[0] == "research"
    assert args[1:3] == ["--runtime-config", str(config_file)]


def test_package_root_exposes_the_governed_high_level_run_api() -> None:
    import owner_research

    expected = {
        "OwnerEquityResearchDependencies": OwnerEquityResearchDependencies,
        "OwnerEquityResearchError": OwnerEquityResearchError,
        "OwnerEquityResearchRequest": OwnerEquityResearchRequest,
        "OwnerEquityResearchResult": OwnerEquityResearchResult,
        "PhaseStatus": PhaseStatus,
        "PublicationProfile": PublicationProfile,
        "ResearchIntent": ResearchIntent,
        "SecurityScope": SecurityScope,
        "build_runtime_dependencies": build_runtime_dependencies,
        "load_owner_equity_runtime": load_owner_equity_runtime,
        "run_owner_equity_research": run_owner_equity_research,
    }

    assert expected.keys() <= set(owner_research.__all__)
    for name, authority in expected.items():
        assert getattr(owner_research, name) is authority


def test_valuation_route_always_publishes_and_post_kernel_failure_is_quarantined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the closed control flow independently of the expensive live fixtures."""

    import owner_research.owner_equity_research as module

    class RoutePhase:
        def __init__(self, **values):
            self.__dict__.update(values)

    class CapturedResult:
        @classmethod
        def create(cls, **values):
            values["effective_recommendation"] = module._derive_effective_recommendation(
                values
            )
            return SimpleNamespace(**values)

    quarantine_calls: list[tuple[str, object, tuple[str, ...]]] = []

    class CapturedQuarantine:
        @classmethod
        def from_kernel(cls, *, phase, kernel, issue_codes):
            quarantine_calls.append((phase, kernel, issue_codes))
            return SimpleNamespace(kind="hash-only-quarantine", phase=phase)

    for name in (
        "OfficialResearchPhaseResult",
        "FutuNonPricePhaseResult",
        "PriceBlindRefreezePhaseResult",
        "FutuMarketReferencePhaseResult",
        "KernelValuationPhaseResult",
        "SynthesisPhaseResult",
        "ScorePhaseResult",
        "MarketExpectationsPhaseResult",
        "ReportPhaseResult",
        "PublicationPhaseResult",
    ):
        monkeypatch.setattr(module, name, RoutePhase)
    monkeypatch.setattr(module, "OwnerEquityResearchResult", CapturedResult)
    monkeypatch.setattr(module, "QuarantineReceipt", CapturedQuarantine)

    request = OwnerEquityResearchRequest(
        issuer_id="issuer:us:route-test",
        data_cutoff_date="2026-08-14",
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
        requested_by="human:route-reviewer",
        requested_at="2026-08-15T09:00:00+08:00",
    )
    calls: list[str] = []

    def phase(name: str, **extra):
        def adapter(*args):
            calls.append(name)
            return RoutePhase(
                status=PhaseStatus.COMPLETED,
                issuer_id=request.issuer_id,
                data_cutoff_date=request.data_cutoff_date,
                issue_codes=(),
                **extra,
            )

        return adapter

    dependencies = OwnerEquityResearchDependencies(
        official_research=phase(
            "official",
            security_scope=SimpleNamespace(specialist_issue=None),
        ),
        quarterly=phase("quarterly"),
        futu_nonprice=phase("futu_nonprice"),
        refreeze_price_blind=phase("price_blind"),
        futu_market_reference=phase("market"),
        run_owner_valuation=phase("kernel"),
        synthesize=phase("synthesis"),
        score=phase("score", recommendation="观察"),
        futu_market_expectations=phase("expectations"),
        build_report=phase("report", profile=PublicationProfile.FULL_VALUATION),
        publish=phase("publication", profile=PublicationProfile.FULL_VALUATION),
        audit=phase("audit"),
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
    )

    completed = run_owner_equity_research(request=request, dependencies=dependencies)
    assert completed.status is PhaseStatus.COMPLETED
    assert completed.publication is not None
    assert calls.count("kernel") == 1
    assert calls[-2:] == ["report", "publication"]
    assert completed.effective_recommendation == "观察"

    def partial_expectations(*args):
        calls.append("expectations")
        return RoutePhase(
            status=PhaseStatus.PARTIAL,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            issue_codes=("market_expectations_missing:analyst_consensus",),
        )

    calls.clear()
    partial_dependencies = replace(
        dependencies,
        futu_market_expectations=partial_expectations,
    )
    partial = run_owner_equity_research(
        request=request,
        dependencies=partial_dependencies,
    )
    assert partial.status is PhaseStatus.PARTIAL
    assert partial.score.recommendation == "观察"
    assert partial.effective_recommendation == "无法评级"
    assert partial.publication is not None
    assert calls[-3:] == ["expectations", "report", "publication"]

    calls.clear()

    def blocked_report(*args):
        calls.append("report")
        raise OSError("private report failure")

    blocked_dependencies = replace(dependencies, build_report=blocked_report)
    blocked = run_owner_equity_research(
        request=request,
        dependencies=blocked_dependencies,
    )
    assert blocked.status is PhaseStatus.BLOCKED
    assert calls.count("kernel") == 1
    assert quarantine_calls[-1][0] == "report"
    assert blocked.quarantine_receipt.kind == "hash-only-quarantine"
    assert blocked.kernel is None
    assert blocked.synthesis is None
    assert blocked.score is None
    assert blocked.report is None
    assert blocked.publication is None
    assert "valuation_outputs_quarantined:report" in blocked.issue_codes
