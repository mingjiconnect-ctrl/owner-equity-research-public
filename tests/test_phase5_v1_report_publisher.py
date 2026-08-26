from __future__ import annotations

import errno
import hashlib
import inspect
import json
import os
import subprocess
import threading
from copy import deepcopy
from dataclasses import replace
from decimal import ROUND_DOWN, ROUND_UP, Decimal, Subnormal, localcontext
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from phase4e2_support import complete_phase4e_graph
from phase5_v1_scope_support import formal_scope_graph
from test_phase4e1_research_bundle_builder import _completed_graph, _input_graph

import owner_research.research_publisher as publisher_module
import owner_research.research_report as report_module
from owner_research.contracts import ReportSpec, Score, contract_from_dict
from owner_research.fingerprints import (
    canonical_json,
    canonical_sha256,
)
from owner_research.owner_equity_research import (
    OwnerEquityResearchInputReceipt,
    OwnerEquityResearchRequest,
    PhaseReceipt,
    PhaseStatus,
    PublicationPhaseResult,
    PublicationProfile,
    ReportPhaseResult,
    ResearchIntent,
    ScorePhaseResult,
)
from owner_research.owner_equity_types import (
    build_futu_optional_data_dispositions,
    build_market_expectations_comparison,
    build_research_source_index,
)
from owner_research.research_bundle_artifacts import write_research_bundle_artifacts
from owner_research.research_bundle_builder import (
    ResearchBundleBuildResult,
    build_research_bundle,
)
from owner_research.research_bundle_validation import dependency_closure
from owner_research.research_publisher import (
    PUBLISH_IMAGE_MAX_BYTES,
    PUBLISH_MAX_MEMBERS,
    PublicationManifest,
    PublishedPackageReceipt,
    PublishedResearchPackage,
    ResearchPublisherError,
    _validate_limits,
    _verify_report_build,
    load_owner_research_package,
    load_published_package,
    publish_owner_research,
    publish_research_report,
    republish_owner_research_package,
)
from owner_research.research_report import (
    ComparableValuationPublicationManifest,
    CompositeValuationPublicationManifest,
    ForwardReOIValuationPublicationManifest,
    LatexReportRenderer,
    PdfRenderResult,
    ReportBuildReceipt,
    ReportBuildResult,
    ReportToolchainAuthority,
    ResearchReportContent,
    ResearchReportError,
    _closed_renderer_environment,
    _composite_horizon_publication,
    _composite_ineligible_narrative,
    _report_decimal,
    _report_ratio_percent,
    _stage_report_toolchain,
    _TrustedCacheEntry,
    _TrustedExecutableSnapshot,
    _TrustedTectonicCacheSnapshot,
    bootstrap_report_toolchain_authority_entry_from_manifest,
    build_research_report,
    load_report_toolchain_authority,
    load_report_toolchain_authority_registry,
    reload_research_input,
    reload_valuation_input,
)
from owner_research.valuation_run_archive import ValuationRunArchive
from owner_research.valuation_synthesis_types import build_named_human_review_authority


class DeterministicRenderer:
    def __init__(
        self,
        section_titles: tuple[str, ...],
        *,
        page_count: int = 30,
        page_character_counts: tuple[int, ...] | None = None,
        page_non_white_ratios: tuple[str, ...] | None = None,
    ) -> None:
        self.section_titles = section_titles
        self.page_count = page_count
        self.page_character_counts = page_character_counts or (120,) * page_count
        self.page_non_white_ratios = page_non_white_ratios or ("0.100000",) * page_count
        self.calls = 0

    def render(self, tex_sources):
        self.calls += 1
        assert set(tex_sources) == {
            "report.tex",
            "report-data.tex",
            "report-table.tex",
            "report-chart.tex",
        }
        assert b"\\documentclass" in tex_sources["report.tex"]
        assert "所有者视角综合研究报告" in tex_sources["report-data.tex"].decode()
        extracted = (
            "所有者视角综合研究报告 证据 研究 估值 "
            + " ".join(self.section_titles)
            + " "
            + tex_sources["report-data.tex"].decode().replace(r"\allowbreak{}", "")
        )
        return PdfRenderResult(
            pdf_bytes=b"%PDF-1.7\n% deterministic injected test renderer\n",
            page_count=self.page_count,
            extracted_text=extracted,
            rendered_page_count=self.page_count,
            renderer_id="phase5-test-renderer",
            renderer_version="1.0.0",
            engine="injected-test-renderer",
            page_text_character_counts=self.page_character_counts,
            rendered_page_sha256=("0" * 64,) * self.page_count,
            page_non_white_ratios=self.page_non_white_ratios,
        )


def _independent_all_page_pdf_qa(pdf_bytes: bytes) -> tuple[int, tuple[Decimal, ...]]:
    import pypdfium2 as pdfium
    from pypdf import PdfReader

    document = pdfium.PdfDocument(pdf_bytes)
    ratios: list[Decimal] = []
    try:
        for page_number in range(len(document)):
            page = document[page_number]
            bitmap = None
            try:
                bitmap = page.render(
                    scale=48 / 72,
                    fill_color=(255, 255, 255, 255),
                    rev_byteorder=True,
                )
                buffer = bytes(bitmap.buffer)
                non_white = 0
                for row in range(bitmap.height):
                    row_offset = row * bitmap.stride
                    for column in range(bitmap.width):
                        offset = row_offset + column * bitmap.n_channels
                        if min(buffer[offset : offset + 3]) < 245:
                            non_white += 1
                ratios.append(
                    Decimal(non_white) / Decimal(bitmap.width * bitmap.height)
                )
            finally:
                if bitmap is not None:
                    bitmap.close()
                page.close()
    finally:
        document.close()
    reader = PdfReader(BytesIO(pdf_bytes))
    page_count = len(reader.pages)
    assert page_count == len(ratios)
    assert all(value >= Decimal("0.040000") for value in ratios[1:])
    for index in (1, page_count // 2, page_count - 1):
        extracted = reader.pages[index].extract_text() or ""
        assert f"第 {index + 1}/{page_count} 页" in extracted
    last_page_text = reader.pages[-1].extract_text() or ""
    assert "类型 / Type" in last_page_text
    assert "对象标识 / Object ID" in last_page_text
    return page_count, tuple(ratios)


@pytest.mark.parametrize(
    ("raw", "display"),
    (
        ("0.020000000000000018", "0.02"),
        ("0.0250000000000000133", "0.025"),
        ("280.00000000000006", "280"),
        ("5.684341886080802e-14", "5.68434e-14"),
        ("-4.263256414560601e-14", "-4.26326e-14"),
        ("-47.539199999999994", "-47.5392"),
        ("-0.00000000000000000", "0"),
    ),
)
def test_report_display_numbers_remove_binary_float_pseudo_precision(
    raw: str,
    display: str,
) -> None:
    retained = {"sensitivity_value": raw}
    assert report_module._professional_decimal_text(raw) == display
    assert (
        report_module._latex_table_cell(raw).replace(r"\allowbreak{}", "")
        == display
    )
    assert display in report_module._latex_prose(f"value={raw}").replace(
        r"\allowbreak{}", ""
    )
    assert raw not in report_module._professionalize_numeric_tokens(f"value={raw}")
    assert retained == {"sensitivity_value": raw}


def test_report_display_number_formatting_preserves_identifiers_dates_and_versions() -> None:
    visible = (
        "CIK=0000320193; date=2026-02-16; OpenD=10.10.7008; "
        "sha256=64e760343312"
    )
    assert report_module._professionalize_numeric_tokens(visible) == visible


@pytest.mark.parametrize("rounding", (ROUND_DOWN, ROUND_UP))
def test_report_decimal_uses_fixed_half_even_context(rounding: str) -> None:
    with localcontext() as context:
        context.prec = 2
        context.rounding = rounding
        context.Emax = 1
        context.Emin = -1
        context.traps[Subnormal] = True

        assert _report_decimal("1.005", places=2) == "1.00"
        assert _report_ratio_percent("0.01005", places=2) == "1%"


def _typed_report_inputs(sample_payloads, tmp_path: Path, *, graph=None):
    if graph is None:
        graph = complete_phase4e_graph(sample_payloads)
    result = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    completed = _completed_graph(graph, result)
    bundle_directory = tmp_path / "strict-research-input"
    write_research_bundle_artifacts(
        completed,
        result,
        output_directory=bundle_directory,
    )
    research = reload_research_input(bundle_directory, graph=completed)
    source_index = build_research_source_index(graph=completed, research=result)
    report_payload = {
        **sample_payloads["report-spec"],
        "output_formats": ["json", "markdown", "latex_pdf"],
    }
    report_spec = contract_from_dict("report-spec", report_payload)
    score = contract_from_dict("score", sample_payloads["score"])
    assert isinstance(report_spec, ReportSpec)
    assert isinstance(score, Score)
    return research, source_index, report_spec, (score,)


def _build_research_only(sample_payloads, tmp_path: Path):
    research, source_index, report_spec, scores = _typed_report_inputs(sample_payloads, tmp_path)
    titles = tuple(str(section["title"]) for section in report_spec.sections)
    renderer = DeterministicRenderer(titles)
    report = build_research_report(
        profile="research_only",
        research=research,
        report_spec=report_spec,
        research_source_index=source_index,
        scores=scores,
        renderer=renderer,
    )
    assert renderer.calls == 1
    return report, research, report_spec, scores


def _full_valuation_inputs(sample_payloads, monkeypatch, tmp_path: Path):
    import test_phase5_v1_futu_data_plane as futu_fixtures
    import test_phase5_v1_valuation_synthesis as synthesis_fixtures

    original_peer_builder = futu_fixtures.build_futu_peer_evidence_fixture
    optional_peer_plan_specs = (
        futu_fixtures.FutuRequestSpec(
            "valuation_pre_price_verification",
            3246,
            futu_fixtures.FrozenMap({"currency_code": "USD", "num": 50}),
        ),
    )
    aligned_peer_fixture = None
    aligned_peer_call = None

    def peer_call_identity(price_blind_freeze, keyword_arguments):
        return (
            price_blind_freeze.artifact.fingerprint,
            keyword_arguments.get("target_security_id", "security:acme:common"),
            keyword_arguments.get("peer_count", 5),
            keyword_arguments.get("trading_date", "2026-08-14"),
            keyword_arguments.get("data_cutoff_date"),
            keyword_arguments.get("target_vendor_code", "US.ACME"),
        )

    def build_aligned_peer_fixture(price_blind_freeze, **keyword_arguments):
        nonlocal aligned_peer_call, aligned_peer_fixture
        call_identity = peer_call_identity(price_blind_freeze, keyword_arguments)
        if aligned_peer_fixture is not None:
            shared_authority = keyword_arguments.get("shared_live_authority")
            peer_authority = aligned_peer_fixture.peer_sessions[0].authority_set
            if (
                call_identity != aligned_peer_call
                or shared_authority is None
                or shared_authority.runtime_authorization is None
                or peer_authority.runtime_authorization is None
                or shared_authority.runtime_authorization.fingerprint
                != peer_authority.runtime_authorization.fingerprint
                or shared_authority.supply_chain is None
                or peer_authority.supply_chain is None
                or shared_authority.supply_chain.fingerprint
                != peer_authority.supply_chain.fingerprint
            ):
                raise AssertionError(
                    "complete Futu session did not request the frozen synthesis peer evidence"
                )
            return aligned_peer_fixture
        target_vendor_code = keyword_arguments.get("target_vendor_code", "US.ACME")
        peer_count = keyword_arguments.get("peer_count", 5)
        trading_date = keyword_arguments.get("trading_date", "2026-08-14")
        base_authority, _, _ = futu_fixtures._authorities(
            target_vendor_code=target_vendor_code,
            peer_count=peer_count,
            trading_date=trading_date,
            request_plan_profile="full",
            optional_pre_price_specs=optional_peer_plan_specs,
        )
        aligned_arguments = dict(keyword_arguments)
        aligned_arguments["shared_live_authority"] = replace(
            base_authority,
            runtime=None,
        )
        aligned_peer_fixture = original_peer_builder(
            price_blind_freeze,
            **aligned_arguments,
        )
        aligned_peer_call = call_identity
        return aligned_peer_fixture

    monkeypatch.setattr(
        futu_fixtures,
        "build_futu_peer_evidence_fixture",
        build_aligned_peer_fixture,
    )
    cached_synthesis = synthesis_fixtures._SYNTHESIS_CACHE
    if cached_synthesis is not None:
        cached_peer_authority = cached_synthesis[3]
        cached_peer_set = cached_peer_authority.futu_peer_evidence_set
        cached_runtime = cached_peer_set.peers[0].authority_set.runtime_authorization
        cached_plan_has_optional_protocol = cached_runtime is not None and any(
            item["protocol_id"] == 3246 for item in cached_runtime.request_plan
        )
        if cached_plan_has_optional_protocol:
            cached_run = cached_synthesis[0]
            cached_basis = cached_synthesis[1]
            aligned_peer_fixture = futu_fixtures.FutuPeerEvidenceFixture(
                peer_evidence_set=cached_peer_set,
                peer_sessions=tuple(cached_peer_set.peers),
                verifier=futu_fixtures.DeterministicVerifier(),
            )
            aligned_peer_call = (
                cached_run.input_receipt.expected_freeze.artifact.fingerprint,
                cached_basis.security_id,
                len(cached_peer_set.peers),
                cached_run.archive.market_reference.trading_date,
                cached_run.data_cutoff_date,
                f"US.{cached_basis.ticker}",
            )
        else:
            monkeypatch.setattr(synthesis_fixtures, "_SYNTHESIS_CACHE", None)
            monkeypatch.setattr(
                synthesis_fixtures,
                "_SYNTHESIS_CACHE_STATE_BASE",
                None,
            )

    (
        run_result,
        _basis,
        forward,
        peer_authority,
        comparables,
        composite,
        score_v2,
        scorecard,
    ) = synthesis_fixtures._complete_synthesis(sample_payloads, monkeypatch, tmp_path)
    if aligned_peer_fixture is None:
        raise AssertionError("synthesis did not retain its exact Futu peer evidence fixture")
    assert run_result.archive is not None
    graph = run_result.input_receipt.graph
    bundle = graph.research_bundles[0]
    manifest = next(item for item in graph.manifests if item.run_id == bundle.run_id)
    research_result = ResearchBundleBuildResult(bundle=bundle, run_manifest=manifest)
    research_directory = tmp_path / "strict-report-research-input"
    write_research_bundle_artifacts(
        graph,
        research_result,
        output_directory=research_directory,
    )
    research = reload_research_input(research_directory, graph=graph)
    source_index = build_research_source_index(graph=graph, research=research_result)
    valuation = reload_valuation_input(run_result.archive.output_directory)
    report_payload = {
        **sample_payloads["report-spec"],
        "output_formats": ["json", "markdown", "latex_pdf"],
    }
    report_spec = contract_from_dict("report-spec", report_payload)
    assert isinstance(report_spec, ReportSpec)
    roots = tuple(
        object_id
        for reference in bundle.module_references
        for object_id in reference["object_ids"]
    )
    closure = dependency_closure(graph, roots)
    object_type, fact = next(
        (object_type, item)
        for object_type, item in closure.values()
        if object_type == "Fact"
    )
    optional_data_review = build_named_human_review_authority(
        scope="futu_optional_data_plan",
        graph=graph,
        research_bundle=bundle,
        reviewer_id="human:futu-data-reviewer",
        reviewed_at="2026-08-15T00:58:00Z",
        rationale=(
            "Freeze the operational-efficiency vendor cross-check plan before the exact "
            "Futu session."
        ),
        reviewed_payload={
            "company_executives": False,
            "executive_background_leader_name": None,
            "operational_efficiency": True,
            "us_buybacks_disposition": "not_supported_for_us_sec_primary",
        },
        evidence_bindings=(
            {
                "object_type": object_type,
                "object_id": fact.fact_id,
                "fingerprint": fact.fingerprint,
            },
        ),
    )
    assert (
        futu_fixtures.compile_futu_optional_data_request_specs(optional_data_review)
        == optional_peer_plan_specs
    )
    futu_fixture = futu_fixtures.build_complete_futu_session_fixture(
        run_result.input_receipt.expected_freeze,
        composite_valuation=composite,
        owner_scorecard=scorecard,
        optional_data_review=optional_data_review,
    )
    assert (
        futu_fixture.session.peer_evidence_set.fingerprint
        == peer_authority.futu_peer_evidence_set.fingerprint
    )
    market_expectations = build_market_expectations_comparison(
        session=futu_fixture.session,
        composite_valuation=composite,
        owner_scorecard=scorecard,
        verifier=futu_fixture.verifier,
    )
    optional_data_dispositions = build_futu_optional_data_dispositions(
        execution=futu_fixture.pre_execution,
        review_authority=futu_fixture.optional_data_review,
    )
    return SimpleNamespace(
        run_result=run_result,
        research=research,
        source_index=source_index,
        report_spec=report_spec,
        valuation=valuation,
        archive=run_result.archive,
        forward=forward,
        comparables=comparables,
        composite=composite,
        score_v2=score_v2,
        scorecard=scorecard,
        futu=futu_fixture,
        optional_data_dispositions=optional_data_dispositions,
        market_expectations=market_expectations,
    )


def _rebind_synthesis_publication_payload(
    payload: dict[str, object],
    *,
    id_field: str,
) -> dict[str, object]:
    rebound = deepcopy(payload)
    source = rebound["source_payload"]
    assert isinstance(source, dict)
    source_identity = dict(source)
    source_id = source_identity.pop(id_field)
    assert isinstance(source_id, str)
    source[id_field] = f"{source_id.rsplit(':', 1)[0]}:{canonical_sha256(source_identity)[:24]}"
    identity = {
        "schema_version": rebound["schema_version"],
        "artifact_type": rebound["artifact_type"],
        "issuer_id": rebound["issuer_id"],
        "source_schema": rebound["source_schema"],
        "source_object_id": source[id_field],
        "source_fingerprint": canonical_sha256(source),
        "source_payload": source,
    }
    fingerprint = canonical_sha256(identity)
    return {
        **identity,
        "manifest_id": (
            f"{identity['artifact_type']}:{identity['issuer_id']}:{fingerprint[:24]}"
        ),
        "manifest_fingerprint": fingerprint,
    }


def test_valuation_publications_use_fixed_context_and_full_decimal_domain(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _full_valuation_inputs(sample_payloads, monkeypatch, tmp_path)
    composite_manifest = CompositeValuationPublicationManifest.from_source(inputs.composite)

    fingerprints = set()
    for rounding in (ROUND_DOWN, ROUND_UP):
        with localcontext() as context:
            context.prec = 2
            context.rounding = rounding
            context.Emax = 1
            context.Emin = -1
            context.traps[Subnormal] = True
            replayed = CompositeValuationPublicationManifest.from_dict(
                composite_manifest.to_dict()
            )
        fingerprints.add(replayed.fingerprint)
    assert fingerprints == {composite_manifest.fingerprint}

    out_of_domain = "1" + "0" * 1200
    cases = (
        (
            ForwardReOIValuationPublicationManifest,
            ForwardReOIValuationPublicationManifest.from_source(inputs.forward),
        ),
        (
            ComparableValuationPublicationManifest,
            ComparableValuationPublicationManifest.from_source(inputs.comparables),
        ),
    )
    for manifest_type, manifest in cases:
        rebound = manifest.to_dict()
        rebound["source_payload"]["scenarios"][0]["current_value_per_share"] = (
            out_of_domain
        )
        with pytest.raises(ResearchReportError, match="bounded decimal domain"):
            manifest_type.from_dict(
                _rebind_synthesis_publication_payload(rebound, id_field="result_id")
            )


@pytest.mark.parametrize("contested_horizon", ("current", "twelve_month"))
def test_composite_publication_replays_horizon_specific_contested_nulls(
    contested_horizon: str,
) -> None:
    def scenarios(current: str, future: str) -> list[dict[str, str]]:
        return [
            {
                "name": name,
                "current_value_per_share": current,
                "twelve_month_value_per_share": future,
            }
            for name in ("black_swan", "base", "bull")
        ]

    current_values = ("50", "100", "150") if contested_horizon == "current" else (
        "100",
        "100",
        "100",
    )
    future_values = (
        ("100", "100", "100")
        if contested_horizon == "current"
        else ("50", "100", "150")
    )
    panel_scenarios = {
        panel: scenarios(current, future)
        for panel, current, future in zip(
            ("mckinsey", "forward_reoi", "comparables"),
            current_values,
            future_values,
            strict=True,
        )
    }
    current_contested = contested_horizon == "current"
    payload = {
        "status": "contested",
        "panel_scenarios": panel_scenarios,
        "current_intrinsic_value": None if current_contested else "100",
        "twelve_month_target": "100" if current_contested else None,
        "current_relative_dispersion": "1" if current_contested else "0",
        "twelve_month_relative_dispersion": "0" if current_contested else "1",
        "market_price": "80",
        "margin_of_safety": None if current_contested else "0.2",
        "twelve_month_upside": "0.25" if current_contested else None,
        "contested": True,
        "recommendation_eligible": False,
        "issue_codes": [
            (
                "current_panel_dispersion_exceeds_50_percent"
                if current_contested
                else "twelve_month_panel_dispersion_exceeds_50_percent"
            )
        ],
    }

    report_module._validate_synthesis_projection_arithmetic(
        "composite-valuation-result",
        payload,
    )
    leaked = deepcopy(payload)
    leaked[
        "current_intrinsic_value" if current_contested else "twelve_month_target"
    ] = "100"
    with pytest.raises(ResearchReportError, match="contested .* composite was published"):
        report_module._validate_synthesis_projection_arithmetic(
            "composite-valuation-result",
            leaked,
        )


@pytest.mark.parametrize("contested_horizon", ("current", "twelve_month"))
def test_report_keeps_the_uncontested_composite_horizon_visible(
    contested_horizon: str,
) -> None:
    current_contested = contested_horizon == "current"
    composite = SimpleNamespace(
        status="contested",
        issue_codes=(
            "current_panel_dispersion_exceeds_50_percent"
            if current_contested
            else "twelve_month_panel_dispersion_exceeds_50_percent",
        ),
        current_intrinsic_value=None if current_contested else "101.25",
        twelve_month_target="118.75" if current_contested else None,
    )

    publication = _composite_horizon_publication(composite)
    text_zh, text_en = _composite_ineligible_narrative(
        composite,
        section_title_zh="综合价值、目标价与建议资格",
        section_title_en="Composite Value, Target, and Recommendation Eligibility",
    )

    if current_contested:
        assert publication.current_value == "Unknown"
        assert publication.current_status == "contested"
        assert publication.twelve_month_value == "118.75"
        assert publication.twelve_month_status == "complete"
        assert "当前综合值因当前估值面板离散度超过50%以 Unknown 展示" in text_zh
        assert "未受影响的12个月目标价为 118.75" in text_zh
        assert "unaffected twelve-month target is 118.75" in text_en
    else:
        assert publication.current_value == "101.25"
        assert publication.current_status == "complete"
        assert publication.twelve_month_value == "Unknown"
        assert publication.twelve_month_status == "contested"
        assert "未受影响的当前综合值为 101.25" in text_zh
        assert "12个月目标价因12个月估值面板离散度超过50%以 Unknown 展示" in text_zh
        assert "unaffected current composite value is 101.25" in text_en
    assert "当前综合值与12个月目标价均" not in text_zh


def test_research_only_report_is_scored_chinese_and_zero_valuation(
    sample_payloads,
    tmp_path: Path,
) -> None:
    report, _, _, _ = _build_research_only(sample_payloads, tmp_path)

    assert isinstance(report, ReportBuildResult)
    assert type(report.receipt) is ReportBuildReceipt
    assert report.receipt["profile"] == "research_only"
    assert report.receipt["valuation_archive_id"] is None
    assert report.receipt["qa"]["page_count"] == 30
    assert report.receipt["qa"]["simplified_chinese_detected"] is True
    assert report.receipt["score_fingerprints"]
    report_data = json.loads(
        next(item.content for item in report.artifacts if item.path == "report-data.json")
    )
    assert report_data["legacy_scores"]
    assert {
        "valuation_manifest",
        "valuation_result",
        "futu_session_publication_manifest",
        "forward_reoi",
        "comparable_valuation",
        "composite_valuation",
        "score_v2",
        "owner_scorecard",
    }.isdisjoint(report_data)
    assert not any("futu" in item.path.lower() for item in report.artifacts)
    content_payload = json.loads(
        next(item.content for item in report.artifacts if item.path == "report-content.json")
    )
    assert content_payload == report.content.to_dict()
    assert content_payload["substantive_unit_count"] >= 30
    assert content_payload["paragraph_count"] == content_payload["distinct_paragraph_count"]
    assert content_payload["anti_padding_method"] == "unique-evidence-bound-narrative-v1"
    reference_table = next(
        item
        for item in content_payload["tables"]
        if item["table_id"] == "table:references_and_source_receipts"
    )
    assert reference_table["columns"] == [
        "document_id",
        "apa7_metadata_status",
        "verified_author",
        "verified_title",
        "missing_metadata",
        "apa7_reference",
        "source_url",
        "content_sha256",
    ]
    assert all(
        row[1] == "partial"
        and row[2] == "Unknown"
        and row[3] == "Unknown"
        and row[4] == "verified_author;verified_title"
        and row[5] == "Unknown"
        and row[6].startswith("https://")
        and len(row[7]) == 64
        for row in reference_table["rows"]
    )
    reference_section = next(
        item
        for item in content_payload["sections"]
        if item["section_id"] == "references_and_source_receipts"
    )
    assert any(
        "APA 7 元数据状态为 partial" in paragraph["text_zh"]
        and "verified_author" in paragraph["missing_evidence"]
        and "verified_title" in paragraph["missing_evidence"]
        for paragraph in reference_section["paragraphs"]
    )
    assert report.receipt["qa"]["anti_padding"] == {
        "status": "passed",
        "method": "unique-evidence-bound-narrative-v1",
        "verified_paragraph_count": content_payload["paragraph_count"],
        "unique_paragraph_count": content_payload["distinct_paragraph_count"],
        "blank_page_count": 0,
        "low_density_non_cover_page_count": 0,
        "minimum_non_cover_characters": 120,
        "page_character_counts_sha256": canonical_sha256([120] * 30),
    }
    assert {
        "decision_summary",
        "sources_and_cutoff",
        "business_and_moat",
        "financial_history_and_segments",
        "accounting_quality",
        "management_and_capital_allocation",
        "risks_and_falsification",
        "evidence_audit_index",
    }.issubset({item["section_id"] for item in content_payload["sections"]})
    assert "本附录仅重复" not in canonical_json(content_payload)
    report_tex = next(
        item.content.decode("utf-8") for item in report.artifacts if item.path == "report-data.tex"
    )
    assert "续 / continued" not in report_tex
    assert r"\noindent\color{OwnerGray}\small " not in report_tex
    assert r"\par\normalsize\color{black}" not in report_tex
    assert r"{\color{OwnerGray}\small\noindent " in report_tex
    assert r"{\footnotesize\color{OwnerGray}\noindent " in report_tex
    evidence_count = len(report_module._report_evidence_bindings(report.content))
    assert report_tex.count(r"\begin{longtable}") == 1
    assert report_tex.count(r"\clearpage") == 1
    assert r"Source\allowbreak{}Document" in report_tex
    assert report_tex.count("[0.28em]") == evidence_count
    assert report_tex.count(r"\\*") == 5
    table_tex = next(
        item.content.decode("utf-8") for item in report.artifacts if item.path == "report-table.tex"
    )
    chart_tex = next(
        item.content.decode("utf-8") for item in report.artifacts if item.path == "report-chart.tex"
    )
    assert "\\clearpage" not in table_tex
    assert "\\clearpage" not in chart_tex
    assert "@{}" in table_tex
    assert "accounting\\_quality\\_review" in table_tex.replace("\\allowbreak{}", "")
    assert "Evidence Binding Appendix" in report_tex
    assert "@" + "0" * 64 not in report_tex
    chart_svg = next(
        item.content.decode("utf-8")
        for item in report.artifacts
        if item.path == "report-charts.svg"
    )
    assert chart_svg.startswith('<?xml version="1.0" encoding="UTF-8"?>')
    assert 'data-sign="positive"' in chart_svg or 'data-sign="negative"' in chart_svg


def test_report_spec_requires_every_listed_input_type(
    sample_payloads,
    tmp_path: Path,
) -> None:
    research, source_index, _, scores = _typed_report_inputs(sample_payloads, tmp_path)
    report_payload = {
        **sample_payloads["report-spec"],
        "sections": [
            {
                "section_id": "all-required-types",
                "title": "全部必需类型",
                "required_input_types": ["Fact", "ValuationAssumptionCandidate"],
            }
        ],
        "output_formats": ["json", "markdown", "latex_pdf"],
    }
    report_spec = contract_from_dict("report-spec", report_payload)
    assert isinstance(report_spec, ReportSpec)
    report = build_research_report(
        profile="research_only",
        research=research,
        report_spec=report_spec,
        research_source_index=source_index,
        scores=scores,
        renderer=DeterministicRenderer(tuple(str(item["title"]) for item in report_spec.sections)),
    )
    content = json.loads(
        next(item.content for item in report.artifacts if item.path == "report-content.json")
    )
    section = next(
        item
        for item in content["sections"]
        if item["section_id"] == "report_spec_all-required-types"
    )

    assert content["status"] == "partial"
    assert section["status"] == "partial"
    assert [
        binding["object_type"]
        for paragraph in section["paragraphs"]
        for binding in paragraph["bindings"]
        if binding["object_type"] == "Fact"
    ] == ["Fact"]
    assert any(
        "required_input_type:ValuationAssumptionCandidate" in paragraph["missing_evidence"]
        for paragraph in section["paragraphs"]
    )


def test_report_artifacts_and_receipt_ignore_hostile_decimal_context(
    sample_payloads,
    tmp_path: Path,
) -> None:
    research, source_index, report_spec, scores = _typed_report_inputs(sample_payloads, tmp_path)
    titles = tuple(str(section["title"]) for section in report_spec.sections)
    baseline = build_research_report(
        profile="research_only",
        research=research,
        report_spec=report_spec,
        research_source_index=source_index,
        scores=scores,
        renderer=DeterministicRenderer(titles),
    )

    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_UP
        context.Emax = 1
        context.Emin = -1
        context.traps[Subnormal] = True
        hostile = build_research_report(
            profile="research_only",
            research=research,
            report_spec=report_spec,
            research_source_index=source_index,
            scores=scores,
            renderer=DeterministicRenderer(titles),
        )

    assert hostile.artifacts == baseline.artifacts
    assert hostile.content == baseline.content
    assert hostile.receipt == baseline.receipt
    assert hostile.receipt.fingerprint == baseline.receipt.fingerprint


def test_reviewed_fact_charts_never_mix_heterogeneous_units(
    sample_payloads,
    tmp_path: Path,
) -> None:
    graph = _input_graph(sample_payloads)
    base = graph.facts[0]
    heterogeneous = (
        replace(
            base,
            fact_id="fact:acme:chart-boundary:currency",
            concept="heterogeneous_chart_boundary",
            source_locator="test:chart-boundary:currency",
        ),
        replace(
            base,
            fact_id="fact:acme:chart-boundary:ratio",
            concept="heterogeneous_chart_boundary",
            unit="ratio",
            currency=None,
            source_locator="test:chart-boundary:ratio",
        ),
        replace(
            base,
            fact_id="fact:acme:chart-boundary:shares",
            concept="heterogeneous_chart_boundary",
            unit="shares",
            currency=None,
            source_locator="test:chart-boundary:shares",
        ),
    )
    graph = replace(graph, facts=(*graph.facts, *heterogeneous))
    result = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    completed = _completed_graph(graph, result)
    directory = tmp_path / "heterogeneous-unit-input"
    write_research_bundle_artifacts(completed, result, output_directory=directory)
    research = reload_research_input(directory, graph=completed)
    source_index = build_research_source_index(graph=completed, research=result)
    report_payload = {
        **sample_payloads["report-spec"],
        "output_formats": ["json", "markdown", "latex_pdf"],
    }
    report_spec = contract_from_dict("report-spec", report_payload)
    assert isinstance(report_spec, ReportSpec)
    report = build_research_report(
        profile="research_only",
        research=research,
        report_spec=report_spec,
        research_source_index=source_index,
        renderer=DeterministicRenderer(
            tuple(str(section["title"]) for section in report_spec.sections)
        ),
    )

    assert all(
        "heterogeneous_chart_boundary" not in str(chart["title_en"])
        for chart in report.content["charts"]
    )


def test_reviewed_fact_charts_split_period_kinds_and_preserve_signed_direction(
    sample_payloads,
    tmp_path: Path,
) -> None:
    graph = _input_graph(sample_payloads)
    base = graph.facts[0]
    facts = tuple(
        replace(
            base,
            fact_id=f"fact:acme:period-kind:{index}",
            concept="period_kind_boundary",
            value=value,
            period=period,
            source_locator=f"test:period-kind:{index}",
        )
        for index, value, period in (
            (1, -10, {"start": "2024-01-01", "end": "2024-12-31"}),
            (2, 20, {"start": "2025-01-01", "end": "2025-12-31"}),
            (3, -3, {"start": "2025-01-01", "end": "2025-03-31"}),
            (4, 5, {"start": "2025-04-01", "end": "2025-06-30"}),
        )
    )
    graph = replace(graph, facts=(*graph.facts, *facts))
    result = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    completed = _completed_graph(graph, result)
    directory = tmp_path / "period-kind-input"
    write_research_bundle_artifacts(completed, result, output_directory=directory)
    research = reload_research_input(directory, graph=completed)
    source_index = build_research_source_index(graph=completed, research=result)
    report_spec = contract_from_dict(
        "report-spec",
        {
            **sample_payloads["report-spec"],
            "output_formats": ["json", "markdown", "latex_pdf"],
        },
    )
    assert isinstance(report_spec, ReportSpec)
    report = build_research_report(
        profile="research_only",
        research=research,
        report_spec=report_spec,
        research_source_index=source_index,
        renderer=DeterministicRenderer(
            tuple(str(section["title"]) for section in report_spec.sections)
        ),
    )

    matching = [
        chart
        for chart in report.content["charts"]
        if "period_kind_boundary" in str(chart["title_en"])
    ]
    assert len(matching) == 2
    assert {len(chart["series"][0]["points"]) for chart in matching} == {2}
    svg = next(
        item.content.decode("utf-8")
        for item in report.artifacts
        if item.path == "report-charts.svg"
    )
    assert 'data-sign="negative"' in svg
    assert 'data-sign="positive"' in svg
    chart_tex = next(
        item.content.decode("utf-8")
        for item in report.artifacts
        if item.path == "report-chart.tex"
    )
    assert "OwnerRed" in chart_tex
    assert "OwnerBlue" in chart_tex
    assert "Red-left is negative" in chart_tex


def test_research_only_report_does_not_require_legacy_scoring(
    sample_payloads,
    tmp_path: Path,
) -> None:
    research, source_index, report_spec, _ = _typed_report_inputs(sample_payloads, tmp_path)
    report = build_research_report(
        profile="research_only",
        research=research,
        report_spec=report_spec,
        research_source_index=source_index,
        scores=(),
        renderer=DeterministicRenderer(
            tuple(str(section["title"]) for section in report_spec.sections)
        ),
    )

    assert report.legacy_scores == ()
    assert report.receipt["score_fingerprints"] == ()
    report_data = json.loads(
        next(item.content for item in report.artifacts if item.path == "report-data.json")
    )
    assert report_data["legacy_scores"] == []
    assert all(
        key not in report_data
        for key in (
            "valuation_manifest",
            "valuation_result",
            "futu_session_publication_manifest",
            "composite_valuation",
            "score_v2",
            "owner_scorecard",
        )
    )


def test_research_only_content_rejects_coordinated_futu_narrative_rebind(
    sample_payloads,
    tmp_path: Path,
) -> None:
    report, _, _, _ = _build_research_only(sample_payloads, tmp_path)
    rebound = report.content.to_dict()
    paragraph = rebound["sections"][0]["paragraphs"][0]
    paragraph["text_zh"] += " 富途市场价格为任意重绑定值。"
    paragraph_base = {
        "text_zh": paragraph["text_zh"],
        "text_en": paragraph["text_en"],
        "bindings": paragraph["bindings"],
        "missing_evidence": paragraph["missing_evidence"],
    }
    paragraph["paragraph_id"] = (
        f"paragraph:{rebound['sections'][0]['section_id']}:{canonical_sha256(paragraph_base)[:16]}"
    )
    rebound.pop("content_fingerprint")
    rebound["content_fingerprint"] = canonical_sha256(rebound)

    with pytest.raises(ValueError, match="research_only content contains"):
        ResearchReportContent.from_dict(rebound)


def test_research_only_publisher_round_trips_read_only_and_is_idempotent(
    sample_payloads,
    tmp_path: Path,
) -> None:
    report, research, _, _ = _build_research_only(sample_payloads, tmp_path)
    output = tmp_path / "published-research"
    source = research.source_directory
    source.chmod(0o755)
    for member in source.iterdir():
        member.chmod(0o644)
        member.unlink()
    source.rmdir()

    first = publish_research_report(
        report,
        research,
        output_directory=output,
        allow_injected_test_renderer=True,
    )
    mtimes = {str(path.relative_to(output)): path.stat().st_mtime_ns for path in output.rglob("*")}
    second = publish_research_report(
        report,
        research,
        output_directory=output,
        allow_injected_test_renderer=True,
    )

    assert first.fingerprint == second.fingerprint
    assert dict(second.file_sha256) == {
        path: hashlib.sha256(content).hexdigest()
        for path, content in dict(second.file_bytes).items()
    }
    assert second.valuation is None
    assert type(second) is PublishedResearchPackage
    assert type(second.publication_manifest) is PublicationManifest
    assert second.profile == "research_only"
    assert not (output / "valuation").exists()
    assert not (output / "synthesis").exists()
    assert not (output / "scoring").exists()
    assert stat_mode(output) == 0o555
    assert all(stat_mode(path) == (0o555 if path.is_dir() else 0o444) for path in output.rglob("*"))
    assert {
        str(path.relative_to(output)): path.stat().st_mtime_ns for path in output.rglob("*")
    } == mtimes
    assert load_published_package(output, allow_injected_test_renderer=True) == second
    with pytest.raises(ResearchPublisherError, match="directory is unavailable"):
        replace(second, output_directory=tmp_path / "nonexistent-rebound-package")


def test_atomic_publisher_never_replaces_a_concurrent_empty_target(tmp_path: Path) -> None:
    parent = tmp_path / "exclusive-parent"
    parent.mkdir(mode=0o700)
    staging = parent / "staging"
    staging.mkdir(mode=0o700)
    (staging / "owned.txt").write_text("owned staging", encoding="utf-8")
    target = parent / "target"
    target.mkdir(mode=0o700)

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    parent_fd = os.open(parent, flags)
    try:
        with pytest.raises(FileExistsError):
            publisher_module._atomic_publish_staging(parent_fd, staging.name, target.name)
    finally:
        os.close(parent_fd)

    assert target.is_dir()
    assert tuple(target.iterdir()) == ()
    assert (staging / "owned.txt").read_text(encoding="utf-8") == "owned staging"


def test_identical_concurrent_publication_reloads_the_winner(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report, research, _, _ = _build_research_only(sample_payloads, tmp_path)
    output = tmp_path / "concurrent-identical-target"
    target_state = publisher_module._publication_target_state

    def publish_winner_but_pause_before_sealing(
        parent_fd: int,
        staging_name: str,
        target_name: str,
    ) -> None:
        publisher_module._rename_noreplace(parent_fd, staging_name, target_name)
        raise FileExistsError("an identical concurrent publisher is still sealing")

    observed_unsealed_target = False

    def seal_after_observing_the_real_race(parent_fd: int, target_name: str) -> str:
        nonlocal observed_unsealed_target
        state = target_state(parent_fd, target_name)
        if state == "staging" and not observed_unsealed_target:
            observed_unsealed_target = True
            descriptor = publisher_module._open_child_directory(parent_fd, target_name)
            try:
                os.fchmod(descriptor, 0o555)
                os.fsync(descriptor)
                os.fsync(parent_fd)
            finally:
                os.close(descriptor)
            return "staging"
        return state

    monkeypatch.setattr(
        publisher_module,
        "_atomic_publish_staging",
        publish_winner_but_pause_before_sealing,
    )
    monkeypatch.setattr(
        publisher_module,
        "_publication_target_state",
        seal_after_observing_the_real_race,
    )
    published = publish_research_report(
        report,
        research,
        output_directory=output,
        allow_injected_test_renderer=True,
    )

    assert published.output_directory == output
    assert observed_unsealed_target is True
    assert stat_mode(output) == 0o555
    assert published.report.fingerprint == report.fingerprint
    assert load_published_package(output, allow_injected_test_renderer=True) == published


def test_idempotent_call_waits_for_an_already_visible_unsealed_winner(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report, research, _, _ = _build_research_only(sample_payloads, tmp_path)
    output = tmp_path / "visible-unsealed-winner"
    first = publish_research_report(
        report,
        research,
        output_directory=output,
        allow_injected_test_renderer=True,
    )
    output.chmod(0o700)
    target_state = publisher_module._publication_target_state
    observed_unsealed_target = False

    def seal_after_observing_target(parent_fd: int, target_name: str) -> str:
        nonlocal observed_unsealed_target
        state = target_state(parent_fd, target_name)
        if state == "staging" and not observed_unsealed_target:
            observed_unsealed_target = True
            descriptor = publisher_module._open_child_directory(parent_fd, target_name)
            try:
                os.fchmod(descriptor, 0o555)
                os.fsync(descriptor)
                os.fsync(parent_fd)
            finally:
                os.close(descriptor)
            return "staging"
        return state

    monkeypatch.setattr(
        publisher_module,
        "_publication_target_state",
        seal_after_observing_target,
    )
    second = publish_research_report(
        report,
        research,
        output_directory=output,
        allow_injected_test_renderer=True,
    )

    assert observed_unsealed_target is True
    assert stat_mode(output) == 0o555
    assert second.fingerprint == first.fingerprint


def test_failed_seal_and_failed_rollback_reseal_the_retained_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "rollback-parent"
    parent.mkdir(mode=0o700)
    staging = parent / "staging"
    staging.mkdir(mode=0o700)
    (staging / "owned.txt").write_text("owned staging", encoding="utf-8")
    original_rename = publisher_module._rename_noreplace
    original_fsync = publisher_module.os.fsync
    rename_calls = 0
    fsync_calls = 0

    def fail_rollback(
        parent_fd: int,
        source_name: str,
        target_name: str,
    ) -> None:
        nonlocal rename_calls
        rename_calls += 1
        if rename_calls == 2:
            raise OSError(errno.EIO, "injected rollback failure")
        original_rename(parent_fd, source_name, target_name)

    def fail_first_seal_sync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 1:
            raise OSError(errno.EIO, "injected seal sync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(publisher_module, "_rename_noreplace", fail_rollback)
    monkeypatch.setattr(publisher_module.os, "fsync", fail_first_seal_sync)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    parent_fd = os.open(parent, flags)
    try:
        with pytest.raises(ResearchPublisherError, match="resealed read-only"):
            publisher_module._atomic_publish_staging(parent_fd, staging.name, "target")
    finally:
        os.close(parent_fd)

    target = parent / "target"
    assert target.is_dir()
    assert stat_mode(target) == 0o555
    assert (target / "owned.txt").read_text(encoding="utf-8") == "owned staging"


def test_concurrent_publisher_waits_for_winner_parent_fsync_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "parent-fsync-race"
    parent.mkdir(mode=0o700)
    winner_staging = parent / "winner-staging"
    loser_staging = parent / "loser-staging"
    winner_staging.mkdir(mode=0o700)
    loser_staging.mkdir(mode=0o700)
    (winner_staging / "owner.txt").write_text("winner", encoding="utf-8")
    (loser_staging / "owner.txt").write_text("loser", encoding="utf-8")

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    parent_fd = os.open(parent, flags)
    real_fsync = publisher_module.os.fsync
    real_target_state = publisher_module._publication_target_state
    winner_at_parent_fsync = threading.Event()
    loser_observing_target = threading.Event()
    release_parent_fsync_failure = threading.Event()
    winner_done = threading.Event()
    failure_injected = False
    results: dict[str, object] = {}

    def fail_winner_parent_fsync_once(descriptor: int) -> None:
        nonlocal failure_injected
        if (
            threading.current_thread().name == "publisher-winner"
            and descriptor == parent_fd
            and not failure_injected
        ):
            failure_injected = True
            winner_at_parent_fsync.set()
            if not release_parent_fsync_failure.wait(5):
                raise AssertionError("loser did not reach the visible target")
            raise OSError(errno.EIO, "injected parent fsync failure")
        real_fsync(descriptor)

    def synchronize_loser_observation(parent_descriptor: int, target_name: str) -> str:
        state = real_target_state(parent_descriptor, target_name)
        if threading.current_thread().name == "publisher-loser":
            loser_observing_target.set()
            if state == "settled" and not winner_done.wait(5):
                raise AssertionError("winner did not finish its rollback")
        return state

    def publish_winner() -> None:
        try:
            results["winner"] = publisher_module._publish_staging_exclusive(
                parent_fd,
                winner_staging.name,
                "target",
            )
        except BaseException as exc:  # noqa: BLE001 - thread result is asserted below.
            results["winner"] = exc
        finally:
            winner_done.set()

    def publish_loser() -> None:
        try:
            results["loser"] = publisher_module._publish_staging_exclusive(
                parent_fd,
                loser_staging.name,
                "target",
            )
        except BaseException as exc:  # noqa: BLE001 - thread result is asserted below.
            results["loser"] = exc

    monkeypatch.setattr(publisher_module.os, "fsync", fail_winner_parent_fsync_once)
    monkeypatch.setattr(
        publisher_module,
        "_publication_target_state",
        synchronize_loser_observation,
    )
    winner_thread = threading.Thread(target=publish_winner, name="publisher-winner")
    loser_thread = threading.Thread(target=publish_loser, name="publisher-loser")
    try:
        winner_thread.start()
        assert winner_at_parent_fsync.wait(5)
        loser_thread.start()
        assert loser_observing_target.wait(5)
        release_parent_fsync_failure.set()
        winner_thread.join(5)
        loser_thread.join(5)
        assert not winner_thread.is_alive()
        assert not loser_thread.is_alive()
    finally:
        release_parent_fsync_failure.set()
        winner_thread.join(5)
        loser_thread.join(5)
        os.close(parent_fd)

    assert isinstance(results["winner"], OSError)
    assert results["loser"] is True
    assert failure_injected is True
    assert stat_mode(parent / "target") == 0o555
    assert (parent / "target" / "owner.txt").read_text(encoding="utf-8") == "loser"
    assert (winner_staging / "owner.txt").read_text(encoding="utf-8") == "winner"


def test_production_publication_rejects_injected_renderer(
    sample_payloads,
    tmp_path: Path,
) -> None:
    report, research, _, _ = _build_research_only(sample_payloads, tmp_path)

    with pytest.raises(ResearchPublisherError, match="real LaTeX renderer"):
        publish_research_report(
            report,
            research,
            output_directory=tmp_path / "must-not-publish",
        )
    assert not (tmp_path / "must-not-publish").exists()


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _coordinated_rebind_publication_recommendation(
    output: Path,
    *,
    field: str,
    replacement: str,
) -> tuple[PublicationManifest, PublishedPackageReceipt, bytes, bytes]:
    manifest_path = output / "publication-manifest.json"
    package_path = output / "published-package.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    package = json.loads(package_path.read_text(encoding="utf-8"))

    manifest[field] = replacement
    identity_excluded = {
        "schema_version",
        "artifact_type",
        "publication_id",
        "report_build_id",
        "payload_member_count",
        "payload_total_bytes",
        "manifest_fingerprint",
    }
    identity = {
        key: value
        for key, value in manifest.items()
        if key not in identity_excluded
    }
    manifest["publication_id"] = (
        f"research-publication:{manifest['issuer_id']}:"
        f"{canonical_sha256(identity)[:24]}"
    )
    unsigned_manifest = dict(manifest)
    unsigned_manifest.pop("manifest_fingerprint")
    manifest["manifest_fingerprint"] = canonical_sha256(unsigned_manifest)
    manifest_bytes = (canonical_json(manifest) + "\n").encode("utf-8")

    package["publication_id"] = manifest["publication_id"]
    package["publication_manifest_sha256"] = hashlib.sha256(
        manifest_bytes
    ).hexdigest()
    package["publication_manifest_fingerprint"] = manifest["manifest_fingerprint"]
    unsigned_package = dict(package)
    unsigned_package.pop("package_fingerprint")
    package["package_fingerprint"] = canonical_sha256(unsigned_package)
    package_bytes = (canonical_json(package) + "\n").encode("utf-8")

    for path, content in (
        (manifest_path, manifest_bytes),
        (package_path, package_bytes),
    ):
        path.chmod(0o644)
        path.write_bytes(content)
        path.chmod(0o444)
    return (
        PublicationManifest(manifest),
        PublishedPackageReceipt(package),
        manifest_bytes,
        package_bytes,
    )


def test_publisher_rejects_writable_directory_and_member_tampering(
    sample_payloads,
    tmp_path: Path,
) -> None:
    report, research, _, _ = _build_research_only(sample_payloads, tmp_path)
    output = tmp_path / "tamper-target"
    publish_research_report(
        report,
        research,
        output_directory=output,
        allow_injected_test_renderer=True,
    )

    output.chmod(0o755)
    with pytest.raises(ResearchPublisherError, match="permissions"):
        load_published_package(output, allow_injected_test_renderer=True)
    output.chmod(0o555)

    member = output / "report" / "report.md"
    member.chmod(0o644)
    member.write_bytes(member.read_bytes() + b"tampered")
    member.chmod(0o444)
    with pytest.raises(ResearchPublisherError, match="hash|differs"):
        load_published_package(output, allow_injected_test_renderer=True)


def test_publisher_rejects_different_manifest_at_existing_target(
    sample_payloads,
    tmp_path: Path,
) -> None:
    report, research, report_spec, scores = _build_research_only(sample_payloads, tmp_path)
    output = tmp_path / "immutable-target"
    publish_research_report(
        report,
        research,
        output_directory=output,
        allow_injected_test_renderer=True,
    )
    changed_score = replace(
        scores[0],
        score=7.5,
        rationale="Changed reviewed score for immutable-target test.",
    )
    changed = build_research_report(
        profile="research_only",
        research=research,
        report_spec=report_spec,
        research_source_index=report.research_source_index,
        scores=(changed_score,),
        renderer=DeterministicRenderer(
            tuple(str(section["title"]) for section in report_spec.sections)
        ),
    )

    with pytest.raises(ResearchPublisherError, match="different content"):
        publish_research_report(
            changed,
            research,
            output_directory=output,
            allow_injected_test_renderer=True,
        )


def test_full_valuation_publishes_the_exact_six_file_archive(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _full_valuation_inputs(sample_payloads, monkeypatch, tmp_path)
    report = build_research_report(
        profile="full_valuation",
        research=inputs.research,
        report_spec=inputs.report_spec,
        research_source_index=inputs.source_index,
        scores=(),
        valuation=inputs.valuation,
        futu_session_evidence=inputs.futu.session,
        futu_verifier=inputs.futu.verifier,
        futu_optional_data_dispositions=inputs.optional_data_dispositions,
        forward_reoi=inputs.forward,
        comparable_valuation=inputs.comparables,
        composite_valuation=inputs.composite,
        score_v2=inputs.score_v2,
        owner_scorecard=inputs.scorecard,
        market_expectations=inputs.market_expectations,
        renderer=LatexReportRenderer(),
    )
    score_request = OwnerEquityResearchRequest(
        issuer_id=report.issuer_id,
        data_cutoff_date=report.data_cutoff_date,
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
        requested_by="human:score-outcome-reviewer",
        requested_at="2026-08-15T01:18:00Z",
    )
    score_input = OwnerEquityResearchInputReceipt.from_request(score_request)
    forged_score_receipt = PhaseReceipt.create(
        phase="owner_scorecard",
        input_receipt=score_input,
        upstream_receipts=(),
        authorities=(inputs.score_v2, inputs.scorecard),
    )
    with pytest.raises(
        ValueError,
        match="score phase outcome does not replay its exact scorecard",
    ):
        ScorePhaseResult(
            status=PhaseStatus.PARTIAL,
            issuer_id=report.issuer_id,
            data_cutoff_date=report.data_cutoff_date,
            receipt=forged_score_receipt,
            lens_scores=inputs.score_v2,
            scorecard=inputs.scorecard,
            recommendation=inputs.scorecard.recommendation,
            issue_codes=("owner_scorecard_partial",),
        )
    report_request = OwnerEquityResearchRequest(
        issuer_id=report.issuer_id,
        data_cutoff_date=report.data_cutoff_date,
        intent=ResearchIntent.VALUATION,
        profile=PublicationProfile.FULL_VALUATION,
        requested_by="human:report-outcome-reviewer",
        requested_at="2026-08-15T01:19:00Z",
    )
    report_input = OwnerEquityResearchInputReceipt.from_request(report_request)
    forged_report_receipt = PhaseReceipt.create(
        phase="report",
        input_receipt=report_input,
        upstream_receipts=(),
        authorities=(report, report.receipt),
    )
    with pytest.raises(
        ValueError,
        match="report phase outcome does not replay its exact build",
    ):
        ReportPhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=report.issuer_id,
            data_cutoff_date=report.data_cutoff_date,
            receipt=forged_report_receipt,
            profile=PublicationProfile.FULL_VALUATION,
            report_build=report,
            report_build_receipt=report.receipt,
            contains_market_price=True,
            contains_target_price=True,
        )
    assert 30 <= report.receipt["qa"]["page_count"] <= 60
    assert report.receipt["qa"]["rendered_page_count"] == report.receipt["qa"]["page_count"]
    pdf_bytes = next(
        item.content for item in report.artifacts if item.path == "report.pdf"
    )
    page_count, page_ratios = _independent_all_page_pdf_qa(pdf_bytes)
    assert page_count == report.receipt["qa"]["page_count"]
    assert min(page_ratios[1:]) >= Decimal("0.040000")
    extracted = next(
        item.content.decode("utf-8")
        for item in report.artifacts
        if item.path == "report-extracted.txt"
    )
    for required_text in (
        "Forward ReOI",
        "Comparable Valuation",
        "Composite Value",
        "Four-Lens Scorecard",
        "Market Expectations",
    ):
        assert required_text in extracted
    output = tmp_path / "published-full"
    for source in (
        inputs.research.source_directory,
        inputs.valuation.source_directory,
    ):
        source.chmod(0o755)
        for member in source.iterdir():
            member.chmod(0o644)
            member.unlink()
        source.rmdir()

    published = publish_owner_research(
        report,
        inputs.research,
        valuation=inputs.valuation,
        output_directory=output,
        futu_verifier=inputs.futu.verifier,
        allow_injected_test_renderer=True,
    )

    assert published.profile == "full_valuation"
    assert published.valuation is not None
    assert published.valuation.fingerprint == inputs.archive.fingerprint
    assert published.forward_reoi_manifest == report.forward_reoi_manifest
    assert published.comparable_valuation_manifest == report.comparable_valuation_manifest
    assert published.composite_valuation_manifest == report.composite_valuation_manifest
    assert published.score_v2_manifests == report.score_v2_manifests
    assert published.owner_scorecard_manifest == report.owner_scorecard_manifest
    assert published.futu_session_manifest == report.futu_session_manifest
    assert published.futu_optional_data_disposition_manifests == (
        report.futu_optional_data_disposition_manifests
    )
    assert published.market_expectations_manifest == report.market_expectations_manifest
    assert inputs.market_expectations.status == "partial"
    assert inputs.scorecard.recommendation != "无法评级"
    assert published.publication_manifest["effective_recommendation"] == "无法评级"
    assert (
        published.publication_manifest["frozen_score_recommendation"]
        == inputs.scorecard.recommendation
    )
    report_markdown = (output / "report" / "report.md").read_text(encoding="utf-8")
    assert "研究建议=无法评级" in report_markdown
    assert f"冻结评分建议={inputs.scorecard.recommendation}" in report_markdown
    assert {path.name for path in (output / "valuation").iterdir()} == set(
        inputs.archive.file_sha256
    )
    for name, content in inputs.valuation.file_bytes.items():
        assert (output / "valuation" / name).read_bytes() == content
    assert (output / "synthesis" / "forward-reoi-publication-manifest.json").read_bytes() == (
        json.dumps(
            report.forward_reoi_manifest.to_dict(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()
    assert (
        load_owner_research_package(
            output,
            allow_injected_test_renderer=True,
        )
        == published
    )
    publish_request = OwnerEquityResearchRequest(
        issuer_id=published.report.issuer_id,
        data_cutoff_date=published.report.data_cutoff_date,
        intent=ResearchIntent.PUBLISH,
        profile=PublicationProfile.FULL_VALUATION,
        requested_by="human:publication-outcome-reviewer",
        requested_at="2026-08-15T01:20:00Z",
    )
    publish_input = OwnerEquityResearchInputReceipt.from_request(publish_request)
    forged_completed_receipt = PhaseReceipt.create(
        phase="publication",
        input_receipt=publish_input,
        upstream_receipts=(),
        authorities=(published, published, published.publication_manifest),
    )
    with pytest.raises(
        ValueError,
        match="publication phase outcome does not replay its strict package",
    ):
        PublicationPhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=published.report.issuer_id,
            data_cutoff_date=published.report.data_cutoff_date,
            receipt=forged_completed_receipt,
            profile=PublicationProfile.FULL_VALUATION,
            published_package=published,
            publication_manifest=published.publication_manifest,
            source_package=published,
        )
    republished = republish_owner_research_package(
        published,
        output_directory=tmp_path / "republished-full",
        allow_injected_test_renderer=True,
    )
    assert dict(republished.file_bytes) == dict(published.file_bytes)
    assert dict(republished.file_sha256) == dict(published.file_sha256)
    assert republished.publication_manifest == published.publication_manifest
    assert republished.package_receipt == published.package_receipt
    for source_package, field in (
        (published, "effective_recommendation"),
        (republished, "frozen_score_recommendation"),
    ):
        manifest, receipt, manifest_bytes, package_bytes = (
            _coordinated_rebind_publication_recommendation(
                source_package.output_directory,
                field=field,
                replacement="观察",
            )
        )
        captured = dict(source_package.file_bytes)
        captured["publication-manifest.json"] = manifest_bytes
        captured["published-package.json"] = package_bytes
        with pytest.raises(
            ResearchPublisherError,
            match="publication manifest rebinds its report recommendation authority",
        ):
            replace(
                source_package,
                publication_manifest=manifest,
                package_receipt=receipt,
                file_sha256={
                    path: hashlib.sha256(content).hexdigest()
                    for path, content in captured.items()
                },
                file_bytes=captured,
            )
        with pytest.raises(
            ResearchPublisherError,
            match="publication manifest rebinds a typed input",
        ):
            load_owner_research_package(
                source_package.output_directory,
                allow_injected_test_renderer=True,
            )


def test_profile_boundary_rejects_missing_or_extra_valuation(
    sample_payloads,
    tmp_path: Path,
) -> None:
    research, source_index, report_spec, scores = _typed_report_inputs(sample_payloads, tmp_path)
    renderer = DeterministicRenderer(
        tuple(str(section["title"]) for section in report_spec.sections)
    )

    with pytest.raises(ValueError, match="requires a strictly reloaded archive"):
        build_research_report(
            profile="full_valuation",
            research=research,
            report_spec=report_spec,
            research_source_index=source_index,
            scores=scores,
            renderer=renderer,
        )


def test_valuation_reload_rejects_a_rebound_typed_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class TypedPayload:
        def __init__(self, payload):
            self.payload = payload

        def to_dict(self):
            return self.payload

    payloads = {
        "valuation-handoff.json": {"kind": "handoff"},
        "price-blind-input.json": {"kind": "price-blind"},
        "market-reference.json": {"kind": "market"},
        "valuation-request.json": {"kind": "request"},
        "valuation-result.json": {"kind": "result"},
        "valuation-run-manifest.json": {"kind": "manifest"},
    }
    contents = {
        name: (
            canonical_json(payload).encode("utf-8")
            if name in {"valuation-request.json", "valuation-result.json"}
            else (canonical_json(payload) + "\n").encode("utf-8")
        )
        for name, payload in payloads.items()
    }
    archive = ValuationRunArchive(
        output_directory=tmp_path / "verified-original",
        directory_device=1,
        directory_inode=1,
        handoff=TypedPayload(payloads["valuation-handoff.json"]),
        price_blind_input=TypedPayload(payloads["price-blind-input.json"]),
        market_reference=TypedPayload(payloads["market-reference.json"]),
        request_payload=payloads["valuation-request.json"],
        result_payload=payloads["valuation-result.json"],
        manifest=payloads["valuation-run-manifest.json"],
        file_sha256={
            name: hashlib.sha256(content).hexdigest()
            for name, content in contents.items()
        },
    )
    monkeypatch.setattr(
        report_module,
        "load_valuation_run_archive",
        lambda *_args, **_kwargs: archive,
    )
    missing_path = tmp_path / "caller-path-must-not-be-reopened"

    with pytest.raises(ValueError, match="typed snapshot does not replay"):
        reload_valuation_input(missing_path)
    assert not missing_path.exists()


def test_full_report_rejects_coordinated_composite_and_score_rebinding(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import test_phase5_v1_valuation_synthesis as synthesis_fixtures

    synthesis = synthesis_fixtures._complete_synthesis(
        sample_payloads, monkeypatch, tmp_path
    )
    composite = synthesis[5]
    valuation_before = composite.to_dict()
    valuation_fingerprint = composite.fingerprint

    with pytest.raises(ValueError, match="replay|deterministic|valuation"):
        replace(
            composite,
            current_intrinsic_value=str(
                Decimal(str(composite.current_intrinsic_value)) + Decimal("1")
            ),
        )
    assert composite.to_dict() == valuation_before
    assert composite.fingerprint == valuation_fingerprint


def test_public_api_names_are_exact_and_compatibility_aliases_are_identical() -> None:
    import owner_research

    assert publish_owner_research is publish_research_report
    assert load_owner_research_package is load_published_package
    assert owner_research.PublishedResearchPackage is PublishedResearchPackage
    assert owner_research.publish_owner_research is publish_owner_research
    assert owner_research.load_owner_research_package is load_owner_research_package


def test_report_builder_rejects_pdf_without_real_qa_contract(
    sample_payloads,
    tmp_path: Path,
) -> None:
    research, source_index, report_spec, scores = _typed_report_inputs(sample_payloads, tmp_path)
    renderer = DeterministicRenderer(
        tuple(str(section["title"]) for section in report_spec.sections)
    )

    class ShortRenderer(DeterministicRenderer):
        def render(self, tex_sources):
            result = super().render(tex_sources)
            return replace(result, page_count=29, rendered_page_count=29)

    with pytest.raises(ValueError, match="30-60 page QA"):
        build_research_report(
            profile="research_only",
            research=research,
            report_spec=report_spec,
            research_source_index=source_index,
            scores=scores,
            renderer=ShortRenderer(renderer.section_titles),
        )


@pytest.mark.parametrize("page_count", (30, 60))
def test_report_page_scale_accepts_both_contract_boundaries(
    sample_payloads,
    tmp_path: Path,
    page_count: int,
) -> None:
    research, source_index, report_spec, scores = _typed_report_inputs(
        sample_payloads,
        tmp_path,
    )
    report = build_research_report(
        profile="research_only",
        research=research,
        report_spec=report_spec,
        research_source_index=source_index,
        scores=scores,
        renderer=DeterministicRenderer(
            tuple(str(section["title"]) for section in report_spec.sections),
            page_count=page_count,
        ),
    )

    assert report.receipt["qa"]["page_count"] == page_count
    assert report.receipt["qa"]["rendered_page_count"] == page_count


def test_report_page_scale_and_sparse_page_fail_closed(
    sample_payloads,
    tmp_path: Path,
) -> None:
    research, source_index, report_spec, scores = _typed_report_inputs(
        sample_payloads,
        tmp_path,
    )
    titles = tuple(str(section["title"]) for section in report_spec.sections)

    with pytest.raises(ValueError, match="30-60 page QA"):
        build_research_report(
            profile="research_only",
            research=research,
            report_spec=report_spec,
            research_source_index=source_index,
            scores=scores,
            renderer=DeterministicRenderer(titles, page_count=61),
        )
    with pytest.raises(ValueError, match="low-density non-cover pages"):
        build_research_report(
            profile="research_only",
            research=research,
            report_spec=report_spec,
            research_source_index=source_index,
            scores=scores,
            renderer=DeterministicRenderer(
                titles,
                page_character_counts=(120, 119, *((120,) * 28)),
            ),
        )
    with pytest.raises(ValueError, match="visually sparse non-cover pages"):
        build_research_report(
            profile="research_only",
            research=research,
            report_spec=report_spec,
            research_source_index=source_index,
            scores=scores,
            renderer=DeterministicRenderer(
                titles,
                page_non_white_ratios=(
                    "0.010000",
                    "0.039999",
                    *(("0.100000",) * 28),
                ),
            ),
        )


def test_report_builder_rejects_rendered_narrative_repetition(
    sample_payloads,
    tmp_path: Path,
) -> None:
    research, source_index, report_spec, scores = _typed_report_inputs(sample_payloads, tmp_path)

    class PaddingRenderer(DeterministicRenderer):
        def render(self, tex_sources):
            result = super().render(tex_sources)
            repeated = result.extracted_text + "\n" + tex_sources["report-data.tex"].decode()
            return replace(result, extracted_text=repeated)

    with pytest.raises(ValueError, match="omits or repeats substantive paragraph"):
        build_research_report(
            profile="research_only",
            research=research,
            report_spec=report_spec,
            research_source_index=source_index,
            scores=scores,
            renderer=PaddingRenderer(
                tuple(str(section["title"]) for section in report_spec.sections)
            ),
        )


def test_renderer_environment_is_closed_and_drops_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-pass")
    monkeypatch.setenv("FUTU_PASSWORD", "must-not-pass")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-pass")

    environment = _closed_renderer_environment(tmp_path, "/bin/sh")

    assert set(environment) == {
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "SOURCE_DATE_EPOCH",
        "TZ",
        "openin_any",
        "openout_any",
        "shell_escape",
    }
    assert all("must-not-pass" not in value for value in environment.values())


def test_report_toolchain_authority_is_pretrusted_and_cannot_be_self_attested() -> None:
    packaged = load_report_toolchain_authority()
    payload = packaged.to_dict()
    payload["renderer"]["sha256"] = "0" * 64
    payload.pop("authority_id")
    payload.pop("authority_fingerprint")
    fingerprint = canonical_sha256(payload)
    payload["authority_id"] = (
        f"report-toolchain-authority:{payload['platform_target']}:{fingerprint[:24]}"
    )
    payload["authority_fingerprint"] = fingerprint
    with pytest.raises(ValueError, match="component evidence is rebound"):
        self_attested = ReportToolchainAuthority.from_dict(payload)
        LatexReportRenderer(authority=self_attested)


def test_report_toolchain_registry_is_closed_and_bootstrap_is_read_only() -> None:
    registry = load_report_toolchain_authority_registry()
    authority = load_report_toolchain_authority()

    assert registry["required_platform_targets"] == ("linux-x64", "macos-arm64")
    assert (
        registry.for_platform(str(authority["platform_target"])).to_dict()
        == authority.to_dict()
    )
    assert registry["release_status"] == (
        "ready"
        if not registry["missing_platform_targets"]
        and all(
            item["release_evidence_status"] == "ready"
            for item in registry["authorities"]
        )
        else "blocked"
    )
    with pytest.raises(ValueError, match="platform is not authorized"):
        registry.for_platform("solaris-x64")
    assert tuple(
        inspect.signature(
            bootstrap_report_toolchain_authority_entry_from_manifest
        ).parameters
    ) == ("path",)


def test_renderer_stages_verified_executable_and_cache_snapshots_before_use(
    tmp_path: Path,
) -> None:
    source_executable = tmp_path / "source-tectonic"
    source_cache = tmp_path / "source-cache"
    source_cache.mkdir(mode=0o700)
    source_cache_member = source_cache / "bundle.bin"
    trusted_executable = b"#!/bin/sh\nprintf 'trusted-snapshot\\n'\n"
    trusted_cache = b"trusted-cache-bytes"
    source_executable.write_bytes(trusted_executable)
    source_executable.chmod(0o500)
    source_cache_member.write_bytes(trusted_cache)
    source_cache_member.chmod(0o400)
    executable_snapshot = _TrustedExecutableSnapshot(
        source_path=str(source_executable),
        sha256=hashlib.sha256(trusted_executable).hexdigest(),
        size=len(trusted_executable),
        content=trusted_executable,
    )
    cache_snapshot = _TrustedTectonicCacheSnapshot(
        source_path=str(source_cache),
        tree_sha256=canonical_sha256({"bundle.bin": hashlib.sha256(trusted_cache).hexdigest()}),
        member_count=1,
        total_bytes=len(trusted_cache),
        entries=(_TrustedCacheEntry("bundle.bin", False, trusted_cache),),
    )

    source_executable.chmod(0o700)
    source_executable.write_bytes(b"#!/bin/sh\nprintf 'mutated-source\\n'\n")
    source_cache_member.chmod(0o600)
    source_cache_member.write_bytes(b"mutated-cache")
    workspace = tmp_path / "private-render-workspace"
    workspace.mkdir(mode=0o700)
    staged_root = workspace / "trusted-toolchain"
    try:
        executable_path, cache_path = _stage_report_toolchain(
            workspace,
            executable_snapshot,
            cache_snapshot,
        )
        completed = subprocess.run(
            [executable_path],
            check=True,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        assert completed.stdout == "trusted-snapshot\n"
        assert (Path(cache_path) / "bundle.bin").read_bytes() == trusted_cache
        assert Path(executable_path).stat().st_mode & 0o777 == 0o500
        assert Path(cache_path).stat().st_mode & 0o777 == 0o500
    finally:
        if staged_root.exists():
            (staged_root / "tectonic-cache").chmod(0o700)
            staged_root.chmod(0o700)


def test_real_pretrusted_toolchain_renders_and_qa_checks_all_pages(
    sample_payloads,
    tmp_path: Path,
) -> None:
    research, source_index, report_spec, _ = _typed_report_inputs(
        sample_payloads,
        tmp_path,
        graph=formal_scope_graph(sample_payloads),
    )
    report = build_research_report(
        profile="research_only",
        research=research,
        report_spec=report_spec,
        research_source_index=source_index,
        renderer=LatexReportRenderer(),
    )

    assert 30 <= report.receipt["qa"]["page_count"] <= 60
    assert report.receipt["qa"]["rendered_page_count"] == report.receipt["qa"]["page_count"]
    assert report.receipt["renderer"]["toolchain_authority_fingerprint"] == (
        load_report_toolchain_authority().fingerprint
    )
    assert report.receipt["qa"]["anti_padding"]["status"] == "passed"
    assert Decimal(report.receipt["qa"]["page_non_white_ratios"][-1]) >= Decimal("0.040000")
    assert len(report.receipt["qa"]["rendered_page_sha256"]) == report.receipt["qa"][
        "page_count"
    ]
    assert report.receipt["qa"]["pdf_text_backend"] == load_report_toolchain_authority()[
        "pdf_text_backend"
    ]

    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    forged_pdf = BytesIO()
    writer.write(forged_pdf)
    forged_bytes = forged_pdf.getvalue()
    forged_artifacts = tuple(
        replace(item, content=forged_bytes) if item.path == "report.pdf" else item
        for item in report.artifacts
    )
    forged_receipt = report.receipt.to_dict() if hasattr(report.receipt, "to_dict") else dict(
        report.receipt
    )
    forged_receipt["artifacts"] = [
        {
            "path": item.path,
            "media_type": item.media_type,
            "size": len(item.content),
            "sha256": item.sha256,
        }
        for item in sorted(forged_artifacts, key=lambda artifact: artifact.path)
    ]
    forged_receipt.pop("receipt_fingerprint")
    forged_receipt["receipt_fingerprint"] = canonical_sha256(forged_receipt)
    rebound = replace(
        report,
        artifacts=forged_artifacts,
        receipt=ReportBuildReceipt(forged_receipt),
    )
    with pytest.raises(ResearchPublisherError, match="independently replay"):
        _verify_report_build(rebound)


def test_publisher_enforces_member_image_and_cumulative_limits() -> None:
    with pytest.raises(ResearchPublisherError, match="byte limit"):
        _validate_limits({"report/chart.png": b"x" * (PUBLISH_IMAGE_MAX_BYTES + 1)})
    with pytest.raises(ResearchPublisherError, match="512-member"):
        _validate_limits({f"report/item-{index}.txt": b"x" for index in range(PUBLISH_MAX_MEMBERS)})


def test_publisher_module_has_no_external_delivery_or_acquisition_surface() -> None:
    import owner_research.research_publisher as publisher

    forbidden = {
        "fetch",
        "download",
        "upload",
        "email",
        "github",
        "futu",
        "kernel",
        "execute",
    }
    public_names = {name.lower() for name in dir(publisher) if not name.startswith("_")}
    assert forbidden.isdisjoint(public_names)
    assert "httpx" not in publisher.__dict__


def test_publisher_rejects_non_host_owned_or_shared_parent(
    sample_payloads,
    tmp_path: Path,
) -> None:
    report, research, _, _ = _build_research_only(sample_payloads, tmp_path)
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o777)
    shared.chmod(0o777)
    try:
        with pytest.raises(ResearchPublisherError, match="host-owned"):
            publish_research_report(
                report,
                research,
                output_directory=shared / "published",
                allow_injected_test_renderer=True,
            )
    finally:
        shared.chmod(0o700)


def test_publisher_rejects_symlinked_parent(
    sample_payloads,
    tmp_path: Path,
) -> None:
    report, research, _, _ = _build_research_only(sample_payloads, tmp_path)
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ResearchPublisherError, match="without symlinks"):
        publish_research_report(
            report,
            research,
            output_directory=linked_parent / "published",
            allow_injected_test_renderer=True,
        )
