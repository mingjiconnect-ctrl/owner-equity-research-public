from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from test_phase5_v1_report_publisher import (
    DeterministicRenderer,
    _build_research_only,
)

from owner_research.owner_equity_research import (
    OwnerEquityResearchDependencies,
    OwnerEquityResearchInputReceipt,
    OwnerEquityResearchRequest,
    PhaseReceipt,
    PhaseStatus,
    PublicationPhaseResult,
    PublicationProfile,
    ResearchIntent,
    run_owner_equity_research,
)
from owner_research.research_publisher import (
    ResearchPublisherError,
    publish_owner_research,
    republish_owner_research_package,
)
from owner_research.research_report import build_research_report


def _publish_distinct_research_only_packages(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
):
    report, research, report_spec, scores = _build_research_only(
        sample_payloads,
        tmp_path,
    )
    titles = tuple(str(section["title"]) for section in report_spec.sections)
    changed_score = replace(
        scores[0],
        score=7.5,
        rationale="Distinct reviewed score for republication binding regression.",
    )
    changed_report = build_research_report(
        profile="research_only",
        research=research,
        report_spec=report_spec,
        research_source_index=report.research_source_index,
        scores=(changed_score,),
        renderer=DeterministicRenderer(titles),
    )
    source = publish_owner_research(
        report,
        research,
        output_directory=tmp_path / "source-package",
        allow_injected_test_renderer=True,
    )
    alternate = publish_owner_research(
        changed_report,
        research,
        output_directory=tmp_path / "alternate-package",
        allow_injected_test_renderer=True,
    )
    assert source.profile == alternate.profile == "research_only"
    assert source.report.issuer_id == alternate.report.issuer_id
    assert source.report.data_cutoff_date == alternate.report.data_cutoff_date
    assert source.publication_manifest != alternate.publication_manifest
    assert dict(source.file_bytes) != dict(alternate.file_bytes)
    return source, alternate


def test_byte_preserving_republication_is_idempotent_and_rejects_other_content(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    source, alternate = _publish_distinct_research_only_packages(
        sample_payloads,
        tmp_path,
    )
    source_mtimes = {
        path.relative_to(source.output_directory): path.stat().st_mtime_ns
        for path in source.output_directory.rglob("*")
    }

    same_directory = republish_owner_research_package(
        source,
        output_directory=source.output_directory,
        allow_injected_test_renderer=True,
    )
    copied = republish_owner_research_package(
        source,
        output_directory=tmp_path / "copied-package",
        allow_injected_test_renderer=True,
    )

    assert dict(same_directory.file_bytes) == dict(source.file_bytes)
    assert dict(same_directory.file_sha256) == dict(source.file_sha256)
    assert same_directory.publication_manifest == source.publication_manifest
    assert same_directory.package_receipt == source.package_receipt
    assert {
        path.relative_to(source.output_directory): path.stat().st_mtime_ns
        for path in source.output_directory.rglob("*")
    } == source_mtimes
    assert dict(copied.file_bytes) == dict(source.file_bytes)
    assert dict(copied.file_sha256) == dict(source.file_sha256)
    assert copied.publication_manifest == source.publication_manifest
    assert copied.package_receipt == source.package_receipt

    with pytest.raises(
        ResearchPublisherError,
        match="destination differs from the retained source package",
    ):
        republish_owner_research_package(
            source,
            output_directory=alternate.output_directory,
            allow_injected_test_renderer=True,
        )


def test_publish_route_blocks_an_injected_alternate_valid_source_and_output(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
) -> None:
    source, alternate = _publish_distinct_research_only_packages(
        sample_payloads,
        tmp_path,
    )
    request = OwnerEquityResearchRequest(
        issuer_id=source.report.issuer_id,
        data_cutoff_date=source.report.data_cutoff_date,
        intent=ResearchIntent.PUBLISH,
        profile=PublicationProfile.RESEARCH_ONLY,
        requested_by="human:republication-reviewer",
        requested_at="2026-08-15T09:00:00+08:00",
    )
    adapter_calls = 0

    def forbidden_adapter(*_args, **_kwargs):
        raise AssertionError("publish-only route crossed a forbidden dependency")

    def injected_alternate(inputs):
        nonlocal adapter_calls
        adapter_calls += 1
        assert inputs.source_package is source
        input_receipt = OwnerEquityResearchInputReceipt.from_request(request)
        receipt = PhaseReceipt.create(
            phase="publication",
            input_receipt=input_receipt,
            upstream_receipts=(),
            authorities=(
                alternate,
                alternate,
                alternate.publication_manifest,
            ),
        )
        return PublicationPhaseResult(
            status=PhaseStatus.COMPLETED,
            issuer_id=request.issuer_id,
            data_cutoff_date=request.data_cutoff_date,
            receipt=receipt,
            profile=PublicationProfile.RESEARCH_ONLY,
            published_package=alternate,
            publication_manifest=alternate.publication_manifest,
            source_package=alternate,
        )

    dependencies = OwnerEquityResearchDependencies(
        official_research=forbidden_adapter,
        quarterly=forbidden_adapter,
        futu_nonprice=forbidden_adapter,
        refreeze_price_blind=forbidden_adapter,
        futu_market_reference=forbidden_adapter,
        run_owner_valuation=forbidden_adapter,
        synthesize=forbidden_adapter,
        score=forbidden_adapter,
        futu_market_expectations=forbidden_adapter,
        build_report=forbidden_adapter,
        publish=injected_alternate,
        audit=forbidden_adapter,
        intent=ResearchIntent.PUBLISH,
        profile=PublicationProfile.RESEARCH_ONLY,
        publication_source=source,
    )

    result = run_owner_equity_research(
        request=request,
        dependencies=dependencies,
    )

    assert adapter_calls == 1
    assert result.status is PhaseStatus.BLOCKED
    assert result.publication is None
    assert result.published_package is None
    assert result.issue_codes == ("publication_blocked",)
    assert tuple(
        (step.sequence, step.phase, step.status) for step in result.trace
    ) == ((1, "publication", PhaseStatus.BLOCKED),)
