from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from owner_research import workflow_cli
from owner_research.owner_equity_research import (
    OwnerEquityResearchDependencies,
    PhaseStatus,
    PublicationProfile,
    ResearchIntent,
)


def _dependencies() -> OwnerEquityResearchDependencies:
    def unavailable(*args):
        return None

    return OwnerEquityResearchDependencies(
        official_research=unavailable,
        quarterly=unavailable,
        futu_nonprice=unavailable,
        refreeze_price_blind=unavailable,
        futu_market_reference=unavailable,
        run_owner_valuation=unavailable,
        synthesize=unavailable,
        score=unavailable,
        futu_market_expectations=unavailable,
        build_report=unavailable,
        publish=unavailable,
        audit=unavailable,
        intent=ResearchIntent.RESEARCH,
        profile=None,
    )


@dataclass(frozen=True, slots=True)
class _CliResult:
    status: PhaseStatus = PhaseStatus.COMPLETED
    official_research: object | None = None
    report: object | None = None

    @property
    def result_id(self) -> str:
        return "test-result"

    @property
    def result_fingerprint(self) -> str:
        return "a" * 64

    def summary(self):
        return {"artifact_type": "test-summary", "status": self.status.value}


def _identity_args() -> list[str]:
    return [
        "--issuer-id",
        "issuer:us:test",
        "--data-cutoff-date",
        "2026-08-14",
        "--requested-by",
        "human:reviewer",
        "--requested-at",
        "2026-08-15T09:00:00+08:00",
    ]


@pytest.mark.parametrize(
    ("command", "extra", "intent", "profile"),
    (
        ("research", [], ResearchIntent.RESEARCH, None),
        ("quarterly", [], ResearchIntent.QUARTERLY, None),
        (
            "valuation",
            [],
            ResearchIntent.VALUATION,
            PublicationProfile.FULL_VALUATION,
        ),
        (
            "report",
            [],
            ResearchIntent.REPORT,
            PublicationProfile.RESEARCH_ONLY,
        ),
        ("audit", [], ResearchIntent.AUDIT, None),
        (
            "publish",
            ["--profile", "research_only"],
            ResearchIntent.PUBLISH,
            PublicationProfile.RESEARCH_ONLY,
        ),
        (
            "publish",
            ["--profile", "full_valuation"],
            ResearchIntent.PUBLISH,
            PublicationProfile.FULL_VALUATION,
        ),
    ),
)
def test_unified_cli_routes_closed_subcommands(
    monkeypatch, capsys, tmp_path, command, extra, intent, profile
):
    captured = {}
    delivery_output = tmp_path / "report-package"
    if command == "report":
        extra = [*extra, "--output", str(delivery_output)]
        report_build = object()
        research_input = object()
        result = _CliResult(
            official_research=SimpleNamespace(research_input=research_input),
            report=SimpleNamespace(report_build=report_build),
        )

        def fake_publish(report, research, *, output_directory):
            assert report is report_build
            assert research is research_input
            assert output_directory == delivery_output
            return SimpleNamespace(
                output_directory=output_directory,
                publication_manifest=SimpleNamespace(fingerprint="b" * 64),
                fingerprint="c" * 64,
            )

        monkeypatch.setattr(workflow_cli, "publish_owner_research", fake_publish)
    else:
        result = _CliResult()

    def fake_run(*, request, dependencies):
        captured["request"] = request
        captured["dependencies"] = dependencies
        return result

    monkeypatch.setattr(workflow_cli, "run_owner_equity_research", fake_run)
    service = workflow_cli.WorkflowService(_dependencies())
    exit_code = workflow_cli.run_cli(
        [command, *_identity_args(), *extra],
        service=service,
    )

    assert exit_code == 0
    assert captured["request"].intent is intent
    assert captured["request"].profile is profile
    assert captured["dependencies"] is service.dependencies
    expected = {
        "artifact_type": "test-summary",
        "status": "completed",
    }
    if command == "report":
        expected["delivery"] = {
            "artifact_type": "owner-equity-research-report-delivery",
            "status": "written",
            "reason": None,
            "output_directory": str(delivery_output),
            "report_pdf": str(delivery_output / "report" / "report.pdf"),
            "publication_manifest_fingerprint": "b" * 64,
            "package_fingerprint": "c" * 64,
        }
    assert json.loads(capsys.readouterr().out) == expected


def test_console_entry_requires_strict_runtime_config(capsys):
    exit_code = workflow_cli.main(["research", *_identity_args()])

    assert exit_code == 2
    error = json.loads(capsys.readouterr().err)
    assert error["status"] == "invalid_request"
    assert "--runtime-config is required" in error["error"]


def test_console_help_lists_all_six_routes():
    help_text = workflow_cli.build_parser().format_help()

    for command in ("research", "quarterly", "valuation", "report", "publish", "audit"):
        assert command in help_text


def test_report_requires_an_explicit_output_directory(tmp_path: Path):
    parser = workflow_cli.build_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["report", *_identity_args()])

    assert exc_info.value.code == 2
    parsed = parser.parse_args(
        ["report", *_identity_args(), "--output", str(tmp_path / "report-package")]
    )
    assert parsed.output == tmp_path / "report-package"


def test_report_output_failure_is_distinct_from_workflow_status(
    monkeypatch, capsys, tmp_path: Path
):
    report_build = object()
    research_input = object()
    result = _CliResult(
        official_research=SimpleNamespace(research_input=research_input),
        report=SimpleNamespace(report_build=report_build),
    )
    monkeypatch.setattr(
        workflow_cli,
        "run_owner_equity_research",
        lambda **_kwargs: result,
    )

    def fail_publish(*_args, **_kwargs):
        raise ValueError("publication parent must already exist without symlinks")

    monkeypatch.setattr(workflow_cli, "publish_owner_research", fail_publish)
    output = tmp_path / "missing" / "report-package"

    exit_code = workflow_cli.run_cli(
        ["report", *_identity_args(), "--output", str(output)],
        service=workflow_cli.WorkflowService(_dependencies()),
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "artifact_type": "owner-equity-research-cli-error",
        "status": "output_error",
        "error": "publication parent must already exist without symlinks",
        "output_directory": str(output),
        "workflow_status": "completed",
        "result_id": "test-result",
        "result_fingerprint": "a" * 64,
    }


def test_blocked_report_marks_requested_output_not_written(monkeypatch, capsys, tmp_path: Path):
    monkeypatch.setattr(
        workflow_cli,
        "run_owner_equity_research",
        lambda **_kwargs: _CliResult(status=PhaseStatus.BLOCKED),
    )
    output = tmp_path / "report-package"

    exit_code = workflow_cli.run_cli(
        ["report", *_identity_args(), "--output", str(output)],
        service=workflow_cli.WorkflowService(_dependencies()),
    )

    assert exit_code == 5
    assert json.loads(capsys.readouterr().out)["delivery"] == {
        "artifact_type": "owner-equity-research-report-delivery",
        "status": "not_written",
        "reason": "report_not_available",
        "output_directory": str(output),
        "report_pdf": None,
        "publication_manifest_fingerprint": None,
        "package_fingerprint": None,
    }


def test_cli_rejects_unnamed_requester_without_calling_service(monkeypatch, capsys):
    called = False

    def fake_run(**kwargs):
        nonlocal called
        called = True
        return _CliResult()

    monkeypatch.setattr(workflow_cli, "run_owner_equity_research", fake_run)
    args = ["research", *_identity_args()]
    args[args.index("human:reviewer")] = "anonymous"
    exit_code = workflow_cli.run_cli(
        args,
        service=workflow_cli.WorkflowService(_dependencies()),
    )

    assert exit_code == 2
    assert called is False
    assert json.loads(capsys.readouterr().err)["status"] == "invalid_request"
