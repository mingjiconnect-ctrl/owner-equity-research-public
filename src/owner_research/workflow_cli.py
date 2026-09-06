"""Unified CLI router for the comprehensive Owner Equity Research workflow.

Production calls use one strict runtime-config locator which is immediately resolved into
typed authorities.  Explicit service injection remains only as an internal test seam; the
console entry point never creates fixtures, substitutes a price source, or fabricates
runtime authority.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .owner_equity_research import (
    OwnerEquityResearchDependencies,
    OwnerEquityResearchError,
    OwnerEquityResearchRequest,
    OwnerEquityResearchResult,
    PhaseStatus,
    PublicationProfile,
    ResearchIntent,
    run_owner_equity_research,
)
from .research_publisher import publish_owner_research


@dataclass(frozen=True, slots=True)
class WorkflowService:
    dependencies: OwnerEquityResearchDependencies

    def __post_init__(self) -> None:
        if type(self.dependencies) is not OwnerEquityResearchDependencies:
            raise OwnerEquityResearchError("workflow service requires exact dependencies")


def _add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--runtime-config",
        type=Path,
        help="canonical owner-equity-runtime-config.json (required outside tests)",
    )
    parser.add_argument("--issuer-id", required=True, help="official issuer identity")
    parser.add_argument(
        "--data-cutoff-date",
        required=True,
        help="official evidence cutoff in YYYY-MM-DD form",
    )
    parser.add_argument(
        "--requested-by",
        required=True,
        help="named human identity in human:<name> form",
    )
    parser.add_argument(
        "--requested-at",
        required=True,
        help="timezone-aware ISO-8601 request time",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="owner-equity-research",
        description=(
            "Run a strictly loaded, fail-closed Owner Equity Research workflow. "
            "No live authority or source data is inferred by this command."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    children: dict[str, argparse.ArgumentParser] = {}
    for command, help_text in (
        ("research", "run ordinary price-blind official-source research"),
        ("quarterly", "run the explicit price-blind quarterly route"),
        ("valuation", "run the explicit valuation, report, and local package route"),
        ("report", "build a price-blind report without Futu or valuation"),
        ("audit", "run the explicit read-only audit route"),
    ):
        child = subparsers.add_parser(command, help=help_text)
        _add_identity_arguments(child)
        children[command] = child
    children["report"].add_argument(
        "--output",
        type=Path,
        required=True,
        help="new local research-only package directory containing report/report.pdf",
    )
    publish = subparsers.add_parser(
        "publish", help="build and atomically publish one closed local package profile"
    )
    _add_identity_arguments(publish)
    publish.add_argument(
        "--profile",
        required=True,
        choices=tuple(profile.value for profile in PublicationProfile),
        help="closed publication profile; full_valuation is explicit valuation intent",
    )
    return parser


def _request_from_args(args: argparse.Namespace) -> OwnerEquityResearchRequest:
    intent = ResearchIntent(args.command)
    if intent is ResearchIntent.REPORT:
        profile = PublicationProfile.RESEARCH_ONLY
    elif intent is ResearchIntent.VALUATION:
        profile = PublicationProfile.FULL_VALUATION
    elif intent is ResearchIntent.PUBLISH:
        profile = PublicationProfile(args.profile)
    else:
        profile = None
    return OwnerEquityResearchRequest(
        issuer_id=args.issuer_id,
        data_cutoff_date=args.data_cutoff_date,
        intent=intent,
        profile=profile,
        requested_by=args.requested_by,
        requested_at=args.requested_at,
    )


def _deliver_report(
    result: OwnerEquityResearchResult,
    output_directory: Path,
) -> dict[str, object]:
    """Persist the retained price-blind report through the strict local Publisher."""

    target = output_directory.expanduser().absolute()
    report_phase = result.report
    if report_phase is None or report_phase.report_build is None:
        return {
            "artifact_type": "owner-equity-research-report-delivery",
            "status": "not_written",
            "reason": "report_not_available",
            "output_directory": str(target),
            "report_pdf": None,
            "publication_manifest_fingerprint": None,
            "package_fingerprint": None,
        }
    official = result.official_research
    if official is None or official.research_input is None:
        raise OwnerEquityResearchError("report delivery lacks the retained strict research input")
    package = publish_owner_research(
        report_phase.report_build,
        official.research_input,
        output_directory=target,
    )
    return {
        "artifact_type": "owner-equity-research-report-delivery",
        "status": "written",
        "reason": None,
        "output_directory": str(package.output_directory),
        "report_pdf": str(package.output_directory / "report" / "report.pdf"),
        "publication_manifest_fingerprint": package.publication_manifest.fingerprint,
        "package_fingerprint": package.fingerprint,
    }


def run_cli(
    argv: Sequence[str],
    *,
    service: WorkflowService,
) -> int:
    """Parse and run one command using an explicit real-runtime service."""

    if type(service) is not WorkflowService:
        raise OwnerEquityResearchError("CLI requires the exact WorkflowService")
    args = build_parser().parse_args(argv)
    try:
        request = _request_from_args(args)
        result = run_owner_equity_research(
            request=request,
            dependencies=service.dependencies,
        )
    except OwnerEquityResearchError as exc:
        print(
            json.dumps(
                {
                    "artifact_type": "owner-equity-research-cli-error",
                    "error": str(exc),
                    "status": "invalid_request",
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    summary = result.summary()
    if request.intent is ResearchIntent.REPORT:
        try:
            summary["delivery"] = _deliver_report(result, args.output)
        except (OSError, TypeError, ValueError) as exc:
            print(
                json.dumps(
                    {
                        "artifact_type": "owner-equity-research-cli-error",
                        "status": "output_error",
                        "error": str(exc),
                        "output_directory": str(args.output.expanduser().absolute()),
                        "workflow_status": result.status.value,
                        "result_id": result.result_id,
                        "result_fingerprint": result.result_fingerprint,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return {
        PhaseStatus.COMPLETED: 0,
        PhaseStatus.CONTESTED: 3,
        PhaseStatus.SPECIALIST_REQUIRED: 4,
        PhaseStatus.BLOCKED: 5,
        PhaseStatus.PARTIAL: 6,
    }[result.status]


def main(
    argv: Sequence[str] | None = None,
    *,
    service: WorkflowService | None = None,
) -> int:
    """Console entry point with a real strict runtime factory."""

    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if service is None:
        # Parse first so ``--help`` remains a normal console-script smoke test.
        args = build_parser().parse_args(arguments)
        try:
            request = _request_from_args(args)
            if args.runtime_config is None:
                raise OwnerEquityResearchError(
                    "--runtime-config is required; runtime authority is never inferred"
                )
            from .owner_equity_runtime import (
                build_runtime_dependencies,
                load_owner_equity_runtime,
            )

            runtime = load_owner_equity_runtime(
                args.runtime_config,
                intent=request.intent,
                profile=request.profile,
            )
            service = WorkflowService(build_runtime_dependencies(runtime))
        except (ImportError, OwnerEquityResearchError, OSError, TypeError, ValueError) as exc:
            print(
                json.dumps(
                    {
                        "artifact_type": "owner-equity-research-cli-error",
                        "error": str(exc),
                        "status": "invalid_request",
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2
    return run_cli(arguments, service=service)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ("WorkflowService", "build_parser", "main", "run_cli")
