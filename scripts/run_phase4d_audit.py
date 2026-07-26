#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AUDIT_TOOL = "owner-research-phase4e2-readonly"
AUDIT_VERSION = "1.7.2"


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args],
        text=True,
        stderr=subprocess.STDOUT,
    ).strip()


def _record(
    checks: list[dict[str, Any]],
    findings: list[dict[str, str]],
    *,
    check_id: str,
    passed: bool,
    summary: str,
    evidence: str,
    priority: str = "P1",
) -> None:
    digest = hashlib.sha256(evidence.encode()).hexdigest()
    checks.append(
        {
            "check_id": check_id,
            "status": "passed" if passed else "failed",
            "evidence_sha256": digest,
        }
    )
    if not passed:
        findings.append(
            {
                "finding_id": f"{priority}:{check_id}",
                "priority": priority,
                "check_id": check_id,
                "summary": summary,
                "evidence_sha256": digest,
            }
        )


def main() -> int:
    started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--valuation-repo", type=Path, required=True)
    parser.add_argument("--reviewed-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    repository = args.repository.resolve()
    checks: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    head = _git(repository, "rev-parse", "HEAD")
    _record(
        checks,
        findings,
        check_id="reviewed-commit",
        passed=head == args.reviewed_commit,
        summary="Audit checkout does not match the reviewed commit.",
        evidence=f"expected={args.reviewed_commit}\nactual={head}",
    )
    remotes = _git(repository, "remote")
    _record(
        checks,
        findings,
        check_id="no-remote",
        passed=not remotes,
        summary="Audit checkout retains a Git remote.",
        evidence=remotes or "no remotes",
    )

    expected_versions = {
        "capital-allocation-event-candidate": "2.0.0",
        "capital-allocation-event-review-decision": "1.0.0",
        "capital-allocation-event": "2.0.0",
        "capital-allocation-outcome": "2.0.0",
        "source-search-receipt": "1.0.0",
        "capital-allocation-review": "3.0.0",
        "research-bundle": "1.0.0",
    }
    observed_versions: dict[str, str | None] = {}
    schemas_closed = True
    for name, expected in expected_versions.items():
        schema = json.loads(
            (repository / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8")
        )
        observed_versions[name] = schema["properties"]["schema_version"].get("const")
        schemas_closed = schemas_closed and schema.get("additionalProperties") is False
        schemas_closed = schemas_closed and observed_versions[name] == expected
    _record(
        checks,
        findings,
        check_id="phase4e2-public-contracts",
        passed=schemas_closed,
        summary="Phase 4E-2 public contracts are missing, open, or incorrectly versioned.",
        evidence=json.dumps(observed_versions, sort_keys=True),
    )

    policy_text = (
        repository / "src" / "owner_research" / "capital_allocation_policies.py"
    ).read_text(encoding="utf-8")
    validation_text = (repository / "src" / "owner_research" / "validation.py").read_text(
        encoding="utf-8"
    )
    ledger_text = (
        repository / "src" / "owner_research" / "capital_allocation_ledger.py"
    ).read_text(encoding="utf-8")
    bridge_text = (
        repository / "src" / "owner_research" / "capital_allocation_bridges.py"
    ).read_text(encoding="utf-8")
    outcome_text = (
        repository / "src" / "owner_research" / "capital_allocation_outcomes.py"
    ).read_text(encoding="utf-8")
    review_text = (
        repository / "src" / "owner_research" / "capital_allocation_reviews.py"
    ).read_text(encoding="utf-8")
    receipt_text = (repository / "src" / "owner_research" / "source_search_receipts.py").read_text(
        encoding="utf-8"
    )
    bundle_policy_text = (
        repository / "src" / "owner_research" / "research_bundle_policies.py"
    ).read_text(encoding="utf-8")
    bundle_validation_text = (
        repository / "src" / "owner_research" / "research_bundle_validation.py"
    ).read_text(encoding="utf-8")
    bundle_builder_text = (
        repository / "src" / "owner_research" / "research_bundle_builder.py"
    ).read_text(encoding="utf-8")
    bundle_artifact_text = (
        repository / "src" / "owner_research" / "research_bundle_artifacts.py"
    ).read_text(encoding="utf-8")
    integration_test_text = (
        repository / "tests" / "test_phase4e2_integration_closeout.py"
    ).read_text(encoding="utf-8")
    shadow_text = (repository / "scripts" / "capital_allocation_shadow_run.py").read_text(
        encoding="utf-8"
    )
    required_tokens = {
        'EVENT_POLICY_VERSION = "1.0.0"': policy_text,
        'OUTCOME_POLICY_VERSION = "1.0.0"': policy_text,
        "IDENTITY_ROLE_SETS": policy_text,
        "SOURCE_FAMILIES": policy_text,
        "role_accepts_unit": policy_text,
        "CapitalAllocationEvent silently deletes predecessor evidence": validation_text,
        "acquisition revenue cannot be classified as organic": validation_text,
        "debt refinancing cannot be represented as new debt": validation_text,
        "CapitalAllocationReview does not match deterministic replay": validation_text,
        "select_capital_allocation_filings": ledger_text,
        "build_event_candidate": ledger_text,
        "review_event_candidate": ledger_text,
        "compile_event": ledger_text,
        "Event compilation omits predecessor review Decisions": ledger_text,
        "Event Decision fingerprint is stale": ledger_text,
        'BRIDGE_POLICY_VERSION = "1.0.0"': bridge_text,
        "CAPITAL_ALLOCATION_BRIDGE_POLICIES": bridge_text,
        "run_capital_allocation_bridge": bridge_text,
        "input_assumption_ids": bridge_text,
        "bridge Fact is not reviewed by the Event": bridge_text,
        "forbidden result shortcut": bridge_text,
        "evaluate_capital_allocation_outcome": outcome_text,
        "Outcome Claim lacks valid human review": outcome_text,
        "not-disclosed Outcome role lacks a completed official search": outcome_text,
        "Outcome calculation cannot use Assumptions": outcome_text,
        "observed Outcome role Claim does not cover its result evidence": outcome_text,
        "Outcome observation window already has other evidence": outcome_text,
        "build_capital_allocation_review": review_text,
        "search_receipt_missing:": review_text,
        "event_type_search_incomplete:": review_text,
        "_event_is_active": review_text,
        "source_search_request_fingerprint": receipt_text,
        "build_source_search_receipt": receipt_text,
        "outcome_missing:": review_text,
        'CUTOFF = "2026-07-11"': shadow_text,
        '"contains_market_price": False': shadow_text,
        '"contains_valuation": False': shadow_text,
        '"contains_publisher": False': shadow_text,
        'BUNDLE_POLICY_VERSION = "1.0.0"': bundle_policy_text,
        "module_artifact_sha256": bundle_policy_text,
        "dependency_closure_sha256": bundle_policy_text,
        "source_graph_sha256": bundle_policy_text,
        "validate_research_bundle": bundle_validation_text,
        "ResearchBundle status was forged": bundle_validation_text,
        "RunManifest lacks the ResearchBundle output hash": bundle_validation_text,
        "build_research_bundle": bundle_builder_text,
        "ResearchBundleBuildResult": bundle_builder_text,
        "output_hashes[\"research-bundle.json\"]": bundle_builder_text,
        "Constructed ResearchBundle is invalid": bundle_builder_text,
        "Existing ResearchBundle is stale or conflicts with replay": bundle_builder_text,
        "write_research_bundle_artifacts": bundle_artifact_text,
        "load_research_bundle_artifacts": bundle_artifact_text,
        "Artifact path cannot contain a symlink": bundle_artifact_text,
        "Artifact directory must contain exactly the Bundle and RunManifest": (
            bundle_artifact_text
        ),
        "Artifact JSON is not canonically serialized": bundle_artifact_text,
        "test_complete_bundle_materializes_and_replays_end_to_end": integration_test_text,
        "test_new_policy_source_makes_bundle_partial_without_old_module_fallback": (
            integration_test_text
        ),
        "test_missing_modules_remain_blocked_through_artifact_roundtrip": (
            integration_test_text
        ),
    }
    missing_tokens = sorted(
        token for token, content in required_tokens.items() if token not in content
    )
    _record(
        checks,
        findings,
        check_id="phase4e2-artifact-integration-and-prior-phase-gates",
        passed=not missing_tokens,
        summary=("Phase 4E-2 artifact integration or prior-phase gates are incomplete."),
        evidence=json.dumps({"missing_tokens": missing_tokens}, sort_keys=True),
    )

    forbidden_modules = {
        "capital_allocation.py",
        "capital_allocation_intake.py",
        "capital_allocation_compiler.py",
        "capital_allocation_evaluator.py",
        "capital_allocation_review_builder.py",
        "capital_allocation_cash_bridge.py",
        "capital_allocation_outcome_evaluator.py",
        "capital_allocation_shadow.py",
        "publisher.py",
        "valuation_handoff.py",
        "research_bundle_cli.py",
        "research_bundle_orchestrator.py",
        "research_bundle_shadow.py",
    }
    present_forbidden = sorted(
        path.name
        for path in (repository / "src" / "owner_research").glob("*.py")
        if path.name in forbidden_modules
    )
    _record(
        checks,
        findings,
        check_id="phase4e2-production-boundary",
        passed=not present_forbidden,
        summary="Phase 4E-2 contains an unauthorized later-phase module.",
        evidence=json.dumps({"forbidden_modules": present_forbidden}, sort_keys=True),
        priority="P0",
    )

    tracked = _git(repository, "ls-files").splitlines()
    writable = [
        item
        for item in tracked
        if (repository / item).stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    ]
    _record(
        checks,
        findings,
        check_id="readonly-tree",
        passed=not writable,
        summary="Audit checkout contains writable tracked files.",
        evidence="\n".join(writable) if writable else "all tracked files read-only",
    )
    before = _git(repository, "status", "--porcelain")
    _record(
        checks,
        findings,
        check_id="clean-before",
        passed=not before,
        summary="Audit checkout is dirty before verification.",
        evidence=before or "clean",
    )

    test_manifest = args.output.with_name("phase4e2-test-counts.json")
    environment = os.environ.copy()
    environment["OWNER_VALUATION_REPO"] = str(args.valuation_repo.resolve())
    environment.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    environment.setdefault("PYTEST_ADDOPTS", "-p no:cacheprovider")
    with tempfile.TemporaryDirectory(prefix="phase4e2-audit-runtime-") as runtime:
        environment.setdefault("PYTHONPYCACHEPREFIX", str(Path(runtime) / "pycache"))
        environment.setdefault("RUFF_CACHE_DIR", str(Path(runtime) / "ruff"))
        completed = subprocess.run(
            [
                sys.executable,
                str(repository / "scripts" / "verify_all.py"),
                "--test-manifest",
                str(test_manifest),
            ],
            cwd=repository,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    _record(
        checks,
        findings,
        check_id="repository-verification",
        passed=completed.returncode == 0,
        summary="Phase 4E-2 repository verification failed.",
        evidence=completed.stdout,
    )
    after = _git(repository, "status", "--porcelain")
    _record(
        checks,
        findings,
        check_id="clean-after",
        passed=not after,
        summary="Verification modified the read-only audit checkout.",
        evidence=after or "clean",
    )
    test_counts = (
        json.loads(test_manifest.read_text(encoding="utf-8"))
        if test_manifest.is_file()
        else {
            "collected_tests": 0,
            "passed_tests": 0,
            "skipped_tests": 0,
            "failed_tests": 1,
        }
    )
    payload = {
        "audit_tool": AUDIT_TOOL,
        "audit_version": AUDIT_VERSION,
        "reviewed_commit": args.reviewed_commit,
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "test_counts": test_counts,
        "checks": checks,
        "findings": findings,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
