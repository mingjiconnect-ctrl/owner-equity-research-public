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

AUDIT_TOOL = "owner-research-phase5b-readonly"
AUDIT_VERSION = "2.0.4"
PHASE5A_MERGE = "54e2794a1147d32ef5dd0963730b96cd578e4ed1"
KERNEL_BASELINE = "a7dd1528c34f09702686b32ffbb8a397439665f0"
AUDITED_FILES = (
    "src/owner_research/valuation_fact_mapping_policies.py",
    "src/owner_research/valuation_fact_mapping_types.py",
    "src/owner_research/valuation_fact_mapping.py",
    "src/owner_research/valuation_readiness.py",
    "src/owner_research/research_bundle_validation.py",
    "docs/phase5b-mapping-policy.md",
    "docs/adr/0025-phase5b-fact-mapping-boundary.md",
    "tests/fixtures/phase5b/adversarial-cases.json",
    "tests/test_phase5b1_raw_fact_compiler.py",
    "tests/test_phase5b2_derived_lineage.py",
    "tests/test_phase5b3_readiness_routing.py",
    "tests/fixtures/phase5b/golden-readiness-cases.json",
    "tests/test_phase5b4_replay_closeout.py",
    "docs/phase-status.json",
    "docs/roadmap.md",
    "AGENTS.md",
)


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def _record(
    checks: list[dict[str, str]],
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


def _run(
    command: list[str], *, cwd: Path, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--valuation-repo", type=Path, required=True)
    parser.add_argument("--reviewed-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repository = args.repository.resolve()
    kernel = args.valuation_repo.resolve()
    checks: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    head = _git(repository, "rev-parse", "HEAD")
    remotes = _git(repository, "remote")
    _record(
        checks,
        findings,
        check_id="exact-head-no-remote",
        passed=head == args.reviewed_commit and not remotes,
        summary="Audit checkout is not exact-head or retains a remote.",
        evidence=f"expected={args.reviewed_commit}\nhead={head}\nremotes={remotes}",
        priority="P0",
    )
    writable = [
        item
        for item in (".", *AUDITED_FILES)
        if (repository / item).stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    ]
    _record(
        checks,
        findings,
        check_id="read-only-checkout",
        passed=not writable,
        summary="Audit checkout or Phase 5B files remain writable.",
        evidence=json.dumps(writable),
        priority="P0",
    )
    phase5a_ok = (
        subprocess.run(
            ["git", "-C", str(repository), "merge-base", "--is-ancestor", PHASE5A_MERGE, "HEAD"]
        ).returncode
        == 0
    )
    kernel_ok = (
        _git(kernel, "rev-parse", "HEAD") == KERNEL_BASELINE
        and _git(kernel, "rev-parse", "v2.0.0-rc.1^{}") == KERNEL_BASELINE
    )
    _record(
        checks,
        findings,
        check_id="fixed-baselines",
        passed=phase5a_ok and kernel_ok,
        summary="Phase 5A or valuation-kernel baseline drifted.",
        evidence=f"phase5a={PHASE5A_MERGE}\nkernel={_git(kernel, 'rev-parse', 'HEAD')}",
        priority="P0",
    )

    environment = os.environ.copy()
    environment.update(
        {
            "OWNER_VALUATION_REPO": str(kernel),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_ADDOPTS": "-p no:cacheprovider",
        }
    )
    with tempfile.TemporaryDirectory(prefix="phase5b-audit-runtime-") as runtime:
        runtime_path = Path(runtime)
        environment["PYTHONPYCACHEPREFIX"] = str(runtime_path / "pycache")
        environment["RUFF_CACHE_DIR"] = str(runtime_path / "ruff-cache")
        test_manifest = runtime_path / "phase5b-test-counts.json"
        verification = _run(
            [
                sys.executable,
                str(repository / "scripts/verify_all.py"),
                "--test-manifest",
                str(test_manifest),
            ],
            cwd=repository,
            environment=environment,
        )
        _record(
            checks,
            findings,
            check_id="full-verification",
            passed=verification.returncode == 0,
            summary="Full Phase 1-5B verification failed.",
            evidence=verification.stdout,
            priority="P0",
        )
        boundary = _run(
            [sys.executable, str(repository / "scripts/verify_phase5b_mapping.py")],
            cwd=repository,
            environment=environment,
        )
        _record(
            checks,
            findings,
            check_id="phase5b-mapping-boundary",
            passed=boundary.returncode == 0,
            summary="Phase 5B mapping or anti-anchoring boundary failed.",
            evidence=boundary.stdout,
            priority="P0",
        )
        test_counts = (
            json.loads(test_manifest.read_text())
            if test_manifest.is_file()
            else {
                "collected_tests": 0,
                "passed_tests": 0,
                "skipped_tests": 0,
                "failed_tests": 1,
            }
        )

    after = _git(repository, "status", "--porcelain")
    _record(
        checks,
        findings,
        check_id="clean-after",
        passed=not after,
        summary="Verification modified the audit checkout.",
        evidence=after or "clean",
        priority="P0",
    )
    payload: dict[str, Any] = {
        "audit_tool": AUDIT_TOOL,
        "audit_version": AUDIT_VERSION,
        "reviewed_commit": args.reviewed_commit,
        "phase5a_merge_commit": PHASE5A_MERGE,
        "valuation_kernel_commit": KERNEL_BASELINE,
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "audited_file_sha256": {
            relative: hashlib.sha256((repository / relative).read_bytes()).hexdigest()
            for relative in AUDITED_FILES
        },
        "test_counts": test_counts,
        "checks": checks,
        "findings": findings,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
