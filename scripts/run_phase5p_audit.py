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

AUDIT_TOOL = "owner-research-phase5p-readonly"
AUDIT_VERSION = "1.8.0"
RESEARCH_BASELINE = "30d6e77780175deeffc5c211749bcb0169aa1dde"
KERNEL_BASELINE = "a7dd1528c34f09702686b32ffbb8a397439665f0"
PLANNING_DOCS = (
    "docs/phase5-plan.md",
    "docs/phase5-methodology.md",
    "docs/phase5-interface-matrix.json",
    "docs/phase5-failure-mode-matrix.json",
    "docs/adr/0023-research-to-valuation-boundary.md",
    "docs/phase5-acceptance.md",
)


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
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--valuation-repo", type=Path, required=True)
    parser.add_argument("--reviewed-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    repository = args.repository.resolve()
    kernel = args.valuation_repo.resolve()
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
        priority="P0",
    )
    remotes = _git(repository, "remote")
    _record(
        checks,
        findings,
        check_id="no-remote",
        passed=not remotes,
        summary="Audit checkout retains a Git remote.",
        evidence=remotes or "no remotes",
        priority="P0",
    )
    writable = [
        str(path.relative_to(repository))
        for path in (repository, *(repository / item for item in PLANNING_DOCS))
        if path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    ]
    _record(
        checks,
        findings,
        check_id="read-only-checkout",
        passed=not writable,
        summary="Audit checkout or planning documents remain writable.",
        evidence=json.dumps(writable),
        priority="P0",
    )
    kernel_head = _git(kernel, "rev-parse", "HEAD")
    _record(
        checks,
        findings,
        check_id="fixed-baselines",
        passed=(
            _git(repository, "rev-parse", "v0.4.0-alpha.1^{}") == RESEARCH_BASELINE
            and kernel_head == KERNEL_BASELINE
            and _git(kernel, "rev-parse", "v2.0.0-rc.1^{}") == KERNEL_BASELINE
        ),
        summary="Research or valuation-kernel baseline drifted.",
        evidence=f"research={RESEARCH_BASELINE}\nkernel={kernel_head}",
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
    with tempfile.TemporaryDirectory(prefix="phase5p-audit-runtime-") as runtime:
        runtime_path = Path(runtime)
        environment["PYTHONPYCACHEPREFIX"] = str(runtime_path / "pycache")
        environment["RUFF_CACHE_DIR"] = str(runtime_path / "ruff-cache")
        test_manifest = runtime_path / "phase5p-test-counts.json"
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
            check_id="historical-verification",
            passed=completed.returncode == 0,
            summary="Phase 1-4 verification failed in the read-only audit.",
            evidence=completed.stdout,
        )
        planning = subprocess.run(
            [
                sys.executable,
                str(repository / "scripts" / "verify_phase5p_plan.py"),
                "--repository",
                str(repository),
                "--valuation-repo",
                str(kernel),
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
            check_id="planning-and-interface-audit",
            passed=planning.returncode == 0,
            summary="Phase 5P planning or pinned-interface audit failed.",
            evidence=planning.stdout,
            priority="P0",
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

    after = _git(repository, "status", "--porcelain")
    _record(
        checks,
        findings,
        check_id="clean-after",
        passed=not after,
        summary="Verification modified the read-only audit checkout.",
        evidence=after or "clean",
        priority="P0",
    )
    document_hashes = {
        relative: hashlib.sha256((repository / relative).read_bytes()).hexdigest()
        for relative in PLANNING_DOCS
    }
    payload = {
        "audit_tool": AUDIT_TOOL,
        "audit_version": AUDIT_VERSION,
        "reviewed_commit": args.reviewed_commit,
        "research_baseline_commit": RESEARCH_BASELINE,
        "valuation_kernel_commit": KERNEL_BASELINE,
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "planning_document_sha256": document_hashes,
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
