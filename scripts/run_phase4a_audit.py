#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AUDIT_TOOL = "owner-research-phase4a-readonly"
AUDIT_VERSION = "1.1.0"


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args],
        text=True,
        stderr=subprocess.STDOUT,
    ).strip()


def _record_check(
    checks: list[dict[str, Any]],
    findings: list[dict[str, str]],
    *,
    check_id: str,
    passed: bool,
    summary: str,
    evidence: str,
    priority: str = "P1",
) -> None:
    evidence_sha256 = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
    checks.append(
        {
            "check_id": check_id,
            "status": "passed" if passed else "failed",
            "evidence_sha256": evidence_sha256,
        }
    )
    if not passed:
        findings.append(
            {
                "finding_id": f"{priority}:{check_id}",
                "priority": priority,
                "check_id": check_id,
                "summary": summary,
                "evidence_sha256": evidence_sha256,
            }
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--valuation-repo", type=Path, required=True)
    parser.add_argument("--reviewed-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    repository = args.repository.resolve()
    started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    checks: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []

    head = _git(repository, "rev-parse", "HEAD")
    _record_check(
        checks,
        findings,
        check_id="reviewed-commit",
        passed=head == args.reviewed_commit,
        summary="Audit checkout does not match the declared reviewed commit.",
        evidence=f"expected={args.reviewed_commit}\nactual={head}",
    )

    remotes = _git(repository, "remote")
    _record_check(
        checks,
        findings,
        check_id="no-remote",
        passed=not remotes,
        summary="Audit checkout retains a Git remote.",
        evidence=remotes or "no remotes",
    )

    tracked_paths = _git(repository, "ls-files").splitlines()
    writable = [
        relative
        for relative in tracked_paths
        if (repository / relative).stat().st_mode
        & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    ]
    _record_check(
        checks,
        findings,
        check_id="readonly-tree",
        passed=not writable,
        summary="Audit checkout contains writable tracked files.",
        evidence="\n".join(writable) if writable else "all tracked files read-only",
    )

    before = _git(repository, "status", "--porcelain")
    _record_check(
        checks,
        findings,
        check_id="clean-before",
        passed=not before,
        summary="Audit checkout is dirty before verification.",
        evidence=before or "clean",
    )

    environment = os.environ.copy()
    environment["OWNER_VALUATION_REPO"] = str(args.valuation_repo.resolve())
    completed = subprocess.run(
        [sys.executable, str(repository / "scripts" / "verify_all.py")],
        cwd=repository,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    _record_check(
        checks,
        findings,
        check_id="repository-verification",
        passed=completed.returncode == 0,
        summary="Phase 4A repository verification failed.",
        evidence=completed.stdout,
    )

    after = _git(repository, "status", "--porcelain")
    _record_check(
        checks,
        findings,
        check_id="clean-after",
        passed=not after,
        summary="Verification modified the read-only audit checkout.",
        evidence=after or "clean",
    )

    payload = {
        "audit_tool": AUDIT_TOOL,
        "audit_version": AUDIT_VERSION,
        "reviewed_commit": args.reviewed_commit,
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "checks": checks,
        "findings": findings,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote audit evidence: {args.output}")
    print(f"checks={len(checks)} findings={len(findings)}")
    return 1 if any(item["priority"] in {"P0", "P1"} for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
