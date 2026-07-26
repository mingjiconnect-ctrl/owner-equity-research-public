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

AUDIT_TOOL = "owner-research-phase5d-readonly"
AUDIT_VERSION = "2.2.6"
PHASE5C_BASELINE = "d3028bc7a601c63aebf9faf136ce133e4097b9d2"
KERNEL_BASELINE = "a7dd1528c34f09702686b32ffbb8a397439665f0"
STATIC_CONTROL_FILES = {
    ".github/workflows/ci.yml",
    "AGENTS.md",
    "README.md",
    "component-lock.json",
    "docs/architecture.md",
    "docs/contract-dependency-matrix.json",
    "docs/phase-status.json",
    "docs/roadmap.md",
    "plugins/owner-equity-research/.codex-plugin/plugin.json",
    "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md",
    "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md",
    "schemas/valuation-assumption-candidate.schema.json",
    "schemas/valuation-handoff.schema.json",
    "scripts/run_phase5d_audit.py",
    "scripts/verify_all.py",
    "scripts/verify_phase5c_baseline.py",
    "scripts/verify_phase5d0_policies.py",
    "scripts/verify_phase5d0_baseline.py",
    "scripts/verify_phase5d1_candidates.py",
    "scripts/verify_phase5d1_baseline.py",
    "scripts/verify_phase5d2_assumption_ledger.py",
    "scripts/verify_phase5d2_baseline.py",
    "scripts/verify_phase5d3_mckinsey_inputs.py",
    "scripts/verify_phase5d3_baseline.py",
    "scripts/verify_phase5d4_penman_inputs.py",
    "scripts/verify_phase5d4_baseline.py",
    "scripts/verify_phase5d5_price_blind_freeze.py",
    "scripts/verify_phase5d5_baseline.py",
    "scripts/verify_phase5d6_replay_closeout.py",
    "scripts/write_phase5d_audit.py",
    "src/owner_research/contracts.py",
    "src/owner_research/validation.py",
    "src/owner_research/valuation_assumption_types.py",
    "src/owner_research/valuation_assumption_candidates.py",
    "src/owner_research/valuation_assumption_ledger.py",
    "src/owner_research/valuation_mckinsey_inputs.py",
    "src/owner_research/valuation_penman_inputs.py",
    "src/owner_research/valuation_price_blind_freeze.py",
    "src/owner_research/valuation_handoff_policies.py",
    "src/owner_research/valuation_handoff_validation.py",
}


def _has_blocking_findings(findings: tuple[dict[str, str], ...] | list[dict[str, str]]) -> bool:
    return any(item.get("priority") in {"P0", "P1", "P2", "P3"} for item in findings)


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
    changed_files = set(
        _git(
            repository,
            "diff",
            "--name-only",
            "--no-renames",
            PHASE5C_BASELINE,
            "HEAD",
        ).splitlines()
    )
    audited_files = tuple(sorted(changed_files | STATIC_CONTROL_FILES))
    missing = [relative for relative in audited_files if not (repository / relative).is_file()]
    _record(
        checks,
        findings,
        check_id="audited-files-present",
        passed=not missing,
        summary="Required Phase 5D-0 audit files are missing.",
        evidence=json.dumps(missing, sort_keys=True),
        priority="P0",
    )
    existing = [relative for relative in audited_files if (repository / relative).is_file()]
    writable = [
        item
        for item in (".", *existing)
        if (repository / item).stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    ]
    _record(
        checks,
        findings,
        check_id="read-only-checkout",
        passed=not writable,
        summary="Audit checkout or Phase 5D-0 files remain writable.",
        evidence=json.dumps(writable, sort_keys=True),
        priority="P0",
    )
    phase5c_ok = (
        subprocess.run(
            ["git", "-C", str(repository), "merge-base", "--is-ancestor", PHASE5C_BASELINE, "HEAD"]
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
        passed=phase5c_ok and kernel_ok,
        summary="Phase 5C or valuation-kernel baseline drifted.",
        evidence=f"phase5c={PHASE5C_BASELINE}\nkernel={_git(kernel, 'rev-parse', 'HEAD')}",
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
    with tempfile.TemporaryDirectory(prefix="phase5d-audit-runtime-") as runtime:
        runtime_path = Path(runtime)
        environment["PYTHONPYCACHEPREFIX"] = str(runtime_path / "pycache")
        environment["RUFF_CACHE_DIR"] = str(runtime_path / "ruff-cache")
        test_manifest = runtime_path / "phase5d-test-counts.json"
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
            summary="Full Phase 1-5D-0 verification failed.",
            evidence=verification.stdout,
            priority="P0",
        )
        boundary = _run(
            [
                sys.executable,
                str(repository / "scripts/verify_phase5d6_replay_closeout.py"),
            ],
            cwd=repository,
            environment=environment,
        )
        _record(
            checks,
            findings,
            check_id="phase5d6-boundary",
            passed=boundary.returncode == 0,
            summary="Phase 5D-6 deterministic replay or closeout boundary failed.",
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
        "phase5c_baseline_commit": PHASE5C_BASELINE,
        "valuation_kernel_commit": KERNEL_BASELINE,
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "audited_file_sha256": {
            relative: hashlib.sha256((repository / relative).read_bytes()).hexdigest()
            for relative in existing
        },
        "test_counts": test_counts,
        "checks": checks,
        "findings": findings,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 1 if _has_blocking_findings(findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
