from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

from owner_research.fingerprints import canonical_sha256

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "write_phase4a_audit.py"
AUDIT_TOOL = "owner-research-phase4a-readonly"
AUDIT_VERSION = "1.1.0"


def _write_findings(path: Path, *, priority: str | None = None) -> None:
    findings = []
    if priority is not None:
        findings.append(
            {
                "finding_id": f"{priority}:test",
                "priority": priority,
                "check_id": "test",
                "summary": "Synthetic audit finding.",
                "evidence_sha256": "a" * 64,
            }
        )
    path.write_text(
        json.dumps(
            {
                "audit_tool": AUDIT_TOOL,
                "audit_version": AUDIT_VERSION,
                "reviewed_commit": "a" * 40,
                "checks": [{"check_id": "test", "status": "passed"}],
                "findings": findings,
            }
        ),
        encoding="utf-8",
    )


def test_phase4a_audit_manifest_has_canonical_self_hash(tmp_path: Path) -> None:
    output = tmp_path / "phase4a-audit.json"
    findings = tmp_path / "phase4a-findings.json"
    _write_findings(findings)
    subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--output",
            str(output),
            "--reviewed-commit",
            "a" * 40,
            "--started-at",
            "2026-07-11T00:00:00Z",
            "--ci-run-id",
            "12345",
            "--findings-file",
            str(findings),
        ],
        cwd=ROOT,
        check=True,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    report_sha256 = payload.pop("report_sha256")

    assert report_sha256 == canonical_sha256(payload)
    assert payload["finding_counts"] == {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    assert payload["ci_run_ids"] == ["12345"]


def test_phase4a_audit_manifest_derives_counts_without_zero_defaults(tmp_path: Path) -> None:
    for priority in ("P0", "P1", "P2", "P3"):
        findings = tmp_path / f"{priority}-findings.json"
        output = tmp_path / f"{priority}-audit.json"
        _write_findings(findings, priority=priority)
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--output",
                str(output),
                "--reviewed-commit",
                "a" * 40,
                "--started-at",
                "2026-07-11T00:00:00Z",
                "--findings-file",
                str(findings),
            ],
            cwd=ROOT,
            check=True,
        )
        counts = json.loads(output.read_text(encoding="utf-8"))["finding_counts"]
        assert counts[priority] == 1
        assert sum(counts.values()) == 1


def test_phase4a_audit_manifest_requires_machine_findings(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--output",
            str(tmp_path / "phase4a-audit.json"),
            "--reviewed-commit",
            "a" * 40,
            "--started-at",
            "2026-07-11T00:00:00Z",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "--findings-file" in result.stderr


def test_ci_runs_current_audit_in_no_remote_readonly_clone() -> None:
    workflow_path = ROOT / "legacy_governance" / "phase5e2b12a-acceptance-gate.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    job = workflow["jobs"]["phase5e-readonly-audit"]
    text = workflow_path.read_text(encoding="utf-8")
    launcher = (ROOT / "scripts/launch_phase5e_readonly_audit.sh").read_text(encoding="utf-8")

    assert job["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["phase5e-readonly-audit-comment"]["permissions"] == {
        "contents": "read",
        "pull-requests": "write",
    }
    assert "Remove remotes and unrelated Git identity before sandboxing" in text
    assert (
        'chmod -R a-w "$control_repo" "$candidate_repo" "$kernel_interface" "$venv"'
        in launcher
    )
    assert "unshare --mount --net --pid" in launcher
    assert "phase5e-audit.json" in text
    assert "run_phase5e_audit.py" in launcher
    assert "continue-on-error: true" in text
    assert (
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
        in text
    )
    assert "<!-- phase5e-protected-base-readonly-audit -->" in text
    assert "findings: P0=0" not in text
    assert "Enforce zero findings after durable evidence upload" in text
