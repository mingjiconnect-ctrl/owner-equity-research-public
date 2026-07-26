from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

from owner_research.fingerprints import canonical_sha256

ROOT = Path(__file__).parents[1]
WRITER = ROOT / "scripts" / "write_phase4d_audit.py"


def _findings(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "audit_tool": "owner-research-phase4e2-readonly",
                "audit_version": "1.7.2",
                "reviewed_commit": "a" * 40,
                "test_counts": {
                    "collected_tests": 228,
                    "passed_tests": 228,
                    "skipped_tests": 0,
                    "failed_tests": 0,
                },
                "checks": [{"check_id": "tests", "status": "passed"}],
                "findings": [],
            }
        ),
        encoding="utf-8",
    )


def test_phase4e2_audit_manifest_records_machine_test_counts(tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    output = tmp_path / "phase4e2-audit.json"
    _findings(findings)
    subprocess.run(
        [
            sys.executable,
            str(WRITER),
            "--output",
            str(output),
            "--reviewed-commit",
            "a" * 40,
            "--started-at",
            "2026-07-12T00:00:00Z",
            "--ci-run-id",
            "123",
            "--findings-file",
            str(findings),
        ],
        cwd=ROOT,
        check=True,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    report_hash = payload.pop("report_sha256")
    assert report_hash == canonical_sha256(payload)
    assert payload["test_counts"]["collected_tests"] == 228
    assert payload["finding_counts"] == {"P0": 0, "P1": 0, "P2": 0, "P3": 0}


def test_ci_uses_current_readonly_audit_and_dynamic_counts() -> None:
    path = ROOT / ".github" / "workflows" / "phase5e2b12a-acceptance-gate.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    job = workflow["jobs"]["phase5e-readonly-audit"]
    text = path.read_text(encoding="utf-8")
    launcher = (ROOT / "scripts/launch_phase5e_readonly_audit.sh").read_text(
        encoding="utf-8"
    )
    assert job["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["phase5e-readonly-audit-comment"]["permissions"] == {
        "contents": "read",
        "pull-requests": "write",
    }
    assert "Remove remotes and unrelated Git identity before sandboxing" in text
    assert 'for readonly_tree in "$1" "$2" "$3" "$4"' in launcher
    assert 'mount -o remount,ro,bind "$readonly_tree"' in launcher
    assert "run_phase5e_audit.py" in launcher
    assert "verify_phase5e_audit_runtime_matrix.py" in text
    assert "collected_tests" in text
    assert "<!-- phase5e-protected-base-readonly-audit -->" in text
