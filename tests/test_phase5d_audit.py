from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

from owner_research.fingerprints import canonical_sha256
from scripts.run_phase5d_audit import STATIC_CONTROL_FILES, _has_blocking_findings

ROOT = Path(__file__).parents[1]
WRITER = ROOT / "scripts" / "write_phase5d_audit.py"


def _write_findings(path: Path, *, priority: str | None = None) -> None:
    findings = []
    if priority is not None:
        findings.append(
            {
                "finding_id": f"{priority}:synthetic",
                "priority": priority,
                "check_id": "synthetic",
                "summary": "Synthetic finding.",
                "evidence_sha256": "a" * 64,
            }
        )
    path.write_text(
        json.dumps(
            {
                "audit_tool": "owner-research-phase5d-readonly",
                "audit_version": "2.2.6",
                "reviewed_commit": "a" * 40,
                "phase5c_baseline_commit": "b" * 40,
                "valuation_kernel_commit": "c" * 40,
                "test_counts": {
                    "collected_tests": 700,
                    "passed_tests": 700,
                    "skipped_tests": 0,
                    "failed_tests": 0,
                },
                "audited_file_sha256": {"policy": "d" * 64},
                "checks": [{"check_id": "synthetic", "status": "passed"}],
                "findings": findings,
            }
        ),
        encoding="utf-8",
    )


def test_phase5d_audit_manifest_has_dynamic_counts_and_canonical_hash(tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    output = tmp_path / "phase5d-audit.json"
    _write_findings(findings, priority="P3")
    subprocess.run(
        [
            sys.executable,
            str(WRITER),
            "--output",
            str(output),
            "--reviewed-commit",
            "a" * 40,
            "--started-at",
            "2026-07-14T00:00:00Z",
            "--ci-run-id",
            "456",
            "--findings-file",
            str(findings),
        ],
        cwd=ROOT,
        check=False,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    report_hash = payload.pop("report_sha256")
    assert report_hash == canonical_sha256(payload)
    assert payload["finding_counts"] == {"P0": 0, "P1": 0, "P2": 0, "P3": 1}
    assert payload["test_counts"]["collected_tests"] == 700
    assert payload["ci_run_ids"] == ["456"]


def test_all_phase5d_finding_priorities_block_acceptance() -> None:
    for priority in ("P0", "P1", "P2", "P3"):
        assert _has_blocking_findings(({"priority": priority},))
    assert not _has_blocking_findings(())


def test_phase5d_ci_permissions_and_isolation_are_enforced() -> None:
    path = ROOT / "legacy_governance" / "phase5e2b12a-acceptance-gate.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    job = workflow["jobs"]["phase5e-readonly-audit"]
    comment_job = workflow["jobs"]["phase5e-readonly-audit-comment"]
    text = path.read_text(encoding="utf-8")
    launcher = (ROOT / "scripts/launch_phase5e_readonly_audit.sh").read_text(encoding="utf-8")
    assert job["permissions"] == {"contents": "read"}
    assert comment_job["permissions"] == {"contents": "read", "pull-requests": "write"}
    assert comment_job["needs"] == "phase5e-readonly-audit"
    assert "Remove remotes and unrelated Git identity before sandboxing" in text
    assert "unshare --mount --net --pid" in launcher
    assert 'for readonly_tree in "$1" "$2" "$3" "$4"' in launcher
    assert 'mount -o remount,ro,bind "$readonly_tree"' in launcher
    assert "run_phase5e_audit.py" in launcher
    assert "verify_phase5e_audit_runtime_matrix.py" in text
    assert 'any(manifest["finding_counts"].values())' in text


def test_phase5d_audit_hashes_changed_paths_and_static_controls() -> None:
    required = {
        ".github/workflows/ci.yml",
        "AGENTS.md",
        "component-lock.json",
        "schemas/valuation-assumption-candidate.schema.json",
        "schemas/valuation-handoff.schema.json",
        "scripts/run_phase5d_audit.py",
        "scripts/write_phase5d_audit.py",
        "scripts/verify_phase5d0_policies.py",
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
        "src/owner_research/valuation_assumption_types.py",
        "src/owner_research/valuation_assumption_candidates.py",
        "src/owner_research/valuation_assumption_ledger.py",
        "src/owner_research/valuation_mckinsey_inputs.py",
        "src/owner_research/valuation_penman_inputs.py",
        "src/owner_research/valuation_price_blind_freeze.py",
        "src/owner_research/valuation_handoff_validation.py",
    }
    assert required.issubset(STATIC_CONTROL_FILES)
    source = (ROOT / "scripts" / "run_phase5d_audit.py").read_text(encoding="utf-8")
    assert '"diff",' in source
    assert '"--name-only",' in source
    assert "changed_files | STATIC_CONTROL_FILES" in source
