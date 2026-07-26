from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from owner_research.fingerprints import canonical_sha256
from scripts.run_phase5c_audit import STATIC_CONTROL_FILES, _has_blocking_findings
from scripts.verify_phase5c_policies import (
    ALLOWED_PHASE5C_SOURCE_CHANGES,
    _expected_phase5c_init,
    _parse_name_status,
    _validate_source_change_set,
)

ROOT = Path(__file__).parents[1]
WRITER = ROOT / "scripts" / "write_phase5c_audit.py"


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
                "audit_tool": "owner-research-phase5c-readonly",
                "audit_version": "2.1.5.1",
                "reviewed_commit": "a" * 40,
                "phase5b_merge_commit": "b" * 40,
                "valuation_kernel_commit": "c" * 40,
                "test_counts": {
                    "collected_tests": 541,
                    "passed_tests": 541,
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


def test_phase5c_audit_manifest_has_dynamic_counts_and_canonical_hash(tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    output = tmp_path / "phase5c-audit.json"
    _write_findings(findings, priority="P2")
    subprocess.run(
        [
            sys.executable,
            str(WRITER),
            "--output",
            str(output),
            "--reviewed-commit",
            "a" * 40,
            "--started-at",
            "2026-07-13T00:00:00Z",
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
    assert payload["finding_counts"] == {"P0": 0, "P1": 0, "P2": 1, "P3": 0}
    assert payload["test_counts"]["collected_tests"] == 541
    assert payload["ci_run_ids"] == ["123"]


def test_all_phase5c_finding_priorities_block_acceptance() -> None:
    for priority in ("P0", "P1", "P2", "P3"):
        assert _has_blocking_findings(({"priority": priority},))
    assert not _has_blocking_findings(())


def test_ci_runs_current_readonly_audit_on_pr_and_main_with_split_permissions() -> None:
    path = ROOT / ".github" / "workflows" / "phase5e2b12a-acceptance-gate.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    job = workflow["jobs"]["phase5e-readonly-audit"]
    comment_job = workflow["jobs"]["phase5e-readonly-audit-comment"]
    text = path.read_text(encoding="utf-8")
    assert job["permissions"] == {"contents": "read"}
    identity_job = workflow["jobs"]["resolve-audit-identity"]
    assert "github.event.workflow_run.head_branch == 'main'" in identity_job["if"]
    assert "resolve-audit-identity" in job["needs"]
    assert comment_job["permissions"] == {
        "contents": "read",
        "pull-requests": "write",
    }
    assert comment_job["needs"] == "phase5e-readonly-audit"
    assert "Resolve reviewed and prior protected controller commits" in text
    assert "Remove remotes and unrelated Git identity before sandboxing" in text
    launcher = (ROOT / "scripts/launch_phase5e_readonly_audit.sh").read_text(encoding="utf-8")
    assert "unshare --mount --net --pid" in launcher
    assert 'for readonly_tree in "$1" "$2" "$3" "$4"' in launcher
    assert 'mount -o remount,ro,bind "$readonly_tree"' in launcher
    assert "run_phase5e_audit.py" in launcher
    assert "verify_phase5e_audit_runtime_matrix.py" in text
    assert "<!-- phase5e-protected-base-readonly-audit -->" in text
    assert "for priority in P0 P1 P2 P3" in text
    assert 'any(manifest["finding_counts"].values())' in text


def test_phase5c_audit_hashes_changed_paths_and_static_controls() -> None:
    required = {
        ".github/workflows/ci.yml",
        "README.md",
        "docs/architecture.md",
        "scripts/verify_phase_state.py",
        "scripts/run_phase5c_audit.py",
        "scripts/write_phase5c_audit.py",
        "src/owner_research/__init__.py",
        "src/owner_research/valuation_accounting_quality.py",
        "src/owner_research/valuation_accounting_reconciliation.py",
        "src/owner_research/valuation_method_views.py",
        "src/owner_research/valuation_equity_bridge.py",
        "component-lock.json",
        "plugins/owner-equity-research/.codex-plugin/plugin.json",
        "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md",
        "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md",
    }
    assert required.issubset(STATIC_CONTROL_FILES)
    source = (ROOT / "scripts" / "run_phase5c_audit.py").read_text(encoding="utf-8")
    assert '"diff",' in source
    assert '"--name-only",' in source
    assert "changed_files | STATIC_CONTROL_FILES" in source


def test_phase5c_source_change_allowlist_rejects_all_other_mutations() -> None:
    valid_text = "\n".join(
        f"{status}\t{path}" for status, path in sorted(ALLOWED_PHASE5C_SOURCE_CHANGES)
    )
    _validate_source_change_set(_parse_name_status(valid_text))
    for extra in (
        ("M", "src/owner_research/contracts.py"),
        ("D", "src/owner_research/valuation_fact_mapping.py"),
        ("A", "src/owner_research/phase5c_compiler.py"),
    ):
        with pytest.raises(ValueError, match="authorized compiler boundary"):
            _validate_source_change_set(ALLOWED_PHASE5C_SOURCE_CHANGES | {extra})
    with pytest.raises(ValueError, match="unsupported status"):
        _parse_name_status("R100\tsrc/owner_research/a.py\tsrc/owner_research/b.py")


def test_phase5c_package_root_allows_only_the_version_bump() -> None:
    baseline = '__version__ = "0.5.0.dev2"\nPUBLIC = ()\n'
    assert _expected_phase5c_init(baseline) == ('__version__ = "0.5.0.dev3"\nPUBLIC = ()\n')
    with pytest.raises(ValueError, match="not uniquely reproducible"):
        _expected_phase5c_init("PUBLIC = ()\n")
