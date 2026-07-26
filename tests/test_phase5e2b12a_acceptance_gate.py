from __future__ import annotations

import copy
import hashlib
import io
import json
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import pytest

import scripts.verify_phase5e2b12a_acceptance_gate as acceptance_gate
from scripts.run_phase5e_audit import EXPECTED_AUDIT_CHECK_IDS
from scripts.verify_phase5e2b12a_acceptance_gate import (
    ACCEPTED_PROHIBITED,
    AUDIT_TOOL,
    AUDIT_VERSION,
    EXPECTED_NODEID_SHA256,
    EXPECTED_PROHIBITED,
    EXPECTED_TEST_COUNT,
    PENDING_ACCEPTANCE_TRUST_ROOT,
    PERMANENT_ACCEPTED_TRUST_ROOT,
    REQUIRED_AUDITED_PATHS,
    verify_acceptance,
    verify_non_acceptance_pr,
)

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_SLUG = "owner/research"
ONE_NODEID_BYTES = b"tests/test_one.py::test_one\n"
ONE_NODEID_SHA256 = hashlib.sha256(ONE_NODEID_BYTES).hexdigest()
ONE_JUNIT_BYTES = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<testsuites name="pytest tests"><testsuite name="pytest" tests="1" '
    b'failures="0" errors="0" skipped="0" time="0.001" '
    b'timestamp="2026-07-16T00:00:00.000000+00:00" hostname="audit">'
    b'<testcase classname="tests.test_one" name="test_one" time="0.001">'
    b'<properties><property name="phase5e_nodeid" '
    b'value="tests/test_one.py::test_one"/></properties></testcase></testsuite>'
    b"</testsuites>"
)


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args],
        text=True,
    ).strip()


def _commit(repository: Path, message: str) -> str:
    subprocess.run(["git", "-C", str(repository), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-m", message],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return _git(repository, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> tuple[Path, str, str, str]:
    """Create a merged implementation plus an uncommitted two-file acceptance tree."""

    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(["git", "-C", str(repository), "init", "-b", "main"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "audit@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Audit Fixture"],
        check=True,
    )
    (repository / "docs").mkdir()
    (repository / "src").mkdir()
    for path in sorted(REQUIRED_AUDITED_PATHS):
        target = repository / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"fixture:{path}\n", encoding="utf-8")
    (repository / "docs/phase-status.json").write_text(
        json.dumps(
            {
                "current_phase": "Phase 5E-2B.1",
                "status": "implementation_complete_pending_acceptance",
                "authorized_next": list(acceptance_gate.PENDING_AUTHORIZED_NEXT),
                "prohibited": list(EXPECTED_PROHIBITED),
                "release_tag": None,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (repository / "src/frozen.py").write_text("VALUE = 1\n", encoding="utf-8")
    root_commit = _commit(repository, "root")
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", "implementation"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    (repository / "src/frozen.py").write_text("VALUE = 2\n", encoding="utf-8")
    implementation_head = _commit(repository, "implementation")
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "main"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge",
            "--no-ff",
            "implementation",
            "-m",
            "merge implementation",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    implementation_merge = _git(repository, "rev-parse", "HEAD")
    assert _git(repository, "rev-parse", f"{implementation_merge}^2") == implementation_head
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", "acceptance"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    status = {
        "current_phase": "Phase 5E-2B.1-2A",
        "status": "accepted_closed",
        "authorized_next": list(acceptance_gate.ACCEPTED_AUTHORIZED_NEXT),
        "prohibited": list(ACCEPTED_PROHIBITED),
        "release_tag": None,
    }
    (repository / "docs/phase-status.json").write_text(
        json.dumps(status, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    closeout = {
        "schema_version": "1.0.0",
        "phase": "Phase 5E-2B.1-2A",
        "implementation_pull_request": 76,
        "implementation_head_commit": implementation_head,
        "implementation_merge_commit": implementation_merge,
        "implementation_tree_sha": _git(
            repository,
            "rev-parse",
            f"{implementation_merge}^{{tree}}",
        ),
        "acceptance_pull_request": 77,
        "pr_ci_run_id": "1001",
        "main_ci_run_id": "1002",
        "audit_workflow_id": 456,
        "controller_app_id": 98765,
        "controller_app_slug": "phase5e-controller",
        "controller_installation_id": 54321,
        "audit_tool": AUDIT_TOOL,
        "audit_profile": acceptance_gate.PHASE5E2B12A_AUDIT_PROFILE,
        "audit_version": AUDIT_VERSION,
        "audit_report_sha256": "a" * 64,
        "audit_artifact_sha256": "b" * 64,
        "test_inventory_sha256": EXPECTED_NODEID_SHA256,
        "runtime_matrix_sha256": "c" * 64,
        "audit_wheelhouse_manifest_sha256": "d" * 64,
        "test_count": EXPECTED_TEST_COUNT,
    }
    (repository / "docs/phase5e2b12a-acceptance-closeout.json").write_text(
        json.dumps(closeout, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return repository, root_commit, implementation_head, implementation_merge


def _event(
    *,
    base: str,
    head: str,
    base_ref: str = "main",
    slug: str = REPOSITORY_SLUG,
    head_ref: str = "feature/phase5e2b12a-acceptance-closeout",
) -> dict[str, Any]:
    return {
        "number": 77,
        "repository": {"full_name": slug},
        "pull_request": {
            "base": {
                "sha": base,
                "ref": base_ref,
                "repo": {"full_name": slug},
            },
            "head": {
                "sha": head,
                "ref": head_ref,
                "repo": {"full_name": slug},
            },
        },
    }


def _write_closeout(repository: Path, updates: dict[str, Any]) -> None:
    path = repository / "docs/phase5e2b12a-acceptance-closeout.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.update(updates)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _controller_status_fixture(
    *,
    head_sha: str,
    workflow_run_id: str,
    start_id: int = 1,
    app_slug: str = "phase5e-controller",
) -> list[dict[str, Any]]:
    target = f"https://github.com/{REPOSITORY_SLUG}/actions/runs/{workflow_run_id}"
    statuses = [
        {
            "id": index,
            "sha": head_sha,
            "context": context,
            "state": "success",
            "target_url": target,
            "creator": {"login": f"{app_slug}[bot]", "type": "Bot"},
        }
        for index, context in enumerate(
            sorted(acceptance_gate.CONTROLLER_APP_CHECKS),
            start=start_id,
        )
    ]
    statuses.append(
        {
            "id": start_id + len(statuses),
            "sha": head_sha,
            "context": "phase5e/actions-status-token-revoked",
            "state": "success",
            "target_url": target,
            "creator": {"login": "github-actions[bot]", "type": "Bot"},
        }
    )
    return statuses


def _remote_evidence(
    *,
    repository: Path,
    root_commit: str,
    implementation_head: str,
    implementation_merge: str,
    monkeypatch: pytest.MonkeyPatch,
    check_mode: str = "valid",
    omit_member: str | None = None,
    omit_audited_path: bool = False,
    run_mutation: tuple[str, Any] | None = None,
    pull_request_mutation: tuple[str, Any] | None = None,
    workflow_mutation: tuple[str, Any] | None = None,
    authority_mode: str = "valid",
    junit_bytes: bytes = ONE_JUNIT_BYTES,
    artifact_json_mode: str = "canonical",
    archive_prefix: str = "",
    artifact_total_count: int = 1,
) -> str:
    """Bind exact four-file evidence, commit acceptance once, and install a fake API."""

    monkeypatch.setattr(acceptance_gate, "PHASE5D_BASELINE", root_commit)
    monkeypatch.setattr(acceptance_gate, "CONTROLLER_AUTHORITY_STATUS", "pinned")
    monkeypatch.setattr(acceptance_gate, "PINNED_CONTROLLER_APP_ID", 98765)
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_CONTROLLER_APP_SLUG",
        "phase5e-controller",
    )
    monkeypatch.setattr(acceptance_gate, "PINNED_CONTROLLER_INSTALLATION_ID", 54321)
    monkeypatch.setattr(acceptance_gate, "KERNEL_READER_AUTHORITY_STATUS", "pinned")
    monkeypatch.setattr(acceptance_gate, "PINNED_KERNEL_READER_APP_ID", 24680)
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_KERNEL_READER_APP_SLUG",
        "phase5e-kernel-reader",
    )
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_KERNEL_READER_INSTALLATION_ID",
        13579,
    )
    monkeypatch.setattr(acceptance_gate, "EXTERNAL_GATE_AUTHORITY_STATUS", "pinned")
    monkeypatch.setattr(acceptance_gate, "PINNED_EXTERNAL_GATE_AUTHOR_APP_ID", 11223)
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG",
        "phase5e-gate-author",
    )
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_EXTERNAL_GATE_AUTHOR_INSTALLATION_ID",
        44556,
    )
    monkeypatch.setattr(
        acceptance_gate,
        "STATIC_CONTROL_FILES",
        frozenset(REQUIRED_AUDITED_PATHS),
    )
    monkeypatch.setattr(acceptance_gate, "EXPECTED_TEST_COUNT", 1)
    monkeypatch.setattr(acceptance_gate, "EXPECTED_NODEID_SHA256", ONE_NODEID_SHA256)
    baseline_fields = {
        "phase5d_baseline_commit": root_commit,
        "phase5e0_baseline_commit": acceptance_gate.PHASE5E0_BASELINE,
        "phase5e11_baseline_commit": acceptance_gate.PHASE5E11_BASELINE,
        "phase5e2a_baseline_commit": acceptance_gate.PHASE5E2A_BASELINE,
        "phase5e2b10_baseline_commit": acceptance_gate.PHASE5E2B10_BASELINE,
        "phase5e2b11_baseline_commit": acceptance_gate.PHASE5E2B11_BASELINE,
        "valuation_kernel_commit": acceptance_gate.KERNEL_BASELINE,
    }
    monkeypatch.setattr(acceptance_gate, "EXPECTED_BASELINE_FIELDS", baseline_fields)

    expected_paths = set(REQUIRED_AUDITED_PATHS) | {"src/frozen.py"}
    if omit_audited_path:
        expected_paths.remove("src/frozen.py")
    audited_hashes = {
        path: hashlib.sha256(
            subprocess.check_output(
                ["git", "-C", str(repository), "show", f"{implementation_merge}:{path}"]
            )
        ).hexdigest()
        for path in sorted(expected_paths)
    }
    test_counts = {
        "collected_tests": 1,
        "passed_tests": 1,
        "skipped_tests": 0,
        "failed_tests": 0,
        "nodeid_sha256": ONE_NODEID_SHA256,
        "junit_sha256": hashlib.sha256(junit_bytes).hexdigest(),
    }
    checks = [
        {
            "check_id": check_id,
            "status": "passed",
            "evidence": check_id,
            "evidence_sha256": hashlib.sha256(check_id.encode()).hexdigest(),
        }
        for check_id in sorted(EXPECTED_AUDIT_CHECK_IDS)
    ]
    if check_mode == "missing":
        checks.pop()
    elif check_mode == "duplicate":
        checks[-1] = dict(checks[0])
    elif check_mode == "forged_evidence":
        checks[-1] = {**checks[-1], "evidence": "forged evidence payload"}
    findings = {
        "audit_tool": AUDIT_TOOL,
        "audit_version": AUDIT_VERSION,
        "reviewed_commit": implementation_merge,
        **baseline_fields,
        "started_at": "2026-07-16T00:00:00Z",
        "finished_at": "2026-07-16T00:01:00Z",
        "test_counts": test_counts,
        "audited_file_sha256": audited_hashes,
        "checks": checks,
        "findings": [],
    }
    if artifact_json_mode == "unknown_findings_field":
        findings["attacker"] = "unknown"
    elif artifact_json_mode == "boolean_test_count":
        test_counts["failed_tests"] = False
    elif artifact_json_mode == "floating_test_count":
        test_counts["collected_tests"] = 1.0
    findings_bytes = (json.dumps(findings, indent=2, sort_keys=True) + "\n").encode()
    if artifact_json_mode == "duplicate_findings_key":
        findings_bytes = b'{"audit_tool":"forged",' + findings_bytes[1:]
    elif artifact_json_mode == "nonfinite_findings_json":
        findings_bytes = b'{\n  "attacker": NaN,\n' + findings_bytes[2:]
    report = {
        "audit_tool": AUDIT_TOOL,
        "audit_version": AUDIT_VERSION,
        "reviewed_commit": implementation_merge,
        **baseline_fields,
        "started_at": "2026-07-16T00:00:00Z",
        "finished_at": "2026-07-16T00:02:00Z",
        "finding_counts": {priority: 0 for priority in ("P0", "P1", "P2", "P3")},
        "test_counts": test_counts,
        "audited_file_sha256": audited_hashes,
        "ci_run_ids": ["1002"],
        "check_count": len(EXPECTED_AUDIT_CHECK_IDS),
        "audit_evidence_sha256": hashlib.sha256(findings_bytes).hexdigest(),
    }
    if artifact_json_mode == "unknown_report_field":
        report["attacker"] = "unknown"
    elif artifact_json_mode == "boolean_finding_count":
        report["finding_counts"]["P0"] = False
    elif artifact_json_mode == "nonlist_ci_run_ids":
        report["ci_run_ids"] = "1002"
    report["report_sha256"] = hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    if artifact_json_mode == "duplicate_report_key":
        report_bytes = b'{"audit_tool":"forged",' + report_bytes[1:]
    elif artifact_json_mode == "compact_report":
        report_bytes = (json.dumps(report, sort_keys=True) + "\n").encode()
    elif artifact_json_mode == "nonfinite_report_json":
        report_bytes = b'{\n  "attacker": Infinity,\n' + report_bytes[2:]
    elif artifact_json_mode == "overflow_report_json":
        report_bytes = b'{\n  "attacker": 1e400,\n' + report_bytes[2:]
    evidence = {
        "phase5e-audit.json": report_bytes,
        "phase5e-findings.json": findings_bytes,
        "phase5e-independent.xml": junit_bytes,
        "phase5e-nodeids.txt": ONE_NODEID_BYTES,
    }
    _write_closeout(
        repository,
        {
            "audit_report_sha256": report["report_sha256"],
            "audit_artifact_sha256": hashlib.sha256(report_bytes).hexdigest(),
            "audit_findings_sha256": hashlib.sha256(findings_bytes).hexdigest(),
            "audit_junit_sha256": hashlib.sha256(junit_bytes).hexdigest(),
            "audit_nodeids_sha256": ONE_NODEID_SHA256,
            "test_count": 1,
            "test_nodeid_sha256": ONE_NODEID_SHA256,
        },
    )
    acceptance_head = _commit(repository, "acceptance")
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        for name, raw in evidence.items():
            if name != omit_member:
                bundle.writestr(f"{archive_prefix}{name}", raw)

    def fake_api_json(url: str, token: str) -> dict[str, Any]:
        assert token == "token"
        if url == f"https://api.github.com/repos/{REPOSITORY_SLUG}":
            return {
                "private": True,
                "allow_merge_commit": True,
                "allow_squash_merge": False,
                "allow_rebase_merge": False,
            }
        environment_base = f"https://api.github.com/repos/{REPOSITORY_SLUG}/environments"
        controller_environment = (
            f"{environment_base}/{acceptance_gate.CONTROLLER_ENVIRONMENT_NAME}"
        )
        kernel_environment = f"{environment_base}/{acceptance_gate.KERNEL_ENVIRONMENT_NAME}"
        gate_environment = (
            f"{environment_base}/{acceptance_gate.EXTERNAL_GATE_AUTHOR_ENVIRONMENT}"
        )
        if url == environment_base:
            environments = [
                {"id": 1, "name": acceptance_gate.CONTROLLER_ENVIRONMENT_NAME},
                {"id": 2, "name": acceptance_gate.KERNEL_ENVIRONMENT_NAME},
                {"id": 3, "name": acceptance_gate.EXTERNAL_GATE_AUTHOR_ENVIRONMENT},
            ]
            if authority_mode == "missing_kernel_environment":
                environments = [environments[0], environments[2]]
            return {"total_count": len(environments), "environments": environments}
        if url in {controller_environment, kernel_environment, gate_environment}:
            environment_name = url.rsplit("/", 1)[-1]
            deployment_policy = {
                "protected_branches": False,
                "custom_branch_policies": True,
            }
            if authority_mode == "unrestricted_environment" and url == controller_environment:
                deployment_policy = {
                    "protected_branches": False,
                    "custom_branch_policies": False,
                }
            return {
                "id": (
                    1
                    if url == controller_environment
                    else (2 if url == kernel_environment else 3)
                ),
                "name": environment_name,
                "protection_rules": [{"id": 3, "type": "branch_policy"}],
                "deployment_branch_policy": deployment_policy,
            }
        if url in {
            f"{controller_environment}/deployment-branch-policies",
            f"{kernel_environment}/deployment-branch-policies",
            f"{gate_environment}/deployment-branch-policies",
        }:
            policy_name = (
                "feature/*"
                if authority_mode == "wrong_environment_branch"
                and url.startswith(controller_environment)
                else "main"
            )
            return {
                "total_count": 1,
                "branch_policies": [{"id": 4, "name": policy_name, "type": "branch"}],
            }
        if url == f"https://api.github.com/repos/{REPOSITORY_SLUG}/actions/secrets":
            secrets: list[dict[str, str]] = []
            if authority_mode == "repository_kernel_secret":
                secrets.append({"name": acceptance_gate.KERNEL_READER_PRIVATE_KEY_SECRET})
            if authority_mode == "repository_controller_secret":
                secrets.append({"name": acceptance_gate.CONTROLLER_PRIVATE_KEY_SECRET})
            return {"total_count": len(secrets), "secrets": secrets}
        if url == f"https://api.github.com/repos/{REPOSITORY_SLUG}/actions/variables":
            variables: list[dict[str, str]] = []
            if authority_mode == "repository_controller_variable":
                variables.append(
                    {"name": acceptance_gate.CONTROLLER_APP_ID_VARIABLE, "value": "98765"}
                )
            return {"total_count": len(variables), "variables": variables}
        if url == f"{controller_environment}/secrets":
            secrets = (
                []
                if authority_mode == "missing_controller_secret"
                else [{"name": acceptance_gate.CONTROLLER_PRIVATE_KEY_SECRET}]
            )
            return {"total_count": len(secrets), "secrets": secrets}
        if url == f"{controller_environment}/variables":
            variables = (
                []
                if authority_mode == "missing_controller_variable"
                else [
                    {"name": acceptance_gate.CONTROLLER_APP_ID_VARIABLE, "value": "98765"}
                ]
            )
            return {"total_count": len(variables), "variables": variables}
        if url == f"{kernel_environment}/secrets":
            secrets = (
                []
                if authority_mode == "missing_kernel_secret"
                else [{"name": acceptance_gate.KERNEL_READER_PRIVATE_KEY_SECRET}]
            )
            return {"total_count": len(secrets), "secrets": secrets}
        if url == f"{kernel_environment}/variables":
            variables = (
                []
                if authority_mode == "missing_kernel_variable"
                else [
                    {
                        "name": acceptance_gate.KERNEL_READER_APP_ID_VARIABLE,
                        "value": "24680",
                    }
                ]
            )
            return {"total_count": len(variables), "variables": variables}
        if url.endswith("/branches/main/protection"):
            return {
                "required_status_checks": {
                    "strict": True,
                    "contexts": list(acceptance_gate.REQUIRED_PROTECTION_CONTEXT_MARKERS),
                    "checks": [],
                },
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews": True,
                    "require_last_push_approval": True,
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
                "required_conversation_resolution": {"enabled": True},
            }
        if url.endswith("/actions/runs/1001"):
            payload: dict[str, Any] = {
                "head_sha": implementation_head,
                "head_branch": "implementation",
                "event": "pull_request",
                "conclusion": "success",
                "name": "owner-research-ci",
                "path": ".github/workflows/ci.yml",
                "workflow_id": 123,
                "repository": {"full_name": REPOSITORY_SLUG},
                "head_repository": {"full_name": REPOSITORY_SLUG},
                "pull_requests": [
                    {
                        "number": 76,
                        "head": {"sha": implementation_head, "ref": "implementation"},
                        "base": {"sha": root_commit, "ref": "main"},
                    }
                ],
            }
            if run_mutation:
                payload[run_mutation[0]] = run_mutation[1]
            return payload
        if url.endswith("/actions/workflows/123"):
            payload = {
                "id": 123,
                "path": ".github/workflows/ci.yml",
                "name": "owner-research-ci",
                "state": "active",
            }
            if workflow_mutation:
                payload[workflow_mutation[0]] = workflow_mutation[1]
            return payload
        if url.endswith("/pulls/76"):
            payload = {
                "number": 76,
                "state": "closed",
                "merged": True,
                "merged_at": "2026-07-16T00:00:00Z",
                "merge_commit_sha": implementation_merge,
                "base": {
                    "sha": root_commit,
                    "ref": "main",
                    "repo": {"full_name": REPOSITORY_SLUG},
                },
                "head": {
                    "sha": implementation_head,
                    "ref": "implementation",
                    "repo": {"full_name": REPOSITORY_SLUG},
                },
            }
            if pull_request_mutation:
                payload[pull_request_mutation[0]] = pull_request_mutation[1]
            return payload
        if url.endswith("/actions/runs/1002"):
            return {
                "head_sha": implementation_merge,
                "head_branch": "main",
                "event": "push",
                "conclusion": "success",
                "name": "owner-research-ci",
                "path": ".github/workflows/ci.yml",
                "workflow_id": 123,
                "repository": {"full_name": REPOSITORY_SLUG},
                "head_repository": {"full_name": REPOSITORY_SLUG},
            }
        if "/actions/runs/1002/artifacts?" in url:
            return {
                "total_count": artifact_total_count,
                "artifacts": [
                    {
                        "id": 3001,
                        "name": f"phase5e-audit-{implementation_merge}",
                        "expired": False,
                        "archive_download_url": "https://example.invalid/audit.zip",
                    }
                ],
            }
        raise AssertionError(url)

    monkeypatch.setattr(acceptance_gate, "_api_json", fake_api_json)
    monkeypatch.setattr(
        acceptance_gate,
        "_api_bytes",
        lambda url, token: archive.getvalue(),
    )
    return acceptance_head


# This definition intentionally replaces the historical four-member artifact fixture above.  The
# protected controller now publishes one sanitized three-runtime manifest; raw findings, JUnit,
# and node-id inventories never cross the root-owned audit boundary.
def _remote_evidence(  # noqa: F811
    *,
    repository: Path,
    root_commit: str,
    implementation_head: str,
    implementation_merge: str,
    monkeypatch: pytest.MonkeyPatch,
    report_mode: str = "canonical",
    omit_audited_path: bool = False,
    run_mutation: tuple[str, Any] | None = None,
    pull_request_mutation: tuple[str, Any] | None = None,
    workflow_mutation: tuple[str, Any] | None = None,
    authority_mode: str = "valid",
    archive_prefix: str = "",
    artifact_total_count: int = 1,
    **legacy: Any,
) -> str:
    if legacy:
        raise AssertionError(f"obsolete remote-evidence fixture arguments: {sorted(legacy)}")
    monkeypatch.setattr(acceptance_gate, "PHASE5D_BASELINE", root_commit)
    monkeypatch.setattr(acceptance_gate, "CONTROLLER_AUTHORITY_STATUS", "pinned")
    monkeypatch.setattr(acceptance_gate, "PINNED_CONTROLLER_APP_ID", 98765)
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_CONTROLLER_APP_SLUG",
        "phase5e-controller",
    )
    monkeypatch.setattr(acceptance_gate, "PINNED_CONTROLLER_INSTALLATION_ID", 54321)
    monkeypatch.setattr(acceptance_gate, "KERNEL_READER_AUTHORITY_STATUS", "pinned")
    monkeypatch.setattr(acceptance_gate, "PINNED_KERNEL_READER_APP_ID", 24680)
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_KERNEL_READER_APP_SLUG",
        "phase5e-kernel-reader",
    )
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_KERNEL_READER_INSTALLATION_ID",
        13579,
    )
    monkeypatch.setattr(acceptance_gate, "EXTERNAL_GATE_AUTHORITY_STATUS", "pinned")
    monkeypatch.setattr(acceptance_gate, "PINNED_EXTERNAL_GATE_AUTHOR_APP_ID", 11223)
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG",
        "phase5e-gate-author",
    )
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_EXTERNAL_GATE_AUTHOR_INSTALLATION_ID",
        44556,
    )
    monkeypatch.setattr(
        acceptance_gate,
        "STATIC_CONTROL_FILES",
        frozenset(REQUIRED_AUDITED_PATHS),
    )
    baseline_fields = {
        "phase5d_baseline_commit": root_commit,
        "phase5e0_baseline_commit": acceptance_gate.PHASE5E0_BASELINE,
        "phase5e11_baseline_commit": acceptance_gate.PHASE5E11_BASELINE,
        "phase5e2a_baseline_commit": acceptance_gate.PHASE5E2A_BASELINE,
        "phase5e2b10_baseline_commit": acceptance_gate.PHASE5E2B10_BASELINE,
        "phase5e2b11_baseline_commit": acceptance_gate.PHASE5E2B11_BASELINE,
        "valuation_kernel_commit": acceptance_gate.KERNEL_BASELINE,
    }
    monkeypatch.setattr(acceptance_gate, "EXPECTED_BASELINE_FIELDS", baseline_fields)

    expected_paths = set(REQUIRED_AUDITED_PATHS) | {"src/frozen.py"}
    if omit_audited_path:
        expected_paths.remove("src/frozen.py")
    check_ids = tuple(sorted(EXPECTED_AUDIT_CHECK_IDS))
    test_counts = {
        "collected_tests": EXPECTED_TEST_COUNT,
        "passed_tests": EXPECTED_TEST_COUNT,
        "skipped_tests": 0,
        "failed_tests": 0,
    }
    finding_counts = {priority: 0 for priority in ("P0", "P1", "P2", "P3")}
    trust_paths = {
        "workflow_sha256": ".github/workflows/phase5e2b12a-acceptance-gate.yml",
        "audit_controller_sha256": "scripts/run_phase5e_audit.py",
        "launcher_sha256": "scripts/launch_phase5e_readonly_audit.sh",
        "candidate_executor_sha256": "scripts/phase5e_candidate_exec.sh",
        "semantic_oracle_sha256": "scripts/verify_phase5e2b12a_semantic_oracle.py",
        "audit_profile_registry_sha256": "scripts/phase5e_audit_profiles.py",
        "requirements_lock_sha256": "scripts/phase5e-audit-requirements.lock",
        "runtime_matrix_sha256": "scripts/phase5e-audit-runtime-matrix.json",
        "runtime_matrix_oracle_sha256": "scripts/verify_phase5e_audit_runtime_matrix.py",
        "audit_wheelhouse_manifest_sha256": "scripts/phase5e-audit-wheelhouse.sha256",
    }
    trust = {
        "controller_commit": root_commit,
        "controller_tree": _git(repository, "rev-parse", f"{root_commit}^{{tree}}"),
        "candidate_tree": "",
        **{
            field: hashlib.sha256(
                subprocess.check_output(
                    ["git", "-C", str(repository), "show", f"{root_commit}:{path}"]
                )
            ).hexdigest()
            for field, path in trust_paths.items()
        },
        "kernel_interface_sha256": "a" * 64,
        "control_oracle_tree_sha256": "b" * 64,
        "sandbox_profile": "linux-root-controller-net-pid-v2",
    }
    protected_profile = acceptance_gate.audit_profile(
        acceptance_gate.PHASE5E2B12A_AUDIT_PROFILE
    )
    trust["audit_profile_context_sha256"] = (
        acceptance_gate.audit_profile_context_sha256(protected_profile)
    )
    trust["audit_profile_policy_sha256"] = (
        acceptance_gate.audit_profile_policy_sha256(protected_profile)
    )

    def report_for(reviewed_commit: str, run_id: str) -> tuple[bytes, dict[str, Any]]:
        audited = {
            path: hashlib.sha256(
                subprocess.check_output(
                    ["git", "-C", str(repository), "show", f"{reviewed_commit}:{path}"]
                )
            ).hexdigest()
            for path in sorted(expected_paths)
        }
        report_trust = dict(trust)
        report_trust["candidate_tree"] = _git(
            repository, "rev-parse", f"{reviewed_commit}^{{tree}}"
        )
        runtimes = [
            {
                "runtime_id": runtime_id,
                "python_version": version,
                "implementation": "CPython",
                "abi": runtime_id,
                "operating_system": "Linux",
                "architecture": "x86_64",
                "threading": "gil",
                "test_counts": test_counts,
                "finding_counts": finding_counts,
                "check_ids_sha256": acceptance_gate._check_ids_sha256(check_ids),
            }
            for runtime_id, version in (
                ("cp311", "3.11.15"),
                ("cp312", "3.12.13"),
                ("cp313", "3.13.13"),
            )
        ]
        report: dict[str, Any] = {
            "audit_tool": AUDIT_TOOL,
            "audit_profile": acceptance_gate.PHASE5E2B12A_AUDIT_PROFILE,
            "audit_version": AUDIT_VERSION,
            "reviewed_commit": reviewed_commit,
            **baseline_fields,
            "audit_trust": report_trust,
            "started_at": "2026-07-16T00:00:00Z",
            "finished_at": "2026-07-16T00:02:00Z",
            "finding_counts": finding_counts,
            "test_counts": test_counts,
            "test_inventory_sha256": EXPECTED_NODEID_SHA256,
            "runtime_matrix_sha256": report_trust["runtime_matrix_sha256"],
            "audit_wheelhouse_manifest_sha256": report_trust[
                "audit_wheelhouse_manifest_sha256"
            ],
            "runtime_results": runtimes,
            "audited_file_sha256": audited,
            "check_ids": list(check_ids),
            "check_ids_sha256": acceptance_gate._check_ids_sha256(check_ids),
            "check_count": len(check_ids),
            "ci_run_ids": [run_id],
        }
        if report_mode == "unknown_report_field":
            report["attacker"] = "unknown"
        elif report_mode == "boolean_finding_count":
            report["finding_counts"] = {**finding_counts, "P0": False}
        elif report_mode == "boolean_test_count":
            report["test_counts"] = {**test_counts, "failed_tests": False}
        elif report_mode == "floating_test_count":
            report["test_counts"] = {**test_counts, "collected_tests": 1.0}
        elif report_mode == "nonlist_ci_run_ids":
            report["ci_run_ids"] = run_id
        elif report_mode == "missing_runtime":
            report["runtime_results"] = runtimes[:-1]
        elif report_mode == "duplicate_runtime":
            report["runtime_results"] = [runtimes[0], runtimes[0], runtimes[2]]
        elif report_mode == "runtime_version_drift":
            report["runtime_results"][1] = {**runtimes[1], "python_version": "3.12.12"}
        elif report_mode == "raw_evidence_hash":
            report["audit_junit_sha256"] = "c" * 64
        elif report_mode == "missing_check":
            report["check_ids"] = list(check_ids[:-1])
        elif report_mode == "duplicate_check":
            report["check_ids"] = [*check_ids[:-1], check_ids[0]]
        elif report_mode == "forged_check_evidence":
            report["check_ids_sha256"] = "f" * 64
        report["report_sha256"] = hashlib.sha256(
            json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        if report_mode == "duplicate_report_key":
            raw = b'{"audit_tool":"forged",' + raw[1:]
        elif report_mode == "compact_report":
            raw = (json.dumps(report, sort_keys=True) + "\n").encode()
        elif report_mode == "nonfinite_report_json":
            raw = b'{\n  "attacker": Infinity,\n' + raw[2:]
        elif report_mode == "overflow_report_json":
            raw = b'{\n  "attacker": 1e400,\n' + raw[2:]
        return raw, report

    pr_report_bytes, _ = report_for(implementation_head, "1001")
    main_report_bytes, main_report = report_for(implementation_merge, "1002")
    _write_closeout(
        repository,
        {
            "audit_workflow_id": 456,
            "audit_report_sha256": main_report["report_sha256"],
            "audit_artifact_sha256": hashlib.sha256(main_report_bytes).hexdigest(),
            "test_inventory_sha256": EXPECTED_NODEID_SHA256,
            "runtime_matrix_sha256": main_report["runtime_matrix_sha256"],
            "audit_wheelhouse_manifest_sha256": main_report[
                "audit_wheelhouse_manifest_sha256"
            ],
            "test_count": EXPECTED_TEST_COUNT,
        },
    )
    acceptance_head = _commit(repository, "acceptance")

    def archive(raw: bytes) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as bundle:
            if report_mode != "missing_report":
                bundle.writestr(f"{archive_prefix}phase5e-audit.json", raw)
        return buffer.getvalue()

    archives = {
        "https://example.invalid/pr-audit.zip": archive(pr_report_bytes),
        "https://example.invalid/main-audit.zip": archive(main_report_bytes),
    }
    implementation_ref = "fix/phase5e2b12a-r2-coverage-claim-parity"
    association = {
        "number": 76,
        "head": {
            "sha": implementation_head,
            "ref": implementation_ref,
            "repo": {"full_name": REPOSITORY_SLUG},
        },
        "base": {
            "sha": root_commit,
            "ref": "main",
            "repo": {"full_name": REPOSITORY_SLUG},
        },
    }

    def _secret_item(name: str) -> dict[str, str]:
        return {
            "name": name,
            "created_at": "2026-07-16T00:00:00Z",
            "updated_at": "2026-07-16T00:00:00Z",
        }

    def _variable_item(name: str, value: str) -> dict[str, str]:
        return {
            "name": name,
            "value": value,
            "created_at": "2026-07-16T00:00:00Z",
            "updated_at": "2026-07-16T00:00:00Z",
        }

    def authority_api_json(url: str) -> dict[str, Any] | None:
        url = url.split("?", 1)[0]
        environment_base = f"https://api.github.com/repos/{REPOSITORY_SLUG}/environments"
        controller_environment = (
            f"{environment_base}/{acceptance_gate.CONTROLLER_ENVIRONMENT_NAME}"
        )
        kernel_environment = f"{environment_base}/{acceptance_gate.KERNEL_ENVIRONMENT_NAME}"
        gate_environment = (
            f"{environment_base}/{acceptance_gate.EXTERNAL_GATE_AUTHOR_ENVIRONMENT}"
        )
        if url == environment_base:
            environments = [
                {"id": 1, "name": acceptance_gate.CONTROLLER_ENVIRONMENT_NAME},
                {"id": 2, "name": acceptance_gate.KERNEL_ENVIRONMENT_NAME},
                {"id": 3, "name": acceptance_gate.EXTERNAL_GATE_AUTHOR_ENVIRONMENT},
            ]
            if authority_mode == "missing_kernel_environment":
                environments = [environments[0], environments[2]]
            return {"total_count": len(environments), "environments": environments}
        if url in {controller_environment, kernel_environment, gate_environment}:
            deployment_policy = {
                "protected_branches": False,
                "custom_branch_policies": True,
            }
            if authority_mode == "unrestricted_environment" and url == controller_environment:
                deployment_policy["custom_branch_policies"] = False
            return {
                "id": (
                    1
                    if url == controller_environment
                    else (2 if url == kernel_environment else 3)
                ),
                "name": url.rsplit("/", 1)[-1],
                "can_admins_bypass": authority_mode == "environment_admin_bypass",
                "protection_rules": (
                    [{"id": 3, "type": "branch_policy"}, {"id": 5, "type": "wait_timer"}]
                    if authority_mode == "extra_environment_protection"
                    and url == controller_environment
                    else [{"id": 3, "type": "branch_policy"}]
                ),
                "deployment_branch_policy": deployment_policy,
            }
        if url in {
            f"{controller_environment}/deployment-branch-policies",
            f"{kernel_environment}/deployment-branch-policies",
            f"{gate_environment}/deployment-branch-policies",
        }:
            policy_name = (
                "feature/*"
                if authority_mode == "wrong_environment_branch"
                and url.startswith(controller_environment)
                else "main"
            )
            return {
                "total_count": (
                    2
                    if authority_mode == "duplicate_main_policy"
                    and url.startswith(controller_environment)
                    else 1
                ),
                "branch_policies": (
                    [
                        {"id": 4, "name": "main", "type": "branch"},
                        {"id": 5, "name": "main", "type": "branch"},
                    ]
                    if authority_mode == "duplicate_main_policy"
                    and url.startswith(controller_environment)
                    else [
                        {
                            "id": 4,
                            "name": policy_name,
                            "type": (
                                "tag"
                                if authority_mode == "tag_environment_policy"
                                and url.startswith(controller_environment)
                                else (
                                    None
                                    if authority_mode == "missing_environment_policy_type"
                                    and url.startswith(controller_environment)
                                    else "branch"
                                )
                            ),
                        }
                    ]
                ),
            }
        if url == f"https://api.github.com/repos/{REPOSITORY_SLUG}/actions/secrets":
            secrets: list[dict[str, str]] = []
            if authority_mode == "repository_kernel_secret":
                secrets.append(
                    _secret_item(acceptance_gate.KERNEL_READER_PRIVATE_KEY_SECRET)
                )
            if authority_mode == "repository_controller_secret":
                secrets.append(_secret_item(acceptance_gate.CONTROLLER_PRIVATE_KEY_SECRET))
            return {"total_count": len(secrets), "secrets": secrets}
        if url == f"https://api.github.com/repos/{REPOSITORY_SLUG}/actions/variables":
            variables: list[dict[str, str]] = []
            if authority_mode == "repository_controller_variable":
                variables.append(
                    _variable_item(acceptance_gate.CONTROLLER_APP_ID_VARIABLE, "98765")
                )
            return {"total_count": len(variables), "variables": variables}
        if url == f"{controller_environment}/secrets":
            secrets = [] if authority_mode == "missing_controller_secret" else [
                _secret_item(acceptance_gate.CONTROLLER_PRIVATE_KEY_SECRET)
            ]
            if authority_mode in {"kernel_secret_in_controller", "extra_controller_secret"}:
                secrets.append(
                    _secret_item(acceptance_gate.KERNEL_READER_PRIVATE_KEY_SECRET)
                )
            return {"total_count": len(secrets), "secrets": secrets}
        if url == f"{controller_environment}/variables":
            controller_app_value = "98765"
            if authority_mode == "wrong_controller_variable_value":
                controller_app_value = "98766"
            elif authority_mode == "noncanonical_controller_variable_value":
                controller_app_value = "098765"
            variables = (
                []
                if authority_mode == "missing_controller_variable"
                else [
                    _variable_item(
                        acceptance_gate.CONTROLLER_APP_ID_VARIABLE,
                        controller_app_value,
                    )
                ]
            )
            if authority_mode == "extra_controller_variable":
                variables.append(_variable_item("UNRELATED", "1"))
            return {"total_count": len(variables), "variables": variables}
        if url == f"{kernel_environment}/secrets":
            secrets = [] if authority_mode == "missing_kernel_secret" else [
                _secret_item(acceptance_gate.KERNEL_READER_PRIVATE_KEY_SECRET)
            ]
            if authority_mode == "controller_secret_in_kernel":
                secrets.append(_secret_item(acceptance_gate.CONTROLLER_PRIVATE_KEY_SECRET))
            return {"total_count": len(secrets), "secrets": secrets}
        if url == f"{kernel_environment}/variables":
            value = "24680"
            if authority_mode == "wrong_kernel_variable_value":
                value = "24681"
            elif authority_mode == "noncanonical_kernel_variable_value":
                value = "024680"
            variables = (
                []
                if authority_mode == "missing_kernel_variable"
                else [
                    _variable_item(
                        acceptance_gate.KERNEL_READER_APP_ID_VARIABLE,
                        value,
                    )
                ]
            )
            if authority_mode == "extra_kernel_variable":
                variables.append(_variable_item("UNRELATED", "1"))
            return {"total_count": len(variables), "variables": variables}
        if url == f"{gate_environment}/secrets":
            return {
                "total_count": 1,
                "secrets": [
                    _secret_item(
                        acceptance_gate.EXTERNAL_GATE_AUTHOR_PRIVATE_KEY_SECRET
                    )
                ],
            }
        if url == f"{gate_environment}/variables":
            return {
                "total_count": 1,
                "variables": [
                    _variable_item(
                        acceptance_gate.EXTERNAL_GATE_AUTHOR_APP_ID_VARIABLE,
                        "11223",
                    )
                ],
            }
        return None

    def fake_api_json(url: str, token: str) -> Any:
        assert token == "token"
        bare = url.split("?", 1)[0]
        authority = authority_api_json(url)
        if authority is not None:
            return authority
        if bare == f"https://api.github.com/repos/{REPOSITORY_SLUG}/collaborators":
            collaborators = [
                {
                    "id": 263841576,
                    "login": "owner",
                    "type": "User",
                    "site_admin": False,
                    "role_name": "admin",
                    "permissions": {
                        "admin": True,
                        "maintain": True,
                        "pull": True,
                        "push": True,
                        "triage": True,
                    },
                }
            ]
            if authority_mode == "extra_repository_collaborator":
                collaborators.append(
                    {
                        **collaborators[0],
                        "id": 7,
                        "login": "attacker",
                    }
                )
            return collaborators
        if bare == f"https://api.github.com/repos/{REPOSITORY_SLUG}/invitations":
            return (
                [{"id": 8, "invitee": {"login": "attacker"}}]
                if authority_mode == "pending_repository_invitation"
                else []
            )
        if url == "https://api.github.com/app":
            return {
                "id": (
                    98765.0
                    if authority_mode == "floating_controller_app_id"
                    else 98765
                ),
                "slug": "phase5e-controller",
                "owner": {"login": "owner"},
                "permissions": dict(acceptance_gate.CONTROLLER_APP_INSTALLATION_PERMISSIONS),
            }
        if url == "https://api.github.com/installation/repositories":
            return {
                "total_count": (
                    1.0 if authority_mode == "floating_controller_app_id" else 1
                ),
                "repositories": [{"full_name": REPOSITORY_SLUG}],
                "repository_selection": "selected",
            }
        if url == f"https://api.github.com/repos/{REPOSITORY_SLUG}":
            return {
                "id": 1312436919,
                "full_name": REPOSITORY_SLUG,
                "owner": {"id": 263841576, "login": "owner", "type": "User"},
                "fork": False,
                "default_branch": "main",
                "private": False,
                "allow_merge_commit": True,
                "allow_squash_merge": False,
                "allow_rebase_merge": False,
            }
        if bare == f"https://api.github.com/repos/{REPOSITORY_SLUG}/actions/artifacts":
            artifact_name = (
                "unapproved-private-evidence"
                if authority_mode == "unapproved_public_artifact"
                else f"phase5e-audit-{implementation_head}"
            )
            artifact_id: object = (
                "not-an-integer"
                if authority_mode == "malformed_public_artifact"
                else 7001
            )
            return {
                "total_count": 1,
                "artifacts": [{"id": artifact_id, "name": artifact_name}],
            }
        if url.endswith("/branches/main/protection"):
            checks = [
                {
                    "context": context,
                    "app_id": (
                        acceptance_gate.GITHUB_ACTIONS_APP_ID
                        if context in acceptance_gate.GITHUB_ACTIONS_CHECKS
                        else 98765
                    ),
                }
                for context in sorted(acceptance_gate.REQUIRED_PROTECTION_CHECKS)
            ]
            return {
                "required_status_checks": {
                    "strict": True,
                    "checks": checks,
                },
                "required_pull_request_reviews": {
                    "required_approving_review_count": 0,
                    "dismiss_stale_reviews": False,
                    "require_last_push_approval": False,
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
                "required_conversation_resolution": {"enabled": True},
            }
        if url.endswith("/actions/runs/1001"):
            payload: dict[str, Any] = {
                "id": 1001,
                "head_sha": root_commit,
                "head_branch": "main",
                "event": "pull_request_target",
                "conclusion": "success",
                "name": "phase5e2b12a-base-owned-acceptance-gate",
                "path": ".github/workflows/phase5e2b12a-acceptance-gate.yml",
                "workflow_id": 456,
                "repository": {"full_name": REPOSITORY_SLUG},
                "head_repository": {"full_name": REPOSITORY_SLUG},
                "pull_requests": [association],
            }
            if run_mutation:
                payload[run_mutation[0]] = run_mutation[1]
            return payload
        if url.endswith("/actions/runs/1002"):
            return {
                "id": 1002,
                "head_sha": implementation_merge,
                "head_branch": "main",
                "event": "workflow_run",
                "conclusion": "success",
                "name": "phase5e2b12a-base-owned-acceptance-gate",
                "path": ".github/workflows/phase5e2b12a-acceptance-gate.yml",
                "workflow_id": 456,
                "repository": {"full_name": REPOSITORY_SLUG},
                "head_repository": {"full_name": REPOSITORY_SLUG},
                "pull_requests": [],
            }
        if url.endswith("/actions/workflows/456"):
            payload = {
                "id": 456,
                "path": ".github/workflows/phase5e2b12a-acceptance-gate.yml",
                "name": "phase5e2b12a-base-owned-acceptance-gate",
                "state": "active",
            }
            if workflow_mutation:
                payload[workflow_mutation[0]] = workflow_mutation[1]
            return payload
        if url.endswith("/pulls/76"):
            payload = {
                "number": 76,
                "state": "closed",
                "merged": True,
                "merged_at": "2026-07-16T00:00:00Z",
                "merge_commit_sha": implementation_merge,
                "base": association["base"],
                "head": association["head"],
            }
            if pull_request_mutation:
                payload[pull_request_mutation[0]] = pull_request_mutation[1]
            return payload
        if "/actions/runs/1001/artifacts?" in url:
            return {
                "total_count": artifact_total_count,
                "artifacts": [
                    {
                        "id": 3001,
                        "name": f"phase5e-audit-{implementation_head}",
                        "expired": False,
                        "archive_download_url": "https://example.invalid/pr-audit.zip",
                    }
                ],
            }
        if "/actions/runs/1002/artifacts?" in url:
            return {
                "total_count": artifact_total_count,
                "artifacts": [
                    {
                        "id": 3002,
                        "name": f"phase5e-audit-{implementation_merge}",
                        "expired": False,
                        "archive_download_url": "https://example.invalid/main-audit.zip",
                    }
                ],
            }
        raise AssertionError(url)

    def fake_api_list(url: str, token: str) -> list[dict[str, Any]]:
        assert token == "token"
        if f"/repos/{REPOSITORY_SLUG}/collaborators?" in url:
            collaborators = [
                {
                    "id": 263841576,
                    "login": "owner",
                    "type": "User",
                    "site_admin": False,
                    "role_name": "admin",
                    "permissions": {
                        "admin": True,
                        "maintain": True,
                        "pull": True,
                        "push": True,
                        "triage": True,
                    },
                }
            ]
            if authority_mode == "extra_repository_collaborator":
                collaborators.append(
                    {
                        **collaborators[0],
                        "id": 7,
                        "login": "attacker",
                    }
                )
            return collaborators
        if f"/repos/{REPOSITORY_SLUG}/invitations?" in url:
            return (
                [{"id": 8, "invitee": {"login": "attacker"}}]
                if authority_mode == "pending_repository_invitation"
                else []
            )
        if "/rulesets?" in url:
            return []
        if f"/commits/{implementation_head}/statuses?" in url:
            return _controller_status_fixture(
                head_sha=implementation_head,
                workflow_run_id="1001",
            )
        raise AssertionError(url)

    monkeypatch.setattr(acceptance_gate, "_api_json", fake_api_json)
    monkeypatch.setattr(acceptance_gate, "_api_list", fake_api_list)
    monkeypatch.setattr(
        acceptance_gate,
        "_api_bytes",
        lambda url, token: archives[url],
    )
    return acceptance_head


def test_base_owned_acceptance_gate_accepts_governance_only_diff(tmp_path: Path) -> None:
    repository, _, _, base = _repository(tmp_path)
    head = _commit(repository, "acceptance")
    verify_acceptance(
        repository=repository,
        base=base,
        head=head,
        event=_event(base=base, head=head),
        repository_slug=REPOSITORY_SLUG,
        token=None,
        require_remote=False,
    )


@pytest.mark.parametrize(
    "path",
    (
        "docs/phase-status.json",
        "docs/phase5e2b12a-acceptance-closeout.json",
    ),
)
@pytest.mark.parametrize("encoding_attack", ("compact", "crlf"))
def test_base_owned_gate_rejects_noncanonical_authority_json(
    tmp_path: Path,
    path: str,
    encoding_attack: str,
) -> None:
    repository, _, _, base = _repository(tmp_path)
    target = repository / path
    payload = json.loads(target.read_text(encoding="utf-8"))
    if encoding_attack == "compact":
        raw = json.dumps(payload, sort_keys=True) + "\n"
    else:
        raw = json.dumps(payload, indent=2, sort_keys=True).replace("\n", "\r\n")
        raw += "\r\n"
    target.write_bytes(raw.encode())
    head = _commit(repository, "noncanonical authority")
    with pytest.raises(SystemExit, match="not canonically serialized"):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=None,
            repository_slug=None,
            token=None,
            require_remote=False,
        )


@pytest.mark.parametrize(
    ("path", "key"),
    (
        ("docs/phase-status.json", "authorized_next"),
        ("docs/phase5e2b12a-acceptance-closeout.json", "phase"),
    ),
)
def test_acceptance_authority_rejects_duplicate_json_keys(
    tmp_path: Path,
    path: str,
    key: str,
) -> None:
    repository, _, _, base = _repository(tmp_path)
    target = repository / path
    text = target.read_text(encoding="utf-8").strip()
    assert text.startswith("{")
    target.write_text(
        "{" + json.dumps(key) + ':"forged",' + text[1:] + "\n",
        encoding="utf-8",
    )
    head = _commit(repository, "duplicate authority key")
    with pytest.raises(SystemExit, match="duplicate JSON key"):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=_event(base=base, head=head),
            repository_slug=REPOSITORY_SLUG,
            token=None,
            require_remote=False,
        )


@pytest.mark.parametrize("attack", ("production", "mode"))
def test_base_owned_acceptance_gate_rejects_frozen_path_or_mode_change(
    tmp_path: Path,
    attack: str,
) -> None:
    repository, _, _, base = _repository(tmp_path)
    if attack == "production":
        (repository / "src/frozen.py").write_text("VALUE = 3\n", encoding="utf-8")
    else:
        (repository / "docs/phase-status.json").chmod(0o755)
    head = _commit(repository, f"attack {attack}")
    with pytest.raises(
        SystemExit,
        match="frozen paths|file type, mode|modify status and add one new closeout",
    ):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=None,
            repository_slug=None,
            token=None,
            require_remote=False,
        )


def test_acceptance_gate_rejects_multi_commit_add_revert_history(tmp_path: Path) -> None:
    repository, _, _, base = _repository(tmp_path)
    _commit(repository, "acceptance")
    path = repository / "docs/phase-status.json"
    original = path.read_text(encoding="utf-8")
    path.write_text(original + "\n", encoding="utf-8")
    _commit(repository, "hidden intermediate")
    path.write_text(original, encoding="utf-8")
    head = _commit(repository, "revert intermediate")
    with pytest.raises(SystemExit, match="one direct non-merge commit"):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=None,
            repository_slug=None,
            token=None,
            require_remote=False,
        )


@pytest.mark.parametrize("target", ("status", "closeout"))
def test_acceptance_gate_rejects_unexpected_governance_authority(
    tmp_path: Path,
    target: str,
) -> None:
    repository, _, _, base = _repository(tmp_path)
    path = repository / (
        "docs/phase-status.json"
        if target == "status"
        else "docs/phase5e2b12a-acceptance-closeout.json"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["unexpected_authority"] = "Phase 5E-2C"
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    head = _commit(repository, f"unexpected {target} authority")
    with pytest.raises(SystemExit, match="machine state|acceptance evidence"):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=None,
            repository_slug=None,
            token=None,
            require_remote=False,
        )


@pytest.mark.parametrize(
    ("base_ref", "event_slug", "repository_slug"),
    (
        ("attacker-base", REPOSITORY_SLUG, REPOSITORY_SLUG),
        ("main", "attacker/research", REPOSITORY_SLUG),
        ("main", REPOSITORY_SLUG, "different/research"),
    ),
)
def test_acceptance_gate_rejects_wrong_event_repository_or_base(
    tmp_path: Path,
    base_ref: str,
    event_slug: str,
    repository_slug: str,
) -> None:
    repository, _, _, base = _repository(tmp_path)
    head = _commit(repository, "acceptance")
    with pytest.raises(SystemExit, match="event identity"):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=_event(base=base, head=head, base_ref=base_ref, slug=event_slug),
            repository_slug=repository_slug,
            token=None,
            require_remote=False,
        )


def test_acceptance_workflow_is_base_owned_read_only_and_immutably_pinned() -> None:
    text = (ROOT / ".github/workflows/phase5e2b12a-acceptance-gate.yml").read_text(encoding="utf-8")

    def job_block(name: str) -> str:
        lines = text.splitlines()
        marker = f"  {name}:"
        start = lines.index(marker)
        end = len(lines)
        for index in range(start + 1, len(lines)):
            line = lines[index]
            if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
                end = index
                break
        return "\n".join(lines[start:end])

    assert "pull_request_target:" in text
    assert "branches: [main]" in text
    assert text.count("actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd") >= 3
    assert "actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c" in text
    assert "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1" in text
    assert "actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd" in text
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in text
    assert "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" in text
    assert "@v6" not in text
    assert "ubuntu-latest" not in text
    assert "runs-on: ubuntu-24.04" in text
    assert 'python-version: "3.11.9"' in text
    assert "contents: read" in text
    assert "actions: read" in text
    assert "pull-requests: read" in text
    assert "phase5e-readonly-audit-comment:" in text
    assert "Narrow platform-token exception" in text
    assert "pull-requests: write" in text
    assert "OWNER_VALUATION_DEPLOY_KEY" not in text
    assert "ssh-key:" not in text
    assert "PHASE5E_KERNEL_READER_PRIVATE_KEY" in text
    assert "PHASE5E_KERNEL_READER_APP_ID" in text
    assert "permission-contents: read" in text
    assert "permission-metadata: read" in text
    assert "--verify-kernel-reader-authority-only" in text
    assert "controller-global-authority:" not in text
    assert "audit-kernel-reader-checkout-token" not in text
    assert "PHASE5E_KERNEL_READER_APP_JWT" in text
    assert text.count("actions/create-github-app-token@") == 5
    assert text.count("skip-token-revoke: true") == 5
    assert text.count("--hard-revoke-current-installation-token") == 5
    assert "https://api.github.com/installation/token" not in text
    assert text.count("repositories: owner-equity-research-public") == 4
    assert text.count("repositories: owner-valuation-kernel") == 1
    assert "source-artifact-audience-preflight:" not in text
    assert "kernel-release-interface:" not in text

    external_job = job_block("external-gate-author-authority")
    assert external_job.count("actions/create-github-app-token@") == 1
    assert "repositories: owner-equity-research-public" in external_job
    assert "permission-contents: read" in external_job
    assert "permission-pull-requests: read" in external_job
    assert "permission-contents: write" not in external_job
    assert "permission-pull-requests: write" not in external_job
    assert external_job.index(
        "Verify App-global and full-installation author scope"
    ) < external_job.index(
        "Replay external-author handoff and commit provenance"
    ) < external_job.index(
        "Reverify author authority after provenance replay"
    ) < external_job.index(
        "Hard-revoke full-installation external author audit token"
    )

    evidence_job = job_block("acceptance-structure-and-evidence")
    assert evidence_job.count("actions/create-github-app-token@") == 1
    assert evidence_job.index(
        "Verify controller authority immediately before evidence replay"
    ) < evidence_job.index(
        "Verify exact phase transition from protected base"
    ) < evidence_job.index(
        "Verify controller authority immediately after evidence replay"
    ) < evidence_job.index("Hard-revoke controller evidence token")

    kernel_job = job_block("phase5e-readonly-audit")
    assert kernel_job.count("actions/create-github-app-token@") == 1
    assert "token: ${{ steps.audit-kernel-reader-authority-token.outputs.token }}" in kernel_job
    assert kernel_job.index(
        "Mint ephemeral kernel-reader App identity JWT in the audit job"
    ) < kernel_job.index(
        "Mint full-installation kernel-reader audit token in the audit job"
    ) < kernel_job.index(
        "Reverify exact kernel-reader authority in the consuming job"
    ) < kernel_job.index(
        "Check out pinned private kernel inside the consuming audit job"
    ) < kernel_job.index(
        "Reverify kernel-reader authority after pinned checkout"
    ) < kernel_job.index(
        "Hard-revoke audit-job kernel-reader token and prove invalidation"
    ) < kernel_job.index("Build the bounded kernel interface in the consuming audit job")
    audit_full_token = kernel_job.split(
        "id: audit-kernel-reader-authority-token",
        1,
    )[1].split("- name: Reverify exact kernel-reader authority", 1)[0]
    assert "repositories: owner-valuation-kernel" in audit_full_token
    assert "phase5e-kernel-interface-${{ github.run_id }}" not in text
    assert "Download bounded kernel interface" not in text
    assert "Build the bounded kernel interface in the consuming audit job" in text
    assert kernel_job.index(
        "Build the bounded kernel interface in the consuming audit job"
    ) < kernel_job.index("Run root-owned no-network CPython 3.11 audit sandbox")
    assert "Verify governance and owner-only artifact audience immediately before build" not in text
    assert "environment: phase5e-private-kernel-readonly" in text
    assert "PHASE5E_CONTROLLER_PRIVATE_KEY" in text
    assert "PHASE5E_CONTROLLER_APP_ID" in text
    controller_token_blocks = [
        part.split("skip-token-revoke: true", 1)[0]
        for part in text.split("id: controller-token")[1:]
    ]
    merged_controller_block = text.split(
        "id: merged-controller-authority-token", 1
    )[1].split("skip-token-revoke: true", 1)[0]
    assert len(controller_token_blocks) == 2
    for token_block in (*controller_token_blocks, merged_controller_block):
        assert "repositories: owner-equity-research-public" in token_block
        assert "permission-" not in token_block
    assert "--verify-remote-governance-only" in text
    assert "phase5e/controller-structure" in text
    assert "phase5e/controller-readonly-audit" in text
    assert "phase5e/actions-status-token-revoked" in text
    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        if workflow.name != "phase5e2b12a-acceptance-gate.yml":
            assert "phase5e/actions-status-token-revoked" not in workflow.read_text(
                encoding="utf-8"
            )
    publisher_job = job_block("publish-protected-candidate-statuses")
    assert publisher_job.count("actions/create-github-app-token@") == 1
    assert publisher_job.index(
        "Verify controller authority before status publication"
    ) < publisher_job.index(
        "Revalidate remote governance immediately before status publication"
    ) < publisher_job.index(
        "Bind protected-base structure and audit results"
    ) < publisher_job.index(
        "Revalidate remote governance after status publication"
    ) < publisher_job.index(
        "Reverify controller authority after status publication"
    ) < publisher_job.index(
        "Hard-revoke controller status token and prove invalidation"
    )
    assert text.index("Mark status-token revocation pending") < text.index(
        "Bind protected-base structure and audit results"
    ) < text.index(
        "Publish the Actions-owned revocation attestation"
    )

    merged_job = job_block("merged-main-acceptance-evidence")
    assert merged_job.count("actions/create-github-app-token@") == 1
    assert "repositories: owner-equity-research-public" in merged_job
    assert merged_job.index(
        "Reverify controller global scope before merged-main replay"
    ) < merged_job.index(
        "Replay merged-main phase transition and remote provenance"
    ) < merged_job.index(
        "Reverify controller authority after merged-main replay"
    ) < merged_job.index(
        "Hard-revoke merged-main controller token and prove invalidation"
    )
    assert "PUBLISHER_RESULT" in text
    assert "BASE_REF:" in text
    assert "BASE_REPOSITORY:" in text
    assert "HEAD_REPOSITORY:" in text
    assert "Pull request has invalid repository identity" in text
    assert "--non-acceptance-pr" in text
    assert "fetch-depth: 0" in text
    assert "if: steps.classify.outputs.is_acceptance" not in text
    assert "acceptance-structure-and-evidence:" in text
    assert "if: github.event_name == 'pull_request_target'" in text
    assert "pull_request.base.sha" in text
    assert "pull_request.head.sha" in text
    assert "github.event.workflow_run.event == 'push'" in text
    assert "github.event.workflow_run.repository.full_name == github.repository" in text
    assert "path: _control" in text
    assert "path: _candidate_objects" in text
    assert "git -C _control fetch --no-tags ../_candidate_objects HEAD" in text
    assert "git -C _control remote remove origin" in text
    assert "submodules: false" in text
    assert "lfs: false" in text
    assert "--require-remote" in text
    ci_text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "secrets." not in ci_text
    assert "OWNER_VALUATION_DEPLOY_KEY" not in ci_text
    assert "PHASE5E_KERNEL_READER_PRIVATE_KEY" not in ci_text
    assert "verify_phase5e_candidate_surface.py" in ci_text
    assert "run_phase5e_audit.py" not in ci_text


def test_acceptance_verifier_uses_an_immutable_self_contained_trust_snapshot() -> None:
    verifier = (ROOT / "scripts/verify_phase5e2b12a_acceptance_gate.py").read_text(
        encoding="utf-8"
    )
    trust_path = ROOT / "scripts/phase5e2b12a-acceptance-trust.json"
    raw = trust_path.read_bytes()
    trust = json.loads(raw)
    assert "from scripts.run_phase5e_audit import" not in verifier
    assert "from run_phase5e_audit import" not in verifier
    assert raw == (json.dumps(trust, indent=2, sort_keys=True) + "\n").encode()
    assert str(trust_path.relative_to(ROOT)) in trust["static_control_files"]
    assert str(trust_path.relative_to(ROOT)) in PERMANENT_ACCEPTED_TRUST_ROOT
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/verify_phase5e2b12a_acceptance_gate.py"),
            "--help",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--verify-kernel-reader-authority-only" in completed.stdout


def _ordinary_repository(
    tmp_path: Path,
    *,
    accepted: bool = False,
    head_ref: str = "feature/ordinary",
) -> tuple[Path, str, str]:
    repository = tmp_path / "ordinary-repo"
    repository.mkdir()
    subprocess.run(["git", "-C", str(repository), "init", "-b", "main"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "audit@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Audit Fixture"],
        check=True,
    )
    for path in sorted(PENDING_ACCEPTANCE_TRUST_ROOT):
        if path in {acceptance_gate.CLOSEOUT_PATH, acceptance_gate.STATUS_PATH}:
            continue
        target = repository / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"base:{path}\n", encoding="utf-8")
    pending_status = {
        "current_phase": "Phase 5E-2B.1",
        "status": "implementation_complete_pending_acceptance",
        "authorized_next": list(acceptance_gate.PENDING_AUTHORIZED_NEXT),
        "prohibited": list(EXPECTED_PROHIBITED),
        "release_tag": None,
    }
    (repository / "docs").mkdir(parents=True, exist_ok=True)
    (repository / acceptance_gate.STATUS_PATH).write_text(
        json.dumps(pending_status, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if accepted:
        (repository / acceptance_gate.PUBLIC_REVALIDATION_PATH).write_text(
            json.dumps(
                acceptance_gate.PUBLIC_REVALIDATION_PAYLOAD,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (repository / acceptance_gate.CLOSEOUT_PATH).write_text(
            json.dumps(
                {
                    "schema_version": "1.0.0",
                    "phase": "Phase 5E-2B.1-2A",
                    "implementation_pull_request": 76,
                    "implementation_head_commit": "1" * 40,
                    "implementation_merge_commit": "2" * 40,
                    "implementation_tree_sha": "3" * 40,
                    "acceptance_pull_request": 77,
                    "pr_ci_run_id": "1001",
                    "main_ci_run_id": "1002",
                    "audit_workflow_id": 123,
                    "controller_app_id": 98765,
                    "controller_app_slug": "phase5e-controller",
                    "controller_installation_id": 54321,
                    "audit_tool": AUDIT_TOOL,
                    "audit_profile": acceptance_gate.PHASE5E2B12A_AUDIT_PROFILE,
                    "audit_version": AUDIT_VERSION,
                    "audit_report_sha256": "a" * 64,
                    "audit_artifact_sha256": "b" * 64,
                    "test_inventory_sha256": EXPECTED_NODEID_SHA256,
                    "runtime_matrix_sha256": "c" * 64,
                    "audit_wheelhouse_manifest_sha256": "d" * 64,
                    "test_count": EXPECTED_TEST_COUNT,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        status = {
            "current_phase": "Phase 5E-2B.1-2A",
            "status": "accepted_closed",
            "authorized_next": list(acceptance_gate.ACCEPTED_AUTHORIZED_NEXT),
            "prohibited": list(ACCEPTED_PROHIBITED),
            "release_tag": None,
        }
        (repository / acceptance_gate.STATUS_PATH).write_text(
            json.dumps(status, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    base = _commit(repository, "base")
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", head_ref],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return repository, base, head_ref


def test_pending_acceptance_rejects_every_non_acceptance_pr_except_exact_public_revalidation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, base, head_ref = _ordinary_repository(tmp_path)
    target = repository / "src/ordinary.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("VALUE = 1\n", encoding="utf-8")
    head = _commit(repository, "ordinary source change")
    with pytest.raises(SystemExit, match="permits only the reserved acceptance"):
        verify_non_acceptance_pr(
            repository=repository,
            base=base,
            head=head,
            event=_event(base=base, head=head, head_ref=head_ref),
            repository_slug=REPOSITORY_SLUG,
        )

    revalidation_scope = tmp_path / "revalidation"
    revalidation_scope.mkdir()
    repository, base, head_ref = _ordinary_repository(
        revalidation_scope,
        head_ref=acceptance_gate.PUBLIC_REVALIDATION_BRANCH,
    )
    marker = repository / acceptance_gate.PUBLIC_REVALIDATION_PATH
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        json.dumps(
            acceptance_gate.PUBLIC_REVALIDATION_PAYLOAD,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    head = _commit(repository, "public audit revalidation")
    monkeypatch.setattr(
        acceptance_gate,
        "_verify_remote_repository_governance",
        lambda *args, **kwargs: (54321, "phase5e-controller"),
    )
    verify_non_acceptance_pr(
        repository=repository,
        base=base,
        head=head,
        event=_event(base=base, head=head, head_ref=head_ref),
        repository_slug=REPOSITORY_SLUG,
        token="controller-token",
        require_remote=True,
        controller_app_id=98765,
    )


@pytest.mark.parametrize("protected_path", sorted(PENDING_ACCEPTANCE_TRUST_ROOT))
def test_non_acceptance_pr_cannot_change_the_frozen_trust_root(
    tmp_path: Path,
    protected_path: str,
) -> None:
    repository, base, head_ref = _ordinary_repository(tmp_path)
    target = repository / protected_path
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(existing + "attack\n", encoding="utf-8")
    head = _commit(repository, f"attack {protected_path}")
    with pytest.raises(SystemExit, match="permits only the reserved acceptance"):
        verify_non_acceptance_pr(
            repository=repository,
            base=base,
            head=head,
            event=_event(base=base, head=head, head_ref=head_ref),
            repository_slug=REPOSITORY_SLUG,
        )


@pytest.mark.parametrize("protected_path", sorted(PERMANENT_ACCEPTED_TRUST_ROOT))
def test_accepted_phase_permanently_freezes_historical_acceptance_evidence(
    tmp_path: Path,
    protected_path: str,
) -> None:
    repository, base, head_ref = _ordinary_repository(
        tmp_path,
        accepted=True,
        head_ref="feature/phase5e2b12b-canonical-rollforward",
    )
    target = repository / protected_path
    target.write_text(target.read_text(encoding="utf-8") + "rewrite\n", encoding="utf-8")
    head = _commit(repository, f"rewrite accepted evidence {protected_path}")
    with pytest.raises(SystemExit, match="frozen acceptance trust root"):
        verify_non_acceptance_pr(
            repository=repository,
            base=base,
            head=head,
            event=_event(base=base, head=head, head_ref=head_ref),
            repository_slug=REPOSITORY_SLUG,
        )


def test_permanent_acceptance_root_is_a_strict_subset_of_pending_root() -> None:
    assert PERMANENT_ACCEPTED_TRUST_ROOT < PENDING_ACCEPTANCE_TRUST_ROOT


def test_accepted_phase_rejects_unregistered_successor_branch(tmp_path: Path) -> None:
    repository, base, head_ref = _ordinary_repository(tmp_path, accepted=True)
    target = repository / "src/successor.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("VALUE = 1\n", encoding="utf-8")
    head = _commit(repository, "unregistered successor")
    with pytest.raises(SystemExit):
        verify_non_acceptance_pr(
            repository=repository,
            base=base,
            head=head,
            event=_event(base=base, head=head, head_ref=head_ref),
            repository_slug=REPOSITORY_SLUG,
        )


def test_legacy_self_signed_successor_bootstrap_is_rejected(tmp_path: Path) -> None:
    repository, base, head_ref = _ordinary_repository(
        tmp_path,
        accepted=True,
        head_ref="feature/phase5e2b12b-governance-bootstrap",
    )
    target = repository / "scripts/verify_phase5e2b12b_acceptance_gate.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("def main():\n    return 0\n", encoding="utf-8")
    head = _commit(repository, "self-signed successor")
    with pytest.raises(SystemExit):
        verify_non_acceptance_pr(
            repository=repository,
            base=base,
            head=head,
            event=_event(base=base, head=head, head_ref=head_ref),
            repository_slug=REPOSITORY_SLUG,
        )


def test_base_owned_gate_replays_exact_remote_ci_and_audit_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, root_commit, implementation_head, base = _repository(tmp_path)
    head = _remote_evidence(
        repository=repository,
        root_commit=root_commit,
        implementation_head=implementation_head,
        implementation_merge=base,
        monkeypatch=monkeypatch,
    )
    verify_acceptance(
        repository=repository,
        base=base,
        head=head,
        event=None,
        repository_slug=REPOSITORY_SLUG,
        token="token",
        require_remote=True,
        controller_app_id=98765,
    )


@pytest.mark.parametrize(
    "attack",
    (
        "missing_required_check",
        "stale_review_survives",
        "force_push",
        "squash_merge",
        "wrong_actions_app_id",
        "wrong_controller_app_id",
    ),
)
def test_remote_acceptance_requires_non_bypass_public_main_protection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    repository, root_commit, implementation_head, base = _repository(tmp_path)
    head = _remote_evidence(
        repository=repository,
        root_commit=root_commit,
        implementation_head=implementation_head,
        implementation_merge=base,
        monkeypatch=monkeypatch,
    )
    prior_api = acceptance_gate._api_json

    def weakened_api(url: str, token: str) -> dict[str, Any]:
        payload = json.loads(json.dumps(prior_api(url, token)))
        if attack == "squash_merge" and url == f"https://api.github.com/repos/{REPOSITORY_SLUG}":
            payload["allow_squash_merge"] = True
        elif url.endswith("/branches/main/protection"):
            if attack == "missing_required_check":
                payload["required_status_checks"]["checks"] = [
                    item
                    for item in payload["required_status_checks"]["checks"]
                    if item["context"] != "phase5e/controller-structure"
                ]
            elif attack == "stale_review_survives":
                payload["required_pull_request_reviews"]["dismiss_stale_reviews"] = True
            elif attack == "force_push":
                payload["allow_force_pushes"]["enabled"] = True
            elif attack == "wrong_actions_app_id":
                next(
                    item
                    for item in payload["required_status_checks"]["checks"]
                    if item["context"] == "verify (3.11)"
                )["app_id"] = 1
            elif attack == "wrong_controller_app_id":
                next(
                    item
                    for item in payload["required_status_checks"]["checks"]
                    if item["context"] == "phase5e/controller-structure"
                )["app_id"] = 1
        return payload

    monkeypatch.setattr(acceptance_gate, "_api_json", weakened_api)
    with pytest.raises(SystemExit, match="non-bypass acceptance protections"):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=None,
            repository_slug=REPOSITORY_SLUG,
            token="token",
            require_remote=True,
            controller_app_id=98765,
        )


@pytest.mark.parametrize(
    "authority_mode",
    (
        "missing_kernel_environment",
        "unrestricted_environment",
        "wrong_environment_branch",
        "repository_kernel_secret",
        "repository_controller_secret",
        "repository_controller_variable",
        "missing_controller_secret",
        "missing_controller_variable",
        "missing_kernel_secret",
        "missing_kernel_variable",
        "environment_admin_bypass",
        "extra_environment_protection",
        "duplicate_main_policy",
        "tag_environment_policy",
        "missing_environment_policy_type",
        "floating_controller_app_id",
        "kernel_secret_in_controller",
        "controller_secret_in_kernel",
        "extra_controller_secret",
        "extra_controller_variable",
        "wrong_controller_variable_value",
        "noncanonical_controller_variable_value",
        "extra_kernel_variable",
        "wrong_kernel_variable_value",
        "noncanonical_kernel_variable_value",
        "unapproved_public_artifact",
        "malformed_public_artifact",
    ),
)
def test_remote_acceptance_requires_exact_environment_and_secret_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority_mode: str,
) -> None:
    repository, root_commit, implementation_head, base = _repository(tmp_path)
    head = _remote_evidence(
        repository=repository,
        root_commit=root_commit,
        implementation_head=implementation_head,
        implementation_merge=base,
        monkeypatch=monkeypatch,
        authority_mode=authority_mode,
    )
    with pytest.raises(
        SystemExit,
        match=(
            "environment|secret|variable|App ID|controller App token authority|"
            "artifact|pagination"
        ),
    ):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=None,
            repository_slug=REPOSITORY_SLUG,
            token="token",
            require_remote=True,
            controller_app_id=98765,
        )


def test_remote_acceptance_requires_a_pre_pinned_controller_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, root_commit, implementation_head, base = _repository(tmp_path)
    head = _remote_evidence(
        repository=repository,
        root_commit=root_commit,
        implementation_head=implementation_head,
        implementation_merge=base,
        monkeypatch=monkeypatch,
    )
    monkeypatch.setattr(acceptance_gate, "CONTROLLER_AUTHORITY_STATUS", "bootstrap_pending")
    with pytest.raises(SystemExit, match="bootstrap is still pending"):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=None,
            repository_slug=REPOSITORY_SLUG,
            token="token",
            require_remote=True,
            controller_app_id=98765,
        )


def test_remote_acceptance_requires_a_pre_pinned_kernel_reader_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, root_commit, implementation_head, base = _repository(tmp_path)
    head = _remote_evidence(
        repository=repository,
        root_commit=root_commit,
        implementation_head=implementation_head,
        implementation_merge=base,
        monkeypatch=monkeypatch,
    )
    monkeypatch.setattr(
        acceptance_gate,
        "KERNEL_READER_AUTHORITY_STATUS",
        "bootstrap_pending",
    )
    with pytest.raises(SystemExit, match="kernel-reader authority bootstrap is still pending"):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=None,
            repository_slug=REPOSITORY_SLUG,
            token="token",
            require_remote=True,
            controller_app_id=98765,
        )


def test_remote_acceptance_rejects_controller_installation_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, root_commit, implementation_head, base = _repository(tmp_path)
    head = _remote_evidence(
        repository=repository,
        root_commit=root_commit,
        implementation_head=implementation_head,
        implementation_merge=base,
        monkeypatch=monkeypatch,
    )
    monkeypatch.setattr(acceptance_gate, "PINNED_CONTROLLER_INSTALLATION_ID", 99999)
    with pytest.raises(SystemExit, match="closeout does not bind controller App authority"):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=None,
            repository_slug=REPOSITORY_SLUG,
            token="token",
            require_remote=True,
            controller_app_id=98765,
        )


@pytest.mark.parametrize(
    "scope_attack",
    ("missing", "extra", "downgraded"),
)
def test_remote_acceptance_requires_exact_controller_token_repository_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope_attack: str,
) -> None:
    repository, root_commit, implementation_head, base = _repository(tmp_path)
    head = _remote_evidence(
        repository=repository,
        root_commit=root_commit,
        implementation_head=implementation_head,
        implementation_merge=base,
        monkeypatch=monkeypatch,
    )
    prior_api = acceptance_gate._api_json

    def api(url: str, token: str) -> dict[str, Any]:
        payload = json.loads(json.dumps(prior_api(url, token)))
        if url == "https://api.github.com/installation/repositories":
            if scope_attack == "missing":
                payload = {"total_count": 0, "repositories": []}
            elif scope_attack == "extra":
                payload["total_count"] = 2
                payload["repositories"].append({"full_name": "owner/other"})
            else:
                payload["repositories"][0]["full_name"] = "owner/other"
        return payload

    monkeypatch.setattr(acceptance_gate, "_api_json", api)
    with pytest.raises(SystemExit, match="token authority"):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=None,
            repository_slug=REPOSITORY_SLUG,
            token="token",
            require_remote=True,
            controller_app_id=98765,
        )


def test_remote_acceptance_rejects_coordinated_controller_app_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, root_commit, implementation_head, base = _repository(tmp_path)
    head = _remote_evidence(
        repository=repository,
        root_commit=root_commit,
        implementation_head=implementation_head,
        implementation_merge=base,
        monkeypatch=monkeypatch,
    )
    monkeypatch.setattr(acceptance_gate, "PINNED_CONTROLLER_APP_ID", 11111)
    monkeypatch.setattr(acceptance_gate, "PINNED_CONTROLLER_APP_SLUG", "replacement")
    monkeypatch.setattr(acceptance_gate, "PINNED_CONTROLLER_INSTALLATION_ID", 22222)
    with pytest.raises(SystemExit, match="not the pinned authority"):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=None,
            repository_slug=REPOSITORY_SLUG,
            token="token",
            require_remote=True,
            controller_app_id=98765,
        )


@pytest.mark.parametrize("authority_kind", ("controller", "external_author"))
def test_controller_and_external_author_wrappers_require_full_installation_proof(
    monkeypatch: pytest.MonkeyPatch,
    authority_kind: str,
) -> None:
    monkeypatch.setattr(acceptance_gate, "PINNED_CONTROLLER_APP_ID", 98765)
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_CONTROLLER_APP_SLUG",
        "phase5e-controller",
    )
    monkeypatch.setattr(acceptance_gate, "PINNED_CONTROLLER_INSTALLATION_ID", 54321)
    monkeypatch.setattr(acceptance_gate, "PINNED_KERNEL_READER_APP_ID", 24680)
    monkeypatch.setattr(acceptance_gate, "PINNED_EXTERNAL_GATE_AUTHOR_APP_ID", 13570)
    calls: list[dict[str, Any]] = []

    def record(*args: Any, **kwargs: Any) -> None:
        assert args == ("installation-token",)
        calls.append(kwargs)

    monkeypatch.setattr(
        acceptance_gate,
        "_verify_single_repository_app_authority",
        record,
    )
    if authority_kind == "controller":
        monkeypatch.setattr(acceptance_gate, "CONTROLLER_AUTHORITY_STATUS", "pinned")
        acceptance_gate._verify_controller_token_authority(
            "installation-token",
            app_jwt="app-jwt",
            app_id=98765,
            app_slug="phase5e-controller",
            installation_id=54321,
        )
        assert calls[0]["label"] == "controller"
        assert calls[0]["expected_repository"] == acceptance_gate.CONTROLLER_REPOSITORY
        assert calls[0]["expected_permissions"] == acceptance_gate.CONTROLLER_PERMISSIONS
    else:
        monkeypatch.setattr(acceptance_gate, "EXTERNAL_GATE_AUTHORITY_STATUS", "pinned")
        monkeypatch.setattr(acceptance_gate, "PINNED_EXTERNAL_GATE_AUTHOR_APP_ID", 13570)
        monkeypatch.setattr(
            acceptance_gate,
            "PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG",
            "phase5e-gate-author",
        )
        monkeypatch.setattr(
            acceptance_gate,
            "PINNED_EXTERNAL_GATE_AUTHOR_INSTALLATION_ID",
            97531,
        )
        acceptance_gate._verify_external_gate_author_token_authority(
            "installation-token",
            app_jwt="app-jwt",
            app_id=13570,
            app_slug="phase5e-gate-author",
            installation_id=97531,
        )
        assert calls[0]["label"] == "external gate-author"
        assert calls[0]["expected_repository"] == acceptance_gate.CONTROLLER_REPOSITORY
        assert calls[0]["expected_permissions"] == {
            "contents": "write",
            "metadata": "read",
            "pull_requests": "write",
        }
    assert calls[0]["app_jwt"] == "app-jwt"


@pytest.mark.parametrize(
    "attack",
    (
        "contents_write",
        "extra_permission",
        "nonempty_events",
        "suspended",
        "all_repositories",
        "wrong_account",
        "wrong_repository",
        "public_repository",
        "archived_repository",
        "two_repositories",
        "public_app",
        "two_global_installations",
        "wrong_app_owner",
        "direct_repository_drift",
    ),
)
def test_kernel_reader_authority_rejects_scope_permission_and_identity_drift(
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    monkeypatch.setattr(acceptance_gate, "KERNEL_READER_AUTHORITY_STATUS", "pinned")
    monkeypatch.setattr(acceptance_gate, "PINNED_KERNEL_READER_APP_ID", 24680)
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_KERNEL_READER_APP_SLUG",
        "phase5e-kernel-reader",
    )
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_KERNEL_READER_INSTALLATION_ID",
        13579,
    )
    monkeypatch.setattr(
        acceptance_gate,
        "_unauthenticated_app_http_status",
        lambda app_slug: 200 if attack == "public_app" else 404,
    )
    repository = {
        "id": acceptance_gate.KERNEL_READER_REPOSITORY_ID,
        "full_name": acceptance_gate.KERNEL_READER_REPOSITORY,
        "private": attack != "public_repository",
        "fork": False,
        "archived": attack == "archived_repository",
        "disabled": False,
        "default_branch": "main",
        "owner": {
            "id": acceptance_gate.KERNEL_READER_ACCOUNT_ID,
            "login": acceptance_gate.KERNEL_READER_ACCOUNT_LOGIN,
            "type": acceptance_gate.KERNEL_READER_ACCOUNT_TYPE,
        },
    }
    if attack == "wrong_repository":
        repository["id"] = 1

    permissions = dict(acceptance_gate.KERNEL_READER_PERMISSIONS)
    if attack == "contents_write":
        permissions["contents"] = "write"
    elif attack == "extra_permission":
        permissions["actions"] = "read"

    def api(url: str, token: str) -> dict[str, Any]:
        bare = url.split("?", 1)[0]
        if bare == "https://api.github.com/app":
            assert token == "app-jwt"
            return {
                "id": 24680,
                "slug": "phase5e-kernel-reader",
                "owner": {
                    "id": (
                        1
                        if attack == "wrong_app_owner"
                        else acceptance_gate.KERNEL_READER_ACCOUNT_ID
                    ),
                    "login": acceptance_gate.KERNEL_READER_ACCOUNT_LOGIN,
                    "type": acceptance_gate.KERNEL_READER_ACCOUNT_TYPE,
                },
                "permissions": permissions,
                "events": ["push"] if attack == "nonempty_events" else [],
            }
        if bare == "https://api.github.com/app/installations":
            assert token == "app-jwt"
            installations = [
                {
                    "id": 13579,
                    "app_id": 24680,
                    "app_slug": "phase5e-kernel-reader",
                    "account": {
                        "id": (
                            1
                            if attack == "wrong_account"
                            else acceptance_gate.KERNEL_READER_ACCOUNT_ID
                        ),
                        "login": acceptance_gate.KERNEL_READER_ACCOUNT_LOGIN,
                        "type": acceptance_gate.KERNEL_READER_ACCOUNT_TYPE,
                    },
                    "target_type": acceptance_gate.KERNEL_READER_ACCOUNT_TYPE,
                    "repository_selection": (
                        "all" if attack == "all_repositories" else "selected"
                    ),
                    "permissions": permissions,
                    "events": ["push"] if attack == "nonempty_events" else [],
                    "suspended_at": (
                        "2026-07-22T00:00:00Z" if attack == "suspended" else None
                    ),
                    "suspended_by": (
                        {"login": "owner"} if attack == "suspended" else None
                    ),
                }
            ]
            if attack == "two_global_installations":
                installations.append({**installations[0], "id": 13580})
            return installations
        assert token == "kernel-token"
        if bare == "https://api.github.com/installation/repositories":
            repositories = [repository]
            if attack == "two_repositories":
                repositories.append({**repository, "id": repository["id"] + 1})
            return {
                "total_count": len(repositories),
                "repositories": repositories,
                "repository_selection": "selected",
            }
        if bare == f"https://api.github.com/repos/{acceptance_gate.KERNEL_READER_REPOSITORY}":
            return (
                {**repository, "default_branch": "other"}
                if attack == "direct_repository_drift"
                else repository
            )
        raise AssertionError(url)

    def paginated(url: str, token: str) -> list[dict[str, Any]]:
        value = api(url, token)
        assert isinstance(value, list)
        return value

    monkeypatch.setattr(acceptance_gate, "_api_json", api)
    monkeypatch.setattr(acceptance_gate, "_api_paginated_list", paginated)
    with pytest.raises(SystemExit, match="kernel-reader"):
        acceptance_gate._verify_kernel_reader_token_authority(
            "kernel-token",
            app_jwt="app-jwt",
            app_id=24680,
            app_slug="phase5e-kernel-reader",
            installation_id=13579,
        )


def test_kernel_reader_authority_accepts_exact_single_repository_read_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(acceptance_gate, "KERNEL_READER_AUTHORITY_STATUS", "pinned")
    monkeypatch.setattr(acceptance_gate, "PINNED_KERNEL_READER_APP_ID", 24680)
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_KERNEL_READER_APP_SLUG",
        "phase5e-kernel-reader",
    )
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_KERNEL_READER_INSTALLATION_ID",
        13579,
    )
    monkeypatch.setattr(
        acceptance_gate,
        "_unauthenticated_app_http_status",
        lambda app_slug: 404,
    )
    repository = {
        "id": acceptance_gate.KERNEL_READER_REPOSITORY_ID,
        "full_name": acceptance_gate.KERNEL_READER_REPOSITORY,
        "private": True,
        "fork": False,
        "archived": False,
        "disabled": False,
        "default_branch": "main",
        "owner": {
            "id": acceptance_gate.KERNEL_READER_ACCOUNT_ID,
            "login": acceptance_gate.KERNEL_READER_ACCOUNT_LOGIN,
            "type": acceptance_gate.KERNEL_READER_ACCOUNT_TYPE,
        },
    }

    def api(url: str, token: str) -> dict[str, Any]:
        bare = url.split("?", 1)[0]
        if bare == "https://api.github.com/app":
            assert token == "app-jwt"
            return {
                "id": 24680,
                "slug": "phase5e-kernel-reader",
                "owner": {
                    "id": acceptance_gate.KERNEL_READER_ACCOUNT_ID,
                    "login": acceptance_gate.KERNEL_READER_ACCOUNT_LOGIN,
                    "type": acceptance_gate.KERNEL_READER_ACCOUNT_TYPE,
                },
                "permissions": dict(acceptance_gate.KERNEL_READER_PERMISSIONS),
                "events": [],
            }
        if bare == "https://api.github.com/app/installations":
            assert token == "app-jwt"
            return [
                {
                    "id": 13579,
                    "app_id": 24680,
                    "app_slug": "phase5e-kernel-reader",
                    "account": {
                        "id": acceptance_gate.KERNEL_READER_ACCOUNT_ID,
                        "login": acceptance_gate.KERNEL_READER_ACCOUNT_LOGIN,
                        "type": acceptance_gate.KERNEL_READER_ACCOUNT_TYPE,
                    },
                    "target_type": acceptance_gate.KERNEL_READER_ACCOUNT_TYPE,
                    "repository_selection": "selected",
                    "permissions": dict(acceptance_gate.KERNEL_READER_PERMISSIONS),
                    "events": [],
                    "suspended_at": None,
                    "suspended_by": None,
                }
            ]
        assert token == "kernel-token"
        if bare == "https://api.github.com/installation/repositories":
            return {
                "total_count": 1,
                "repositories": [repository],
                "repository_selection": "selected",
            }
        if bare == f"https://api.github.com/repos/{acceptance_gate.KERNEL_READER_REPOSITORY}":
            return repository
        raise AssertionError(url)

    def paginated(url: str, token: str) -> list[dict[str, Any]]:
        value = api(url, token)
        assert isinstance(value, list)
        return value

    monkeypatch.setattr(acceptance_gate, "_api_json", api)
    monkeypatch.setattr(acceptance_gate, "_api_paginated_list", paginated)
    acceptance_gate._verify_kernel_reader_token_authority(
        "kernel-token",
        app_jwt="app-jwt",
        app_id=24680,
        app_slug="phase5e-kernel-reader",
        installation_id=13579,
    )


@pytest.mark.parametrize(
    "attack",
    (
        None,
        "human_author",
        "two_commits",
        "unverified",
        "wrong_parent",
        "wrong_author_app",
        "wrong_tree",
        "wrong_pr_ref",
        "future_approval",
        "expired_before_pr",
        "wrong_app_metadata",
    ),
)
def test_external_controller_handoff_requires_the_pinned_author_app(
    monkeypatch: pytest.MonkeyPatch,
    attack: str | None,
) -> None:
    base = "a" * 40
    head = "b" * 40
    tree = "c" * 40
    bot = {
        "id": 24681,
        "login": "phase5e-gate-author[bot]",
        "type": "Bot",
        "site_admin": False,
    }
    handoff = {
        "approved_at": "2026-07-21T00:59:00Z",
        "receipt_bindings": [
            {"payload": {"expires_at": "2026-07-22T00:00:00Z"}}
            for _ in range(3)
        ],
        "controller_app_id": 98765,
        "controller_app_slug": "phase5e-controller",
        "controller_installation_id": 54321,
        "author_app_id": 24680,
        "author_app_slug": "phase5e-gate-author",
        "author_installation_id": 13579,
    }
    if attack == "wrong_author_app":
        handoff["author_app_id"] = 24682
    elif attack == "future_approval":
        handoff["approved_at"] = "2030-07-21T00:59:00Z"
    elif attack == "expired_before_pr":
        handoff["receipt_bindings"] = [
            {"payload": {"expires_at": "2026-07-21T01:01:30Z"}}
            for _ in range(3)
        ]
    monkeypatch.setattr(acceptance_gate, "EXTERNAL_GATE_AUTHORITY_STATUS", "pinned")
    monkeypatch.setattr(acceptance_gate, "PINNED_EXTERNAL_GATE_AUTHOR_APP_ID", 24680)
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG",
        "phase5e-gate-author",
    )
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_EXTERNAL_GATE_AUTHOR_INSTALLATION_ID",
        13579,
    )
    monkeypatch.setattr(
        acceptance_gate,
        "_unauthenticated_app_http_status",
        lambda app_slug: 404,
    )
    monkeypatch.setattr(acceptance_gate, "_read_json", lambda *args: handoff)
    monkeypatch.setattr(
        acceptance_gate,
        "_commit_parents",
        lambda *args: (("d" * 40,) if attack == "wrong_parent" else (base,)),
    )
    monkeypatch.setattr(acceptance_gate, "_tree", lambda *args: tree)

    def api_json(url: str, token: str) -> dict[str, Any]:
        assert token == "token"
        if url.endswith("/apps/phase5e-gate-author"):
            return {
                "id": 24682 if attack == "wrong_app_metadata" else 24680,
                "slug": "phase5e-gate-author",
                "owner": {
                    "id": 263841576,
                    "login": "mingjiconnect-ctrl",
                    "type": "User",
                },
                "permissions": {
                    "contents": "write",
                    "metadata": "read",
                    "pull_requests": "write",
                },
                "events": [],
            }
        if url.endswith("/pulls/77"):
            user = dict(bot)
            if attack == "human_author":
                user.update({"login": "owner", "type": "User"})
            return {
                "number": 77,
                "state": "open",
                "draft": False,
                "merged": False,
                "closed_at": None,
                "merged_at": None,
                "commits": 2 if attack == "two_commits" else 1,
                "created_at": "2026-07-21T01:02:00Z",
                "user": user,
                "head": {
                    "sha": head,
                    "ref": (
                        "feature/wrong-branch"
                        if attack == "wrong_pr_ref"
                        else acceptance_gate.EXTERNAL_CONTROLLER_BRANCH
                    ),
                    "repo": {"full_name": REPOSITORY_SLUG},
                },
                "base": {
                    "sha": base,
                    "ref": "main",
                    "repo": {"full_name": REPOSITORY_SLUG},
                },
            }
        if url.endswith(f"/commits/{head}"):
            return {
                "sha": head,
                "author": dict(bot),
                "committer": dict(bot),
                "parents": [{"sha": base}],
                "commit": {
                    "tree": {"sha": "d" * 40 if attack == "wrong_tree" else tree},
                    "committer": {"date": "2026-07-21T01:00:00Z"},
                    "verification": {
                        "verified": attack != "unverified",
                        "reason": "valid" if attack != "unverified" else "unsigned",
                        "signature": "signature",
                        "payload": "payload",
                        "verified_at": "2026-07-21T01:01:00Z",
                    },
                },
            }
        raise AssertionError(url)

    monkeypatch.setattr(acceptance_gate, "_api_json", api_json)
    monkeypatch.setattr(
        acceptance_gate,
        "_api_list",
        lambda url, token: [{"sha": head}],
    )
    def call() -> None:
        acceptance_gate._verify_external_controller_handoff_remote(
            repository=Path("/unused"),
            repository_slug=REPOSITORY_SLUG,
            token="token",
            base=base,
            head=head,
            event={"number": 77},
            controller_app_id=98765,
            controller_app_slug="phase5e-controller",
            controller_installation_id=54321,
        )
    if attack is None:
        call()
    else:
        with pytest.raises(SystemExit):
            call()


def test_external_controller_handoff_is_blocked_until_author_app_is_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(acceptance_gate, "EXTERNAL_GATE_AUTHORITY_STATUS", "bootstrap_pending")
    with pytest.raises(SystemExit, match="bootstrap is still pending"):
        acceptance_gate._verify_external_controller_handoff_remote(
            repository=Path("/unused"),
            repository_slug=REPOSITORY_SLUG,
            token="unused",
            base="a" * 40,
            head="b" * 40,
            event={"number": 77},
            controller_app_id=98765,
            controller_app_slug="phase5e-controller",
            controller_installation_id=54321,
        )


@pytest.mark.parametrize(
    ("merged_at", "accepted"),
    (
        ("2026-07-21T02:00:00Z", True),
        ("2026-07-23T00:00:01Z", False),
    ),
)
def test_external_handoff_merge_must_land_within_every_signed_receipt_ttl(
    merged_at: str,
    accepted: bool,
) -> None:
    handoff = {
        "approved_at": "2026-07-21T00:59:00Z",
        "receipt_bindings": [
            {"payload": {"expires_at": "2026-07-23T00:00:00Z"}}
            for _ in range(3)
        ],
    }
    pull_request = {
        "created_at": "2026-07-21T01:02:00Z",
        "merged_at": merged_at,
    }
    if accepted:
        acceptance_gate._verify_external_handoff_merge_window(
            handoff=handoff,
            pull_request=pull_request,
        )
    else:
        with pytest.raises(SystemExit, match="signed receipt validity window"):
            acceptance_gate._verify_external_handoff_merge_window(
                handoff=handoff,
                pull_request=pull_request,
            )


@pytest.mark.parametrize(
    ("app_id", "app_slug", "installation_id"),
    (
        (24681, "phase5e-kernel-reader", 13579),
        (24680, "replacement", 13579),
        (24680, "phase5e-kernel-reader", 13580),
    ),
)
def test_kernel_reader_authority_rejects_action_output_drift(
    monkeypatch: pytest.MonkeyPatch,
    app_id: int,
    app_slug: str,
    installation_id: int,
) -> None:
    monkeypatch.setattr(acceptance_gate, "KERNEL_READER_AUTHORITY_STATUS", "pinned")
    monkeypatch.setattr(acceptance_gate, "PINNED_KERNEL_READER_APP_ID", 24680)
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_KERNEL_READER_APP_SLUG",
        "phase5e-kernel-reader",
    )
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_KERNEL_READER_INSTALLATION_ID",
        13579,
    )
    with pytest.raises(SystemExit, match="action outputs"):
        acceptance_gate._verify_kernel_reader_token_authority(
            "kernel-token",
            app_jwt="app-jwt",
            app_id=app_id,
            app_slug=app_slug,
            installation_id=installation_id,
        )


def test_kernel_reader_may_not_reuse_external_author_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(acceptance_gate, "KERNEL_READER_AUTHORITY_STATUS", "pinned")
    monkeypatch.setattr(acceptance_gate, "PINNED_KERNEL_READER_APP_ID", 24680)
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_KERNEL_READER_APP_SLUG",
        "phase5e-kernel-reader",
    )
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_KERNEL_READER_INSTALLATION_ID",
        13579,
    )
    monkeypatch.setattr(
        acceptance_gate,
        "PINNED_EXTERNAL_GATE_AUTHOR_APP_ID",
        24680,
    )
    with pytest.raises(SystemExit, match="action outputs"):
        acceptance_gate._verify_kernel_reader_token_authority(
            "kernel-token",
            app_jwt="app-jwt",
            app_id=24680,
            app_slug="phase5e-kernel-reader",
            installation_id=13579,
        )


def test_secret_inventory_reads_the_complete_second_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def secret(name: str) -> dict[str, str]:
        return {
            "name": name,
            "created_at": "2026-07-16T00:00:00Z",
            "updated_at": "2026-07-16T00:00:00Z",
        }

    def api(url: str, token: str) -> dict[str, Any]:
        assert token == "token"
        if url.endswith("page=1"):
            return {"total_count": 101, "secrets": [secret(f"S{index}") for index in range(100)]}
        if url.endswith("page=2"):
            return {
                "total_count": 101,
                "secrets": [
                    secret(acceptance_gate.KERNEL_READER_PRIVATE_KEY_SECRET)
                ],
            }
        raise AssertionError(url)

    monkeypatch.setattr(acceptance_gate, "_api_json", api)
    assert (
        acceptance_gate.KERNEL_READER_PRIVATE_KEY_SECRET
        in acceptance_gate._secret_inventory(
        "https://api.github.com/repos/owner/research/actions/secrets",
        "token",
        )
    )


def test_variable_inventory_reads_the_complete_second_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def variable(name: str, value: str) -> dict[str, str]:
        return {
            "name": name,
            "value": value,
            "created_at": "2026-07-16T00:00:00Z",
            "updated_at": "2026-07-16T00:00:00Z",
        }

    def api(url: str, token: str) -> dict[str, Any]:
        assert token == "token"
        if url.endswith("page=1"):
            return {
                "total_count": 31,
                "variables": [variable(f"V{index}", str(index)) for index in range(30)],
            }
        if url.endswith("page=2"):
            return {
                "total_count": 31,
                "variables": [variable(acceptance_gate.CONTROLLER_APP_ID_VARIABLE, "98765")],
            }
        raise AssertionError(url)

    monkeypatch.setattr(acceptance_gate, "_api_json", api)
    values = acceptance_gate._variable_inventory(
        "https://api.github.com/repos/owner/research/actions/variables",
        "token",
    )
    assert values[acceptance_gate.CONTROLLER_APP_ID_VARIABLE] == "98765"


@pytest.mark.parametrize(
    ("attack", "expected"),
    (
        ("duplicate", "duplicate names"),
        ("total_drift", "total count drifted"),
        ("early_short", "ended before"),
        ("boolean_total", "metadata is malformed"),
    ),
)
def test_paginated_authority_inventory_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
    expected: str,
) -> None:
    def secret(name: str) -> dict[str, str]:
        return {
            "name": name,
            "created_at": "2026-07-16T00:00:00Z",
            "updated_at": "2026-07-16T00:00:00Z",
        }

    def api(url: str, token: str) -> dict[str, Any]:
        assert token == "token"
        if attack == "boolean_total":
            return {"total_count": True, "secrets": []}
        if attack == "early_short":
            return {"total_count": 101, "secrets": [secret("only-one")]}
        if url.endswith("page=1"):
            return {"total_count": 101, "secrets": [secret(f"S{index}") for index in range(100)]}
        if attack == "total_drift":
            return {"total_count": 102, "secrets": [secret("last")]}
        return {"total_count": 101, "secrets": [secret("S0")]}

    monkeypatch.setattr(acceptance_gate, "_api_json", api)
    with pytest.raises(SystemExit, match=expected):
        acceptance_gate._secret_inventory(
            "https://api.github.com/repos/owner/research/actions/secrets",
            "token",
        )


def test_paginated_resource_ids_must_be_unique_across_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def api(url: str, token: str) -> dict[str, Any]:
        assert token == "token"
        if url.endswith("page=1"):
            return {
                "total_count": 101,
                "environments": [{"id": index} for index in range(1, 101)],
            }
        return {"total_count": 101, "environments": [{"id": 1}]}

    monkeypatch.setattr(acceptance_gate, "_api_json", api)
    with pytest.raises(SystemExit, match="pagination identity is ambiguous"):
        acceptance_gate._api_paginated_collection(
            "https://api.github.com/repos/owner/research/environments",
            "token",
            collection_key="environments",
            per_page=100,
            identity_key="id",
        )


def test_artifact_storage_may_not_redirect_a_second_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed = "https://audit.blob.core.windows.net/container/report.zip?sig=redacted"

    class RedirectingOpener:
        calls = 0

        def open(self, request: Any, timeout: int) -> Any:
            assert timeout == 30
            self.calls += 1
            if self.calls == 1:
                raise urllib.error.HTTPError(
                    request.full_url,
                    302,
                    "redirect",
                    {"Location": signed},
                    None,
                )
            raise urllib.error.HTTPError(
                signed,
                302,
                "second redirect",
                {"Location": "https://untrusted.invalid/report.zip"},
                None,
            )

    opener = RedirectingOpener()
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: opener)
    with pytest.raises(SystemExit, match="second redirect"):
        acceptance_gate._api_bytes(
            "https://api.github.com/repos/owner/research/actions/artifacts/1/zip",
            "token",
        )


@pytest.mark.parametrize(
    ("delete_status", "probe_status", "accepted"),
    (
        (204, 401, True),
        (200, 401, False),
        (403, 401, False),
        (204, 200, False),
        (204, 403, False),
        (204, 302, False),
    ),
)
def test_hard_revoke_requires_delete_204_then_same_token_get_401(
    monkeypatch: pytest.MonkeyPatch,
    delete_status: int,
    probe_status: int,
    accepted: bool,
) -> None:
    calls: list[tuple[str, str]] = []

    class Response:
        def __init__(self, status: int) -> None:
            self.status = status

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    class Opener:
        def open(self, request: Any, timeout: int) -> Any:
            assert timeout == 30
            calls.append((request.get_method(), request.headers["Authorization"]))
            status = delete_status if request.get_method() == "DELETE" else probe_status
            if status >= 300:
                raise urllib.error.HTTPError(
                    request.full_url,
                    status,
                    "expected test response",
                    {},
                    None,
                )
            return Response(status)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    if accepted:
        acceptance_gate._hard_revoke_installation_token("secret-token")
    else:
        with pytest.raises(SystemExit):
            acceptance_gate._hard_revoke_installation_token("secret-token")
    expected_calls = [("DELETE", "Bearer secret-token")]
    if delete_status == 204:
        expected_calls.append(("GET", "Bearer secret-token"))
    assert calls == expected_calls


def test_controller_status_must_bind_the_exact_head_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statuses = _controller_status_fixture(
        head_sha="f" * 40,
        workflow_run_id="1",
    )
    monkeypatch.setattr(
        acceptance_gate,
        "_api_paginated_list",
        lambda url, token: statuses,
    )
    with pytest.raises(SystemExit, match="status identity drifted"):
        acceptance_gate._verify_controller_statuses(
            repository_slug=REPOSITORY_SLUG,
            token="token",
            head_sha="e" * 40,
            workflow_run_id="1",
            app_slug="phase5e-controller",
        )


@pytest.mark.parametrize(
    "attack",
    (
        "missing",
        "pending",
        "failure",
        "wrong_head",
        "wrong_target",
        "wrong_creator_login",
        "wrong_creator_type",
        "boolean_id",
        "duplicate_id",
        "newer_failure",
    ),
)
def test_actions_revocation_status_is_latest_exact_and_actions_owned(
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    head = "e" * 40
    statuses = _controller_status_fixture(head_sha=head, workflow_run_id="10")
    revocation = statuses[-1]
    if attack == "missing":
        statuses.pop()
    elif attack in {"pending", "failure"}:
        revocation["state"] = attack
    elif attack == "wrong_head":
        revocation["sha"] = "f" * 40
    elif attack == "wrong_target":
        revocation["target_url"] = (
            f"https://github.com/{REPOSITORY_SLUG}/actions/runs/11"
        )
    elif attack == "wrong_creator_login":
        revocation["creator"]["login"] = "phase5e-controller[bot]"
    elif attack == "wrong_creator_type":
        revocation["creator"]["type"] = "User"
    elif attack == "boolean_id":
        revocation["id"] = True
    elif attack == "duplicate_id":
        revocation["id"] = statuses[0]["id"]
    elif attack == "newer_failure":
        statuses.append(
            {
                **copy.deepcopy(revocation),
                "id": revocation["id"] + 1,
                "state": "failure",
            }
        )
    monkeypatch.setattr(
        acceptance_gate,
        "_api_paginated_list",
        lambda url, token: statuses,
    )
    with pytest.raises(SystemExit, match="status|revocation"):
        acceptance_gate._verify_controller_statuses(
            repository_slug=REPOSITORY_SLUG,
            token="token",
            head_sha=head,
            workflow_run_id="10",
            app_slug="phase5e-controller",
        )


def test_latest_successful_revocation_supersedes_older_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    head = "e" * 40
    statuses = _controller_status_fixture(head_sha=head, workflow_run_id="10")
    latest = statuses[-1]
    latest["id"] = 5
    statuses.insert(
        -1,
        {
            **copy.deepcopy(latest),
            "id": 4,
            "state": "failure",
        },
    )
    monkeypatch.setattr(
        acceptance_gate,
        "_api_paginated_list",
        lambda url, token: statuses,
    )
    acceptance_gate._verify_controller_statuses(
        repository_slug=REPOSITORY_SLUG,
        token="token",
        head_sha=head,
        workflow_run_id="10",
        app_slug="phase5e-controller",
    )


@pytest.mark.parametrize(
    "association_attack",
    (
        None,
        "old_head",
        "wrong_base",
        "same_head_failure",
        "incomplete_pagination",
    ),
)
def test_merged_main_replays_acceptance_pr_gate_and_main_ci_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    association_attack: str | None,
) -> None:
    repository, root_commit, implementation_head, implementation_merge = _repository(tmp_path)
    acceptance_head = _remote_evidence(
        repository=repository,
        root_commit=root_commit,
        implementation_head=implementation_head,
        implementation_merge=implementation_merge,
        monkeypatch=monkeypatch,
    )
    prior_api = acceptance_gate._api_json
    prior_list = acceptance_gate._api_list
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "main"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge",
            "--no-ff",
            acceptance_head,
            "-m",
            "merge acceptance",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    merged_main = _git(repository, "rev-parse", "HEAD")
    acceptance_association = {
        "number": 77,
        "head": {
            "sha": acceptance_head,
            "ref": "feature/phase5e2b12a-acceptance-closeout",
            "repo": {"full_name": REPOSITORY_SLUG},
        },
        "base": {
            "sha": implementation_merge,
            "ref": "main",
            "repo": {"full_name": REPOSITORY_SLUG},
        },
    }
    successful_association = json.loads(json.dumps(acceptance_association))
    if association_attack == "old_head":
        successful_association["head"]["sha"] = implementation_head
    elif association_attack == "wrong_base":
        successful_association["base"]["sha"] = root_commit

    def post_merge_api(url: str, token: str) -> dict[str, Any]:
        if url.endswith("/pulls/77"):
            return {
                "number": 77,
                "state": "closed",
                "merged": True,
                "merged_at": "2026-07-16T01:00:00Z",
                "merge_commit_sha": merged_main,
                "base": {
                    "sha": implementation_merge,
                    "ref": "main",
                    "repo": {"full_name": REPOSITORY_SLUG},
                },
                "head": {
                    "sha": acceptance_head,
                    "ref": "feature/phase5e2b12a-acceptance-closeout",
                    "repo": {"full_name": REPOSITORY_SLUG},
                },
            }
        if url.endswith("/actions/runs/2000"):
            return {
                "id": 2000,
                "head_sha": merged_main,
                "head_branch": "main",
                "event": "push",
                "conclusion": "success",
                "name": "owner-research-ci",
                "path": ".github/workflows/ci.yml",
                "workflow_id": 123,
                "repository": {"full_name": REPOSITORY_SLUG},
                "head_repository": {"full_name": REPOSITORY_SLUG},
                "pull_requests": [],
            }
        if url.endswith("/actions/runs/1999"):
            return {
                "id": 1999,
                "head_sha": implementation_merge,
                "head_branch": "main",
                "event": "pull_request_target",
                "conclusion": "success",
                "name": "phase5e2b12a-base-owned-acceptance-gate",
                "path": ".github/workflows/phase5e2b12a-acceptance-gate.yml",
                "workflow_id": 456,
                "repository": {"full_name": REPOSITORY_SLUG},
                "head_repository": {"full_name": REPOSITORY_SLUG},
                "pull_requests": [successful_association],
            }
        if url.endswith("/actions/workflows/456"):
            return {
                "id": 456,
                "path": ".github/workflows/phase5e2b12a-acceptance-gate.yml",
                "name": "phase5e2b12a-base-owned-acceptance-gate",
                "state": "active",
            }
        if url.endswith("/actions/workflows/123"):
            return {
                "id": 123,
                "path": ".github/workflows/ci.yml",
                "name": "owner-research-ci",
                "state": "active",
            }
        if "phase5e2b12a-acceptance-gate.yml/runs?" in url:
            workflow_runs = [
                {
                    "id": 1999,
                    "head_sha": implementation_merge,
                    "conclusion": "success",
                    "name": "phase5e2b12a-base-owned-acceptance-gate",
                    "path": ".github/workflows/phase5e2b12a-acceptance-gate.yml",
                    "pull_requests": [successful_association],
                }
            ]
            if association_attack is not None:
                workflow_runs.append(
                    {
                        "id": 2001,
                        "head_sha": implementation_merge,
                        "conclusion": "failure",
                        "name": "phase5e2b12a-base-owned-acceptance-gate",
                        "path": ".github/workflows/phase5e2b12a-acceptance-gate.yml",
                        "pull_requests": [acceptance_association],
                    }
                )
            return {
                "total_count": (
                    len(workflow_runs) + 1
                    if association_attack == "incomplete_pagination"
                    else len(workflow_runs)
                ),
                "workflow_runs": workflow_runs,
            }
        return prior_api(url, token)

    def post_merge_list(url: str, token: str) -> list[dict[str, Any]]:
        if f"/commits/{acceptance_head}/statuses?" in url:
            return _controller_status_fixture(
                head_sha=acceptance_head,
                workflow_run_id="1999",
                start_id=100,
            )
        return prior_list(url, token)

    monkeypatch.setattr(acceptance_gate, "_api_json", post_merge_api)
    monkeypatch.setattr(acceptance_gate, "_api_list", post_merge_list)
    if association_attack is None:
        assert acceptance_gate.verify_merged_main_acceptance(
            repository=repository,
            merged_main=merged_main,
            repository_slug=REPOSITORY_SLUG,
            token="token",
            triggering_ci_run_id="2000",
            controller_app_id=98765,
        )
    else:
        with pytest.raises(SystemExit, match="workflow.*run|pagination"):
            acceptance_gate.verify_merged_main_acceptance(
                repository=repository,
                merged_main=merged_main,
                repository_slug=REPOSITORY_SLUG,
                token="token",
                triggering_ci_run_id="2000",
                controller_app_id=98765,
            )


def test_merged_main_rejects_tree_not_equal_to_acceptance_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, root_commit, implementation_head, implementation_merge = _repository(tmp_path)
    acceptance_head = _remote_evidence(
        repository=repository,
        root_commit=root_commit,
        implementation_head=implementation_head,
        implementation_merge=implementation_merge,
        monkeypatch=monkeypatch,
    )
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "main"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "-C", str(repository), "merge", "--no-ff", "--no-commit", acceptance_head],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    (repository / "src/frozen.py").write_text("VALUE = 999\n", encoding="utf-8")
    merged_main = _commit(repository, "malicious merge acceptance")
    with pytest.raises(SystemExit, match="tree differs from the acceptance"):
        acceptance_gate.verify_merged_main_acceptance(
            repository=repository,
            merged_main=merged_main,
            repository_slug=REPOSITORY_SLUG,
            token="token",
            triggering_ci_run_id="2000",
            controller_app_id=98765,
        )


@pytest.mark.parametrize(
    ("case", "expected"),
    (
        ("missing_report", "exact bounded one-report bundle"),
        ("missing_check", "bounded evidence"),
        ("duplicate_check", "bounded evidence"),
        ("forged_check_evidence", "bounded evidence"),
        ("incomplete_audit", "omits acceptance trust-root files"),
        ("wrong_workflow", "expected successful head"),
        ("workflow_path_suffix", "expected successful head"),
        ("wrong_workflow_ref", "expected successful head"),
        ("wrong_workflow_metadata", "workflow identity"),
        ("wrong_pull_request", "pull request identity does not replay"),
        ("wrong_pull_request_base", "pull request identity does not replay"),
        ("unknown_report_field", "unknown or missing field"),
        ("boolean_finding_count", "finding counts"),
        ("boolean_test_count", "test counts"),
        ("floating_test_count", "test counts"),
        ("nonlist_ci_run_ids", "CI run identities"),
        ("duplicate_report_json", "duplicate JSON key"),
        ("nonfinite_report_json", "non-finite JSON constant"),
        ("overflow_report_json", "non-finite JSON number"),
        ("compact_report_json", "canonically serialized"),
        ("nested_artifact_member", "exact bounded one-report bundle"),
        ("incomplete_artifact_pagination", "pagination is incomplete"),
        ("missing_runtime", "exactly three runtime results"),
        ("duplicate_runtime", "protected matrix"),
        ("runtime_version_drift", "protected matrix"),
        ("raw_evidence_hash", "unknown or missing field"),
    ),
)
def test_remote_gate_rejects_incomplete_or_wrongly_identified_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected: str,
) -> None:
    repository, root_commit, implementation_head, base = _repository(tmp_path)
    kwargs: dict[str, Any] = {}
    if case in {
        "missing_report",
        "missing_check",
        "duplicate_check",
        "forged_check_evidence",
        "unknown_report_field",
        "boolean_finding_count",
        "boolean_test_count",
        "floating_test_count",
        "nonlist_ci_run_ids",
        "missing_runtime",
        "duplicate_runtime",
        "runtime_version_drift",
        "raw_evidence_hash",
    }:
        kwargs["report_mode"] = case
    elif case == "incomplete_audit":
        kwargs["omit_audited_path"] = True
    elif case == "wrong_workflow":
        kwargs["run_mutation"] = (
            "path",
            ".github/workflows/attacker.yml@refs/heads/main",
        )
    elif case == "workflow_path_suffix":
        kwargs["run_mutation"] = (
            "path",
            ".github/workflows/phase5e2b12a-acceptance-gate.yml@evil",
        )
    elif case == "wrong_workflow_ref":
        kwargs["run_mutation"] = ("head_branch", "attacker")
    elif case == "wrong_workflow_metadata":
        kwargs["workflow_mutation"] = ("path", ".github/workflows/attacker.yml")
    elif case == "wrong_pull_request":
        kwargs["pull_request_mutation"] = (
            "head",
            {
                "sha": "f" * 40,
                "ref": "fix/phase5e2b12a-r2-coverage-claim-parity",
                "repo": {"full_name": REPOSITORY_SLUG},
            },
        )
    elif case == "wrong_pull_request_base":
        kwargs["pull_request_mutation"] = (
            "base",
            {
                "sha": implementation_head,
                "ref": "main",
                "repo": {"full_name": REPOSITORY_SLUG},
            },
        )
    elif case == "duplicate_report_json":
        kwargs["report_mode"] = "duplicate_report_key"
    elif case == "nonfinite_report_json":
        kwargs["report_mode"] = "nonfinite_report_json"
    elif case == "overflow_report_json":
        kwargs["report_mode"] = "overflow_report_json"
    elif case == "compact_report_json":
        kwargs["report_mode"] = "compact_report"
    elif case == "nested_artifact_member":
        kwargs["archive_prefix"] = "nested/"
    elif case == "incomplete_artifact_pagination":
        kwargs["artifact_total_count"] = 2
    head = _remote_evidence(
        repository=repository,
        root_commit=root_commit,
        implementation_head=implementation_head,
        implementation_merge=base,
        monkeypatch=monkeypatch,
        **kwargs,
    )
    with pytest.raises(SystemExit, match=expected):
        verify_acceptance(
            repository=repository,
            base=base,
            head=head,
            event=None,
            repository_slug=REPOSITORY_SLUG,
            token="token",
            require_remote=True,
            controller_app_id=98765,
        )
