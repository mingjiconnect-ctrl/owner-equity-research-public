from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from scripts import run_phase5e_audit as audit_runner
from scripts import verify_phase5e2b12a_acceptance_gate as acceptance_gate_2a
from scripts import verify_phase5e2b12a_semantic_oracle as semantic_oracle_2a
from scripts import verify_phase5e2b12b_semantic_oracle as semantic_oracle_2b
from scripts import verify_phase5e_audit_runtime_matrix as runtime_matrix
from scripts import verify_phase5e_candidate_import_surface as import_surface
from scripts.public_bootstrap import commit_exists, verify_public_bootstrap_snapshot
from scripts.run_phase5e_audit import (
    CONTROL_ORACLE_FIXED_PATHS,
    EXPECTED_AUDIT_CHECK_IDS,
    PHASE5E2B12A_ACCEPTANCE_CLOSEOUT_PATH,
    PHASE5E2B12A_ALLOWED_CHANGED_PATHS,
    PHASE5E2B12A_OPTIONAL_CHANGED_PATHS,
    STATIC_CONTROL_FILES,
    _has_blocking_findings,
    _phase5e2b12a_changed_path_violations,
    _run_dynamic_successor_oracles,
    _strict_junit_tree,
    _verify_profile_semantic_oracle_binding,
)
from scripts.verify_phase5e2b12a_integration_contracts import (
    PUBLIC_CANONICAL_MIGRATION_CHANGED_PATHS,
    PUBLIC_CANONICAL_MIGRATION_OPTIONAL_CHANGED_PATHS,
)

ROOT = Path(__file__).parents[1]
WRITER = ROOT / "scripts" / "write_phase5e_audit.py"


@pytest.mark.parametrize(
    "resolver_failure",
    (
        ValueError("corrupt recursive gate"),
        subprocess.CalledProcessError(2, ["git", "show"]),
    ),
    ids=("recursive-value-error", "recursive-git-error"),
)
def test_emergency_profile_resolution_failure_is_never_labeled_legacy_2a(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    resolver_failure: BaseException,
) -> None:
    def fail_resolution(*args: object, **kwargs: object) -> None:
        raise resolver_failure

    monkeypatch.setattr(
        audit_runner,
        "resolve_controller_audit_profile",
        fail_resolution,
    )
    output = tmp_path / "phase5e-audit.json"
    audit_runner._emergency_failure(
        [
            "--output",
            str(output),
            "--reviewed-commit",
            "a" * 40,
            "--runtime-id",
            "emergency-test",
        ],
        RuntimeError("primary audit failure"),
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["audit_profile"] == "phase5e-audit-profile-resolution-failed"
    assert payload["audit_profile"] != "phase5e2b12a"
    assert payload["check_ids"] == ["phase5e-audit-profile-resolution"]
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["priority"] == "P0"


def test_emergency_failure_writer_never_masks_the_primary_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_writer(*args: object, **kwargs: object) -> None:
        raise OSError("unwritable emergency destination")

    monkeypatch.setattr(audit_runner, "_write_emergency_failure", fail_writer)
    audit_runner._emergency_failure([], RuntimeError("primary audit failure"))


def _minimal_candidate_import_tree(root: Path) -> None:
    for relative in ("src/owner_research", "scripts", "tests"):
        (root / relative).mkdir(parents=True, exist_ok=True)


def test_candidate_import_surface_accepts_only_the_expected_project_roots(
    tmp_path: Path,
) -> None:
    _minimal_candidate_import_tree(tmp_path)
    (tmp_path / "src/owner_research/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "scripts/project_check.py").write_text("", encoding="utf-8")
    (tmp_path / "tests/test_project.py").write_text("", encoding="utf-8")
    import_surface.verify(tmp_path)


def test_control_oracle_launcher_and_runner_have_one_exact_fixed_inventory() -> None:
    launcher = (ROOT / "scripts/launch_phase5e_readonly_audit.sh").read_text(
        encoding="utf-8"
    )
    pairs = re.findall(
        r'install -m [0-9]+ "\$control_repo/([^"]+)" \\\n'
        r'  "\$runtime/oracle/([^"]+)"',
        launcher,
    )
    assert pairs
    assert all(source == target for source, target in pairs)
    staged = {target for _, target in pairs} | {"component-lock.json"}
    assert staged == set(CONTROL_ORACLE_FIXED_PATHS)
    assert {
        "docs/phase5-completion-overlay-v3.md",
        "scripts/phase5e-futu-market-authority-policy-v1.json",
        "scripts/phase5e2b12a-acceptance-trust.json",
        "scripts/public_bootstrap.py",
    } <= staged
    assert "scripts/verify_phase5e_candidate_import_surface.py" not in staged


def test_control_oracle_root_is_traversable_but_remains_root_owned_and_read_only() -> None:
    launcher = (ROOT / "scripts/launch_phase5e_readonly_audit.sh").read_text(
        encoding="utf-8"
    )
    assert 'install -d -m 0700 "$runtime/final"' in launcher
    assert 'install -d -m 0755 "$runtime/oracle"' in launcher
    assert 'install -d -m 0700 "$runtime/final" "$runtime/oracle"' not in launcher
    assert 'chown -R root:root "$runtime/final" "$runtime/oracle"' in launcher
    assert 'mount -o remount,ro,bind "$root/oracle"' in (
        ROOT / "scripts/phase5e_candidate_exec.sh"
    ).read_text(encoding="utf-8")


def test_dynamic_successor_behavior_never_starts_after_structural_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = {"behavior": 0}

    monkeypatch.setattr(
        audit_runner,
        "_run_direct",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 9, "blocked", None),
    )

    def forbidden_behavior(*args: object, **kwargs: object) -> None:
        calls["behavior"] += 1
        raise AssertionError("behavior oracle must not start")

    monkeypatch.setattr(audit_runner, "_run", forbidden_behavior)
    structural, behavior = _run_dynamic_successor_oracles(
        repository=tmp_path,
        controller_root=tmp_path,
        controller_ref="a" * 40,
        candidate_ref="b" * 40,
        profile=SimpleNamespace(semantic_oracle_path="scripts/oracle.py"),
        environment={},
        protected_mode=True,
        controller_integrity_passed=True,
    )
    assert structural.returncode == 9
    assert behavior is None
    assert calls["behavior"] == 0


def test_dynamic_successor_behavior_uses_the_bounded_oracle_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr(
        audit_runner,
        "_run_direct",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "ok", None),
    )

    def bounded_runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.append(command)
        return subprocess.CompletedProcess(command, 0, "ok", None)

    monkeypatch.setattr(audit_runner, "_run", bounded_runner)
    _, behavior = _run_dynamic_successor_oracles(
        repository=tmp_path,
        controller_root=tmp_path,
        controller_ref="a" * 40,
        candidate_ref="b" * 40,
        profile=SimpleNamespace(semantic_oracle_path="scripts/oracle.py"),
        environment={},
        protected_mode=True,
        controller_integrity_passed=True,
    )
    assert behavior is not None and behavior.returncode == 0
    assert captured == [
        [
            sys.executable,
            "-I",
            "/oracle/scripts/oracle.py",
            "--repository",
            str(tmp_path),
        ]
    ]


def test_dynamic_semantic_oracle_binds_policy_git_worktree_and_exposed_bytes(
    tmp_path: Path,
) -> None:
    controller = tmp_path / "controller"
    exposed = tmp_path / "oracle"
    (controller / "scripts").mkdir(parents=True)
    (exposed / "scripts").mkdir(parents=True)
    oracle = controller / "scripts/oracle.py"
    oracle.write_text("print('protected')\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(controller)], check=True)
    subprocess.run(["git", "-C", str(controller), "add", "scripts/oracle.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(controller),
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "oracle",
        ],
        check=True,
    )
    head = subprocess.check_output(
        ["git", "-C", str(controller), "rev-parse", "HEAD"], text=True
    ).strip()
    digest = hashlib.sha256(oracle.read_bytes()).hexdigest()
    exposed_oracle = exposed / "scripts/oracle.py"
    exposed_oracle.write_bytes(oracle.read_bytes())
    profile = SimpleNamespace(
        semantic_oracle_path="scripts/oracle.py",
        semantic_oracle_sha256=digest,
    )
    assert (
        _verify_profile_semantic_oracle_binding(
            controller_root=controller,
            controller_ref=head,
            profile=profile,
            oracle_root=exposed,
            oracle_manifest={"scripts/oracle.py": digest},
        )
        == digest
    )
    exposed_oracle.write_text("print('replaced')\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="sandbox semantic oracle"):
        _verify_profile_semantic_oracle_binding(
            controller_root=controller,
            controller_ref=head,
            profile=profile,
            oracle_root=exposed,
            oracle_manifest={"scripts/oracle.py": digest},
        )


@pytest.mark.parametrize(
    "relative",
    (
        "sitecustomize.py",
        "src/usercustomize/__init__.py",
        "src/jsonschema.py",
        "scripts/json.py",
        "tests/pytest.py",
        "tests/_pytest/__init__.py",
        "tests/yaml.cpython-311-x86_64-linux-gnu.so",
        "tests/json.cp313-win_amd64.pyd",
        "tests/pytest.cpython-313-darwin.dylib",
        "tests/injected.pth",
        "src/owner_research/pyvenv.cfg",
        "tests/__pycache__/sitecustomize.cpython-311.pyc",
    ),
)
def test_candidate_import_surface_rejects_startup_and_shadow_entries(
    tmp_path: Path,
    relative: str,
) -> None:
    _minimal_candidate_import_tree(tmp_path)
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\0" if path.suffix == ".so" else b"")
    with pytest.raises(SystemExit):
        import_surface.verify(tmp_path)


def test_candidate_import_surface_rejects_symlinks(tmp_path: Path) -> None:
    _minimal_candidate_import_tree(tmp_path)
    (tmp_path / "tests/target.py").write_text("", encoding="utf-8")
    (tmp_path / "tests/linked.py").symlink_to("target.py")
    with pytest.raises(SystemExit, match="unsafe import entry type"):
        import_surface.verify(tmp_path)


def _runtime_findings(
    *, runtime_id: str, python_version: str, nodeids: bytes, junit: bytes
) -> bytes:
    check_ids = ["independent-check"]
    payload = {
        "audit_tool": "owner-research-phase5e-readonly",
        "audit_profile": "phase5e2b12a",
        "audit_version": "2.3.2.3.3",
        "reviewed_commit": "a" * 40,
        "phase5d_baseline_commit": "b" * 40,
        "phase5e0_baseline_commit": "2" * 40,
        "phase5e11_baseline_commit": "3" * 40,
        "phase5e2a_baseline_commit": "e" * 40,
        "phase5e2b10_baseline_commit": "f" * 40,
        "phase5e2b11_baseline_commit": "1" * 40,
        "valuation_kernel_commit": "c" * 40,
        "runtime_identity": {
            "runtime_id": runtime_id,
            "python_version": python_version,
            "implementation": "CPython",
            "abi": runtime_id,
            "operating_system": "Linux",
            "architecture": "x86_64",
            "threading": "gil",
        },
        "audit_trust": {
            "controller_commit": "4" * 40,
            "controller_tree": "5" * 40,
            "candidate_tree": "6" * 40,
            "workflow_sha256": "1" * 64,
            "audit_controller_sha256": "2" * 64,
            "launcher_sha256": "3" * 64,
            "candidate_executor_sha256": "4" * 64,
            "semantic_oracle_sha256": "5" * 64,
            "audit_profile_context_sha256": "a" * 64,
            "audit_profile_policy_sha256": "b" * 64,
            "audit_profile_registry_sha256": "9" * 64,
            "requirements_lock_sha256": "6" * 64,
            "runtime_matrix_sha256": hashlib.sha256(
                (ROOT / "scripts/phase5e-audit-runtime-matrix.json").read_bytes()
            ).hexdigest(),
            "runtime_matrix_oracle_sha256": hashlib.sha256(
                (ROOT / "scripts/verify_phase5e_audit_runtime_matrix.py").read_bytes()
            ).hexdigest(),
            "audit_wheelhouse_manifest_sha256": hashlib.sha256(
                (ROOT / "scripts/phase5e-audit-wheelhouse.sha256").read_bytes()
            ).hexdigest(),
            "kernel_interface_sha256": "7" * 64,
            "control_oracle_tree_sha256": "8" * 64,
            "sandbox_profile": "linux-root-controller-net-pid-v2",
        },
        "started_at": "2026-07-18T00:00:00Z",
        "finished_at": "2026-07-18T00:01:00Z",
        "audited_file_sha256": {"policy": "d" * 64},
        "test_counts": {
            "collected_tests": 1,
            "passed_tests": 1,
            "skipped_tests": 0,
            "failed_tests": 0,
            "nodeid_sha256": hashlib.sha256(nodeids).hexdigest(),
            "junit_sha256": hashlib.sha256(junit).hexdigest(),
        },
        "check_ids": check_ids,
        "check_ids_sha256": hashlib.sha256(b"independent-check\n").hexdigest(),
        "checks": [
            {
                "check_id": "independent-check",
                "status": "passed",
                "evidence_sha256": "a" * 64,
                "evidence_size": 1,
            }
        ],
        "findings": [],
    }
    return (json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()


def test_three_runtime_audit_aggregator_emits_only_sanitized_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nodeids = b"tests/test_one.py::test_one\n"
    junit = (
        b'<testsuites name="pytest tests"><testsuite name="pytest" errors="0" '
        b'failures="0" skipped="0" tests="1" time="0.001" '
        b'timestamp="2026-07-18T00:00:00+00:00" hostname="audit">'
        b'<testcase classname="tests.test_one" name="test_one" time="0.001">'
        b'<properties><property name="phase5e_nodeid" '
        b'value="tests/test_one.py::test_one"/></properties></testcase>'
        b"</testsuite></testsuites>"
    )
    versions = {"cp311": "3.11.15", "cp312": "3.12.13", "cp313": "3.13.13"}
    evidence = {
        runtime_id: {
            "findings.json": _runtime_findings(
                runtime_id=runtime_id,
                python_version=version,
                nodeids=nodeids,
                junit=junit,
            ),
            "phase5e-independent.xml": junit,
            "phase5e-nodeids.txt": nodeids,
        }
        for runtime_id, version in versions.items()
    }

    def private_file(path: Path, *, maximum_bytes: int) -> bytes:
        raw = evidence[path.parent.name][path.name]
        assert len(raw) <= maximum_bytes
        return raw

    monkeypatch.setattr(runtime_matrix, "_private_file", private_file)
    output = tmp_path / "phase5e-audit.json"
    report = runtime_matrix.aggregate(
        matrix_path=ROOT / "scripts/phase5e-audit-runtime-matrix.json",
        wheelhouse_manifest=ROOT / "scripts/phase5e-audit-wheelhouse.sha256",
        runtime_roots={runtime_id: tmp_path / runtime_id for runtime_id in versions},
        output=output,
        reviewed_commit="a" * 40,
        ci_run_ids=("123",),
    )
    assert [item["runtime_id"] for item in report["runtime_results"]] == list(versions)
    assert report["finding_counts"] == {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    assert report["test_inventory_sha256"] == hashlib.sha256(nodeids).hexdigest()
    text = output.read_text(encoding="utf-8")
    assert "junit_sha256" not in text
    assert "nodeid_sha256" not in text
    assert "findings.json" not in text

    blocked_junit = (
        b'<testsuites name="pytest tests"><testsuite name="pytest" errors="0" '
        b'failures="1" skipped="0" tests="1" time="0.001" '
        b'timestamp="2026-07-18T00:00:00+00:00" hostname="audit">'
        b'<testcase classname="tests.test_one" name="test_one" time="0.001">'
        b'<properties><property name="phase5e_nodeid" '
        b'value="tests/test_one.py::test_one"/></properties>'
        b'<failure message="redacted" type="AssertionError">private trace</failure>'
        b"<system-out>private stdout</system-out>"
        b"</testcase></testsuite></testsuites>"
    )
    fallback_junit = blocked_junit.replace(
        b'<properties><property name="phase5e_nodeid" '
        b'value="tests/test_one.py::test_one"/></properties>',
        b"",
    ).replace(b'classname="tests.test_one"', b'classname=""')
    blocked_evidence = {
        "cp311": fallback_junit,
        "cp312": blocked_junit,
        "cp313": blocked_junit,
    }

    def blocked_private_file(path: Path, *, maximum_bytes: int) -> bytes:
        raw = blocked_evidence[path.parent.name]
        assert len(raw) <= maximum_bytes
        return raw

    monkeypatch.setattr(runtime_matrix, "_private_file", blocked_private_file)
    emergency_output = tmp_path / "phase5e-emergency-audit.json"
    runtime_matrix._write_emergency_manifest(
        output=emergency_output,
        reviewed_commit="a" * 40,
        ci_run_ids=("123",),
        error=ValueError("JUnit contains a failure or skip"),
        runtime_roots={
            runtime_id: tmp_path / runtime_id
            for runtime_id in ("cp311", "cp312", "cp313")
        },
    )
    emergency = json.loads(emergency_output.read_text(encoding="utf-8"))
    assert emergency["error_code"] == "protected_runtime_junit_blocked"
    assert emergency["finding_counts"] == {"P0": 1, "P1": 0, "P2": 0, "P3": 0}
    assert emergency["runtime_diagnostics"] == [
        {
            "runtime_id": runtime_id,
            "failed_tests": 1,
            "skipped_tests": 0,
            "outcomes_reconciled": True,
            "blocked_test_nodeids": [
                {
                    "identity": (
                        "::test_one"
                        if runtime_id == "cp311"
                        else "tests/test_one.py::test_one"
                    ),
                    "identity_kind": (
                        "junit_testcase" if runtime_id == "cp311" else "nodeid"
                    ),
                    "status": "failed",
                }
            ],
        }
        for runtime_id in ("cp311", "cp312", "cp313")
    ]
    serialized = emergency_output.read_text(encoding="utf-8")
    assert "private trace" not in serialized
    assert "private stdout" not in serialized
    assert "redacted" not in serialized


def test_three_runtime_audit_oracle_rejects_hidden_junit_children() -> None:
    nodeids = ("tests/test_one.py::test_one",)
    attacked = (
        b'<testsuites name="pytest tests"><testsuite name="pytest" errors="0" '
        b'failures="0" skipped="0" tests="1" time="0" timestamp="t" hostname="h">'
        b'<testcase classname="a" name="b" time="0"><properties>'
        b'<property name="phase5e_nodeid" value="tests/test_one.py::test_one"/>'
        b'</properties></testcase><failure message="hidden"/></testsuite></testsuites>'
    )
    with pytest.raises(ValueError, match="testcase count"):
        runtime_matrix._strict_junit(attacked, nodeids)


def _write_findings(path: Path, *, priority: str | None = None) -> None:
    check_ids = tuple(sorted(EXPECTED_AUDIT_CHECK_IDS))
    failed_check_id = check_ids[0] if priority is not None else None
    findings = []
    if priority is not None:
        findings.append(
            {
                "finding_id": f"{priority}:{failed_check_id}",
                "priority": priority,
                "check_id": failed_check_id,
                "summary": "Synthetic finding.",
                "evidence_sha256": "a" * 64,
            }
        )
    path.write_text(
        json.dumps(
            {
                "audit_tool": "owner-research-phase5e-readonly",
                "audit_profile": "phase5e2b12a",
                "audit_version": "2.3.2.3.3",
                "reviewed_commit": "a" * 40,
                "phase5d_baseline_commit": "b" * 40,
                "phase5e0_baseline_commit": "2" * 40,
                "phase5e11_baseline_commit": "3" * 40,
                "phase5e2a_baseline_commit": "e" * 40,
                "phase5e2b10_baseline_commit": "f" * 40,
                "phase5e2b11_baseline_commit": "1" * 40,
                "valuation_kernel_commit": "c" * 40,
                "audit_trust": {
                    "controller_commit": "4" * 40,
                    "controller_tree": "5" * 40,
                    "candidate_tree": "6" * 40,
                    "workflow_sha256": "1" * 64,
                    "audit_controller_sha256": "2" * 64,
                    "launcher_sha256": "3" * 64,
                    "candidate_executor_sha256": "4" * 64,
                    "semantic_oracle_sha256": "5" * 64,
                    "audit_profile_context_sha256": "a" * 64,
                    "audit_profile_policy_sha256": "b" * 64,
                    "audit_profile_registry_sha256": "9" * 64,
                    "requirements_lock_sha256": "6" * 64,
                    "runtime_matrix_sha256": "a" * 64,
                    "runtime_matrix_oracle_sha256": "b" * 64,
                    "audit_wheelhouse_manifest_sha256": "c" * 64,
                    "kernel_interface_sha256": "7" * 64,
                    "control_oracle_tree_sha256": "8" * 64,
                    "sandbox_profile": "linux-root-controller-net-pid-v2",
                },
                "started_at": "2026-07-14T00:00:00Z",
                "finished_at": "2026-07-14T00:01:00Z",
                "test_counts": {
                    "collected_tests": 741,
                    "passed_tests": 741,
                    "skipped_tests": 0,
                    "failed_tests": 0,
                    "nodeid_sha256": "e" * 64,
                    "junit_sha256": "f" * 64,
                },
                "audited_file_sha256": {"policy": "d" * 64},
                "check_ids": list(check_ids),
                "check_ids_sha256": hashlib.sha256(
                    ("\n".join(check_ids) + "\n").encode()
                ).hexdigest(),
                "checks": [
                    {
                        "check_id": check_id,
                        "status": "failed" if check_id == failed_check_id else "passed",
                        "evidence_sha256": "a" * 64,
                        "evidence_size": 1,
                    }
                    for check_id in check_ids
                ],
                "findings": findings,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_single_runtime_audit_writer_is_fail_closed(tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    output = tmp_path / "phase5e-audit.json"
    _write_findings(findings, priority="P3")
    completed = subprocess.run(
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
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert "single-runtime audit reports are retired" in completed.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    "attack",
    ("compact", "duplicate_key", "nonfinite", "overflow"),
)
def test_phase5e_audit_writer_rejects_noncanonical_findings(
    tmp_path: Path,
    attack: str,
) -> None:
    findings = tmp_path / "findings.json"
    output = tmp_path / "phase5e-audit.json"
    _write_findings(findings)
    value = json.loads(findings.read_text(encoding="utf-8"))
    if attack == "compact":
        findings.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    elif attack == "duplicate_key":
        raw = findings.read_text(encoding="utf-8")
        findings.write_text(
            '{"audit_tool":"forged",' + raw[1:],
            encoding="utf-8",
        )
    elif attack == "nonfinite":
        raw = findings.read_text(encoding="utf-8")
        findings.write_text(
            '{\n  "attacker": NaN,\n' + raw[2:],
            encoding="utf-8",
        )
    else:
        raw = findings.read_text(encoding="utf-8")
        findings.write_text(
            '{\n  "attacker": 1e400,\n' + raw[2:],
            encoding="utf-8",
        )
    completed = subprocess.run(
        [
            sys.executable,
            str(WRITER),
            "--output",
            str(output),
            "--reviewed-commit",
            "a" * 40,
            "--started-at",
            "2026-07-14T00:00:00Z",
            "--findings-file",
            str(findings),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert not output.exists()


@pytest.mark.parametrize(
    "attack",
    ("missing", "extra", "duplicate", "substitution", "hash_drift"),
)
def test_phase5e_audit_writer_rejects_check_identity_set_attacks(
    tmp_path: Path,
    attack: str,
) -> None:
    findings = tmp_path / "findings.json"
    output = tmp_path / "phase5e-audit.json"
    _write_findings(findings)
    value = json.loads(findings.read_text(encoding="utf-8"))
    if attack == "missing":
        value["check_ids"].pop()
        value["checks"].pop()
    elif attack == "extra":
        value["check_ids"].append("zz-attacker-check")
        value["checks"].append(
            {
                "check_id": "zz-attacker-check",
                "status": "passed",
                "evidence_sha256": "a" * 64,
                "evidence_size": 1,
            }
        )
    elif attack == "duplicate":
        value["check_ids"].append(value["check_ids"][-1])
    elif attack == "substitution":
        replaced = value["check_ids"][0]
        value["check_ids"][0] = "aa-attacker-substitute"
        value["checks"][0]["check_id"] = "aa-attacker-substitute"
        assert replaced != value["check_ids"][0]
    else:
        value["check_ids_sha256"] = "0" * 64
    findings.write_text(
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(WRITER),
            "--output",
            str(output),
            "--reviewed-commit",
            "a" * 40,
            "--started-at",
            "2026-07-14T00:00:00Z",
            "--findings-file",
            str(findings),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert not output.exists()


def test_phase5e_audit_rejects_namespaced_or_unknown_junit_structure() -> None:
    valid = ET.fromstring(
        '<testsuites name="pytest tests"><testsuite name="pytest" errors="0" '
        'failures="0" skipped="0" tests="1" time="0.001" '
        'timestamp="2026-07-16T00:00:00+00:00" hostname="audit">'
        '<testcase classname="tests.test_a" name="test_a" time="0.001"><properties>'
        '<property name="phase5e_nodeid" value="tests/test_a.py::test_a"/>'
        "</properties></testcase></testsuite></testsuites>"
    )
    namespaced_failure = ET.fromstring(
        '<testsuites name="pytest tests"><testsuite name="pytest" errors="0" '
        'failures="0" skipped="0" tests="1" time="0" timestamp="t" hostname="h">'
        '<testcase classname="a" name="b" time="0"><properties>'
        '<property name="phase5e_nodeid" value="n"/></properties>'
        '<failure xmlns="urn:attacker" message="hidden"/></testcase></testsuite></testsuites>'
    )
    unknown = ET.fromstring(
        '<testsuites name="pytest tests"><testsuite name="pytest" errors="0" '
        'failures="0" skipped="0" tests="1" time="0" timestamp="t" hostname="h">'
        '<testcase classname="a" name="b" time="0"><attacker/></testcase>'
        "</testsuite></testsuites>"
    )
    suite_level_failure = ET.fromstring(
        '<testsuites name="pytest tests"><testsuite name="pytest" errors="0" '
        'failures="0" skipped="0" tests="0" time="0" timestamp="t" hostname="h">'
        "<failure message='hidden'/></testsuite></testsuites>"
    )
    nested_suite = ET.fromstring(
        '<testsuites name="pytest tests"><testsuite name="pytest" errors="0" '
        'failures="0" skipped="0" tests="0" time="0" timestamp="t" hostname="h">'
        "<testsuite/></testsuite></testsuites>"
    )
    system_out_failure = ET.fromstring(
        '<testsuites name="pytest tests"><testsuite name="pytest" errors="0" '
        'failures="0" skipped="0" tests="1" time="0" timestamp="t" hostname="h">'
        '<testcase classname="a" name="b" time="0"><properties>'
        '<property name="phase5e_nodeid" value="n"/></properties>'
        "<system-out>1 failed</system-out></testcase></testsuite></testsuites>"
    )
    assert _strict_junit_tree(valid)
    assert not _strict_junit_tree(namespaced_failure)
    assert not _strict_junit_tree(unknown)
    assert not _strict_junit_tree(suite_level_failure)
    assert not _strict_junit_tree(nested_suite)
    assert not _strict_junit_tree(system_out_failure)


@pytest.mark.parametrize(
    "attack",
    (
        ' failures="1"',
        ' status="notrun"',
        ' result="skipped"',
        ' time="-1"',
    ),
)
def test_phase5e_audit_rejects_junit_attribute_or_counter_extensions(attack: str) -> None:
    valid = (
        '<testsuites name="pytest tests"><testsuite name="pytest" errors="0" '
        'failures="0" skipped="0" tests="1" time="0" timestamp="t" hostname="h">'
        '<testcase classname="a" name="b" time="0"><properties>'
        '<property name="phase5e_nodeid" value="n"/></properties></testcase>'
        "</testsuite></testsuites>"
    )
    if attack.startswith(" failures"):
        attacked = valid.replace(
            '<testsuites name="pytest tests"', '<testsuites name="pytest tests"' + attack
        )
    elif attack.startswith(" time"):
        attacked = valid.replace('tests="1" time="0"', 'tests="1" time="-1"')
    else:
        attacked = valid.replace('name="b" time="0"', 'name="b" time="0"' + attack)
    assert not _strict_junit_tree(ET.fromstring(attacked))


def test_phase5e_audit_rejects_negative_or_cancelling_junit_suite_counts() -> None:
    for suite_counts in (
        'errors="1" failures="-1" skipped="0" tests="1"',
        'errors="0" failures="0" skipped="0" tests="-1"',
    ):
        root = ET.fromstring(
            '<testsuites name="pytest tests"><testsuite name="pytest" '
            + suite_counts
            + ' time="0" timestamp="t" hostname="h">'
            '<testcase classname="a" name="b" time="0"><properties>'
            '<property name="phase5e_nodeid" value="n"/></properties></testcase>'
            "</testsuite></testsuites>"
        )
        assert not _strict_junit_tree(root)


def test_all_phase5e_finding_priorities_block_acceptance() -> None:
    for priority in ("P0", "P1", "P2", "P3"):
        assert _has_blocking_findings(({"priority": priority},))
    assert not _has_blocking_findings(())


def test_phase5e2b12a_repository_wide_changed_path_boundary_is_closed() -> None:
    accepted = (ROOT / PHASE5E2B12A_ACCEPTANCE_CLOSEOUT_PATH).is_file()
    expected_paths = set(PHASE5E2B12A_ALLOWED_CHANGED_PATHS)
    if accepted:
        expected_paths.add(PHASE5E2B12A_ACCEPTANCE_CLOSEOUT_PATH)
    private_baseline = "4fd643df73108b1fa3ab3ce1eb258ae3c3ce8a6d"
    if commit_exists(private_baseline, ROOT):
        changed_paths = set(
            subprocess.check_output(
                [
                    "git",
                    "diff",
                    "--name-only",
                    "--no-renames",
                    private_baseline,
                ],
                cwd=ROOT,
                text=True,
            ).splitlines()
        ) | set(
            subprocess.check_output(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=ROOT,
                text=True,
            ).splitlines()
        )
    else:
        provenance = verify_public_bootstrap_snapshot(ROOT)
        assert provenance["private_source"]["commit"] == (
            "253c869af34d3aa6dc2068171b5a8bd06a0cff95"
        )
        assert all((ROOT / path).is_file() for path in expected_paths)
        changed_paths = expected_paths
    assert changed_paths == expected_paths
    assert _phase5e2b12a_changed_path_violations(
        changed_paths,
        accepted=accepted,
    ) == ((), ())
    assert _phase5e2b12a_changed_path_violations(
        changed_paths | {PHASE5E2B12A_ACCEPTANCE_CLOSEOUT_PATH},
        accepted=True,
    ) == ((), ())
    assert PHASE5E2B12A_OPTIONAL_CHANGED_PATHS == {
        "docs/public-phase5e2b12a-revalidation.json"
    }
    assert (
        PUBLIC_CANONICAL_MIGRATION_OPTIONAL_CHANGED_PATHS
        == {
            "docs/public-phase5e2b12a-revalidation.json",
            "scripts/phase5e-audit-requirements.lock",
            "scripts/phase5e-audit-runtime-matrix.json",
            "scripts/phase5e-audit-wheelhouse.sha256",
            "scripts/phase5e_pid1_reaper.py",
        }
    )
    assert (
        "scripts/phase5e_kernel_git_shim.sh"
        in PUBLIC_CANONICAL_MIGRATION_CHANGED_PATHS
    )
    assert audit_runner._regular_tracked_file(
        ROOT,
        "scripts/verify_phase5e2a21_recursive_evidence.py",
    )
    assert _phase5e2b12a_changed_path_violations(
        changed_paths | PHASE5E2B12A_OPTIONAL_CHANGED_PATHS,
        accepted=accepted,
    ) == ((), ())
    unexpected, missing = _phase5e2b12a_changed_path_violations(
        changed_paths | {"scripts/compile_phase5e2c_market_evidence.py"},
        accepted=accepted,
    )
    assert unexpected == ("scripts/compile_phase5e2c_market_evidence.py",)
    assert not missing


def test_phase5e_ci_permissions_and_isolation_are_enforced() -> None:
    path = ROOT / ".github/workflows/phase5e2b12a-acceptance-gate.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    job = workflow["jobs"]["phase5e-readonly-audit"]
    comment_job = workflow["jobs"]["phase5e-readonly-audit-comment"]
    text = path.read_text(encoding="utf-8")
    assert job["permissions"] == {"contents": "read"}
    assert comment_job["permissions"] == {"contents": "read", "pull-requests": "write"}
    assert comment_job["needs"] == "phase5e-readonly-audit"
    assert job["runs-on"] == "ubuntu-24.04"
    assert comment_job["runs-on"] == "ubuntu-24.04"
    assert "ubuntu-latest" not in text
    assert "protected audit finding ids:" in text
    assert 'item["finding_id"]' in text
    assert 'item.get("evidence")' not in text
    assert 'item["evidence"]' not in text
    assert text.count("actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd") >= 8
    assert text.count("actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c") >= 4
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in text
    assert "actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd" in text
    assert 'python-version: "3.11.9"' in text
    for version in ("3.11.15", "3.12.13", "3.13.13"):
        assert f'python-version: "{version}"' in text
    assert "Remove remotes and unrelated Git identity before sandboxing" in text
    launcher = (ROOT / "scripts/launch_phase5e_readonly_audit.sh").read_text(encoding="utf-8")
    audit_runner = (ROOT / "scripts/run_phase5e_audit.py").read_text(encoding="utf-8")
    candidate_executor = (ROOT / "scripts/phase5e_candidate_exec.sh").read_text(
        encoding="utf-8"
    )
    git_shim = (ROOT / "scripts/phase5e_kernel_git_shim.sh").read_text(
        encoding="utf-8"
    )
    successor_tests = (ROOT / "tests/test_phase5e_successor_gate.py").read_text(
        encoding="utf-8"
    )
    assert (
        'chmod -R a-w "$control_repo" "$candidate_repo" "$kernel_interface" "$venv"'
        in launcher
    )
    assert "unshare --mount --net --pid" in launcher
    assert "--no-new-privs" in launcher
    assert "socket.if_nameindex()" in audit_runner
    assert 'Path("/sys/class/net").iterdir()' not in audit_runner
    assert "pivot_root" in candidate_executor
    assert "--reuid=65534" in candidate_executor
    assert 'mount --bind "$interface" "$root/interface"' in candidate_executor
    assert (
        "PYTHONPATH=/oracle:/work/src:/work:/work/tests"
        in candidate_executor
    )
    assert "/interface/kernel/src" not in candidate_executor
    assert 'mount --bind "$oracle/tests" "$root/work/tests"' in candidate_executor
    assert (
        'mount -t tmpfs -o mode=0555,nosuid,nodev,noexec tmpfs "$root/oracle/tests"'
        in candidate_executor
    )
    assert acceptance_gate_2a._trusted_successor_surface_path(
        Path("/oracle"), "tests/test_phase5e_successor_gate.py"
    ) == Path("/work/tests/test_phase5e_successor_gate.py")
    assert acceptance_gate_2a._trusted_successor_surface_path(
        ROOT, "scripts/verify_phase5e_successor_gate.py"
    ) == ROOT / "scripts/verify_phase5e_successor_gate.py"
    assert 'exec /usr/bin/git -c safe.directory=/work "$@"' in git_shim
    assert 'for copied_path in (repository, *repository.rglob("*"))' in successor_tests
    assert "stat.S_IWUSR" in successor_tests
    assert "/audit/control" not in candidate_executor
    assert "run_phase5e_audit.py" in launcher
    for protected_oracle in (
        "verify_phase5e2b12c_semantic_oracle.py",
        "verify_phase5e2c0_semantic_oracle.py",
    ):
        assert f'$control_repo/scripts/{protected_oracle}' in launcher
        assert f'$runtime/oracle/scripts/{protected_oracle}' in launcher
    assert "--require-os-sandbox" in launcher
    assert "verify_phase5e_audit_runtime_matrix.py" in text
    assert "write_phase5e_audit.py" not in text
    assert "$RUNNER_TEMP/phase5e-audit.json" in text
    for runtime in ("cp311", "cp312", "cp313"):
        assert f"$RUNNER_TEMP/phase5e-audit-runtime-{runtime}/final" in text
    assert "Upload only the normalized trusted audit manifest" in text
    assert all(job.get("timeout-minutes") for job in workflow["jobs"].values())
    assert "build_kernel_release_interface.py" in text
    assert "owner-valuation-rc2.bundle" not in text
    assert "--no-index" in text
    assert "--require-hashes" in text
    assert "needs.resolve-audit-identity.result == 'success'" in text
    assert "phase5e-independent.xml" not in text
    assert "phase5e-nodeids.txt" not in text
    assert "any(manifest[\"finding_counts\"].values())" in text
    assert 'value.get("report_sha256", sys.argv[2])' in text
    assert 'value.get("test_counts", {}).get(sys.argv[2], 0)' in text
    assert "\n          PY\n          done\n          set +e\n" in text
    assert text.count("feature/phase5e2b12a-acceptance-closeout") >= 1


def test_candidate_owned_ci_has_no_private_kernel_secret_or_write_token() -> None:
    path = ROOT / ".github/workflows/ci.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    text = path.read_text(encoding="utf-8")
    assert workflow["permissions"] == {"contents": "read"}
    assert "OWNER_VALUATION_DEPLOY_KEY" not in text
    assert "PHASE5E_KERNEL_READER_PRIVATE_KEY" not in text
    assert "PHASE5E_KERNEL_READER_APP_ID" not in text
    assert "secrets." not in text
    assert "pull_request_target" not in text
    assert "pull-requests: write" not in text
    assert "owner-valuation-kernel" not in text


def test_phase5e_audit_hashes_policy_and_control_surface() -> None:
    lock_text = (ROOT / "scripts/phase5e-audit-requirements.lock").read_text(
        encoding="utf-8"
    )
    ruff_version = re.search(
        r"^ruff==([0-9]+)\.([0-9]+)\.([0-9]+)\b",
        lock_text,
        re.MULTILINE,
    )
    assert ruff_version is not None
    assert tuple(int(part) for part in ruff_version.groups()) >= (0, 14, 14)
    required = {
        ".github/workflows/ci.yml",
        ".github/workflows/phase5e2b12a-acceptance-gate.yml",
        "AGENTS.md",
        "component-lock.json",
        "docs/adr/0029-phase5e-market-execution-policy.md",
        "docs/adr/0030-phase5e11-market-authority-trust-root.md",
        "docs/adr/0031-phase5e2a-market-reference-snapshot-v2.md",
        "docs/adr/0032-phase5e2a1-dilution-authority-contract-parity.md",
        "docs/adr/0034-phase5e2a21-recursive-current-share-evidence.md",
        "docs/adr/0035-phase5e2b-current-share-compiler.md",
        "docs/adr/0036-phase5e2b1-cross-source-share-event-identity.md",
        "docs/adr/0037-phase5e2b11-production-share-event-grouping.md",
        "docs/adr/0038-phase5e2b12a-current-share-integration-contracts.md",
        "docs/adr/0039-phase5e2b12a-semantic-trust-boundaries.md",
        "docs/phase5e2a21-implementation.md",
        "docs/phase5e2b-acceptance-closeout.md",
        "docs/phase5e2b-current-share-compilation.md",
        "docs/phase5e2b1-share-event-identity-policy.md",
        "docs/phase5e2b11-acceptance-closeout.md",
        "docs/phase5e2b11-production-grouping.md",
        "docs/phase5e2b12a-integration-contracts.md",
        "scripts/run_phase5e_audit.py",
        "scripts/verify_phase5e2b12a_acceptance_gate.py",
        "scripts/verify_phase5e0_policies.py",
        "scripts/verify_phase5e0_baseline.py",
        "scripts/verify_phase5e1_market_access.py",
        "scripts/verify_phase5e2a_snapshot_contract.py",
        "scripts/verify_phase5e2a1_semantic_closeout.py",
        "scripts/verify_phase5e2a21_recursive_evidence.py",
        "scripts/verify_phase5e2b_current_share_compiler.py",
        "scripts/verify_phase5e2b_acceptance_closeout.py",
        "scripts/verify_phase5e2b1_cross_source_red.py",
        "scripts/verify_phase5e2b10_frozen.py",
        "scripts/verify_phase5e2b11_acceptance_closeout.py",
        "scripts/verify_phase5e2b11_frozen_acceptance.py",
        "scripts/verify_phase5e2b11_share_event_grouping.py",
        "scripts/verify_phase5e2b12a_integration_contracts.py",
        "scripts/verify_phase5e2b12a_semantic_oracle.py",
        "scripts/verify_market_access_authority.py",
        "scripts/write_phase5e_audit.py",
        "src/owner_research/valuation_current_share_evidence.py",
        "src/owner_research/valuation_current_share_compiler.py",
        "src/owner_research/valuation_share_event_identity.py",
        "src/owner_research/valuation_share_event_grouping.py",
        "src/owner_research/valuation_share_event_integration_types.py",
        "src/owner_research/resources/current_share/canonical-event-integration-policy.json",
        "tests/test_phase5e2a21_recursive_evidence.py",
        "tests/phase5e2b_support.py",
        "tests/test_phase5e2b_current_share_compiler.py",
        "tests/fixtures/phase5e2b1/adversarial-cases.json",
        "tests/test_phase5e2b1_share_event_identity_policy.py",
        "tests/test_phase5e2b11_share_event_grouping.py",
        "tests/fixtures/phase5e2b12a/adversarial-cases.json",
        "tests/test_phase5e2b12a_integration_contracts.py",
        "tests/test_phase5e2b12a_acceptance_gate.py",
        "src/owner_research/valuation_market_execution_policies.py",
        "src/owner_research/valuation_market_execution_types.py",
        "src/owner_research/valuation_market_access.py",
        "src/owner_research/valuation_market_authority.py",
        "src/owner_research/valuation_market_parsers.py",
        "src/owner_research/valuation_security_identity.py",
        "src/owner_research/valuation_market_reference_types.py",
        "schemas/market-reference-snapshot.schema.json",
        "tests/fixtures/phase5e0/adversarial-cases.json",
        "tests/fixtures/phase5e1/recorded-quote.json",
        "tests/test_phase5e1_market_access.py",
        "tests/test_phase5e2a_snapshot_contract.py",
    }
    assert required.issubset(STATIC_CONTROL_FILES)


def test_phase5e2b11_acceptance_is_frozen_and_successor_is_current() -> None:
    subprocess.run(
        [sys.executable, "scripts/verify_phase5e2b11_frozen_acceptance.py"],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [sys.executable, "scripts/verify_phase5e2b12a_integration_contracts.py"],
        cwd=ROOT,
        check=True,
    )


def test_2a_semantic_oracle_cannot_treat_candidate_system_exit_zero_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def malicious_main() -> int:
        raise SystemExit(0)

    monkeypatch.setattr(semantic_oracle_2a, "main", malicious_main)
    assert semantic_oracle_2a._fail_closed_main() == 1


def test_2b_semantic_oracle_cannot_treat_candidate_system_exit_zero_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def malicious_main() -> int:
        raise SystemExit(0)

    monkeypatch.setattr(semantic_oracle_2b, "main", malicious_main)
    assert semantic_oracle_2b._fail_closed_main() == 1


def test_2b_semantic_oracle_runs_in_an_isolated_interpreter() -> None:
    phase2a = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import runpy,sys;"
                "runpy.run_path(sys.argv[1],run_name='_phase5e2b12a_isolated_load')"
            ),
            str(ROOT / "scripts/verify_phase5e2b12a_semantic_oracle.py"),
        ],
        cwd="/",
        env={
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        },
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert phase2a.returncode == 0, phase2a.stderr.decode(errors="replace")
    assert phase2a.stderr == b""

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/verify_phase5e2b12b_semantic_oracle.py"),
            "--repository",
            str(ROOT),
            "--protected-load-only",
        ],
        cwd="/",
        env={
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        },
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    assert completed.stderr == b""
    assert completed.stdout == (
        b"Phase 5E-2B.1-2B protected profile load passed\n"
    )


def test_2b_semantic_oracle_rejects_main_module_serializer_poisoning(
    tmp_path: Path,
) -> None:
    compiler = tmp_path / semantic_oracle_2b.COMPILER_PATH
    dedicated_test = tmp_path / semantic_oracle_2b.REQUIRED_TEST_PATH
    compiler.parent.mkdir(parents=True)
    dedicated_test.parent.mkdir(parents=True)
    compiler.write_text(
        "from owner_research.valuation_share_event_integration_types import (\n"
        "    CanonicalShareEventFactMaterialization, ShareEventNumericConsumption,\n"
        ")\n"
        "class CanonicalRollforwardResult:\n"
        "    pass\n"
        "def compile_quote_date_current_common_shares():\n"
        "    return CanonicalRollforwardResult()\n"
        "import sys\n"
        "sys.modules['__main__']._canonical_bytes = lambda value: b'{}'\n",
        encoding="utf-8",
    )
    dedicated_test.write_text(
        "\n".join(
            f"def {nodeid.rsplit('::', 1)[1]}():\n    pass"
            for nodeid in semantic_oracle_2b.PHASE5E2B12B_ADDED_TEST_NODEIDS
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="audit-process attack surface"):
        semantic_oracle_2b.verify_candidate_surface(tmp_path)


def test_2b_semantic_oracle_rejects_reflective_process_exit(
    tmp_path: Path,
) -> None:
    compiler = tmp_path / semantic_oracle_2b.COMPILER_PATH
    dedicated_test = tmp_path / semantic_oracle_2b.REQUIRED_TEST_PATH
    compiler.parent.mkdir(parents=True)
    dedicated_test.parent.mkdir(parents=True)
    compiler.write_text(
        "from pathlib import Path\n"
        "from owner_research.valuation_share_event_integration_types import (\n"
        "    CanonicalShareEventFactMaterialization, ShareEventNumericConsumption,\n"
        ")\n"
        "class CanonicalRollforwardResult:\n"
        "    pass\n"
        "def compile_quote_date_current_common_shares():\n"
        "    hidden_os = Path.cwd.__func__.__globals__['os']\n"
        "    hidden_os._exit(0)\n"
        "    return CanonicalRollforwardResult()\n",
        encoding="utf-8",
    )
    dedicated_test.write_text(
        "\n".join(
            f"def {nodeid.rsplit('::', 1)[1]}():\n    pass"
            for nodeid in semantic_oracle_2b.PHASE5E2B12B_ADDED_TEST_NODEIDS
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="audit-process attack surface"):
        semantic_oracle_2b.verify_candidate_surface(tmp_path)
