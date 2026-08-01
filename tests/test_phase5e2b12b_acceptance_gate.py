from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts import verify_phase5e2b12b_acceptance_gate as acceptance_gate
from scripts.verify_phase5e2b12b_acceptance_gate import (
    ACCEPTANCE_BRANCH,
    ACCEPTANCE_DIFF,
    AUDIT_PROFILE,
    AUDIT_TOOL,
    AUDIT_VERSION,
    EXPECTED_TEST_COUNT,
    IMPLEMENTATION_BRANCH,
    IMPLEMENTATION_DIFF,
    PHASE5E2B12A_CLOSEOUT_PATH,
    PHASE5E2B12B_CLOSEOUT_PATH,
    PHASE5E2B12B_TEST_PATH,
    STATE_PATCHES,
    STATUS_PATH,
    state_id,
    verify_pull_request,
)

REPOSITORY_SLUG = "owner/research"


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


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _event(*, base: str, head: str, branch: str, number: int) -> dict[str, Any]:
    return {
        "number": number,
        "repository": {"full_name": REPOSITORY_SLUG},
        "pull_request": {
            "base": {
                "ref": "main",
                "sha": base,
                "repo": {"full_name": REPOSITORY_SLUG},
            },
            "head": {
                "ref": branch,
                "sha": head,
                "repo": {"full_name": REPOSITORY_SLUG},
            },
        },
    }


def _accepted_2a_repository(tmp_path: Path) -> tuple[Path, str]:
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
    for path, contents in (
        ("src/owner_research/valuation_current_share_compiler.py", "VALUE = 1\n"),
        (PHASE5E2B12A_CLOSEOUT_PATH, "{}\n"),
        ("scripts/phase5e_audit_profiles.py", "PROFILE = 1\n"),
        ("scripts/phase5e2b12a-acceptance-trust.json", "{}\n"),
        (
            "scripts/phase5e_candidate_exec.sh",
            "timeout --signal=TERM --kill-after=10s 15m\n",
        ),
        ("tests/test_phase5e_audit.py", "def test_profile():\n    assert True\n"),
        ("scripts/verify_phase5e2b12a_acceptance_gate.py", "OUTER = 1\n"),
        ("scripts/verify_phase5e2b12b_acceptance_gate.py", "INNER = 1\n"),
        ("tests/test_phase5e2b12a_acceptance_gate.py", "def test_outer():\n    assert True\n"),
        ("tests/test_phase5e2b12b_acceptance_gate.py", "def test_inner():\n    assert True\n"),
    ):
        target = repository / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
    (repository / "tests").mkdir(exist_ok=True)
    _write_json(repository / STATUS_PATH, STATE_PATCHES["s1"])
    return repository, _commit(repository, "accepted 2A")


def _implementation_candidate(
    tmp_path: Path,
    *,
    branch: str = IMPLEMENTATION_BRANCH,
    extra_path: str | None = None,
) -> tuple[Path, str, str]:
    repository, base = _accepted_2a_repository(tmp_path)
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", branch],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    compiler = repository / "src/owner_research/valuation_current_share_compiler.py"
    compiler.write_text("VALUE = 2\n", encoding="utf-8")
    test_path = repository / PHASE5E2B12B_TEST_PATH
    test_path.write_text("def test_canonical():\n    assert True\n", encoding="utf-8")
    _write_json(repository / STATUS_PATH, STATE_PATCHES["s2"])
    if extra_path is not None:
        target = repository / extra_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("unexpected\n", encoding="utf-8")
    return repository, base, _commit(repository, "2B implementation")


def _pending_2b_repository(tmp_path: Path) -> tuple[Path, str, str, str]:
    repository, implementation_base, implementation_head = _implementation_candidate(tmp_path)
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
            IMPLEMENTATION_BRANCH,
            "-m",
            "merge 2B implementation",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    merge = _git(repository, "rev-parse", "HEAD")
    assert _git(repository, "rev-parse", f"{merge}^2") == implementation_head
    assert state_id(repository, merge) == "s2"
    return repository, merge, implementation_base, implementation_head


def _closeout(
    *,
    repository: Path,
    implementation_merge: str,
    implementation_head: str,
    acceptance_number: int = 82,
) -> dict[str, Any]:
    return {
        "acceptance_pull_request": acceptance_number,
        "audit_artifact_sha256": "a" * 64,
        "audit_profile": AUDIT_PROFILE,
        "audit_report_sha256": "b" * 64,
        "audit_tool": AUDIT_TOOL,
        "audit_version": AUDIT_VERSION,
        "audit_workflow_id": 4321,
        "audit_wheelhouse_manifest_sha256": "c" * 64,
        "controller_app_id": 98765,
        "controller_app_slug": "phase5e-controller",
        "controller_installation_id": 54321,
        "implementation_head_commit": implementation_head,
        "implementation_merge_commit": implementation_merge,
        "implementation_pull_request": 81,
        "implementation_tree_sha": _git(
            repository, "rev-parse", f"{implementation_merge}^{{tree}}"
        ),
        "main_ci_run_id": "2002",
        "phase": "Phase 5E-2B.1-2B",
        "pr_ci_run_id": "2001",
        "runtime_matrix_sha256": "d" * 64,
        "schema_version": "1.0.0",
        "test_count": EXPECTED_TEST_COUNT,
        "test_inventory_sha256": "e" * 64,
    }


def _acceptance_candidate(
    tmp_path: Path,
    *,
    branch: str = ACCEPTANCE_BRANCH,
    acceptance_number: int = 82,
    extra_path: str | None = None,
) -> tuple[Path, str, str, str, dict[str, Any]]:
    repository, base, implementation_base, implementation_head = _pending_2b_repository(tmp_path)
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", branch],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    _write_json(
        repository / PHASE5E2B12B_CLOSEOUT_PATH,
        _closeout(
            repository=repository,
            implementation_merge=base,
            implementation_head=implementation_head,
            acceptance_number=acceptance_number,
        ),
    )
    _write_json(repository / STATUS_PATH, STATE_PATCHES["s3"])
    if extra_path is not None:
        target = repository / extra_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("unexpected\n", encoding="utf-8")
    head = _commit(repository, "2B acceptance")
    return (
        repository,
        base,
        implementation_base,
        head,
        _event(
            base=base,
            head=head,
            branch=branch,
            number=acceptance_number,
        ),
    )


def _interstitial_acceptance_candidate(
    tmp_path: Path,
    *,
    sealed_timeout_recovery: bool = False,
) -> tuple[Path, str, str, str, str, dict[str, Any], dict[str, Any]]:
    repository, implementation_merge, implementation_base, implementation_head = (
        _pending_2b_repository(tmp_path)
    )
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", "profile-repair"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    for path in ("scripts/phase5e_audit_profiles.py", "tests/test_phase5e_audit.py"):
        target = repository / path
        target.write_text(target.read_text(encoding="utf-8") + "# repaired\n", encoding="utf-8")
    profile_head = _commit(repository, "profile repair")
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
            "profile-repair",
            "-m",
            "merge profile repair",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    profile_merge = _git(repository, "rev-parse", "HEAD")
    profile = {
        "merge": profile_merge,
        "first_parent": implementation_merge,
        "second_parent": profile_head,
        "tree": _git(repository, "rev-parse", f"{profile_merge}^{{tree}}"),
        "files": {
            path: {
                "status": "M",
                "mode": "100644",
                "blob": _git(repository, "rev-parse", f"{profile_merge}:{path}"),
            }
            for path in ("scripts/phase5e_audit_profiles.py", "tests/test_phase5e_audit.py")
        },
    }

    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", "topology-repair"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    for path in acceptance_gate.POST_IMPLEMENTATION_TOPOLOGY_REPAIR_PATHS:
        target = repository / path
        target.write_text(target.read_text(encoding="utf-8") + "# topology\n", encoding="utf-8")
    _commit(repository, "topology repair")
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
            "topology-repair",
            "-m",
            "merge topology repair",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    topology_merge = _git(repository, "rev-parse", "HEAD")
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", "timeout-repair"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    for path in acceptance_gate.POST_IMPLEMENTATION_TIMEOUT_REPAIR_PATHS:
        target = repository / path
        if path == "scripts/phase5e_candidate_exec.sh":
            target.write_text(
                target.read_text(encoding="utf-8").replace("15m", "30m"),
                encoding="utf-8",
            )
        else:
            target.write_text(
                target.read_text(encoding="utf-8") + "# timeout\n",
                encoding="utf-8",
            )
    _commit(repository, "audit timeout repair")
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
            "timeout-repair",
            "-m",
            "merge audit timeout repair",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    acceptance_base = _git(repository, "rev-parse", "HEAD")
    assert _git(repository, "rev-parse", f"{acceptance_base}^1") == topology_merge
    if sealed_timeout_recovery:
        timeout_merge = acceptance_base
        subprocess.run(
            ["git", "-C", str(repository), "checkout", "-b", "timeout-audit-recovery"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        authority = {
            "failed_audit_artifact_digest": (
                "sha256:83babe803d69f5a5fc2415be551f9c56935051f039fa0bfc462f642c89b2178e"
            ),
            "failed_audit_artifact_id": 8820812727,
            "failed_audit_artifact_size": 622,
            "failed_audit_report_file_sha256": (
                "5581f2b63e8b97ebdbf4ba5547b9af61eb095a5fc05346133fb0c88bd14bccfc"
            ),
            "failed_audit_run_id": 30707380080,
            "failed_error_code": "protected_runtime_junit_blocked",
            "failed_error_fingerprint": (
                "0677944bbf28a071fbed5eee1da49561d7b3c67b479bf7182f5a62d06c3b447f"
            ),
            "failed_head_commit": timeout_merge,
            "failed_test_identities": [
                "::tests.test_phase5e2b12a_acceptance_gate",
                "::tests.test_phase5e_audit",
            ],
            "predecessor_merge_commit": timeout_merge,
            "reason_code": (
                "protected-predecessor-tests-rejected-the-bounded-timeout-control-repair"
            ),
            "recovery_id": "phase5e2b12b-protected-audit-timeout-recovery-v1",
            "repair_base_commit": "f8f3fd15f741c7df10d8b89812e7f793c5ffa72b",
            "repair_branch": "fix/phase5e2b12b-r11-audit-timeout-boundary",
            "repair_head_commit": "7f4e1df9456ad294dcea81c66c2f606786f9658f",
            "repair_main_ci_run_id": 30707371608,
            "repair_merge_commit": timeout_merge,
            "repair_pull_request": 79,
            "repair_tree": "84a4c4fb5325101dc088ee3e40ec7117ba9736bd",
            "schema_version": "1.0.0",
        }
        authority_path = (
            repository / acceptance_gate.POST_IMPLEMENTATION_TIMEOUT_RECOVERY_AUTHORITY_PATH
        )
        _write_json(authority_path, authority)
        for path in acceptance_gate.POST_IMPLEMENTATION_TIMEOUT_RECOVERY_BOOTSTRAP_PATHS:
            if path == acceptance_gate.POST_IMPLEMENTATION_TIMEOUT_RECOVERY_AUTHORITY_PATH:
                continue
            target = repository / path
            target.write_text(
                target.read_text(encoding="utf-8") + "# timeout-audit recovery\n",
                encoding="utf-8",
            )
        bootstrap = _commit(repository, "bootstrap timeout-audit recovery")
        _write_json(
            repository / acceptance_gate.POST_IMPLEMENTATION_TIMEOUT_RECOVERY_SEAL_PATH,
            {
                "authority_sha256": hashlib.sha256(authority_path.read_bytes()).hexdigest(),
                "bootstrap_commit": bootstrap,
                "reason_code": "sealed-one-time-protected-audit-timeout-recovery",
                "recovery_id": "phase5e2b12b-protected-audit-timeout-recovery-v1",
                "schema_version": "1.0.0",
            },
        )
        _commit(repository, "seal timeout-audit recovery")
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
                "timeout-audit-recovery",
                "-m",
                "merge timeout-audit recovery",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        acceptance_base = _git(repository, "rev-parse", "HEAD")
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", ACCEPTANCE_BRANCH],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    _write_json(
        repository / PHASE5E2B12B_CLOSEOUT_PATH,
        _closeout(
            repository=repository,
            implementation_merge=implementation_merge,
            implementation_head=implementation_head,
        ),
    )
    _write_json(repository / STATUS_PATH, STATE_PATCHES["s3"])
    head = _commit(repository, "2B acceptance after control repair")
    return (
        repository,
        acceptance_base,
        implementation_base,
        implementation_merge,
        head,
        _event(base=acceptance_base, head=head, branch=ACCEPTANCE_BRANCH, number=82),
        profile,
    )


def test_trust_diff_contract_is_narrow() -> None:
    assert EXPECTED_TEST_COUNT == 1392
    assert IMPLEMENTATION_DIFF == {
        STATUS_PATH: "M",
        "src/owner_research/valuation_current_share_compiler.py": "M",
        PHASE5E2B12B_TEST_PATH: "A",
    }
    assert ACCEPTANCE_DIFF == {
        STATUS_PATH: "M",
        PHASE5E2B12B_CLOSEOUT_PATH: "A",
    }


def test_accepted_2a_allows_only_exact_2b_implementation(tmp_path: Path) -> None:
    repository, base, head = _implementation_candidate(tmp_path)
    calls: list[object] = []
    verify_pull_request(
        repository=repository,
        base=base,
        head=head,
        event=_event(base=base, head=head, branch=IMPLEMENTATION_BRANCH, number=81),
        repository_slug=REPOSITORY_SLUG,
        remote_verifier=lambda **kwargs: calls.append(kwargs),
    )
    assert state_id(repository, head) == "s2"
    assert calls == []


@pytest.mark.parametrize(
    ("branch", "extra_path"),
    (("feature/wrong", None), (IMPLEMENTATION_BRANCH, "src/extra.py")),
)
def test_implementation_rejects_wrong_branch_or_extra_path(
    tmp_path: Path,
    branch: str,
    extra_path: str | None,
) -> None:
    repository, base, head = _implementation_candidate(
        tmp_path, branch=branch, extra_path=extra_path
    )
    with pytest.raises(SystemExit):
        verify_pull_request(
            repository=repository,
            base=base,
            head=head,
            event=_event(base=base, head=head, branch=branch, number=81),
            repository_slug=REPOSITORY_SLUG,
        )


def test_acceptance_requires_and_calls_remote_replay_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, base, implementation_base, head, event = _acceptance_candidate(tmp_path)
    calls: list[dict[str, Any]] = []

    def replay(**kwargs: Any) -> None:
        calls.append(kwargs)

    verify_pull_request(
        repository=repository,
        base=base,
        head=head,
        event=event,
        repository_slug=REPOSITORY_SLUG,
        token="controller-token",
        require_remote=True,
        remote_verifier=replay,
    )
    assert state_id(repository, head) == "s3"
    assert len(calls) == 1
    assert calls[0]["implementation_base"] == implementation_base
    assert calls[0]["implementation_merge"] == base
    assert calls[0]["token"] == "controller-token"

    interstitial_root = tmp_path / "interstitial"
    interstitial_root.mkdir()
    interstitial = _interstitial_acceptance_candidate(interstitial_root)
    repository, base, implementation_base, implementation_merge, head, event, profile = interstitial
    monkeypatch.setattr(acceptance_gate, "POST_IMPLEMENTATION_PROFILE_REPAIR", profile)
    calls.clear()
    verify_pull_request(
        repository=repository,
        base=base,
        head=head,
        event=event,
        repository_slug=REPOSITORY_SLUG,
        token="controller-token",
        require_remote=True,
        remote_verifier=replay,
    )
    assert calls[0]["implementation_base"] == implementation_base
    assert calls[0]["implementation_merge"] == implementation_merge

    sealed_root = tmp_path / "sealed"
    sealed_root.mkdir()
    sealed = _interstitial_acceptance_candidate(
        sealed_root,
        sealed_timeout_recovery=True,
    )
    sealed_repository, sealed_base, _, sealed_implementation, _, _, sealed_profile = sealed
    monkeypatch.setattr(
        acceptance_gate,
        "POST_IMPLEMENTATION_PROFILE_REPAIR",
        sealed_profile,
    )
    acceptance_gate._verify_post_implementation_control_history(
        repository=sealed_repository,
        implementation_merge=sealed_implementation,
        acceptance_base=sealed_base,
    )

    attack_root = tmp_path / "attack"
    attack_root.mkdir()
    repository, base, _, implementation_merge, _, _, profile = _interstitial_acceptance_candidate(
        attack_root
    )
    monkeypatch.setattr(acceptance_gate, "POST_IMPLEMENTATION_PROFILE_REPAIR", profile)
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "main"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    assert _git(repository, "rev-parse", "HEAD") == base
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", "extra-control-repair"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    target = repository / "scripts/phase5e_candidate_exec.sh"
    target.write_text(target.read_text(encoding="utf-8") + "# replay\n", encoding="utf-8")
    _commit(repository, "unapproved fourth repair")
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
            "extra-control-repair",
            "-m",
            "merge unapproved fourth repair",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    with pytest.raises(
        SystemExit,
        match="timeout-audit recovery",
    ):
        acceptance_gate._verify_post_implementation_control_history(
            repository=repository,
            implementation_merge=implementation_merge,
            acceptance_base=_git(repository, "rev-parse", "HEAD"),
        )


@pytest.mark.parametrize(
    ("token", "require_remote", "has_replay"),
    ((None, True, True), ("controller-token", False, True), ("controller-token", True, False)),
)
def test_acceptance_cannot_omit_remote_evidence(
    tmp_path: Path,
    token: str | None,
    require_remote: bool,
    has_replay: bool,
) -> None:
    repository, base, _, head, event = _acceptance_candidate(tmp_path)
    replay = (lambda **kwargs: None) if has_replay else None
    with pytest.raises(SystemExit, match="requires protected remote evidence replay"):
        verify_pull_request(
            repository=repository,
            base=base,
            head=head,
            event=event,
            repository_slug=REPOSITORY_SLUG,
            token=token,
            require_remote=require_remote,
            remote_verifier=replay,
        )


@pytest.mark.parametrize("priority", ("P0", "P1", "P2", "P3"))
def test_any_remote_finding_blocks_acceptance(tmp_path: Path, priority: str) -> None:
    repository, base, _, head, event = _acceptance_candidate(tmp_path)

    def replay(**kwargs: Any) -> None:
        raise SystemExit(f"remote audit contains {priority}=1")

    with pytest.raises(SystemExit, match=priority):
        verify_pull_request(
            repository=repository,
            base=base,
            head=head,
            event=event,
            repository_slug=REPOSITORY_SLUG,
            token="controller-token",
            require_remote=True,
            remote_verifier=replay,
        )


@pytest.mark.parametrize(
    ("branch", "event_number", "extra_path"),
    (("feature/wrong", 82, None), (ACCEPTANCE_BRANCH, 999, None), (ACCEPTANCE_BRANCH, 82, "x")),
)
def test_acceptance_rejects_wrong_identity_or_extra_path(
    tmp_path: Path,
    branch: str,
    event_number: int,
    extra_path: str | None,
) -> None:
    repository, base, _, head, event = _acceptance_candidate(
        tmp_path,
        branch=branch,
        acceptance_number=82,
        extra_path=extra_path,
    )
    event["number"] = event_number
    with pytest.raises(SystemExit):
        verify_pull_request(
            repository=repository,
            base=base,
            head=head,
            event=event,
            repository_slug=REPOSITORY_SLUG,
            token="controller-token",
            require_remote=True,
            remote_verifier=lambda **kwargs: None,
        )


def test_accepted_state_authorizes_only_preimplementation_gate_work() -> None:
    accepted = STATE_PATCHES["s3"]
    assert accepted["authorized_next"] == ["Phase 5E-2B.1-2C successor-gate bootstrap"]
    assert "Phase 5E-2B.1-2C" in accepted["prohibited"]
    assert "Phase 5E-2C" in accepted["prohibited"]
    assert not (set(accepted["authorized_next"]) & set(accepted["prohibited"]))
