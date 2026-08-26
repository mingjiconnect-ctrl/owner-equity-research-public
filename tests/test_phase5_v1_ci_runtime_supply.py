from __future__ import annotations

import ast
import hashlib
import json
import runpy
import shutil
import stat
import subprocess
import sys
import warnings
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
CI_PATH = ROOT / ".github/workflows/ci.yml"
WHEEL_VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_wheel.py"))
VERIFY_WHEEL = WHEEL_VERIFIER["verify"]
LEGACY_PATHS = [
    "tests/test_phase4d5_phase_state.py",
    "tests/test_phase5e2b12a_acceptance_gate.py",
    "tests/test_phase5e2b12b_acceptance_gate.py",
    "tests/test_phase5e_audit.py",
    "tests/test_phase5e_successor_gate.py",
]


def _workflow() -> dict:
    return yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))


def _step(name: str) -> dict:
    steps = _workflow()["jobs"]["verify"]["steps"]
    return next(step for step in steps if step.get("name") == name)


def _joined_verify_step_source(*names: str) -> str:
    return "\n".join(_step(name)["run"] for name in names)


def _dependency_supply_source() -> str:
    return _joined_verify_step_source(
        "Materialize the exact dependency lock files before private access",
        "Materialize the exact dependency supply validator",
        "Prefetch and seal the exact dependency supply before private access",
    )


def _candidate_execution_source() -> str:
    return _joined_verify_step_source(
        "Stage netless, then verify in the authorized 3.11 container",
        "Run the exact candidate in the authorized 3.11 container",
    )


def _release_tag_block_step() -> dict:
    return {
        "name": "Fail closed until external release control is deployed",
        "if": "startsWith(github.ref, 'refs/tags/')",
        "shell": "bash",
        "run": (
            "set -euo pipefail\n"
            "printf '%s\\n' \\\n"
            "  '::error title=Release control unavailable::"
            "release_control_root_not_deployed' >&2\n"
            "exit 1\n"
        ),
    }


def _sanitizer_namespace() -> dict:
    source = _step(
        "Delete private channels and rebuild one allowlisted canonical summary"
    )["run"]
    embedded = source.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    tree = ast.parse(embedded)
    assert isinstance(tree.body[-1], ast.Try)
    tree.body.pop()
    namespace: dict = {}
    exec(compile(ast.fix_missing_locations(tree), "<workflow-sanitizer>", "exec"), namespace)
    return namespace


def test_release_tags_fail_closed_in_all_four_required_checks() -> None:
    workflow = _workflow()
    expected_gate = _release_tag_block_step()
    verify = workflow["jobs"]["verify"]
    semantic = workflow["jobs"]["semantic-audit"]
    assert verify["steps"][0] == expected_gate
    assert semantic["steps"][0] == expected_gate
    assert "if" not in verify
    assert "if" not in semantic
    assert verify["strategy"]["matrix"]["python-version"] == ["3.11", "3.12", "3.13"]
    check_names = [
        f"verify ({version})"
        for version in verify["strategy"]["matrix"]["python-version"]
    ] + [semantic["name"]]
    assert check_names == [
        "verify (3.11)",
        "verify (3.12)",
        "verify (3.13)",
        "phase5/semantic-audit",
    ]

    failed = subprocess.run(
        ("bash", "-c", expected_gate["run"]),
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert failed.returncode == 1
    assert failed.stdout == ""
    assert failed.stderr == (
        "::error title=Release control unavailable::"
        "release_control_root_not_deployed\n"
    )
    assert "${{" not in expected_gate["run"]
    assert "$GITHUB" not in expected_gate["run"]


def test_release_tag_block_does_not_change_non_tag_event_paths() -> None:
    workflow = _workflow()
    events = workflow[True]
    assert set(events) == {"pull_request", "push", "workflow_dispatch"}
    assert events["pull_request"] == {"branches": ["main"]}
    assert events["push"] == {
        "branches": ["main"],
        "tags": ["v*-rc*"],
    }
    assert events["workflow_dispatch"] is None
    for job in workflow["jobs"].values():
        assert job["steps"][0]["if"] == "startsWith(github.ref, 'refs/tags/')"
        assert "release_control_root_not_deployed" in job["steps"][0]["run"]
        assert job["steps"][1]["name"].startswith("Check out the exact")


def test_github_run_blocks_stay_within_the_expression_parser_limit() -> None:
    for job in _workflow()["jobs"].values():
        for step in job["steps"]:
            if "run" in step:
                assert len(step["run"]) <= 21_000, step.get("name")


def test_phase_verifier_batches_test_files_and_removes_sealed_batch_trees(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = runpy.run_path(str(ROOT / "scripts/verify_phase5_v1.py"))
    sealed = tmp_path / "sealed"
    child = sealed / "child"
    child.mkdir(parents=True)
    member = child / "member.json"
    member.write_text("{}\n", encoding="utf-8")
    member.chmod(0o444)
    child.chmod(0o555)
    sealed.chmod(0o555)
    assert verifier["_remove_test_tree"](sealed)
    assert not sealed.exists()
    retained = tmp_path / "retained"
    retained.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(retained, target_is_directory=True)
    assert verifier["_remove_test_tree"](linked)
    assert retained.is_dir()

    calls: list[tuple[str, tuple[str, ...], float | None]] = []

    def fake_pytest(_temporary_directory: Path, **kwargs):
        calls.append(
            (
                kwargs["label"],
                tuple(kwargs["paths"]),
                kwargs["timeout_seconds"],
            )
        )
        return 0, {"collected": 1, "passed": 1, "skipped": 0, "failed": 0}

    monkeypatch.setitem(
        verifier["_pytest_by_file"].__globals__,
        "_pytest",
        fake_pytest,
    )
    requested = (
        "tests/test_phase5_v1_ci_kernel_reader.py",
        "tests/test_phase5_v1_container_envelopes.py",
        "sidecars/futu-opend/tests/test_fake_opend_uds_e2e.py",
    )
    result, counts = verifier["_pytest_by_file"](
        tmp_path,
        label="bounded",
        paths=reversed(requested),
    )
    assert result == 0
    assert counts == {"collected": 3, "passed": 3, "skipped": 0, "failed": 0}
    assert calls == [
        (
            "bounded-001",
            (requested[2],),
            verifier["SIDECAR_TEST_FILE_TIMEOUT_SECONDS"],
        ),
        ("bounded-002", (requested[0],), None),
        ("bounded-003", (requested[1],), None),
    ]


def test_phase_verifier_turns_a_process_timeout_into_a_bounded_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    verifier = runpy.run_path(str(ROOT / "scripts/verify_phase5_v1.py"))

    def expire(*_args, **kwargs):
        assert kwargs["timeout"] == 0.25
        raise subprocess.TimeoutExpired(["python", "-m", "pytest"], 0.25)

    monkeypatch.setitem(verifier["_run"].__globals__["subprocess"].__dict__, "run", expire)
    result = verifier["_run"](["python", "-m", "pytest"], timeout_seconds=0.25)
    assert result == verifier["COMMAND_TIMEOUT_RETURN_CODE"]
    assert "timed out after 0.25 seconds" in capsys.readouterr().err


def _attestation_source() -> str:
    source = _step("Run the exact candidate in the authorized 3.11 container")["run"]
    marker = '"$KERNEL_RUNTIME_IMAGE" "$KERNEL_RUNTIME_IMAGE_ID" <<\'PY\'\n'
    return source.split(marker, 1)[1].split("\nPY", 1)[0]


def _supply_validator_namespace() -> dict:
    source = _step("Materialize the exact dependency supply validator")["run"]
    embedded = source.split('cat > "$validator" <<\'PY\'\n', 1)[1].split("\nPY", 1)[0]
    tree = ast.parse(embedded)
    selected: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            selected.append(node)
        elif isinstance(node, ast.Assign) and all(
            isinstance(target, ast.Name) and target.id in {"common", "per_minor"}
            for target in node.targets
        ):
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == "verify_observed":
            selected.append(node)
    namespace: dict = {}
    tree = ast.Module(body=selected, type_ignores=[])
    exec(compile(tree, "<supply-validator>", "exec"), namespace)
    return namespace


def _raw_report(*, message: str = "test failure") -> bytes:
    report = {
        "commit": "a" * 40,
        "findings": [
            {"code": "P5V1-TESTS", "message": message, "priority": "P0"}
        ],
        "mode": "verify",
        "report_kind": "nonlegacy_verification",
        "P0": 1,
        "P1": 0,
        "P2": 0,
        "P3": 0,
        "required_zero": [],
        "schema_version": "1.0.0",
        "tests": {
            "collected": 1,
            "passed": 0,
            "skipped": 0,
            "failed": 1,
            "excluded_legacy_paths": LEGACY_PATHS,
        },
        "tree": "b" * 40,
    }
    canonical = json.dumps(
        report, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return (json.dumps(report, sort_keys=True) + "\n").encode()


def test_private_runtime_supply_and_containment_order_is_closed() -> None:
    workflow = _workflow()
    assert set(workflow["jobs"]) == {"verify", "semantic-audit"}
    verify = workflow["jobs"]["verify"]
    assert verify["name"] == "verify (${{ matrix.python-version }})"
    assert verify["strategy"]["matrix"] == {
        "python-version": ["3.11", "3.12", "3.13"]
    }
    assert verify["timeout-minutes"] == 180
    assert workflow["jobs"]["semantic-audit"]["name"] == "phase5/semantic-audit"
    assert workflow["jobs"]["semantic-audit"]["timeout-minutes"] == 90
    semantic_projection = json.dumps(workflow["jobs"]["semantic-audit"])
    semantic_steps = workflow["jobs"]["semantic-audit"]["steps"]
    assert "cache" not in semantic_steps[2].get("with", {})
    assert all(
        step["name"] != "Install current project and verification dependencies"
        for step in semantic_steps
    )
    assert "pip install --disable-pip-version-check -e" not in semantic_projection
    policy_script = next(
        step["run"]
        for step in workflow["jobs"]["semantic-audit"]["steps"]
        if step["name"] == "Select the audit mode and severity gate"
    )
    assert (
        'if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then\n'
        "  mode=semantic-audit\n"
        "  require_zero=P0,P1,P2,P3"
    ) in policy_script
    assert "OWNER_VALUATION_REPO" not in semantic_projection
    assert "OWNER_RESEARCH_KERNEL_" not in semantic_projection
    steps = verify["steps"]
    names = [step["name"] for step in steps]
    prefetch = names.index("Prefetch and seal the exact dependency supply before private access")
    mint = names.index("Mint the scoped private-kernel reader token")
    revoke = names.index("Revoke the private-kernel reader token before candidate code runs")
    stage = names.index(
        "Stage netless, then verify in the authorized 3.11 container"
    )
    candidate = names.index("Run the exact candidate in the authorized 3.11 container")
    sanitize = names.index(
        "Delete private channels and rebuild one allowlisted canonical summary"
    )
    upload = names.index("Upload only the allowlisted canonical verification summary")
    assert prefetch < mint < revoke < stage < candidate < sanitize < upload
    assert "cache" not in steps[2].get("with", {})
    for step_name in (
        "Mint the scoped private-kernel reader token",
        "Check out the exact private-kernel source without persisted credentials",
        "Verify the pinned kernel and remove its remote",
    ):
        assert "if" not in _step(step_name)
    assert _step("Revoke the private-kernel reader token before candidate code runs")[
        "if"
    ] == "always() && steps.kernel-reader-token.outputs.token != ''"

    prefetch_run = _dependency_supply_source()
    for marker in (
        "--require-hashes",
        "--only-binary=:all:",
        "--no-deps",
        "--no-cache-dir",
        "-I -m pip download",
        "setuptools==80.9.0",
        "hatchling==1.27.0",
        "cffi==2.1.1",
        "cryptography==50.0.0",
        "pypdf==6.16.1",
        "pypdfium2==5.13.0",
        "pycparser==3.0",
        "futu-api==10.10.7008",
        "numpy==2.4.2",
        "protobuf==7.35.1",
        "--no-binary=:all:",
        "futu_api-10.10.7008.tar.gz",
        "sidecar.lock",
        "/usr/bin/docker pull --platform linux/amd64",
        "--entrypoint=/bin/sh",
        '-ceu \'test "$(command -v git)" = /usr/bin/git\'',
        'if [[ "$minor" == 3.11 ]]; then',
        "scripts/bootstrap_linux_x64_report_toolchain.py",
        "2f80b744f1e397a8b9b7570b3464c313fa14629bf358e69aa2c7b4089b3c8790",
        "NotoSansCJKsc-Regular.otf",
        "2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b",
        "f4b3aa468ddfbc8214410f611e7014f6d311a9d5922ac8e5e41ef25dbaa0775c",
        "4a2ac210d3aafabdfc2c6f887552632ec6f0dc78c6b232261445074312b1378c",
        "81a40c76ba93c36365e3ed965949685d4e1042dfb4cc5b285ef2a3f9c51a4b42",
        "feb6abd5dea694c23d4e94151ef09719f1a47e124a8d98a24d1f331a9c352f41",
        "1d224c0e9a26652d51c531f78e15de5a361d7f6f9c3029486846cce90d272f11",
        'sudo chmod 0555 "$report_runtime/tectonic"',
        'candidate.get("renderer") != linux[0].get("renderer")',
        "candidate != committed_candidate",
        "committed_candidate != linux[0]",
        'candidate.get("pdf_text_backend", {}).get("distribution") != "pypdf"',
        'candidate.get("pdf_render_backend", {}).get("distribution")',
        'observed != candidate["offline_bundle"]',
    ):
        assert marker in prefetch_run
    assert "${{ steps.python.outputs.python-path }}" in prefetch_run
    assert workflow["env"]["KERNEL_RUNTIME_IMAGE"] == (
        "docker.io/library/python@sha256:"
        "eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
    )
    assert workflow["env"]["KERNEL_RUNTIME_IMAGE_ID"] == (
        "sha256:d299dee73063206fe64248b8eb62cbef36f6baedfc2c5e2ef4c7618ad18efb3a"
    )
    assert " -e " not in prefetch_run
    assert "git+" not in prefetch_run
    assert "pip download ." not in prefetch_run
    runtime_block = prefetch_run.split('cat > "$runtime_lock" <<\'LOCK\'\n', 1)[
        1
    ].split("\nLOCK", 1)[0]
    assert set(runtime_block.splitlines()) == {
        "attrs==26.1.0 --hash=sha256:"
        "c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309",
        "jsonschema==4.26.0 --hash=sha256:"
        "d489f15263b8d200f8387e64b4c3a75f06629559fb73deb8fdfb525f2dab50ce",
        "jsonschema-specifications==2025.9.1 --hash=sha256:"
        "98802fee3a11ee76ecaca44429fda8a41bff98b00a0f2838151b113f210cc6fe",
        "referencing==0.37.0 --hash=sha256:"
        "381329a9f99628c9069361716891d34ad94af76e461dcb0335825aecc7692231",
        "rpds-py==2026.6.3 --hash=sha256:"
        "9c1255b302953c86a486b81d330d5ee1d5bd937691ce271b6be0ef0e299eaab7",
        "typing-extensions==4.16.0 --hash=sha256:"
        "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8",
    }


    candidate_run = _candidate_execution_source()
    for marker in (
        "/usr/bin/sudo -n /usr/bin/unshare",
        "--mount --net --pid --fork --kill-child --mount-proc",
        "candidate_uid=65534",
        "candidate_gid=65534",
        ': > "$private_root/stage.stdout"',
        ': > "$private_root/stage.stderr"',
        ': > "$private_root/container.stdout"',
        ': > "$private_root/container.stderr"',
        'test "$host_uid" -gt 0 && test "$host_gid" -gt 0',
        'test "$candidate_uid" -ne "$host_uid"',
        "test -x /usr/bin/setpriv",
        'test "$(id -u)" -eq 0',
        "mount --make-rprivate /",
        'test "$(readlink -f /var/run)" = /run',
        "mount -t tmpfs -o mode=0755,nosuid,nodev,noexec tmpfs /run",
        "test -x /usr/sbin/ip",
        "/usr/sbin/ip link set dev lo up",
        "/usr/sbin/ip link show dev lo | grep -F '<LOOPBACK,UP,'",
        "test -d /tmp && test ! -L /tmp",
        "mount -t tmpfs -o rw,exec,nosuid,nodev,size=268435456,mode=1777 "
        "tmpfs /tmp",
        "workspace=/run/owner-research/workspace",
        "kernel_checkout=/run/owner-research/private-kernel",
        "wheelhouse=/run/owner-research/wheelhouse",
        "supply_lock=/run/owner-research/supply.lock",
        "validator=/run/owner-research/validator.py",
        "private_root=/run/owner-research/private",
        "mkdir -m 0700 /run/owner-research/tmp",
        "-o rw,exec,nosuid,nodev,size=1073741824,mode=0700",
        "tmpfs /run/owner-research/tmp",
        "stage_code=70",
        "stage_code=75",
        "for privileged_channel in /usr/bin/docker /usr/bin/sudo",
        'mount --bind /dev/null "$privileged_channel"',
        'find "$kernel_source" -xdev',
        "-type f -links +1",
        'chown -R --no-dereference "$candidate_uid:$candidate_gid" '
        '"$kernel_source"',
        '! -user "$candidate_uid"',
        '! -group "$candidate_gid"',
        'mount --bind "$kernel_source" "$kernel_source"',
        'mount -o remount,bind,ro "$kernel_source"',
        'mount --bind "$wheelhouse_source" "$wheelhouse_source"',
        'mount -o remount,bind,ro,noexec,nosuid,nodev "$wheelhouse_source"',
        'mount --bind "$wheelhouse_source" "$wheelhouse"',
        'mount -o remount,bind,ro,noexec,nosuid,nodev "$wheelhouse"',
        'mount --bind "$supply_lock_source" "$supply_lock_source"',
        'mount -o remount,bind,ro,noexec,nosuid,nodev "$supply_lock_source"',
        'mount --bind "$supply_lock_source" "$supply_lock"',
        'mount -o remount,bind,ro,noexec,nosuid,nodev "$supply_lock"',
        'mount --bind "$validator_source" "$validator_source"',
        'mount -o remount,bind,ro,noexec,nosuid,nodev "$validator_source"',
        'mount --bind "$validator_source" "$validator"',
        'mount -o remount,bind,ro,noexec,nosuid,nodev "$validator"',
        'mount --bind "$report_runtime_source" "$report_runtime_source"',
        'mount -o remount,bind,ro,exec,nosuid,nodev "$report_runtime_source"',
        'mount --bind "$report_runtime_source" "$report_runtime"',
        'mount -o remount,bind,ro,exec,nosuid,nodev "$report_runtime"',
        '"$report_runtime/home/.cache/tectonic"',
        '"$private_root/home/.cache/tectonic"',
        'mount --bind "$private_root_source" "$private_root_source"',
        'mount -o remount,bind,rw,exec,nosuid,nodev "$private_root_source"',
        'mount --bind "$private_root_source" "$private_root"',
        'mount -o remount,bind,rw,exec,nosuid,nodev "$private_root"',
        '/usr/bin/git config --file "$private_root/home/.gitconfig"',
        '--add safe.directory "$workspace"',
        '--add safe.directory "$kernel_checkout"',
        'chown -R --no-dereference "$candidate_uid:$candidate_gid"',
        '"$private_root/venv"',
        '"$private_root/kernel-cas"',
        'chmod 0711 "$private_root"',
        'chmod 0755 "$private_root/output"',
        "stat -c '%u:%g:%a' \"$private_root\"",
        "stat -c '%u:%g:%a:%h' \"$protected_path\"",
        "/usr/bin/setpriv",
        "stage_code=80",
        "stage_code=96",
        'trap \'exit "$stage_code"\' ERR',
        "trap - ERR",
        '--reuid="$candidate_uid"',
        '--regid="$candidate_gid"',
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        'test ! -w "$private_root"',
        "test ! -x /usr/bin/docker",
        "test ! -x /usr/bin/sudo",
        "test ! -S /var/run/docker.sock",
        "test ! -S /run/docker.sock",
        'test "$(command -v docker)" = /usr/bin/docker',
        'test "$(command -v sudo)" = /usr/bin/sudo',
        "/usr/bin/env -i",
        'GIT_CONFIG_GLOBAL="$private_root/home/.gitconfig"',
        "GIT_CONFIG_COUNT=2",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_CONFIG_KEY_0=safe.directory",
        "GIT_CONFIG_KEY_1=safe.directory",
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_CONFIG_VALUE_0=/workspace",
        "GIT_CONFIG_VALUE_1=/private-kernel",
        "GIT_OPTIONAL_LOCKS=0",
        'test "$(command -v git)" = /usr/bin/git',
        'git -C "$workspace" rev-parse --show-toplevel',
        "git -C /private-kernel rev-parse --show-toplevel",
        "CapInh CapPrm CapEff CapBnd CapAmb",
        'NoNewPrivs:/ {print $2}',
        "/proc/net/dev",
        'test "${network_interfaces[*]}" = lo',
        'test -z "$(awk \'NR > 1 {print; exit}\' /proc/net/route)"',
        'findmnt -n -o OPTIONS --target "$workspace"',
        'findmnt -n -o OPTIONS --target "$kernel_checkout"',
        'findmnt -n -o OPTIONS --target "$wheelhouse"',
        'findmnt -n -o OPTIONS --target "$supply_lock"',
        'findmnt -n -o OPTIONS --target "$validator"',
        'findmnt -n -o OPTIONS --target "$report_runtime"',
        'findmnt -n -o OPTIONS --target "$report_cache"',
        'test "$(command -v tectonic)" = "$report_runtime/tectonic"',
        "93898e5680acc5ae857b96a3ac1447d84f3bb2eb8dd39398c9859e284afb5443",
        'findmnt -n -o OPTIONS --target "$private_root"',
        'test "$TMPDIR" = /run/owner-research/tmp',
        'tmp_mount_options=$(findmnt -n -o OPTIONS --target "$TMPDIR")',
        "for required_option in rw nosuid nodev",
        "for forbidden_option in ro noexec",
        "stat -c '%u:%g:%a' \"$TMPDIR\"",
        "for required_option in ro noexec nosuid nodev",
        'test -r "$validator" && test ! -w "$validator"',
        'test -r "$supply_lock" && test ! -w "$supply_lock"',
        'test -r "$wheelhouse" && test -x "$wheelhouse"',
        "PIP_NO_INDEX=1",
        "PIP_FIND_LINKS=",
        "TMPDIR=/run/owner-research/tmp",
        "--no-index",
        "--no-isolation",
        "/usr/bin/docker run --rm --interactive --pull=never",
        '--user="$candidate_uid:$candidate_gid"',
        "--platform=linux/amd64",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--cpus=1.0",
        "TMPDIR=/output/tmp",
        '"$(id -u):$(id -g):700"',
        "--mount=\"type=bind,src=$GITHUB_WORKSPACE,dst=/workspace,readonly\"",
        "--mount=\"type=bind,src=$private_kernel,dst=/private-kernel,readonly\"",
        "--mount=\"type=bind,src=$report_runtime,dst=/report-toolchain,readonly\"",
        "--mount=\"type=bind,src=$attestation_directory,dst=/run/owner-research,readonly\"",
        "--mount=\"type=bind,src=$private_root/output,dst=/output\"",
        "--entrypoint=/usr/bin/env",
        '"boundary": "trusted_workflow_authorized_container"',
        '"role": "canonical_summary_output"',
        "stat -c '%u:%g:%a:%h'",
        "OWNER_VALUATION_REPO",
        "OWNER_RESEARCH_KERNEL_CAS",
        "OWNER_RESEARCH_KERNEL_RUNTIME_MANIFEST",
        "OWNER_RESEARCH_KERNEL_RUNTIME_MANIFEST_FILE_SHA256",
        "OWNER_RESEARCH_TRUSTED_CONTAINER_ATTESTATION_SHA256",
        "HOME=/report-toolchain/home",
        "PATH=/report-toolchain:/usr/local/bin:/usr/bin:/bin",
        'test -d "$HOME/.cache/tectonic" && test ! -w "$HOME/.cache/tectonic"',
        "PHASE5_V1_KERNEL_EXECUTION_REQUIRED=0",
        "PHASE5_V1_KERNEL_EXECUTION_REQUIRED=1",
        "PHASE5_V1_SIDECAR_PYTHON",
        "futu_api-10.10.7008.tar.gz",
        "5aa0c0cfae77213d5d16bf67426c28f53a76c1dc1273f8627fb87cd40d78168e",
        "verify_sidecar_distribution.py",
        "stage.stdout",
        "stage.stderr",
        "container.stdout",
        "container.stderr",
    ):
        assert marker in candidate_run
    assert "/sys/class/net" not in candidate_run
    assert "unshare --user" not in candidate_run
    assert "--map-root-user" not in candidate_run
    assert "--init-groups" not in candidate_run
    assert '--reuid="$host_uid"' not in candidate_run
    assert '--regid="$host_gid"' not in candidate_run
    assert (
        'chown -R --no-dereference "$candidate_uid:$candidate_gid" "$workspace"'
        not in candidate_run
    )
    assert (
        'chown --no-dereference "$candidate_uid:$candidate_gid" "$workspace"'
        not in candidate_run
    )
    assert (
        'chown -R --no-dereference "$candidate_uid:$candidate_gid" '
        '"$workspace_source"' not in candidate_run
    )
    assert (
        'chown --no-dereference "$candidate_uid:$candidate_gid" "$workspace_source"'
        not in candidate_run
    )
    assert (
        'chown -R --no-dereference "$candidate_uid:$candidate_gid" "$private_root"'
        not in candidate_run
    )
    assert (
        'chown --no-dereference "$candidate_uid:$candidate_gid" "$private_root"'
        not in candidate_run
    )
    assert candidate_run.count(
        "for protected_log in stage.stdout stage.stderr container.stdout "
        "container.stderr; do"
    ) == 2
    assert "TMPDIR=/tmp" not in candidate_run
    assert candidate_run.count("TMPDIR=/run/owner-research/tmp") == 1
    assert candidate_run.count("TMPDIR=/output/tmp") == 1
    assert '"$private_root/tmp"' not in candidate_run
    assert candidate_run.index("mount --make-rprivate /") < candidate_run.index(
        "exec /usr/bin/setpriv"
    )
    assert candidate_run.index("test -d /tmp && test ! -L /tmp") < candidate_run.index(
        "mount -t tmpfs -o rw,exec,nosuid,nodev,size=268435456,mode=1777 "
        "tmpfs /tmp"
    )
    assert candidate_run.index(
        "mount -t tmpfs -o rw,exec,nosuid,nodev,size=268435456,mode=1777 "
        "tmpfs /tmp"
    ) < candidate_run.index("exec /usr/bin/setpriv")
    assert candidate_run.index("exec /usr/bin/setpriv") < candidate_run.index(
        "TMPDIR=/run/owner-research/tmp"
    )
    assert candidate_run.index("exec /usr/bin/setpriv") < candidate_run.index(
        'tmp_mount_options=$(findmnt -n -o OPTIONS --target "$TMPDIR")'
    )
    assert candidate_run.index(
        'tmp_mount_options=$(findmnt -n -o OPTIONS --target "$TMPDIR")'
    ) < candidate_run.index('"$runner_python" -I -c')
    assert candidate_run.index(
        'chown -R --no-dereference "$candidate_uid:$candidate_gid" '
        '"$kernel_source"'
    ) < candidate_run.index('mount --bind "$kernel_source" "$kernel_source"')
    assert candidate_run.index(
        'mount -o remount,bind,ro "$kernel_source"'
    ) < candidate_run.index('mount --bind "$kernel_source" "$kernel_checkout"')
    assert candidate_run.index(
        'mount -o remount,bind,ro,noexec,nosuid,nodev "$wheelhouse_source"'
    ) < candidate_run.index('mount --bind "$wheelhouse_source" "$wheelhouse"')
    assert candidate_run.index(
        'mount --bind "$wheelhouse_source" "$wheelhouse"'
    ) < candidate_run.index("exec /usr/bin/setpriv")
    assert candidate_run.index(
        'mount -o remount,bind,rw,exec,nosuid,nodev "$private_root_source"'
    ) < candidate_run.index('mount --bind "$private_root_source" "$private_root"')
    assert candidate_run.index(
        'mount --bind "$private_root_source" "$private_root"'
    ) < candidate_run.index("exec /usr/bin/setpriv")
    assert candidate_run.index("exec /usr/bin/setpriv") < candidate_run.index(
        '"$runner_python" -I "$validator"'
    )
    assert "GITHUB_ENV" not in candidate_run
    assert "GITHUB_OUTPUT" not in candidate_run
    assert "GITHUB_PATH" not in candidate_run
    assert "GITHUB_STEP_SUMMARY" not in candidate_run
    assert "docker pull" not in candidate_run
    assert "src=/var/run/docker.sock" not in candidate_run
    assert "--mount=/var/run/docker.sock" not in candidate_run
    assert "OWNER_RESEARCH_KERNEL_PYTHON" not in candidate_run
    assert "OWNER_RESEARCH_TRUSTED_CONTAINER_ATTESTATION=/" not in candidate_run

    upload_step = steps[upload]
    assert upload_step["if"] == "always() && steps.sanitize.outcome == 'success'"
    upload_path = upload_step["with"]["path"]
    assert upload_path == (
        "${{ runner.temp }}/phase5-v1-upload-${{ matrix.python-version }}/"
        "phase5-v1-verify.json"
    )
    assert not any(character in upload_path for character in "*?[")


def test_crypto_binary_supply_is_exact_for_all_supported_python_minors() -> None:
    namespace = _supply_validator_namespace()
    common = namespace["common"]
    per_minor = namespace["per_minor"]
    verify_observed = namespace["verify_observed"]
    cryptography_wheel = (
        "cryptography-50.0.0-cp311-abi3-manylinux2014_x86_64."
        "manylinux_2_17_x86_64.whl"
    )
    assert common[cryptography_wheel] == (
        "06a32a980526a6ab9a4b9bf8f7385800791e2bb960903cb6b530e4817509a3b7"
    )
    assert common["pycparser-3.0-py3-none-any.whl"] == (
        "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992"
    )
    assert common["pypdf-6.16.1-py3-none-any.whl"] == (
        "63fec31c4092ae50b6729beedcb469055b60d20c834bde1c402df241f371f644"
    )
    assert common[
        "pypdfium2-5.13.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
    ] == "81df25c1ab4c13ff773102d3cbea1967511d079123b067fc077bd0c4d57d91d8"
    prefetch = _dependency_supply_source()
    supply_lock = prefetch.split('cat > "$supply_lock" <<\'LOCK\'\n', 1)[1].split(
        "\nLOCK", 1
    )[0]
    for locked_requirement in (
        "cryptography==50.0.0 --hash=sha256:"
        "06a32a980526a6ab9a4b9bf8f7385800791e2bb960903cb6b530e4817509a3b7",
        "pycparser==3.0 --hash=sha256:"
        "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992",
        "pypdf==6.16.1 --hash=sha256:"
        "63fec31c4092ae50b6729beedcb469055b60d20c834bde1c402df241f371f644",
        "pypdfium2==5.13.0 --hash=sha256:"
        "81df25c1ab4c13ff773102d3cbea1967511d079123b067fc077bd0c4d57d91d8",
        "--hash=sha256:34e261f78cb6ceaaa36f42f2613f4380d94d9c759a9c73c769ee6e0247364632",
        "--hash=sha256:c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf",
        "--hash=sha256:a931079504ecc49efed7744c476a5c343a92fabf66dec2db95edb1b2fdc770e2",
    ):
        assert locked_requirement in supply_lock
    cffi = {
        "3.11": (
            "cffi-2.1.1-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
            "34e261f78cb6ceaaa36f42f2613f4380d94d9c759a9c73c769ee6e0247364632",
        ),
        "3.12": (
            "cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
            "c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf",
        ),
        "3.13": (
            "cffi-2.1.1-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
            "a931079504ecc49efed7744c476a5c343a92fabf66dec2db95edb1b2fdc770e2",
        ),
    }
    for minor, (filename, digest) in cffi.items():
        assert per_minor[minor][filename] == digest
        observed = common | per_minor[minor]
        verify_observed(observed, minor)
        missing = dict(observed)
        missing.pop(cryptography_wheel)
        with pytest.raises(SystemExit, match="inventory or hashes drifted"):
            verify_observed(missing, minor)
        tampered = dict(observed)
        tampered[cryptography_wheel] = "0" * 64
        with pytest.raises(SystemExit, match="inventory or hashes drifted"):
            verify_observed(tampered, minor)
        missing_transitive = dict(observed)
        missing_transitive.pop(filename)
        with pytest.raises(SystemExit, match="inventory or hashes drifted"):
            verify_observed(missing_transitive, minor)
        tampered_transitive = dict(observed)
        tampered_transitive[filename] = "0" * 64
        with pytest.raises(SystemExit, match="inventory or hashes drifted"):
            verify_observed(tampered_transitive, minor)


def test_sidecar_supply_is_exact_and_futu_sdk_is_an_honest_sdist_build() -> None:
    namespace = _supply_validator_namespace()
    common = namespace["common"]
    per_minor = namespace["per_minor"]
    verify_observed = namespace["verify_observed"]
    assert common["futu_api-10.10.7008.tar.gz"] == (
        "3c607c7dce02a3a2b308f3424420277a360d7b3a4ba4508b39eaa4ff11271f98"
    )
    assert common["protobuf-7.35.1-cp310-abi3-manylinux2014_x86_64.whl"] == (
        "74758715c53d7158fb76caf4f0cfdacc5329a4b1bb994f865d6cf302d413a1c4"
    )
    assert common["wheel-0.48.0-py3-none-any.whl"] == (
        "3217dcc807155e45db462d7ef2431f5ddda0d7273b700d05a67b271ceb1287ab"
    )
    assert common["sidecar.lock"] == (
        "444b04fda92f93a67c434e74584b5f6d072e2c79ed57c4a07f96dcdb842d36a4"
    )
    assert common["futu-source.lock"] == (
        "6da209692c78e9a5b09c6567177684876df7348dacdb7db29afaf15cdb87b048"
    )
    expected_platform_wheels = {
        "3.11": {
            "numpy-2.4.2-cp311-cp311-manylinux_2_27_x86_64."
            "manylinux_2_28_x86_64.whl": (
                "c02ef4401a506fb60b411467ad501e1429a3487abca4664871d9ae0b46c8ba32"
            ),
            "pandas-3.0.5-cp311-cp311-manylinux_2_24_x86_64."
            "manylinux_2_28_x86_64.whl": (
                "2c0cf1dd9b55a22d105fc46c1b489af3bd42264fcba7c66297bf47a9a1d9c78a"
            ),
            "simplejson-4.1.1-cp311-cp311-manylinux1_x86_64."
            "manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl": (
                "7ce252b28fddbdd83db5bd7d93dad2a8a591d7ada098afec9c1b23d6b722a7a4"
            ),
        },
        "3.12": {
            "numpy-2.4.2-cp312-cp312-manylinux_2_27_x86_64."
            "manylinux_2_28_x86_64.whl": (
                "9e35d3e0144137d9fdae62912e869136164534d64a169f86438bc9561b6ad49f"
            ),
            "pandas-3.0.5-cp312-cp312-manylinux_2_24_x86_64."
            "manylinux_2_28_x86_64.whl": (
                "d373ce03ffd84010ed9839fa73672a9c8256990532e158440c0085db7d914b34"
            ),
            "simplejson-4.1.1-cp312-cp312-manylinux1_x86_64."
            "manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl": (
                "45ec18e337fec538b7e902d489505c450b2454653d1290f3f50385e6fd8aa607"
            ),
        },
        "3.13": {
            "numpy-2.4.2-cp313-cp313-manylinux_2_27_x86_64."
            "manylinux_2_28_x86_64.whl": (
                "d0d9b7c93578baafcbc5f0b83eaf17b79d345c6f36917ba0c67f45226911d499"
            ),
            "pandas-3.0.5-cp313-cp313-manylinux_2_24_x86_64."
            "manylinux_2_28_x86_64.whl": (
                "4b11c36e218331d0387cbe3a0a5f75162357a1d92d57b2b08a336ff94b19b2be"
            ),
            "simplejson-4.1.1-cp313-cp313-manylinux1_x86_64."
            "manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl": (
                "8e5cdd6a5d52299f345c15ab5678cc4249e24f383f361d986afbc3c7072a6b6b"
            ),
        },
    }
    for minor, platform_wheels in expected_platform_wheels.items():
        assert platform_wheels.items() <= per_minor[minor].items()
        observed = common | per_minor[minor]
        verify_observed(observed, minor)
        missing_sdk = dict(observed)
        missing_sdk.pop("futu_api-10.10.7008.tar.gz")
        with pytest.raises(SystemExit, match="inventory or hashes drifted"):
            verify_observed(missing_sdk, minor)

    prefetch = _dependency_supply_source()
    sidecar_lock = prefetch.split('cat > "$sidecar_lock" <<\'LOCK\'\n', 1)[1].split(
        "\nLOCK", 1
    )[0]
    futu_source_lock = prefetch.split(
        'cat > "$futu_source_lock" <<\'LOCK\'\n', 1
    )[1].split("\nLOCK", 1)[0]
    for marker in (
        "futu-api==10.10.7008",
        "numpy==2.4.2",
        "pandas==3.0.5",
        "protobuf==7.35.1",
        "pytest==8.4.2",
        "ruff==0.12.9",
        "wheel==0.48.0",
    ):
        assert marker in sidecar_lock or marker in futu_source_lock
    assert futu_source_lock.splitlines() == [
        "futu-api==10.10.7008 --hash=sha256:"
        "3c607c7dce02a3a2b308f3424420277a360d7b3a4ba4508b39eaa4ff11271f98"
    ]
    assert prefetch.count("--no-binary=:all:") == 1
    assert "futu_api-10.10.7008-py3-none-any.whl" not in prefetch

    candidate = _candidate_execution_source()
    for marker in (
        "SOURCE_DATE_EPOCH=1580601600",
        "--no-build-isolation",
        "--no-compile",
        "futu_api-10.10.7008-py3-none-any.whl",
        "5aa0c0cfae77213d5d16bf67426c28f53a76c1dc1273f8627fb87cd40d78168e",
        "PHASE5_V1_SIDECAR_PYTHON",
    ):
        assert marker in candidate

    semantic_steps = _workflow()["jobs"]["semantic-audit"]["steps"]
    semantic_prefetch = next(
        step["run"]
        for step in semantic_steps
        if step["name"]
        == "Prefetch and seal the exact semantic supply before netless replay"
    )
    semantic_replay = next(
        step["run"]
        for step in semantic_steps
        if step["name"] == "Run candidate replay at the exact PR head or replay merged main"
    )
    assert "--require-hashes" in semantic_prefetch
    assert "--no-binary=:all:" in semantic_prefetch
    assert "--no-compile" in semantic_prefetch
    for marker in (
        'supply_lock="$RUNNER_TEMP/phase5-v1-semantic-supply.lock"',
        'python -I "$validator" "$wheelhouse" 3.11',
        "2301b798cfeea3ae4ff99cf07879222804549a09ddc5407d32f12be88236e2f3",
        "444b04fda92f93a67c434e74584b5f6d072e2c79ed57c4a07f96dcdb842d36a4",
        "6da209692c78e9a5b09c6567177684876df7348dacdb7db29afaf15cdb87b048",
        "be7237e9a0c0eb669e9186f97b1c9ec6d7a10540ad859fbf2b1ff53135bc8df7",
        '"$semantic_venv/bin/python" -I -m pip install',
        '--requirement "$supply_lock"',
        'sudo chown -R 65534:65534',
    ):
        assert marker in semantic_prefetch
    assert semantic_prefetch.index('python -I "$validator" "$wheelhouse" 3.11') < (
        semantic_prefetch.index('"$semantic_venv/bin/python" -I -m pip install')
    )
    assert semantic_prefetch.index('--requirement "$supply_lock"') < (
        semantic_prefetch.index('"$semantic_venv/bin/python" -I "$report_bootstrap_script"')
    )
    for marker in (
        "scripts/bootstrap_linux_x64_report_toolchain.py",
        "2f80b744f1e397a8b9b7570b3464c313fa14629bf358e69aa2c7b4089b3c8790",
        "2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b",
        "f4b3aa468ddfbc8214410f611e7014f6d311a9d5922ac8e5e41ef25dbaa0775c",
        "4a2ac210d3aafabdfc2c6f887552632ec6f0dc78c6b232261445074312b1378c",
        "1d224c0e9a26652d51c531f78e15de5a361d7f6f9c3029486846cce90d272f11",
        'sudo chmod 0555 "$report_runtime/tectonic"',
        'test ! -w "$report_runtime/home/.cache/tectonic"',
    ):
        assert marker in semantic_prefetch
    assert "sudo unshare --mount --net --" in semantic_replay
    assert "candidate_content != committed_candidate_content" in semantic_prefetch
    assert "committed_candidate != linux[0]" in semantic_prefetch
    assert 'test "$(readlink -f /var/run)" = /run' in semantic_replay
    assert "mount -t tmpfs -o mode=0755,nosuid,nodev,noexec tmpfs /run" in semantic_replay
    assert "/usr/sbin/ip link set dev lo up" in semantic_replay
    assert "/usr/sbin/ip link show dev lo | grep -F '<LOOPBACK,UP,'" in semantic_replay
    assert "boundary=/run/owner-research-semantic" in semantic_replay
    assert 'mkdir -m 0700 "$boundary/tmp"' in semantic_replay
    assert "-o rw,exec,nosuid,nodev,size=1073741824,mode=0700" in semantic_replay
    assert 'tmpfs "$boundary/tmp"' in semantic_replay
    assert 'TMPDIR="$tmp_root"' in semantic_replay
    assert 'test "$TMPDIR" = /run/owner-research-semantic/tmp' in semantic_replay
    assert 'tmp_mount_options=$(findmnt -n -o OPTIONS --target "$TMPDIR")' in semantic_replay
    assert "grep -Fx noexec" in semantic_replay
    assert 'research_output="$TMPDIR/research-wheel"' in semantic_replay
    assert "--no-compile" in semantic_replay
    assert "PHASE5_V1_SIDECAR_PYTHON" in semantic_replay
    assert "exec /usr/bin/setpriv" in semantic_replay
    assert '--reuid="$candidate_uid"' in semantic_replay
    assert '--bounding-set=-all' in semantic_replay
    assert 'mount -o remount,bind,ro,noexec,nosuid,nodev "$wheelhouse"' in semantic_replay
    assert 'mount -o remount,bind,ro,exec,nosuid,nodev "$report_runtime"' in semantic_replay
    assert '"$semantic_python" -I -m build' in semantic_replay
    assert '"$semantic_python" -I "$workspace/scripts/verify_wheel.py"' in semantic_replay
    assert 'test "$(command -v tectonic)"' in semantic_replay
    assert "--collect-only" not in semantic_replay
    assert "pip install --disable-pip-version-check -e" not in semantic_replay
    verifier = runpy.run_path(str(ROOT / "scripts/verify_phase5_v1.py"))
    assert verifier["SIDECAR_TEST_PATH"] == "sidecars/futu-opend/tests"


def test_semantic_supply_extractor_uses_only_stdlib_and_replays_exact_locks(
    tmp_path: Path,
) -> None:
    semantic_steps = _workflow()["jobs"]["semantic-audit"]["steps"]
    prefetch = next(
        step["run"]
        for step in semantic_steps
        if step["name"]
        == "Prefetch and seal the exact semantic supply before netless replay"
    )
    embedded = prefetch.split('"$validator" <<\'PY\'\n', 1)[1].split("\nPY", 1)[0]
    assert "import yaml" not in embedded
    destinations = [
        tmp_path / "supply.lock",
        tmp_path / "sidecar.lock",
        tmp_path / "futu-source.lock",
        tmp_path / "validator.py",
    ]
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-",
            str(CI_PATH),
            *(str(path) for path in destinations),
        ],
        input=embedded,
        text=True,
        check=True,
        capture_output=True,
    )
    assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in destinations] == [
        "2301b798cfeea3ae4ff99cf07879222804549a09ddc5407d32f12be88236e2f3",
        "444b04fda92f93a67c434e74584b5f6d072e2c79ed57c4a07f96dcdb842d36a4",
        "6da209692c78e9a5b09c6567177684876df7348dacdb7db29afaf15cdb87b048",
        "be7237e9a0c0eb669e9186f97b1c9ec6d7a10540ad859fbf2b1ff53135bc8df7",
    ]


def test_crypto_supply_lock_and_validator_cannot_be_rebound_together() -> None:
    verifier = runpy.run_path(str(ROOT / "scripts/verify_phase5_v1.py"))
    workflow_text = CI_PATH.read_text(encoding="utf-8")
    assert verifier["_kernel_reader_ci_findings"](workflow_text) == []
    crypto_sha256 = "06a32a980526a6ab9a4b9bf8f7385800791e2bb960903cb6b530e4817509a3b7"
    assert workflow_text.count(crypto_sha256) == 3
    rebound = workflow_text.replace(crypto_sha256, "0" * 64)
    findings = verifier["_kernel_reader_ci_findings"](rebound)
    assert any(
        finding.code == "P5V1-KERNEL-READER-CI"
        and "exact closed projection" in finding.message
        for finding in findings
    )


def test_linux_report_bootstrap_fixture_exercises_real_report_dependencies() -> None:
    bootstrap = runpy.run_path(
        str(ROOT / "scripts/bootstrap_linux_x64_report_toolchain.py")
    )
    fixture = bootstrap["_fixture_tex"]().decode("utf-8")

    package_markers = (
        r"\usepackage{booktabs}",
        r"\usepackage{longtable}",
        r"\usepackage{array}",
    )
    assert [fixture.index(marker) for marker in package_markers] == sorted(
        fixture.index(marker) for marker in package_markers
    )
    assert fixture.count(r"\begin{longtable}") == 30
    assert fixture.count(r"\endfirsthead") == 30
    assert fixture.count(r"\endhead") == 30
    assert fixture.count(r"\endfoot") == 30
    assert fixture.count(r"\endlastfoot") == 30
    assert fixture.count(r">{\raggedright\arraybackslash}p{") == 30
    for marker in (
        r"\tiny ",
        r"\scriptsize ",
        r"\footnotesize ",
        r"\small ",
        r"\normalsize ",
        r"\large ",
        r"\Large ",
        r"\LARGE ",
        r"\huge ",
        r"\Huge\bfseries",
        r"\fontsize{5pt}{6pt}\selectfont",
        r"\fontsize{7pt}{8pt}\selectfont",
    ):
        assert marker in fixture


@pytest.mark.parametrize(
    ("digest", "expected_count"),
    (
        (
            "2f80b744f1e397a8b9b7570b3464c313fa14629bf358e69aa2c7b4089b3c8790",
            2,
        ),
        (
            "2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b",
            2,
        ),
        (
            "f4b3aa468ddfbc8214410f611e7014f6d311a9d5922ac8e5e41ef25dbaa0775c",
            3,
        ),
        (
            "4a2ac210d3aafabdfc2c6f887552632ec6f0dc78c6b232261445074312b1378c",
            2,
        ),
        (
            "1d224c0e9a26652d51c531f78e15de5a361d7f6f9c3029486846cce90d272f11",
            2,
        ),
        (
            "93898e5680acc5ae857b96a3ac1447d84f3bb2eb8dd39398c9859e284afb5443",
            4,
        ),
    ),
)
def test_report_toolchain_supply_identity_cannot_be_rebound(
    digest: str,
    expected_count: int,
) -> None:
    verifier = runpy.run_path(str(ROOT / "scripts/verify_phase5_v1.py"))
    workflow_text = CI_PATH.read_text(encoding="utf-8")
    assert workflow_text.count(digest) == expected_count
    rebound = workflow_text.replace(digest, "0" * 64)
    findings = verifier["_kernel_reader_ci_findings"](rebound)
    assert any(
        finding.code == "P5V1-KERNEL-READER-CI"
        and "exact closed projection" in finding.message
        for finding in findings
    )


@pytest.mark.parametrize(
    ("marker", "replacement"),
    (
        (
            'python -I "$validator" "$wheelhouse" 3.11',
            'python -I "$validator" "$wheelhouse" 3.12',
        ),
        (
            '"$semantic_venv/bin/python" -I -m pip install',
            '"$semantic_venv/bin/python" -I -m pip install --no-deps',
        ),
        ("sudo unshare --mount --net --", "sudo unshare --net --"),
        (
            'mount -o remount,bind,ro,exec,nosuid,nodev "$report_runtime"',
            'mount -o remount,bind,rw,exec,nosuid,nodev "$report_runtime"',
        ),
        ("--bounding-set=-all", "--bounding-set=+all"),
    ),
)
def test_semantic_supply_or_isolation_weakening_is_rejected(
    marker: str,
    replacement: str,
) -> None:
    verifier = runpy.run_path(str(ROOT / "scripts/verify_phase5_v1.py"))
    workflow_text = CI_PATH.read_text(encoding="utf-8")
    assert marker in workflow_text
    rebound = workflow_text.replace(marker, replacement, 1)
    findings = verifier["_kernel_reader_ci_findings"](rebound)
    assert any(
        finding.code == "P5V1-KERNEL-READER-CI"
        and "exact closed projection" in finding.message
        for finding in findings
    )


def test_inline_sanitizer_removes_private_message_and_writes_one_regular_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = _sanitizer_namespace()
    sentinel = "PRIVATE_KERNEL_SENTINEL_owner_valuation_source"
    private = tmp_path / "private"
    private.mkdir()
    output_root = private / "output"
    output_root.mkdir()
    (output_root / "raw-summary.json").write_bytes(_raw_report(message=sentinel))
    cleanup_paths = [
        tmp_path / "kernel",
        tmp_path / "private-kernel",
        private,
        tmp_path / "wheelhouse",
        tmp_path / "supply.lock",
        tmp_path / "runtime.lock",
        tmp_path / "validator.py",
        tmp_path / "report-bootstrap",
        tmp_path / "report-runtime",
    ]
    for path in cleanup_paths:
        if path == private:
            continue
        if path.suffix:
            path.write_bytes(b"private")
        else:
            path.mkdir()
    upload = tmp_path / "upload"

    class Completed:
        returncode = 0

    def fake_cleanup(command: list[str], **_: object) -> Completed:
        assert command[:4] == ["/usr/bin/sudo", "/bin/rm", "-rf", "--"]
        for raw_path in command[4:]:
            path = Path(raw_path)
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        return Completed()

    monkeypatch.setattr(namespace["subprocess"], "run", fake_cleanup)
    original_write = namespace["os"].write
    write_calls = 0

    def short_write(descriptor: int, value: bytes | memoryview) -> int:
        nonlocal write_calls
        write_calls += 1
        return original_write(descriptor, value[:3])

    monkeypatch.setattr(namespace["os"], "write", short_write)
    monkeypatch.setattr(
        namespace["sys"],
        "argv",
        [
            "sanitizer",
            str(output_root),
            "raw-summary.json",
            str(private),
            str(cleanup_paths[0]),
            str(cleanup_paths[1]),
            *(str(path) for path in cleanup_paths[3:]),
            str(upload),
            "a" * 40,
            "b" * 40,
        ],
    )
    namespace["main"]()
    assert write_calls > 1
    output = upload / "phase5-v1-verify.json"
    assert output.is_file() and not output.is_symlink()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert [path.name for path in upload.iterdir()] == [output.name]
    raw = output.read_bytes()
    assert sentinel.encode() not in raw
    assert set(json.loads(raw)) == {
        "commit",
        "finding_counts",
        "findings",
        "mode",
        "test_counts",
        "tree",
    }


def test_trusted_attestation_is_canonical_and_matches_the_registered_outer_profile(
    tmp_path: Path,
) -> None:
    attestation = tmp_path / "trusted-container-attestation.json"
    image_reference = (
        "docker.io/library/python@sha256:"
        "eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
    )
    image_config = (
        "sha256:d299dee73063206fe64248b8eb62cbef36f6baedfc2c5e2ef4c7618ad18efb3a"
    )
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-",
            str(attestation),
            "1001",
            "121",
            image_reference,
            image_config,
        ],
        input=_attestation_source(),
        text=True,
        check=True,
        capture_output=True,
    )
    raw = attestation.read_bytes()
    payload = json.loads(raw)
    assert raw == json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    assert payload["image_reference"] == image_reference
    assert payload["image_config_digest"] == image_config
    assert payload["security_profile"]["boundary"] == (
        "trusted_workflow_authorized_container"
    )
    assert payload["security_profile"]["read_only_mounts"] == (
        WHEEL_VERIFIER["EXPECTED_TRUSTED_WORKFLOW"]["read_only_mounts"]
    )
    assert payload["security_profile"]["writable_mounts"] == (
        WHEEL_VERIFIER["EXPECTED_TRUSTED_WORKFLOW"]["writable_mounts"]
    )
    expected_profile_sha = hashlib.sha256(
        json.dumps(
            payload["security_profile"], separators=(",", ":"), sort_keys=True
        ).encode()
    ).hexdigest()
    assert payload["security_profile_sha256"] == expected_profile_sha


@pytest.mark.parametrize(
    "mutation",
    ("extra_key", "duplicate_key", "nonfinite", "duplicate_finding", "invalid_counts"),
)
def test_inline_sanitizer_rejects_nonclosed_json(mutation: str) -> None:
    namespace = _sanitizer_namespace()
    raw = _raw_report()
    if mutation == "extra_key":
        value = json.loads(raw)
        value["private"] = "sentinel"
        raw = json.dumps(value).encode()
    elif mutation == "duplicate_key":
        raw = raw.replace(b"{", b'{"mode":"verify",', 1)
    elif mutation == "nonfinite":
        raw = raw.replace(b'"collected": 1', b'"collected": NaN', 1)
    elif mutation == "duplicate_finding":
        value = json.loads(raw)
        value["findings"].append(dict(value["findings"][0]))
        value["P0"] = 2
        value.pop("report_sha256")
        canonical = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode()
        value["report_sha256"] = hashlib.sha256(canonical).hexdigest()
        raw = json.dumps(value).encode()
    else:
        value = json.loads(raw)
        value["tests"]["passed"] = 2
        value.pop("report_sha256")
        canonical = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode()
        value["report_sha256"] = hashlib.sha256(canonical).hexdigest()
        raw = json.dumps(value).encode()
    with pytest.raises((ValueError, json.JSONDecodeError)):
        namespace["sanitize"](raw, "a" * 40, "b" * 40)


def test_inline_sanitizer_rejects_symlink_and_oversize_raw_summary(tmp_path: Path) -> None:
    namespace = _sanitizer_namespace()
    target = tmp_path / "target.json"
    target.write_bytes(_raw_report())
    link = tmp_path / "raw-summary.json"
    link.symlink_to(target)
    with pytest.raises(OSError):
        namespace["read_raw"](tmp_path, link.name)
    link.unlink()
    link.write_bytes(b"x" * (namespace["MAXIMUM_RAW_BYTES"] + 1))
    with pytest.raises(ValueError, match="bounded"):
        namespace["read_raw"](tmp_path, link.name)


@pytest.fixture(scope="module")
def research_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    destination = tmp_path_factory.mktemp("phase5-v1-wheel")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(destination),
            str(ROOT),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    wheels = list(destination.iterdir())
    assert len(wheels) == 1
    assert VERIFY_WHEEL(wheels[0]) == ()
    return wheels[0]


def _mutate_wheel(
    source: Path,
    destination: Path,
    *,
    replacements: dict[str, bytes] | None = None,
    additions: tuple[tuple[str, bytes], ...] = (),
) -> Path:
    replacements = replacements or {}
    with zipfile.ZipFile(source) as incoming, zipfile.ZipFile(destination, "w") as outgoing:
        for item in incoming.infolist():
            outgoing.writestr(item, replacements.get(item.filename, incoming.read(item.filename)))
        for name, raw in additions:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                outgoing.writestr(name, raw)
    return destination


def test_wheel_verifier_rejects_duplicate_member(research_wheel: Path, tmp_path: Path) -> None:
    member = "owner_research/component-lock.json"
    with zipfile.ZipFile(research_wheel) as archive:
        raw = archive.read(member)
    mutated = _mutate_wheel(
        research_wheel, tmp_path / "duplicate.whl", additions=((member, raw),)
    )
    assert "duplicate archive members" in "\n".join(VERIFY_WHEEL(mutated))


def test_wheel_verifier_rejects_innocuous_extra_member(
    research_wheel: Path, tmp_path: Path
) -> None:
    mutated = _mutate_wheel(
        research_wheel,
        tmp_path / "extra-member.whl",
        additions=(("owner_research/innocent-extra.txt", b"not public"),),
    )
    assert "member inventory is not the exact public projection" in "\n".join(
        VERIFY_WHEEL(mutated)
    )


def test_wheel_verifier_rejects_nonclosed_or_rebound_lock(
    research_wheel: Path, tmp_path: Path
) -> None:
    with zipfile.ZipFile(research_wheel) as archive:
        lock = json.loads(archive.read("owner_research/component-lock.json"))
    lock["unexpected"] = True
    bad_lock = _mutate_wheel(
        research_wheel,
        tmp_path / "bad-lock.whl",
        replacements={
            "owner_research/component-lock.json": json.dumps(lock).encode(),
        },
    )
    assert "top-level shape is not closed" in "\n".join(VERIFY_WHEEL(bad_lock))
    lock.pop("unexpected")
    lock["valuation_kernel_runtime"]["expected_release_wheel_sha256"] = "0" * 64
    rebound = _mutate_wheel(
        research_wheel,
        tmp_path / "rebound-lock.whl",
        replacements={
            "owner_research/component-lock.json": json.dumps(lock).encode(),
        },
    )
    assert "release-wheel hash is not the pinned value" in "\n".join(
        VERIFY_WHEEL(rebound)
    )


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    (
        ("authority_version", "9.9.9", "authority version is not the pinned value"),
        ("manifest_policy_id", "rebound-policy", "policy identity is not the pinned value"),
    ),
)
def test_wheel_verifier_rejects_runtime_lock_identity_rebinding(
    research_wheel: Path,
    tmp_path: Path,
    field: str,
    value: str,
    expected: str,
) -> None:
    lock_member = "owner_research/component-lock.json"
    with zipfile.ZipFile(research_wheel) as archive:
        lock = json.loads(archive.read(lock_member))
    lock["valuation_kernel_runtime"][field] = value
    mutated = _mutate_wheel(
        research_wheel,
        tmp_path / f"rebound-{field}.whl",
        replacements={lock_member: json.dumps(lock).encode()},
    )
    assert expected in "\n".join(VERIFY_WHEEL(mutated))


def test_wheel_verifier_rejects_runtime_lock_path_and_duplicate_json_key(
    research_wheel: Path, tmp_path: Path
) -> None:
    lock_member = "owner_research/component-lock.json"
    with zipfile.ZipFile(research_wheel) as archive:
        lock = json.loads(archive.read(lock_member))
        raw = archive.read(lock_member)
    lock["valuation_kernel_runtime"]["runner_code"]["path"] = "runner-rebound.py"
    path_rebound = _mutate_wheel(
        research_wheel,
        tmp_path / "rebound-runtime-path.whl",
        replacements={lock_member: json.dumps(lock).encode()},
    )
    assert "runtime lock path drifted: runner_code" in "\n".join(
        VERIFY_WHEEL(path_rebound)
    )
    duplicate_json = _mutate_wheel(
        research_wheel,
        tmp_path / "duplicate-json-key.whl",
        replacements={lock_member: raw.replace(b"{", b'{"lock_version":"1.2.0",', 1)},
    )
    assert "duplicate JSON key" in "\n".join(VERIFY_WHEEL(duplicate_json))
    nonfinite_json = _mutate_wheel(
        research_wheel,
        tmp_path / "nonfinite-json.whl",
        replacements={
            lock_member: raw.replace(
                b'"generated_date"', b'"nonfinite":NaN,"generated_date"', 1
            )
        },
    )
    assert "non-finite JSON constant" in "\n".join(VERIFY_WHEEL(nonfinite_json))


@pytest.mark.parametrize(
    "authority_edge", ("result_schema", "container", "trusted_workflow")
)
def test_wheel_verifier_rejects_internally_rebound_runtime_authority(
    research_wheel: Path, tmp_path: Path, authority_edge: str
) -> None:
    lock_member = "owner_research/component-lock.json"
    authority_member = (
        "owner_research/resources/phase5-v1-kernel-runtime/runtime-authority.json"
    )
    with zipfile.ZipFile(research_wheel) as archive:
        lock = json.loads(archive.read(lock_member))
        authority = json.loads(archive.read(authority_member))
    if authority_edge == "result_schema":
        authority["runtime"]["result_schema"]["filename"] = "rebound-result.json"
    elif authority_edge == "container":
        authority["runtime"]["container"]["network_mode"] = "bridge"
    else:
        authority["runtime"]["trusted_workflow"]["writable_mounts"][0][
            "target"
        ] = "/workspace"
    authority_raw = json.dumps(authority, separators=(",", ":"), sort_keys=True).encode()
    lock["valuation_kernel_runtime"]["runtime_authority"]["sha256"] = hashlib.sha256(
        authority_raw
    ).hexdigest()
    mutated = _mutate_wheel(
        research_wheel,
        tmp_path / f"rebound-authority-{authority_edge}.whl",
        replacements={
            lock_member: json.dumps(lock).encode(),
            authority_member: authority_raw,
        },
    )
    errors = "\n".join(VERIFY_WHEEL(mutated)).lower().replace("-", " ")
    assert authority_edge.replace("_", " ") in errors


@pytest.mark.parametrize(
    ("member", "lock_key"),
    (
        ("owner_research/valuation_kernel_materializer.py", "materializer_code"),
        ("owner_research/valuation_pinned_kernel.py", "runner_code"),
        (
            "owner_research/resources/phase5-v1-kernel-runtime/runtime-authority.json",
            "runtime_authority",
        ),
    ),
)
def test_wheel_verifier_rejects_each_raw_runtime_member_tamper(
    research_wheel: Path, tmp_path: Path, member: str, lock_key: str
) -> None:
    with zipfile.ZipFile(research_wheel) as archive:
        raw = archive.read(member)
    mutated = _mutate_wheel(
        research_wheel,
        tmp_path / f"bad-{lock_key}.whl",
        replacements={member: raw + b"\n "},
    )
    assert lock_key in "\n".join(VERIFY_WHEEL(mutated))


@pytest.mark.parametrize(
    ("member", "lock_key"),
    (
        ("owner_research/valuation_kernel_materializer.py", "materializer_code"),
        ("owner_research/valuation_pinned_kernel.py", "runner_code"),
        (
            "owner_research/resources/phase5-v1-kernel-runtime/runtime-authority.json",
            "runtime_authority",
        ),
    ),
)
def test_wheel_verifier_rejects_runtime_member_and_embedded_lock_rebinding(
    research_wheel: Path, tmp_path: Path, member: str, lock_key: str
) -> None:
    lock_member = "owner_research/component-lock.json"
    with zipfile.ZipFile(research_wheel) as archive:
        lock = json.loads(archive.read(lock_member))
        rebound_raw = archive.read(member) + b"\n "
    lock["valuation_kernel_runtime"][lock_key]["sha256"] = hashlib.sha256(
        rebound_raw
    ).hexdigest()
    mutated = _mutate_wheel(
        research_wheel,
        tmp_path / f"rebound-{lock_key}.whl",
        replacements={
            lock_member: json.dumps(lock).encode(),
            member: rebound_raw,
        },
    )
    errors = "\n".join(VERIFY_WHEEL(mutated))
    assert f"runtime lock hash is not pinned: {lock_key}" in errors
    assert f"runtime member hash mismatch: {lock_key}" in errors


@pytest.mark.parametrize(
    "name",
    (
        "owner_research/private/kernel.whl",
        "owner_valuation/contracts.py",
        "owner_research/resources/phase5-v1-kernel-runtime/manifests/runtime.json",
    ),
)
def test_wheel_verifier_rejects_private_or_generated_content(
    research_wheel: Path, tmp_path: Path, name: str
) -> None:
    mutated = _mutate_wheel(
        research_wheel,
        tmp_path / (hashlib.sha256(name.encode()).hexdigest() + ".whl"),
        additions=((name, b"private sentinel"),),
    )
    assert "private-kernel, or generated runtime content" in "\n".join(
        VERIFY_WHEEL(mutated)
    )
