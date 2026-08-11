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


def _attestation_source() -> str:
    source = _step("Stage netless, then verify in the authorized 3.11 container")[
        "run"
    ]
    marker = '"$KERNEL_RUNTIME_IMAGE" "$KERNEL_RUNTIME_IMAGE_ID" <<\'PY\'\n'
    return source.split(marker, 1)[1].split("\nPY", 1)[0]


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
    assert workflow["jobs"]["semantic-audit"]["name"] == "phase5/semantic-audit"
    semantic_projection = json.dumps(workflow["jobs"]["semantic-audit"])
    assert "OWNER_VALUATION_REPO" not in semantic_projection
    assert "OWNER_RESEARCH_KERNEL_" not in semantic_projection
    steps = verify["steps"]
    names = [step["name"] for step in steps]
    prefetch = names.index("Prefetch and seal the exact binary supply before private access")
    mint = names.index("Mint the scoped private-kernel reader token")
    revoke = names.index("Revoke the private-kernel reader token before candidate code runs")
    candidate = names.index(
        "Stage netless, then verify in the authorized 3.11 container"
    )
    sanitize = names.index(
        "Delete private channels and rebuild one allowlisted canonical summary"
    )
    upload = names.index("Upload only the allowlisted canonical verification summary")
    assert prefetch < mint < revoke < candidate < sanitize < upload
    assert "cache" not in steps[1].get("with", {})
    for step_name in (
        "Mint the scoped private-kernel reader token",
        "Check out the exact private-kernel source without persisted credentials",
        "Verify the pinned kernel and remove its remote",
    ):
        assert "if" not in _step(step_name)
    assert _step("Revoke the private-kernel reader token before candidate code runs")[
        "if"
    ] == "always() && steps.kernel-reader-token.outputs.token != ''"

    prefetch_run = steps[prefetch]["run"]
    for marker in (
        "--require-hashes",
        "--only-binary=:all:",
        "--no-deps",
        "--no-cache-dir",
        "-I -m pip download",
        "setuptools==80.9.0",
        "hatchling==1.27.0",
        "/usr/bin/docker pull --platform linux/amd64",
        'if [[ "$minor" == 3.11 ]]; then',
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

    candidate_run = steps[candidate]["run"]
    for marker in (
        "unshare --user --map-root-user --mount --net --pid --fork --kill-child",
        "mount -t tmpfs -o mode=0755,nosuid,nodev,noexec tmpfs /run",
        "mount --bind /dev/null /usr/bin/docker",
        "test ! -x /usr/bin/docker",
        "test ! -S /var/run/docker.sock",
        "env -i",
        "PIP_NO_INDEX=1",
        "PIP_FIND_LINKS=",
        "--no-index",
        "--no-isolation",
        "/usr/bin/docker run --rm --interactive --pull=never",
        "--platform=linux/amd64",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--mount=\"type=bind,src=$GITHUB_WORKSPACE,dst=/workspace,readonly\"",
        "--mount=\"type=bind,src=$private_kernel,dst=/private-kernel,readonly\"",
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
        "PHASE5_V1_KERNEL_EXECUTION_REQUIRED=0",
        "PHASE5_V1_KERNEL_EXECUTION_REQUIRED=1",
        "stage.stdout",
        "stage.stderr",
        "container.stdout",
        "container.stderr",
    ):
        assert marker in candidate_run
    assert "sudo unshare" not in candidate_run
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
