from __future__ import annotations

import hashlib
import inspect
import json
import os
import stat
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from owner_research.valuation_pinned_kernel import (
    PinnedKernelExecutionError,
    _BoundedCommandTimeout,
    _canonical_bytes,
    _container_command,
    _extract_container_wheels,
    _force_remove_and_verify_container_absent,
    _host_uid_gid,
    _load_trusted_container_attestation,
    _read_root_owned_readonly_file,
    _require_read_only_attestation_mount,
    _trusted_workflow_security_profile,
    _validate_canonical_request,
    _validate_result_bytes,
    _verify_local_container_image,
    _verify_result_input_bindings,
    execute_in_authorized_container,
    execute_pinned_kernel,
)

ROOT = Path(__file__).parents[1]
AUTHORITY = json.loads(
    (
        ROOT
        / "src/owner_research/resources/phase5-v1-kernel-runtime/runtime-authority.json"
    ).read_text(encoding="utf-8")
)
CONTAINER = AUTHORITY["runtime"]["container"]
WORKFLOW = AUTHORITY["runtime"]["trusted_workflow"]


def _request() -> dict[str, object]:
    fact_ledger = {
        "entity_id": "issuer:test",
        "facts": [],
        "reporting_currency": "USD",
        "schema_version": "1.0.0",
        "sources": [],
        "valuation_date": "2026-07-10",
    }
    fact_fingerprint = hashlib.sha256(_canonical_bytes(fact_ledger)).hexdigest()
    return {
        "assumption_ledger": {
            "assumptions": [],
            "fact_ledger_fingerprint": fact_fingerprint,
            "schema_version": "1.0.0",
        },
        "fact_ledger": fact_ledger,
        "schema_version": "2.0.0",
    }


def _fingerprinted_result(request: dict[str, object]) -> dict[str, str]:
    request_bytes = _canonical_bytes(request)
    return {
        "fact_ledger_fingerprint": hashlib.sha256(
            _canonical_bytes(request["fact_ledger"])
        ).hexdigest(),
        "assumption_ledger_fingerprint": hashlib.sha256(
            _canonical_bytes(request["assumption_ledger"])
        ).hexdigest(),
        "model_input_fingerprint": hashlib.sha256(request_bytes).hexdigest(),
    }


def _fingerprint_schema() -> dict[str, object]:
    fingerprint = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "fact_ledger_fingerprint",
            "assumption_ledger_fingerprint",
            "model_input_fingerprint",
        ],
        "properties": {
            "fact_ledger_fingerprint": fingerprint,
            "assumption_ledger_fingerprint": fingerprint,
            "model_input_fingerprint": fingerprint,
        },
    }


def test_request_transport_requires_byte_canonical_object_and_binary64_assumptions() -> None:
    canonical = _canonical_bytes(_request())
    assert _validate_canonical_request(canonical) == _request()
    with pytest.raises(PinnedKernelExecutionError, match="canonical"):
        _validate_canonical_request(b'{"schema_version": "2.0.0"}')
    with pytest.raises(PinnedKernelExecutionError, match="JSON"):
        _validate_canonical_request(b"not json")

    integer_assumption = _request()
    integer_assumption["assumption_ledger"]["assumptions"] = [  # type: ignore[index]
        {"assumption_id": "assumption:test", "value": 200}
    ]
    with pytest.raises(PinnedKernelExecutionError, match="binary64"):
        _validate_canonical_request(_canonical_bytes(integer_assumption))


def test_result_bytes_are_schema_valid_canonical_and_bound_to_exact_request() -> None:
    request = _request()
    request_bytes = _canonical_bytes(request)
    result = _fingerprinted_result(request)
    result_bytes = _canonical_bytes(result)
    observed, fingerprints = _validate_result_bytes(
        result_bytes=result_bytes,
        request_bytes=request_bytes,
        request=request,
        schema=_fingerprint_schema(),
    )
    assert observed == result
    assert fingerprints == tuple(result.values())
    with pytest.raises(PinnedKernelExecutionError, match="canonical"):
        _validate_result_bytes(
            result_bytes=result_bytes + b"\n",
            request_bytes=request_bytes,
            request=request,
            schema=_fingerprint_schema(),
        )
    malformed = dict(result)
    malformed["unexpected"] = "field"
    with pytest.raises(PinnedKernelExecutionError, match="Schema"):
        _validate_result_bytes(
            result_bytes=_canonical_bytes(malformed),
            request_bytes=request_bytes,
            request=request,
            schema=_fingerprint_schema(),
        )


def test_result_fingerprints_must_round_trip_exact_request_subtrees() -> None:
    request = _request()
    request_bytes = _canonical_bytes(request)
    expected = _fingerprinted_result(request)
    assert _verify_result_input_bindings(request_bytes, request, expected) == tuple(
        expected.values()
    )
    tampered = dict(expected)
    tampered["model_input_fingerprint"] = "0" * 64
    with pytest.raises(PinnedKernelExecutionError, match="do not round-trip"):
        _verify_result_input_bindings(request_bytes, request, tampered)


def test_execution_has_no_caller_executable_or_container_override() -> None:
    parameters = inspect.signature(execute_pinned_kernel).parameters
    assert "python_executable" not in parameters
    assert "docker_executable" not in parameters
    assert "image_reference" not in parameters
    assert set(inspect.signature(execute_in_authorized_container).parameters) == {
        "request_bytes",
        "runtime_manifest",
        "runtime_manifest_file_sha256",
        "cas_root",
        "timeout_seconds",
    }
    with pytest.raises(TypeError, match="python_executable"):
        execute_pinned_kernel(  # type: ignore[call-arg]
            _canonical_bytes(_request()),
            runtime_manifest=Path("/does/not/exist"),
            runtime_manifest_file_sha256="0" * 64,
            cas_root=Path("/does/not/exist"),
            python_executable=Path("/tmp/attacker"),
        )


def test_execution_fails_before_manifest_on_non_linux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("owner_research.valuation_pinned_kernel.platform.system", lambda: "Darwin")
    with pytest.raises(PinnedKernelExecutionError, match="Linux x86_64"):
        execute_pinned_kernel(
            _canonical_bytes(_request()),
            runtime_manifest=Path("/does/not/exist"),
            runtime_manifest_file_sha256="0" * 64,
            cas_root=Path("/does/not/exist"),
        )


def test_container_command_is_closed_netless_read_only_and_non_root(tmp_path: Path) -> None:
    command = _container_command(
        docker=Path("/usr/bin/docker"),
        container=CONTAINER,
        uid=1001,
        gid=1002,
        wheelhouse=tmp_path / "wheelhouse",
        request_path=tmp_path / "request.json",
        runner_path=tmp_path / "runner.py",
        manifest_path=tmp_path / "manifest.json",
        cidfile=tmp_path / "kernel.cid",
        container_name="owner-research-kernel-test",
    )
    assert command[:4] == ("/usr/bin/docker", "run", "--rm", "--interactive")
    for required in (
        "--pull=never",
        "--platform=linux/amd64",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--user=1001:1002",
        "--name=owner-research-kernel-test",
        f"--cidfile={tmp_path / 'kernel.cid'}",
        "--entrypoint=/usr/local/bin/python3",
    ):
        assert command.count(required) == 1
    assert sum(item.startswith("--mount=") for item in command) == 4
    assert all(
        item.endswith(",readonly") for item in command if item.startswith("--mount=")
    )
    assert sum(item.startswith("--tmpfs=/tmp:") for item in command) == 1
    assert all("docker.sock" not in item for item in command)
    assert "--privileged" not in command
    assert CONTAINER["image_reference"] in command
    assert command[-4:] == (
        "--container-runner",
        "/runtime/wheelhouse",
        "/runtime/runtime-manifest.json",
        "/runtime/request.json",
    )
    assert command.count("-S") == 1


def test_wrong_local_image_config_or_manifest_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    inspected = [
        {
            "Id": CONTAINER["image_config_digest"],
            "RepoDigests": [
                f"python@{CONTAINER['image_manifest_digest']}",
            ],
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {"Env": [f"PYTHON_VERSION={CONTAINER['python_patch']}"]},
        }
    ]

    def completed(*args: object, **kwargs: object) -> tuple[int, bytes, bytes]:
        return 0, json.dumps(inspected).encode("utf-8"), b""

    monkeypatch.setattr(
        "owner_research.valuation_pinned_kernel._run_bounded_command", completed
    )
    identity_sha, inspect_sha = _verify_local_container_image(
        docker=Path("/usr/bin/docker"),
        container=CONTAINER,
        environment={},
        working_directory=tmp_path,
    )
    assert len(identity_sha) == len(inspect_sha) == 64

    inspected[0]["Id"] = "sha256:" + "0" * 64
    with pytest.raises(PinnedKernelExecutionError, match="pinned identity"):
        _verify_local_container_image(
            docker=Path("/usr/bin/docker"),
            container=CONTAINER,
            environment={},
            working_directory=tmp_path,
        )


def test_timed_out_docker_container_is_force_removed_and_verified_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cid = "a" * 64
    cidfile = tmp_path / "kernel.cid"
    cidfile.write_text(cid, encoding="ascii")
    calls: list[tuple[str, ...]] = []

    def command(
        argv: tuple[str, ...], **kwargs: object
    ) -> tuple[int, bytes, bytes]:
        calls.append(argv)
        if argv[2:4] == ("rm", "--force"):
            return 0, (cid + "\n").encode(), b""
        return 1, b"", f"Error: No such object: {cid}\n".encode()

    monkeypatch.setattr(
        "owner_research.valuation_pinned_kernel._run_bounded_command", command
    )
    monkeypatch.setattr("owner_research.valuation_pinned_kernel.time.sleep", lambda _: None)
    _force_remove_and_verify_container_absent(
        docker=Path("/usr/bin/docker"),
        cidfile=cidfile,
        container_name="owner-research-kernel-fallback",
        environment={},
        working_directory=tmp_path,
    )
    assert calls == [
        command
        for _ in range(3)
        for command in (
            ("/usr/bin/docker", "container", "rm", "--force", cid),
            ("/usr/bin/docker", "container", "inspect", cid),
        )
    ]
    assert issubclass(_BoundedCommandTimeout, RuntimeError)


def test_cleanup_stability_window_catches_late_container_creation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    name = "owner-research-kernel-late"
    inspect_count = 0
    calls: list[tuple[str, ...]] = []

    def command(argv: tuple[str, ...], **kwargs: object) -> tuple[int, bytes, bytes]:
        nonlocal inspect_count
        calls.append(argv)
        if argv[2:4] == ("rm", "--force"):
            return 0, b"", b""
        inspect_count += 1
        if inspect_count == 2:
            return 0, b'[{"Id":"late"}]', b""
        return 1, b"", f"Error: No such object: {name}\n".encode()

    monkeypatch.setattr(
        "owner_research.valuation_pinned_kernel._run_bounded_command", command
    )
    monkeypatch.setattr("owner_research.valuation_pinned_kernel.time.sleep", lambda _: None)
    _force_remove_and_verify_container_absent(
        docker=Path("/usr/bin/docker"),
        cidfile=tmp_path / "missing.cid",
        container_name=name,
        environment={},
        working_directory=tmp_path,
    )
    assert inspect_count == 5
    assert len(calls) == 10


def test_container_cleanup_rejects_daemon_permission_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def command(
        argv: tuple[str, ...], **kwargs: object
    ) -> tuple[int, bytes, bytes]:
        if argv[2:4] == ("rm", "--force"):
            return 1, b"", b"permission denied"
        return 1, b"", b"permission denied"

    monkeypatch.setattr(
        "owner_research.valuation_pinned_kernel._run_bounded_command", command
    )
    with pytest.raises(PinnedKernelExecutionError, match="survived cleanup"):
        _force_remove_and_verify_container_absent(
            docker=Path("/usr/bin/docker"),
            cidfile=tmp_path / "missing.cid",
            container_name="owner-research-kernel-fallback",
            environment={},
            working_directory=tmp_path,
        )


def test_root_user_namespace_recovers_one_non_root_host_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("owner_research.valuation_pinned_kernel.os.getuid", lambda: 0)
    monkeypatch.setattr("owner_research.valuation_pinned_kernel.os.getgid", lambda: 0)

    def mapping(path: Path, **kwargs: object) -> bytes:
        return b"0 1001 1\n" if path.name == "uid_map" else b"0 1002 1\n"

    monkeypatch.setattr(
        "owner_research.valuation_pinned_kernel._read_regular_file_nofollow", mapping
    )
    assert _host_uid_gid() == (1001, 1002)

    def root_mapping(path: Path, **kwargs: object) -> bytes:
        return b"0 0 4294967295\n"

    monkeypatch.setattr(
        "owner_research.valuation_pinned_kernel._read_regular_file_nofollow", root_mapping
    )
    with pytest.raises(PinnedKernelExecutionError, match="non-root"):
        _host_uid_gid()


def test_trusted_container_attestation_is_closed_and_hash_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _trusted_workflow_security_profile(
        container=CONTAINER,
        workflow=WORKFLOW,
        uid=1001,
        gid=1002,
    )
    attestation = {
        "schema_version": "1.0.0",
        "authority_kind": "trusted_workflow_container",
        "image_reference": CONTAINER["image_reference"],
        "image_manifest_digest": CONTAINER["image_manifest_digest"],
        "image_config_digest": CONTAINER["image_config_digest"],
        "platform": CONTAINER["platform"],
        "python_patch": CONTAINER["python_patch"],
        "security_profile": profile,
        "security_profile_sha256": hashlib.sha256(_canonical_bytes(profile)).hexdigest(),
    }
    raw = _canonical_bytes(attestation)
    digest = hashlib.sha256(raw).hexdigest()
    monkeypatch.setenv(WORKFLOW["attestation_sha256_env"], digest)
    monkeypatch.setattr(
        "owner_research.valuation_pinned_kernel._require_read_only_attestation_mount",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "owner_research.valuation_pinned_kernel._read_root_owned_readonly_file",
        lambda path: raw,
    )
    assert _load_trusted_container_attestation(
        container=CONTAINER, workflow=WORKFLOW, uid=1001, gid=1002
    ) == (digest, attestation["security_profile_sha256"])
    monkeypatch.setenv(WORKFLOW["attestation_sha256_env"], "0" * 64)
    with pytest.raises(PinnedKernelExecutionError, match="hash mismatch"):
        _load_trusted_container_attestation(
            container=CONTAINER, workflow=WORKFLOW, uid=1001, gid=1002
        )


def test_attestation_inode_metadata_and_symlink_are_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    attestation = tmp_path / "attestation.json"
    attestation.write_bytes(b"{}")
    original_fstat = os.fstat

    def metadata(*, uid: int = 0, mode: int = 0o444, nlink: int = 1):
        def fake_fstat(descriptor: int) -> SimpleNamespace:
            observed = original_fstat(descriptor)
            return SimpleNamespace(
                st_mode=stat.S_IFREG | mode,
                st_uid=uid,
                st_gid=0,
                st_nlink=nlink,
                st_size=observed.st_size,
                st_dev=observed.st_dev,
                st_ino=observed.st_ino,
                st_mtime_ns=observed.st_mtime_ns,
            )

        return fake_fstat

    monkeypatch.setattr(
        "owner_research.valuation_pinned_kernel.os.fstat", metadata()
    )
    assert _read_root_owned_readonly_file(attestation) == b"{}"
    for fake in (metadata(uid=1001), metadata(mode=0o644), metadata(nlink=2)):
        monkeypatch.setattr("owner_research.valuation_pinned_kernel.os.fstat", fake)
        with pytest.raises(PinnedKernelExecutionError, match="ownership or mode"):
            _read_root_owned_readonly_file(attestation)
    link = tmp_path / "attestation-link.json"
    link.symlink_to(attestation)
    monkeypatch.setattr(
        "owner_research.valuation_pinned_kernel.os.fstat", metadata()
    )
    with pytest.raises(PinnedKernelExecutionError, match="unavailable"):
        _read_root_owned_readonly_file(link)


@pytest.mark.parametrize(
    ("mountinfo", "accepted"),
    [
        (
            b"42 35 0:40 / /run/owner-research ro,nosuid - tmpfs tmpfs ro\n",
            True,
        ),
        (b"42 35 0:40 / /run/owner-research rw - tmpfs tmpfs rw\n", False),
        (b"42 35 0:40 / /run/other ro - tmpfs tmpfs ro\n", False),
        (b"", False),
    ],
)
def test_attestation_requires_exact_read_only_mount(
    monkeypatch: pytest.MonkeyPatch, mountinfo: bytes, accepted: bool
) -> None:
    monkeypatch.setattr(
        "owner_research.valuation_pinned_kernel._read_regular_file_nofollow",
        lambda *args, **kwargs: mountinfo,
    )
    def call() -> None:
        _require_read_only_attestation_mount(
            path=Path("/run/owner-research/trusted-container-attestation.json"),
            mount_target=Path("/run/owner-research"),
        )
    if accepted:
        call()
    else:
        with pytest.raises(PinnedKernelExecutionError, match="mount"):
            call()


def test_runtime_wheel_extraction_rejects_cross_wheel_path_collision(
    tmp_path: Path,
) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel_items = []
    for index in range(2):
        filename = f"wheel-{index}.whl"
        wheel = wheelhouse / filename
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("same/module.py", f"value={index}".encode())
        raw = wheel.read_bytes()
        wheel_items.append(
            {"filename": filename, "sha256": hashlib.sha256(raw).hexdigest()}
        )
    schema = wheelhouse / "result.schema.json"
    schema.write_text("{}", encoding="utf-8")
    with pytest.raises(PinnedKernelExecutionError, match="path collision"):
        _extract_container_wheels(
            manifest={
                "wheels": wheel_items,
                "result_schema": {"filename": schema.name},
            },
            wheelhouse=wheelhouse,
            destination=tmp_path / "site",
        )


def test_runtime_wheelhouse_rejects_symbolic_link_member(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    schema = wheelhouse / "result.schema.json"
    schema.write_text("{}", encoding="utf-8")
    target = tmp_path / "target.whl"
    target.write_bytes(b"not a wheel")
    (wheelhouse / "runtime.whl").symlink_to(target)
    with pytest.raises(PinnedKernelExecutionError, match="non-regular"):
        _extract_container_wheels(
            manifest={
                "wheels": [{"filename": "runtime.whl", "sha256": "0" * 64}],
                "result_schema": {"filename": schema.name},
            },
            wheelhouse=wheelhouse,
            destination=tmp_path / "site",
        )


def test_runner_source_has_one_public_kernel_call_and_no_old_isolation_claims() -> None:
    source = (ROOT / "src/owner_research/valuation_pinned_kernel.py").read_text(
        encoding="utf-8"
    )
    assert source.count("owner_valuation.run_dual_panel(request)") == 1
    assert "python_executable:" not in source
    assert "/usr/bin/unshare" not in source
    assert "child-netns.txt" not in source
    assert "addaudithook" not in source
    assert "requests." not in source
    assert "httpx" not in source
    package_root = (ROOT / "src/owner_research/__init__.py").read_text(encoding="utf-8")
    cli = (ROOT / "src/owner_research/cli.py").read_text(encoding="utf-8")
    for symbol in ("execute_pinned_kernel", "execute_in_authorized_container"):
        assert symbol not in package_root
        assert symbol not in cli
