"""Fail-closed execution of the pinned valuation kernel runtime.

The public research process never imports the valuation kernel.  A trusted
orchestrator may call :func:`execute_pinned_kernel`, which verifies a local,
digest-addressed Linux container and starts it with a closed security profile.
The same raw-byte-bound file is the container entry point.  The child extracts
only the registered wheels into tmpfs, calls the pinned public kernel API once,
and writes canonical result bytes to stdout.  The parent validates those exact
bytes again against the pinned result Schema and input fingerprints.

This module deliberately has no package-root, CLI, or Skill export.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import resource
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

_CANONICAL_JSON_KWARGS = {
    "allow_nan": False,
    "ensure_ascii": False,
    "separators": (",", ":"),
    "sort_keys": True,
}
_MAX_REQUEST_BYTES = 16 * 1024 * 1024
_MAX_RESULT_BYTES = 32 * 1024 * 1024
_MAX_DIAGNOSTIC_BYTES = 64 * 1024
_FIXED_ERROR = b"pinned-kernel-runner-error\n"
_DOCKER_EXECUTABLE = Path("/usr/bin/docker")
_CONTAINER_ROOT = Path("/runtime")
_CONTAINER_WHEELHOUSE = _CONTAINER_ROOT / "wheelhouse"
_CONTAINER_REQUEST = _CONTAINER_ROOT / "request.json"
_CONTAINER_RUNNER = _CONTAINER_ROOT / "pinned-runner.py"
_CONTAINER_MANIFEST = _CONTAINER_ROOT / "runtime-manifest.json"


class PinnedKernelExecutionError(RuntimeError):
    """The pinned runtime or isolated kernel execution failed closed."""


class _BoundedCommandTimeout(RuntimeError):
    """A bounded trusted subprocess exceeded its registered wall time."""


@dataclass(frozen=True, slots=True)
class PinnedKernelExecutionResult:
    execution_boundary: str
    request_sha256: str
    result_sha256: str
    result_bytes: bytes
    kernel_wheel_sha256: str
    runtime_authority_sha256: str
    runtime_manifest_file_sha256: str
    runtime_manifest_fingerprint: str
    runner_sha256: str
    result_schema_sha256: str
    wheel_inventory_sha256: str
    docker_executable_sha256: str | None
    container_image_reference: str
    container_image_manifest_digest: str
    container_image_config_digest: str
    container_platform: str
    container_identity_sha256: str | None
    docker_image_inspect_sha256: str | None
    container_security_profile_sha256: str
    trusted_workflow_attestation_sha256: str | None
    fact_ledger_fingerprint: str
    assumption_ledger_fingerprint: str
    model_input_fingerprint: str
    kernel_call_count: int


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, **_CANONICAL_JSON_KWARGS).encode("utf-8")


def _strict_json_loads(value: bytes) -> Any:
    def reject_constant(token: str) -> None:
        raise ValueError(f"non-finite JSON constant: {token}")

    return json.loads(value, parse_constant=reject_constant)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_regular_file_nofollow(
    path: Path, *, maximum_size: int = 256 * 1024 * 1024
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PinnedKernelExecutionError(f"unavailable non-symlink input: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_size:
            raise PinnedKernelExecutionError(f"unbounded or non-regular input: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_size + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_size:
                raise PinnedKernelExecutionError(f"input exceeds the size limit: {path}")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise PinnedKernelExecutionError(f"input changed while being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_private_file(path: Path, payload: bytes, *, mode: int = 0o400) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PinnedKernelExecutionError("private staging write did not complete")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def verify_runtime_wheelhouse(
    *,
    runtime_manifest: Path,
    runtime_manifest_file_sha256: str,
    cas_root: Path,
) -> dict[str, Any]:
    """Bind current code, authority, manifest bytes, Schema, and every CAS wheel."""

    from .valuation_kernel_materializer import (
        KernelMaterializationError,
        load_and_verify_runtime_manifest,
    )

    try:
        return load_and_verify_runtime_manifest(
            runtime_manifest,
            cas_root=cas_root,
            expected_manifest_file_sha256=runtime_manifest_file_sha256,
        )
    except KernelMaterializationError as exc:
        raise PinnedKernelExecutionError("runtime wheelhouse verification failed") from exc


def _safe_runtime_member(name: str) -> None:
    pure = PurePosixPath(name)
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or ".." in pure.parts
        or any(part.endswith(".data") for part in pure.parts)
    ):
        raise PinnedKernelExecutionError(f"forbidden runtime wheel member: {name!r}")


def _wheel_inventory_sha256(manifest: Mapping[str, Any]) -> str:
    return _sha256(_canonical_bytes(manifest["wheels"]))


def _extract_container_wheels(
    *, manifest: Mapping[str, Any], wheelhouse: Path, destination: Path
) -> None:
    expected_names = {str(item["filename"]) for item in manifest["wheels"]}
    expected_names.add(str(manifest["result_schema"]["filename"]))
    try:
        children = tuple(wheelhouse.iterdir())
    except OSError as exc:
        raise PinnedKernelExecutionError("container wheelhouse is unavailable") from exc
    observed_names: set[str] = set()
    for item in children:
        try:
            details = item.lstat()
        except OSError as exc:
            raise PinnedKernelExecutionError("container wheelhouse member is unavailable") from exc
        if not stat.S_ISREG(details.st_mode):
            raise PinnedKernelExecutionError(
                "container wheelhouse contains a non-regular member"
            )
        observed_names.add(item.name)
    if observed_names != expected_names:
        raise PinnedKernelExecutionError("container wheelhouse inventory mismatch")

    observed_members: set[str] = set()
    total_uncompressed = 0
    for item in manifest["wheels"]:
        wheel_path = wheelhouse / str(item["filename"])
        raw = _read_regular_file_nofollow(wheel_path)
        if _sha256(raw) != item["sha256"]:
            raise PinnedKernelExecutionError("container runtime wheel hash mismatch")
        archive: zipfile.ZipFile | None = None
        try:
            archive = zipfile.ZipFile(io.BytesIO(raw))
            if archive.testzip() is not None:
                raise PinnedKernelExecutionError("runtime wheel CRC verification failed")
            for info in archive.infolist():
                _safe_runtime_member(info.filename)
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise PinnedKernelExecutionError(
                        "runtime wheel contains a symbolic link"
                    )
                if info.is_dir():
                    continue
                if info.filename in observed_members:
                    raise PinnedKernelExecutionError(
                        "runtime wheels contain a path collision"
                    )
                total_uncompressed += info.file_size
                if (
                    info.file_size > 64 * 1024 * 1024
                    or total_uncompressed > 256 * 1024 * 1024
                ):
                    raise PinnedKernelExecutionError(
                        "runtime wheel extraction exceeds limits"
                    )
                target = destination.joinpath(*PurePosixPath(info.filename).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                _write_private_file(target, archive.read(info.filename), mode=0o400)
                observed_members.add(info.filename)
        except zipfile.BadZipFile as exc:
            raise PinnedKernelExecutionError("runtime wheel is not a valid ZIP") from exc
        finally:
            if archive is not None:
                archive.close()


def _validate_canonical_request(request_bytes: bytes) -> dict[str, Any]:
    if not request_bytes or len(request_bytes) > _MAX_REQUEST_BYTES:
        raise PinnedKernelExecutionError("canonical request byte length is invalid")
    try:
        payload = _strict_json_loads(request_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PinnedKernelExecutionError("valuation request is invalid JSON") from exc
    if not isinstance(payload, dict) or _canonical_bytes(payload) != request_bytes:
        raise PinnedKernelExecutionError("valuation request is not a canonical JSON object")
    try:
        assumptions = payload["assumption_ledger"]["assumptions"]
    except (KeyError, TypeError) as exc:
        raise PinnedKernelExecutionError("valuation request omits AssumptionLedger") from exc
    if not isinstance(assumptions, list):
        raise PinnedKernelExecutionError("AssumptionLedger assumptions must be a list")
    if any(
        not isinstance(item, dict)
        or isinstance(item.get("value"), (bool, int))
        or not isinstance(item.get("value"), float)
        for item in assumptions
    ):
        raise PinnedKernelExecutionError(
            "AssumptionLedger values are not canonical rc.2 binary64 numbers"
        )
    return payload


def _verify_result_input_bindings(
    request_bytes: bytes, request: Mapping[str, Any], result: Mapping[str, Any]
) -> tuple[str, str, str]:
    try:
        fact_fingerprint = _sha256(_canonical_bytes(request["fact_ledger"]))
        assumption_fingerprint = _sha256(_canonical_bytes(request["assumption_ledger"]))
    except (KeyError, TypeError) as exc:
        raise PinnedKernelExecutionError("canonical request omits a bound ledger") from exc
    model_fingerprint = _sha256(request_bytes)
    if (
        result.get("fact_ledger_fingerprint"),
        result.get("assumption_ledger_fingerprint"),
        result.get("model_input_fingerprint"),
    ) != (fact_fingerprint, assumption_fingerprint, model_fingerprint):
        raise PinnedKernelExecutionError("kernel result input fingerprints do not round-trip")
    return fact_fingerprint, assumption_fingerprint, model_fingerprint


def _load_result_schema(manifest: Mapping[str, Any], wheelhouse: Path) -> dict[str, Any]:
    schema_entry = manifest["result_schema"]
    schema_bytes = _read_regular_file_nofollow(
        wheelhouse / str(schema_entry["filename"]), maximum_size=8 * 1024 * 1024
    )
    if _sha256(schema_bytes) != schema_entry["sha256"]:
        raise PinnedKernelExecutionError("pinned result Schema hash mismatch")
    try:
        schema = _strict_json_loads(schema_bytes)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PinnedKernelExecutionError("pinned result Schema is invalid JSON") from exc
    if not isinstance(schema, dict):
        raise PinnedKernelExecutionError("pinned result Schema is not an object")
    return schema


def _validate_result_schema(result: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    try:
        from jsonschema import Draft202012Validator

        Draft202012Validator.check_schema(schema)
        errors = tuple(Draft202012Validator(schema).iter_errors(result))
    except Exception as exc:  # pragma: no cover - dependency failure is fail-closed
        raise PinnedKernelExecutionError("pinned result Schema could not be applied") from exc
    if errors:
        raise PinnedKernelExecutionError("kernel result failed the pinned result Schema")


def _validate_result_bytes(
    *,
    result_bytes: bytes,
    request_bytes: bytes,
    request: Mapping[str, Any],
    schema: Mapping[str, Any],
) -> tuple[dict[str, Any], tuple[str, str, str]]:
    if not result_bytes or len(result_bytes) > _MAX_RESULT_BYTES:
        raise PinnedKernelExecutionError("isolated kernel result byte length is invalid")
    try:
        result = _strict_json_loads(result_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PinnedKernelExecutionError("isolated kernel result is invalid JSON") from exc
    if not isinstance(result, dict) or _canonical_bytes(result) != result_bytes:
        raise PinnedKernelExecutionError("isolated kernel result is not canonical JSON")
    _validate_result_schema(result, schema)
    fingerprints = _verify_result_input_bindings(request_bytes, request, result)
    return result, fingerprints


def _validated_docker_executable() -> tuple[Path, str]:
    try:
        details = _DOCKER_EXECUTABLE.lstat()
    except OSError as exc:
        raise PinnedKernelExecutionError("fixed Docker executable is unavailable") from exc
    if not stat.S_ISREG(details.st_mode) or not os.access(_DOCKER_EXECUTABLE, os.X_OK):
        raise PinnedKernelExecutionError(
            "fixed Docker executable must be a non-symlink executable file"
        )
    return _DOCKER_EXECUTABLE, _sha256(_read_regular_file_nofollow(_DOCKER_EXECUTABLE))


def _host_uid_gid() -> tuple[int, int]:
    uid, gid = os.getuid(), os.getgid()
    if uid > 0 and gid > 0:
        return uid, gid

    def mapped_host_identifier(path: Path) -> int:
        try:
            rows = _read_regular_file_nofollow(path, maximum_size=4096).decode("ascii").splitlines()
            parsed = tuple(tuple(int(part) for part in row.split()) for row in rows if row)
        except (UnicodeError, ValueError) as exc:
            raise PinnedKernelExecutionError("user-namespace identity map is invalid") from exc
        if len(parsed) != 1 or len(parsed[0]) != 3:
            raise PinnedKernelExecutionError("user-namespace identity map is not closed")
        inside, outside, length = parsed[0]
        if (inside, length) != (0, 1) or outside <= 0:
            raise PinnedKernelExecutionError("user namespace does not map one non-root host id")
        return outside

    if uid == 0 and gid == 0:
        uid = mapped_host_identifier(Path("/proc/self/uid_map"))
        gid = mapped_host_identifier(Path("/proc/self/gid_map"))
    if uid <= 0 or gid <= 0:
        raise PinnedKernelExecutionError(
            "container execution requires a non-root host uid and gid"
        )
    return uid, gid


def _docker_environment(config_directory: Path) -> dict[str, str]:
    return {
        "DOCKER_CONFIG": str(config_directory),
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "HOME": str(config_directory),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }


def _set_cli_file_limit() -> None:
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (_MAX_RESULT_BYTES + _MAX_DIAGNOSTIC_BYTES,)
        * 2,
    )
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _run_bounded_command(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    input_bytes: bytes | None,
    working_directory: Path,
    timeout_seconds: int,
    output_stem: str,
) -> tuple[int, bytes, bytes]:
    if not output_stem or any(
        character not in "abcdefghijklmnopqrstuvwxyz-" for character in output_stem
    ):
        raise PinnedKernelExecutionError("bounded command output identity is invalid")
    stdout_path = working_directory / f"{output_stem}.stdout"
    stderr_path = working_directory / f"{output_stem}.stderr"
    stdout_descriptor = os.open(
        stdout_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    stderr_descriptor = os.open(
        stderr_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        completed = subprocess.run(
            tuple(command),
            input=input_bytes,
            stdout=stdout_descriptor,
            stderr=stderr_descriptor,
            env=dict(environment),
            cwd=working_directory,
            timeout=timeout_seconds,
            preexec_fn=_set_cli_file_limit,
        )
    except subprocess.TimeoutExpired as exc:
        raise _BoundedCommandTimeout from exc
    except OSError as exc:
        raise PinnedKernelExecutionError("fixed Docker command failed") from exc
    finally:
        os.close(stdout_descriptor)
        os.close(stderr_descriptor)
    stdout = _read_regular_file_nofollow(
        stdout_path, maximum_size=_MAX_RESULT_BYTES + 1
    )
    stderr = _read_regular_file_nofollow(
        stderr_path, maximum_size=_MAX_DIAGNOSTIC_BYTES + 1
    )
    return completed.returncode, stdout, stderr


def _normalized_repository(repository: str) -> str:
    if repository.startswith("docker.io/library/"):
        return repository.removeprefix("docker.io/library/")
    if repository.startswith("library/"):
        return repository.removeprefix("library/")
    return repository


def _verify_local_container_image(
    *,
    docker: Path,
    container: Mapping[str, Any],
    environment: Mapping[str, str],
    working_directory: Path,
) -> tuple[str, str]:
    _validate_container_policy(container)
    try:
        returncode, stdout, stderr = _run_bounded_command(
            (str(docker), "image", "inspect", str(container["image_reference"])),
            environment=environment,
            input_bytes=None,
            working_directory=working_directory,
            timeout_seconds=20,
            output_stem="image-inspect",
        )
    except _BoundedCommandTimeout as exc:
        raise PinnedKernelExecutionError("Docker image inspection timed out") from exc
    if returncode != 0 or stderr or not stdout:
        raise PinnedKernelExecutionError(
            "pinned container image is not available locally; runtime never pulls"
        )
    try:
        inspected = _strict_json_loads(stdout)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PinnedKernelExecutionError("Docker image identity is invalid") from exc
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(
        inspected[0], dict
    ):
        raise PinnedKernelExecutionError("Docker image identity is not singular")
    image = inspected[0]
    repo_digests = image.get("RepoDigests")
    config = image.get("Config")
    if not isinstance(repo_digests, list) or not isinstance(config, dict):
        raise PinnedKernelExecutionError("Docker image identity is incomplete")
    expected_repo = _normalized_repository(str(container["image_repository"]))
    expected_manifest = str(container["image_manifest_digest"])
    matching_digest = False
    for item in repo_digests:
        if not isinstance(item, str) or "@" not in item:
            continue
        repository, digest = item.rsplit("@", 1)
        if _normalized_repository(repository) == expected_repo and digest == expected_manifest:
            matching_digest = True
    expected_python = f"PYTHON_VERSION={container['python_patch']}"
    environment_items = config.get("Env")
    if (
        image.get("Id") != container["image_config_digest"]
        or image.get("Os") != container["os"]
        or image.get("Architecture") != container["architecture"]
        or not matching_digest
        or not isinstance(environment_items, list)
        or expected_python not in environment_items
    ):
        raise PinnedKernelExecutionError("Docker image does not match pinned identity")
    identity = {
        "architecture": image["Architecture"],
        "config_digest": image["Id"],
        "manifest_digest": expected_manifest,
        "os": image["Os"],
        "platform": container["platform"],
        "python_patch": container["python_patch"],
        "repository": container["image_repository"],
    }
    return _sha256(_canonical_bytes(identity)), _sha256(stdout)


def _container_security_profile(
    *, container: Mapping[str, Any], uid: int, gid: int
) -> dict[str, Any]:
    return {
        "cap_drop": list(container["cap_drop"]),
        "cpu_limit": container["cpu_limit"],
        "memory_limit_bytes": container["memory_limit_bytes"],
        "memory_swap_limit_bytes": container["memory_swap_limit_bytes"],
        "network_mode": container["network_mode"],
        "pids_limit": container["pids_limit"],
        "pull_policy": container["pull_policy"],
        "read_only_rootfs": container["read_only_rootfs"],
        "security_opt": list(container["security_opt"]),
        "tmpfs": list(container["tmpfs"]),
        "ulimits": list(container["ulimits"]),
        "user": f"{uid}:{gid}",
        "boundary": "trusted_host_docker_launcher",
        "read_only_mounts": [
            {"role": "wheelhouse", "target": str(_CONTAINER_WHEELHOUSE)},
            {"role": "request", "target": str(_CONTAINER_REQUEST)},
            {"role": "runner", "target": str(_CONTAINER_RUNNER)},
            {"role": "manifest", "target": str(_CONTAINER_MANIFEST)},
        ],
        "writable_mounts": [],
    }


def _trusted_workflow_security_profile(
    *,
    container: Mapping[str, Any],
    workflow: Mapping[str, Any],
    uid: int,
    gid: int,
) -> dict[str, Any]:
    profile = _container_security_profile(container=container, uid=uid, gid=gid)
    return {
        **profile,
        "boundary": "trusted_workflow_authorized_container",
        "read_only_mounts": list(workflow["read_only_mounts"]),
        "writable_mounts": list(workflow["writable_mounts"]),
    }


def _validate_container_policy(container: Mapping[str, Any]) -> None:
    required = {
        "engine",
        "engine_path",
        "image_repository",
        "image_tag",
        "image_manifest_digest",
        "image_config_digest",
        "image_reference",
        "platform",
        "os",
        "architecture",
        "python_minor",
        "python_patch",
        "python_executable",
        "pull_policy",
        "network_mode",
        "read_only_rootfs",
        "cap_drop",
        "security_opt",
        "user_policy",
        "pids_limit",
        "memory_limit_bytes",
        "memory_swap_limit_bytes",
        "cpu_limit",
        "tmpfs",
        "ulimits",
        "read_only_mounts",
    }
    if set(container) != required:
        raise PinnedKernelExecutionError("container authority fields are not closed")
    expected_static = {
        "engine": "docker",
        "engine_path": str(_DOCKER_EXECUTABLE),
        "platform": "linux/amd64",
        "os": "linux",
        "architecture": "amd64",
        "python_minor": "3.11",
        "python_patch": "3.11.15",
        "python_executable": "/usr/local/bin/python3",
        "pull_policy": "never",
        "network_mode": "none",
        "read_only_rootfs": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "user_policy": "host_uid_gid",
        "pids_limit": 64,
        "memory_limit_bytes": 1610612736,
        "memory_swap_limit_bytes": 1610612736,
        "cpu_limit": "1.0",
        "tmpfs": ["/tmp:rw,exec,nosuid,nodev,size=268435456,mode=1777"],
        "ulimits": ["core=0:0", "fsize=67108864:67108864", "nofile=64:64"],
        "read_only_mounts": ["manifest", "request", "runner", "wheelhouse"],
    }
    if any(container.get(key) != value for key, value in expected_static.items()):
        raise PinnedKernelExecutionError("container authority security policy mismatch")
    manifest_digest = str(container.get("image_manifest_digest", ""))
    config_digest = str(container.get("image_config_digest", ""))
    if (
        len(manifest_digest) != 71
        or not manifest_digest.startswith("sha256:")
        or len(config_digest) != 71
        or not config_digest.startswith("sha256:")
        or container.get("image_reference")
        != f"{container.get('image_repository')}@{manifest_digest}"
    ):
        raise PinnedKernelExecutionError("container authority image identity is invalid")
    try:
        int(manifest_digest.removeprefix("sha256:"), 16)
        int(config_digest.removeprefix("sha256:"), 16)
    except ValueError as exc:
        raise PinnedKernelExecutionError("container authority digest is invalid") from exc


def _validate_current_container_python(container: Mapping[str, Any]) -> None:
    expected_patch = tuple(int(item) for item in str(container["python_patch"]).split("."))
    if (
        sys.implementation.name != "cpython"
        or sys.version_info[:3] != expected_patch
        or platform.system() != "Linux"
        or platform.machine() not in {"x86_64", "AMD64"}
    ):
        raise PinnedKernelExecutionError("container Python identity mismatch")


def _validate_trusted_workflow_policy(workflow: Mapping[str, Any]) -> None:
    expected = {
        "attestation_path": "/run/owner-research/trusted-container-attestation.json",
        "attestation_mount_target": "/run/owner-research",
        "attestation_sha256_env": (
            "OWNER_RESEARCH_TRUSTED_CONTAINER_ATTESTATION_SHA256"
        ),
        "read_only_mounts": [
            {"role": "candidate_workspace", "target": "/workspace"},
            {"role": "private_kernel_checkout", "target": "/private-kernel"},
            {"role": "binary_supply_wheelhouse", "target": "/supply"},
            {"role": "binary_supply_lock", "target": "/supply.lock"},
            {"role": "verified_research_wheel", "target": "/research-wheel"},
            {"role": "runtime_cas", "target": "/runtime-cas"},
            {
                "role": "trusted_attestation_directory",
                "target": "/run/owner-research",
            },
        ],
        "writable_mounts": [
            {"role": "canonical_summary_output", "target": "/output"}
        ],
    }
    if dict(workflow) != expected:
        raise PinnedKernelExecutionError("trusted workflow authority drifted")


def _read_root_owned_readonly_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PinnedKernelExecutionError(
            "trusted workflow attestation is unavailable"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or stat.S_IMODE(before.st_mode) != 0o444
            or before.st_nlink != 1
            or before.st_size > 1024 * 1024
        ):
            raise PinnedKernelExecutionError(
                "trusted workflow attestation ownership or mode is invalid"
            )
        chunks: list[bytes] = []
        remaining = 1024 * 1024 + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0:
            raise PinnedKernelExecutionError("trusted workflow attestation is too large")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_nlink,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_nlink,
        ):
            raise PinnedKernelExecutionError(
                "trusted workflow attestation changed while being read"
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _require_read_only_attestation_mount(*, path: Path, mount_target: Path) -> None:
    raw = _read_regular_file_nofollow(
        Path("/proc/self/mountinfo"), maximum_size=4 * 1024 * 1024
    )
    matches: list[tuple[str, set[str]]] = []
    for line in raw.decode("utf-8").splitlines():
        fields = line.split()
        if len(fields) < 7:
            continue
        mounted = fields[4].replace("\\040", " ").replace("\\011", "\t")
        try:
            relative = path.relative_to(mounted)
        except ValueError:
            continue
        if not relative.parts or mounted == str(mount_target):
            matches.append((mounted, set(fields[5].split(","))))
    if not matches:
        raise PinnedKernelExecutionError("trusted workflow attestation mount is absent")
    mounted, options = max(matches, key=lambda item: len(item[0]))
    if mounted != str(mount_target) or "ro" not in options:
        raise PinnedKernelExecutionError(
            "trusted workflow attestation mount is not independently read-only"
        )


def _require_trusted_workflow_runtime(workflow: Mapping[str, Any]) -> None:
    raw = _read_regular_file_nofollow(
        Path("/proc/self/mountinfo"), maximum_size=4 * 1024 * 1024
    )
    observed: dict[str, set[str]] = {}
    for line in raw.decode("utf-8").splitlines():
        fields = line.split()
        if len(fields) >= 7:
            target = fields[4].replace("\\040", " ").replace("\\011", "\t")
            observed[target] = set(fields[5].split(","))
    for item in workflow["read_only_mounts"]:
        if "ro" not in observed.get(str(item["target"]), set()):
            raise PinnedKernelExecutionError(
                f"trusted workflow read-only mount is absent: {item['role']}"
            )
    for item in workflow["writable_mounts"]:
        options = observed.get(str(item["target"]), set())
        if "rw" not in options or "ro" in options:
            raise PinnedKernelExecutionError(
                f"trusted workflow writable mount is absent: {item['role']}"
            )
    if _DOCKER_EXECUTABLE.exists() or Path("/var/run/docker.sock").exists():
        raise PinnedKernelExecutionError(
            "trusted workflow container exposes a Docker capability"
        )
    if any(name.startswith("DOCKER_") for name in os.environ):
        raise PinnedKernelExecutionError(
            "trusted workflow container exposes a Docker environment"
        )


def _load_trusted_container_attestation(
    *,
    container: Mapping[str, Any],
    workflow: Mapping[str, Any],
    uid: int,
    gid: int,
) -> tuple[str, str]:
    _validate_trusted_workflow_policy(workflow)
    supplied_path = str(workflow["attestation_path"])
    sha_env = str(workflow["attestation_sha256_env"])
    supplied_sha256 = os.environ.get(sha_env)
    if not supplied_sha256:
        raise PinnedKernelExecutionError("trusted workflow attestation is unavailable")
    attestation_path = Path(supplied_path)
    _require_read_only_attestation_mount(
        path=attestation_path,
        mount_target=Path(str(workflow["attestation_mount_target"])),
    )
    raw = _read_root_owned_readonly_file(attestation_path)
    if _sha256(raw) != supplied_sha256:
        raise PinnedKernelExecutionError("trusted workflow attestation hash mismatch")
    try:
        attestation = _strict_json_loads(raw)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PinnedKernelExecutionError("trusted workflow attestation is invalid JSON") from exc
    if not isinstance(attestation, dict) or _canonical_bytes(attestation) != raw:
        raise PinnedKernelExecutionError("trusted workflow attestation is not canonical")
    required = {
        "schema_version",
        "authority_kind",
        "image_reference",
        "image_manifest_digest",
        "image_config_digest",
        "platform",
        "python_patch",
        "security_profile",
        "security_profile_sha256",
    }
    if set(attestation) != required:
        raise PinnedKernelExecutionError("trusted workflow attestation fields are not closed")
    profile = _trusted_workflow_security_profile(
        container=container,
        workflow=workflow,
        uid=uid,
        gid=gid,
    )
    profile_sha256 = _sha256(_canonical_bytes(profile))
    expected = {
        "schema_version": "1.0.0",
        "authority_kind": "trusted_workflow_container",
        "image_reference": container["image_reference"],
        "image_manifest_digest": container["image_manifest_digest"],
        "image_config_digest": container["image_config_digest"],
        "platform": container["platform"],
        "python_patch": container["python_patch"],
        "security_profile": profile,
        "security_profile_sha256": profile_sha256,
    }
    if attestation != expected:
        raise PinnedKernelExecutionError("trusted workflow attestation does not match authority")
    return supplied_sha256, profile_sha256


def _child_environment() -> dict[str, str]:
    return {
        "HOME": "/tmp/home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }


def _container_command(
    *,
    docker: Path,
    container: Mapping[str, Any],
    uid: int,
    gid: int,
    wheelhouse: Path,
    request_path: Path,
    runner_path: Path,
    manifest_path: Path,
    cidfile: Path,
    container_name: str,
) -> tuple[str, ...]:
    _validate_container_policy(container)

    def mount_source(path: Path) -> str:
        value = str(path)
        if not path.is_absolute() or any(character in value for character in ",\r\n\0"):
            raise PinnedKernelExecutionError("Docker mount source path is unsafe")
        return value

    command = [
        str(docker),
        "run",
        "--rm",
        "--interactive",
        f"--name={container_name}",
        f"--cidfile={mount_source(cidfile)}",
        "--pull=never",
        f"--platform={container['platform']}",
        f"--network={container['network_mode']}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        f"--user={uid}:{gid}",
        f"--pids-limit={container['pids_limit']}",
        f"--memory={container['memory_limit_bytes']}",
        f"--memory-swap={container['memory_swap_limit_bytes']}",
        f"--cpus={container['cpu_limit']}",
    ]
    command.extend(f"--ulimit={item}" for item in container["ulimits"])
    command.extend(f"--tmpfs={item}" for item in container["tmpfs"])
    command.extend(
        (
            "--env=HOME=/tmp/home",
            "--env=LANG=C.UTF-8",
            "--env=LC_ALL=C.UTF-8",
            "--env=PYTHONHASHSEED=0",
            "--env=PYTHONDONTWRITEBYTECODE=1",
            "--env=PYTHONNOUSERSITE=1",
            "--env=TMPDIR=/tmp",
            "--env=TZ=UTC",
            "--workdir=/runtime",
            "--mount=type=bind,src="
            f"{mount_source(wheelhouse)},dst={_CONTAINER_WHEELHOUSE},readonly",
            "--mount=type=bind,src="
            f"{mount_source(request_path)},dst={_CONTAINER_REQUEST},readonly",
            "--mount=type=bind,src="
            f"{mount_source(runner_path)},dst={_CONTAINER_RUNNER},readonly",
            "--mount=type=bind,src="
            f"{mount_source(manifest_path)},dst={_CONTAINER_MANIFEST},readonly",
            f"--entrypoint={container['python_executable']}",
            str(container["image_reference"]),
            "-I",
            "-S",
            "-B",
            str(_CONTAINER_RUNNER),
            "--container-runner",
            str(_CONTAINER_WHEELHOUSE),
            str(_CONTAINER_MANIFEST),
            str(_CONTAINER_REQUEST),
        )
    )
    return tuple(command)


def _container_cleanup_identifier(cidfile: Path, container_name: str) -> str:
    try:
        raw = _read_regular_file_nofollow(cidfile, maximum_size=128).strip()
    except PinnedKernelExecutionError:
        return container_name
    try:
        value = raw.decode("ascii")
    except UnicodeError:
        return container_name
    if len(value) == 64 and all(character in "0123456789abcdef" for character in value):
        return value
    return container_name


def _force_remove_and_verify_container_absent(
    *,
    docker: Path,
    cidfile: Path,
    container_name: str,
    environment: Mapping[str, str],
    working_directory: Path,
) -> None:
    identifier = _container_cleanup_identifier(cidfile, container_name)
    absence_messages = {
        f"Error: No such object: {identifier}\n".encode("ascii"),
        f"Error response from daemon: No such container: {identifier}\n".encode(
            "ascii"
        ),
    }
    labels = ("first", "second", "third", "fourth", "fifth")
    consecutive_absence = 0
    for label in labels:
        try:
            _run_bounded_command(
                (str(docker), "container", "rm", "--force", identifier),
                environment=environment,
                input_bytes=None,
                working_directory=working_directory,
                timeout_seconds=20,
                output_stem=f"container-remove-{label}",
            )
            returncode, stdout, stderr = _run_bounded_command(
                (str(docker), "container", "inspect", identifier),
                environment=environment,
                input_bytes=None,
                working_directory=working_directory,
                timeout_seconds=20,
                output_stem=f"container-absent-{label}",
            )
        except _BoundedCommandTimeout as exc:
            raise PinnedKernelExecutionError("Docker container cleanup timed out") from exc
        if returncode == 1 and not stdout and stderr in absence_messages:
            consecutive_absence += 1
            if consecutive_absence == 3:
                return
        elif returncode == 0 and not stderr:
            consecutive_absence = 0
        else:
            raise PinnedKernelExecutionError("Docker container survived cleanup")
        time.sleep(0.1)
    raise PinnedKernelExecutionError("Docker container survived cleanup")


def _stage_container_runtime(
    *,
    root: Path,
    manifest: Mapping[str, Any],
    manifest_bytes: bytes,
    request_bytes: bytes,
    cas_root: Path,
) -> tuple[Path, Path, Path, Path, dict[str, Any]]:
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(mode=0o700)
    for item in manifest["wheels"]:
        raw = _read_regular_file_nofollow(cas_root / "sha256" / item["sha256"])
        if _sha256(raw) != item["sha256"]:
            raise PinnedKernelExecutionError("runtime wheel changed during staging")
        _write_private_file(wheelhouse / item["filename"], raw)
    schema_entry = manifest["result_schema"]
    schema_bytes = _read_regular_file_nofollow(
        cas_root / "sha256" / schema_entry["sha256"], maximum_size=8 * 1024 * 1024
    )
    if _sha256(schema_bytes) != schema_entry["sha256"]:
        raise PinnedKernelExecutionError("runtime result Schema changed during staging")
    _write_private_file(wheelhouse / schema_entry["filename"], schema_bytes)
    os.chmod(wheelhouse, 0o500)

    runner_bytes = _read_regular_file_nofollow(
        Path(__file__).absolute(), maximum_size=4 * 1024 * 1024
    )
    runner_sha256 = _sha256(runner_bytes)
    if runner_sha256 != manifest["producer"]["runner_sha256"]:
        raise PinnedKernelExecutionError("runner source changed after manifest verification")
    runner_path = root / "pinned-runner.py"
    request_path = root / "request.json"
    manifest_path = root / "runtime-manifest.json"
    _write_private_file(runner_path, runner_bytes)
    _write_private_file(request_path, request_bytes)
    _write_private_file(manifest_path, manifest_bytes)
    schema = _load_result_schema(manifest, wheelhouse)
    return wheelhouse, request_path, runner_path, manifest_path, schema


def _build_execution_result(
    *,
    execution_boundary: str,
    request_bytes: bytes,
    result_bytes: bytes,
    manifest: Mapping[str, Any],
    fingerprints: tuple[str, str, str],
    container_security_profile_sha256: str,
    docker_executable_sha256: str | None,
    container_identity_sha256: str | None,
    docker_image_inspect_sha256: str | None,
    trusted_workflow_attestation_sha256: str | None,
) -> PinnedKernelExecutionResult:
    container = manifest["container"]
    _validate_container_policy(container)
    fact_fingerprint, assumption_fingerprint, model_fingerprint = fingerprints
    return PinnedKernelExecutionResult(
        execution_boundary=execution_boundary,
        request_sha256=_sha256(request_bytes),
        result_sha256=_sha256(result_bytes),
        result_bytes=result_bytes,
        kernel_wheel_sha256=manifest["kernel"]["wheel_sha256"],
        runtime_authority_sha256=manifest["authority"]["sha256"],
        runtime_manifest_file_sha256=_sha256(_canonical_bytes(manifest)),
        runtime_manifest_fingerprint=manifest["manifest_fingerprint"],
        runner_sha256=manifest["producer"]["runner_sha256"],
        result_schema_sha256=manifest["result_schema"]["sha256"],
        wheel_inventory_sha256=_wheel_inventory_sha256(manifest),
        docker_executable_sha256=docker_executable_sha256,
        container_image_reference=container["image_reference"],
        container_image_manifest_digest=container["image_manifest_digest"],
        container_image_config_digest=container["image_config_digest"],
        container_platform=container["platform"],
        container_identity_sha256=container_identity_sha256,
        docker_image_inspect_sha256=docker_image_inspect_sha256,
        container_security_profile_sha256=container_security_profile_sha256,
        trusted_workflow_attestation_sha256=trusted_workflow_attestation_sha256,
        fact_ledger_fingerprint=fact_fingerprint,
        assumption_ledger_fingerprint=assumption_fingerprint,
        model_input_fingerprint=model_fingerprint,
        kernel_call_count=1,
    )


def execute_pinned_kernel(
    request_bytes: bytes,
    *,
    runtime_manifest: Path,
    runtime_manifest_file_sha256: str,
    cas_root: Path,
    timeout_seconds: int = 90,
) -> PinnedKernelExecutionResult:
    """Run the fixed kernel once in a digest-pinned, netless, read-only container."""

    request = _validate_canonical_request(request_bytes)
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise PinnedKernelExecutionError("production kernel execution requires Linux x86_64")
    if not 1 <= timeout_seconds <= 300:
        raise PinnedKernelExecutionError("kernel timeout is outside the registered range")
    manifest = verify_runtime_wheelhouse(
        runtime_manifest=runtime_manifest,
        runtime_manifest_file_sha256=runtime_manifest_file_sha256,
        cas_root=cas_root,
    )
    container = manifest["container"]
    _validate_container_policy(container)
    if manifest["target"]["python_minor"] != container["python_minor"]:
        raise PinnedKernelExecutionError("runtime manifest has no matching pinned container")
    docker, docker_sha256 = _validated_docker_executable()
    uid, gid = _host_uid_gid()
    manifest_bytes = _read_regular_file_nofollow(
        runtime_manifest, maximum_size=8 * 1024 * 1024
    )
    if _sha256(manifest_bytes) != runtime_manifest_file_sha256:
        raise PinnedKernelExecutionError("runtime manifest changed after verification")
    cas = cas_root.resolve(strict=True)

    with tempfile.TemporaryDirectory(
        prefix="owner-kernel-container-", dir="/tmp"
    ) as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        docker_config = root / "docker-config"
        docker_config.mkdir(mode=0o700)
        environment = _docker_environment(docker_config)
        identity_sha256, inspect_sha256 = _verify_local_container_image(
            docker=docker,
            container=container,
            environment=environment,
            working_directory=root,
        )
        wheelhouse, request_path, runner_path, manifest_path, schema = (
            _stage_container_runtime(
                root=root,
                manifest=manifest,
                manifest_bytes=manifest_bytes,
                request_bytes=request_bytes,
                cas_root=cas,
            )
        )
        container_name = f"owner-research-kernel-{_sha256(os.urandom(32))[:24]}"
        cidfile = root / "kernel.cid"
        profile = _container_security_profile(container=container, uid=uid, gid=gid)
        command = _container_command(
            docker=docker,
            container=container,
            uid=uid,
            gid=gid,
            wheelhouse=wheelhouse,
            request_path=request_path,
            runner_path=runner_path,
            manifest_path=manifest_path,
            cidfile=cidfile,
            container_name=container_name,
        )
        try:
            returncode, stdout, stderr = _run_bounded_command(
                command,
                environment=environment,
                input_bytes=request_bytes,
                working_directory=root,
                timeout_seconds=timeout_seconds,
                output_stem="kernel-run",
            )
        except _BoundedCommandTimeout as exc:
            _force_remove_and_verify_container_absent(
                docker=docker,
                cidfile=cidfile,
                container_name=container_name,
                environment=environment,
                working_directory=root,
            )
            raise PinnedKernelExecutionError("isolated kernel process timed out") from exc
        except PinnedKernelExecutionError:
            _force_remove_and_verify_container_absent(
                docker=docker,
                cidfile=cidfile,
                container_name=container_name,
                environment=environment,
                working_directory=root,
            )
            raise
        _force_remove_and_verify_container_absent(
            docker=docker,
            cidfile=cidfile,
            container_name=container_name,
            environment=environment,
            working_directory=root,
        )
        if returncode != 0 or stderr or not stdout:
            raise PinnedKernelExecutionError("isolated kernel process rejected the request")
        _, fingerprints = _validate_result_bytes(
            result_bytes=stdout,
            request_bytes=request_bytes,
            request=request,
            schema=schema,
        )
        if _sha256(_read_regular_file_nofollow(docker)) != docker_sha256:
            raise PinnedKernelExecutionError("fixed Docker executable changed during execution")
        return _build_execution_result(
            execution_boundary="trusted_host_docker_launcher",
            request_bytes=request_bytes,
            result_bytes=stdout,
            manifest=manifest,
            fingerprints=fingerprints,
            container_security_profile_sha256=_sha256(_canonical_bytes(profile)),
            docker_executable_sha256=docker_sha256,
            container_identity_sha256=identity_sha256,
            docker_image_inspect_sha256=inspect_sha256,
            trusted_workflow_attestation_sha256=None,
        )


def execute_in_authorized_container(
    request_bytes: bytes,
    *,
    runtime_manifest: Path,
    runtime_manifest_file_sha256: str,
    cas_root: Path,
    timeout_seconds: int = 90,
) -> PinnedKernelExecutionResult:
    """Run one child kernel call inside an already-authorized pinned container.

    This is an internal CI/orchestration boundary.  The trusted workflow, not
    this process, proves the outer image digest and Docker hardening.  The
    function verifies a canonical, read-only workflow attestation and records
    its hash without claiming an independently observed host image identity.
    """

    request = _validate_canonical_request(request_bytes)
    if not 1 <= timeout_seconds <= 300:
        raise PinnedKernelExecutionError("kernel timeout is outside the registered range")
    manifest = verify_runtime_wheelhouse(
        runtime_manifest=runtime_manifest,
        runtime_manifest_file_sha256=runtime_manifest_file_sha256,
        cas_root=cas_root,
    )
    container = manifest["container"]
    _validate_container_policy(container)
    workflow = manifest["trusted_workflow"]
    _validate_trusted_workflow_policy(workflow)
    if manifest["target"]["python_minor"] != container["python_minor"]:
        raise PinnedKernelExecutionError("runtime manifest has no matching pinned container")
    _validate_current_container_python(container)
    uid, gid = _host_uid_gid()
    _require_trusted_workflow_runtime(workflow)
    attestation_sha256, profile_sha256 = _load_trusted_container_attestation(
        container=container,
        workflow=workflow,
        uid=uid,
        gid=gid,
    )
    manifest_bytes = _read_regular_file_nofollow(
        runtime_manifest, maximum_size=8 * 1024 * 1024
    )
    if _sha256(manifest_bytes) != runtime_manifest_file_sha256:
        raise PinnedKernelExecutionError("runtime manifest changed after verification")
    cas = cas_root.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="owner-kernel-inner-", dir="/tmp") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        wheelhouse, request_path, runner_path, manifest_path, schema = (
            _stage_container_runtime(
                root=root,
                manifest=manifest,
                manifest_bytes=manifest_bytes,
                request_bytes=request_bytes,
                cas_root=cas,
            )
        )
        command = (
            str(container["python_executable"]),
            "-I",
            "-S",
            "-B",
            str(runner_path),
            "--container-runner",
            str(wheelhouse),
            str(manifest_path),
            str(request_path),
        )
        try:
            returncode, stdout, stderr = _run_bounded_command(
                command,
                environment=_child_environment(),
                input_bytes=request_bytes,
                working_directory=root,
                timeout_seconds=timeout_seconds,
                output_stem="inner-kernel-run",
            )
        except _BoundedCommandTimeout as exc:
            raise PinnedKernelExecutionError("isolated kernel process timed out") from exc
        if returncode != 0 or stderr or not stdout:
            raise PinnedKernelExecutionError("isolated kernel process rejected the request")
        _, fingerprints = _validate_result_bytes(
            result_bytes=stdout,
            request_bytes=request_bytes,
            request=request,
            schema=schema,
        )
        return _build_execution_result(
            execution_boundary="trusted_workflow_authorized_container",
            request_bytes=request_bytes,
            result_bytes=stdout,
            manifest=manifest,
            fingerprints=fingerprints,
            container_security_profile_sha256=profile_sha256,
            docker_executable_sha256=None,
            container_identity_sha256=None,
            docker_image_inspect_sha256=None,
            trusted_workflow_attestation_sha256=attestation_sha256,
        )


def _validate_container_manifest(manifest: Mapping[str, Any], manifest_bytes: bytes) -> None:
    required = {
        "schema_version",
        "manifest_policy_id",
        "manifest_policy_version",
        "authority",
        "producer",
        "kernel",
        "target",
        "container",
        "trusted_workflow",
        "result_schema",
        "transport",
        "wheels",
        "manifest_fingerprint",
    }
    if set(manifest) != required or _canonical_bytes(manifest) != manifest_bytes:
        raise PinnedKernelExecutionError("container runtime manifest is not closed canonical JSON")
    fingerprint_payload = dict(manifest)
    supplied = fingerprint_payload.pop("manifest_fingerprint")
    if _sha256(_canonical_bytes(fingerprint_payload)) != supplied:
        raise PinnedKernelExecutionError("container runtime manifest fingerprint mismatch")
    container = manifest["container"]
    _validate_container_policy(container)
    _validate_trusted_workflow_policy(manifest["trusted_workflow"])
    if (
        manifest["target"]
        != {
            "implementation": "cpython",
            "platform": "linux_x86_64",
            "python_minor": "3.11",
        }
        or container.get("python_patch") != "3.11.15"
        or container.get("platform") != "linux/amd64"
        or container.get("network_mode") != "none"
        or container.get("read_only_rootfs") is not True
        or container.get("pull_policy") != "never"
    ):
        raise PinnedKernelExecutionError("container runtime identity or policy mismatch")
    runner_bytes = _read_regular_file_nofollow(
        Path(__file__).absolute(), maximum_size=4 * 1024 * 1024
    )
    if _sha256(runner_bytes) != manifest["producer"].get("runner_sha256"):
        raise PinnedKernelExecutionError("container runner source binding mismatch")


def _container_runner_main(
    wheelhouse: Path, manifest_path: Path, request_path: Path
) -> int:
    try:
        manifest_bytes = _read_regular_file_nofollow(
            manifest_path, maximum_size=8 * 1024 * 1024
        )
        manifest = _strict_json_loads(manifest_bytes)
        if not isinstance(manifest, dict):
            raise PinnedKernelExecutionError("container runtime manifest is invalid")
        _validate_container_manifest(manifest, manifest_bytes)
        _validate_current_container_python(manifest["container"])
        mounted_request = _read_regular_file_nofollow(
            request_path, maximum_size=_MAX_REQUEST_BYTES
        )
        stdin_request = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
        if mounted_request != stdin_request:
            raise PinnedKernelExecutionError("mounted and stdin request bytes differ")
        request = _validate_canonical_request(stdin_request)
        with tempfile.TemporaryDirectory(prefix="kernel-site-", dir="/tmp") as temporary:
            site_packages = Path(temporary)
            _extract_container_wheels(
                manifest=manifest,
                wheelhouse=wheelhouse,
                destination=site_packages,
            )
            sys.path.insert(0, str(site_packages))
            import owner_valuation
            from owner_valuation.contracts import validate_result

            if owner_valuation.__version__ != manifest["kernel"]["package_version"]:
                raise PinnedKernelExecutionError("kernel version mismatch")
            call_count = 0
            call_count += 1
            result = owner_valuation.run_dual_panel(request)
            if call_count != manifest["transport"]["kernel_call_count"]:
                raise PinnedKernelExecutionError("kernel invocation count mismatch")
            validate_result(result)
            schema = _load_result_schema(manifest, wheelhouse)
            _validate_result_schema(result, schema)
            result_bytes = _canonical_bytes(result)
            if len(result_bytes) > _MAX_RESULT_BYTES:
                raise PinnedKernelExecutionError("kernel result exceeds the byte limit")
            sys.stdout.buffer.write(result_bytes)
            sys.stdout.buffer.flush()
        return 0
    except BaseException:
        try:
            sys.stderr.buffer.write(_FIXED_ERROR)
            sys.stderr.buffer.flush()
        except BaseException:
            pass
        return 70


def _main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[0] == "--container-runner":
        return _container_runner_main(Path(argv[1]), Path(argv[2]), Path(argv[3]))
    return 64


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))


__all__: tuple[str, ...] = ()
