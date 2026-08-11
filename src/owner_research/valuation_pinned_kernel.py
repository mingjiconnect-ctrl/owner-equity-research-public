"""Fail-closed execution of the pinned valuation kernel runtime.

The host verifies a content-addressed wheelhouse, extracts it without pip, and
invokes this same raw-byte-bound file once inside a fresh Linux network
namespace.  Canonical request bytes enter through stdin; canonical result bytes
leave through stdout without host-side rewriting.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import resource
import socket
import stat
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Mapping
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
_FIXED_ERROR = b"pinned-kernel-runner-error\n"


class PinnedKernelExecutionError(RuntimeError):
    """The pinned runtime or isolated kernel execution failed closed."""


@dataclass(frozen=True, slots=True)
class PinnedKernelExecutionResult:
    request_sha256: str
    result_sha256: str
    result_bytes: bytes
    kernel_wheel_sha256: str
    runtime_manifest_file_sha256: str
    runtime_manifest_fingerprint: str
    runner_sha256: str
    python_executable_sha256: str
    network_namespace: str
    unshare_sha256: str
    fact_ledger_fingerprint: str
    assumption_ledger_fingerprint: str
    model_input_fingerprint: str
    kernel_call_count: int


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, **_CANONICAL_JSON_KWARGS).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_regular_file_nofollow(path: Path, *, maximum_size: int = 256 * 1024 * 1024) -> bytes:
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


def verify_runtime_wheelhouse(
    *,
    runtime_manifest: Path,
    runtime_manifest_file_sha256: str,
    cas_root: Path,
) -> dict[str, Any]:
    """Bind current code, authority, manifest bytes, and every CAS wheel."""

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


def _extract_runtime_wheels(
    *, manifest: Mapping[str, Any], cas_root: Path, destination: Path
) -> None:
    observed: set[str] = set()
    total_uncompressed = 0
    for item in manifest["wheels"]:
        wheel_path = cas_root / "sha256" / item["sha256"]
        raw = _read_regular_file_nofollow(wheel_path)
        if _sha256(raw) != item["sha256"]:
            raise PinnedKernelExecutionError("runtime wheel changed after manifest verification")
        archive: zipfile.ZipFile | None = None
        try:
            archive = zipfile.ZipFile(io.BytesIO(raw))
            if archive.testzip() is not None:
                raise PinnedKernelExecutionError("runtime wheel CRC verification failed")
            for info in archive.infolist():
                _safe_runtime_member(info.filename)
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise PinnedKernelExecutionError("runtime wheel contains a symbolic link")
                if info.is_dir():
                    continue
                if info.filename in observed:
                    raise PinnedKernelExecutionError("runtime wheels contain a path collision")
                total_uncompressed += info.file_size
                if info.file_size > 64 * 1024 * 1024 or total_uncompressed > 256 * 1024 * 1024:
                    raise PinnedKernelExecutionError("runtime wheel extraction exceeds limits")
                target = destination.joinpath(*PurePosixPath(info.filename).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(info.filename))
                os.chmod(target, 0o600)
                observed.add(info.filename)
        except zipfile.BadZipFile as exc:
            raise PinnedKernelExecutionError("runtime wheel is not a valid ZIP") from exc
        finally:
            if archive is not None:
                archive.close()


def _validate_canonical_request(request_bytes: bytes) -> dict[str, Any]:
    if not request_bytes or len(request_bytes) > _MAX_REQUEST_BYTES:
        raise PinnedKernelExecutionError("canonical request byte length is invalid")
    try:
        payload = json.loads(request_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PinnedKernelExecutionError("valuation request is invalid JSON") from exc
    if not isinstance(payload, dict) or _canonical_bytes(payload) != request_bytes:
        raise PinnedKernelExecutionError("valuation request is not a canonical JSON object")
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


def _validated_executable(path: Path, label: str) -> tuple[Path, str]:
    absolute = path if path.is_absolute() else Path.cwd() / path
    try:
        details = absolute.lstat()
    except OSError as exc:
        raise PinnedKernelExecutionError(f"{label} is unavailable") from exc
    if not stat.S_ISREG(details.st_mode) or not os.access(absolute, os.X_OK):
        raise PinnedKernelExecutionError(f"{label} must be a non-symlink executable file")
    return absolute, _sha256(_read_regular_file_nofollow(absolute))


def _runtime_python_identity(executable: Path) -> dict[str, str]:
    script = (
        "import json,platform,sys;"
        "print(json.dumps({'implementation':sys.implementation.name,"
        "'minor':f'{sys.version_info.major}.{sys.version_info.minor}',"
        "'machine':platform.machine(),'system':platform.system()},"
        "sort_keys=True,separators=(',',':')))"
    )
    try:
        completed = subprocess.run(
            (str(executable), "-I", "-c", script),
            check=True,
            capture_output=True,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"},
            timeout=10,
        )
        identity = json.loads(completed.stdout)
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as exc:
        raise PinnedKernelExecutionError("runtime Python identity could not be verified") from exc
    if not isinstance(identity, dict):
        raise PinnedKernelExecutionError("runtime Python identity is invalid")
    return identity


def _set_child_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024, 32 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
    resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024 * 1024, 1536 * 1024 * 1024))


def execute_pinned_kernel(
    request_bytes: bytes,
    *,
    runtime_manifest: Path,
    runtime_manifest_file_sha256: str,
    cas_root: Path,
    python_executable: Path,
    timeout_seconds: int = 90,
) -> PinnedKernelExecutionResult:
    """Execute ``run_dual_panel`` once in a netless Linux namespace."""

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
    python_path, python_sha256 = _validated_executable(python_executable, "runtime Python")
    identity = _runtime_python_identity(python_path)
    if identity != {
        "implementation": "cpython",
        "machine": "x86_64",
        "minor": manifest["target"]["python_minor"],
        "system": "Linux",
    }:
        raise PinnedKernelExecutionError("runtime Python does not match the manifest target")
    unshare_path, unshare_sha256 = _validated_executable(Path("/usr/bin/unshare"), "unshare")
    try:
        parent_network_namespace = os.readlink("/proc/self/ns/net")
    except OSError as exc:
        raise PinnedKernelExecutionError("parent network namespace cannot be attested") from exc

    with tempfile.TemporaryDirectory(prefix="owner-kernel-run-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        site_packages = root / "site-packages"
        site_packages.mkdir(mode=0o700)
        _extract_runtime_wheels(
            manifest=manifest,
            cas_root=cas_root.resolve(strict=True),
            destination=site_packages,
        )
        runner_bytes = _read_regular_file_nofollow(
            Path(__file__).absolute(), maximum_size=4 * 1024 * 1024
        )
        runner_sha256 = _sha256(runner_bytes)
        if runner_sha256 != manifest["producer"]["runner_sha256"]:
            raise PinnedKernelExecutionError("runner source changed after manifest verification")
        runner_copy = root / "pinned-runner.py"
        runner_copy.write_bytes(runner_bytes)
        os.chmod(runner_copy, 0o500)
        home = root / "home"
        temp_dir = root / "tmp"
        home.mkdir(mode=0o700)
        temp_dir.mkdir(mode=0o700)
        environment = {
            "HOME": str(home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "OWNER_RESEARCH_PARENT_NETNS": parent_network_namespace,
            "PYTHONHASHSEED": "0",
            "TMPDIR": str(temp_dir),
            "TZ": "UTC",
        }
        command = (
            str(unshare_path),
            "--user",
            "--map-root-user",
            "--net",
            "--fork",
            "--kill-child",
            str(python_path),
            "-I",
            "-B",
            str(runner_copy),
            "--isolated-runner",
            str(site_packages),
        )
        try:
            completed = subprocess.run(
                command,
                input=request_bytes,
                capture_output=True,
                env=environment,
                cwd=root,
                timeout=timeout_seconds,
                preexec_fn=_set_child_limits,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PinnedKernelExecutionError("isolated kernel process failed") from exc
        if completed.returncode != 0 or completed.stderr or not completed.stdout:
            raise PinnedKernelExecutionError("isolated kernel process rejected the request")
        if len(completed.stdout) > _MAX_RESULT_BYTES:
            raise PinnedKernelExecutionError("isolated kernel result exceeds the byte limit")
        try:
            result = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PinnedKernelExecutionError("isolated kernel result is invalid JSON") from exc
        if not isinstance(result, dict) or _canonical_bytes(result) != completed.stdout:
            raise PinnedKernelExecutionError("isolated kernel result is not canonical JSON")
        (
            expected_fact_fingerprint,
            expected_assumption_fingerprint,
            expected_model_fingerprint,
        ) = _verify_result_input_bindings(request_bytes, request, result)
        if _sha256(_read_regular_file_nofollow(python_path)) != python_sha256:
            raise PinnedKernelExecutionError("runtime Python changed during execution")
        if _sha256(_read_regular_file_nofollow(unshare_path)) != unshare_sha256:
            raise PinnedKernelExecutionError("unshare changed during execution")
        namespace_receipt = result.get("_owner_research_network_namespace")
        if namespace_receipt is not None:
            raise PinnedKernelExecutionError("kernel result contains a reserved runner field")
        try:
            child_network_namespace = _read_regular_file_nofollow(
                root / "child-netns.txt", maximum_size=256
            ).decode("ascii")
        except (OSError, UnicodeDecodeError) as exc:
            raise PinnedKernelExecutionError("child network namespace receipt is missing") from exc
        if child_network_namespace == parent_network_namespace:
            raise PinnedKernelExecutionError("kernel did not enter a distinct network namespace")
        return PinnedKernelExecutionResult(
            request_sha256=_sha256(request_bytes),
            result_sha256=_sha256(completed.stdout),
            result_bytes=completed.stdout,
            kernel_wheel_sha256=manifest["kernel"]["wheel_sha256"],
            runtime_manifest_file_sha256=runtime_manifest_file_sha256,
            runtime_manifest_fingerprint=manifest["manifest_fingerprint"],
            runner_sha256=runner_sha256,
            python_executable_sha256=python_sha256,
            network_namespace=child_network_namespace,
            unshare_sha256=unshare_sha256,
            fact_ledger_fingerprint=expected_fact_fingerprint,
            assumption_ledger_fingerprint=expected_assumption_fingerprint,
            model_input_fingerprint=expected_model_fingerprint,
            kernel_call_count=1,
        )


def _network_namespace_probe(parent: str) -> str:
    try:
        current = os.readlink("/proc/self/ns/net")
    except OSError as exc:
        raise RuntimeError("network namespace is unavailable") from exc
    if not parent or current == parent:
        raise RuntimeError("network namespace was not isolated")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.1)
        if probe.connect_ex(("1.1.1.1", 53)) == 0:
            raise RuntimeError("network namespace has external connectivity")
    finally:
        probe.close()
    return current


def _deny_runtime_side_effects(event: str, args: tuple[Any, ...]) -> None:
    if event.startswith("socket.") or event in {
        "os.system",
        "os.posix_spawn",
        "subprocess.Popen",
    }:
        raise PermissionError("isolated kernel side effect denied")
    if event in {
        "os.chmod",
        "os.link",
        "os.mkdir",
        "os.remove",
        "os.rename",
        "os.rmdir",
        "os.symlink",
        "os.truncate",
        "os.unlink",
    }:
        raise PermissionError("isolated kernel filesystem mutation denied")
    if event == "open" and len(args) >= 2:
        mode = args[1]
        if isinstance(mode, str) and any(character in mode for character in "wax+"):
            raise PermissionError("isolated kernel filesystem write denied")


def _isolated_runner_main(site_packages: Path) -> int:
    try:
        parent = os.environ.get("OWNER_RESEARCH_PARENT_NETNS", "")
        child_namespace = _network_namespace_probe(parent)
        if not site_packages.is_dir():
            raise RuntimeError("runtime site-packages is unavailable")
        sys.path.insert(0, str(site_packages))
        import owner_valuation
        from owner_valuation.contracts import validate_result

        if owner_valuation.__version__ != "2.0.0rc2":
            raise RuntimeError("kernel version mismatch")
        Path("child-netns.txt").write_text(child_namespace, encoding="ascii")
        sys.addaudithook(_deny_runtime_side_effects)
        request_bytes = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
        request = _validate_canonical_request(request_bytes)
        result = owner_valuation.run_dual_panel(request)
        validate_result(result)
        result_bytes = _canonical_bytes(result)
        if len(result_bytes) > _MAX_RESULT_BYTES:
            raise RuntimeError("kernel result exceeds the byte limit")
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
    if len(argv) == 2 and argv[0] == "--isolated-runner":
        return _isolated_runner_main(Path(argv[1]))
    return 64


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))


__all__: tuple[str, ...] = ()
