"""Pinned rc.2 kernel supply verification and private-CAS materialization.

This module deliberately has no package-root export.  It builds only from the
registered private checkout, verifies the resulting wheel independently, and
creates a content-addressed, per-Python Linux runtime manifest.  It performs no
valuation and never contacts a package index.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import stat
import struct
import subprocess
import tarfile
import tempfile
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

AUTHORITY_RESOURCE = (
    Path(__file__).resolve().parent
    / "resources"
    / "phase5-v1-kernel-runtime"
    / "runtime-authority.json"
)
MATERIALIZER_SOURCE = Path(__file__).resolve()
RUNNER_SOURCE = Path(__file__).resolve().with_name("valuation_pinned_kernel.py")
MANIFEST_POLICY_ID = "owner-research-pinned-kernel-runtime"
MANIFEST_POLICY_VERSION = "1.0.0"
_CANONICAL_JSON_KWARGS = {
    "allow_nan": False,
    "ensure_ascii": False,
    "separators": (",", ":"),
    "sort_keys": True,
}


class KernelMaterializationError(RuntimeError):
    """The pinned kernel supply or runtime manifest failed closed."""


@dataclass(frozen=True, slots=True)
class KernelSourceAttestation:
    repository: str
    tag: str
    tag_object: str
    commit: str
    tree: str
    tracked_source_count: int
    source_tree_sha256: str


@dataclass(frozen=True, slots=True)
class KernelRuntimeMaterialization:
    target_python_minor: str
    kernel_wheel_sha256: str
    runtime_manifest_path: Path
    runtime_manifest_file_sha256: str
    runtime_manifest_fingerprint: str


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, **_CANONICAL_JSON_KWARGS).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_regular_file_nofollow(path: Path, *, maximum_size: int = 256 * 1024 * 1024) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise KernelMaterializationError(
            f"input is unavailable or not a regular file: {path}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_size:
            raise KernelMaterializationError(f"input is not a bounded regular file: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_size + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_size:
                raise KernelMaterializationError(f"input exceeds the size limit: {path}")
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
            raise KernelMaterializationError(f"input changed while being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _sha256_path(path: Path) -> str:
    return _sha256_bytes(_read_regular_file_nofollow(path))


def _load_authority() -> tuple[dict[str, Any], str]:
    from .component_lock import default_component_lock_path, verify_kernel_runtime_lock

    lock_result = verify_kernel_runtime_lock()
    if not lock_result.ok:
        raise KernelMaterializationError(
            "kernel runtime component lock failed: " + "; ".join(lock_result.errors)
        )
    try:
        lock_raw = _read_regular_file_nofollow(
            default_component_lock_path(), maximum_size=8 * 1024 * 1024
        )
        lock = json.loads(lock_raw)
        runtime_lock = lock["valuation_kernel_runtime"]
        raw = _read_regular_file_nofollow(AUTHORITY_RESOURCE, maximum_size=1024 * 1024)
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise KernelMaterializationError("runtime authority is unavailable or invalid") from exc
    expected_paths = {
        "runtime_authority": "resources/phase5-v1-kernel-runtime/runtime-authority.json",
        "materializer_code": "valuation_kernel_materializer.py",
        "runner_code": "valuation_pinned_kernel.py",
    }
    locked_raw = {
        "runtime_authority": raw,
        "materializer_code": _read_regular_file_nofollow(
            MATERIALIZER_SOURCE, maximum_size=4 * 1024 * 1024
        ),
        "runner_code": _read_regular_file_nofollow(RUNNER_SOURCE, maximum_size=4 * 1024 * 1024),
    }
    for key, expected_path in expected_paths.items():
        entry = runtime_lock.get(key)
        if (
            not isinstance(entry, dict)
            or entry.get("path") != expected_path
            or entry.get("sha256") != _sha256_bytes(locked_raw[key])
        ):
            raise KernelMaterializationError(f"runtime authority lock drifted at {key}")
    if not isinstance(value, dict):
        raise KernelMaterializationError("runtime authority must be a JSON object")
    if (value.get("policy_id"), value.get("policy_version")) != (
        MANIFEST_POLICY_ID,
        MANIFEST_POLICY_VERSION,
    ):
        raise KernelMaterializationError("runtime authority policy identity mismatch")
    return value, _sha256_bytes(raw)


def _run_git(checkout: Path, *args: str, binary: bool = False) -> str | bytes:
    command = ("git", "-c", "core.hooksPath=/dev/null", "-C", str(checkout), *args)
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise KernelMaterializationError(f"git verification failed: {' '.join(args)}") from exc
    if binary:
        return completed.stdout
    return completed.stdout.decode("utf-8").strip()


def _git_blob(checkout: Path, commit: str, relative_path: str) -> bytes:
    return _run_git(checkout, "show", f"{commit}:{relative_path}", binary=True)  # type: ignore[return-value]


def _tracked_kernel_sources(checkout: Path, commit: str) -> tuple[str, ...]:
    output = _run_git(
        checkout,
        "ls-tree",
        "-r",
        "--name-only",
        commit,
        "src/owner_valuation",
    )
    assert isinstance(output, str)
    sources = tuple(sorted(line for line in output.splitlines() if line))
    if not sources or any(not item.startswith("src/owner_valuation/") for item in sources):
        raise KernelMaterializationError("pinned kernel source inventory is empty or invalid")
    return sources


def verify_pinned_kernel_checkout(kernel_checkout: Path) -> KernelSourceAttestation:
    """Verify the exact private tag, commit, tree, manifests, and Schema bytes."""

    checkout = kernel_checkout.resolve(strict=True)
    authority, _ = _load_authority()
    kernel = authority["kernel"]
    if _run_git(checkout, "rev-parse", "--is-inside-work-tree") != "true":
        raise KernelMaterializationError("kernel checkout is not a Git worktree")
    tag_ref = f"refs/tags/{kernel['tag']}"
    if _run_git(checkout, "rev-parse", tag_ref) != kernel["tag_object"]:
        raise KernelMaterializationError("kernel annotated tag object mismatch")
    if _run_git(checkout, "cat-file", "-t", kernel["tag_object"]) != "tag":
        raise KernelMaterializationError("kernel release tag is not annotated")
    if _run_git(checkout, "rev-parse", f"{tag_ref}^{{}}") != kernel["commit"]:
        raise KernelMaterializationError("kernel tag does not peel to the pinned commit")
    if _run_git(checkout, "rev-parse", f"{kernel['commit']}^{{tree}}") != kernel["tree"]:
        raise KernelMaterializationError("kernel commit tree mismatch")

    expected_files = {
        kernel["source_manifest_path"]: kernel["source_manifest_sha256"],
        kernel["release_manifest_path"]: kernel["release_manifest_sha256"],
        "pyproject.toml": kernel["pyproject_sha256"],
        "uv.lock": kernel["uv_lock_sha256"],
    }
    for relative_path, expected_sha256 in expected_files.items():
        if _sha256_bytes(_git_blob(checkout, kernel["commit"], relative_path)) != expected_sha256:
            raise KernelMaterializationError(f"pinned kernel file mismatch: {relative_path}")
    for filename, expected_sha256 in kernel["schema_sha256"].items():
        relative_path = f"schemas/{filename}"
        if _sha256_bytes(_git_blob(checkout, kernel["commit"], relative_path)) != expected_sha256:
            raise KernelMaterializationError(f"pinned kernel Schema mismatch: {filename}")

    sources = _tracked_kernel_sources(checkout, kernel["commit"])
    source_digest = hashlib.sha256()
    for relative_path in sources:
        blob = _git_blob(checkout, kernel["commit"], relative_path)
        source_digest.update(relative_path.encode("utf-8") + b"\0" + blob + b"\0")
    return KernelSourceAttestation(
        repository=kernel["repository"],
        tag=kernel["tag"],
        tag_object=kernel["tag_object"],
        commit=kernel["commit"],
        tree=kernel["tree"],
        tracked_source_count=len(sources),
        source_tree_sha256=source_digest.hexdigest(),
    )


def _safe_archive_name(name: str) -> None:
    pure = PurePosixPath(name)
    if not name or name.startswith("/") or "\\" in name or ".." in pure.parts:
        raise KernelMaterializationError(f"unsafe archive member: {name!r}")


def _validate_wheel_record(archive: zipfile.ZipFile) -> None:
    infos = archive.infolist()
    names = [item.filename for item in infos]
    if len(names) != len(set(names)):
        raise KernelMaterializationError("wheel contains duplicate members")
    for info in infos:
        _safe_archive_name(info.filename)
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise KernelMaterializationError("wheel contains a symbolic link")
    if archive.testzip() is not None:
        raise KernelMaterializationError("wheel CRC verification failed")
    record_names = [
        name
        for name in names
        if name.endswith(".dist-info/RECORD") and len(PurePosixPath(name).parts) == 2
    ]
    if len(record_names) != 1:
        raise KernelMaterializationError("wheel must contain exactly one RECORD")
    record_name = record_names[0]
    rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
    if len(rows) != len(names):
        raise KernelMaterializationError("wheel RECORD does not cover the exact inventory")
    by_name = {row[0]: row for row in rows if len(row) == 3}
    if set(by_name) != set(names):
        raise KernelMaterializationError("wheel RECORD inventory mismatch")
    for name in names:
        digest_field, size_field = by_name[name][1:]
        if name == record_name:
            if digest_field or size_field:
                raise KernelMaterializationError("wheel RECORD self-row must be unhashed")
            continue
        data = archive.read(name)
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if digest_field != f"sha256={digest}" or size_field != str(len(data)):
            raise KernelMaterializationError(f"wheel RECORD mismatch: {name}")


def _open_verified_wheel(path: Path) -> zipfile.ZipFile:
    try:
        archive = zipfile.ZipFile(io.BytesIO(_read_regular_file_nofollow(path)))
        _validate_wheel_record(archive)
        return archive
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError, csv.Error) as exc:
        raise KernelMaterializationError(f"invalid wheel: {path.name}") from exc


def verify_release_wheel(wheel_path: Path, kernel_checkout: Path) -> str:
    """Independently bind the release wheel to Git blobs and wheel metadata."""

    wheel = wheel_path if wheel_path.is_absolute() else Path.cwd() / wheel_path
    authority, _ = _load_authority()
    kernel = authority["kernel"]
    verify_pinned_kernel_checkout(kernel_checkout)
    if wheel.name != kernel["wheel_filename"]:
        raise KernelMaterializationError("kernel wheel filename mismatch")
    wheel_sha256 = _sha256_path(wheel)
    if wheel_sha256 != kernel["wheel_sha256"]:
        raise KernelMaterializationError("kernel release wheel SHA mismatch")

    archive = _open_verified_wheel(wheel)
    try:
        sources = _tracked_kernel_sources(kernel_checkout, kernel["commit"])
        package_names = {item.removeprefix("src/") for item in sources}
        dist_info = set(authority["build"]["normalized_dist_info_entries"])
        if set(archive.namelist()) != package_names | dist_info:
            raise KernelMaterializationError("kernel release wheel inventory mismatch")
        source_timestamp = tuple(
            int(value)
            for value in authority["build"]["source_zip_timestamp_utc"]
            .removesuffix("Z")
            .replace("T", "-")
            .replace(":", "-")
            .split("-")
        )
        dist_info_timestamp = tuple(
            int(value)
            for value in authority["build"]["dist_info_zip_timestamp_utc"]
            .removesuffix("Z")
            .replace("T", "-")
            .replace(":", "-")
            .split("-")
        )
        timestamp_by_name = {item.filename: item.date_time for item in archive.infolist()}
        if any(timestamp_by_name[name] != source_timestamp for name in package_names):
            raise KernelMaterializationError("kernel wheel source timestamp mismatch")
        if any(timestamp_by_name[name] != dist_info_timestamp for name in dist_info):
            raise KernelMaterializationError("kernel wheel dist-info timestamp mismatch")
        for source_path in sources:
            wheel_name = source_path.removeprefix("src/")
            if archive.read(wheel_name) != _git_blob(
                kernel_checkout, kernel["commit"], source_path
            ):
                raise KernelMaterializationError(f"kernel wheel source mismatch: {wheel_name}")
        prefix = "owner_valuation_kernel-2.0.0rc2.dist-info/"
        metadata = archive.read(prefix + "METADATA").decode("utf-8")
        wheel_metadata = archive.read(prefix + "WHEEL").decode("utf-8")
        entry_points = archive.read(prefix + "entry_points.txt").decode("utf-8")
        top_level = archive.read(prefix + "top_level.txt").decode("utf-8")
        required_metadata = (
            "Name: owner-valuation-kernel\n",
            "Version: 2.0.0rc2\n",
            "Requires-Python: >=3.11\n",
            "Requires-Dist: jsonschema<5,>=4.23\n",
        )
        if not all(item in metadata for item in required_metadata):
            raise KernelMaterializationError("kernel wheel METADATA identity mismatch")
        if wheel_metadata != (
            "Wheel-Version: 1.0\n"
            "Generator: setuptools (80.9.0)\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n\n"
        ):
            raise KernelMaterializationError("kernel wheel WHEEL metadata mismatch")
        if (
            entry_points != ("[console_scripts]\nowner-valuation = owner_valuation.cli:main\n")
            or top_level != "owner_valuation\n"
        ):
            raise KernelMaterializationError("kernel wheel entry-point identity mismatch")
    finally:
        archive.close()
    return wheel_sha256


def _verify_registered_wheel(path: Path, filename: str, expected_sha256: str) -> None:
    resolved = path if path.is_absolute() else Path.cwd() / path
    if resolved.name != filename or _sha256_path(resolved) != expected_sha256:
        raise KernelMaterializationError(f"registered wheel mismatch: {filename}")
    archive = _open_verified_wheel(resolved)
    archive.close()


def _extract_zip_safely(archive_path: Path, destination: Path) -> None:
    archive = _open_verified_wheel(archive_path)
    try:
        for info in archive.infolist():
            target = destination.joinpath(*PurePosixPath(info.filename).parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info.filename))
    finally:
        archive.close()


def _extract_git_archive(kernel_checkout: Path, commit: str, destination: Path) -> None:
    raw = _run_git(kernel_checkout, "archive", "--format=tar", commit, binary=True)
    assert isinstance(raw, bytes)
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive.getmembers():
                _safe_archive_name(member.name)
                if member.issym() or member.islnk() or member.isdev():
                    raise KernelMaterializationError("Git archive contains a forbidden member")
                if member.isdir():
                    destination.joinpath(*PurePosixPath(member.name).parts).mkdir(
                        parents=True, exist_ok=True
                    )
                    continue
                if not member.isfile():
                    raise KernelMaterializationError("Git archive contains an unsupported member")
                source = archive.extractfile(member)
                if source is None:
                    raise KernelMaterializationError("Git archive member could not be read")
                target = destination.joinpath(*PurePosixPath(member.name).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read())
                os.utime(target, (member.mtime, member.mtime))
    except tarfile.TarError as exc:
        raise KernelMaterializationError("Git archive extraction failed") from exc


def _dos_datetime(timestamp: str) -> tuple[int, int]:
    from datetime import datetime

    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    dos_date = ((parsed.year - 1980) << 9) | (parsed.month << 5) | parsed.day
    dos_time = (parsed.hour << 11) | (parsed.minute << 5) | (parsed.second // 2)
    return dos_time, dos_date


def _normalize_registered_zip_timestamps(
    wheel_path: Path, *, names: frozenset[str], timestamp: str
) -> None:
    """Patch only registered DOS timestamps without recompressing wheel content."""

    raw = bytearray(wheel_path.read_bytes())
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = {item.filename: item for item in archive.infolist()}
    except zipfile.BadZipFile as exc:
        raise KernelMaterializationError("built wheel is not a valid ZIP") from exc
    if set(infos).intersection(names) != set(names):
        raise KernelMaterializationError("built wheel lacks a registered dist-info entry")
    dos_time, dos_date = _dos_datetime(timestamp)
    for name in names:
        offset = infos[name].header_offset
        if raw[offset : offset + 4] != b"PK\x03\x04":
            raise KernelMaterializationError("wheel local-header offset is invalid")
        struct.pack_into("<HH", raw, offset + 10, dos_time, dos_date)

    eocd = raw.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(raw):
        raise KernelMaterializationError("wheel central directory is invalid")
    count = struct.unpack_from("<H", raw, eocd + 10)[0]
    central_offset = struct.unpack_from("<I", raw, eocd + 16)[0]
    seen: set[str] = set()
    cursor = central_offset
    for _ in range(count):
        if raw[cursor : cursor + 4] != b"PK\x01\x02":
            raise KernelMaterializationError("wheel central-directory entry is invalid")
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", raw, cursor + 28)
        member_name = bytes(raw[cursor + 46 : cursor + 46 + name_length]).decode("utf-8")
        if member_name in names:
            struct.pack_into("<HH", raw, cursor + 12, dos_time, dos_date)
            seen.add(member_name)
        cursor += 46 + name_length + extra_length + comment_length
    if seen != set(names):
        raise KernelMaterializationError("registered central-directory entries are incomplete")
    wheel_path.write_bytes(raw)


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_private_cas(cas_root: Path, kernel_checkout: Path) -> Path:
    resolved = cas_root.expanduser().resolve()
    research_root = Path(__file__).resolve().parents[2]
    kernel_root = kernel_checkout.resolve()
    if _is_within(resolved, research_root) or _is_within(resolved, kernel_root):
        raise KernelMaterializationError("private CAS must be outside both repositories")
    resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(resolved, 0o700)
    return resolved


def _store_cas_file(source: Path, cas_root: Path, sha256: str) -> Path:
    directory = cas_root / "sha256"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    target = directory / sha256
    if target.exists():
        if _sha256_path(target) != sha256:
            raise KernelMaterializationError("private CAS object hash mismatch")
        return target
    source_bytes = _read_regular_file_nofollow(source)
    if _sha256_bytes(source_bytes) != sha256:
        raise KernelMaterializationError("private CAS source hash mismatch")
    temporary = directory / f".{sha256}.{os.getpid()}.tmp"
    with temporary.open("xb") as outgoing:
        os.chmod(temporary, 0o600)
        outgoing.write(source_bytes)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    if _sha256_path(temporary) != sha256:
        temporary.unlink(missing_ok=True)
        raise KernelMaterializationError("private CAS write did not preserve bytes")
    os.replace(temporary, target)
    os.chmod(target, 0o600)
    return target


def _source_sha256(path: Path) -> str:
    return _sha256_path(path)


def _validated_executable(path: Path) -> tuple[Path, str]:
    absolute = path if path.is_absolute() else Path.cwd() / path
    try:
        details = absolute.lstat()
    except OSError as exc:
        raise KernelMaterializationError("build Python executable is unavailable") from exc
    if not stat.S_ISREG(details.st_mode) or not os.access(absolute, os.X_OK):
        raise KernelMaterializationError("build Python must be a non-symlink executable file")
    snapshot_sha256 = _sha256_bytes(_read_regular_file_nofollow(absolute))
    return absolute, snapshot_sha256


def _build_release_wheel(
    *,
    checkout: Path,
    build_python: Path,
    setuptools_wheel: Path,
    destination: Path,
    authority: Mapping[str, Any],
) -> Path:
    build = authority["build"]
    _verify_registered_wheel(
        setuptools_wheel,
        build["setuptools_wheel_filename"],
        build["setuptools_wheel_sha256"],
    )
    executable, executable_sha256 = _validated_executable(build_python)
    source_dir = destination / "source"
    backend_dir = destination / "backend"
    output_dir = destination / "wheel"
    source_dir.mkdir()
    backend_dir.mkdir()
    output_dir.mkdir()
    _extract_git_archive(checkout, authority["kernel"]["commit"], source_dir)
    _extract_zip_safely(setuptools_wheel, backend_dir)
    script = (
        "import pathlib,sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "from setuptools import build_meta;"
        "pathlib.Path(sys.argv[3]).write_text("
        "build_meta.build_wheel(sys.argv[2]),encoding='utf-8')"
    )
    filename_file = destination / "built-filename.txt"
    environment = {
        "HOME": str(destination / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": "1784088771",
        "TZ": "UTC",
    }
    Path(environment["HOME"]).mkdir()
    try:
        subprocess.run(
            (
                str(executable),
                "-I",
                "-c",
                script,
                str(backend_dir),
                str(output_dir),
                str(filename_file),
            ),
            cwd=source_dir,
            env=environment,
            check=True,
            capture_output=True,
            timeout=180,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise KernelMaterializationError("offline setuptools wheel build failed") from exc
    if _sha256_path(executable) != executable_sha256:
        raise KernelMaterializationError("build Python changed during materialization")
    try:
        filename = filename_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise KernelMaterializationError("build backend did not return a wheel filename") from exc
    if filename != authority["kernel"]["wheel_filename"]:
        raise KernelMaterializationError("build backend returned an unexpected wheel filename")
    wheel = output_dir / filename
    _normalize_registered_zip_timestamps(
        wheel,
        names=frozenset(build["normalized_dist_info_entries"]),
        timestamp=build["dist_info_zip_timestamp_utc"],
    )
    return wheel


def materialize_pinned_kernel_runtime(
    *,
    kernel_checkout: Path,
    cas_root: Path,
    build_python: Path,
    setuptools_wheel: Path,
    dependency_wheels: Iterable[Path],
    target_python_minor: str,
) -> KernelRuntimeMaterialization:
    """Build, verify, and materialize one pinned Linux runtime without networking."""

    authority, authority_sha256 = _load_authority()
    verify_pinned_kernel_checkout(kernel_checkout)
    cas = _validate_private_cas(cas_root, kernel_checkout)
    dependency_wheels = tuple(Path(item) for item in dependency_wheels)
    expected_dependencies = {
        filename: sha256
        for filename, sha256 in authority["runtime"]["python_minors"].get(target_python_minor, ())
    }
    if not expected_dependencies:
        raise KernelMaterializationError("target Python minor is not registered")
    supplied = {item.name: item for item in dependency_wheels}
    if len(supplied) != len(dependency_wheels) or set(supplied) != set(expected_dependencies):
        raise KernelMaterializationError("runtime dependency wheel inventory mismatch")
    for filename, expected_sha256 in expected_dependencies.items():
        _verify_registered_wheel(supplied[filename], filename, expected_sha256)

    with tempfile.TemporaryDirectory(prefix="owner-kernel-materialize-") as temporary:
        temporary_path = Path(temporary)
        wheel = _build_release_wheel(
            checkout=kernel_checkout,
            build_python=build_python,
            setuptools_wheel=setuptools_wheel,
            destination=temporary_path,
            authority=authority,
        )
        kernel_sha256 = verify_release_wheel(wheel, kernel_checkout)
        _store_cas_file(wheel, cas, kernel_sha256)
    wheel_items = [
        {
            "filename": authority["kernel"]["wheel_filename"],
            "role": "kernel",
            "sha256": authority["kernel"]["wheel_sha256"],
            "uri": f"cas://sha256/{authority['kernel']['wheel_sha256']}",
        }
    ]
    for filename, expected_sha256 in sorted(expected_dependencies.items()):
        _store_cas_file(supplied[filename], cas, expected_sha256)
        wheel_items.append(
            {
                "filename": filename,
                "role": "runtime_dependency",
                "sha256": expected_sha256,
                "uri": f"cas://sha256/{expected_sha256}",
            }
        )
    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "manifest_policy_id": MANIFEST_POLICY_ID,
        "manifest_policy_version": MANIFEST_POLICY_VERSION,
        "authority": {
            "path": "owner_research/resources/phase5-v1-kernel-runtime/runtime-authority.json",
            "sha256": authority_sha256,
        },
        "producer": {
            "materializer_path": "owner_research/valuation_kernel_materializer.py",
            "materializer_sha256": _source_sha256(MATERIALIZER_SOURCE),
            "runner_path": "owner_research/valuation_pinned_kernel.py",
            "runner_sha256": _source_sha256(RUNNER_SOURCE),
        },
        "kernel": {
            key: authority["kernel"][key]
            for key in (
                "repository",
                "tag",
                "tag_object",
                "commit",
                "tree",
                "package_version",
                "plugin_version",
                "wheel_sha256",
            )
        },
        "target": {
            "implementation": "cpython",
            "platform": authority["runtime"]["platform"],
            "python_minor": target_python_minor,
        },
        "transport": {
            "kernel_call": authority["runtime"]["kernel_call"],
            "kernel_call_count": authority["runtime"]["kernel_call_count"],
            "network_mode": authority["runtime"]["network_mode"],
            "request": authority["runtime"]["request_transport"],
            "result": authority["runtime"]["result_transport"],
            "result_bytes_preserved": authority["runtime"]["result_bytes_preserved"],
        },
        "wheels": wheel_items,
    }
    manifest["manifest_fingerprint"] = _sha256_bytes(_canonical_bytes(manifest))
    manifest_bytes = _canonical_bytes(manifest)
    manifest_file_sha256 = _sha256_bytes(manifest_bytes)
    manifest_directory = cas / "manifests"
    manifest_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(manifest_directory, 0o700)
    manifest_path = manifest_directory / f"{manifest_file_sha256}.json"
    if manifest_path.exists() and manifest_path.read_bytes() != manifest_bytes:
        raise KernelMaterializationError("runtime manifest CAS collision")
    if not manifest_path.exists():
        temporary_manifest = manifest_directory / f".{manifest_file_sha256}.{os.getpid()}.tmp"
        with temporary_manifest.open("xb") as handle:
            os.chmod(temporary_manifest, 0o600)
            handle.write(manifest_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_manifest, manifest_path)
        os.chmod(manifest_path, 0o600)
    load_and_verify_runtime_manifest(
        manifest_path,
        cas_root=cas,
        expected_manifest_file_sha256=manifest_file_sha256,
    )
    return KernelRuntimeMaterialization(
        target_python_minor=target_python_minor,
        kernel_wheel_sha256=kernel_sha256,
        runtime_manifest_path=manifest_path,
        runtime_manifest_file_sha256=manifest_file_sha256,
        runtime_manifest_fingerprint=manifest["manifest_fingerprint"],
    )


def _validate_manifest_shape(manifest: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "manifest_policy_id",
        "manifest_policy_version",
        "authority",
        "producer",
        "kernel",
        "target",
        "transport",
        "wheels",
        "manifest_fingerprint",
    }
    if set(manifest) != required:
        raise KernelMaterializationError("runtime manifest fields are not closed")
    if (manifest["manifest_policy_id"], manifest["manifest_policy_version"]) != (
        MANIFEST_POLICY_ID,
        MANIFEST_POLICY_VERSION,
    ):
        raise KernelMaterializationError("runtime manifest policy identity mismatch")


def load_and_verify_runtime_manifest(
    manifest_path: Path,
    *,
    cas_root: Path,
    expected_manifest_file_sha256: str | None = None,
) -> dict[str, Any]:
    """Reload and bind a runtime manifest to current authority, code, and CAS bytes."""

    path = manifest_path if manifest_path.is_absolute() else Path.cwd() / manifest_path
    try:
        details = path.lstat()
    except OSError as exc:
        raise KernelMaterializationError("runtime manifest is unavailable") from exc
    if not stat.S_ISREG(details.st_mode):
        raise KernelMaterializationError("runtime manifest must be a non-symlink regular file")
    cas = cas_root.resolve(strict=True)
    if path.parent.resolve() != (cas / "manifests").resolve():
        raise KernelMaterializationError("runtime manifest is outside the private CAS")
    raw = _read_regular_file_nofollow(path, maximum_size=8 * 1024 * 1024)
    file_sha256 = _sha256_bytes(raw)
    if expected_manifest_file_sha256 is not None and file_sha256 != expected_manifest_file_sha256:
        raise KernelMaterializationError("runtime manifest file SHA mismatch")
    if path.name != f"{file_sha256}.json":
        raise KernelMaterializationError("runtime manifest path is not content addressed")
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise KernelMaterializationError("runtime manifest is invalid JSON") from exc
    if not isinstance(manifest, dict) or raw != _canonical_bytes(manifest):
        raise KernelMaterializationError("runtime manifest is not canonical JSON")
    _validate_manifest_shape(manifest)
    fingerprint_payload = dict(manifest)
    supplied_fingerprint = fingerprint_payload.pop("manifest_fingerprint")
    if _sha256_bytes(_canonical_bytes(fingerprint_payload)) != supplied_fingerprint:
        raise KernelMaterializationError("runtime manifest fingerprint mismatch")

    authority, authority_sha256 = _load_authority()
    if manifest["authority"] != {
        "path": "owner_research/resources/phase5-v1-kernel-runtime/runtime-authority.json",
        "sha256": authority_sha256,
    }:
        raise KernelMaterializationError("runtime manifest authority binding mismatch")
    if manifest["producer"] != {
        "materializer_path": "owner_research/valuation_kernel_materializer.py",
        "materializer_sha256": _source_sha256(MATERIALIZER_SOURCE),
        "runner_path": "owner_research/valuation_pinned_kernel.py",
        "runner_sha256": _source_sha256(RUNNER_SOURCE),
    }:
        raise KernelMaterializationError("runtime manifest producer-code binding mismatch")
    expected_kernel = {
        key: authority["kernel"][key]
        for key in (
            "repository",
            "tag",
            "tag_object",
            "commit",
            "tree",
            "package_version",
            "plugin_version",
            "wheel_sha256",
        )
    }
    if manifest["kernel"] != expected_kernel:
        raise KernelMaterializationError("runtime manifest kernel identity mismatch")
    python_minor = manifest["target"].get("python_minor")
    if (
        manifest["target"]
        != {
            "implementation": "cpython",
            "platform": authority["runtime"]["platform"],
            "python_minor": python_minor,
        }
        or python_minor not in authority["runtime"]["python_minors"]
    ):
        raise KernelMaterializationError("runtime manifest target mismatch")
    expected_wheels = {
        authority["kernel"]["wheel_filename"]: authority["kernel"]["wheel_sha256"],
        **{
            filename: sha256
            for filename, sha256 in authority["runtime"]["python_minors"][python_minor]
        },
    }
    wheels = manifest["wheels"]
    expected_wheel_items = [
        {
            "filename": authority["kernel"]["wheel_filename"],
            "role": "kernel",
            "sha256": authority["kernel"]["wheel_sha256"],
            "uri": f"cas://sha256/{authority['kernel']['wheel_sha256']}",
        },
        *[
            {
                "filename": filename,
                "role": "runtime_dependency",
                "sha256": sha256,
                "uri": f"cas://sha256/{sha256}",
            }
            for filename, sha256 in sorted(authority["runtime"]["python_minors"][python_minor])
        ],
    ]
    if wheels != expected_wheel_items:
        raise KernelMaterializationError("runtime manifest wheel inventory mismatch")
    expected_transport = {
        "kernel_call": authority["runtime"]["kernel_call"],
        "kernel_call_count": authority["runtime"]["kernel_call_count"],
        "network_mode": authority["runtime"]["network_mode"],
        "request": authority["runtime"]["request_transport"],
        "result": authority["runtime"]["result_transport"],
        "result_bytes_preserved": authority["runtime"]["result_bytes_preserved"],
    }
    if manifest["transport"] != expected_transport:
        raise KernelMaterializationError("runtime manifest transport mismatch")
    observed: dict[str, str] = {}
    for item in wheels:
        if not isinstance(item, dict) or set(item) != {"filename", "role", "sha256", "uri"}:
            raise KernelMaterializationError("runtime manifest wheel entry is not closed")
        filename = item["filename"]
        sha256 = item["sha256"]
        if filename in observed or expected_wheels.get(filename) != sha256:
            raise KernelMaterializationError("runtime manifest contains an unregistered wheel")
        expected_role = (
            "kernel"
            if filename == authority["kernel"]["wheel_filename"]
            else ("runtime_dependency")
        )
        if item["role"] != expected_role or item["uri"] != f"cas://sha256/{sha256}":
            raise KernelMaterializationError("runtime manifest wheel binding mismatch")
        wheel_path = cas / "sha256" / sha256
        if not wheel_path.is_file() or _sha256_path(wheel_path) != sha256:
            raise KernelMaterializationError("runtime wheel CAS object mismatch")
        _verify_registered_wheel(wheel_path, wheel_path.name, sha256)
        observed[filename] = sha256
    if observed != expected_wheels:
        raise KernelMaterializationError("runtime manifest omitted a registered wheel")
    return manifest


__all__: tuple[str, ...] = ()
