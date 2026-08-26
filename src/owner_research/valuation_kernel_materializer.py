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
import platform
import stat
import struct
import subprocess
import sys
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
    absolute = Path(path).expanduser().absolute()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise KernelMaterializationError(
            f"input is unavailable or not a regular file: {path}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum_size
        ):
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
        try:
            path_after = absolute.lstat()
        except OSError as exc:
            raise KernelMaterializationError(f"input changed while being read: {path}") from exc

        def identity(item: os.stat_result) -> tuple[int, ...]:
            return (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_nlink,
                item.st_uid,
                item.st_gid,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if (
            total != before.st_size
            or identity(before) != identity(after)
            or identity(after) != identity(path_after)
        ):
            raise KernelMaterializationError(f"input changed while being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _sha256_path(path: Path) -> str:
    return _sha256_bytes(_read_regular_file_nofollow(path))


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_authority() -> tuple[dict[str, Any], str]:
    from .component_lock import default_component_lock_path, verify_kernel_runtime_snapshot

    try:
        lock_raw = _read_regular_file_nofollow(
            default_component_lock_path(), maximum_size=8 * 1024 * 1024
        )
        raw = _read_regular_file_nofollow(AUTHORITY_RESOURCE, maximum_size=1024 * 1024)
        materializer_raw = _read_regular_file_nofollow(
            MATERIALIZER_SOURCE, maximum_size=4 * 1024 * 1024
        )
        runner_raw = _read_regular_file_nofollow(
            RUNNER_SOURCE, maximum_size=4 * 1024 * 1024
        )
        result = verify_kernel_runtime_snapshot(
            lock_bytes=lock_raw,
            runtime_authority_bytes=raw,
            materializer_bytes=materializer_raw,
            runner_bytes=runner_raw,
        )
        if not result.ok:
            raise KernelMaterializationError(
                "kernel runtime component lock failed: " + "; ".join(result.errors)
            )
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except KernelMaterializationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise KernelMaterializationError("runtime authority is unavailable or invalid") from exc
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

    raw = bytearray(_read_regular_file_nofollow(wheel_path))
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


def _validate_private_directory_descriptor(descriptor: int, label: str) -> None:
    details = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise KernelMaterializationError(f"{label} is not a private owned directory")


def _open_private_directory(path: Path, *, create: bool, label: str) -> int:
    if create:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise KernelMaterializationError(f"{label} could not be created") from exc
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise KernelMaterializationError(f"{label} is unavailable or unsafe") from exc
    try:
        _validate_private_directory_descriptor(descriptor, label)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_private_cas_subdirectory(
    cas_root: Path, name: str, *, create: bool
) -> tuple[Path, int]:
    if name not in {"sha256", "manifests"}:
        raise KernelMaterializationError("private CAS directory role is unregistered")
    root_descriptor = _open_private_directory(
        cas_root, create=False, label="private CAS root"
    )
    try:
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=root_descriptor)
            except FileExistsError:
                pass
            except OSError as exc:
                raise KernelMaterializationError(
                    f"private CAS {name} directory could not be created"
                ) from exc
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(name, flags, dir_fd=root_descriptor)
        except OSError as exc:
            raise KernelMaterializationError(
                f"private CAS {name} directory is unavailable or unsafe"
            ) from exc
        try:
            _validate_private_directory_descriptor(
                descriptor, f"private CAS {name} directory"
            )
        except BaseException:
            os.close(descriptor)
            raise
        return cas_root / name, descriptor
    finally:
        os.close(root_descriptor)


def _read_private_cas_member(
    cas_root: Path,
    directory_name: str,
    filename: str,
    *,
    maximum_size: int = 256 * 1024 * 1024,
) -> bytes:
    if not filename or PurePosixPath(filename).name != filename:
        raise KernelMaterializationError("private CAS member name is unsafe")
    _, directory_descriptor = _open_private_cas_subdirectory(
        cas_root, directory_name, create=False
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            descriptor = os.open(filename, flags, dir_fd=directory_descriptor)
        except OSError as exc:
            raise KernelMaterializationError("private CAS member is unavailable or unsafe") from exc
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & 0o077
                or before.st_nlink != 1
                or before.st_size > maximum_size
            ):
                raise KernelMaterializationError("private CAS member metadata is unsafe")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(
                    descriptor, min(1024 * 1024, maximum_size + 1 - total)
                )
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum_size:
                    raise KernelMaterializationError("private CAS member exceeds its limit")
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
                raise KernelMaterializationError("private CAS member changed while read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_descriptor)


def _validate_private_cas(cas_root: Path, kernel_checkout: Path) -> Path:
    requested = Path(os.path.abspath(cas_root.expanduser()))
    research_root = Path(__file__).resolve().parents[2]
    kernel_root = kernel_checkout.resolve()
    prospective = requested.resolve(strict=False)
    if _is_within(prospective, research_root) or _is_within(prospective, kernel_root):
        raise KernelMaterializationError("private CAS must be outside both repositories")
    requested.parent.mkdir(parents=True, exist_ok=True)
    descriptor = _open_private_directory(
        requested, create=True, label="private CAS root"
    )
    os.close(descriptor)
    resolved = requested.resolve(strict=True)
    if _is_within(resolved, research_root) or _is_within(resolved, kernel_root):
        raise KernelMaterializationError("private CAS must be outside both repositories")
    return resolved


def _validate_existing_private_cas(cas_root: Path) -> Path:
    requested = Path(os.path.abspath(cas_root.expanduser()))
    descriptor = _open_private_directory(
        requested, create=False, label="private CAS root"
    )
    os.close(descriptor)
    resolved = requested.resolve(strict=True)
    if _is_within(resolved, Path(__file__).resolve().parents[2]):
        raise KernelMaterializationError("private CAS must be outside the research repository")
    return resolved


def _store_cas_file(source: Path, cas_root: Path, sha256: str) -> Path:
    return _store_cas_bytes(_read_regular_file_nofollow(source), cas_root, sha256)


def _store_private_cas_member(
    source_bytes: bytes,
    cas_root: Path,
    *,
    directory_name: str,
    filename: str,
    expected_sha256: str,
) -> Path:
    if not filename or PurePosixPath(filename).name != filename:
        raise KernelMaterializationError("private CAS member name is unsafe")
    if _sha256_bytes(source_bytes) != expected_sha256:
        raise KernelMaterializationError("private CAS source hash mismatch")
    directory, directory_descriptor = _open_private_cas_subdirectory(
        cas_root, directory_name, create=True
    )
    target = directory / filename
    temporary_name = (
        f".{expected_sha256}.{os.getpid()}.{_sha256_bytes(os.urandom(16))}.tmp"
    )
    descriptor: int | None = None
    try:
        try:
            probe = os.open(
                filename,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_descriptor,
            )
        except FileNotFoundError:
            probe = None
        except OSError as exc:
            raise KernelMaterializationError(
                "private CAS object is unavailable or unsafe"
            ) from exc
        if probe is not None:
            os.close(probe)
            existing = _read_private_cas_member(cas_root, directory_name, filename)
            if _sha256_bytes(existing) != expected_sha256:
                raise KernelMaterializationError("private CAS object hash mismatch")
            return target
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_descriptor)
        view = memoryview(source_bytes)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise KernelMaterializationError("private CAS write did not complete")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(
                temporary_name,
                filename,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing = _read_private_cas_member(cas_root, directory_name, filename)
            if _sha256_bytes(existing) != expected_sha256:
                raise KernelMaterializationError(
                    "private CAS object hash mismatch"
                ) from None
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        os.fsync(directory_descriptor)
        if (
            _sha256_bytes(_read_private_cas_member(cas_root, directory_name, filename))
            != expected_sha256
        ):
            raise KernelMaterializationError("private CAS write did not preserve bytes")
        return target
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass
        os.close(directory_descriptor)


def _store_cas_bytes(source_bytes: bytes, cas_root: Path, sha256: str) -> Path:
    return _store_private_cas_member(
        source_bytes,
        cas_root,
        directory_name="sha256",
        filename=sha256,
        expected_sha256=sha256,
    )


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


def _trusted_build_python() -> tuple[Path, dict[str, str]]:
    try:
        executable = Path(sys.executable).resolve(strict=True)
    except OSError as exc:
        raise KernelMaterializationError("running build Python is unavailable") from exc
    if (
        sys.implementation.name != "cpython"
        or sys.version_info[:2] != (3, 11)
        or platform.system() != "Linux"
        or platform.machine() not in {"x86_64", "AMD64"}
    ):
        raise KernelMaterializationError(
            "materialization requires the trusted Linux x86_64 CPython 3.11 process"
        )
    executable, executable_sha256 = _validated_executable(executable)
    return executable, {
        "implementation": "cpython",
        "python_version": platform.python_version(),
        "platform": "linux_x86_64",
        "executable_sha256": executable_sha256,
    }


def _build_release_wheel(
    *,
    checkout: Path,
    setuptools_wheel: Path,
    destination: Path,
    authority: Mapping[str, Any],
) -> tuple[Path, dict[str, str]]:
    build = authority["build"]
    _verify_registered_wheel(
        setuptools_wheel,
        build["setuptools_wheel_filename"],
        build["setuptools_wheel_sha256"],
    )
    executable, build_python_identity = _trusted_build_python()
    executable_sha256 = build_python_identity["executable_sha256"]
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
        filename = _read_regular_file_nofollow(
            filename_file,
            maximum_size=1024,
        ).decode("utf-8")
    except (OSError, UnicodeError, KernelMaterializationError) as exc:
        raise KernelMaterializationError("build backend did not return a wheel filename") from exc
    if filename != authority["kernel"]["wheel_filename"]:
        raise KernelMaterializationError("build backend returned an unexpected wheel filename")
    wheel = output_dir / filename
    _normalize_registered_zip_timestamps(
        wheel,
        names=frozenset(build["normalized_dist_info_entries"]),
        timestamp=build["dist_info_zip_timestamp_utc"],
    )
    return wheel, build_python_identity


def materialize_pinned_kernel_runtime(
    *,
    kernel_checkout: Path,
    cas_root: Path,
    setuptools_wheel: Path,
    dependency_wheels: Iterable[Path],
    target_python_minor: str,
) -> KernelRuntimeMaterialization:
    """Build, verify, and materialize one pinned Linux runtime without networking."""

    authority, authority_sha256 = _load_authority()
    verify_pinned_kernel_checkout(kernel_checkout)
    cas = _validate_private_cas(cas_root, kernel_checkout)
    dependency_wheels = tuple(Path(item) for item in dependency_wheels)
    if target_python_minor != authority["runtime"]["container"]["python_minor"]:
        raise KernelMaterializationError(
            "target Python minor has no pinned production container"
        )
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
        wheel, build_python_identity = _build_release_wheel(
            checkout=kernel_checkout,
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
    result_schema = authority["runtime"]["result_schema"]
    result_schema_bytes = _git_blob(
        kernel_checkout,
        authority["kernel"]["commit"],
        f"schemas/{result_schema['filename']}",
    )
    if _sha256_bytes(result_schema_bytes) != result_schema["sha256"]:
        raise KernelMaterializationError("pinned result Schema bytes do not match authority")
    _store_cas_bytes(result_schema_bytes, cas, result_schema["sha256"])
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
            "build_python": build_python_identity,
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
        "container": authority["runtime"]["container"],
        "trusted_workflow": authority["runtime"]["trusted_workflow"],
        "result_schema": {
            "filename": result_schema["filename"],
            "sha256": result_schema["sha256"],
            "uri": f"cas://sha256/{result_schema['sha256']}",
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
    manifest_path = _store_private_cas_member(
        manifest_bytes,
        cas,
        directory_name="manifests",
        filename=f"{manifest_file_sha256}.json",
        expected_sha256=manifest_file_sha256,
    )
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
        "container",
        "trusted_workflow",
        "result_schema",
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

    path = Path(os.path.abspath(manifest_path.expanduser()))
    cas = _validate_existing_private_cas(cas_root)
    if path.parent != cas / "manifests":
        raise KernelMaterializationError("runtime manifest is outside the private CAS")
    raw = _read_private_cas_member(
        cas, "manifests", path.name, maximum_size=8 * 1024 * 1024
    )
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
    producer = manifest["producer"]
    build_python = producer.get("build_python") if isinstance(producer, dict) else None
    expected_producer = {
        "materializer_path": "owner_research/valuation_kernel_materializer.py",
        "materializer_sha256": _source_sha256(MATERIALIZER_SOURCE),
        "runner_path": "owner_research/valuation_pinned_kernel.py",
        "runner_sha256": _source_sha256(RUNNER_SOURCE),
        "build_python": build_python,
    }
    if producer != expected_producer:
        raise KernelMaterializationError("runtime manifest producer-code binding mismatch")
    if (
        not isinstance(build_python, dict)
        or set(build_python)
        != {"implementation", "python_version", "platform", "executable_sha256"}
        or build_python.get("implementation") != "cpython"
        or not str(build_python.get("python_version", "")).startswith("3.11.")
        or build_python.get("platform") != "linux_x86_64"
        or len(str(build_python.get("executable_sha256", ""))) != 64
        or any(
            character not in "0123456789abcdef"
            for character in str(build_python.get("executable_sha256", ""))
        )
    ):
        raise KernelMaterializationError("runtime manifest build-Python binding mismatch")
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
    if manifest["container"] != authority["runtime"]["container"]:
        raise KernelMaterializationError("runtime manifest container identity mismatch")
    if manifest["trusted_workflow"] != authority["runtime"]["trusted_workflow"]:
        raise KernelMaterializationError("runtime manifest trusted-workflow identity mismatch")
    result_schema = authority["runtime"]["result_schema"]
    expected_result_schema = {
        "filename": result_schema["filename"],
        "sha256": result_schema["sha256"],
        "uri": f"cas://sha256/{result_schema['sha256']}",
    }
    if manifest["result_schema"] != expected_result_schema:
        raise KernelMaterializationError("runtime manifest result Schema binding mismatch")
    result_schema_bytes = _read_private_cas_member(
        cas,
        "sha256",
        result_schema["sha256"],
        maximum_size=8 * 1024 * 1024,
    )
    if _sha256_bytes(result_schema_bytes) != result_schema["sha256"]:
        raise KernelMaterializationError("runtime result Schema CAS object mismatch")
    try:
        result_schema_payload = json.loads(result_schema_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise KernelMaterializationError("runtime result Schema is invalid JSON") from exc
    if (
        not isinstance(result_schema_payload, dict)
        or result_schema_payload.get("$schema")
        != "https://json-schema.org/draft/2020-12/schema"
        or result_schema_payload.get("additionalProperties") is not False
    ):
        raise KernelMaterializationError("runtime result Schema identity is invalid")
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
        wheel_bytes = _read_private_cas_member(cas, "sha256", sha256)
        if _sha256_bytes(wheel_bytes) != sha256:
            raise KernelMaterializationError("runtime wheel CAS object mismatch")
        _verify_registered_wheel(wheel_path, wheel_path.name, sha256)
        observed[filename] = sha256
    if observed != expected_wheels:
        raise KernelMaterializationError("runtime manifest omitted a registered wheel")
    return manifest


__all__: tuple[str, ...] = ()
