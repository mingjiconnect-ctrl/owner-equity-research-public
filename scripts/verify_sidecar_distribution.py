#!/usr/bin/env python3
"""Verify the private Futu OpenD sidecar wheel and sdist against trusted source."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import stat
import struct
import subprocess
import tarfile
import tempfile
import tomllib
import zlib
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile

ROOT = Path(__file__).resolve().parents[1]
SIDECAR_RELATIVE = PurePosixPath("sidecars/futu-opend")
PACKAGE = "owner_research_futu_sidecar"
PROJECT_NAME = "owner-research-futu-sidecar"
PROJECT_VERSION = "1.0.0.dev0"
PROJECT_LICENSE_EXPRESSION = "LicenseRef-Owner-Research-Proprietary"
DIST_STEM = "owner_research_futu_sidecar-1.0.0.dev0"
DIST_INFO = f"{DIST_STEM}.dist-info"
SDIST_PREFIX = f"{DIST_STEM}/"
FIXED_ZIP_TIME = (2020, 2, 2, 0, 0, 0)
FIXED_TAR_TIME = 1_580_601_600
MAXIMUM_MEMBERS = 512
MAXIMUM_MEMBER_BYTES = 64 * 1024 * 1024
MAXIMUM_ARCHIVE_BYTES = 512 * 1024 * 1024
MAXIMUM_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
_ZIP_EOCD = struct.Struct("<4s4H2LH")
_ZIP_LOCAL_HEADER = struct.Struct("<4s5H3L2H")
_ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3L5H2L")
_CANONICAL_GZIP_HEADER = struct.pack(
    "<BBBBLBB",
    0x1F,
    0x8B,
    8,
    0,
    FIXED_TAR_TIME,
    2,
    255,
)

SOURCE_DIRECTORIES = (
    "launcher",
    "resources",
    "src/owner_research_futu_sidecar",
    "supply",
    "tests",
    "wire",
)
WHEEL_SOURCE_DIRECTORIES = (
    "launcher",
    "resources",
    "src/owner_research_futu_sidecar",
    "supply",
    "wire",
)
IGNORED_PARTS = {"__pycache__", ".pytest_cache", ".ruff_cache"}
EXPECTED_DEPENDENCIES = [
    "cffi==2.1.1; platform_python_implementation != 'PyPy'",
    "cryptography==50.0.0",
    "futu-api==10.10.7008",
    "numpy==2.4.2; python_version < '3.14'",
    "pandas==3.0.5",
    "protobuf==7.35.1",
    "pycparser==3.0; platform_python_implementation != 'PyPy'",
    "pycryptodome==3.23.0",
    "python-dateutil==2.9.0.post0",
    "simplejson==4.1.1",
    "six==1.17.0",
]
EXPECTED_TEST_DEPENDENCIES = [
    "attrs==26.1.0",
    "iniconfig==2.3.0",
    "jsonschema==4.26.0",
    "jsonschema-specifications==2025.9.1",
    "packaging==26.3",
    "pluggy==1.6.0",
    "pygments==2.20.0",
    "pytest==8.4.2",
    "referencing==0.37.0",
    "rpds-py==2026.6.3",
    "ruff==0.12.9",
    "typing-extensions==4.16.0",
]
EXPECTED_SCRIPTS = {
    "owner-research-futu-sidecar": "owner_research_futu_sidecar.cli:main",
    "owner-research-futu-launch": "owner_research_futu_sidecar.launcher:main",
    "owner-research-futu-preopen-and-launch": (
        "owner_research_futu_sidecar.launcher:preopen_and_launch_main"
    ),
}
EXPECTED_ENTRY_POINTS = (
    b"[console_scripts]\n"
    b"owner-research-futu-launch = owner_research_futu_sidecar.launcher:main\n"
    b"owner-research-futu-preopen-and-launch = "
    b"owner_research_futu_sidecar.launcher:preopen_and_launch_main\n"
    b"owner-research-futu-sidecar = owner_research_futu_sidecar.cli:main\n"
)
EXPECTED_WHEEL = (
    b"Wheel-Version: 1.0\nGenerator: hatchling 1.27.0\nRoot-Is-Purelib: true\n"
    b"Tag: py3-none-any\n"
)


def _exact_deflate_stream_error(
    descriptor: int,
    payload_offset: int,
    compressed_size: int,
    uncompressed_size: int,
) -> str | None:
    """Require one raw DEFLATE stream to consume its declared span exactly."""
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    position = payload_offset
    remaining = compressed_size
    total = 0
    try:
        while remaining:
            chunk_size = min(1024 * 1024, remaining)
            pending = os.pread(descriptor, chunk_size, position)
            if len(pending) != chunk_size:
                return "sidecar wheel ZIP member compressed stream is truncated"
            position += chunk_size
            remaining -= chunk_size
            while pending:
                output_limit = min(1024 * 1024, uncompressed_size - total + 1)
                decoded = decoder.decompress(pending, output_limit)
                pending = decoder.unconsumed_tail
                total += len(decoded)
                if total > uncompressed_size:
                    return "sidecar wheel ZIP member expands beyond its declared size"
                if decoder.unused_data:
                    return "sidecar wheel ZIP member compressed stream has trailing data"
                if decoder.eof:
                    if pending or remaining:
                        return "sidecar wheel ZIP member compressed stream has trailing data"
                    break
            if decoder.eof:
                break
    except zlib.error:
        return "sidecar wheel ZIP member compressed stream is invalid"
    if not decoder.eof:
        return "sidecar wheel ZIP member compressed stream is truncated"
    if total != uncompressed_size:
        return "sidecar wheel ZIP member decompressed size drifted"
    return None


def _zip_envelope_errors(
    descriptor: int,
    file_size: int,
    infos: list[object],
) -> list[str]:
    """Reject bytes outside one canonical, comment-free classic ZIP envelope."""
    if file_size < _ZIP_EOCD.size:
        return ["sidecar wheel ZIP container envelope is truncated"]
    eocd_offset = file_size - _ZIP_EOCD.size
    raw = os.pread(descriptor, _ZIP_EOCD.size, eocd_offset)
    if len(raw) != _ZIP_EOCD.size:
        return ["sidecar wheel ZIP container envelope is truncated"]
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = _ZIP_EOCD.unpack(raw)
    if (
        signature != b"PK\x05\x06"
        or comment_size != 0
        or disk_number != 0
        or central_disk != 0
        or disk_entries != total_entries
        or total_entries != len(infos)
        or total_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
        or central_offset + central_size != eocd_offset
    ):
        return [
            "sidecar wheel ZIP container envelope has prefix, suffix, comment, "
            "concatenation, or EOCD drift"
        ]
    expected_offset = 0
    central_position = central_offset
    for item in infos:
        central_header = os.pread(
            descriptor,
            _ZIP_CENTRAL_HEADER.size,
            central_position,
        )
        if len(central_header) != _ZIP_CENTRAL_HEADER.size:
            return ["sidecar wheel ZIP central-directory envelope is truncated"]
        (
            central_signature,
            version_made,
            central_version_needed,
            central_flags,
            central_compression,
            central_mod_time,
            central_mod_date,
            central_crc32,
            central_compressed_size,
            central_uncompressed_size,
            central_name_size,
            central_extra_size,
            central_comment_size,
            disk_start,
            internal_attr,
            external_attr,
            local_offset,
        ) = _ZIP_CENTRAL_HEADER.unpack(central_header)
        central_name = os.pread(
            descriptor,
            central_name_size,
            central_position + _ZIP_CENTRAL_HEADER.size,
        )
        expected_name = item.filename.encode("utf-8")
        if (
            central_signature != b"PK\x01\x02"
            or version_made != (item.create_system << 8) | item.create_version
            or central_version_needed != item.extract_version
            or central_flags != item.flag_bits
            or central_compression != item.compress_type
            or central_crc32 != item.CRC
            or central_compressed_size != item.compress_size
            or central_uncompressed_size != item.file_size
            or central_extra_size != 0
            or central_comment_size != 0
            or disk_start != 0
            or internal_attr != item.internal_attr
            or external_attr != item.external_attr
            or local_offset != item.header_offset
            or central_name != expected_name
        ):
            return ["sidecar wheel ZIP central-directory envelope is not canonical"]
        header_offset = item.header_offset
        if header_offset != expected_offset:
            return [
                "sidecar wheel ZIP container envelope has unreferenced or prefixed bytes"
            ]
        header = os.pread(descriptor, _ZIP_LOCAL_HEADER.size, expected_offset)
        if len(header) != _ZIP_LOCAL_HEADER.size:
            return ["sidecar wheel ZIP local-file envelope is truncated"]
        (
            local_signature,
            version_needed,
            flags,
            compression,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            name_size,
            extra_size,
        ) = _ZIP_LOCAL_HEADER.unpack(header)
        name = os.pread(
            descriptor,
            name_size,
            expected_offset + _ZIP_LOCAL_HEADER.size,
        )
        if (
            local_signature != b"PK\x03\x04"
            or version_needed != central_version_needed
            or flags != 0
            or flags != item.flag_bits
            or compression != item.compress_type
            or mod_time != central_mod_time
            or mod_date != central_mod_date
            or crc32 != item.CRC
            or compressed_size != item.compress_size
            or uncompressed_size != item.file_size
            or extra_size != 0
            or name != expected_name
        ):
            return ["sidecar wheel ZIP local-file envelope is not canonical"]
        payload_offset = expected_offset + _ZIP_LOCAL_HEADER.size + name_size + extra_size
        if compression != 8:
            return ["sidecar wheel ZIP member compression is not canonical DEFLATE"]
        stream_error = _exact_deflate_stream_error(
            descriptor,
            payload_offset,
            compressed_size,
            uncompressed_size,
        )
        if stream_error is not None:
            return [stream_error]
        expected_offset = payload_offset + compressed_size
        central_position += (
            _ZIP_CENTRAL_HEADER.size
            + central_name_size
            + central_extra_size
            + central_comment_size
        )
    return (
        []
        if expected_offset == central_offset and central_position == eocd_offset
        else ["sidecar wheel ZIP container envelope has bytes outside member payloads"]
    )


def _canonical_gzip_payload(
    descriptor: int,
    compressed_size: int,
) -> tuple[tempfile.SpooledTemporaryFile[bytes], int, list[str]]:
    """Fully consume exactly one canonical gzip member into a bounded spool."""
    header = os.pread(descriptor, len(_CANONICAL_GZIP_HEADER), 0)
    if len(header) != len(_CANONICAL_GZIP_HEADER) or header[:3] != b"\x1f\x8b\x08":
        raise ValueError("sidecar sdist gzip envelope header is not canonical")
    envelope_errors = (
        []
        if header == _CANONICAL_GZIP_HEADER
        else ["sidecar sdist gzip envelope header is not canonical"]
    )
    output = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")
    decoder = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    offset = 0
    total = 0
    try:
        while offset < compressed_size:
            chunk = os.pread(descriptor, min(1024 * 1024, compressed_size - offset), offset)
            if not chunk:
                raise ValueError("sidecar sdist gzip envelope is truncated")
            offset += len(chunk)
            pending = chunk
            while pending:
                decoded = decoder.decompress(pending, 1024 * 1024)
                pending = decoder.unconsumed_tail
                total += len(decoded)
                if total > MAXIMUM_UNCOMPRESSED_BYTES:
                    raise ValueError("sidecar sdist exceeds the uncompressed byte limit")
                output.write(decoded)
                if decoder.eof:
                    if decoder.unused_data or pending or offset != compressed_size:
                        raise ValueError(
                            "sidecar sdist gzip envelope has trailing or concatenated data"
                        )
                    break
            if decoder.eof:
                break
        if not decoder.eof or offset != compressed_size:
            raise ValueError("sidecar sdist gzip envelope is truncated or not fully consumed")
        flushed = decoder.flush()
        total += len(flushed)
        if total > MAXIMUM_UNCOMPRESSED_BYTES:
            raise ValueError("sidecar sdist exceeds the uncompressed byte limit")
        output.write(flushed)
        output.seek(0)
        return output, total, envelope_errors
    except zlib.error as exc:
        output.close()
        raise ValueError("sidecar sdist gzip compressed stream is invalid") from exc
    except Exception:
        output.close()
        raise


def _tar_envelope_errors(
    payload: tempfile.SpooledTemporaryFile[bytes],
    payload_size: int,
    members: list[tarfile.TarInfo],
) -> list[str]:
    """Require canonical USTAR headers, zero padding, and one exact end record."""
    expected_offset = 0
    for member in members:
        if member.offset != expected_offset or member.offset_data != expected_offset + 512:
            return ["sidecar sdist tar envelope contains hidden or extended headers"]
        payload.seek(member.offset)
        header = payload.read(512)
        try:
            canonical_header = member.tobuf(
                format=tarfile.USTAR_FORMAT,
                encoding="utf-8",
                errors="strict",
            )
        except (UnicodeError, ValueError) as exc:
            return [f"sidecar sdist tar header is not canonical USTAR: {exc}"]
        if len(canonical_header) != 512 or header != canonical_header:
            return ["sidecar sdist tar header bytes are not canonical USTAR"]
        padded_end = member.offset_data + ((member.size + 511) // 512) * 512
        payload.seek(member.offset_data + member.size)
        padding = payload.read(padded_end - member.offset_data - member.size)
        if padding != b"\0" * len(padding):
            return ["sidecar sdist tar member padding is not canonical"]
        expected_offset = padded_end
    canonical_size = (
        (expected_offset + 2 * 512 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE
    ) * tarfile.RECORDSIZE
    if payload_size != canonical_size:
        return ["sidecar sdist tar envelope length or end records are not canonical"]
    payload.seek(expected_offset)
    trailer = payload.read(payload_size - expected_offset)
    if trailer != b"\0" * len(trailer):
        return ["sidecar sdist tar envelope has trailing or concatenated data"]
    return []
EXPECTED_METADATA = (
    b"Metadata-Version: 2.4\n"
    b"Name: owner-research-futu-sidecar\n"
    b"Version: 1.0.0.dev0\n"
    b"Summary: Private quote-only Futu OpenD sidecar for Owner Equity Research\n"
    b"License-Expression: LicenseRef-Owner-Research-Proprietary\n"
    b"License-File: LICENSE\n"
    b"Requires-Python: <3.14,>=3.11\n"
    b"Requires-Dist: cffi==2.1.1; platform_python_implementation != 'PyPy'\n"
    b"Requires-Dist: cryptography==50.0.0\n"
    b"Requires-Dist: futu-api==10.10.7008\n"
    b"Requires-Dist: numpy==2.4.2; python_version < '3.14'\n"
    b"Requires-Dist: pandas==3.0.5\n"
    b"Requires-Dist: protobuf==7.35.1\n"
    b"Requires-Dist: pycparser==3.0; platform_python_implementation != 'PyPy'\n"
    b"Requires-Dist: pycryptodome==3.23.0\n"
    b"Requires-Dist: python-dateutil==2.9.0.post0\n"
    b"Requires-Dist: simplejson==4.1.1\n"
    b"Requires-Dist: six==1.17.0\n"
    b"Provides-Extra: test\n"
    b"Requires-Dist: attrs==26.1.0; extra == 'test'\n"
    b"Requires-Dist: iniconfig==2.3.0; extra == 'test'\n"
    b"Requires-Dist: jsonschema-specifications==2025.9.1; extra == 'test'\n"
    b"Requires-Dist: jsonschema==4.26.0; extra == 'test'\n"
    b"Requires-Dist: packaging==26.3; extra == 'test'\n"
    b"Requires-Dist: pluggy==1.6.0; extra == 'test'\n"
    b"Requires-Dist: pygments==2.20.0; extra == 'test'\n"
    b"Requires-Dist: pytest==8.4.2; extra == 'test'\n"
    b"Requires-Dist: referencing==0.37.0; extra == 'test'\n"
    b"Requires-Dist: rpds-py==2026.6.3; extra == 'test'\n"
    b"Requires-Dist: ruff==0.12.9; extra == 'test'\n"
    b"Requires-Dist: typing-extensions==4.16.0; extra == 'test'\n"
)


def _safe_relative(value: str) -> PurePosixPath:
    logical = PurePosixPath(value)
    if not value or value.startswith("/") or "\\" in value or ".." in logical.parts:
        raise ValueError(f"unsafe source path: {value!r}")
    return logical


def _read_regular(path: Path, *, label: str) -> tuple[bytes, int]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"{label} is not a regular single-link non-symlink file")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in {0o644, 0o755}:
        raise ValueError(f"{label} has an unauthorized source mode: {mode:o}")
    if metadata.st_size > MAXIMUM_MEMBER_BYTES:
        raise ValueError(f"{label} exceeds the member byte limit")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= MAXIMUM_MEMBER_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAXIMUM_MEMBER_BYTES + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (  # noqa: E731 - compact immutable identity helper
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_mode,
            item.st_nlink,
        )
        if identity(before) != identity(after) or len(raw) != before.st_size:
            raise ValueError(f"{label} changed while being read")
        if len(raw) > MAXIMUM_MEMBER_BYTES:
            raise ValueError(f"{label} exceeds the member byte limit")
        return bytes(raw), mode
    finally:
        os.close(descriptor)


def _resolve_exact_commit(source_root: Path, expected_commit: str) -> tuple[str, str]:
    if len(expected_commit) != 40 or any(
        character not in "0123456789abcdef" for character in expected_commit
    ):
        raise ValueError("expected commit must be a lowercase full SHA-1 object name")
    commit_result = subprocess.run(
        ("git", "-C", str(source_root), "rev-parse", "--verify", f"{expected_commit}^{{commit}}"),
        check=False,
        capture_output=True,
        text=True,
    )
    if commit_result.returncode or commit_result.stdout.strip() != expected_commit:
        raise ValueError("expected commit is unavailable from the trusted repository")
    tree_result = subprocess.run(
        ("git", "-C", str(source_root), "rev-parse", "--verify", f"{expected_commit}^{{tree}}"),
        check=False,
        capture_output=True,
        text=True,
    )
    tree = tree_result.stdout.strip()
    if tree_result.returncode or len(tree) != 40:
        raise ValueError("expected commit tree is unavailable from the trusted repository")
    return expected_commit, tree


def source_identity(source_root: Path, expected_commit: str) -> tuple[str, str]:
    """Return the verified full commit and root tree object identities."""

    return _resolve_exact_commit(source_root, expected_commit)


def _git_blob(source_root: Path, commit: str, relative: str) -> bytes:
    _safe_relative(relative)
    result = subprocess.run(
        ("git", "-C", str(source_root), "show", f"{commit}:{relative}"),
        check=False,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError(f"trusted source blob is unavailable: {relative}")
    if len(result.stdout) > MAXIMUM_MEMBER_BYTES:
        raise ValueError(f"trusted source blob exceeds the member byte limit: {relative}")
    return result.stdout


def _git_100644_blob(source_root: Path, commit: str, relative: str) -> bytes:
    """Read one exact trusted metadata blob only when its Git mode is canonical."""

    _safe_relative(relative)
    result = subprocess.run(
        ("git", "-C", str(source_root), "ls-tree", "-z", commit, "--", relative),
        check=False,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError(f"trusted sidecar metadata could not be enumerated: {relative}")
    records = tuple(record for record in result.stdout.split(b"\0") if record)
    try:
        identity, path_raw = records[0].split(b"\t", 1)
        mode, object_type, _object_id = identity.decode("ascii").split(" ", 2)
        observed_path = path_raw.decode("utf-8")
    except (IndexError, UnicodeError, ValueError) as exc:
        raise ValueError(f"trusted sidecar metadata tree record is malformed: {relative}") from exc
    if (
        len(records) != 1
        or observed_path != relative
        or mode != "100644"
        or object_type != "blob"
    ):
        raise ValueError(f"trusted sidecar metadata is not a 100644 regular blob: {relative}")
    return _git_blob(source_root, commit, relative)


def _git_directory(
    source_root: Path,
    commit: str,
    relative: str,
) -> dict[str, tuple[bytes, int]]:
    _safe_relative(relative)
    result = subprocess.run(
        ("git", "-C", str(source_root), "ls-tree", "-r", "-z", commit, "--", relative),
        check=False,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError(f"trusted source tree could not be enumerated: {relative}")
    projection: dict[str, tuple[bytes, int]] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        identity, path_raw = record.split(b"\t", 1)
        mode_raw, kind, _object_id = identity.decode("ascii").split(" ", 2)
        path = path_raw.decode("utf-8")
        logical = _safe_relative(path)
        if any(part in IGNORED_PARTS for part in logical.parts) or logical.suffix in {
            ".pyc",
            ".pyo",
        }:
            continue
        if kind != "blob" or mode_raw not in {"100644", "100755"}:
            raise ValueError(f"trusted source member is not a regular release blob: {path}")
        projection[path] = (
            _git_blob(source_root, commit, path),
            0o755 if mode_raw == "100755" else 0o644,
        )
    return projection


def _filesystem_directory(root: Path, relative: str) -> dict[str, tuple[bytes, int]]:
    start = root.joinpath(*PurePosixPath(relative).parts)
    metadata = start.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"trusted source directory is unsafe: {relative}")
    projection: dict[str, tuple[bytes, int]] = {}
    for current, directories, filenames in os.walk(start, followlinks=False):
        current_path = Path(current)
        kept_directories: list[str] = []
        for directory in directories:
            child = current_path / directory
            child_relative = child.relative_to(root).as_posix()
            if directory in IGNORED_PARTS:
                continue
            child_metadata = child.lstat()
            if not stat.S_ISDIR(child_metadata.st_mode) or stat.S_ISLNK(child_metadata.st_mode):
                raise ValueError(f"trusted source directory is unsafe: {child_relative}")
            kept_directories.append(directory)
        directories[:] = kept_directories
        for filename in filenames:
            path = current_path / filename
            logical = PurePosixPath(path.relative_to(root).as_posix())
            if logical.suffix in {".pyc", ".pyo"} or filename == ".DS_Store":
                continue
            raw, mode = _read_regular(path, label=f"trusted sidecar source {logical}")
            projection[logical.as_posix()] = (raw, mode)
    return projection


def _source_projection(
    source_root: Path,
    *,
    expected_commit: str | None,
) -> tuple[dict[str, tuple[bytes, int]], bytes, str | None]:
    sidecar_prefix = SIDECAR_RELATIVE.as_posix()
    projection: dict[str, tuple[bytes, int]] = {}
    tree: str | None = None
    if expected_commit is None:
        sidecar = source_root.joinpath(*SIDECAR_RELATIVE.parts)
        for directory in SOURCE_DIRECTORIES:
            projection.update(_filesystem_directory(sidecar, directory))
        pyproject_raw, pyproject_mode = _read_regular(
            sidecar / "pyproject.toml", label="trusted sidecar pyproject"
        )
        license_raw, license_mode = _read_regular(
            sidecar / "LICENSE", label="trusted sidecar project license"
        )
        gitignore_raw, gitignore_mode = _read_regular(
            source_root / ".gitignore", label="trusted repository .gitignore"
        )
    else:
        commit, tree = _resolve_exact_commit(source_root, expected_commit)
        for directory in SOURCE_DIRECTORIES:
            full = f"{sidecar_prefix}/{directory}"
            for path, value in _git_directory(source_root, commit, full).items():
                projection[path.removeprefix(sidecar_prefix + "/")] = value
        pyproject_path = f"{sidecar_prefix}/pyproject.toml"
        pyproject_raw = _git_100644_blob(source_root, commit, pyproject_path)
        pyproject_mode = 0o644
        license_raw = _git_100644_blob(source_root, commit, f"{sidecar_prefix}/LICENSE")
        license_mode = 0o644
        gitignore_raw = _git_100644_blob(source_root, commit, ".gitignore")
        gitignore_mode = 0o644
    projection["pyproject.toml"] = (pyproject_raw, pyproject_mode)
    projection["LICENSE"] = (license_raw, license_mode)
    projection[".gitignore"] = (gitignore_raw, gitignore_mode)
    if not projection or len(projection) > MAXIMUM_MEMBERS:
        raise ValueError("trusted sidecar source member count is invalid")
    if sum(len(raw) for raw, _mode in projection.values()) > MAXIMUM_UNCOMPRESSED_BYTES:
        raise ValueError("trusted sidecar source exceeds the cumulative byte limit")
    _validate_pyproject(pyproject_raw)
    return projection, pyproject_raw, tree


def _validate_sdist_commit_regular_blobs(
    source_root: Path,
    expected_commit: str,
    source_projection: dict[str, tuple[bytes, int]],
) -> None:
    """Bind each sidecar sdist path to its exact trusted regular-blob mode."""

    sidecar_prefix = SIDECAR_RELATIVE.as_posix()
    expected_modes: dict[str, str] = {}
    for relative, (_raw, mode) in source_projection.items():
        logical = _safe_relative(relative)
        repository_path = (
            ".gitignore"
            if relative == ".gitignore"
            else f"{sidecar_prefix}/{logical.as_posix()}"
        )
        if mode not in {0o644, 0o755}:
            raise ValueError(
                f"trusted sidecar sdist projection mode is not closed: {relative}"
            )
        expected_modes[repository_path] = "100755" if mode == 0o755 else "100644"
    if not expected_modes:
        raise ValueError("trusted sidecar sdist commit projection is empty")
    result = subprocess.run(
        (
            "git",
            "-C",
            str(source_root),
            "ls-tree",
            "-r",
            "-z",
            expected_commit,
            "--",
            *sorted(expected_modes),
        ),
        check=False,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError("trusted sidecar sdist commit entries could not be enumerated")
    entries: dict[str, tuple[str, str]] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            identity, path_raw = record.split(b"\t", 1)
            mode, object_type, _object_id = identity.decode("ascii").split(" ", 2)
            relative = path_raw.decode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise ValueError("trusted sidecar sdist commit tree record is malformed") from exc
        if relative in entries:
            raise ValueError(f"trusted sidecar sdist commit tree entry is duplicated: {relative}")
        entries[relative] = (mode, object_type)
    if set(entries) != set(expected_modes):
        raise ValueError("trusted sidecar sdist commit entry inventory is incomplete or open")
    for relative, (mode, object_type) in entries.items():
        expected_mode = expected_modes[relative]
        if mode != expected_mode or object_type != "blob":
            raise ValueError(
                "trusted sidecar sdist commit source does not match its expected "
                f"{expected_mode} regular blob mode: {relative}"
            )


def _validate_pyproject(raw: bytes) -> None:
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"sidecar pyproject is invalid TOML: {exc}") from exc
    project = document.get("project")
    build = document.get("build-system")
    hatch = document.get("tool", {}).get("hatch", {}).get("build", {}).get("targets", {})
    if not isinstance(project, dict) or not isinstance(build, dict) or not isinstance(hatch, dict):
        raise ValueError("sidecar pyproject release tables are missing")
    if (
        project.get("name") != PROJECT_NAME
        or project.get("version") != PROJECT_VERSION
        or project.get("description")
        != "Private quote-only Futu OpenD sidecar for Owner Equity Research"
        or project.get("requires-python") != ">=3.11,<3.14"
        or project.get("license") != PROJECT_LICENSE_EXPRESSION
        or project.get("dependencies") != EXPECTED_DEPENDENCIES
        or project.get("optional-dependencies") != {"test": EXPECTED_TEST_DEPENDENCIES}
        or project.get("scripts") != EXPECTED_SCRIPTS
    ):
        raise ValueError("sidecar project metadata, dependencies, or entry points drifted")
    if build != {
        "requires": ["hatchling==1.27.0"],
        "build-backend": "hatchling.build",
    }:
        raise ValueError("sidecar build backend is not the pinned Hatchling release")
    wheel = hatch.get("wheel")
    sdist = hatch.get("sdist")
    if (
        not isinstance(wheel, dict)
        or wheel.get("packages") != ["src/owner_research_futu_sidecar"]
        or wheel.get("force-include")
        != {
            "resources": "owner_research_futu_sidecar/resources",
            "wire": "owner_research_futu_sidecar/wire",
            "supply": "owner_research_futu_sidecar/supply",
            "launcher": "owner_research_futu_sidecar/launcher",
            "pyproject.toml": "owner_research_futu_sidecar/supply/source-pyproject.toml",
        }
        or not isinstance(sdist, dict)
        or sdist.get("include")
        != [
            "LICENSE",
            "launcher",
            "pyproject.toml",
            "resources",
            "src",
            "supply",
            "tests",
            "wire",
        ]
    ):
        raise ValueError("sidecar wheel or sdist source projection drifted")


def _wheel_projection(
    source_projection: dict[str, tuple[bytes, int]],
) -> dict[str, tuple[bytes, int]]:
    projection: dict[str, tuple[bytes, int]] = {}
    for source_name, value in source_projection.items():
        if source_name == "pyproject.toml":
            projection[f"{PACKAGE}/supply/source-pyproject.toml"] = value
        elif source_name == "LICENSE":
            projection[f"{DIST_INFO}/licenses/LICENSE"] = value
        elif source_name == ".gitignore" or source_name.startswith("tests/"):
            continue
        elif source_name.startswith("src/owner_research_futu_sidecar/"):
            projection[source_name.removeprefix("src/")] = value
        elif source_name.startswith(tuple(f"{item}/" for item in WHEEL_SOURCE_DIRECTORIES)):
            projection[f"{PACKAGE}/{source_name}"] = value
    return projection


def _record_bytes(member_bytes: dict[str, bytes], ordered_names: list[str]) -> bytes:
    record_name = f"{DIST_INFO}/RECORD"
    lines: list[str] = []
    for name in ordered_names:
        if name == record_name:
            lines.append(f"{name},,")
            continue
        raw = member_bytes[name]
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        lines.append(f"{name},sha256={digest},{len(raw)}")
    return ("\n".join(lines) + "\n").encode()


def _wheel_source_order(
    source: dict[str, tuple[bytes, int]],
    projection: dict[str, tuple[bytes, int]],
) -> list[str]:
    package_members = sorted(
        name.removeprefix("src/")
        for name in source
        if name.startswith("src/owner_research_futu_sidecar/")
    )
    pyproject_member = f"{PACKAGE}/supply/source-pyproject.toml"
    license_member = f"{DIST_INFO}/licenses/LICENSE"
    forced_members = sorted(
        name
        for name in projection
        if name not in {*package_members, pyproject_member, license_member}
    )
    return [*package_members, *forced_members, pyproject_member]


def verify_wheel(
    wheel: Path,
    *,
    source_root: Path = ROOT,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
) -> tuple[str, ...]:
    errors: list[str] = []
    try:
        source, _pyproject, tree = _source_projection(
            source_root, expected_commit=expected_commit
        )
        if expected_tree is not None and tree != expected_tree:
            raise ValueError("trusted sidecar commit tree does not match expected tree")
        projection = _wheel_projection(source)
        metadata_name = f"{DIST_INFO}/METADATA"
        wheel_name = f"{DIST_INFO}/WHEEL"
        entry_points_name = f"{DIST_INFO}/entry_points.txt"
        license_name = f"{DIST_INFO}/licenses/LICENSE"
        record_name = f"{DIST_INFO}/RECORD"
        expected_order = [
            *_wheel_source_order(source, projection),
            metadata_name,
            wheel_name,
            entry_points_name,
            license_name,
            record_name,
        ]
        expected_names = set(expected_order)
        path_metadata = wheel.lstat()
        if not stat.S_ISREG(path_metadata.st_mode) or path_metadata.st_nlink != 1:
            return ("sidecar wheel is not a regular single-link non-symlink file",)
        if path_metadata.st_size > MAXIMUM_ARCHIVE_BYTES:
            return ("sidecar wheel exceeds the archive byte limit",)
        descriptor = os.open(wheel, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            with os.fdopen(descriptor, "rb", closefd=False) as handle, ZipFile(handle) as archive:
                infos = archive.infolist()
                errors.extend(_zip_envelope_errors(descriptor, before.st_size, infos))
                ordered_names = [item.filename for item in infos]
                names = set(ordered_names)
                if len(infos) > MAXIMUM_MEMBERS:
                    errors.append("sidecar wheel exceeds the member-count limit")
                if len(names) != len(ordered_names):
                    errors.append("sidecar wheel contains duplicate members")
                if ordered_names != expected_order or names != expected_names:
                    errors.append("sidecar wheel inventory or order is not the exact trusted build")
                if archive.comment:
                    errors.append("sidecar wheel archive comment is forbidden")
                total = 0
                member_bytes: dict[str, bytes] = {}
                for item in infos:
                    total += item.file_size
                    logical = PurePosixPath(item.filename)
                    source_value = projection.get(item.filename)
                    expected_mode = (
                        0o644
                        if item.filename == license_name
                        else source_value[1] | stat.S_IFREG
                        if source_value is not None
                        else 0o644
                    )
                    mode = item.external_attr >> 16
                    if (
                        not item.filename
                        or item.filename.startswith("/")
                        or "\\" in item.filename
                        or ".." in logical.parts
                        or item.is_dir()
                        or item.file_size > MAXIMUM_MEMBER_BYTES
                        or item.compress_size > MAXIMUM_MEMBER_BYTES
                        or item.create_system != 3
                        or mode != expected_mode
                        or item.date_time != FIXED_ZIP_TIME
                        or item.compress_type != 8
                        or item.flag_bits != 0
                        or item.extra
                        or item.comment
                    ):
                        errors.append(
                            "sidecar wheel member metadata is unsafe or drifted: "
                            f"{item.filename}"
                        )
                    if item.file_size <= MAXIMUM_MEMBER_BYTES:
                        member_bytes[item.filename] = archive.read(item)
                if total > MAXIMUM_UNCOMPRESSED_BYTES:
                    errors.append("sidecar wheel exceeds the cumulative uncompressed byte limit")
                if total <= MAXIMUM_UNCOMPRESSED_BYTES and archive.testzip() is not None:
                    errors.append("sidecar wheel CRC verification failed")
                for name, (trusted_raw, _mode) in projection.items():
                    actual = member_bytes.get(name)
                    if actual is not None and actual != trusted_raw:
                        errors.append(
                            f"sidecar wheel member differs from trusted source bytes: {name}"
                        )
                if member_bytes.get(metadata_name) != EXPECTED_METADATA:
                    errors.append("sidecar wheel METADATA is not the exact trusted metadata")
                if member_bytes.get(wheel_name) != EXPECTED_WHEEL:
                    errors.append("sidecar wheel WHEEL identity is not the exact trusted build")
                if member_bytes.get(entry_points_name) != EXPECTED_ENTRY_POINTS:
                    errors.append("sidecar wheel entry points are not the exact closed interface")
                if names == expected_names and len(names) == len(ordered_names):
                    expected_record = _record_bytes(member_bytes, ordered_names)
                    if member_bytes.get(record_name) != expected_record:
                        errors.append(
                            "sidecar wheel RECORD hashes, sizes, order, or members drifted"
                        )
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                errors.append("sidecar wheel changed while being verified")
        finally:
            os.close(descriptor)
    except (BadZipFile, KeyError, OSError, UnicodeError, ValueError) as exc:
        errors.append(f"sidecar wheel could not be verified: {exc}")
    return tuple(errors)


def _sdist_order(source: dict[str, tuple[bytes, int]]) -> list[str]:
    included = sorted(
        name for name in source if name not in {".gitignore", "LICENSE", "pyproject.toml"}
    )
    return [
        *(SDIST_PREFIX + name for name in included),
        SDIST_PREFIX + ".gitignore",
        SDIST_PREFIX + "LICENSE",
        SDIST_PREFIX + "pyproject.toml",
        SDIST_PREFIX + "PKG-INFO",
    ]


def verify_sdist(
    sdist: Path,
    *,
    source_root: Path = ROOT,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
) -> tuple[str, ...]:
    errors: list[str] = []
    try:
        source, _pyproject, tree = _source_projection(
            source_root, expected_commit=expected_commit
        )
        if expected_commit is not None:
            _validate_sdist_commit_regular_blobs(
                source_root,
                expected_commit,
                source,
            )
        if expected_tree is not None and tree != expected_tree:
            raise ValueError("trusted sidecar commit tree does not match expected tree")
        expected_order = _sdist_order(source)
        expected_names = set(expected_order)
        expected: dict[str, tuple[bytes, int]] = {
            SDIST_PREFIX + name: value for name, value in source.items()
        }
        expected[SDIST_PREFIX + "PKG-INFO"] = (EXPECTED_METADATA, 0o644)
        path_metadata = sdist.lstat()
        if not stat.S_ISREG(path_metadata.st_mode) or path_metadata.st_nlink != 1:
            return ("sidecar sdist is not a regular single-link non-symlink file",)
        if path_metadata.st_size > MAXIMUM_ARCHIVE_BYTES:
            return ("sidecar sdist exceeds the archive byte limit",)
        descriptor = os.open(sdist, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            payload, payload_size, gzip_errors = _canonical_gzip_payload(
                descriptor, before.st_size
            )
            errors.extend(gzip_errors)
            with payload, tarfile.open(fileobj=payload, mode="r:") as archive:
                members = archive.getmembers()
                errors.extend(_tar_envelope_errors(payload, payload_size, members))
                ordered_names = [member.name for member in members]
                names = set(ordered_names)
                if len(members) > MAXIMUM_MEMBERS:
                    errors.append("sidecar sdist exceeds the member-count limit")
                if len(names) != len(ordered_names):
                    errors.append("sidecar sdist contains duplicate members")
                if ordered_names != expected_order or names != expected_names:
                    errors.append("sidecar sdist inventory or order is not the exact trusted build")
                total = 0
                for member in members:
                    total += member.size
                    logical = PurePosixPath(member.name)
                    trusted = expected.get(member.name)
                    expected_mode = trusted[1] if trusted is not None else 0o644
                    if (
                        not member.name
                        or member.name.startswith("/")
                        or "\\" in member.name
                        or ".." in logical.parts
                        or not member.name.startswith(SDIST_PREFIX)
                        or not member.isreg()
                        or member.type != tarfile.REGTYPE
                        or member.islnk()
                        or member.issym()
                        or member.devmajor != 0
                        or member.devminor != 0
                        or member.size > MAXIMUM_MEMBER_BYTES
                        or member.mode != expected_mode
                        or member.uid != 0
                        or member.gid != 0
                        or member.uname
                        or member.gname
                        or member.mtime != FIXED_TAR_TIME
                        or member.linkname
                        or member.pax_headers
                    ):
                        errors.append(
                            "sidecar sdist member metadata is unsafe or drifted: "
                            f"{member.name}"
                        )
                        continue
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        errors.append(f"sidecar sdist member cannot be read: {member.name}")
                        continue
                    raw = extracted.read(MAXIMUM_MEMBER_BYTES + 1)
                    if len(raw) != member.size or len(raw) > MAXIMUM_MEMBER_BYTES:
                        errors.append(f"sidecar sdist member size drifted: {member.name}")
                    elif trusted is not None and raw != trusted[0]:
                        if member.name.endswith("/PKG-INFO"):
                            errors.append(
                                "sidecar sdist PKG-INFO is not the exact trusted metadata"
                            )
                        else:
                            errors.append(
                                "sidecar sdist member differs from trusted source bytes: "
                                f"{member.name}"
                            )
                if total > MAXIMUM_UNCOMPRESSED_BYTES:
                    errors.append("sidecar sdist exceeds the cumulative uncompressed byte limit")
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                errors.append("sidecar sdist changed while being verified")
        finally:
            os.close(descriptor)
    except (KeyError, OSError, tarfile.TarError, UnicodeError, ValueError) as exc:
        errors.append(f"sidecar sdist could not be verified: {exc}")
    return tuple(errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("wheel", "sdist"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("artifact", type=Path)
        command_parser.add_argument("--source-root", type=Path, default=ROOT)
        command_parser.add_argument("--expected-commit")
        command_parser.add_argument("--expected-tree")
    args = parser.parse_args()
    verifier = verify_wheel if args.command == "wheel" else verify_sdist
    errors = verifier(
        args.artifact,
        source_root=args.source_root,
        expected_commit=args.expected_commit,
        expected_tree=args.expected_tree,
    )
    for error in errors:
        print(error)
    if errors:
        return 1
    binding = f" at commit {args.expected_commit}" if args.expected_commit else ""
    print(f"sidecar {args.command} verification passed{binding}: {args.artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
