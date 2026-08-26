#!/usr/bin/env python3
"""Verify the closed source distribution against a trusted source projection."""

from __future__ import annotations

import argparse
import os
import runpy
import stat
import subprocess
import tarfile
import tempfile
import zlib
from pathlib import Path, PurePosixPath

_WHEEL_VERIFIER = runpy.run_path(str(Path(__file__).with_name("verify_wheel.py")))
DIST_INFO_STEM = _WHEEL_VERIFIER["DIST_INFO_STEM"]
MAXIMUM_SOURCE_MEMBER_BYTES = _WHEEL_VERIFIER["MAXIMUM_SOURCE_MEMBER_BYTES"]
MAXIMUM_SOURCE_PROJECTION_BYTES = _WHEEL_VERIFIER["MAXIMUM_SOURCE_PROJECTION_BYTES"]
ROOT = _WHEEL_VERIFIER["ROOT"]
_release_content_errors = _WHEEL_VERIFIER["_release_content_errors"]
_source_projection = _WHEEL_VERIFIER["_source_projection"]
_trusted_file = _WHEEL_VERIFIER["_trusted_file"]

SDIST_STEM = DIST_INFO_STEM.removesuffix(".dist-info")
SDIST_PREFIX = f"{SDIST_STEM}/"
DEFAULT_SOURCE_DATE_EPOCH = 1_580_601_600
# Hatchling 1.27.0 normalizes each emitted sdist data member to 0644. Locking the
# build backend's exact output rejects every additional write bit and every special bit.
HATCH_SDIST_REGULAR_MODE = 0o644
_DEFERRED_SDIST_NAMES = (".gitignore", "README.md", "pyproject.toml")
_USTAR_NAME_BYTES = 100
_SDIST_SUPPLY_MEMBERS = (
    "scripts/phase5-v1-release-dependency-lock.json",
    "scripts/phase5-v1-release-supply-identity.json",
    "scripts/phase5-v1-release-supply-manifest.json",
    "scripts/phase5-v1-reviewed-artifact-metadata.json",
    "scripts/phase5_v1_dependency_lock.py",
)


def _canonical_gzip_payload(
    descriptor: int,
    compressed_size: int,
    *,
    expected_epoch: int,
) -> tuple[tempfile.SpooledTemporaryFile[bytes], int, tuple[str, ...]]:
    """Fully consume exactly one canonical gzip member into a bounded spool."""

    expected_header = (
        b"\x1f\x8b\x08\x00"
        + expected_epoch.to_bytes(4, "little", signed=False)
        + b"\x02\xff"
    )
    header = os.pread(descriptor, len(expected_header), 0)
    if len(header) != len(expected_header) or header[:3] != b"\x1f\x8b\x08":
        raise ValueError("sdist gzip envelope header is invalid")
    envelope_errors = (
        ()
        if header == expected_header
        else ("sdist gzip envelope header is not the exact trusted build header",)
    )
    output = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")
    decoder = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    offset = 0
    total = 0
    try:
        while offset < compressed_size:
            chunk = os.pread(descriptor, min(1024 * 1024, compressed_size - offset), offset)
            if not chunk:
                raise ValueError("sdist gzip envelope is truncated")
            offset += len(chunk)
            pending = chunk
            while pending:
                decoded = decoder.decompress(pending, 1024 * 1024)
                pending = decoder.unconsumed_tail
                total += len(decoded)
                if total > MAXIMUM_SOURCE_PROJECTION_BYTES:
                    raise ValueError("sdist exceeds the cumulative uncompressed byte limit")
                output.write(decoded)
                if decoder.eof:
                    if decoder.unused_data or pending or offset != compressed_size:
                        raise ValueError(
                            "sdist gzip envelope has trailing or concatenated data"
                        )
                    break
            if decoder.eof:
                break
        if not decoder.eof or offset != compressed_size:
            raise ValueError("sdist gzip envelope is truncated or not fully consumed")
        flushed = decoder.flush()
        total += len(flushed)
        if total > MAXIMUM_SOURCE_PROJECTION_BYTES:
            raise ValueError("sdist exceeds the cumulative uncompressed byte limit")
        output.write(flushed)
        output.seek(0)
        return output, total, envelope_errors
    except zlib.error as exc:
        output.close()
        raise ValueError("sdist gzip compressed stream is invalid") from exc
    except Exception:
        output.close()
        raise


def _tar_envelope_errors(
    payload: tempfile.SpooledTemporaryFile[bytes],
    payload_size: int,
    members: list[tarfile.TarInfo],
) -> tuple[str, ...]:
    """Require exact PAX headers, zero padding, and one canonical end region."""

    expected_offset = 0
    for member in members:
        if member.offset != expected_offset:
            return ("sdist tar envelope contains hidden or unparsed headers",)
        payload.seek(member.offset)
        header_span = payload.read(member.offset_data - member.offset)
        try:
            canonical_header = member.tobuf(
                format=tarfile.PAX_FORMAT,
                encoding="utf-8",
                errors="strict",
            )
        except (UnicodeError, ValueError) as exc:
            return (f"sdist tar header is not canonical PAX: {exc}",)
        if header_span != canonical_header:
            return ("sdist tar header bytes are not canonical PAX",)
        padded_end = member.offset_data + ((member.size + 511) // 512) * 512
        payload.seek(member.offset_data + member.size)
        padding = payload.read(padded_end - member.offset_data - member.size)
        if padding != b"\0" * len(padding):
            return ("sdist tar member padding is not canonical",)
        expected_offset = padded_end
    canonical_size = (
        (expected_offset + 2 * 512 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE
    ) * tarfile.RECORDSIZE
    if payload_size != canonical_size:
        return ("sdist tar envelope length or end records are not canonical",)
    payload.seek(expected_offset)
    trailer = payload.read(payload_size - expected_offset)
    if trailer != b"\0" * len(trailer):
        return ("sdist tar envelope has trailing or concatenated data",)
    return ()


def _source_name(wheel_name: str) -> str:
    if wheel_name == "owner_research/component-lock.json":
        return "component-lock.json"
    mappings = (
        (
            "owner_research/resources/futu/market-authority-policy-v2.json",
            "scripts/phase5e-futu-market-authority-policy-v2.json",
        ),
        (
            "owner_research/report_assets/",
            "plugins/owner-equity-research/skills/owner-equity-research/assets/",
        ),
        ("owner_research/extension_schemas/", "extension_schemas/"),
        ("owner_research/schemas/", "schemas/"),
        ("owner_research/", "src/owner_research/"),
    )
    for wheel_prefix, source_prefix in mappings:
        if wheel_name.startswith(wheel_prefix):
            return source_prefix + wheel_name.removeprefix(wheel_prefix)
    raise ValueError(f"wheel projection cannot map back to source: {wheel_name}")


def _validate_exact_commit_regular_blobs(
    source_root: Path,
    expected_commit: str,
    relative_paths: set[str],
) -> None:
    """Bind every sdist source byte to an exact 100644 blob tree entry."""

    if not relative_paths:
        raise ValueError("trusted sdist commit projection is empty")
    for relative in relative_paths:
        logical = PurePosixPath(relative)
        if (
            not relative
            or relative.startswith("/")
            or "\\" in relative
            or ".." in logical.parts
        ):
            raise ValueError(f"trusted sdist commit path is unsafe: {relative!r}")
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
            *sorted(relative_paths),
        ),
        check=False,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError("trusted sdist commit tree entries could not be enumerated")
    entries: dict[str, tuple[str, str]] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            identity, path_raw = record.split(b"\t", 1)
            mode, object_type, _object_id = identity.decode("ascii").split(" ", 2)
            relative = path_raw.decode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise ValueError("trusted sdist commit tree record is malformed") from exc
        if relative in entries:
            raise ValueError(f"trusted sdist commit tree entry is duplicated: {relative}")
        entries[relative] = (mode, object_type)
    if set(entries) != relative_paths:
        raise ValueError("trusted sdist commit tree entry inventory is incomplete or open")
    for relative, (mode, object_type) in entries.items():
        if mode != "100644" or object_type != "blob":
            raise ValueError(
                "trusted sdist commit source is not a 100644 regular blob: " f"{relative}"
            )


def _expected_projection(
    source_root: Path, *, expected_commit: str | None
) -> tuple[dict[str, bytes], dict[str, bytes], bytes]:
    wheel_projection, metadata, pyproject_raw = _source_projection(
        source_root, expected_commit=expected_commit
    )
    source_projection = {_source_name(name): raw for name, raw in wheel_projection.items()}
    if len(source_projection) != len(wheel_projection):
        raise ValueError("sdist source projection mapping is ambiguous")
    source_projection["pyproject.toml"] = pyproject_raw
    source_projection["README.md"] = _trusted_file(
        source_root, "README.md", expected_commit=expected_commit
    )
    source_projection[".gitignore"] = _trusted_file(
        source_root, ".gitignore", expected_commit=expected_commit
    )
    for relative in _SDIST_SUPPLY_MEMBERS:
        source_projection[relative] = _trusted_file(
            source_root, relative, expected_commit=expected_commit
        )
    if expected_commit is not None:
        _validate_exact_commit_regular_blobs(
            source_root,
            expected_commit,
            set(source_projection),
        )
    if sum(map(len, source_projection.values())) > MAXIMUM_SOURCE_PROJECTION_BYTES:
        raise ValueError("sdist source projection exceeds the cumulative byte limit")
    return source_projection, wheel_projection, metadata


def _source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        return DEFAULT_SOURCE_DATE_EPOCH
    if not raw.isascii() or not raw.isdecimal() or str(int(raw)) != raw:
        raise ValueError("SOURCE_DATE_EPOCH must be a canonical non-negative integer")
    epoch = int(raw)
    if epoch != DEFAULT_SOURCE_DATE_EPOCH:
        raise ValueError(
            "SOURCE_DATE_EPOCH conflicts with the fixed trusted sdist build timestamp"
        )
    return DEFAULT_SOURCE_DATE_EPOCH


def _walk_sdist_names(names: set[str], *, prefix: str = "") -> list[str]:
    """Reproduce Hatchling's stable files-first walk without consulting the filesystem."""

    direct_files = sorted(name for name in names if "/" not in name)
    directories = sorted({name.split("/", 1)[0] for name in names if "/" in name})
    ordered = [prefix + name for name in direct_files]
    for directory in directories:
        children = {
            name.split("/", 1)[1] for name in names if name.startswith(f"{directory}/")
        }
        ordered.extend(_walk_sdist_names(children, prefix=f"{prefix}{directory}/"))
    return ordered


def _sdist_order(projection: dict[str, bytes]) -> list[str]:
    deferred = set(_DEFERRED_SDIST_NAMES)
    if not deferred.issubset(projection):
        raise ValueError("sdist deferred source members are incomplete")
    included = set(projection).difference(deferred)
    return [
        *(SDIST_PREFIX + name for name in _walk_sdist_names(included)),
        *(SDIST_PREFIX + name for name in _DEFERRED_SDIST_NAMES),
        SDIST_PREFIX + "PKG-INFO",
    ]


def _expected_pax_headers(member_name: str) -> dict[str, str]:
    if len(member_name.encode("utf-8")) > _USTAR_NAME_BYTES:
        return {"path": member_name}
    return {}


def verify(
    sdist: Path,
    *,
    source_root: Path | None = None,
    expected_commit: str | None = None,
) -> tuple[str, ...]:
    errors: list[str] = []
    try:
        trusted_root = source_root if source_root is not None else ROOT
        projection, wheel_projection, expected_metadata = _expected_projection(
            trusted_root, expected_commit=expected_commit
        )
        errors.extend(_release_content_errors(wheel_projection))
        errors.extend(_release_content_errors(projection))
        expected = {f"{SDIST_PREFIX}{name}": raw for name, raw in projection.items()}
        metadata_name = f"{SDIST_PREFIX}PKG-INFO"
        expected[metadata_name] = expected_metadata
        expected_order = _sdist_order(projection)
        expected_epoch = _source_date_epoch()

        path_metadata = sdist.lstat()
        if not stat.S_ISREG(path_metadata.st_mode) or path_metadata.st_nlink != 1:
            return ("sdist path is not a regular single-link non-symlink file",)
        if path_metadata.st_size > MAXIMUM_SOURCE_PROJECTION_BYTES:
            return ("sdist exceeds the cumulative release byte limit",)
        descriptor = os.open(sdist, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            payload, payload_size, gzip_errors = _canonical_gzip_payload(
                descriptor,
                before.st_size,
                expected_epoch=expected_epoch,
            )
            errors.extend(gzip_errors)
            with payload, tarfile.open(fileobj=payload, mode="r:") as archive:
                members = archive.getmembers()
                errors.extend(_tar_envelope_errors(payload, payload_size, members))
                ordered_names = [member.name for member in members]
                names = set(ordered_names)
                if len(ordered_names) != len(names):
                    errors.append("sdist contains duplicate archive members")
                if ordered_names != expected_order:
                    errors.append("sdist member order is not the exact trusted build order")
                total = 0
                actual: dict[str, bytes] = {}
                for member in members:
                    logical = PurePosixPath(member.name)
                    if (
                        not member.name
                        or member.name.startswith("/")
                        or "\\" in member.name
                        or ".." in logical.parts
                        or not member.name.startswith(SDIST_PREFIX)
                        or member.type != tarfile.REGTYPE
                        or not member.isreg()
                        or member.islnk()
                        or member.issym()
                        or member.size > MAXIMUM_SOURCE_MEMBER_BYTES
                    ):
                        errors.append(f"sdist contains an unsafe member: {member.name!r}")
                        continue
                    if (
                        member.mode != HATCH_SDIST_REGULAR_MODE
                        or member.uid != 0
                        or member.gid != 0
                        or member.uname
                        or member.gname
                        or member.mtime != expected_epoch
                        or member.linkname
                        or member.devmajor != 0
                        or member.devminor != 0
                        or member.pax_headers != _expected_pax_headers(member.name)
                    ):
                        errors.append(
                            "sdist member metadata is unsafe or drifted: " f"{member.name}"
                        )
                        continue
                    total += member.size
                    if total > MAXIMUM_SOURCE_PROJECTION_BYTES:
                        errors.append("sdist exceeds the cumulative uncompressed byte limit")
                        continue
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        errors.append(f"sdist member cannot be read: {member.name}")
                        continue
                    raw = extracted.read(MAXIMUM_SOURCE_MEMBER_BYTES + 1)
                    if len(raw) != member.size or len(raw) > MAXIMUM_SOURCE_MEMBER_BYTES:
                        errors.append(f"sdist member size drifted: {member.name}")
                        continue
                    actual[member.name] = raw
                if names != set(expected):
                    errors.append("sdist member inventory is not the exact trusted projection")
                for name, trusted_raw in expected.items():
                    archive_raw = actual.get(name)
                    if archive_raw is not None and archive_raw != trusted_raw:
                        if name == metadata_name:
                            errors.append(
                                "sdist PKG-INFO is not the exact trusted project metadata"
                            )
                        else:
                            errors.append(f"sdist member differs from trusted source bytes: {name}")
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
                errors.append("sdist changed while being verified")
        finally:
            os.close(descriptor)
    except (KeyError, OSError, tarfile.TarError, UnicodeError, ValueError) as exc:
        errors.append(f"sdist could not be verified: {exc}")
    return tuple(errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sdist", type=Path)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--expected-commit")
    args = parser.parse_args()
    errors = verify(
        args.sdist,
        source_root=args.source_root,
        expected_commit=args.expected_commit,
    )
    for error in errors:
        print(error)
    if errors:
        return 1
    binding = f" at commit {args.expected_commit}" if args.expected_commit else ""
    print(f"sdist content verification passed{binding}: {args.sdist}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
