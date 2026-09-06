#!/usr/bin/env python3
"""Build and verify the exact Owner Equity Research Codex Plugin bundle."""

from __future__ import annotations

import argparse
import json
import os
import stat
import struct
import subprocess
import tomllib
import zlib
from pathlib import Path, PurePosixPath
from typing import Any
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
PROJECT_RELATIVE = Path("pyproject.toml")
MARKETPLACE_RELATIVE = Path(".agents/plugins/marketplace.json")
PLUGIN_RELATIVE = Path("plugins/owner-equity-research")
MARKETPLACE_MEMBER = MARKETPLACE_RELATIVE.as_posix()
PLUGIN_PREFIX = PLUGIN_RELATIVE.as_posix() + "/"
MARKETPLACE_NAME = "owner-equity-research-release"
MAXIMUM_MEMBER_BYTES = 64 * 1024 * 1024
MAXIMUM_BUNDLE_BYTES = 256 * 1024 * 1024
MAXIMUM_MEMBERS = 512
EXPECTED_SKILLS = {
    "owner-equity-research": True,
    "owner-quarterly-update": False,
    "owner-research-audit": False,
    "owner-research-publish": False,
}
PROJECT_PLUGIN_VERSIONS = {
    "1.0.0.dev0": "1.0.0-dev.0",
    "1.0.0rc1": "1.0.0-rc.1",
}
EXPECTED_MARKETPLACE = {
    "name": MARKETPLACE_NAME,
    "interface": {"displayName": "Owner Equity Research Release"},
    "plugins": [
        {
            "name": "owner-equity-research",
            "source": {
                "source": "local",
                "path": "./plugins/owner-equity-research",
            },
            "policy": {
                "installation": "AVAILABLE",
                "authentication": "ON_INSTALL",
            },
            "category": "Productivity",
        }
    ],
}
FIXED_ZIP_TIME = (2020, 2, 2, 0, 0, 0)
_ZIP_EOCD = struct.Struct("<4s4H2LH")
_ZIP_LOCAL_HEADER = struct.Struct("<4s5H3L2H")
_ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3L5H2L")


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
                return "Plugin ZIP member compressed stream is truncated"
            position += chunk_size
            remaining -= chunk_size
            while pending:
                output_limit = min(1024 * 1024, uncompressed_size - total + 1)
                decoded = decoder.decompress(pending, output_limit)
                pending = decoder.unconsumed_tail
                total += len(decoded)
                if total > uncompressed_size:
                    return "Plugin ZIP member expands beyond its declared size"
                if decoder.unused_data:
                    return "Plugin ZIP member compressed stream has trailing data"
                if decoder.eof:
                    if pending or remaining:
                        return "Plugin ZIP member compressed stream has trailing data"
                    break
            if decoder.eof:
                break
    except zlib.error:
        return "Plugin ZIP member compressed stream is invalid"
    if not decoder.eof:
        return "Plugin ZIP member compressed stream is truncated"
    if total != uncompressed_size:
        return "Plugin ZIP member decompressed size drifted"
    return None


def _zip_envelope_errors(
    descriptor: int,
    file_size: int,
    infos: list[Any],
) -> list[str]:
    """Reject bytes outside one canonical, comment-free classic ZIP envelope."""
    if file_size < _ZIP_EOCD.size:
        return ["Plugin ZIP container envelope is truncated"]
    eocd_offset = file_size - _ZIP_EOCD.size
    raw = os.pread(descriptor, _ZIP_EOCD.size, eocd_offset)
    if len(raw) != _ZIP_EOCD.size:
        return ["Plugin ZIP container envelope is truncated"]
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
            "Plugin ZIP container envelope has prefix, suffix, comment, "
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
            return ["Plugin ZIP central-directory envelope is truncated"]
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
            return ["Plugin ZIP central-directory envelope is not canonical"]
        if item.header_offset != expected_offset:
            return ["Plugin ZIP container envelope has unreferenced or prefixed bytes"]
        header = os.pread(descriptor, _ZIP_LOCAL_HEADER.size, expected_offset)
        if len(header) != _ZIP_LOCAL_HEADER.size:
            return ["Plugin ZIP local-file envelope is truncated"]
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
            return ["Plugin ZIP local-file envelope is not canonical"]
        payload_offset = expected_offset + _ZIP_LOCAL_HEADER.size + name_size + extra_size
        if compression != 8:
            return ["Plugin ZIP member compression is not canonical DEFLATE"]
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
        else ["Plugin ZIP container envelope has bytes outside member payloads"]
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not a JSON object")
    return value


def _read_regular(path: Path, label: str) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"{label} is not a regular single-link file")
    if metadata.st_size > MAXIMUM_MEMBER_BYTES:
        raise ValueError(f"{label} exceeds the member byte limit")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= MAXIMUM_MEMBER_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAXIMUM_MEMBER_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(raw) != before.st_size
        ):
            raise ValueError(f"{label} changed while being read")
        if len(raw) > MAXIMUM_MEMBER_BYTES:
            raise ValueError(f"{label} exceeds the member byte limit")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _resolve_commit(source_root: Path, expected_commit: str) -> str:
    if len(expected_commit) != 40 or any(
        char not in "0123456789abcdef" for char in expected_commit
    ):
        raise ValueError("expected commit must be a lowercase full SHA-1 object name")
    result = subprocess.run(
        ("git", "-C", str(source_root), "rev-parse", "--verify", f"{expected_commit}^{{commit}}"),
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode or result.stdout.strip() != expected_commit:
        raise ValueError("expected commit is unavailable from the trusted repository")
    return expected_commit


def _git_regular_bytes(
    source_root: Path,
    commit: str,
    relative: Path,
    *,
    label: str,
) -> bytes:
    relative_text = relative.as_posix()
    listed = subprocess.run(
        ("git", "-C", str(source_root), "ls-tree", "-z", commit, "--", relative_text),
        check=False,
        capture_output=True,
    )
    records = [record for record in listed.stdout.split(b"\0") if record]
    if listed.returncode or len(records) != 1:
        raise ValueError(f"{label} is unavailable from the trusted commit")
    identity, path_raw = records[0].split(b"\t", 1)
    mode, kind, _object_id = identity.decode("ascii").split(" ", 2)
    if (
        mode != "100644"
        or kind != "blob"
        or path_raw.decode("utf-8") != relative_text
    ):
        raise ValueError(f"{label} is not a trusted 0644 regular blob")
    shown = subprocess.run(
        ("git", "-C", str(source_root), "show", f"{commit}:{relative_text}"),
        check=False,
        capture_output=True,
    )
    if shown.returncode or len(shown.stdout) > MAXIMUM_MEMBER_BYTES:
        raise ValueError(f"{label} is unavailable or exceeds the byte limit")
    return shown.stdout


def _expected_plugin_version(source_root: Path, commit: str | None) -> str:
    if commit is None:
        raw = _read_regular(
            source_root / PROJECT_RELATIVE,
            "trusted project metadata",
        )
    else:
        raw = _git_regular_bytes(
            source_root,
            commit,
            PROJECT_RELATIVE,
            label="trusted project metadata",
        )
    try:
        project = tomllib.loads(raw.decode("utf-8"))
        version = project["project"]["version"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("trusted project version is unavailable") from exc
    expected = PROJECT_PLUGIN_VERSIONS.get(version)
    if expected is None:
        raise ValueError("trusted project version is outside the Plugin release contract")
    return expected


def _git_projection(source_root: Path, commit: str) -> dict[str, bytes]:
    prefix = PLUGIN_RELATIVE.as_posix()
    result = subprocess.run(
        (
            "git",
            "-C",
            str(source_root),
            "ls-tree",
            "-r",
            "-z",
            commit,
            "--",
            prefix,
            MARKETPLACE_MEMBER,
        ),
        check=False,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError("trusted Plugin tree could not be enumerated")
    projection: dict[str, bytes] = {}
    total = 0
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        identity, path_raw = record.split(b"\t", 1)
        mode, kind, _object_id = identity.decode("ascii").split(" ", 2)
        relative = path_raw.decode("utf-8")
        if mode != "100644" or kind != "blob":
            raise ValueError(f"trusted Plugin member is not a 0644 regular blob: {relative}")
        shown = subprocess.run(
            ("git", "-C", str(source_root), "show", f"{commit}:{relative}"),
            check=False,
            capture_output=True,
        )
        if shown.returncode:
            raise ValueError(f"trusted Plugin member is unavailable: {relative}")
        raw = shown.stdout
        if len(raw) > MAXIMUM_MEMBER_BYTES:
            raise ValueError(f"trusted Plugin member exceeds the byte limit: {relative}")
        if relative != MARKETPLACE_MEMBER and not relative.startswith(prefix + "/"):
            raise ValueError(f"trusted Plugin member escaped the closed projection: {relative}")
        projection[relative] = raw
        total += len(raw)
    if MARKETPLACE_MEMBER not in projection:
        raise ValueError("trusted Plugin marketplace manifest is missing")
    if (
        not projection
        or len(projection) > MAXIMUM_MEMBERS
        or total > MAXIMUM_BUNDLE_BYTES
    ):
        raise ValueError("trusted Plugin projection is empty or exceeds the cumulative limit")
    return projection


def _worktree_projection(source_root: Path) -> dict[str, bytes]:
    plugin = source_root / PLUGIN_RELATIVE
    if not stat.S_ISDIR(plugin.lstat().st_mode):
        raise ValueError("trusted Plugin source is not a directory")
    marketplace = source_root / MARKETPLACE_RELATIVE
    projection: dict[str, bytes] = {
        MARKETPLACE_MEMBER: _read_regular(
            marketplace,
            "trusted Plugin marketplace manifest",
        )
    }
    total = len(projection[MARKETPLACE_MEMBER])
    for current, directories, filenames in os.walk(plugin, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            child = current_path / directory
            if not stat.S_ISDIR(child.lstat().st_mode):
                raise ValueError(f"Plugin contains an unsafe directory: {child}")
        for filename in filenames:
            path = current_path / filename
            relative = path.relative_to(plugin).as_posix()
            if "__pycache__" in PurePosixPath(relative).parts or filename == ".DS_Store":
                continue
            raw = _read_regular(path, f"Plugin source {relative}")
            projection[PLUGIN_PREFIX + relative] = raw
            total += len(raw)
    if (
        not projection
        or len(projection) > MAXIMUM_MEMBERS
        or total > MAXIMUM_BUNDLE_BYTES
    ):
        raise ValueError("trusted Plugin projection is empty or exceeds the cumulative limit")
    return projection


def _projection(source_root: Path, expected_commit: str | None) -> dict[str, bytes]:
    if expected_commit is None:
        projection = _worktree_projection(source_root)
        expected_version = _expected_plugin_version(source_root, None)
    else:
        commit = _resolve_commit(source_root, expected_commit)
        projection = _git_projection(source_root, commit)
        expected_version = _expected_plugin_version(source_root, commit)
    _validate_plugin_semantics(projection, expected_plugin_version=expected_version)
    return projection


def _validate_plugin_semantics(
    projection: dict[str, bytes],
    *,
    expected_plugin_version: str,
) -> None:
    marketplace = _strict_json(
        projection[MARKETPLACE_MEMBER],
        "Plugin marketplace manifest",
    )
    if marketplace != EXPECTED_MARKETPLACE:
        raise ValueError(
            "Plugin marketplace name, path, policy, category, or closed inventory drifted"
        )
    manifest_name = PLUGIN_PREFIX + ".codex-plugin/plugin.json"
    manifest = _strict_json(projection[manifest_name], "Plugin manifest")
    if (
        manifest.get("name") != "owner-equity-research"
        or manifest.get("skills") != "./skills/"
        or manifest.get("version") != expected_plugin_version
        or manifest.get("interface", {}).get("capabilities") != []
    ):
        raise ValueError(
            "Plugin manifest identity, project-bound version, skills, "
            "or capability boundary drifted"
        )
    skill_files = {
        name
        for name in projection
        if PurePosixPath(name).name == "SKILL.md"
    }
    expected_skill_files = {
        f"{PLUGIN_PREFIX}skills/{skill}/SKILL.md" for skill in EXPECTED_SKILLS
    }
    if skill_files != expected_skill_files:
        raise ValueError("Plugin Skill inventory is not the exact four-Skill surface")
    implicit_skills: set[str] = set()
    for skill, implicit in EXPECTED_SKILLS.items():
        skill_name = f"{PLUGIN_PREFIX}skills/{skill}/SKILL.md"
        yaml_name = f"{PLUGIN_PREFIX}skills/{skill}/agents/openai.yaml"
        skill_text = projection[skill_name].decode("utf-8")
        yaml_text = projection[yaml_name].decode("utf-8")
        if not skill_text.startswith("---\n") or f"\nname: {skill}\n" not in skill_text[:1024]:
            raise ValueError(f"Plugin Skill frontmatter identity drifted: {skill}")
        expected_line = f"  allow_implicit_invocation: {str(implicit).lower()}"
        policy_lines = [
            line
            for line in yaml_text.splitlines()
            if line.lstrip().startswith("allow_implicit_invocation:")
        ]
        if policy_lines != [expected_line]:
            raise ValueError(f"Plugin Skill implicit-routing policy drifted: {skill}")
        if implicit:
            implicit_skills.add(skill)
    if implicit_skills != {"owner-equity-research"}:
        raise ValueError("Plugin must expose exactly one implicit Skill")
    main_lines = projection[
        PLUGIN_PREFIX + "skills/owner-equity-research/SKILL.md"
    ].splitlines()
    if len(main_lines) > 200:
        raise ValueError("main Owner Equity Research Skill exceeds 200 lines")


def build_bundle(
    destination: Path,
    *,
    source_root: Path = ROOT,
    expected_commit: str | None = None,
) -> Path:
    projection = _projection(source_root, expected_commit)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(destination, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(projection):
            info = ZipInfo(name, date_time=FIXED_ZIP_TIME)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = ZIP_DEFLATED
            archive.writestr(info, projection[name], compress_type=ZIP_DEFLATED, compresslevel=9)
    errors = verify(destination, source_root=source_root, expected_commit=expected_commit)
    if errors:
        raise ValueError("built Plugin bundle failed verification: " + "; ".join(errors))
    return destination


def verify(
    bundle: Path,
    *,
    source_root: Path = ROOT,
    expected_commit: str | None = None,
) -> tuple[str, ...]:
    errors: list[str] = []
    try:
        projection = _projection(source_root, expected_commit)
        metadata = bundle.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            return ("Plugin bundle is not a regular single-link file",)
        if metadata.st_size > MAXIMUM_BUNDLE_BYTES:
            return ("Plugin bundle exceeds the cumulative byte limit",)
        descriptor = os.open(bundle, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            with os.fdopen(descriptor, "rb", closefd=False) as handle, ZipFile(handle) as archive:
                infos = archive.infolist()
                errors.extend(_zip_envelope_errors(descriptor, before.st_size, infos))
                ordered_names = [item.filename for item in infos]
                names = set(ordered_names)
                if len(infos) > MAXIMUM_MEMBERS:
                    errors.append("Plugin bundle exceeds the member-count limit")
                if ordered_names != sorted(projection) or names != set(projection):
                    errors.append("Plugin bundle inventory or order differs from trusted source")
                if len(ordered_names) != len(names):
                    errors.append("Plugin bundle contains duplicate members")
                if archive.comment:
                    errors.append("Plugin bundle comment is forbidden")
                total = 0
                for item in infos:
                    logical = PurePosixPath(item.filename)
                    total += item.file_size
                    if (
                        item.filename != MARKETPLACE_MEMBER
                        and not item.filename.startswith(PLUGIN_PREFIX)
                    ) or (
                        item.filename.startswith("/")
                        or "\\" in item.filename
                        or ".." in logical.parts
                        or item.is_dir()
                        or item.create_system != 3
                        or item.external_attr >> 16 != (stat.S_IFREG | 0o644)
                        or item.date_time != FIXED_ZIP_TIME
                        or item.compress_type != ZIP_DEFLATED
                        or item.extra
                        or item.comment
                        or item.flag_bits != 0
                        or item.file_size > MAXIMUM_MEMBER_BYTES
                        or item.compress_size > MAXIMUM_MEMBER_BYTES
                    ):
                        errors.append(f"Plugin bundle contains an unsafe member: {item.filename!r}")
                        continue
                    raw = archive.read(item)
                    if raw != projection.get(item.filename):
                        errors.append(
                            "Plugin bundle member differs from trusted source bytes: "
                            f"{item.filename}"
                        )
                if total > MAXIMUM_BUNDLE_BYTES:
                    errors.append("Plugin bundle exceeds the cumulative uncompressed byte limit")
                if total <= MAXIMUM_BUNDLE_BYTES and archive.testzip() is not None:
                    errors.append("Plugin bundle CRC verification failed")
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                errors.append("Plugin bundle changed while being verified")
        finally:
            os.close(descriptor)
    except (BadZipFile, KeyError, OSError, UnicodeError, ValueError) as exc:
        errors.append(f"Plugin bundle could not be verified: {exc}")
    return tuple(errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("bundle", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("bundle", type=Path)
    for command_parser in (build_parser, verify_parser):
        command_parser.add_argument("--source-root", type=Path, default=ROOT)
        command_parser.add_argument("--expected-commit")
    args = parser.parse_args()
    if args.command == "build":
        build_bundle(
            args.bundle,
            source_root=args.source_root,
            expected_commit=args.expected_commit,
        )
        print(f"Plugin bundle built and verified: {args.bundle}")
        return 0
    errors = verify(
        args.bundle,
        source_root=args.source_root,
        expected_commit=args.expected_commit,
    )
    for error in errors:
        print(error)
    if errors:
        return 1
    binding = f" at commit {args.expected_commit}" if args.expected_commit else ""
    print(f"Plugin bundle verification passed{binding}: {args.bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
