#!/usr/bin/env python3
"""Validate the closed, direct-runtime dependency supply identity.

This module intentionally uses only the Python standard library.  It is run before
private-kernel access in CI, so it cannot rely on the candidate's dependency set or
on a YAML parser.  The CI workflow consumes the machine-readable supply manifest;
this validator verifies that its exact artifact tuples, the lock, declared runtime
requirements, and the separately pinned identity cannot be silently rebound.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOCK_RELATIVE_PATH = "scripts/phase5-v1-release-dependency-lock.json"
MANIFEST_RELATIVE_PATH = "scripts/phase5-v1-release-supply-manifest.json"
IDENTITY_RELATIVE_PATH = "scripts/phase5-v1-release-supply-identity.json"
VALIDATOR_RELATIVE_PATH = "scripts/phase5_v1_dependency_lock.py"
SIDECAR_REVIEWED_LOCK_RELATIVE_PATH = "sidecars/futu-opend/supply/dependency-lock-v1.json"
REVIEWED_METADATA_RELATIVE_PATH = "scripts/phase5-v1-reviewed-artifact-metadata.json"
PYTHON_TARGETS = ("3.11", "3.12", "3.13")
REQUIRES_PYTHON = ">=3.11,<3.14"
PROJECT_PATHS = {
    "owner": "pyproject.toml",
    "sidecar": "sidecars/futu-opend/pyproject.toml",
}
CI_RELATIVE_PATH = ".github/workflows/ci.yml"
AUTHORITY_RELATIVE_PATHS = (
    LOCK_RELATIVE_PATH,
    MANIFEST_RELATIVE_PATH,
    IDENTITY_RELATIVE_PATH,
    VALIDATOR_RELATIVE_PATH,
    REVIEWED_METADATA_RELATIVE_PATH,
    SIDECAR_REVIEWED_LOCK_RELATIVE_PATH,
    *PROJECT_PATHS.values(),
    CI_RELATIVE_PATH,
)
MAXIMUM_AUTHORITY_BYTES = 16 * 1024 * 1024
MAXIMUM_ARTIFACT_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NORMALIZED_NAME_RE = re.compile(r"[-_.]+")
REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)(?P<specifier>(?:[<>=!~][^;]*)?)(?:; (?P<marker>.+))?$"
)
SPECIFIER_RE = re.compile(r"^(===|==|!=|<=|>=|<|>)\s*([0-9]+(?:\.[0-9]+)*(?:\.post[0-9]+)?)$")
MARKER_RE = re.compile(
    r"^(platform_python_implementation|python_version)\s*(==|!=|<=|>=|<|>)\s*'([^']+)'$"
)
CI_LOCK_ENTRY_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)==(?P<version>[^\s\\]+)(?P<rest>.*)$"
)
CI_LOCK_HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})")
CI_MATRIX_RE = re.compile(
    r'^\s{8}python-version:\s*(?P<targets>\["[0-9.]+"(?:,\s*"[0-9.]+")*\])\s*$',
    re.MULTILINE,
)
CI_PYTHON_VERSION_RE = re.compile(
    r"^\s+python-version:\s*(?P<value>[^\n#]+?)\s*$",
    re.MULTILINE,
)


class DependencyLockError(ValueError):
    """Raised when the release direct-runtime supply is not exact and closed."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _read_regular_bytes(path: Path, *, maximum: int = MAXIMUM_AUTHORITY_BYTES) -> bytes:
    """Read a sealed authority/artifact without following paths or hard links."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        _fail(f"cannot open regular 0644 file {path}: {error}")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o644
            or before.st_size > maximum
        ):
            _fail(f"{path} is not a bounded regular 0644 single-link file")
        chunks: list[bytes] = []
        consumed = 0
        while block := os.read(descriptor, 1024 * 1024):
            consumed += len(block)
            if consumed > maximum:
                _fail(f"{path} exceeds its bounded read limit")
            chunks.append(block)
        after = os.fstat(descriptor)
        if (
            consumed != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            _fail(f"{path} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_sealed_artifact_bytes(path: Path, *, maximum: int = MAXIMUM_ARTIFACT_BYTES) -> bytes:
    """Read a downloaded or sealed build artifact without following or rebinding it."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        _fail(f"cannot open sealed artifact {path}: {error}")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in {0o444, 0o644}
            or before.st_size > maximum
        ):
            _fail(f"{path} is not a bounded regular sealed single-link artifact")
        digest = bytearray()
        consumed = 0
        while block := os.read(descriptor, 1024 * 1024):
            consumed += len(block)
            if consumed > maximum:
                _fail(f"{path} exceeds its bounded artifact read limit")
            digest.extend(block)
        after = os.fstat(descriptor)
        if (
            consumed != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            _fail(f"{path} changed while it was read")
        return bytes(digest)
    finally:
        os.close(descriptor)


def file_sha256(path: Path, *, maximum: int = MAXIMUM_AUTHORITY_BYTES) -> str:
    return hashlib.sha256(_read_regular_bytes(path, maximum=maximum)).hexdigest()


def _fail(message: str) -> None:
    raise DependencyLockError(message)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        raw = _read_regular_bytes(path)
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"invalid JSON at {path}: {error}")
    if not isinstance(value, dict):
        _fail(f"JSON root at {path} must be an object")
    if raw != canonical_bytes(value):
        _fail(f"JSON at {path} is not canonical")
    return value


def _safe_relative_path(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        _fail(f"{field} must be a non-empty repository-relative path")
    path = Path(value)
    if any(part in {"", ".", ".."} for part in path.parts):
        _fail(f"{field} is not a safe repository-relative path")
    return value


def _normalise_name(value: str) -> str:
    return NORMALIZED_NAME_RE.sub("-", value).lower()


def _version_key(value: str) -> tuple[tuple[int, ...], int | None]:
    """Parse the deliberately closed PEP 440 subset used by this release lock."""
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)*)(?:\.post([0-9]+))?", value)
    if match is None:
        _fail(f"unsupported resolved version syntax: {value!r}")
    release = tuple(int(part) for part in match.group(1).split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    # A final release and ``.post0`` are different PEP 440 versions.  The
    # former sorts first; representing absence as -1 preserves that ordering.
    return release, int(match.group(2)) if match.group(2) is not None else -1


def _compare_versions(left: str, right: str) -> int:
    left_key = _version_key(left)
    right_key = _version_key(right)
    return (left_key > right_key) - (left_key < right_key)


def _satisfies_specifier(version: str, specifier: str) -> bool:
    terms = [term.strip() for term in specifier.split(",")]
    if not terms or any(not term for term in terms):
        _fail("requirement specifier must be a non-empty comma-separated closed subset")
    for term in terms:
        match = SPECIFIER_RE.fullmatch(term)
        if match is None:
            _fail(f"unsupported requirement specifier: {term!r}")
        operator, expected = match.groups()
        comparison = _compare_versions(version, expected)
        if not {
            "===": version == expected,
            "==": comparison == 0,
            "!=": comparison != 0,
            "<=": comparison <= 0,
            ">=": comparison >= 0,
            "<": comparison < 0,
            ">": comparison > 0,
        }[operator]:
            return False
    return True


def _marker_applies(marker: str, *, python_target: str) -> bool:
    if not marker:
        return True
    terms = [term.strip() for term in marker.split(" and ")]
    if not terms or any(not term for term in terms):
        _fail("marker must be a non-empty closed conjunction")
    for term in terms:
        match = MARKER_RE.fullmatch(term)
        if match is None:
            _fail(f"unsupported marker: {term!r}")
        field, operator, expected = match.groups()
        actual = "CPython" if field == "platform_python_implementation" else python_target
        comparison = (
            _compare_versions(actual, expected)
            if field == "python_version"
            else (actual > expected) - (actual < expected)
        )
        applies = {
            "==": actual == expected,
            "!=": actual != expected,
            "<=": comparison <= 0,
            ">=": comparison >= 0,
            "<": comparison < 0,
            ">": comparison > 0,
        }[operator]
        if not applies:
            return False
    return True


def _parse_requirement(
    value: object, *, expected_name: str, expected_version: str
) -> tuple[str, str]:
    if not isinstance(value, str):
        _fail("declared requirement must be text")
    match = REQUIREMENT_RE.fullmatch(value)
    if match is None:
        _fail(f"unsupported declared requirement syntax: {value!r}")
    if _normalise_name(match.group("name")) != expected_name:
        _fail(f"requirement name does not own component {expected_name}: {value!r}")
    specifier = (match.group("specifier") or "").strip()
    marker = match.group("marker") or ""
    if not specifier:
        _fail(f"requirement must constrain resolved version {expected_version}: {value!r}")
    if not _satisfies_specifier(expected_version, specifier):
        _fail(f"resolved version {expected_version} does not satisfy {value!r}")
    return specifier, marker


def _assert_sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail(f"{field} must be a lowercase SHA-256")
    return value


def _assert_spdx_expression(value: object) -> str:
    if not isinstance(value, str) or not value:
        _fail("license_expression must be a non-empty SPDX expression")
    # This is deliberately a small closed grammar: SPDX IDs plus AND/OR/WITH and
    # the reviewed Futu SDK LicenseRef.  Free-text classifier licenses are rejected.
    tokens = value.split()
    allowed_operators = {"AND", "OR", "WITH"}
    identifier = re.compile(r"(?:[A-Za-z0-9.-]+|LicenseRef-[A-Za-z0-9.-]+)")
    if any(
        (index % 2 == 0 and identifier.fullmatch(token) is None)
        or (index % 2 == 1 and token not in allowed_operators)
        for index, token in enumerate(tokens)
    ):
        _fail("license_expression is not a closed SPDX expression")
    return value


def _validate_target(value: object, *, source: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("artifact target must be an object")
    expected_keys = (
        {"kind", "python_targets", "implementation", "platform"}
        if source
        else {"kind", "python_tags", "abi_tags", "platform_tags", "python_targets"}
    )
    if set(value) != expected_keys:
        _fail("artifact target has an unexpected shape")
    if value.get("kind") != ("sdist" if source else "wheel"):
        _fail("artifact target kind is invalid")
    targets = value.get("python_targets")
    if (
        not isinstance(targets, list)
        or not targets
        or any(item not in PYTHON_TARGETS for item in targets)
    ):
        _fail("artifact target python_targets is invalid")
    if targets != sorted(set(targets)):
        _fail("artifact target python_targets must be unique and sorted")
    if source:
        if value.get("implementation") != "cpython" or value.get("platform") != "linux-x86_64":
            _fail("sdist target must be a CPython Linux x86_64 recipe")
    else:
        for field in ("python_tags", "abi_tags", "platform_tags"):
            tags = value.get(field)
            if (
                not isinstance(tags, list)
                or not tags
                or any(not isinstance(tag, str) or not tag for tag in tags)
            ):
                _fail(f"wheel {field} must be a non-empty tag list")
            if tags != sorted(set(tags)):
                _fail(f"wheel {field} must be unique and sorted")
    return value


def _wheel_target_from_filename(filename: str) -> dict[str, Any]:
    stem = filename.removesuffix(".whl")
    try:
        _, _, python_tag, abi_tag, platform_tag = stem.rsplit("-", 4)
    except ValueError:
        _fail("wheel filename does not contain normalized name, version, and three tags")
    python_tags = sorted(python_tag.split("."))
    abi_tags = sorted(abi_tag.split("."))
    platform_tags = sorted(platform_tag.split("."))
    if platform_tags != ["any"] and not all(
        "linux" in tag and tag.endswith("x86_64") for tag in platform_tags
    ):
        _fail("wheel platform tags are not Linux x86_64")
    cp_python_tags = {
        (3, int(match.group(1)[1:]))
        for tag in python_tags
        if (match := re.fullmatch(r"cp(3[0-9]{1,2})", tag)) is not None
    }
    cp_abi_tags = {
        (3, int(match.group(1)[1:]))
        for tag in abi_tags
        if (match := re.fullmatch(r"cp(3[0-9]{1,2})", tag)) is not None
    }
    if "py3" in python_tags and abi_tags == ["none"]:
        # ``py2.py3-none-any`` is a legitimate universal tag.  py2 is not an
        # implementation-specific CPython tag and does not expand our target
        # matrix beyond the closed py3 entries.
        if any(tag not in {"py2", "py3"} for tag in python_tags):
            _fail("universal wheel cannot mix py3 with implementation tags")
        targets = list(PYTHON_TARGETS)
    elif not cp_python_tags:
        _fail("wheel tags do not identify a supported CPython target")
    elif len(cp_python_tags) != 1:
        _fail("wheel filename mixes CPython minor tags")
    elif abi_tags == ["abi3"]:
        minimum = next(iter(cp_python_tags))
        targets = [
            target for target in PYTHON_TARGETS if (3, int(target.split(".")[1])) >= minimum
        ]
    else:
        if cp_abi_tags != cp_python_tags or len(abi_tags) != 1:
            _fail("wheel filename CPython ABI tag does not equal its Python tag")
        minimum = next(iter(cp_python_tags))
        targets = [f"{minimum[0]}.{minimum[1]}"]
    if not targets or any(target not in PYTHON_TARGETS for target in targets):
        _fail("wheel tags do not target the closed CPython matrix")
    return {
        "abi_tags": abi_tags,
        "kind": "wheel",
        "platform_tags": platform_tags,
        "python_tags": python_tags,
        "python_targets": targets,
    }


def _validate_artifact(
    value: object, *, component_name: str, component_version: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("artifact must be an object")
    if set(value) != {"filename", "sha256", "target"}:
        _fail("artifact has an unexpected shape")
    filename = value.get("filename")
    if not isinstance(filename, str) or not filename or Path(filename).name != filename:
        _fail("artifact filename must be a basename")
    _assert_sha256(value.get("sha256"), field="artifact sha256")
    source = filename.endswith((".tar.gz", ".zip"))
    target = _validate_target(value.get("target"), source=source)
    if source and component_name != "futu-api":
        _fail("only the reviewed Futu SDK source artifact is permitted")
    if not source and not filename.endswith(".whl"):
        _fail("non-source artifact must be a wheel")
    if source:
        stem = filename.removesuffix(".tar.gz").removesuffix(".zip")
        expected_prefix = component_name.replace("-", "_")
        if stem != f"{expected_prefix}-{component_version}":
            _fail("source artifact filename does not match normalized component name and version")
    else:
        stem = filename.removesuffix(".whl")
        distribution_and_version = stem.rsplit("-", 3)[0]
        expected_prefix = f"{component_name.replace('-', '_')}-{component_version}"
        if distribution_and_version != expected_prefix:
            _fail("wheel filename does not match normalized component name and version")
        if target != _wheel_target_from_filename(filename):
            _fail("wheel target does not exactly equal filename tags")
    return value


def _direct_project_requirements(root: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for project, relative in PROJECT_PATHS.items():
        path = root / relative
        try:
            payload = tomllib.loads(_read_regular_bytes(path).decode("utf-8"))
            project_table = payload["project"]
            dependencies = project_table["dependencies"]
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
            _fail(f"cannot load declared runtime dependencies from {relative}: {error}")
        if project_table.get("requires-python") != REQUIRES_PYTHON:
            _fail(f"{relative} requires-python must be exactly {REQUIRES_PYTHON}")
        if not isinstance(dependencies, list) or any(
            not isinstance(item, str) for item in dependencies
        ):
            _fail(f"declared runtime dependencies in {relative} are invalid")
        result[project] = list(dependencies)
    return result


def _validate_ci_python_matrix(root: Path) -> None:
    try:
        text = _read_regular_bytes(root / CI_RELATIVE_PATH).decode("utf-8")
    except UnicodeDecodeError as error:
        _fail(f"CI workflow is not UTF-8: {error}")
    matches = list(CI_MATRIX_RE.finditer(text))
    if len(matches) != 1:
        _fail("CI must contain exactly one closed inline Python version matrix")
    try:
        targets = json.loads(matches[0].group("targets"))
    except json.JSONDecodeError as error:
        _fail(f"CI Python matrix is invalid: {error}")
    if targets != list(PYTHON_TARGETS):
        _fail("CI Python matrix does not exactly equal the supported project range")
    declarations = tuple(match.group("value") for match in CI_PYTHON_VERSION_RE.finditer(text))
    expected = (
        json.dumps(list(PYTHON_TARGETS)),
        "${{ matrix.python-version }}",
        '"3.11"',
    )
    if declarations != expected:
        _fail("CI Python matrix/version declarations are not closed to 3.11, 3.12, and 3.13")


def _load_sidecar_reviewed_lock(root: Path, binding: object) -> dict[str, dict[str, Any]]:
    if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
        _fail("sidecar reviewed lock binding has an unexpected shape")
    if _safe_relative_path(binding["path"], field="sidecar reviewed lock path") != (
        SIDECAR_REVIEWED_LOCK_RELATIVE_PATH
    ):
        _fail("sidecar reviewed lock path is not fixed")
    expected_sha = _assert_sha256(binding["sha256"], field="sidecar reviewed lock sha256")
    path = root / SIDECAR_REVIEWED_LOCK_RELATIVE_PATH
    raw = _read_regular_bytes(path)
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        _fail("sidecar reviewed lock bytes drifted")
    try:
        payload = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"cannot load sidecar reviewed lock: {error}")
    if not isinstance(payload, dict) or payload.get("lock_id") != (
        "owner-research-futu-sidecar-dependency-lock-v1"
    ):
        _fail("sidecar reviewed lock identity is invalid")
    # The sidecar owns a compact canonical profile.  Do not coerce this into the
    # release manifest profile: both raw bytes and this profile are authority.
    sidecar_canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    if raw != sidecar_canonical:
        _fail("sidecar reviewed lock is not canonical under its sidecar profile")
    components = payload.get("components")
    if not isinstance(components, list):
        _fail("sidecar reviewed lock components are invalid")
    result: dict[str, dict[str, Any]] = {}
    for entry in components:
        if not isinstance(entry, dict) or set(entry) != {
            "artifact",
            "license",
            "name",
            "scopes",
            "sha256",
            "version",
        }:
            _fail("sidecar reviewed lock component entry is invalid")
        name = entry.get("name")
        if not isinstance(name, str) or name in result:
            _fail("sidecar reviewed lock has duplicate component names")
        _assert_sha256(entry.get("sha256"), field="sidecar reviewed artifact sha256")
        _assert_spdx_expression(entry.get("license"))
        result[name] = entry
    return result


def _load_reviewed_metadata(root: Path, binding: object) -> dict[str, dict[str, Any]]:
    if not isinstance(binding, dict) or set(binding) != {"path", "sha256"}:
        _fail("reviewed artifact metadata binding has an unexpected shape")
    if _safe_relative_path(binding["path"], field="reviewed artifact metadata path") != (
        REVIEWED_METADATA_RELATIVE_PATH
    ):
        _fail("reviewed artifact metadata path is not fixed")
    path = root / REVIEWED_METADATA_RELATIVE_PATH
    if file_sha256(path) != _assert_sha256(
        binding["sha256"], field="reviewed artifact metadata sha256"
    ):
        _fail("reviewed artifact metadata bytes drifted")
    payload = _read_json(path)
    if (
        set(payload) != {"artifact_type", "records", "schema_version"}
        or payload.get("artifact_type") != "owner-equity-reviewed-artifact-metadata"
    ):
        _fail("reviewed artifact metadata identity is invalid")
    if payload.get("schema_version") != "1.0.0" or not isinstance(payload.get("records"), list):
        _fail("reviewed artifact metadata schema is invalid")
    records: dict[str, dict[str, Any]] = {}
    for record in payload["records"]:
        if not isinstance(record, dict) or set(record) != {
            "artifacts",
            "component",
            "license_expression",
            "record_id",
            "version",
        }:
            _fail("reviewed artifact metadata record has an unexpected shape")
        record_id = record.get("record_id")
        if not isinstance(record_id, str) or record_id in records:
            _fail("reviewed artifact metadata record id is invalid")
        _assert_spdx_expression(record.get("license_expression"))
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            _fail("reviewed artifact metadata record artifacts are invalid")
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {
                "filename",
                "license_file_headers",
                "license_files",
                "metadata_license",
                "metadata_path",
                "metadata_sha256",
                "sha256",
            }:
                _fail("reviewed artifact metadata artifact has an unexpected shape")
            _assert_sha256(artifact.get("sha256"), field="reviewed metadata artifact sha256")
            _assert_sha256(artifact.get("metadata_sha256"), field="reviewed metadata sha256")
            if not isinstance(artifact.get("metadata_license"), str) or not isinstance(
                artifact.get("metadata_path"), str
            ):
                _fail("reviewed artifact metadata license fields are invalid")
            license_files = artifact.get("license_files")
            license_headers = artifact.get("license_file_headers")
            if not isinstance(license_files, list) or any(
                not isinstance(item, dict) or set(item) != {"path", "sha256"}
                for item in license_files
            ):
                _fail("reviewed artifact metadata license file inventory is invalid")
            if (
                not isinstance(license_headers, list)
                or any(not isinstance(item, str) or not item for item in license_headers)
                or len(license_headers) != len(set(license_headers))
            ):
                _fail("reviewed artifact metadata License-File header inventory is invalid")
            for item in license_files:
                _assert_sha256(item["sha256"], field="reviewed metadata license file sha256")
        records[record_id] = record
    return records


def validate_lock(lock: dict[str, Any], *, root: Path) -> list[dict[str, Any]]:
    expected = {
        "artifact_type",
        "components",
        "inventory_scope",
        "platform",
        "python_targets",
        "reviewed_artifact_metadata",
        "schema_version",
        "sidecar_reviewed_lock",
        "supply_manifest_path",
    }
    if set(lock) != expected:
        _fail("dependency lock has an unexpected top-level shape")
    if (
        lock["artifact_type"] != "owner-equity-release-dependency-lock"
        or lock["schema_version"] != "2.0.0"
    ):
        _fail("dependency lock identity is invalid")
    if lock["inventory_scope"] != "direct_runtime_only":
        _fail("only the declared direct-runtime inventory scope is currently authorized")
    if lock["platform"] != "linux-x86_64-cpython":
        _fail("dependency lock platform is invalid")
    if lock["python_targets"] != list(PYTHON_TARGETS):
        _fail("dependency lock Python targets are invalid")
    if _safe_relative_path(lock["supply_manifest_path"], field="supply_manifest_path") != (
        MANIFEST_RELATIVE_PATH
    ):
        _fail("dependency lock supply manifest path is not fixed")
    sidecar_entries = _load_sidecar_reviewed_lock(root, lock["sidecar_reviewed_lock"])
    metadata_records = _load_reviewed_metadata(root, lock["reviewed_artifact_metadata"])
    components = lock.get("components")
    if not isinstance(components, list) or not components:
        _fail("dependency lock components must be a non-empty list")
    observed_requirements: dict[str, list[str]] = {project: [] for project in PROJECT_PATHS}
    flat: list[dict[str, Any]] = []
    component_names: list[str] = []
    for component in components:
        if not isinstance(component, dict) or set(component) != {
            "artifacts",
            "license_evidence",
            "license_expression",
            "name",
            "requirements",
            "version",
        }:
            _fail("component has an unexpected shape")
        name = component.get("name")
        version = component.get("version")
        if not isinstance(name, str) or _normalise_name(name) != name:
            _fail("component name must be normalized")
        if not isinstance(version, str) or not version or any(char in version for char in "<>=,; "):
            _fail("component version must be exact")
        component_names.append(name)
        _assert_spdx_expression(component.get("license_expression"))
        evidence = component.get("license_evidence")
        if not isinstance(evidence, dict) or set(evidence) != {
            "record_id",
            "record_sha256",
            "source",
        }:
            _fail("component license evidence has an unexpected shape")
        if evidence["source"] not in {
            "reviewed-artifact-metadata",
            "sidecar-reviewed-lock",
        }:
            _fail("component license evidence source is invalid")
        if not isinstance(evidence["record_id"], str) or not evidence["record_id"]:
            _fail("component license evidence record id is invalid")
        _assert_sha256(evidence["record_sha256"], field="component license evidence record sha256")
        requirements = component.get("requirements")
        if not isinstance(requirements, list) or not requirements:
            _fail("component requirements must be non-empty")
        requirement_keys: list[tuple[str, str]] = []
        for requirement in requirements:
            if not isinstance(requirement, dict) or set(requirement) != {
                "declared_requirement",
                "declared_specifier",
                "marker",
                "normalized_name",
                "project",
                "resolved_version",
                "applicable_python_targets",
            }:
                _fail("component requirement has an unexpected shape")
            project = requirement.get("project")
            if project not in observed_requirements:
                _fail("component requirement project is invalid")
            if (
                requirement.get("normalized_name") != name
                or requirement.get("resolved_version") != version
            ):
                _fail("component requirement ownership is invalid")
            specifier, marker = _parse_requirement(
                requirement.get("declared_requirement"),
                expected_name=name,
                expected_version=version,
            )
            if (
                requirement.get("declared_specifier") != specifier
                or requirement.get("marker") != marker
            ):
                _fail("component requirement parsed fields drifted")
            applicable_targets = [
                target for target in PYTHON_TARGETS if _marker_applies(marker, python_target=target)
            ]
            if requirement.get("applicable_python_targets") != applicable_targets:
                _fail("component requirement marker applicability drifted")
            if not applicable_targets:
                _fail("component requirement does not apply to the closed target matrix")
            requirement_keys.append((project, str(requirement["declared_requirement"])))
            observed_requirements[project].append(str(requirement["declared_requirement"]))
        if requirement_keys != sorted(set(requirement_keys)):
            _fail("component requirements must be unique and sorted")
        artifacts = component.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            _fail("component artifacts must be non-empty")
        artifact_keys: list[tuple[str, str, str]] = []
        for artifact in artifacts:
            valid = _validate_artifact(artifact, component_name=name, component_version=version)
            artifact_keys.append(
                (valid["filename"], valid["sha256"], canonical_sha256(valid["target"]))
            )
            flat.append({"component": name, **valid})
        if artifact_keys != sorted(set(artifact_keys)):
            _fail("component artifacts must be unique and sorted")
        applicable_component_targets = sorted(
            {
                target
                for requirement in requirements
                for target in requirement["applicable_python_targets"]
            }
        )
        artifact_targets = sorted(
            {target for artifact in artifacts for target in artifact["target"]["python_targets"]}
        )
        if artifact_targets != applicable_component_targets:
            _fail("artifact target coverage does not equal evaluated requirement markers")
        if evidence["source"] == "sidecar-reviewed-lock":
            source_entry = sidecar_entries.get(name)
            if source_entry is None or evidence["record_id"] != f"{name}@{version}":
                _fail("sidecar reviewed lock license record identity is invalid")
            if evidence["record_sha256"] != canonical_sha256(source_entry):
                _fail("sidecar reviewed lock exact component entry drifted")
            if (
                source_entry["version"] != version
                or source_entry["license"] != component["license_expression"]
            ):
                _fail("sidecar reviewed lock license expression drifted")
            if source_entry["scopes"] != ["runtime"]:
                _fail("sidecar reviewed lock component is not an exact runtime entry")
        else:
            record = metadata_records.get(evidence["record_id"])
            if record is None or record["component"] != name or record["version"] != version:
                _fail("reviewed artifact metadata record identity is invalid")
            if evidence["record_sha256"] != canonical_sha256(record):
                _fail("reviewed artifact metadata exact record drifted")
            if record["license_expression"] != component["license_expression"]:
                _fail("reviewed artifact metadata license expression drifted")
            expected_artifacts = [
                {key: artifact[key] for key in ("filename", "sha256")} for artifact in artifacts
            ]
            recorded_artifacts = [
                {key: artifact[key] for key in ("filename", "sha256")}
                for artifact in record["artifacts"]
            ]
            if recorded_artifacts != expected_artifacts:
                _fail("reviewed artifact metadata does not cover exact wheel artifacts")
        if name == "futu-api":
            source_artifacts = [
                artifact for artifact in artifacts if artifact["filename"].endswith(".tar.gz")
            ]
            if len(source_artifacts) != 1:
                _fail("Futu SDK requires exactly one reviewed source artifact")
            derived = source_artifacts[0].get("derived_wheel")
            # The derived wheel is deliberately carried in the source artifact's
            # target recipe to bind build output to the exact reviewed sdist.
            if derived is not None:
                _fail(
                    "derived_wheel must be represented in the manifest, not an untyped lock field"
                )
    if component_names != sorted(set(component_names)):
        _fail("component names must be unique and sorted")
    derived_record = metadata_records.get("futu-api-derived-wheel@10.10.7008")
    if derived_record is None or derived_record["artifacts"] != [
        {
            "filename": "futu_api-10.10.7008-py3-none-any.whl",
            "license_file_headers": ["LICENSE"],
            "license_files": [
                {
                    "path": "licenses/LICENSE",
                    "sha256": "b440e384707fdcbdd7144388790e25aed8bbd086dcbd4ccfb344db8705af4364",
                }
            ],
            "metadata_license": "License: Apache License 2.0",
            "metadata_path": "futu_api-10.10.7008.dist-info/METADATA",
            "metadata_sha256": "e1fc155fd67fe129d1163ca420000dc9ec134f3986c8acbd2046b519460a8085",
            "sha256": "5aa0c0cfae77213d5d16bf67426c28f53a76c1dc1273f8627fb87cd40d78168e",
        }
    ]:
        _fail("Futu deterministic derived wheel metadata evidence is not closed")
    declared = _direct_project_requirements(root)
    if any(
        sorted(observed_requirements[project]) != sorted(declared[project])
        for project in PROJECT_PATHS
    ):
        _fail("lock requirements do not exactly equal declared direct runtime requirements")
    flat_keys = [(item["component"], item["filename"], item["sha256"]) for item in flat]
    if flat_keys != sorted(set(flat_keys)):
        _fail("global artifact identity tuples must be unique and sorted")
    return flat


def _manifest_artifact_record(component: str, artifact: dict[str, Any]) -> dict[str, Any]:
    result = {
        "component": component,
        "filename": artifact["filename"],
        "sha256": artifact["sha256"],
        "target": artifact["target"],
    }
    if artifact["filename"] == "futu_api-10.10.7008.tar.gz":
        result["derived_wheel"] = {
            "filename": "futu_api-10.10.7008-py3-none-any.whl",
            "recipe": {
                "build_backend": "setuptools",
                "python_targets": list(PYTHON_TARGETS),
                "source_date_epoch": 1580601600,
                "wheel_filename": "futu_api-10.10.7008-py3-none-any.whl",
            },
            "sha256": "5aa0c0cfae77213d5d16bf67426c28f53a76c1dc1273f8627fb87cd40d78168e",
        }
    return result


def expected_supply_manifest(lock: dict[str, Any], flat: list[dict[str, Any]]) -> dict[str, Any]:
    artifacts = [_manifest_artifact_record(item.pop("component"), item) for item in flat]
    return {
        "artifact_type": "owner-equity-release-supply-manifest",
        "artifacts": artifacts,
        "inventory_scope": lock["inventory_scope"],
        "lock_path": LOCK_RELATIVE_PATH,
        "lock_sha256": canonical_sha256(lock),
        "python_targets": list(PYTHON_TARGETS),
        "schema_version": "1.0.0",
    }


def validate_supply_manifest(
    manifest: dict[str, Any], *, lock: dict[str, Any], flat: list[dict[str, Any]]
) -> None:
    expected = expected_supply_manifest(lock, [dict(item) for item in flat])
    if manifest != expected:
        _fail("supply manifest does not exactly equal the closed lock inventory")
    for artifact in manifest["artifacts"]:
        derived = artifact.get("derived_wheel")
        if derived is None:
            continue
        if set(derived) != {"filename", "recipe", "sha256"}:
            _fail("Futu derived wheel has an unexpected shape")
        if not isinstance(derived["filename"], str) or not derived["filename"].endswith(".whl"):
            _fail("Futu derived wheel filename is invalid")
        _assert_sha256(derived["sha256"], field="Futu derived wheel sha256")
        recipe = derived["recipe"]
        if not isinstance(recipe, dict) or set(recipe) != {
            "build_backend",
            "python_targets",
            "source_date_epoch",
            "wheel_filename",
        }:
            _fail("Futu derived wheel recipe has an unexpected shape")
        if recipe["build_backend"] != "setuptools" or recipe["python_targets"] != list(
            PYTHON_TARGETS
        ):
            _fail("Futu derived wheel recipe is invalid")
        if (
            recipe["source_date_epoch"] != 1580601600
            or recipe["wheel_filename"] != derived["filename"]
        ):
            _fail("Futu derived wheel recipe identity drifted")


def expected_identity(
    root: Path, *, lock: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    return {
        "artifact_type": "owner-equity-release-supply-identity",
        "inventory_scope": "direct_runtime_only",
        "lock": {"path": LOCK_RELATIVE_PATH, "sha256": canonical_sha256(lock)},
        "schema_version": "1.0.0",
        "supply_manifest": {
            "path": MANIFEST_RELATIVE_PATH,
            "sha256": canonical_sha256(manifest),
        },
        "validator": {
            "path": VALIDATOR_RELATIVE_PATH,
            "sha256": file_sha256(root / VALIDATOR_RELATIVE_PATH),
        },
    }


def validate_identity(
    identity: dict[str, Any], *, root: Path, lock: dict[str, Any], manifest: dict[str, Any]
) -> None:
    expected = expected_identity(root, lock=lock, manifest=manifest)
    if identity != expected:
        _fail("supply identity does not bind the exact lock, manifest, and validator")


def _git_output(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", os.fspath(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        _fail(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def validate_git_binding(root: Path, *, expected_commit: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        _fail("expected Git commit must be a full lowercase SHA-1")
    if _git_output(root, "rev-parse", "HEAD") != expected_commit:
        _fail("repository HEAD does not equal the expected commit")
    for relative in AUTHORITY_RELATIVE_PATHS:
        line = _git_output(root, "ls-tree", expected_commit, "--", relative)
        match = re.fullmatch(r"100644 blob ([0-9a-f]{40})\t(.+)", line)
        if match is None or match.group(2) != relative:
            _fail(f"{relative} is not an exact regular 100644 blob at expected commit")
        path = root / relative
        # This safe snapshot also enforces no-follow, one hard-link, 0644, and
        # bounded reads before Git receives a pathname.
        _read_regular_bytes(path)
        blob = _git_output(root, "hash-object", "--", relative)
        if blob != match.group(1):
            _fail(f"checkout bytes for {relative} do not equal its expected Git blob")


def _metadata_headers(raw: bytes) -> dict[str, list[str]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        _fail(f"wheel METADATA is not UTF-8: {error}")
    headers: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line:
            break
        if line.startswith((" ", "\t")):
            continue
        if ":" not in line:
            _fail("wheel METADATA has unsupported folded or malformed header")
        name, value = line.split(":", 1)
        headers.setdefault(name, []).append(value.lstrip())
    return headers


def _verify_wheel_metadata(raw: bytes, *, record: dict[str, Any]) -> None:
    """Verify installed wheel metadata from the exact ZIP bytes, never a side JSON."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as error:
        _fail(f"locked wheel is not a ZIP archive: {error}")
    expected_path = record["metadata_path"]
    names = archive.namelist()
    if names.count(expected_path) != 1:
        _fail("wheel has no unique reviewed METADATA member")
    metadata = archive.read(expected_path)
    if hashlib.sha256(metadata).hexdigest() != record["metadata_sha256"]:
        _fail("wheel METADATA bytes drifted from reviewed evidence")
    headers = _metadata_headers(metadata)
    expected_name = _normalise_name(record["component"])
    if [_normalise_name(value) for value in headers.get("Name", [])] != [expected_name]:
        _fail("wheel METADATA Name is not the locked normalized component")
    if headers.get("Version") != [record["version"]]:
        _fail("wheel METADATA Version is not the locked resolved version")
    license_line = record["metadata_license"]
    if license_line.startswith("License: "):
        if headers.get("License") != [license_line.removeprefix("License: ")]:
            _fail("wheel METADATA License is not reviewed")
    elif license_line.startswith("License-Expression: "):
        if headers.get("License-Expression") != [
            license_line.removeprefix("License-Expression: ")
        ]:
            _fail("wheel METADATA License-Expression is not reviewed")
    else:
        _fail("reviewed METADATA license evidence has no closed header kind")
    expected_files = {item["path"]: item["sha256"] for item in record["license_files"]}
    if headers.get("License-File", []) != record["license_file_headers"]:
        _fail("wheel METADATA License-File headers are not the reviewed inventory")
    prefix = expected_path.rsplit("/", 1)[0] + "/"
    observed_files = {
        name.removeprefix(prefix): hashlib.sha256(archive.read(name)).hexdigest()
        for name in names
        if name.startswith(prefix)
        and not name.endswith("/")
        and (
            name.removeprefix(prefix).startswith("licenses/")
            or Path(name.removeprefix(prefix)).name.upper().startswith(
                ("LICENSE", "COPYING", "AUTHORS")
            )
        )
    }
    if observed_files != expected_files:
        _fail("wheel License-File inventory or bytes drifted from reviewed evidence")


def _verify_sdist_metadata(raw: bytes, *, record: dict[str, Any]) -> None:
    """Validate Futu's reviewed sdist evidence without treating it as a wheel."""
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
        metadata = archive.extractfile(record["metadata_path"])
        if metadata is None:
            _fail("sdist has no reviewed PKG-INFO member")
        metadata_bytes = metadata.read()
    except (tarfile.TarError, OSError) as error:
        _fail(f"locked sdist is not a gzip tar archive: {error}")
    if hashlib.sha256(metadata_bytes).hexdigest() != record["metadata_sha256"]:
        _fail("sdist PKG-INFO bytes drifted from reviewed evidence")
    headers = _metadata_headers(metadata_bytes)
    if [_normalise_name(value) for value in headers.get("Name", [])] != [
        _normalise_name(record["component"])
    ] or headers.get("Version") != [record["version"]]:
        _fail("sdist PKG-INFO Name or Version is not reviewed")
    license_line = record["metadata_license"]
    if not license_line.startswith("License: ") or headers.get("License") != [
        license_line.removeprefix("License: ")
    ]:
        _fail("sdist PKG-INFO License is not reviewed")
    base = record["metadata_path"].rsplit("/", 1)[0] + "/"
    expected_files = {item["path"]: item["sha256"] for item in record["license_files"]}
    if headers.get("License-File", []) != record["license_file_headers"]:
        _fail("sdist PKG-INFO License-File headers are not the reviewed inventory")
    observed_files: dict[str, str] = {}
    for member in archive.getmembers():
        if not member.isfile() or not member.name.startswith(base):
            continue
        relative = member.name.removeprefix(base)
        if relative not in expected_files:
            continue
        extracted = archive.extractfile(member)
        if extracted is None:
            _fail("sdist license member cannot be read")
        observed_files[relative] = hashlib.sha256(extracted.read()).hexdigest()
    if observed_files != expected_files:
        _fail("sdist License-File inventory or bytes drifted from reviewed evidence")


def _artifact_matches_target(artifact: dict[str, Any], *, python_target: str) -> bool:
    return python_target in artifact["target"]["python_targets"]


def _parse_ci_lock(path: Path) -> dict[tuple[str, str], set[str]]:
    """Parse the deliberately closed pip --require-hashes lock grammar."""
    raw = _read_sealed_artifact_bytes(path, maximum=MAXIMUM_AUTHORITY_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        _fail(f"CI supply lock is not UTF-8: {error}")
    logical: list[str] = []
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
            continue
        logical.append(current + stripped)
        current = ""
    if current:
        _fail("CI supply lock has an unterminated continuation")
    entries: dict[tuple[str, str], set[str]] = {}
    for line in logical:
        match = CI_LOCK_ENTRY_RE.fullmatch(line)
        if match is None:
            _fail("CI supply lock has unsupported requirement syntax")
        key = (_normalise_name(match["name"]), match["version"])
        hashes = set(CI_LOCK_HASH_RE.findall(match["rest"]))
        if not hashes or key in entries:
            _fail("CI supply lock has an unpinned or duplicate requirement")
        entries[key] = hashes
    return entries


def _validate_ci_lock_projection(
    manifest: dict[str, Any], *, ci_locks: list[Path]
) -> None:
    observed: dict[tuple[str, str], set[str]] = {}
    for path in ci_locks:
        for key, hashes in _parse_ci_lock(path).items():
            observed.setdefault(key, set()).update(hashes)
    expected: dict[tuple[str, str], set[str]] = {}
    for artifact in manifest["artifacts"]:
        key = (artifact["component"], _artifact_version_from_filename(artifact["filename"]))
        expected.setdefault(key, set()).add(artifact["sha256"])
    direct_names = {name for name, _version in expected}
    observed_direct = {key: hashes for key, hashes in observed.items() if key[0] in direct_names}
    if observed_direct != expected:
        _fail(
            "CI hardcoded direct component/version keys and hashes do not exactly equal manifest"
        )


def _artifact_version_from_filename(filename: str) -> str:
    if filename.endswith(".whl"):
        stem = filename.removesuffix(".whl")
        try:
            distribution_and_version = stem.rsplit("-", 3)[0]
            return distribution_and_version.rsplit("-", 1)[1]
        except ValueError:
            _fail("cannot obtain normalized version from wheel filename")
    stem = filename.removesuffix(".tar.gz").removesuffix(".zip")
    try:
        return stem.rsplit("-", 1)[1]
    except ValueError:
        _fail("cannot obtain normalized version from source filename")


def _verify_derived_futu_wheel(
    path: Path, *, manifest: dict[str, Any], metadata: dict[str, dict[str, Any]]
) -> str:
    """Verify the actual deterministic Futu wheel before any installation."""
    candidates = [
        artifact["derived_wheel"]
        for artifact in manifest["artifacts"]
        if artifact["component"] == "futu-api" and "derived_wheel" in artifact
    ]
    if len(candidates) != 1:
        _fail("manifest must authorize exactly one Futu derived wheel")
    derived = candidates[0]
    if path.name != derived["filename"]:
        _fail("actual Futu derived wheel filename is not manifest-authorized")
    record = metadata.get("futu-api-derived-wheel@10.10.7008")
    if (
        record is None
        or record.get("component") != "futu-api"
        or record.get("version") != _artifact_version_from_filename(derived["filename"])
    ):
        _fail("Futu derived wheel reviewed metadata identity is missing")
    evidence = [
        artifact for artifact in record["artifacts"] if artifact["filename"] == derived["filename"]
    ]
    if len(evidence) != 1 or evidence[0]["sha256"] != derived["sha256"]:
        _fail("Futu derived wheel manifest and reviewed metadata hashes are not identical")
    raw = _read_sealed_artifact_bytes(path)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != derived["sha256"]:
        _fail("actual Futu derived wheel hash drifted from the manifest")
    _verify_wheel_metadata(raw, record={**record, **evidence[0]})
    return digest


def verify_artifacts(
    root: Path,
    *,
    wheelhouse: Path,
    python_target: str,
    expected_git_commit: str | None = None,
    ci_locks: list[Path] | None = None,
    derived_futu_wheel: Path | None = None,
) -> dict[str, str]:
    """Verify current-target wheelhouse bytes and reviewed embedded license evidence."""
    if python_target not in PYTHON_TARGETS:
        _fail("artifact verification target is outside the closed CPython matrix")
    identity = validate_repository(root, expected_git_commit=expected_git_commit)
    lock = _read_json(root / LOCK_RELATIVE_PATH)
    manifest = _read_json(root / MANIFEST_RELATIVE_PATH)
    if ci_locks:
        _validate_ci_lock_projection(manifest, ci_locks=ci_locks)
    metadata = _load_reviewed_metadata(root, lock["reviewed_artifact_metadata"])
    try:
        wheelhouse_info = wheelhouse.lstat()
    except OSError as error:
        _fail(f"cannot stat wheelhouse: {error}")
    if wheelhouse.is_symlink() or not stat.S_ISDIR(wheelhouse_info.st_mode):
        _fail("wheelhouse is not a real directory")
    verified: dict[str, bytes] = {}
    for artifact in manifest["artifacts"]:
        if not _artifact_matches_target(artifact, python_target=python_target):
            continue
        filename = artifact["filename"]
        path = wheelhouse / filename
        raw = _read_sealed_artifact_bytes(path, maximum=MAXIMUM_ARTIFACT_BYTES)
        if hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
            _fail(f"wheelhouse artifact hash drifted: {filename}")
        verified[filename] = raw
    # Futu stays isolated: its sdist and deterministic derived wheel are bound
    # by the sidecar source lock/recipe, not parsed as a release dependency wheel.
    evidence_by_filename: dict[str, list[dict[str, Any]]] = {}
    for record in metadata.values():
        for artifact in record["artifacts"]:
            evidence_by_filename.setdefault(artifact["filename"], []).append({**record, **artifact})
    for filename, raw in verified.items():
        evidence = evidence_by_filename.get(filename, [])
        if len(evidence) != 1:
            _fail("every selected locked artifact must have one reviewed metadata record")
        if filename.endswith(".whl"):
            _verify_wheel_metadata(raw, record=evidence[0])
        elif filename == "futu_api-10.10.7008.tar.gz":
            _verify_sdist_metadata(raw, record=evidence[0])
    if derived_futu_wheel is not None:
        identity["verified_derived_futu_wheel_sha256"] = _verify_derived_futu_wheel(
            derived_futu_wheel,
            manifest=manifest,
            metadata=metadata,
        )
    return {**identity, "verified_python_target": python_target}


def validate_repository(root: Path, *, expected_git_commit: str | None = None) -> dict[str, str]:
    _validate_ci_python_matrix(root)
    lock = _read_json(root / LOCK_RELATIVE_PATH)
    manifest = _read_json(root / MANIFEST_RELATIVE_PATH)
    identity = _read_json(root / IDENTITY_RELATIVE_PATH)
    flat = validate_lock(lock, root=root)
    validate_supply_manifest(manifest, lock=lock, flat=flat)
    validate_identity(identity, root=root, lock=lock, manifest=manifest)
    if expected_git_commit is not None:
        validate_git_binding(root, expected_commit=expected_git_commit)
    return {
        "identity_sha256": canonical_sha256(identity),
        "lock_sha256": canonical_sha256(lock),
        "supply_manifest_sha256": canonical_sha256(manifest),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "verify-artifacts"))
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--expected-git-commit")
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--python-target", choices=PYTHON_TARGETS)
    parser.add_argument("--ci-supply-lock", type=Path, action="append", default=[])
    parser.add_argument("--derived-futu-wheel", type=Path)
    parser.add_argument("--downloaded-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        root = args.repository.resolve()
        if args.command == "validate":
            identity = validate_repository(root, expected_git_commit=args.expected_git_commit)
        else:
            if args.wheelhouse is None or args.python_target is None:
                _fail("verify-artifacts requires --wheelhouse and --python-target")
            if args.downloaded_only == (args.derived_futu_wheel is not None):
                _fail(
                    "verify-artifacts requires exactly one of --downloaded-only or "
                    "--derived-futu-wheel"
                )
            identity = verify_artifacts(
                root,
                wheelhouse=args.wheelhouse.resolve(),
                python_target=args.python_target,
                expected_git_commit=args.expected_git_commit,
                ci_locks=args.ci_supply_lock,
                derived_futu_wheel=args.derived_futu_wheel,
            )
    except DependencyLockError as error:
        print(f"dependency lock validation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(identity, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
