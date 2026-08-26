#!/usr/bin/env python3
"""Assemble verified public preview or fail-closed RC release artifacts."""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import hashlib
import json
import os
import re
import runpy
import stat
import subprocess
import sys
import tempfile
import tomllib
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
_WHEEL = runpy.run_path(str(Path(__file__).with_name("verify_wheel.py")))
_SDIST = runpy.run_path(str(Path(__file__).with_name("verify_sdist.py")))
_PLUGIN = runpy.run_path(str(Path(__file__).with_name("verify_plugin_bundle.py")))
_SIDECAR = runpy.run_path(str(Path(__file__).with_name("verify_sidecar_distribution.py")))
ROOT_WHEEL_VERIFY: Callable[..., tuple[str, ...]] = _WHEEL["verify"]
ROOT_SDIST_VERIFY: Callable[..., tuple[str, ...]] = _SDIST["verify"]
PLUGIN_VERIFY: Callable[..., tuple[str, ...]] = _PLUGIN["verify"]
SIDECAR_WHEEL_VERIFY: Callable[..., tuple[str, ...]] = _SIDECAR["verify_wheel"]
SIDECAR_SDIST_VERIFY: Callable[..., tuple[str, ...]] = _SIDECAR["verify_sdist"]

MAXIMUM_JSON_BYTES = 16 * 1024 * 1024
MAXIMUM_SUPPLY_AUTHORITY_BYTES = 64 * 1024 * 1024
MAXIMUM_ARTIFACT_BYTES = 512 * 1024 * 1024
MAXIMUM_RELEASE_BYTES = 2 * 1024 * 1024 * 1024
ARTIFACT_ROLES = (
    "owner_wheel",
    "owner_sdist",
    "plugin_bundle",
    "sidecar_wheel",
    "sidecar_sdist",
)
PUBLIC_ARTIFACT_ROLES = ("owner_wheel", "owner_sdist", "plugin_bundle")
PRIVATE_CANARY_ARTIFACT_ROLES = ("sidecar_wheel", "sidecar_sdist")
ARTIFACT_TYPES = {
    "owner_wheel": "application/vnd.pypa.wheel+zip",
    "owner_sdist": "application/gzip",
    "plugin_bundle": "application/vnd.openai.codex.plugin+zip",
    "sidecar_wheel": "application/vnd.pypa.wheel+zip",
    "sidecar_sdist": "application/gzip",
}
GENERATED_PUBLIC_FILES = ("SHA256SUMS", "release-manifest.json", "sbom.cdx.json")
EXPECTED_PROJECT_NAMES = {
    "owner": "owner-equity-research",
    "plugin": "owner-equity-research",
    "sidecar": "owner-research-futu-sidecar",
}
SAFE_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,199}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
RFC3339_UTC = re.compile(
    r"(?P<whole>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,6}))?Z\Z"
)
KEY_TYPE = "owner-equity-rc-canary-trusted-signer-key"
RECEIPT_TYPE = "owner-equity-rc-canary-receipt"
SIGNING_USAGE = "owner_equity_rc_canary"
# Release control provisions this fixed policy and pins its digest in the trusted
# assembler environment.  The repository intentionally ships bootstrap-blocked: an RC
# cannot be authorized until release control installs a real, independently reviewed
# policy anchor.  Neither value is accepted from the CLI or candidate artifact set.
RELEASE_TRUST_POLICY_PATH = Path("/etc/owner-equity-research/release-canary-trust-policy-v1.json")
RELEASE_CONTROL_TRUST_POLICY_SHA256: str | None = None
GATE_NAMES = (
    "legal",
    "account_entitlement",
    "supply_chain",
    "runtime_isolation",
    "security_identity",
    "session",
    "sec_ir_reconciliation",
    "six_file_archive",
    "publisher_pdf",
)
PRIVATE_EVIDENCE_FILES = (
    "futu-keyring.json",
    "futu-private-evidence.json",
    "owner-equity-phase-receipts.json",
    "owner-equity-result.json",
    "owner-equity-typed-authorities.json",
    "valuation-run-input-receipt.json",
)
PRIVATE_EVIDENCE_DIRECTORIES = ("publication", "research-input", "six-file-archive")
MAXIMUM_PRIVATE_EVIDENCE_MEMBERS = 1024
MAXIMUM_PRIVATE_EVIDENCE_BYTES = 1024 * 1024 * 1024
REQUIRED_OWNER_PHASES = (
    "official_research",
    "futu_nonprice",
    "price_blind",
    "market_reference",
    "kernel",
    "synthesis",
    "score",
    "market_expectations",
    "report",
    "publication",
)
OWNER_PHASE_NAMES = {
    "official_research": "official_research_freeze",
    "futu_nonprice": "futu_nonprice_verification",
    "price_blind": "price_blind_refreeze",
    "market_reference": "futu_market_reference",
    "kernel": "owner_valuation_kernel",
    "synthesis": "three_panel_synthesis",
    "score": "owner_scorecard",
    "market_expectations": "futu_market_expectations",
    "report": "report",
    "publication": "publication",
}
VALUATION_ARCHIVE_MEMBERS = (
    "market-reference.json",
    "price-blind-input.json",
    "valuation-handoff.json",
    "valuation-request.json",
    "valuation-result.json",
    "valuation-run-manifest.json",
)
VALUATION_PANEL_NAMES = ("comparables", "forward_reoi", "mckinsey")
SCORE_LENSES = ("buffett", "duan_yongping", "graham", "munger")
FUTU_REQUIRED_DATA_FAMILIES = (
    "company_profile",
    "financial_statements",
    "historical_kline_quota",
    "market_price",
)
FUTU_CLOSED_RUNTIME_PROTOCOL_IDS = (
    1001,
    1002,
    1004,
    3103,
    3104,
    3202,
    3227,
    3228,
    3229,
    3230,
    3232,
    3234,
    3236,
    3243,
    3244,
    3245,
    3246,
)
DEPENDENCY_SUPPLY_AUTHORITY_PATHS = (
    ".github/workflows/ci.yml",
    "pyproject.toml",
    "sidecars/futu-opend/pyproject.toml",
    "sidecars/futu-opend/supply/dependency-lock-v1.json",
    "scripts/phase5-v1-release-dependency-lock.json",
    "scripts/phase5-v1-reviewed-artifact-metadata.json",
    "scripts/phase5-v1-release-supply-manifest.json",
    "scripts/phase5-v1-release-supply-identity.json",
    "scripts/phase5_v1_dependency_lock.py",
)
DEPENDENCY_SUPPLY_JSON_PATHS = frozenset(
    {
        "sidecars/futu-opend/supply/dependency-lock-v1.json",
        "scripts/phase5-v1-release-dependency-lock.json",
        "scripts/phase5-v1-reviewed-artifact-metadata.json",
        "scripts/phase5-v1-release-supply-manifest.json",
        "scripts/phase5-v1-release-supply-identity.json",
    }
)
DEPENDENCY_LOCK_PATH = "scripts/phase5-v1-release-dependency-lock.json"
DEPENDENCY_REVIEWED_METADATA_PATH = "scripts/phase5-v1-reviewed-artifact-metadata.json"
DEPENDENCY_SUPPLY_MANIFEST_PATH = "scripts/phase5-v1-release-supply-manifest.json"
DEPENDENCY_SUPPLY_IDENTITY_PATH = "scripts/phase5-v1-release-supply-identity.json"
DEPENDENCY_VALIDATOR_PATH = "scripts/phase5_v1_dependency_lock.py"
SIDECAR_REVIEWED_DEPENDENCY_LOCK_PATH = (
    "sidecars/futu-opend/supply/dependency-lock-v1.json"
)


class ReleaseAssemblyError(ValueError):
    """A release artifact or signed release gate failed closed."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseAssemblyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ReleaseAssemblyError(f"non-finite JSON constant: {value}")


def canonical_json_bytes(value: Any, *, newline: bool = True) -> bytes:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return encoded + (b"\n" if newline else b"")


def _dependency_canonical_json_bytes(value: Any) -> bytes:
    """Match the exact canonical format owned by the dependency-lock validator."""

    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True).encode("utf-8")
        + b"\n"
    )


def _strict_dependency_json_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseAssemblyError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseAssemblyError(f"{label} is not a JSON object")
    if raw != _dependency_canonical_json_bytes(value):
        raise ReleaseAssemblyError(f"{label} is not canonical dependency JSON")
    return value


def _read_regular(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
    protected: bool = False,
) -> bytes:
    metadata = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        initial_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        opened_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if initial_identity != opened_identity:
            raise ReleaseAssemblyError(f"{label} changed while being opened")
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ReleaseAssemblyError(f"{label} is not a regular single-link non-symlink file")
        if protected and stat.S_IMODE(before.st_mode) & 0o022:
            raise ReleaseAssemblyError(f"{label} is group- or world-writable")
        if before.st_size > maximum_bytes:
            raise ReleaseAssemblyError(f"{label} exceeds its byte limit")
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
        )
        if before_identity != after_identity or len(raw) != before.st_size:
            raise ReleaseAssemblyError(f"{label} changed while being read")
        if len(raw) > maximum_bytes:
            raise ReleaseAssemblyError(f"{label} exceeds its byte limit")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _strict_json_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseAssemblyError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseAssemblyError(f"{label} is not a JSON object")
    if raw != canonical_json_bytes(value):
        raise ReleaseAssemblyError(f"{label} is not canonical JSON")
    return value


def _strict_json_file(path: Path, *, label: str, protected: bool = False) -> dict[str, Any]:
    return _strict_json_bytes(
        _read_regular(
            path,
            label=label,
            maximum_bytes=MAXIMUM_JSON_BYTES,
            protected=protected,
        ),
        label=label,
    )


def _parse_time(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise ReleaseAssemblyError(f"{label} must be an RFC3339 UTC timestamp")
    match = RFC3339_UTC.fullmatch(value)
    if match is None:
        raise ReleaseAssemblyError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ReleaseAssemblyError(f"{label} must be an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ReleaseAssemblyError(f"{label} must be an RFC3339 UTC timestamp")
    fraction = match.group("fraction")
    replayed = parsed.strftime("%Y-%m-%dT%H:%M:%S")
    if fraction is not None:
        replayed += "." + f"{parsed.microsecond:06d}"[: len(fraction)]
    replayed += "Z"
    if replayed != value:
        raise ReleaseAssemblyError(f"{label} is not canonical")
    return parsed


def _git_identity(source_root: Path, commit: str, tree: str) -> tuple[str, str]:
    if not isinstance(commit, str) or not HEX_40.fullmatch(commit):
        raise ReleaseAssemblyError("expected commit must be a lowercase full SHA-1")
    if not isinstance(tree, str) or not HEX_40.fullmatch(tree):
        raise ReleaseAssemblyError("expected tree must be a lowercase full SHA-1")
    commit_result = subprocess.run(
        ("git", "-C", str(source_root), "rev-parse", "--verify", f"{commit}^{{commit}}"),
        check=False,
        capture_output=True,
        text=True,
    )
    tree_result = subprocess.run(
        ("git", "-C", str(source_root), "rev-parse", "--verify", f"{commit}^{{tree}}"),
        check=False,
        capture_output=True,
        text=True,
    )
    if commit_result.returncode or commit_result.stdout.strip() != commit:
        raise ReleaseAssemblyError("expected commit is unavailable from the trusted repository")
    if tree_result.returncode or tree_result.stdout.strip() != tree:
        raise ReleaseAssemblyError("expected tree does not bind the exact trusted commit")
    return commit, tree


def _git_bytes(source_root: Path, commit: str, relative: str) -> bytes:
    result = subprocess.run(
        ("git", "-C", str(source_root), "show", f"{commit}:{relative}"),
        check=False,
        capture_output=True,
    )
    if result.returncode or len(result.stdout) > MAXIMUM_JSON_BYTES:
        raise ReleaseAssemblyError(f"release source file is unavailable or oversized: {relative}")
    return result.stdout


def _git_regular_blob_bytes(
    source_root: Path,
    commit: str,
    relative: str,
    *,
    maximum_bytes: int,
) -> bytes:
    """Read one exact regular Git blob without consulting checkout bytes."""

    if relative not in DEPENDENCY_SUPPLY_AUTHORITY_PATHS:
        raise ReleaseAssemblyError("dependency supply authority path is not fixed")
    tree_entry = subprocess.run(
        ("git", "-C", str(source_root), "ls-tree", "-z", commit, "--", relative),
        check=False,
        capture_output=True,
    )
    expected_suffix = b"\t" + relative.encode("utf-8") + b"\0"
    if tree_entry.returncode or not tree_entry.stdout.endswith(expected_suffix):
        raise ReleaseAssemblyError(
            f"dependency supply authority is unavailable at exact commit: {relative}"
        )
    prefix = tree_entry.stdout[: -len(expected_suffix)]
    match = re.fullmatch(rb"100644 blob ([0-9a-f]{40})", prefix)
    if match is None:
        raise ReleaseAssemblyError(
            f"dependency supply authority is not a 100644 blob: {relative}"
        )
    blob_sha = match.group(1).decode("ascii")
    size_result = subprocess.run(
        ("git", "-C", str(source_root), "cat-file", "-s", blob_sha),
        check=False,
        capture_output=True,
        text=True,
    )
    if size_result.returncode or re.fullmatch(r"[0-9]+\n?", size_result.stdout) is None:
        raise ReleaseAssemblyError(
            f"dependency supply authority blob size is unavailable: {relative}"
        )
    size = int(size_result.stdout.strip())
    if size > maximum_bytes:
        raise ReleaseAssemblyError(
            f"dependency supply authority exceeds its byte limit: {relative}"
        )
    blob_result = subprocess.run(
        ("git", "-C", str(source_root), "cat-file", "blob", blob_sha),
        check=False,
        capture_output=True,
    )
    raw = blob_result.stdout
    object_hash = hashlib.sha1(  # noqa: S324 - this replays Git's SHA-1 object identity.
        f"blob {len(raw)}\0".encode("ascii") + raw,
        usedforsecurity=False,
    ).hexdigest()
    if blob_result.returncode or len(raw) != size or object_hash != blob_sha:
        raise ReleaseAssemblyError(
            f"dependency supply authority Git object drifted: {relative}"
        )
    return raw


def _load_release_supply_authority(
    source_root: Path,
    commit: str,
) -> dict[str, Any]:
    """Load and semantically replay all dependency authorities from one commit."""

    raw_by_path: dict[str, bytes] = {}
    total = 0
    for relative in DEPENDENCY_SUPPLY_AUTHORITY_PATHS:
        raw = _git_regular_blob_bytes(
            source_root,
            commit,
            relative,
            maximum_bytes=MAXIMUM_JSON_BYTES,
        )
        total += len(raw)
        if total > MAXIMUM_SUPPLY_AUTHORITY_BYTES:
            raise ReleaseAssemblyError(
                "dependency supply authorities exceed their cumulative byte limit"
            )
        raw_by_path[relative] = raw

    json_by_path: dict[str, dict[str, Any]] = {}
    for relative in DEPENDENCY_SUPPLY_JSON_PATHS:
        label = f"dependency supply authority {relative}"
        if relative == SIDECAR_REVIEWED_DEPENDENCY_LOCK_PATH:
            # The sidecar owns a compact canonical profile; the release-v2
            # authorities own the indented standard-library validator profile.
            json_by_path[relative] = _strict_json_bytes(
                raw_by_path[relative],
                label=label,
            )
        else:
            json_by_path[relative] = _strict_dependency_json_bytes(
                raw_by_path[relative],
                label=label,
            )
    try:
        project_by_name = {
            "owner": tomllib.loads(raw_by_path["pyproject.toml"].decode("utf-8")),
            "sidecar": tomllib.loads(
                raw_by_path["sidecars/futu-opend/pyproject.toml"].decode("utf-8")
            ),
        }
        compile(
            raw_by_path[DEPENDENCY_VALIDATOR_PATH].decode("utf-8"),
            DEPENDENCY_VALIDATOR_PATH,
            "exec",
        )
    except (UnicodeError, SyntaxError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseAssemblyError(
            f"dependency supply program or project metadata is invalid: {exc}"
        ) from exc

    expected_validation = {
        "identity_sha256": hashlib.sha256(
            raw_by_path[DEPENDENCY_SUPPLY_IDENTITY_PATH]
        ).hexdigest(),
        "lock_sha256": hashlib.sha256(raw_by_path[DEPENDENCY_LOCK_PATH]).hexdigest(),
        "supply_manifest_sha256": hashlib.sha256(
            raw_by_path[DEPENDENCY_SUPPLY_MANIFEST_PATH]
        ).hexdigest(),
    }
    with tempfile.TemporaryDirectory(prefix="owner-release-supply-") as temporary:
        isolated_root = Path(temporary)
        for relative, raw in raw_by_path.items():
            target = isolated_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            _write_file(target, raw)
            target.chmod(0o644)
        try:
            validation = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-B",
                    str(isolated_root / DEPENDENCY_VALIDATOR_PATH),
                    "validate",
                    "--repository",
                    str(isolated_root),
                ),
                check=False,
                capture_output=True,
                cwd=isolated_root,
                env={
                    "LC_ALL": "C",
                    "PATH": os.defpath,
                    "PYTHONHASHSEED": "0",
                },
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReleaseAssemblyError(
                f"exact dependency supply validator could not complete: {exc}"
            ) from exc
        expected_stdout = (
            json.dumps(expected_validation, sort_keys=True, separators=(",", ":")).encode(
                "ascii"
            )
            + b"\n"
        )
        if (
            validation.returncode != 0
            or validation.stdout != expected_stdout
            or validation.stderr
        ):
            diagnostic = validation.stderr.decode("utf-8", errors="replace")[:1000].strip()
            raise ReleaseAssemblyError(
                "exact dependency supply validator rejected the closed authorities"
                + (f": {diagnostic}" if diagnostic else "")
            )

    sha256_by_path = {
        relative: hashlib.sha256(raw).hexdigest()
        for relative, raw in raw_by_path.items()
    }
    return {
        "identity": json_by_path[DEPENDENCY_SUPPLY_IDENTITY_PATH],
        "inventory_scope": json_by_path[DEPENDENCY_LOCK_PATH]["inventory_scope"],
        "lock": json_by_path[DEPENDENCY_LOCK_PATH],
        "manifest": json_by_path[DEPENDENCY_SUPPLY_MANIFEST_PATH],
        "project_by_name": project_by_name,
        "reviewed_metadata": json_by_path[DEPENDENCY_REVIEWED_METADATA_PATH],
        "sha256_by_path": sha256_by_path,
        "sidecar_reviewed_lock": json_by_path[SIDECAR_REVIEWED_DEPENDENCY_LOCK_PATH],
    }


def _artifact_info(role: str, path: Path) -> tuple[dict[str, Any], bytes]:
    if role not in ARTIFACT_ROLES:
        raise ReleaseAssemblyError(f"unknown release artifact role: {role}")
    if path.name != str(path.name) or not SAFE_FILENAME.fullmatch(path.name):
        raise ReleaseAssemblyError(f"release artifact filename is unsafe: {path.name!r}")
    raw = _read_regular(
        path,
        label=f"release artifact {role}",
        maximum_bytes=MAXIMUM_ARTIFACT_BYTES,
    )
    return (
        {
            "media_type": ARTIFACT_TYPES[role],
            "name": path.name,
            "role": role,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        },
        raw,
    )


def _verify_distributions(
    artifacts: dict[str, Path],
    *,
    source_root: Path,
    expected_commit: str,
    expected_tree: str,
) -> None:
    checks = (
        (
            "owner wheel",
            ROOT_WHEEL_VERIFY,
            artifacts["owner_wheel"],
            {"source_root": source_root, "expected_commit": expected_commit},
        ),
        (
            "owner sdist",
            ROOT_SDIST_VERIFY,
            artifacts["owner_sdist"],
            {"source_root": source_root, "expected_commit": expected_commit},
        ),
        (
            "Plugin bundle",
            PLUGIN_VERIFY,
            artifacts["plugin_bundle"],
            {"source_root": source_root, "expected_commit": expected_commit},
        ),
        (
            "sidecar wheel",
            SIDECAR_WHEEL_VERIFY,
            artifacts["sidecar_wheel"],
            {
                "source_root": source_root,
                "expected_commit": expected_commit,
                "expected_tree": expected_tree,
            },
        ),
        (
            "sidecar sdist",
            SIDECAR_SDIST_VERIFY,
            artifacts["sidecar_sdist"],
            {
                "source_root": source_root,
                "expected_commit": expected_commit,
                "expected_tree": expected_tree,
            },
        ),
    )
    failures: list[str] = []
    for label, verifier, artifact, keywords in checks:
        errors = verifier(artifact, **keywords)
        failures.extend(f"{label}: {error}" for error in errors)
    if failures:
        raise ReleaseAssemblyError("distribution verification failed: " + "; ".join(failures))


def _closed_keys(value: Any, expected: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ReleaseAssemblyError(f"{label} shape is not closed")
    return value


def _fingerprint(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ReleaseAssemblyError(f"{label} must be a lowercase SHA-256")
    return value


def _projection_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value, newline=False)).hexdigest()


def _verify_projection_fingerprint(
    value: dict[str, Any],
    *,
    field: str,
    label: str,
) -> str:
    supplied = _fingerprint(value.get(field), label=f"{label}.{field}")
    projection = dict(value)
    projection.pop(field, None)
    if supplied != _projection_sha256(projection):
        raise ReleaseAssemblyError(f"{label} fingerprint does not replay")
    return supplied


def _positive_decimal(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"(?:[1-9][0-9]*(?:\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)",
        value,
    ):
        raise ReleaseAssemblyError(f"{label} must be a canonical positive decimal")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ReleaseAssemblyError(f"{label} must be a finite decimal") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ReleaseAssemblyError(f"{label} must be positive")
    return value


def _fingerprint_map(value: Any, names: tuple[str, ...], *, label: str) -> dict[str, str]:
    mapping = _closed_keys(value, set(names), label=label)
    for name in names:
        _fingerprint(mapping[name], label=f"{label}.{name}")
    if len(set(mapping.values())) != len(mapping):
        raise ReleaseAssemblyError(f"{label} reuses a typed fingerprint")
    return mapping


def _validity_gate(
    value: Any,
    *,
    label: str,
    executed_at: datetime,
    verification_time: datetime,
    expected_scope: str,
    expected_artifact_type: str,
    extra_keys: set[str],
) -> dict[str, Any]:
    gate = _closed_keys(
        value,
        {
            "artifact_type",
            "status",
            "scope",
            "valid_from",
            "valid_until",
            "receipt_sha256",
            *extra_keys,
        },
        label=label,
    )
    valid_from = _parse_time(gate["valid_from"], label=f"{label}.valid_from")
    valid_until = _parse_time(gate["valid_until"], label=f"{label}.valid_until")
    if (
        gate["artifact_type"] != expected_artifact_type
        or gate["status"] != "passed"
        or gate["scope"] != expected_scope
    ):
        raise ReleaseAssemblyError(f"{label} did not pass for the exact quote-only scope")
    if not (
        valid_from <= executed_at <= valid_until and valid_from <= verification_time <= valid_until
    ):
        raise ReleaseAssemblyError(f"{label} does not cover both canary execution and verification")
    _verify_projection_fingerprint(
        gate,
        field="receipt_sha256",
        label=label,
    )
    return gate


def _verify_gate_payload(
    gates_value: Any,
    *,
    executed_at: datetime,
    verification_time: datetime,
) -> dict[str, Any]:
    gates = _closed_keys(gates_value, set(GATE_NAMES), label="canary gates")
    legal = _validity_gate(
        gates["legal"],
        label="legal gate",
        executed_at=executed_at,
        verification_time=verification_time,
        expected_scope="futu_quote_only_us_equities",
        expected_artifact_type="owner-equity-canary-legal-gate-receipt",
        extra_keys={"authority_fingerprint", "revocable"},
    )
    if legal["revocable"] is not True:
        raise ReleaseAssemblyError("legal gate is not explicitly revocable")
    account = _validity_gate(
        gates["account_entitlement"],
        label="account entitlement gate",
        executed_at=executed_at,
        verification_time=verification_time,
        expected_scope="futu_quote_only_us_equities",
        expected_artifact_type=("owner-equity-canary-account-entitlement-gate-receipt"),
        extra_keys={"authority_fingerprint", "quote_only", "authorized"},
    )
    if account["quote_only"] is not True or account["authorized"] is not True:
        raise ReleaseAssemblyError("account entitlement is not authorized quote-only access")

    exact_requirements: dict[str, tuple[set[str], dict[str, Any]]] = {
        "supply_chain": (
            {
                "status",
                "artifact_type",
                "exact_commit_verified",
                "exact_tree_verified",
                "artifact_hashes_verified",
                "authority_fingerprint",
                "receipt_sha256",
            },
            {
                "status": "passed",
                "exact_commit_verified": True,
                "exact_tree_verified": True,
                "artifact_hashes_verified": True,
            },
        ),
        "runtime_isolation": (
            {
                "status",
                "artifact_type",
                "quote_protocol_allowlist_closed",
                "trade_protocols_blocked",
                "raw_data_private_encrypted_cas",
                "authority_fingerprint",
                "completed_runtime_fingerprint",
                "replay_authority_decision_fingerprint",
                "valid_from",
                "valid_until",
                "receipt_sha256",
            },
            {
                "status": "passed",
                "quote_protocol_allowlist_closed": True,
                "trade_protocols_blocked": True,
                "raw_data_private_encrypted_cas": True,
            },
        ),
        "security_identity": (
            {
                "status",
                "artifact_type",
                "security_identity_matched",
                "currency_matched",
                "share_basis_matched",
                "authority_fingerprint",
                "receipt_sha256",
            },
            {
                "status": "passed",
                "security_identity_matched": True,
                "currency_matched": True,
                "share_basis_matched": True,
            },
        ),
        "session": (
            {
                "artifact_type",
                "status",
                "qot_logined",
                "trd_logined",
                "quote_only",
                "attested_finalization_fingerprint",
                "receipt_sha256",
            },
            {
                "status": "passed",
                "qot_logined": True,
                "trd_logined": False,
                "quote_only": True,
            },
        ),
        "sec_ir_reconciliation": (
            {
                "artifact_type",
                "status",
                "sec_ir_primary",
                "material_conflicts",
                "cross_check_root_fingerprint",
                "receipt_sha256",
            },
            {"status": "passed", "sec_ir_primary": True, "material_conflicts": 0},
        ),
        "six_file_archive": (
            {
                "artifact_type",
                "status",
                "strict_reload",
                "member_count",
                "hashes_verified",
                "archive_fingerprint",
                "receipt_sha256",
            },
            {
                "status": "passed",
                "strict_reload": True,
                "member_count": 6,
                "hashes_verified": True,
            },
        ),
        "publisher_pdf": (
            {
                "status",
                "artifact_type",
                "profile",
                "strict_package_reload",
                "pdf_reload",
                "pdf_pages",
                "target_price_present",
                "scorecard_present",
                "publication_manifest_fingerprint",
                "receipt_sha256",
            },
            {
                "status": "passed",
                "profile": "full_valuation",
                "strict_package_reload": True,
                "pdf_reload": True,
                "target_price_present": True,
                "scorecard_present": True,
            },
        ),
    }
    for name, (keys, requirements) in exact_requirements.items():
        gate = _closed_keys(gates[name], keys, label=f"{name} gate")
        if gate.get(
            "artifact_type"
        ) != f"owner-equity-canary-{name.replace('_', '-')}-gate-receipt" or any(
            gate.get(key) != expected for key, expected in requirements.items()
        ):
            raise ReleaseAssemblyError(f"{name} gate did not explicitly pass")
        _verify_projection_fingerprint(
            gate,
            field="receipt_sha256",
            label=f"{name} gate",
        )
    protocol = gates["runtime_isolation"]
    protocol_valid_from = _parse_time(
        protocol["valid_from"], label="runtime_isolation gate.valid_from"
    )
    protocol_valid_until = _parse_time(
        protocol["valid_until"], label="runtime_isolation gate.valid_until"
    )
    if not (
        protocol_valid_from <= executed_at <= protocol_valid_until
        and protocol_valid_from <= verification_time <= protocol_valid_until
    ):
        raise ReleaseAssemblyError(
            "runtime isolation protocol authority does not cover execution and verification"
        )
    pages = gates["publisher_pdf"]["pdf_pages"]
    if not isinstance(pages, int) or isinstance(pages, bool) or not 30 <= pages <= 60:
        raise ReleaseAssemblyError("publisher PDF page count is outside the 30-60 page contract")
    return gates


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _capture_regular_at(
    directory_descriptor: int,
    name: str,
    *,
    label: str,
    maximum_bytes: int,
) -> tuple[bytes, tuple[int, ...]]:
    initial = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_descriptor,
    )
    try:
        before = os.fstat(descriptor)
        if _stat_identity(initial) != _stat_identity(before):
            raise ReleaseAssemblyError(f"{label} changed while being opened")
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o222
            or before.st_uid != os.geteuid()
        ):
            raise ReleaseAssemblyError(f"{label} is not a protected single-link file")
        if before.st_size > maximum_bytes:
            raise ReleaseAssemblyError(f"{label} exceeds its byte limit")
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if (
            _stat_identity(before) != _stat_identity(after)
            or len(raw) != before.st_size
            or len(raw) > maximum_bytes
        ):
            raise ReleaseAssemblyError(f"{label} changed or exceeded its limit")
        return bytes(raw), _stat_identity(after)
    finally:
        os.close(descriptor)


def _capture_directory_at(
    parent_descriptor: int,
    name: str,
    *,
    destination: Path,
    label: str,
    budget: dict[str, int],
) -> tuple[int, ...]:
    initial = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=parent_descriptor,
    )
    try:
        before = os.fstat(descriptor)
        if _stat_identity(initial) != _stat_identity(before):
            raise ReleaseAssemblyError(f"{label} changed while being opened")
        if (
            not stat.S_ISDIR(before.st_mode)
            or stat.S_IMODE(before.st_mode) & 0o222
            or before.st_uid != os.geteuid()
        ):
            raise ReleaseAssemblyError(
                f"strict reload failed: {label} is not a protected directory"
            )
        names = tuple(sorted(os.listdir(descriptor)))
        destination.mkdir(mode=0o700)
        for member in names:
            if member in {"", ".", ".."} or "/" in member or "\x00" in member:
                raise ReleaseAssemblyError(f"{label} contains an unsafe member name")
            details = os.stat(member, dir_fd=descriptor, follow_symlinks=False)
            budget["members"] += 1
            if budget["members"] > MAXIMUM_PRIVATE_EVIDENCE_MEMBERS:
                raise ReleaseAssemblyError("private canary evidence has too many members")
            child_label = f"{label}/{member}"
            if stat.S_ISDIR(details.st_mode):
                _capture_directory_at(
                    descriptor,
                    member,
                    destination=destination / member,
                    label=child_label,
                    budget=budget,
                )
                continue
            raw, _identity = _capture_regular_at(
                descriptor,
                member,
                label=child_label,
                maximum_bytes=MAXIMUM_ARTIFACT_BYTES,
            )
            budget["bytes"] += len(raw)
            if budget["bytes"] > MAXIMUM_PRIVATE_EVIDENCE_BYTES:
                raise ReleaseAssemblyError("private canary evidence exceeds its byte limit")
            _write_file(destination / member, raw)
        after = os.fstat(descriptor)
        if tuple(sorted(os.listdir(descriptor))) != names or _stat_identity(after) != (
            _stat_identity(before)
        ):
            raise ReleaseAssemblyError(f"{label} changed while being captured")
        os.chmod(destination, 0o555)
        return _stat_identity(after)
    finally:
        os.close(descriptor)


@contextmanager
def _captured_private_evidence(path: Path):
    root = Path(path).expanduser().absolute()
    initial = root.lstat()
    descriptor = os.open(
        root,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        opened = os.fstat(descriptor)
        if _stat_identity(initial) != _stat_identity(opened):
            raise ReleaseAssemblyError("private canary evidence root changed while opening")
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) & 0o222
            or opened.st_uid != os.geteuid()
        ):
            raise ReleaseAssemblyError(
                "strict reload failed: private canary evidence root is unsafe"
            )
        expected = set(PRIVATE_EVIDENCE_FILES) | set(PRIVATE_EVIDENCE_DIRECTORIES)
        names = tuple(sorted(os.listdir(descriptor)))
        if set(names) != expected:
            raise ReleaseAssemblyError("private canary evidence member set is not closed")
        temporary = tempfile.TemporaryDirectory(prefix="owner-canary-evidence-")
        # macOS exposes its temporary root through ``/var`` -> ``/private/var``.
        # Strict archive/package reloaders correctly reject every symlink ancestor,
        # so retain and populate the already-created temporary directory by its
        # physical path instead of leaking the logical alias into replay.
        snapshot = Path(temporary.name).resolve(strict=True) / "evidence"
        snapshot.mkdir(mode=0o700)
        budget = {"bytes": 0, "members": 0}
        directories: dict[str, tuple[int, ...]] = {}
        top_file_sha256: dict[str, str] = {}
        for name in names:
            budget["members"] += 1
            if name in PRIVATE_EVIDENCE_DIRECTORIES:
                directories[name] = _capture_directory_at(
                    descriptor,
                    name,
                    destination=snapshot / name,
                    label=f"private evidence {name}",
                    budget=budget,
                )
                continue
            raw, _identity = _capture_regular_at(
                descriptor,
                name,
                label=f"private evidence {name}",
                maximum_bytes=MAXIMUM_JSON_BYTES,
            )
            budget["bytes"] += len(raw)
            if budget["bytes"] > MAXIMUM_PRIVATE_EVIDENCE_BYTES:
                raise ReleaseAssemblyError("private canary evidence exceeds its byte limit")
            top_file_sha256[name] = hashlib.sha256(raw).hexdigest()
            _write_file(snapshot / name, raw)
        after = os.fstat(descriptor)
        if tuple(sorted(os.listdir(descriptor))) != names or _stat_identity(after) != (
            _stat_identity(opened)
        ):
            raise ReleaseAssemblyError("private canary evidence root changed during capture")
        current = root.lstat()
        if _stat_identity(current) != _stat_identity(opened):
            raise ReleaseAssemblyError("private canary evidence path was rebound")
        os.chmod(snapshot, 0o555)
        yield {
            "directory_identities": directories,
            "original_root": root,
            "root_identity": _stat_identity(after),
            "snapshot_root": snapshot,
            "top_file_sha256": top_file_sha256,
        }
    finally:
        os.close(descriptor)
        if temporary is not None:
            temporary.cleanup()


def _load_owner_result(payload: dict[str, Any]) -> tuple[Any, dict[str, dict[str, Any]]]:
    from owner_research.owner_equity_research import (
        OwnerEquityResearchInputReceipt,
        validate_owner_equity_research_result_projection,
    )

    validate_owner_equity_research_result_projection(payload)
    input_receipt = OwnerEquityResearchInputReceipt.from_dict(payload["input_receipt"])
    identity = dict(payload)
    supplied_id = identity.pop("result_id")
    supplied_fingerprint = identity.pop("result_fingerprint")
    if supplied_fingerprint != _projection_sha256(identity) or supplied_id != (
        f"owner-equity-research-result:{input_receipt.request.issuer_id}:"
        f"{supplied_fingerprint[:24]}"
    ):
        raise ReleaseAssemblyError("owner-equity result identity does not replay")
    request = input_receipt.request
    phases = payload["phases"]
    required = set(REQUIRED_OWNER_PHASES)
    completed = {
        name
        for name, value in phases.items()
        if isinstance(value, dict) and value.get("status") == "completed"
    }
    if (
        payload["status"] != "completed"
        or payload["issue_codes"]
        or payload["quarantine_receipt"] is not None
        or request.intent.value not in {"valuation", "publish"}
        or request.profile.value != "full_valuation"
        or completed != required
        or phases["quarterly"] is not None
        or phases["audit"] is not None
    ):
        raise ReleaseAssemblyError("owner-equity result is not a completed full valuation")
    expected_trace = [OWNER_PHASE_NAMES[name] for name in REQUIRED_OWNER_PHASES]
    if payload["trace"] != [
        {"sequence": index, "phase": phase, "status": "completed"}
        for index, phase in enumerate(expected_trace, 1)
    ]:
        raise ReleaseAssemblyError("owner-equity result trace is not the closed valuation route")
    return input_receipt, {name: phases[name] for name in REQUIRED_OWNER_PHASES}


def _load_phase_receipts(
    payload: dict[str, Any],
    *,
    input_receipt: Any,
    result_phases: dict[str, dict[str, Any]],
    expected_authorities: dict[str, tuple[str, ...]],
) -> tuple[dict[str, dict[str, Any]], str]:
    from owner_research.owner_equity_research import (
        validate_owner_equity_research_schema_payload,
    )

    envelope = _closed_keys(
        payload,
        {
            "artifact_type",
            "input_receipt_fingerprint",
            "input_receipt_id",
            "receipts",
            "schema_version",
            "set_fingerprint",
        },
        label="owner-equity phase receipt set",
    )
    if (
        envelope["artifact_type"] != "owner-equity-research-phase-receipt-set"
        or envelope["schema_version"] != "1.0.0"
        or envelope["input_receipt_id"] != input_receipt.receipt_id
        or envelope["input_receipt_fingerprint"] != input_receipt.fingerprint
    ):
        raise ReleaseAssemblyError("owner-equity phase receipt set changed input identity")
    _verify_projection_fingerprint(
        envelope,
        field="set_fingerprint",
        label="owner-equity phase receipt set",
    )
    receipts_value = envelope["receipts"]
    if not isinstance(receipts_value, list) or len(receipts_value) != len(REQUIRED_OWNER_PHASES):
        raise ReleaseAssemblyError("owner-equity phase receipt count is incomplete")
    receipts: dict[str, dict[str, Any]] = {}
    expected_phases = set(OWNER_PHASE_NAMES.values())
    for item in receipts_value:
        validate_owner_equity_research_schema_payload("owner-equity-research-phase-receipt", item)
        assert isinstance(item, dict)
        phase = item["phase"]
        if phase in receipts or phase not in expected_phases:
            raise ReleaseAssemblyError("owner-equity phase receipt inventory is invalid")
        identity = {
            "phase": phase,
            "input_receipt_id": item["input_receipt_id"],
            "input_receipt_fingerprint": item["input_receipt_fingerprint"],
            "upstream_receipt_ids": item["upstream_receipt_ids"],
            "authority_fingerprints": item["authority_fingerprints"],
        }
        expected_id = f"owner-research-phase:{phase}:{_projection_sha256(identity)[:24]}"
        if (
            item["receipt_id"] != expected_id
            or item["input_receipt_id"] != input_receipt.receipt_id
            or item["input_receipt_fingerprint"] != input_receipt.fingerprint
        ):
            raise ReleaseAssemblyError("owner-equity phase receipt identity does not replay")
        short_name = next(name for name, value in OWNER_PHASE_NAMES.items() if value == phase)
        actual_authorities = tuple(item["authority_fingerprints"])
        expected = expected_authorities[short_name]
        if actual_authorities != expected:
            raise ReleaseAssemblyError(
                f"owner-equity phase receipt rebound typed authorities: {short_name}"
            )
        for fingerprint in actual_authorities:
            _fingerprint(fingerprint, label=f"{phase} authority fingerprint")
        receipts[phase] = item
    upstream_names = {
        "official_research": (),
        "futu_nonprice": ("official_research",),
        "price_blind": ("official_research", "futu_nonprice"),
        "market_reference": ("price_blind", "futu_nonprice"),
        "kernel": ("price_blind", "market_reference"),
        "synthesis": ("price_blind", "market_reference", "kernel"),
        "score": ("synthesis",),
        "market_expectations": ("market_reference", "synthesis", "score"),
        "report": (
            "official_research",
            "price_blind",
            "market_reference",
            "kernel",
            "synthesis",
            "score",
            "market_expectations",
        ),
        "publication": (
            "official_research",
            "price_blind",
            "kernel",
            "synthesis",
            "score",
            "market_expectations",
            "report",
        ),
    }
    for name in REQUIRED_OWNER_PHASES:
        phase = OWNER_PHASE_NAMES[name]
        receipt = receipts[phase]
        expected_upstream = [
            receipts[OWNER_PHASE_NAMES[upstream]]["receipt_id"] for upstream in upstream_names[name]
        ]
        if receipt["upstream_receipt_ids"] != expected_upstream:
            raise ReleaseAssemblyError("owner-equity phase causal chain was rebound")
        result = result_phases[name]
        if (
            result["receipt_id"] != receipt["receipt_id"]
            or result["receipt_fingerprint"] != _projection_sha256(receipt)
            or result["issue_codes"]
        ):
            raise ReleaseAssemblyError("owner-equity result rebound a phase receipt")
    if (
        receipts[OWNER_PHASE_NAMES["kernel"]]["authority_fingerprints"][0]
        != receipts[OWNER_PHASE_NAMES["synthesis"]]["authority_fingerprints"][0]
    ):
        raise ReleaseAssemblyError("kernel and synthesis receipts rebound the valuation run")
    return receipts, envelope["set_fingerprint"]


def _load_valuation_input(payload: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "authority_fingerprint",
        "candidate_compilation_fingerprint",
        "clock_fingerprint",
        "component_lock_sha256",
        "data_cutoff_date",
        "expected_freeze_fingerprint",
        "expected_security_fingerprint",
        "graph_fingerprint",
        "issuer_id",
        "price_blind_input_fingerprint",
        "receipt_id",
        "research_bundle_set_sha256",
        "run_manifest_set_sha256",
        "runtime_manifest_authority",
    }
    value = _closed_keys(payload, expected, label="valuation run input receipt")
    for field in expected - {
        "data_cutoff_date",
        "issuer_id",
        "receipt_id",
        "runtime_manifest_authority",
    }:
        _fingerprint(value[field], label=f"valuation input.{field}")
    runtime = _closed_keys(
        value["runtime_manifest_authority"],
        {"status", "manifest_payload"},
        label="valuation runtime manifest authority",
    )
    manifest = runtime["manifest_payload"]
    if runtime["status"] != "verified" or not isinstance(manifest, dict):
        raise ReleaseAssemblyError("valuation run did not retain verified runtime supply")
    manifest_projection = dict(manifest)
    supplied_manifest_fingerprint = manifest_projection.pop("manifest_fingerprint", None)
    if (
        supplied_manifest_fingerprint != _projection_sha256(manifest_projection)
        or manifest.get("transport", {}).get("kernel_call_count") != 1
    ):
        raise ReleaseAssemblyError("valuation runtime supply does not bind one kernel call")
    expected_authority = _projection_sha256(
        {
            "expected_freeze_fingerprint": value["expected_freeze_fingerprint"],
            "expected_security_fingerprint": value["expected_security_fingerprint"],
            "runtime_manifest_authority_fingerprint": _projection_sha256(runtime),
        }
    )
    identity = dict(value)
    supplied_id = identity.pop("receipt_id")
    if (
        value["authority_fingerprint"] != expected_authority
        or supplied_id
        != f"valuation-run-input-receipt:{value['issuer_id']}:{_projection_sha256(identity)[:24]}"
    ):
        raise ReleaseAssemblyError("valuation run input receipt does not replay")
    return value


def _reference_set(values: Any, *, label: str) -> set[tuple[str, str]]:
    if not isinstance(values, (list, tuple)):
        raise ReleaseAssemblyError(f"{label} is not a typed reference array")
    output: set[tuple[str, str]] = set()
    for item in values:
        if not isinstance(item, dict) or set(item) != {"object_id", "fingerprint"}:
            raise ReleaseAssemblyError(f"{label} contains an invalid typed reference")
        reference = (item["object_id"], _fingerprint(item["fingerprint"], label=label))
        if reference in output:
            raise ReleaseAssemblyError(f"{label} repeats a typed reference")
        output.add(reference)
    return output


def _published_research_authority_fingerprint(package: Any) -> str:
    from owner_research.fingerprints import canonical_sha256, to_json_value

    files = to_json_value(package.file_sha256)
    research_files = {
        name: files[f"research/{name}"] for name in ("research-bundle.json", "run-manifest.json")
    }
    return canonical_sha256(
        {
            "source_directory": str(package.output_directory / "research"),
            "bundle_fingerprint": package.research.bundle.fingerprint,
            "manifest_fingerprint": package.research.run_manifest.fingerprint,
            "file_sha256": research_files,
        }
    )


def _captured_research_authority_fingerprint(
    *,
    snapshot_root: Path,
    original_root: Path,
    package: Any,
) -> str:
    from owner_research.fingerprints import canonical_sha256, to_json_value

    names = ("research-bundle.json", "run-manifest.json")
    source = snapshot_root / "research-input"
    if tuple(sorted(item.name for item in source.iterdir())) != tuple(sorted(names)):
        raise ReleaseAssemblyError("captured research input member set is not closed")
    files = to_json_value(package.file_sha256)
    captured_hashes: dict[str, str] = {}
    for name in names:
        raw = _read_regular(
            source / name,
            label=f"captured research input {name}",
            maximum_bytes=MAXIMUM_JSON_BYTES,
            protected=True,
        )
        captured_hashes[name] = hashlib.sha256(raw).hexdigest()
        if captured_hashes[name] != files[f"research/{name}"]:
            raise ReleaseAssemblyError(
                "captured original research differs from the published strict copy"
            )
    return canonical_sha256(
        {
            "source_directory": str(original_root / "research-input"),
            "bundle_fingerprint": package.research.bundle.fingerprint,
            "manifest_fingerprint": package.research.run_manifest.fingerprint,
            "file_sha256": captured_hashes,
        }
    )


def _replay_market_calendar_selection(
    payload: dict[str, Any],
    *,
    request: Any,
    component_lock_path: Path,
) -> Any:
    from datetime import date

    from owner_research.valuation_market_authority import load_market_access_authority
    from owner_research.valuation_market_authority_types import TradingSession
    from owner_research.valuation_market_calendar import (
        CalendarSelection,
        select_latest_completed_session,
    )

    calendar_payload = _closed_keys(
        payload,
        {
            "calendar_id",
            "coverage_end",
            "coverage_start",
            "dataset_sha256",
            "mic",
            "official_source_record_sha256",
            "official_source_url",
            "session",
        },
        label="market calendar selection",
    )
    session_payload = _closed_keys(
        calendar_payload["session"],
        {"closed_at", "early_close", "mic", "opened_at", "trading_date"},
        label="market calendar session",
    )
    try:
        retained = CalendarSelection(
            **{key: item for key, item in calendar_payload.items() if key != "session"},
            session=TradingSession(**session_payload),
        )
        replayed = select_latest_completed_session(
            load_market_access_authority(component_lock_path),
            mic=request.mic,
            cutoff_date=date.fromisoformat(request.data_cutoff_date),
            observed_at=_parse_time(
                request.request_started_at,
                label="market request_started_at",
            ),
        )
    except (TypeError, ValueError) as exc:
        raise ReleaseAssemblyError("market calendar selection does not replay") from exc
    if (
        retained.to_dict() != replayed.to_dict()
        or request.expected_trading_date != replayed.session.trading_date
    ):
        raise ReleaseAssemblyError("market calendar selection does not replay")
    return replayed


def _load_typed_canary_authorities(
    payload: dict[str, Any],
    *,
    archive: Any,
    valuation_input: dict[str, Any],
    futu: dict[str, Any],
    market_execution_fingerprint: str,
    snapshot_root: Path,
    original_archive_directory: Path,
    archive_directory_identity: tuple[int, ...],
) -> dict[str, Any]:
    from dataclasses import fields

    from owner_research.contracts import contract_from_dict
    from owner_research.fingerprints import canonical_sha256, to_json_value
    from owner_research.futu_session import finalize_futu_market_execution_evidence
    from owner_research.futu_sidecar import FutuDailyCloseAdapterResult
    from owner_research.valuation_current_share_compiler import (
        compile_quote_date_current_common_shares,
    )
    from owner_research.valuation_final_request import _compile_fact_ledger
    from owner_research.valuation_futu_market import (
        FUTU_MARKET_PROVIDER_ID,
        FutuMarketAuthorizationTicket,
        FutuMarketProviderRegistration,
        FutuMarketReferenceAcquisition,
        _governed_access,
        _provider_registry_sha256,
        bind_futu_market_reference_provider,
        build_futu_market_reference_snapshot,
    )
    from owner_research.valuation_kernel_projection import (
        CurrentShareKernelProjection,
        KernelNumericProjectionWitness,
    )
    from owner_research.valuation_market_access import (
        GovernedMarketQuoteReceipt,
        MarketAccessResult,
        MarketProviderQuery,
    )
    from owner_research.valuation_market_execution_types import (
        FinalRequestCompilationReceipt,
        KernelExecutionReceipt,
        MarketQuoteReceipt,
        MarketQuoteRequest,
    )
    from owner_research.valuation_market_provider import (
        MarketAuthorizationConsumption,
        MarketAuthorizationReservation,
        MarketReferenceRequest,
    )
    from owner_research.valuation_owner_execution import _kernel_execution_receipt
    from owner_research.valuation_pinned_kernel import PinnedKernelExecutionResult

    value = _closed_keys(
        payload,
        {
            "artifact_type",
            "final_request_execution_evidence",
            "final_request_receipt",
            "kernel_execution_evidence",
            "kernel_execution_receipt",
            "market_provider",
            "market_ticket",
            "prepared_market_reference",
            "schema_version",
            "valuation_run_context",
        },
        label="typed canary authorities",
    )
    if (
        value["artifact_type"] != "owner-equity-canary-typed-authorities"
        or value["schema_version"] != "1.0.0"
    ):
        raise ReleaseAssemblyError("typed canary authority envelope is invalid")
    ticket = _closed_keys(
        value["market_ticket"],
        {
            "authority_decision",
            "authority_receipt_fingerprints",
            "calendar_selection",
            "contract_graph_fingerprint",
            "expected_freeze_fingerprint",
            "expected_freeze_result_fingerprint",
            "expected_security_fingerprint",
            "expected_security_result_fingerprint",
            "market_quote_request",
            "provider_registry_sha256",
            "registration",
            "request",
            "reservation",
            "security_identity_fingerprint",
            "supply_chain_fingerprint",
        },
        label="Futu market ticket projection",
    )
    provider = _closed_keys(
        value["market_provider"],
        {"daily_close", "market_execution_evidence_fingerprint", "ticket_fingerprint"},
        label="Futu market provider projection",
    )
    prepared = _closed_keys(
        value["prepared_market_reference"],
        {
            "current_shares",
            "market_equity_calculation",
            "market_source",
            "quote_fact",
            "snapshot",
        },
        label="prepared market reference projection",
    )
    valuation_run_context = value["valuation_run_context"]
    if not isinstance(valuation_run_context, dict):
        raise ReleaseAssemblyError("valuation run context projection is not an object")
    from owner_research.valuation_assumption_types import (
        AssumptionCandidateCompilationResult,
    )
    from owner_research.valuation_run import (
        RuntimeManifestInputAuthority,
        ValuationRunInputReceipt,
    )
    from owner_research.valuation_run_context import load_valuation_run_input_context

    try:
        with tempfile.TemporaryDirectory(prefix="owner-canary-run-context-") as temporary:
            context_file = Path(temporary) / "valuation-run-input.json"
            _write_file(context_file, canonical_json_bytes(valuation_run_context))
            replayed_context = load_valuation_run_input_context(
                context_file,
                price_blind_artifact_directory=snapshot_root / "six-file-archive",
            )
        for name in ("research-bundle.json", "run-manifest.json"):
            retained = replayed_context.research_bundle_contents.get(name)
            captured = _read_regular(
                snapshot_root / "research-input" / name,
                label=f"captured valuation context {name}",
                maximum_bytes=MAXIMUM_JSON_BYTES,
                protected=True,
            )
            if retained != captured:
                raise ReleaseAssemblyError(
                    "valuation context differs from the captured original research input"
                )
        candidate_payload = to_json_value(
            replayed_context.expected_freeze.artifact.payload["assumption_candidates"]
        )
        candidate_compilation = AssumptionCandidateCompilationResult(
            **{key: item for key, item in candidate_payload.items() if key != "candidates"},
            candidates=replayed_context.expected_freeze.candidates,
        )
        runtime_manifest_authority = RuntimeManifestInputAuthority(
            **valuation_input["runtime_manifest_authority"]
        )
        replayed_input_receipt = ValuationRunInputReceipt(
            receipt_id=valuation_input["receipt_id"],
            issuer_id=valuation_input["issuer_id"],
            data_cutoff_date=valuation_input["data_cutoff_date"],
            component_lock_sha256=valuation_input["component_lock_sha256"],
            graph=replayed_context.graph,
            candidate_compilation=candidate_compilation,
            expected_freeze=replayed_context.expected_freeze,
            expected_security=replayed_context.expected_security,
            runtime_manifest_authority=runtime_manifest_authority,
            clock=replayed_context.clock,
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ReleaseAssemblyError):
            raise
        raise ReleaseAssemblyError("valuation run typed input authority does not replay") from exc
    if replayed_input_receipt.to_dict() != valuation_input:
        raise ReleaseAssemblyError("valuation run input receipt contains a free or rebound hash")
    from owner_research.futu_crosscheck import (
        build_official_evidence_operand,
        crosscheck_vendor_observation,
    )

    graph_objects: dict[tuple[str, str], Any] = {}
    for field_name, object_type, identifier_name in (
        ("documents", "SourceDocument", "document_id"),
        ("facts", "Fact", "fact_id"),
        ("claims", "Claim", "claim_id"),
    ):
        for item in getattr(replayed_context.graph, field_name):
            key = (object_type, getattr(item, identifier_name))
            if key in graph_objects:
                raise ReleaseAssemblyError("valuation context graph reuses an official object ID")
            graph_objects[key] = item
    vendor_observations = {item.observation_id: item for item in futu["observations"]}
    replayed_official_operands = []
    freeze_transitions = tuple(
        _parse_time(
            item.transitioned_at,
            label="price-blind freeze transition",
        )
        for item in replayed_context.expected_freeze.handoffs
    )
    if not freeze_transitions:
        raise ReleaseAssemblyError("valuation context lacks a price-blind freeze transition")
    final_freeze_transition = max(freeze_transitions)
    for receipt in futu["cross_checks"]:
        official_object = graph_objects.get(
            (receipt.official_object_type, receipt.official_object_id)
        )
        vendor = vendor_observations.get(receipt.vendor_observation_id)
        if official_object is None or vendor is None:
            raise ReleaseAssemblyError(
                "Futu cross-check authority is outside the replayed valuation context"
            )
        try:
            official = build_official_evidence_operand(
                graph=replayed_context.graph,
                official_object=official_object,
            )
            replayed_cross_check = crosscheck_vendor_observation(
                graph=replayed_context.graph,
                official=official,
                vendor=vendor,
                created_at=receipt.created_at,
            )
        except (TypeError, ValueError) as exc:
            raise ReleaseAssemblyError(
                "Futu cross-check did not replay against its official SEC/IR object"
            ) from exc
        if (
            replayed_cross_check.to_dict() != receipt.to_dict()
            or _parse_time(
                receipt.created_at,
                label="Futu cross-check created_at",
            )
            > final_freeze_transition
        ):
            raise ReleaseAssemblyError(
                "Futu cross-check did not replay against its official SEC/IR object"
            )
        replayed_official_operands.append(official)
    split_concepts = {"stock_split_completed", "reverse_stock_split_completed"}
    official_split_facts = tuple(
        item
        for item in replayed_context.graph.facts
        if item.issuer_id == archive.handoff.issuer_id
        and item.concept in split_concepts
        and item.value_type == "number"
        and item.unit == "ratio"
        and item.currency is None
    )
    vendor_split_ids = {item.observation_id for item in futu["split_observations"]}
    split_cross_checks = tuple(
        item
        for item in futu["cross_checks"]
        if item.vendor_observation_id in vendor_split_ids
    )
    if (
        len(official_split_facts) != len(vendor_split_ids)
        or len(split_cross_checks) != len(vendor_split_ids)
        or {item.fact_id for item in official_split_facts}
        != {
            item.official_object_id
            for item in split_cross_checks
            if item.official_object_type == "Fact"
        }
        or (not official_split_facts)
        != (futu["empty_split_disposition"] is not None)
    ):
        raise ReleaseAssemblyError(
            "Futu and SEC/IR split-event sets are not bidirectionally closed"
        )
    registration_payload = _closed_keys(
        ticket.get("registration"),
        set(FutuMarketProviderRegistration.__dataclass_fields__),
        label="Futu market provider registration",
    )
    registration_payload = dict(registration_payload)
    for name in ("supported_mics", "supported_currencies"):
        values = registration_payload.get(name)
        if not isinstance(values, list) or any(type(item) is not str for item in values):
            raise ReleaseAssemblyError(
                f"Futu market provider registration {name} is not a JSON string array"
            )
        registration_payload[name] = tuple(values)
    try:
        market_request = MarketReferenceRequest(**ticket["request"])
        quote_request = MarketQuoteRequest(**ticket["market_quote_request"])
        registration = FutuMarketProviderRegistration(**registration_payload)
        reservation = MarketAuthorizationReservation(**ticket["reservation"])
        daily_close = FutuDailyCloseAdapterResult(**provider["daily_close"])
        snapshot = contract_from_dict("market-reference-snapshot", prepared["snapshot"])
        market_source = contract_from_dict("source-document", prepared["market_source"])
        quote_fact = contract_from_dict("fact", prepared["quote_fact"])
        market_calculation = contract_from_dict(
            "calculation-result",
            prepared["market_equity_calculation"],
        )
        replayed_calendar = _replay_market_calendar_selection(
            ticket["calendar_selection"],
            request=market_request,
            component_lock_path=replayed_context.graph.component_lock_path,
        )
    except (TypeError, ValueError) as exc:
        raise ReleaseAssemblyError("typed market authorities do not reconstruct") from exc
    manifest = to_json_value(archive.manifest)
    request_payload = to_json_value(archive.request_payload)
    try:
        final_receipt_input = value["final_request_receipt"]
        kernel_receipt_input = value["kernel_execution_receipt"]
        final_receipt = FinalRequestCompilationReceipt(**final_receipt_input).to_dict()
        kernel_receipt = KernelExecutionReceipt(**kernel_receipt_input).to_dict()
        final_execution_input = _closed_keys(
            value["final_request_execution_evidence"],
            {
                "current_share_projection",
                "market_execution_evidence",
                "numeric_projection",
                "vendor_market_acquisition",
            },
            label="final-request execution evidence",
        )
        share_projection_input = final_execution_input["current_share_projection"]
        share_projection_values = dict(share_projection_input)
        share_projection_values["numeric_witnesses"] = tuple(
            KernelNumericProjectionWitness(**item)
            for item in share_projection_values["numeric_witnesses"]
        )
        share_projection = CurrentShareKernelProjection(
            **share_projection_values
        )
        numeric_projection_input = _closed_keys(
            final_execution_input["numeric_projection"],
            {
                "current_share_numeric_witnesses",
                "quote_projection_witness",
                "market_equity_projection_witness",
            },
            label="final-request numeric projection evidence",
        )
        current_share_numeric_witnesses = tuple(
            KernelNumericProjectionWitness(**item)
            for item in numeric_projection_input["current_share_numeric_witnesses"]
        )
        quote_projection_witness = KernelNumericProjectionWitness(
            **numeric_projection_input["quote_projection_witness"]
        )
        market_equity_projection_witness = KernelNumericProjectionWitness(
            **numeric_projection_input["market_equity_projection_witness"]
        )
        numeric_projection = {
            "current_share_numeric_witnesses": [
                item.to_dict() for item in current_share_numeric_witnesses
            ],
            "quote_projection_witness": quote_projection_witness.to_dict(),
            "market_equity_projection_witness": (
                market_equity_projection_witness.to_dict()
            ),
        }
        vendor_acquisition_input = _closed_keys(
            final_execution_input["vendor_market_acquisition"],
            {
                "access_result",
                "authorization_consumption",
                "daily_close_adapter_fingerprint",
                "execution_bundle_fingerprint",
                "market_execution_evidence_fingerprint",
                "observation_fingerprint",
                "request_fingerprint",
                "response_fingerprint",
                "ticket_fingerprint",
            },
            label="vendor market acquisition evidence",
        )
        access_input = _closed_keys(
            vendor_acquisition_input["access_result"],
            set(MarketAccessResult.__dataclass_fields__),
            label="vendor market access result",
        )
        governed_input = _closed_keys(
            access_input["receipt"],
            set(GovernedMarketQuoteReceipt.__dataclass_fields__),
            label="governed market quote receipt",
        )
        access_query = MarketProviderQuery(**access_input["query"])
        access_request = MarketQuoteRequest(**access_input["request"])
        governed_receipt = GovernedMarketQuoteReceipt(
            **{key: item for key, item in governed_input.items() if key != "receipt"},
            receipt=MarketQuoteReceipt(**governed_input["receipt"]),
        )
        market_access_result = MarketAccessResult(
            **{
                key: item
                for key, item in access_input.items()
                if key not in {"issue_codes", "query", "receipt", "request"}
            },
            issue_codes=tuple(access_input["issue_codes"]),
            query=access_query,
            request=access_request,
            receipt=governed_receipt,
        )
        authorization_consumption = MarketAuthorizationConsumption(
            **vendor_acquisition_input["authorization_consumption"]
        )
        vendor_acquisition = {
            **{
                key: item
                for key, item in vendor_acquisition_input.items()
                if key not in {"access_result", "authorization_consumption"}
            },
            "access_result": market_access_result.to_dict(),
            "authorization_consumption": authorization_consumption.to_dict(),
        }
        market_execution_input = final_execution_input[
            "market_execution_evidence"
        ]
        market_execution_evidence = finalize_futu_market_execution_evidence(
            authority_set=futu["_pre_runtime_authority_set"],
            authority_decision=futu["_authority_decision_object"],
            executions=(
                futu["_target_executions_by_stage"][
                    "valuation_pre_price_verification"
                ],
                futu["_target_executions_by_stage"]["market_reference"],
            ),
            contract_graph=replayed_context.graph,
            official_operands=tuple(replayed_official_operands),
            cross_checks=futu["cross_checks"],
            checkpoint_at=market_execution_input["checkpoint_at"],
            verifier=futu["_verifier"],
        )
        replayed_ticket = FutuMarketAuthorizationTicket(
            request=market_request,
            market_quote_request=quote_request,
            calendar_selection=replayed_calendar,
            registration=registration,
            provider_registry_sha256=ticket["provider_registry_sha256"],
            authority_set=futu["_pre_runtime_authority_set"],
            authority_decision=futu["_authority_decision_object"],
            security_identity=futu["_pre_runtime_authority_set"].security_identity,
            supply_chain=futu["_pre_runtime_authority_set"].supply_chain,
            expected_freeze_result=replayed_context.expected_freeze,
            expected_security_result=replayed_context.expected_security,
            contract_graph=replayed_context.graph,
            reservation=reservation,
        )
        replayed_provider = bind_futu_market_reference_provider(
            ticket=replayed_ticket,
            market_execution_evidence=market_execution_evidence,
            verifier=futu["_verifier"],
        )
        (
            replayed_market_access,
            replayed_market_execution,
            replayed_market_request,
            replayed_market_response,
            replayed_market_observation,
        ) = _governed_access(
            graph=replayed_context.graph,
            expected_freeze=replayed_context.expected_freeze,
            expected_security=replayed_context.expected_security,
            provider=replayed_provider,
            clock=replayed_context.clock.market,
        )
        replayed_acquisition = FutuMarketReferenceAcquisition(
            ticket=replayed_ticket,
            market_execution_evidence=market_execution_evidence,
            execution=replayed_market_execution,
            request=replayed_market_request,
            response=replayed_market_response,
            observation=replayed_market_observation,
            daily_close=replayed_provider.daily_close,
            access_result=replayed_market_access,
            authorization_consumption=authorization_consumption,
            verifier=futu["_verifier"],
        )
        with tempfile.TemporaryDirectory(
            prefix="owner-canary-price-blind-replay-"
        ) as temporary:
            price_blind_directory = Path(temporary).resolve(strict=True) / "price-blind"
            price_blind_directory.mkdir(mode=0o700)
            _write_file(
                price_blind_directory / "price-blind-input.json",
                _read_regular(
                    snapshot_root
                    / "six-file-archive"
                    / "price-blind-input.json",
                    label="captured price-blind replay artifact",
                    maximum_bytes=MAXIMUM_JSON_BYTES,
                    protected=True,
                ),
            )
            replayed_current_shares = compile_quote_date_current_common_shares(
                price_blind_artifact_directory=price_blind_directory,
                graph=replayed_context.graph,
                expected_freeze=replayed_context.expected_freeze,
                expected_security=replayed_context.expected_security,
                expected_market_access=replayed_market_access,
            )
        if replayed_current_shares.status != "eligible":
            raise ValueError(
                "current-share replay is not eligible: "
                f"{','.join(replayed_current_shares.issue_codes)}"
            )
        replayed_prepared = build_futu_market_reference_snapshot(
            graph=replayed_context.graph,
            expected_freeze=replayed_context.expected_freeze,
            expected_security=replayed_context.expected_security,
            acquisition=replayed_acquisition,
            current_shares=replayed_current_shares,
        )
        base_ledger = to_json_value(
            replayed_context.expected_freeze.artifact.payload[
                "reviewed_assumptions"
            ]["augmented_fact_ledger_payload"]
        )
        replayed_fact_result = _compile_fact_ledger(
            base_ledger=base_ledger,
            prepared=replayed_prepared,
        )
        kernel_execution_input = _closed_keys(
            value["kernel_execution_evidence"],
            set(PinnedKernelExecutionResult.__dataclass_fields__) - {"result_bytes"},
            label="kernel execution evidence",
        )
        kernel_execution = PinnedKernelExecutionResult(
            **kernel_execution_input,
            result_bytes=canonical_json_bytes(
                to_json_value(archive.result_payload),
                newline=False,
            ),
        )
        replayed_kernel_receipt = _kernel_execution_receipt(
            kernel_execution
        ).to_dict()
        final_projection = manifest["final_request_projection"]
        kernel_projection = manifest["kernel_execution_projection"]
        replayed_final_projection = {
            name: final_receipt[name] for name in final_projection
        }
        replayed_kernel_projection = {
            name: kernel_receipt[name] for name in kernel_projection
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise ReleaseAssemblyError(
            "typed valuation execution receipts do not reconstruct: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if (
        final_receipt != final_receipt_input
        or kernel_receipt != kernel_receipt_input
        or share_projection.to_dict() != share_projection_input
        or numeric_projection != numeric_projection_input
        or market_execution_evidence.to_dict() != market_execution_input
        or replayed_ticket.to_dict() != ticket
        or replayed_market_access.to_dict() != market_access_result.to_dict()
        or replayed_acquisition.to_dict() != vendor_acquisition_input
        or replayed_current_shares.to_dict() != prepared["current_shares"]
        or replayed_prepared.snapshot.to_dict() != prepared["snapshot"]
        or replayed_prepared.market_source.to_dict() != prepared["market_source"]
        or replayed_prepared.quote_fact.to_dict() != prepared["quote_fact"]
        or replayed_prepared.market_equity_calculation.to_dict()
        != prepared["market_equity_calculation"]
        or replayed_fact_result.current_share_projection.to_dict()
        != share_projection_input
        or replayed_fact_result.quote_projection_witness.to_dict()
        != numeric_projection_input["quote_projection_witness"]
        or replayed_fact_result.market_equity_projection_witness.to_dict()
        != numeric_projection_input["market_equity_projection_witness"]
        or to_json_value(replayed_fact_result.fact_ledger_payload)
        != request_payload["fact_ledger"]
        or vendor_acquisition != vendor_acquisition_input
        or {
            name: to_json_value(getattr(kernel_execution, name))
            for name in kernel_execution.__dataclass_fields__
            if name != "result_bytes"
        }
        != kernel_execution_input
        or replayed_kernel_receipt != kernel_receipt
        or replayed_final_projection != final_projection
        or replayed_kernel_projection != kernel_projection
    ):
        raise ReleaseAssemblyError(
            "typed valuation execution receipts differ from exact input or archive projections"
        )
    runtime_authority = replayed_input_receipt.runtime_manifest_authority
    if (
        hashlib.sha256(
            canonical_json_bytes(request_payload, newline=False)
        ).hexdigest()
        != kernel_execution.request_sha256
        or hashlib.sha256(kernel_execution.result_bytes).hexdigest()
        != kernel_execution.result_sha256
        or runtime_authority.runtime_manifest_file_sha256
        != kernel_receipt["runtime_manifest_file_sha256"]
        or runtime_authority.runtime_manifest_fingerprint
        != kernel_receipt["runtime_manifest_fingerprint"]
        or runtime_authority.runtime_authority_sha256
        != kernel_receipt["runtime_authority_sha256"]
        or runtime_authority.wheel_inventory_sha256
        != kernel_receipt["wheel_inventory_sha256"]
    ):
        raise ReleaseAssemblyError(
            "kernel execution receipt differs from replayed runtime authority"
        )
    snapshot_payload = to_json_value(archive.market_reference)
    current_shares = prepared["current_shares"]
    if not isinstance(current_shares, dict):
        raise ReleaseAssemblyError("current-share authority is not a canonical projection")
    current_output = current_shares.get("output_fact")
    if not isinstance(current_output, dict):
        raise ReleaseAssemblyError("current-share authority lacks its output Fact")
    try:
        current_output_fact = contract_from_dict("fact", current_output)
    except (TypeError, ValueError) as exc:
        raise ReleaseAssemblyError("current-share output Fact does not reconstruct") from exc

    replayed_validation_contexts = tuple(
        replayed_prepared.graph.market_reference_validation_contexts
    )
    if len(replayed_validation_contexts) != 1:
        raise ReleaseAssemblyError(
            "replayed market preparation lacks one exact validation context"
        )
    ticket_fingerprint = canonical_sha256(ticket)
    replayed_validation_context = replayed_validation_contexts[0]
    expected_market_context_fingerprint = replayed_validation_context.fingerprint

    try:
        source_refs = request_payload["fact_ledger"]["sources"]
        request_facts = {
            item["fact_id"]: item for item in request_payload["fact_ledger"]["facts"]
        }
        market_source_refs = [
            item
            for item in source_refs
            if item["source_id"] == final_receipt["market_source_document_id"]
        ]
        raw_response_sha256 = snapshot_payload["raw_evidence"][
            "raw_response_sha256"
        ]
        governed_receipt = snapshot_payload["governed_market_quote_receipt"]
        authority_lineage = snapshot_payload["authority_lineage"]
    except (KeyError, TypeError) as exc:
        raise ReleaseAssemblyError(
            "final-request receipt replay evidence is incomplete"
        ) from exc
    if len(market_source_refs) != 1:
        raise ReleaseAssemblyError(
            "final-request receipt market SourceRef is unavailable or ambiguous"
        )
    market_source_ref_fingerprint = canonical_sha256(market_source_refs[0])
    current_share_projection_sha256 = share_projection.fingerprint
    numeric_projection_sha256 = canonical_sha256(numeric_projection)
    expected_market_evidence_binding = canonical_sha256(
        {
            "context": [
                final_receipt["market_validation_context_id"],
                final_receipt["market_validation_context_fingerprint"],
            ],
            "access_fingerprint": final_receipt[
                "market_access_result_fingerprint"
            ],
            "provider": [
                final_receipt["market_provider_id"],
                final_receipt["market_provider_registration_sha256"],
                final_receipt["market_provider_receipt_id"],
                final_receipt["market_provider_receipt_fingerprint"],
            ],
            "current_share_compilation_fingerprint": final_receipt[
                "current_share_compilation_fingerprint"
            ],
            "source_document": [
                final_receipt["market_source_document_id"],
                final_receipt["market_source_document_fingerprint"],
            ],
            "source_ref_fingerprint": final_receipt[
                "market_source_ref_fingerprint"
            ],
            "raw_response_sha256": final_receipt["market_raw_response_sha256"],
            "quote_fact": [
                final_receipt["market_quote_fact_id"],
                final_receipt["market_quote_fact_fingerprint"],
            ],
            "market_equity_calculation": [
                final_receipt["market_equity_calculation_id"],
                final_receipt["market_equity_calculation_fingerprint"],
            ],
        }
    )
    replayed_final_receipt_authority = {
        "market_provider_id": replayed_fact_result.market_provider_id,
        "market_provider_registration_sha256": (
            replayed_fact_result.market_provider_registration_sha256
        ),
        "market_provider_receipt_id": replayed_fact_result.market_provider_receipt_id,
        "market_provider_receipt_fingerprint": (
            replayed_fact_result.market_provider_receipt_fingerprint
        ),
        "market_validation_context_id": replayed_fact_result.market_validation_context_id,
        "market_validation_context_fingerprint": (
            replayed_fact_result.market_validation_context_fingerprint
        ),
        "market_access_result_fingerprint": (
            replayed_fact_result.market_access_result_fingerprint
        ),
        "current_share_compilation_fingerprint": (
            replayed_fact_result.current_share_compilation_fingerprint
        ),
        "market_source_document_id": replayed_fact_result.market_source_document_id,
        "market_source_document_fingerprint": (
            replayed_fact_result.market_source_document_fingerprint
        ),
        "market_source_ref_fingerprint": replayed_fact_result.market_source_ref_fingerprint,
        "market_raw_response_sha256": replayed_fact_result.market_raw_response_sha256,
        "market_quote_fact_id": replayed_fact_result.market_quote_fact_id,
        "market_quote_fact_fingerprint": replayed_fact_result.market_quote_fact_fingerprint,
        "market_equity_calculation_id": replayed_fact_result.market_equity_calculation_id,
        "market_equity_calculation_fingerprint": (
            replayed_fact_result.market_equity_calculation_fingerprint
        ),
        "market_evidence_binding_sha256": (
            replayed_fact_result.market_evidence_binding_sha256
        ),
        "current_share_projection_sha256": (
            replayed_fact_result.current_share_projection.fingerprint
        ),
        "numeric_projection_sha256": canonical_sha256(
            {
                "current_share_numeric_witnesses": [
                    item.to_dict()
                    for item in replayed_fact_result.current_share_projection.numeric_witnesses
                ],
                "quote_projection_witness": (
                    replayed_fact_result.quote_projection_witness.to_dict()
                ),
                "market_equity_projection_witness": (
                    replayed_fact_result.market_equity_projection_witness.to_dict()
                ),
            }
        ),
        "added_source_ids": list(replayed_fact_result.added_source_ids),
        "added_fact_ids": list(replayed_fact_result.added_fact_ids),
        "price_blind_fact_ledger_sha256": replayed_fact_result.base_ledger_sha256,
        "final_fact_ledger_sha256": canonical_sha256(
            replayed_fact_result.fact_ledger_payload
        ),
    }

    graph_projection: dict[str, list[str]] = {}
    for field in fields(replayed_context.graph):
        if field.name == "component_lock_path":
            continue
        fingerprints: list[str] = []
        for item in getattr(replayed_context.graph, field.name):
            fingerprint = getattr(item, "fingerprint", None)
            if type(fingerprint) is not str:
                to_dict = getattr(item, "to_dict", None)
                if not callable(to_dict):
                    raise ReleaseAssemblyError(
                        f"valuation graph collection {field.name} is not receiptable"
                    )
                fingerprint = canonical_sha256(to_dict())
            fingerprints.append(fingerprint)
        graph_projection[field.name] = fingerprints

    appended_graph_ids: dict[tuple[str, str], str] = {}

    def append_graph_fingerprint(
        collection: str,
        identifier_name: str,
        identifier: str,
        fingerprint: str,
    ) -> None:
        key = (collection, identifier)
        prior = appended_graph_ids.get(key)
        if prior is not None:
            if prior != fingerprint:
                raise ReleaseAssemblyError(
                    f"typed market preparation collides within graph {collection}"
                )
            return
        matches = tuple(
            item
            for item in getattr(replayed_context.graph, collection)
            if getattr(item, identifier_name) == identifier
        )
        if not matches:
            graph_projection[collection].append(fingerprint)
            appended_graph_ids[key] = fingerprint
            return
        if len(matches) != 1 or getattr(matches[0], "fingerprint", None) != fingerprint:
            raise ReleaseAssemblyError(
                f"typed market preparation collides with valuation graph {collection}"
            )

    rollforward = current_shares.get("canonical_rollforward")
    if rollforward is not None:
        if not isinstance(rollforward, dict) or not isinstance(
            rollforward.get("materializations"), list
        ):
            raise ReleaseAssemblyError("current-share roll-forward is not typed")
        for materialization in rollforward["materializations"]:
            if not isinstance(materialization, dict):
                raise ReleaseAssemblyError("current-share materialization is not typed")
            try:
                event_fact = contract_from_dict(
                    "fact",
                    materialization["canonical_event_fact"],
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ReleaseAssemblyError(
                    "current-share materialization Fact does not reconstruct"
                ) from exc
            append_graph_fingerprint(
                "facts",
                "fact_id",
                event_fact.fact_id,
                event_fact.fingerprint,
            )
    append_graph_fingerprint(
        "facts",
        "fact_id",
        current_output_fact.fact_id,
        current_output_fact.fingerprint,
    )
    append_graph_fingerprint(
        "documents",
        "document_id",
        market_source.document_id,
        market_source.fingerprint,
    )
    append_graph_fingerprint(
        "facts",
        "fact_id",
        quote_fact.fact_id,
        quote_fact.fingerprint,
    )
    append_graph_fingerprint(
        "calculations",
        "calculation_id",
        market_calculation.calculation_id,
        market_calculation.fingerprint,
    )
    append_graph_fingerprint(
        "market_reference_validation_contexts",
        "context_id",
        final_receipt["market_validation_context_id"],
        final_receipt["market_validation_context_fingerprint"],
    )
    append_graph_fingerprint(
        "market_reference_snapshots",
        "snapshot_id",
        snapshot.snapshot_id,
        snapshot.fingerprint,
    )
    prepared_graph_fingerprint = canonical_sha256(graph_projection)
    ticket_fingerprint = canonical_sha256(ticket)
    prepared_fingerprint = canonical_sha256(
        {
            "snapshot": snapshot,
            "market_source": market_source,
            "quote_fact": quote_fact,
            "market_equity_calculation": market_calculation,
            "current_shares": current_shares,
        }
    )
    current_shares_fingerprint = canonical_sha256(current_shares)
    share_attestation = share_projection.research_evidence_attestation
    request_source_index = {item["source_id"]: item for item in source_refs}
    share_projection_matches_request = (
        share_attestation is not None
        and share_attestation.get("current_share_compilation_fingerprint")
        == current_shares_fingerprint
        and share_projection.current_share_fact_id
        == snapshot.share_basis["shares_outstanding_fact_id"]
        and all(
            request_source_index.get(item["source_id"]) == to_json_value(item)
            for item in share_projection.sources
        )
        and all(
            request_facts.get(item["fact_id"]) == to_json_value(item)
            for item in share_projection.facts
        )
        and current_share_numeric_witnesses == share_projection.numeric_witnesses
        and quote_projection_witness.label
        == f"quote:{final_receipt['market_quote_fact_id']}"
        and request_facts.get(final_receipt["market_quote_fact_id"], {}).get("value")
        == quote_projection_witness.kernel_value
        and market_equity_projection_witness.label
        == f"market-equity:{final_receipt['market_equity_calculation_id']}"
        and request_facts.get(
            f"derived:{final_receipt['market_equity_calculation_id']}",
            {},
        ).get("value")
        == market_equity_projection_witness.kernel_value
    )
    if (
        to_json_value(snapshot) != snapshot_payload
        or snapshot.source_authority_kind != "governed_vendor"
        or snapshot.evidence_mode != "governed_vendor"
        or futu["market_trading_date"] != replayed_calendar.session.trading_date
        or snapshot.trading_date != replayed_calendar.session.trading_date
        or quote_request.trading_calendar_id != replayed_calendar.calendar_id
        or replayed_calendar.mic not in registration.supported_mics
        or registration.provider_id != FUTU_MARKET_PROVIDER_ID
        or registration.fingerprint != quote_request.provider_registration_sha256
        or ticket["provider_registry_sha256"] != _provider_registry_sha256(registration)
        or ticket["contract_graph_fingerprint"] != replayed_input_receipt.graph_fingerprint
        or ticket["authority_decision"] != futu["authority_decision"]
        or ticket["authority_receipt_fingerprints"]
        != futu["authority_decision"]["receipt_fingerprints"]
        or ticket["security_identity_fingerprint"] != futu["security_fingerprint"]
        or ticket["supply_chain_fingerprint"] != futu["supply_chain_fingerprint"]
        or ticket["expected_freeze_result_fingerprint"]
        != valuation_input["expected_freeze_fingerprint"]
        or ticket["expected_freeze_fingerprint"] != valuation_input["expected_freeze_fingerprint"]
        or ticket["expected_security_result_fingerprint"]
        != valuation_input["expected_security_fingerprint"]
        or ticket["expected_security_fingerprint"]
        != valuation_input["expected_security_fingerprint"]
        or market_request.issuer_id != archive.handoff.issuer_id
        or market_request.data_cutoff_date != archive.handoff.data_cutoff_date
        or market_request.security_id != futu["security_id"]
        or market_request.mic != futu["mic"]
        or market_request.quote_currency != futu["currency"]
        or market_request.authorization_handoff_id != snapshot.authorization_handoff_id
        or market_request.authorization_handoff_fingerprint
        != snapshot.authorization_handoff_fingerprint
        or market_request.price_blind_input_fingerprint != archive.price_blind_input.fingerprint
        or quote_request.request_started_at != market_request.request_started_at
        or quote_request.issuer_id != market_request.issuer_id
        or quote_request.security_id != market_request.security_id
        or quote_request.quote_currency != market_request.quote_currency
        or reservation.authorization_handoff_id != market_request.authorization_handoff_id
        or reservation.authorization_handoff_fingerprint
        != market_request.authorization_handoff_fingerprint
        or reservation.price_blind_input_fingerprint != market_request.price_blind_input_fingerprint
        or reservation.request_fingerprint != market_request.request_fingerprint
        or provider["ticket_fingerprint"] != ticket_fingerprint
        or provider["market_execution_evidence_fingerprint"] != market_execution_fingerprint
        or daily_close.issuer_id != archive.handoff.issuer_id
        or daily_close.security_id != futu["security_id"]
        or daily_close.trading_date != snapshot.trading_date
        or daily_close.close_decimal != snapshot.quote_price_decimal
        or daily_close.currency != snapshot.quote_currency
        or daily_close.source_observation_fingerprint
        not in {item[1] for item in futu["observation_refs"]}
        or daily_close.source_request_fingerprint not in {item[1] for item in futu["request_refs"]}
        or market_source.document_id != final_receipt["market_source_document_id"]
        or market_source.fingerprint != final_receipt["market_source_document_fingerprint"]
        or quote_fact.fact_id != final_receipt["market_quote_fact_id"]
        or quote_fact.fingerprint != final_receipt["market_quote_fact_fingerprint"]
        or market_calculation.calculation_id != final_receipt["market_equity_calculation_id"]
        or market_calculation.fingerprint != final_receipt["market_equity_calculation_fingerprint"]
        or current_shares_fingerprint != final_receipt["current_share_compilation_fingerprint"]
        or not share_projection_matches_request
        or any(
            final_receipt[name] != expected
            for name, expected in replayed_final_receipt_authority.items()
        )
        or final_receipt["market_provider_id"] != registration.provider_id
        or final_receipt["market_provider_receipt_id"] != governed_receipt["receipt_id"]
        or final_receipt["market_provider_receipt_fingerprint"]
        != governed_receipt["receipt_fingerprint"]
        or final_receipt["market_provider_registration_sha256"]
        != authority_lineage["provider_registration_sha256"]
        or final_receipt["market_validation_context_id"]
        != (
            f"market-reference-context:{snapshot.issuer_id}:{snapshot.trading_date}:"
            f"{raw_response_sha256[:16]}"
        )
        or final_receipt["market_validation_context_id"]
        != replayed_validation_context.context_id
        or final_receipt["market_validation_context_fingerprint"]
        != expected_market_context_fingerprint
        or final_receipt["market_access_result_fingerprint"]
        != snapshot_payload["market_access_result_fingerprint"]
        or final_receipt["market_source_ref_fingerprint"]
        != market_source_ref_fingerprint
        or final_receipt["market_raw_response_sha256"] != raw_response_sha256
        or final_receipt["market_evidence_binding_sha256"]
        != expected_market_evidence_binding
        or final_receipt["current_share_projection_sha256"]
        != current_share_projection_sha256
        or final_receipt["numeric_projection_sha256"]
        != numeric_projection_sha256
        or current_output_fact.fact_id != snapshot.share_basis["shares_outstanding_fact_id"]
        or current_output_fact.fact_id
        != current_shares.get("share_basis_decision", {}).get("share_fact_id")
    ):
        raise ReleaseAssemblyError("typed market/provider authorities were rebound")
    provider_fingerprint = canonical_sha256(provider)
    prepared_authority_binding = {
        "authorization_handoffs": [
            [snapshot.authorization_handoff_id, snapshot.authorization_handoff_fingerprint]
        ],
        "validation_contexts": [
            [
                final_receipt["market_validation_context_id"],
                final_receipt["market_validation_context_fingerprint"],
            ]
        ],
    }
    execution_preparation_fingerprint = canonical_sha256(
        {
            "status": "prepared",
            "issuer_id": archive.handoff.issuer_id,
            "data_cutoff_date": archive.handoff.data_cutoff_date,
            "price_blind_input_fingerprint": archive.price_blind_input.fingerprint,
            "expected_freeze_fingerprint": valuation_input["expected_freeze_fingerprint"],
            "prepared_market_reference_fingerprint": prepared_fingerprint,
            "prepared_authority_binding": prepared_authority_binding,
            "issue_codes": [],
        }
    )
    preparation_binding = canonical_sha256(
        {
            "status": "prepared",
            "issuer_id": archive.handoff.issuer_id,
            "data_cutoff_date": archive.handoff.data_cutoff_date,
            "price_blind_input_fingerprint": archive.price_blind_input.fingerprint,
            "prepared_market_reference_fingerprint": prepared_fingerprint,
            "prepared_graph_fingerprint": prepared_graph_fingerprint,
            "issue_codes": [],
        }
    )
    execution_binding = canonical_sha256(
        {
            "status": "completed",
            "issuer_id": archive.handoff.issuer_id,
            "data_cutoff_date": archive.handoff.data_cutoff_date,
            "preparation_fingerprint": execution_preparation_fingerprint,
            "stopped_envelope_fingerprint": None,
            "final_request_receipt_fingerprint": canonical_sha256(final_receipt),
            "kernel_execution_receipt_fingerprint": canonical_sha256(kernel_receipt),
            "result_sha256": manifest["valuation_result_sha256"],
            "issue_codes": [],
        }
    )
    archive_binding = {
        "output_directory": str(original_archive_directory),
        "directory_device": archive_directory_identity[0],
        "directory_inode": archive_directory_identity[1],
        "manifest_fingerprint": archive.fingerprint,
        "file_sha256": to_json_value(archive.file_sha256),
    }
    run_result_fingerprint = canonical_sha256(
        {
            "status": "completed",
            "issuer_id": archive.handoff.issuer_id,
            "data_cutoff_date": archive.handoff.data_cutoff_date,
            "input_receipt_fingerprint": replayed_input_receipt.fingerprint,
            "preparation_binding": preparation_binding,
            "execution_binding": execution_binding,
            "archive_binding": archive_binding,
            "issue_codes": [],
        }
    )
    return {
        "contract_graph_fingerprint": replayed_input_receipt.graph_fingerprint,
        "market_provider_fingerprint": provider_fingerprint,
        "prepared_market_reference_fingerprint": prepared_fingerprint,
        "valuation_run_result_fingerprint": run_result_fingerprint,
    }


def _require_sufficient_history_quota(quota: Any) -> None:
    from owner_research.futu_receipts import FutuHistoricalKlineQuotaReceipt

    if (
        type(quota) is not FutuHistoricalKlineQuotaReceipt
        or not quota.sufficient
        or quota.remaining_quota < quota.required_incremental_security_count
    ):
        raise ReleaseAssemblyError(
            "Futu 3104 quota authority is missing, insufficient, or rebound from its exact plan"
        )


def _futu_financial_value_is_admissible(
    item: Any,
    mapping: Any,
    descriptor: Any,
    *,
    statement_name: str,
    futu_api_version: str,
) -> bool:
    """Replay mapped values and typed non-comparable unknown vendor fields."""
    from owner_research.fingerprints import to_json_value

    if descriptor is None:
        return False
    qualifiers = to_json_value(item.qualifiers)
    descriptor_qualifiers = to_json_value(descriptor.qualifiers)
    period = to_json_value(item.period)
    normalized_display_name = qualifiers.get(
        "normalized_financial_field_display_name"
    )
    expected_period_kind = "stock" if statement_name == "balance_sheet" else "flow"
    expected_qualifier_keys = {
        "accounting_standard",
        "auditor_report",
        "financial_period_start_derivation",
        "financial_period_status",
        "financial_type",
        "fiscal_year",
        "futu_api_version",
        "normalized_financial_field_display_name",
        "period_kind",
        "statement_type",
        "vendor_period",
    }
    expected_descriptor_qualifiers = {
        "financial_field_id": item.field_id,
        "futu_api_version": futu_api_version,
        "normalized_display_name": normalized_display_name,
        "statement_type": statement_name,
    }
    if (
        item.data_family != "financial_statements"
        or item.source_role != "vendor_secondary"
        or item.point_in_time_status != "current_snapshot"
        or not isinstance(item.field_id, str)
        or not item.field_id.isascii()
        or not item.field_id.isdigit()
        or str(int(item.field_id)) != item.field_id
        or int(item.field_id) <= 0
        or set(qualifiers) != expected_qualifier_keys
        or qualifiers.get("statement_type") != statement_name
        or qualifiers.get("futu_api_version") != futu_api_version
        or qualifiers.get("financial_type") != 7
        or qualifiers.get("period_kind") != expected_period_kind
        or not isinstance(qualifiers.get("fiscal_year"), int)
        or qualifiers["fiscal_year"] <= 0
        or any(
            not isinstance(qualifiers.get(key), str) or not qualifiers[key]
            for key in ("accounting_standard", "vendor_period")
        )
        or not isinstance(qualifiers.get("auditor_report"), str)
        or not isinstance(normalized_display_name, str)
        or not normalized_display_name
        or descriptor.data_family != "financial_statements"
        or descriptor.field_id != f"financial_structure:{item.field_id}"
        or descriptor.canonical_concept is not None
        or descriptor.comparison_eligible
        or descriptor.value_type != "text"
        or not isinstance(descriptor.value, str)
        or descriptor.unit is not None
        or descriptor.currency is not None
        or to_json_value(descriptor.period) != {"end": None, "start": None}
        or descriptor.response_fingerprint != item.response_fingerprint
        or descriptor_qualifiers != expected_descriptor_qualifiers
        or not isinstance(period.get("end"), str)
    ):
        return False
    period_status = qualifiers["financial_period_status"]
    start_derivation = qualifiers["financial_period_start_derivation"]
    if expected_period_kind == "stock":
        if (
            period.get("start") is not None
            or period_status != "instant"
            or start_derivation != "not_applicable"
        ):
            return False
    elif period_status == "annual_predecessor_unavailable":
        if period.get("start") is not None or start_derivation != "not_derivable":
            return False
    elif (
        period_status != "consecutive_annual_period"
        or not isinstance(period.get("start"), str)
        or start_derivation != "previous_annual_period_end_plus_one_day"
    ):
        return False

    if mapping is None:
        return item.canonical_concept is None and not item.comparison_eligible
    if (
        mapping["statement_type"] != statement_name
        or mapping["period_kind"] != expected_period_kind
        or mapping["futu_api_version"] != futu_api_version
        or mapping["normalized_display_name"] != normalized_display_name
        or mapping["accounting_standard_scope"] != qualifiers["accounting_standard"]
        or mapping["unit"] != item.unit
    ):
        return False
    if item.comparison_eligible:
        return (
            item.canonical_concept == mapping["canonical_concept"]
            and (
                expected_period_kind == "stock"
                or period_status == "consecutive_annual_period"
            )
        )
    return (
        expected_period_kind == "flow"
        and item.canonical_concept is None
        and period_status == "annual_predecessor_unavailable"
    )


def _futu_request_shape(request: Any) -> tuple[int, str]:
    from owner_research.fingerprints import to_json_value

    return request.protocol_id, canonical_json_bytes(
        to_json_value(request.parameters),
        newline=False,
    ).decode("utf-8")


def _require_closed_us_preprice_request_plan(
    first_page_requests: tuple[Any, ...],
) -> None:

    required_shapes = {
        (
            3104,
            canonical_json_bytes({"get_detail": True}, newline=False).decode("utf-8"),
        ),
        (3202, canonical_json_bytes({}, newline=False).decode("utf-8")),
        *{
            (
                3227,
                canonical_json_bytes(
                    {
                        "currency_code": "USD",
                        "financial_type": 7,
                        "num": 10,
                        "statement_type": statement_type,
                    },
                    newline=False,
                ).decode("utf-8"),
            )
            for statement_type in (1, 2, 3)
        },
        (
            3228,
            canonical_json_bytes(
                {"currency_code": "USD", "date": 0, "financial_type": 7},
                newline=False,
            ).decode("utf-8"),
        ),
        (3234, canonical_json_bytes({}, newline=False).decode("utf-8")),
        (3236, canonical_json_bytes({}, newline=False).decode("utf-8")),
        (3243, canonical_json_bytes({}, newline=False).decode("utf-8")),
    }
    optional_protocols = {3244, 3245, 3246}
    shapes = {_futu_request_shape(item) for item in first_page_requests}
    if (
        not required_shapes.issubset(shapes)
        or any(
            protocol_id
            not in {item[0] for item in required_shapes} | optional_protocols
            for protocol_id, _parameters in shapes
        )
        or len(shapes) != len(first_page_requests)
    ):
        raise ReleaseAssemblyError("Futu target pre-price request plan is incomplete or rebound")


def _load_private_futu(
    payload: dict[str, Any],
    *,
    keyring_file: Path,
    executed_at: datetime,
) -> dict[str, Any]:
    from owner_research.fingerprints import to_json_value
    from owner_research.futu_receipts import (
        FutuAuthorityDecision,
        FutuAuthoritySet,
        FutuCrossCheckReceipt,
        FutuDataRequestReceipt,
        FutuDataResponseReceipt,
        FutuEvidenceBundle,
        FutuHistoricalKlineQuotaReceipt,
        FutuObservation,
        evaluate_futu_authority,
        load_futu_authority_set,
        load_futu_signed_receipt,
        signed_receipt_payload,
    )
    from owner_research.futu_sidecar import (
        FutuSidecarExecution,
        load_critical_financial_concepts,
        load_financial_field_registry,
        load_futu_attested_session_finalization,
        validate_futu_execution_replay,
    )
    from owner_research.owner_equity_runtime import Ed25519PublicKeyring

    value = _closed_keys(
        payload,
        {
            "artifact_type",
            "attested_session_finalization",
            "authority_decision",
            "authority_set",
            "cross_checks",
            "executions",
            "schema_version",
        },
        label="private Futu evidence",
    )
    if (
        value["artifact_type"] != "owner-equity-private-futu-evidence"
        or value["schema_version"] != "1.0.0"
    ):
        raise ReleaseAssemblyError("private Futu evidence identity is invalid")
    keyring = Ed25519PublicKeyring.from_file(keyring_file)
    authority_set = load_futu_authority_set(value["authority_set"])
    try:
        authority_decision = FutuAuthorityDecision(**value["authority_decision"])
    except (TypeError, ValueError) as exc:
        raise ReleaseAssemblyError("Futu authority decision is invalid") from exc
    required_authorities = (
        authority_set.legal,
        authority_set.account,
        authority_set.supply_chain,
        authority_set.runtime_authorization,
        authority_set.runtime,
        authority_set.security_identity,
    )
    if any(item is None for item in required_authorities):
        raise ReleaseAssemblyError("Futu authority set is incomplete")
    legal, account, supply, runtime_authorization, runtime, security = required_authorities
    assert legal is not None and account is not None and supply is not None
    assert runtime_authorization is not None and runtime is not None and security is not None
    executions_value = value["executions"]
    if not isinstance(executions_value, list) or not executions_value:
        raise ReleaseAssemblyError("private Futu execution set is empty")
    executions = []
    execution_decisions = []
    execution_securities = []
    for raw in executions_value:
        record = _closed_keys(
            raw,
            {
                "authority_decision",
                "bundle",
                "history_quota",
                "observations",
                "requests",
                "responses",
                "security_identity",
            },
            label="private Futu execution",
        )
        try:
            execution_decision = FutuAuthorityDecision(**record["authority_decision"])
            execution_security = load_futu_signed_receipt(
                "futu-security-identity-receipt", record["security_identity"]
            )
            execution = FutuSidecarExecution(
                bundle=FutuEvidenceBundle(**record["bundle"]),
                requests=tuple(FutuDataRequestReceipt(**item) for item in record["requests"]),
                responses=tuple(FutuDataResponseReceipt(**item) for item in record["responses"]),
                observations=tuple(FutuObservation(**item) for item in record["observations"]),
                history_quota=(
                    None
                    if record["history_quota"] is None
                    else FutuHistoricalKlineQuotaReceipt(**record["history_quota"])
                ),
            )
            execution_authority = FutuAuthoritySet(
                legal=legal,
                account=account,
                supply_chain=supply,
                runtime_authorization=runtime_authorization,
                runtime=runtime,
                security_identity=execution_security,
            )
            execution_requests = execution.requests
            replayed_execution_decision = evaluate_futu_authority(
                execution_authority,
                verifier=keyring,
                now=datetime.fromisoformat(execution_decision.evaluated_at.replace("Z", "+00:00")),
                run_id=execution_decision.run_id,
                policy_sha256=execution_decision.policy_sha256,
                component_lock_sha256=execution_decision.component_lock_sha256,
                required_data_families=tuple(
                    sorted({item.data_family for item in execution_requests})
                ),
                required_protocol_ids=tuple(
                    sorted({item.protocol_id for item in execution_requests})
                ),
                purpose="live_preflight",
            )
            if replayed_execution_decision.to_dict() != execution_decision.to_dict():
                raise ReleaseAssemblyError("private Futu execution authority does not replay")
            validate_futu_execution_replay(
                execution,
                authority=execution_decision,
                security_identity=execution_security,
                supply_chain=supply,
            )
        except (TypeError, ValueError) as exc:
            raise ReleaseAssemblyError("private Futu execution does not replay") from exc
        executions.append(execution)
        execution_decisions.append(execution_decision)
        execution_securities.append(execution_security)
        if not keyring.verify(
            signer_key_id=execution_security.signer_key_id,
            payload=signed_receipt_payload(execution_security),
            signature_hex=execution_security.signature_hex,
        ):
            raise ReleaseAssemblyError("private Futu execution security signature is invalid")
    protocols = tuple(
        sorted({request.protocol_id for execution in executions for request in execution.requests})
    )
    data_families = tuple(
        sorted({request.data_family for execution in executions for request in execution.requests})
    )
    for execution, decision, execution_security in zip(
        executions,
        execution_decisions,
        execution_securities,
        strict=True,
    ):
        is_target = execution.bundle.issuer_id == security.issuer_id
        if is_target != (decision == authority_decision and execution_security == security):
            raise ReleaseAssemblyError("Futu target and peer authorities were coordinated")
    live = evaluate_futu_authority(
        authority_set,
        verifier=keyring,
        now=_parse_time(
            authority_decision.evaluated_at,
            label="Futu authority decision evaluated_at",
        ),
        run_id=authority_decision.run_id,
        policy_sha256=authority_decision.policy_sha256,
        component_lock_sha256=authority_decision.component_lock_sha256,
        required_data_families=data_families,
        required_protocol_ids=protocols,
        purpose="live_preflight",
    )
    if (
        live.status != "eligible"
        or live.to_dict() != authority_decision.to_dict()
        or authority_decision.status != "eligible"
        or tuple(legal.allowed_protocol_ids) != FUTU_CLOSED_RUNTIME_PROTOCOL_IDS
        or tuple(runtime_authorization.allowed_protocol_ids)
        != FUTU_CLOSED_RUNTIME_PROTOCOL_IDS
        or tuple(runtime.allowed_protocol_ids) != FUTU_CLOSED_RUNTIME_PROTOCOL_IDS
        or tuple(authority_decision.allowed_protocol_ids)
        != FUTU_CLOSED_RUNTIME_PROTOCOL_IDS
        or any(
            tuple(item.allowed_protocol_ids) != FUTU_CLOSED_RUNTIME_PROTOCOL_IDS
            for item in execution_decisions
        )
        or not set(protocols).issubset(FUTU_CLOSED_RUNTIME_PROTOCOL_IDS)
        or not set(FUTU_REQUIRED_DATA_FAMILIES).issubset(data_families)
        or authority_decision.security_identity_fingerprint != security.fingerprint
        or any(
            authority_decision.receipt_fingerprints.get(name) != receipt.fingerprint
            for name, receipt in (
                ("legal", legal),
                ("account", account),
                ("supply_chain", supply),
                ("runtime_authorization", runtime_authorization),
                ("security_identity", security),
            )
        )
    ):
        raise ReleaseAssemblyError("Futu execution authority is not eligible or complete")
    try:
        finalization = load_futu_attested_session_finalization(
            value["attested_session_finalization"],
            expected_executions=tuple(executions),
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            verifier=keyring,
        )
        cross_checks = tuple(FutuCrossCheckReceipt(**item) for item in value["cross_checks"])
    except (TypeError, ValueError) as exc:
        raise ReleaseAssemblyError(
            "Futu attested finalization or cross-checks do not replay"
        ) from exc
    if finalization.runtime_receipt != runtime or not cross_checks:
        raise ReleaseAssemblyError("Futu finalization did not retain its completed runtime")
    replay_authority = evaluate_futu_authority(
        authority_set,
        verifier=keyring,
        now=_parse_time(runtime.issued_at, label="Futu completed runtime issued_at"),
        run_id=authority_decision.run_id,
        policy_sha256=authority_decision.policy_sha256,
        component_lock_sha256=authority_decision.component_lock_sha256,
        required_data_families=data_families,
        required_protocol_ids=FUTU_CLOSED_RUNTIME_PROTOCOL_IDS,
        purpose="replay_only",
    )
    expected_replay_receipts = {
        "account": account.fingerprint,
        "legal": legal.fingerprint,
        "runtime": runtime.fingerprint,
        "security_identity": security.fingerprint,
        "supply_chain": supply.fingerprint,
    }
    if (
        replay_authority.status != "eligible"
        or replay_authority.evaluation_scope != "replay_only"
        or tuple(replay_authority.allowed_protocol_ids)
        != FUTU_CLOSED_RUNTIME_PROTOCOL_IDS
        or to_json_value(replay_authority.receipt_fingerprints)
        != expected_replay_receipts
        or replay_authority.security_identity_fingerprint != security.fingerprint
    ):
        raise ReleaseAssemblyError(
            "Futu completed runtime is not eligible under exact replay-only authority"
        )
    requests = tuple(request for execution in executions for request in execution.requests)
    responses = tuple(response for execution in executions for response in execution.responses)
    observations = tuple(
        observation for execution in executions for observation in execution.observations
    )
    boot_issued_at = _parse_time(
        finalization.boot_attestation.receipt["issued_at"],
        label="Futu boot attestation issued_at",
    )
    runtime_started_at = _parse_time(
        runtime.started_at,
        label="Futu runtime started_at",
    )
    runtime_ended_at = _parse_time(
        runtime.ended_at,
        label="Futu runtime ended_at",
    )
    runtime_issued_at = _parse_time(
        runtime.issued_at,
        label="Futu runtime issued_at",
    )
    execution_attestation = finalization.execution_attestation.receipt
    execution_started_at = _parse_time(
        execution_attestation["started_at"],
        label="Futu execution attestation started_at",
    )
    execution_ended_at = _parse_time(
        execution_attestation["ended_at"],
        label="Futu execution attestation ended_at",
    )
    execution_issued_at = _parse_time(
        execution_attestation["issued_at"],
        label="Futu execution attestation issued_at",
    )
    if (
        execution_started_at != runtime_started_at
        or execution_ended_at != runtime_ended_at
        or execution_issued_at != runtime_issued_at
        or not (
            runtime_started_at
            <= boot_issued_at
            <= runtime_ended_at
            <= runtime_issued_at
            <= executed_at
        )
    ):
        raise ReleaseAssemblyError(
            "Futu finalization chronology is not closed by canary executed_at"
        )
    request_times: dict[str, datetime] = {}
    for request in requests:
        if request.fingerprint in request_times:
            raise ReleaseAssemblyError("Futu request chronology reused a request fingerprint")
        request_times[request.fingerprint] = _parse_time(
            request.request_started_at,
            label="Futu request_started_at",
        )
    response_times: dict[str, datetime] = {}
    for response in responses:
        if response.fingerprint in response_times:
            raise ReleaseAssemblyError("Futu response chronology reused a response fingerprint")
        response_times[response.fingerprint] = _parse_time(
            response.retrieved_at,
            label="Futu response retrieved_at",
        )
    if set(request_times) != {item.request_fingerprint for item in responses} or any(
        response.request_fingerprint not in request_times
        or not (
            boot_issued_at
            <= request_times[response.request_fingerprint]
            <= response_times[response.fingerprint]
            <= runtime_ended_at
            <= executed_at
        )
        for response in responses
    ):
        raise ReleaseAssemblyError(
            "Futu request/response chronology escaped the attested canary session"
        )
    response_time_set = {
        fingerprint: response_times[fingerprint] for fingerprint in response_times
    }
    if any(
        observation.response_fingerprint not in response_time_set
        or _parse_time(
            observation.retrieved_at,
            label="Futu observation retrieved_at",
        )
        != response_time_set[observation.response_fingerprint]
        for observation in observations
    ):
        raise ReleaseAssemblyError(
            "Futu observation chronology is not bound to its attested response"
        )
    observations_by_id = {item.observation_id: item for item in observations}
    if len(observations_by_id) != len(observations):
        raise ReleaseAssemblyError("Futu observations reuse an object identity")
    cross_check_ids: set[str] = set()
    cross_checked_observation_ids: set[str] = set()
    for cross_check in cross_checks:
        vendor = observations_by_id.get(cross_check.vendor_observation_id)
        response_time = (
            None
            if vendor is None
            else response_time_set.get(vendor.response_fingerprint)
        )
        created_at = _parse_time(
            cross_check.created_at,
            label="Futu cross-check created_at",
        )
        if (
            cross_check.receipt_id in cross_check_ids
            or cross_check.vendor_observation_id in cross_checked_observation_ids
            or vendor is None
            or response_time is None
            or cross_check.vendor_observation_fingerprint != vendor.fingerprint
            or cross_check.result != "consistent"
            or cross_check.status != "resolved"
            or cross_check.resolution is not None
            or cross_check.reviewer_id is not None
            or not response_time <= created_at <= runtime_ended_at <= executed_at
        ):
            raise ReleaseAssemblyError(
                "Futu SEC/IR cross-check is conflicting, rebound, or out of chronology"
            )
        cross_check_ids.add(cross_check.receipt_id)
        cross_checked_observation_ids.add(cross_check.vendor_observation_id)
    if (
        any(response.status != "completed" for response in responses)
        or any(not response.qot_logined or response.trd_logined for response in responses)
        or len({request.run_id for request in requests}) != 1
    ):
        raise ReleaseAssemblyError("Futu response set is not one quote-only completed run")

    target_executions = tuple(
        execution for execution in executions if execution.bundle.issuer_id == security.issuer_id
    )
    target_by_stage = {execution.bundle.stage: execution for execution in target_executions}
    if len(target_executions) != 3 or set(target_by_stage) != {
        "valuation_pre_price_verification",
        "market_reference",
        "post_valuation_context",
    }:
        raise ReleaseAssemblyError("Futu target run lacks its closed three-stage execution")
    pre_execution = target_by_stage["valuation_pre_price_verification"]
    quota_executions = tuple(item for item in executions if item.history_quota is not None)
    quota_requests = tuple(item for item in requests if item.protocol_id == 3104)
    quota_responses = tuple(
        item
        for item in responses
        if quota_requests and item.request_fingerprint == quota_requests[0].fingerprint
    )
    quota = quota_executions[0].history_quota if len(quota_executions) == 1 else None
    planned_history_codes = tuple(
        sorted({item.vendor_code for item in execution_securities})
    )
    if (
        quota is None
        or quota_executions != (pre_execution,)
        or len(quota_requests) != 1
        or len(quota_responses) != 1
        or pre_execution.requests[0] != quota_requests[0]
        or quota_requests[0].stage != "runtime_authority"
        or to_json_value(quota_requests[0].parameters) != {"get_detail": True}
        or quota.source_request_fingerprint != quota_requests[0].fingerprint
        or quota.source_response_fingerprint != quota_responses[0].fingerprint
        or quota.account_scope_sha256 != account.account_scope_sha256
        or quota.runtime_authorization_fingerprint != runtime_authorization.fingerprint
        or to_json_value(quota.runtime_request_plan)
        != to_json_value(runtime_authorization.request_plan)
        or quota.request_plan_fingerprint != runtime_authorization.request_plan_fingerprint
        or quota.planned_history_security_codes != planned_history_codes
        or quota.required_incremental_security_count
        != len(set(planned_history_codes) - set(quota.already_counted_security_codes))
        or account.protocol_version != supply.futu_api_version
    ):
        raise ReleaseAssemblyError(
            "Futu 3104 quota authority is missing, insufficient, or rebound from its exact plan"
        )
    _require_sufficient_history_quota(quota)
    target_cutoff_dates = {
        request.data_cutoff_date
        for execution in target_executions
        for request in execution.requests
    }
    if len(target_cutoff_dates) != 1:
        raise ReleaseAssemblyError("Futu target run changed its data cutoff")

    required_cross_checked_observation_ids = {
        item.observation_id
        for item in pre_execution.observations
        if item.source_role == "vendor_secondary" and item.comparison_eligible
    }
    if cross_checked_observation_ids != required_cross_checked_observation_ids:
        raise ReleaseAssemblyError(
            "Futu comparison-eligible pre-price data lacks exact SEC/IR cross-check coverage"
        )
    first_page_pre_requests = tuple(item for item in pre_execution.requests if item.page_index == 0)
    _require_closed_us_preprice_request_plan(first_page_pre_requests)

    def actual_observations_for(request_set: tuple[Any, ...]) -> tuple[Any, ...]:
        request_fingerprints = {item.fingerprint for item in request_set}
        response_fingerprints = {
            item.fingerprint
            for item in pre_execution.responses
            if item.request_fingerprint in request_fingerprints and item.status == "completed"
        }
        return tuple(
            item
            for item in pre_execution.observations
            if item.response_fingerprint in response_fingerprints
            and item.field_id != "availability"
        )

    statement_names = {
        1: "income",
        2: "balance_sheet",
        3: "cash_flow",
    }
    financial_registry = load_financial_field_registry()
    critical_concepts = load_critical_financial_concepts()
    consistent_cross_check_concepts = {
        item.canonical_concept
        for item in cross_checks
        if item.result == "consistent" and item.status == "resolved"
    }
    for statement_type, statement_name in statement_names.items():
        statement_requests = tuple(
            item
            for item in pre_execution.requests
            if item.protocol_id == 3227
            and to_json_value(item.parameters).get("statement_type") == statement_type
        )
        statement_observations = actual_observations_for(statement_requests)
        structure_observations = tuple(
            item
            for item in statement_observations
            if item.field_id.startswith("financial_structure:")
        )
        structure_by_field = {
            item.field_id.removeprefix("financial_structure:"): item
            for item in structure_observations
        }
        value_observations = tuple(
            item
            for item in statement_observations
            if not item.field_id.startswith("financial_structure:")
        )
        mapped_values = tuple(
            (item, financial_registry.get(item.field_id)) for item in value_observations
        )
        mapped_concepts = {
            item.canonical_concept
            for item, mapping in mapped_values
            if mapping is not None
            and item.canonical_concept is not None
            and item.comparison_eligible
        }
        required_statement_concepts = set(critical_concepts.get(statement_name, ()))
        if (
            not statement_requests
            or not statement_observations
            or not structure_observations
            or len(structure_by_field) != len(structure_observations)
            or not value_observations
            or any(
                not _futu_financial_value_is_admissible(
                    item,
                    mapping,
                    structure_by_field.get(item.field_id),
                    statement_name=statement_name,
                    futu_api_version=supply.futu_api_version,
                )
                for item, mapping in mapped_values
            )
            or not required_statement_concepts.issubset(mapped_concepts)
            or not required_statement_concepts.issubset(
                consistent_cross_check_concepts
            )
        ):
            raise ReleaseAssemblyError(
                "Futu target financial statement lacks mapped, cross-checked actual data"
            )
    company_requests = tuple(item for item in pre_execution.requests if item.protocol_id == 3243)
    if not any(
        item.data_family == "company_profile" for item in actual_observations_for(company_requests)
    ):
        raise ReleaseAssemblyError("Futu target company profile returned no bound actual data")
    split_concepts = {"stock_split_completed", "reverse_stock_split_completed"}
    split_observations = tuple(
        item
        for item in pre_execution.observations
        if item.canonical_concept in split_concepts
    )
    current_share_dispositions = tuple(
        item
        for item in pre_execution.observations
        if item.data_family == "corporate_actions"
        and item.field_id == "current_common_shares"
    )
    empty_split_dispositions = tuple(
        item
        for item in pre_execution.observations
        if item.data_family == "corporate_actions"
        and item.field_id == "stock_split_event_set"
    )
    if (
        len(current_share_dispositions) != 1
        or current_share_dispositions[0].canonical_concept is not None
        or current_share_dispositions[0].value_type != "null"
        or current_share_dispositions[0].value is not None
        or current_share_dispositions[0].unit is not None
        or current_share_dispositions[0].currency is not None
        or to_json_value(current_share_dispositions[0].qualifiers)
        != {
            "reason_code": "us_3236_shares_after_effect_not_supported",
            "verification_status": "vendor_not_supported",
        }
        or any(
            item.data_family != "corporate_actions"
            or item.field_id != "stock_split_event"
            or item.value_type != "text"
            or not isinstance(item.value, str)
            or re.fullmatch(r"[1-9][0-9]*/[1-9][0-9]*", item.value) is None
            or item.unit != "split_ratio"
            or item.currency is not None
            or not item.comparison_eligible
            or to_json_value(item.qualifiers).get("event_type")
            != item.canonical_concept
            or to_json_value(item.qualifiers).get("current_shares_status")
            != "vendor_not_supported"
            for item in split_observations
        )
        or len(empty_split_dispositions) > 1
        or bool(split_observations) == bool(empty_split_dispositions)
        or any(
            item.canonical_concept is not None
            or item.value_type != "null"
            or item.value is not None
            or item.unit is not None
            or item.currency is not None
            or to_json_value(item.qualifiers)
            != {
                "event_set_status": "empty",
                "reason_code": "official_no_data",
            }
            for item in empty_split_dispositions
        )
    ):
        raise ReleaseAssemblyError(
            "Futu split-event set or current-share disposition is incomplete"
        )
    market_requests = target_by_stage["market_reference"].requests
    if (
        len(market_requests) != 1
        or market_requests[0].protocol_id != 3103
        or market_requests[0].expected_trading_date is None
    ):
        raise ReleaseAssemblyError("Futu market request lacks one selected trading session")
    market_trading_date = market_requests[0].expected_trading_date
    market_shapes = {_futu_request_shape(item) for item in market_requests}
    expected_market_shape = (
        3103,
        canonical_json_bytes(
            {
                "autype": "NONE",
                "end": market_trading_date,
                "extended_time": False,
                "fields": ["CLOSE", "VOLUME"],
                "ktype": "K_DAY",
                "max_count": 1,
                "session": "RTH",
                "start": market_trading_date,
            },
            newline=False,
        ).decode("utf-8"),
    )
    post_shapes = {
        _futu_request_shape(item)
        for item in target_by_stage["post_valuation_context"].requests
    }
    expected_post_shapes = {
        (3229, canonical_json_bytes({}, newline=False).decode("utf-8")),
        (
            3230,
            canonical_json_bytes(
                {"num": 20, "rating_dimension_type": 1, "uid": None},
                newline=False,
            ).decode("utf-8"),
        ),
        (3232, canonical_json_bytes({}, newline=False).decode("utf-8")),
    }
    checkpoints = tuple(runtime.checkpoints)
    if (
        market_shapes != {expected_market_shape}
        or post_shapes != expected_post_shapes
        or not checkpoints
        or checkpoints[0]["checkpoint"] != "startup"
        or checkpoints[-1]["checkpoint"] != "pre_shutdown"
        or any(
            item["protocol_id"] != 1002 or not item["qot_logined"] or item["trd_logined"]
            for item in checkpoints
        )
    ):
        raise ReleaseAssemblyError("Futu market, post-context, or login-state plan drifted")

    def reference(object_id: object, fingerprint: object) -> tuple[str, str]:
        return str(object_id), str(fingerprint)

    return {
        "_authority_decision_object": authority_decision,
        "_pre_runtime_authority_set": FutuAuthoritySet(
            legal=legal,
            account=account,
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            runtime=None,
            security_identity=security,
        ),
        "_target_executions_by_stage": target_by_stage,
        "_verifier": keyring,
        "account_fingerprint": account.fingerprint,
        "authority_decision_fingerprint": authority_decision.fingerprint,
        "boot_attestation_fingerprint": finalization.boot_attestation.fingerprint,
        "bundle_refs": {
            reference(execution.bundle.bundle_id, execution.bundle.fingerprint)
            for execution in executions
        },
        "cross_check_refs": {reference(item.receipt_id, item.fingerprint) for item in cross_checks},
        "cross_checks": cross_checks,
        "cross_check_root_fingerprint": _projection_sha256(
            [item.to_dict() for item in cross_checks]
        ),
        "currency": security.currency,
        "data_cutoff_dates": {request.data_cutoff_date for request in requests},
        "data_families": data_families,
        "authority_decision": authority_decision.to_dict(),
        "security_identity": security.to_dict(),
        "supply_chain": supply.to_dict(),
        "execution_attestation_fingerprint": finalization.execution_attestation.fingerprint,
        "execution_fingerprints": tuple(
            _projection_sha256(
                {
                    "bundle": execution.bundle.to_dict(),
                    "requests": [item.to_dict() for item in execution.requests],
                    "responses": [item.to_dict() for item in execution.responses],
                    "observations": [item.to_dict() for item in execution.observations],
                    "history_quota": (
                        None
                        if execution.history_quota is None
                        else execution.history_quota.to_dict()
                    ),
                }
            )
            for execution in executions
        ),
        "finalization_fingerprint": finalization.fingerprint,
        "issuer_id": security.issuer_id,
        "keyring_fingerprint": keyring.keyring_fingerprint,
        "legal_fingerprint": legal.fingerprint,
        "market_trading_date": market_trading_date,
        "mic": security.mic,
        "observation_refs": {
            reference(item.observation_id, item.fingerprint) for item in observations
        },
        "observations": observations,
        "request_refs": {reference(item.request_id, item.fingerprint) for item in requests},
        "response_refs": {reference(item.response_id, item.fingerprint) for item in responses},
        "target_stage_requests": {
            stage: tuple(item.to_dict() for item in execution.requests)
            for stage, execution in target_by_stage.items()
        },
        "target_stage_responses": {
            stage: tuple(item.to_dict() for item in execution.responses)
            for stage, execution in target_by_stage.items()
        },
        "target_stage_observations": {
            stage: tuple(item.to_dict() for item in execution.observations)
            for stage, execution in target_by_stage.items()
        },
        "run_id": authority_decision.run_id,
        "runtime_authorization_fingerprint": runtime_authorization.fingerprint,
        "runtime_receipt_fingerprint": runtime.fingerprint,
        "replay_authority_decision": replay_authority.to_dict(),
        "replay_authority_decision_fingerprint": replay_authority.fingerprint,
        "security_fingerprint": security.fingerprint,
        "security_id": security.security_id,
        "split_observations": split_observations,
        "empty_split_disposition": (
            None if not empty_split_dispositions else empty_split_dispositions[0]
        ),
        "stage_bundle_fingerprints": {
            stage: tuple(
                execution.bundle.fingerprint
                for execution in executions
                if execution.bundle.issuer_id == security.issuer_id
                and execution.bundle.stage == stage
            )
            for stage in (
                "valuation_pre_price_verification",
                "market_reference",
                "post_valuation_context",
            )
        },
        "stage_execution_authority_fingerprints": {
            stage: tuple(
                _projection_sha256(
                    {
                        "bundle": execution.bundle.fingerprint,
                        "requests": [item.fingerprint for item in execution.requests],
                        "responses": [item.fingerprint for item in execution.responses],
                        "observations": [item.fingerprint for item in execution.observations],
                        "history_quota": (
                            None
                            if execution.history_quota is None
                            else execution.history_quota.fingerprint
                        ),
                    }
                )
                for execution in executions
                if execution.bundle.issuer_id == security.issuer_id
                and execution.bundle.stage == stage
            )
            for stage in (
                "valuation_pre_price_verification",
                "market_reference",
                "post_valuation_context",
            )
        },
        "supply_chain_fingerprint": supply.fingerprint,
    }


def _load_captured_private_canary_evidence(
    capture: dict[str, Any],
    *,
    executed_at: datetime,
) -> dict[str, Any]:
    from owner_research.fingerprints import to_json_value
    from owner_research.owner_equity_research import (
        SecurityScope,
        _report_authority_fingerprint,
    )
    from owner_research.research_publisher import load_owner_research_package
    from owner_research.valuation_run_archive import load_valuation_run_archive

    root = capture["snapshot_root"]
    original_root = capture["original_root"]
    try:
        owner_payload = _strict_json_file(
            root / "owner-equity-result.json",
            label="owner-equity result",
            protected=True,
        )
        phase_payload = _strict_json_file(
            root / "owner-equity-phase-receipts.json",
            label="owner-equity phase receipts",
            protected=True,
        )
        typed_authority_payload = _strict_json_file(
            root / "owner-equity-typed-authorities.json",
            label="typed canary authorities",
            protected=True,
        )
        valuation_input_payload = _strict_json_file(
            root / "valuation-run-input-receipt.json",
            label="valuation run input receipt",
            protected=True,
        )
        futu_payload = _strict_json_file(
            root / "futu-private-evidence.json",
            label="private Futu evidence",
            protected=True,
        )
        archive = load_valuation_run_archive(root / "six-file-archive")
        package = load_owner_research_package(root / "publication")
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, ReleaseAssemblyError):
            raise
        raise ReleaseAssemblyError("private canary evidence failed strict reload") from exc
    input_receipt, result_phases = _load_owner_result(owner_payload)
    valuation_input = _load_valuation_input(valuation_input_payload)
    futu = _load_private_futu(
        futu_payload,
        keyring_file=root / "futu-keyring.json",
        executed_at=executed_at,
    )
    if (
        package.profile != "full_valuation"
        or package.valuation is None
        or package.futu_session_manifest is None
        or package.forward_reoi_manifest is None
        or package.comparable_valuation_manifest is None
        or package.composite_valuation_manifest is None
        or package.owner_scorecard_manifest is None
        or package.market_expectations_manifest is None
        or package.runtime_gap_manifest is not None
        or len(package.score_v2_manifests) != 4
    ):
        raise ReleaseAssemblyError("private Publisher package is not a complete full valuation")
    publication = to_json_value(package.publication_manifest)
    futu_manifest = package.futu_session_manifest.to_dict()
    forward = package.forward_reoi_manifest.to_dict()
    comparables = package.comparable_valuation_manifest.to_dict()
    composite = package.composite_valuation_manifest.to_dict()
    scores = tuple(item.to_dict() for item in package.score_v2_manifests)
    scorecard = package.owner_scorecard_manifest.to_dict()
    market_expectations = package.market_expectations_manifest.to_dict()
    composite_source = composite["source_payload"]
    scorecard_source = scorecard["source_payload"]
    qa = to_json_value(package.report.receipt)["qa"]
    archive_manifest = to_json_value(archive.manifest)
    published_archive_manifest = to_json_value(package.valuation.manifest)
    archive_files = to_json_value(archive.file_sha256)
    published_archive_files = to_json_value(package.valuation.file_sha256)
    package_files = to_json_value(package.file_sha256)
    session_finalized_at = _parse_time(
        futu_manifest["finalized_at"],
        label="published Futu session finalized_at",
    )
    if (
        archive.fingerprint != package.valuation.fingerprint
        or archive_files != published_archive_files
        or archive_manifest != published_archive_manifest
        or set(archive_files) != set(VALUATION_ARCHIVE_MEMBERS)
        or archive_manifest.get("kernel_execution_projection", {}).get("call_count") != 1
        or composite_source.get("status") != "complete"
        or composite_source.get("contested") is not False
        or composite_source.get("recommendation_eligible") is not True
        or composite_source.get("twelve_month_target") is None
        or scorecard_source.get("status") != "complete"
        or scorecard_source.get("recommendation") == "无法评级"
        or {item["source_payload"].get("lens") for item in scores} != set(SCORE_LENSES)
        or any(item["source_payload"].get("status") != "complete" for item in scores)
        or not isinstance(qa.get("page_count"), int)
        or isinstance(qa.get("page_count"), bool)
        or not 30 <= qa["page_count"] <= 60
        or qa.get("rendered_page_count") != qa["page_count"]
        or "report/report.pdf" not in package_files
        or session_finalized_at > executed_at
    ):
        raise ReleaseAssemblyError(
            "private package lacks one kernel call, three panels, four scores, target, or PDF"
        )
    package_request_refs = _reference_set(futu_manifest["requests"], label="published requests")
    package_response_refs = _reference_set(futu_manifest["responses"], label="published responses")
    package_observation_refs = _reference_set(
        futu_manifest["observations"], label="published observations"
    )
    package_cross_check_refs = _reference_set(
        futu_manifest["cross_checks"], label="published cross-checks"
    )
    package_bundle_refs = _reference_set(
        futu_manifest["execution_bundles"], label="published execution bundles"
    )
    if (
        not package_bundle_refs.issubset(futu["bundle_refs"])
        or package_request_refs != futu["request_refs"]
        or package_response_refs != futu["response_refs"]
        or package_observation_refs != futu["observation_refs"]
        or package_cross_check_refs != futu["cross_check_refs"]
        or futu_manifest["authority_decision_fingerprint"] != futu["authority_decision_fingerprint"]
        or futu_manifest["runtime_authorization_fingerprint"]
        != futu["runtime_authorization_fingerprint"]
        or futu_manifest["runtime_receipt_fingerprint"] != futu["runtime_receipt_fingerprint"]
        or futu_manifest["attested_finalization_fingerprint"] != futu["finalization_fingerprint"]
        or futu_manifest["sidecar_boot_attestation"]["fingerprint"]
        != futu["boot_attestation_fingerprint"]
        or futu_manifest["sidecar_execution_attestation"]["fingerprint"]
        != futu["execution_attestation_fingerprint"]
    ):
        raise ReleaseAssemblyError("private Futu evidence differs from the published session")
    handoff = archive.handoff
    snapshot = archive.market_reference
    security = to_json_value(snapshot.security)
    identity = {
        "currency": snapshot.quote_currency,
        "data_cutoff_date": handoff.data_cutoff_date,
        "issuer_id": handoff.issuer_id,
        "run_id": handoff.handoff_run_id,
        "security_id": security.get("security_id"),
    }
    if (
        input_receipt.request.issuer_id != identity["issuer_id"]
        or input_receipt.request.data_cutoff_date != identity["data_cutoff_date"]
        or valuation_input["issuer_id"] != identity["issuer_id"]
        or valuation_input["data_cutoff_date"] != identity["data_cutoff_date"]
        or valuation_input["component_lock_sha256"] != handoff.component_lock_sha256
        or valuation_input["price_blind_input_fingerprint"] != archive.price_blind_input.fingerprint
        or publication["issuer_id"] != identity["issuer_id"]
        or publication["data_cutoff_date"] != identity["data_cutoff_date"]
        or futu["run_id"] != identity["run_id"]
        or futu["issuer_id"] != identity["issuer_id"]
        or futu["security_id"] != identity["security_id"]
        or futu["currency"] != identity["currency"]
        or futu["data_cutoff_dates"] != {identity["data_cutoff_date"]}
        or futu_manifest["run_id"] != identity["run_id"]
        or futu_manifest["issuer_id"] != identity["issuer_id"]
        or futu_manifest["security_id"] != identity["security_id"]
    ):
        raise ReleaseAssemblyError("private canary objects do not share one exact run identity")
    security_scope = SecurityScope(
        listing_mics=(futu["mic"],),
        currency=futu["currency"],
        security_kind="single_common_stock",
        share_classes=("common",),
        sec_reporting=True,
        industry_kind="general_operating_company",
    )
    optional_disposition_fingerprints = [
        item.fingerprint for item in package.futu_optional_data_disposition_manifests
    ]
    research_authority_fingerprint = _captured_research_authority_fingerprint(
        snapshot_root=root,
        original_root=original_root,
        package=package,
    )
    typed_authorities = _load_typed_canary_authorities(
        typed_authority_payload,
        archive=archive,
        valuation_input=valuation_input,
        futu=futu,
        market_execution_fingerprint=futu_manifest["market_execution_evidence"]["fingerprint"],
        snapshot_root=root,
        original_archive_directory=original_root / "six-file-archive",
        archive_directory_identity=capture["directory_identities"]["six-file-archive"],
    )
    if futu_manifest["contract_graph_fingerprint"] != typed_authorities[
        "contract_graph_fingerprint"
    ]:
        raise ReleaseAssemblyError(
            "published Futu cross-check graph differs from the replayed valuation context"
        )
    archive_authority_fingerprint = _projection_sha256(
        {
            "output_directory": str(original_root / "six-file-archive"),
            "directory_device": capture["directory_identities"]["six-file-archive"][0],
            "directory_inode": capture["directory_identities"]["six-file-archive"][1],
            "manifest_fingerprint": archive.fingerprint,
            "file_sha256": archive_files,
        }
    )
    package_authority_fingerprint = _projection_sha256(
        {
            "output_directory": str(original_root / "publication"),
            "package_fingerprint": package.fingerprint,
            "file_sha256": package_files,
        }
    )
    expected_authorities = {
        "official_research": (
            research_authority_fingerprint,
            package.research_source_manifest.fingerprint,
            security_scope.fingerprint,
        ),
        "futu_nonprice": (
            futu["stage_execution_authority_fingerprints"]["valuation_pre_price_verification"][0],
            _projection_sha256(optional_disposition_fingerprints),
        ),
        "price_blind": (
            research_authority_fingerprint,
            valuation_input["expected_freeze_fingerprint"],
        ),
        "market_reference": (
            futu_manifest["market_execution_evidence"]["fingerprint"],
            typed_authorities["market_provider_fingerprint"],
        ),
        "kernel": (
            typed_authorities["valuation_run_result_fingerprint"],
            archive_authority_fingerprint,
        ),
        "synthesis": (
            typed_authorities["valuation_run_result_fingerprint"],
            forward["source_fingerprint"],
            comparables["source_fingerprint"],
            composite["source_fingerprint"],
            futu_manifest["peer_evidence_set"]["fingerprint"],
        ),
        "score": (
            _projection_sha256(
                [item["score_fingerprint"] for item in scorecard_source["lens_scores"]]
            ),
            scorecard["source_fingerprint"],
        ),
        "market_expectations": (
            futu_manifest["session_fingerprint"],
            market_expectations["comparison_fingerprint"],
        ),
        "report": (
            _report_authority_fingerprint(package.report),
            package.report.receipt.fingerprint,
        ),
        "publication": (
            package_authority_fingerprint,
            publication["manifest_fingerprint"],
        ),
    }
    _phase_receipts, phase_set_fingerprint = _load_phase_receipts(
        phase_payload,
        input_receipt=input_receipt,
        result_phases=result_phases,
        expected_authorities=expected_authorities,
    )
    top_file_sha256 = capture["top_file_sha256"]
    evidence_identity = {
        "archive_file_sha256": archive_files,
        "archive_fingerprint": archive.fingerprint,
        "futu": to_json_value(
            {
                key: value
                for key, value in futu.items()
                if not key.startswith("_")
                and key
                not in {
                    "bundle_refs",
                    "cross_check_refs",
                    "data_cutoff_dates",
                    "observation_refs",
                    "request_refs",
                    "response_refs",
                }
            }
        ),
        "identity": identity,
        "owner_input_receipt_fingerprint": input_receipt.fingerprint,
        "owner_result_fingerprint": owner_payload["result_fingerprint"],
        "package_file_sha256": package_files,
        "package_fingerprint": package.fingerprint,
        "phase_receipt_set_fingerprint": phase_set_fingerprint,
        "private_directory_identities": capture["directory_identities"],
        "private_root_identity": capture["root_identity"],
        "publication_manifest_fingerprint": publication["manifest_fingerprint"],
        "typed_authorities": typed_authorities,
        "top_file_sha256": top_file_sha256,
        "valuation_input_receipt_fingerprint": _projection_sha256(valuation_input),
    }
    return {
        **evidence_identity,
        "account_fingerprint": futu["account_fingerprint"],
        "cross_check_root_fingerprint": futu["cross_check_root_fingerprint"],
        "evidence_root_sha256": _projection_sha256(evidence_identity),
        "finalization_fingerprint": futu["finalization_fingerprint"],
        "legal_fingerprint": futu["legal_fingerprint"],
        "pdf_pages": qa["page_count"],
        "runtime_authorization_fingerprint": futu["runtime_authorization_fingerprint"],
        "runtime_receipt_fingerprint": futu["runtime_receipt_fingerprint"],
        "replay_authority_decision_fingerprint": futu[
            "replay_authority_decision_fingerprint"
        ],
        "security_fingerprint": futu["security_fingerprint"],
        "sidecar_boot_attestation_fingerprint": futu["boot_attestation_fingerprint"],
        "sidecar_execution_attestation_fingerprint": futu["execution_attestation_fingerprint"],
        "supply_chain_fingerprint": futu["supply_chain_fingerprint"],
    }


def _load_private_canary_evidence(
    input_directory: Path,
    *,
    executed_at: datetime,
) -> dict[str, Any]:
    with _captured_private_evidence(input_directory) as capture:
        return _load_captured_private_canary_evidence(
            capture,
            executed_at=executed_at,
        )


def _load_release_trust_policy(
    *,
    executed_at: datetime,
    verification_time: datetime,
) -> dict[str, Any]:
    anchor = RELEASE_CONTROL_TRUST_POLICY_SHA256
    if not isinstance(anchor, str) or HEX_64.fullmatch(anchor) is None:
        raise ReleaseAssemblyError(
            "release signer trust policy is bootstrap-pending and blocks RC assembly"
        )
    raw = _read_regular(
        RELEASE_TRUST_POLICY_PATH,
        label="release signer trust policy",
        maximum_bytes=MAXIMUM_JSON_BYTES,
        protected=True,
    )
    if hashlib.sha256(raw).hexdigest() != anchor:
        raise ReleaseAssemblyError("release signer trust policy differs from its control anchor")
    policy = _strict_json_bytes(raw, label="release signer trust policy")
    _closed_keys(
        policy,
        {
            "artifact_type",
            "keys",
            "policy_id",
            "schema_version",
            "signer_keys_installed",
            "status",
            "valid_from",
            "valid_until",
        },
        label="release signer trust policy",
    )
    valid_from = _parse_time(policy["valid_from"], label="release trust policy.valid_from")
    valid_until = _parse_time(policy["valid_until"], label="release trust policy.valid_until")
    keys = policy["keys"]
    if (
        policy["artifact_type"] != "owner-equity-release-canary-trust-policy"
        or policy["schema_version"] != "1.0.0"
        or policy["policy_id"] != "owner-equity-rc-release-control-v1"
        or policy["signer_keys_installed"] is not True
        or policy["status"] != "active"
        or not (
            valid_from <= executed_at <= valid_until
            and valid_from <= verification_time <= valid_until
        )
        or not isinstance(keys, list)
        or not keys
    ):
        raise ReleaseAssemblyError("release signer trust policy is blocked, expired, or incomplete")
    active: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for item in keys:
        key = _closed_keys(
            item,
            {
                "key_id",
                "not_after",
                "not_before",
                "public_key_sha256",
                "revoked",
                "status",
                "usage",
            },
            label="release signer trust policy key",
        )
        key_id = key["key_id"]
        public_key_sha256 = key["public_key_sha256"]
        not_before = _parse_time(key["not_before"], label="release trust key.not_before")
        not_after = _parse_time(key["not_after"], label="release trust key.not_after")
        if (
            not isinstance(key_id, str)
            or not key_id
            or key_id in seen_ids
            or not isinstance(public_key_sha256, str)
            or HEX_64.fullmatch(public_key_sha256) is None
            or key["usage"] != SIGNING_USAGE
            or not isinstance(key["revoked"], bool)
            or key["status"] not in {"active", "blocked"}
        ):
            raise ReleaseAssemblyError("release signer trust policy key is invalid or duplicated")
        seen_ids.add(key_id)
        if (
            key["status"] == "active"
            and key["revoked"] is False
            and not_before <= executed_at <= not_after
            and not_before <= verification_time <= not_after
        ):
            active.append(key)
    if len(active) != 1:
        raise ReleaseAssemblyError(
            "release signer trust policy must select exactly one active RC trusted signer key"
        )
    return active[0]


def _load_trusted_key(
    key_file: Path,
    *,
    expected_key_id: str,
    source_root: Path,
    executed_at: datetime,
    verification_time: datetime,
) -> Ed25519PublicKey:
    policy_key = _load_release_trust_policy(
        executed_at=executed_at,
        verification_time=verification_time,
    )
    if expected_key_id != policy_key["key_id"]:
        raise ReleaseAssemblyError("CLI signer key id is not the release-control signer")
    requested = Path(os.path.abspath(Path(key_file).expanduser()))
    source = Path(os.path.abspath(Path(source_root).expanduser()))
    if requested == source or source in requested.parents:
        raise ReleaseAssemblyError(
            "trusted signer key must be preinstalled outside candidate source"
        )
    root_descriptor = -1
    opened_descriptors: list[int] = []

    def open_directory_chain(
        path: Path,
        *,
        label: str,
        protected: bool,
    ) -> tuple[int, tuple[tuple[int, str, int, tuple[int, ...]], ...]]:
        parent = root_descriptor
        chain: list[tuple[int, str, int, tuple[int, ...]]] = []
        for component in path.parts[1:]:
            initial = os.stat(component, dir_fd=parent, follow_symlinks=False)
            descriptor = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            opened_descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            identity = _stat_identity(opened)
            if _stat_identity(initial) != identity or not stat.S_ISDIR(opened.st_mode):
                raise ReleaseAssemblyError(f"{label} changed while being opened")
            if protected and (
                stat.S_IMODE(opened.st_mode) & 0o022 or opened.st_uid not in {0, os.geteuid()}
            ):
                raise ReleaseAssemblyError("trusted signer key has an unsafe writable ancestor")
            chain.append((parent, component, descriptor, identity))
            parent = descriptor
        return parent, tuple(chain)

    try:
        root_descriptor = os.open(
            "/",
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        opened_descriptors.append(root_descriptor)
        root_details = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(root_details.st_mode)
            or stat.S_IMODE(root_details.st_mode) & 0o022
            or root_details.st_uid not in {0, os.geteuid()}
        ):
            raise ReleaseAssemblyError("trusted signer key has an unsafe writable ancestor")
        source_descriptor, _source_chain = open_directory_chain(
            source,
            label="candidate source root",
            protected=False,
        )
        key_parent_descriptor, key_chain = open_directory_chain(
            requested.parent,
            label="trusted signer key ancestor",
            protected=True,
        )
        source_identity = _stat_identity(os.fstat(source_descriptor))
        if source_identity in {identity for _parent, _name, _fd, identity in key_chain}:
            raise ReleaseAssemblyError(
                "trusted signer key must be preinstalled outside candidate source"
            )
        key_initial = os.stat(
            requested.name,
            dir_fd=key_parent_descriptor,
            follow_symlinks=False,
        )
        key_descriptor = os.open(
            requested.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=key_parent_descriptor,
        )
        opened_descriptors.append(key_descriptor)
        key_before = os.fstat(key_descriptor)
        if (
            _stat_identity(key_initial) != _stat_identity(key_before)
            or not stat.S_ISREG(key_before.st_mode)
            or key_before.st_nlink != 1
            or stat.S_IMODE(key_before.st_mode) & 0o022
            or key_before.st_uid not in {0, os.geteuid()}
            or key_before.st_size > MAXIMUM_JSON_BYTES
        ):
            raise ReleaseAssemblyError("trusted signer key is not a protected single-link file")
        chunks = bytearray()
        while len(chunks) <= MAXIMUM_JSON_BYTES:
            chunk = os.read(
                key_descriptor,
                min(1024 * 1024, MAXIMUM_JSON_BYTES + 1 - len(chunks)),
            )
            if not chunk:
                break
            chunks.extend(chunk)
        key_after = os.fstat(key_descriptor)
        if (
            _stat_identity(key_after) != _stat_identity(key_before)
            or len(chunks) != key_before.st_size
            or len(chunks) > MAXIMUM_JSON_BYTES
        ):
            raise ReleaseAssemblyError("trusted signer key changed while being read")
        for parent, name, descriptor, identity in (*_source_chain, *key_chain):
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                _stat_identity(current) != identity
                or _stat_identity(os.fstat(descriptor)) != identity
            ):
                raise ReleaseAssemblyError("trusted signer key path changed while being loaded")
        raw = bytes(chunks)
    except (OSError, ValueError) as exc:
        if isinstance(exc, ReleaseAssemblyError):
            raise
        raise ReleaseAssemblyError("trusted signer key path is unsafe or unavailable") from exc
    finally:
        for descriptor in reversed(opened_descriptors):
            os.close(descriptor)
    key = _strict_json_bytes(raw, label="trusted signer key")
    _closed_keys(
        key,
        {
            "algorithm",
            "artifact_type",
            "key_id",
            "not_after",
            "not_before",
            "public_key_hex",
            "revoked",
            "schema_version",
            "usages",
        },
        label="trusted signer key",
    )
    not_before = _parse_time(key["not_before"], label="trusted key not_before")
    not_after = _parse_time(key["not_after"], label="trusted key not_after")
    public_hex = key["public_key_hex"]
    public_key_sha256 = (
        hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()
        if isinstance(public_hex, str) and re.fullmatch(r"[0-9a-f]{64}", public_hex)
        else None
    )
    if (
        key["artifact_type"] != KEY_TYPE
        or key["schema_version"] != "1.0.0"
        or key["algorithm"] != "Ed25519"
        or key["key_id"] != expected_key_id
        or key["revoked"] is not False
        or key["usages"] != [SIGNING_USAGE]
        or not isinstance(public_hex, str)
        or not re.fullmatch(r"[0-9a-f]{64}", public_hex)
        or public_key_sha256 != policy_key["public_key_sha256"]
        or not (
            not_before <= executed_at <= not_after and not_before <= verification_time <= not_after
        )
    ):
        raise ReleaseAssemblyError(
            "trusted signer key is invalid, revoked, expired, or absent from release policy"
        )
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))


def verify_canary_receipt(
    receipt_file: Path,
    *,
    trusted_key_file: Path,
    trusted_key_id: str,
    source_root: Path,
    expected_commit: str,
    expected_tree: str,
    artifacts: list[dict[str, Any]],
    evidence_directory: Path,
    verification_time_text: str,
) -> dict[str, Any]:
    verification_time = _parse_time(verification_time_text, label="verification time")
    receipt = _strict_json_file(receipt_file, label="signed canary receipt", protected=True)
    _closed_keys(
        receipt,
        {
            "artifact_type",
            "artifacts",
            "canary_root_sha256",
            "candidate_commit",
            "candidate_tree",
            "executed_at",
            "expires_at",
            "gates",
            "invocation_attestation",
            "schema_version",
            "signature",
            "signer_key_id",
        },
        label="signed canary receipt",
    )
    signature = _closed_keys(
        receipt["signature"],
        {"algorithm", "key_id", "value_base64"},
        label="canary signature",
    )
    executed_at = _parse_time(receipt["executed_at"], label="canary executed_at")
    expires_at = _parse_time(receipt["expires_at"], label="canary expires_at")
    public_key = _load_trusted_key(
        trusted_key_file,
        expected_key_id=trusted_key_id,
        source_root=source_root,
        executed_at=executed_at,
        verification_time=verification_time,
    )
    if (
        receipt["artifact_type"] != RECEIPT_TYPE
        or receipt["schema_version"] != "3.0.0"
        or receipt["signer_key_id"] != trusted_key_id
        or receipt["candidate_commit"] != expected_commit
        or receipt["candidate_tree"] != expected_tree
        or receipt["artifacts"] != artifacts
        or signature["algorithm"] != "Ed25519"
        or signature["key_id"] != trusted_key_id
        or not executed_at <= verification_time <= expires_at
    ):
        raise ReleaseAssemblyError("signed canary identity, artifacts, or validity drifted")
    gates = _verify_gate_payload(
        receipt["gates"],
        executed_at=executed_at,
        verification_time=verification_time,
    )
    evidence = _load_private_canary_evidence(
        evidence_directory,
        executed_at=executed_at,
    )
    invocation = _closed_keys(
        receipt["invocation_attestation"],
        {
            "artifact_type",
            "candidate_commit",
            "candidate_tree",
            "console_script",
            "invocation_attestation_fingerprint",
            "output_evidence_root_sha256",
            "owner_wheel_sha256",
            "plugin_bundle_sha256",
            "sidecar_install_attestation",
            "skill_name",
            "status",
            "subcommand",
        },
        label="owner-equity invocation attestation",
    )
    _verify_projection_fingerprint(
        invocation,
        field="invocation_attestation_fingerprint",
        label="owner-equity invocation attestation",
    )
    sidecar_install = _closed_keys(
        invocation["sidecar_install_attestation"],
        {
            "artifact_type",
            "boot_attestation_fingerprint",
            "execution_attestation_fingerprint",
            "install_attestation_fingerprint",
            "sidecar_sdist_sha256",
            "sidecar_wheel_sha256",
            "status",
            "supply_chain_fingerprint",
        },
        label="sidecar install attestation",
    )
    _verify_projection_fingerprint(
        sidecar_install,
        field="install_attestation_fingerprint",
        label="sidecar install attestation",
    )
    artifact_by_role = {item["role"]: item for item in artifacts}
    if (
        invocation["artifact_type"] != "owner-equity-research-canary-invocation-attestation"
        or invocation["status"] != "completed"
        or invocation["candidate_commit"] != expected_commit
        or invocation["candidate_tree"] != expected_tree
        or invocation["console_script"] != "owner-equity-research"
        or invocation["skill_name"] != "owner-equity-research"
        or invocation["subcommand"] != "valuation"
        or invocation["owner_wheel_sha256"] != artifact_by_role["owner_wheel"]["sha256"]
        or invocation["plugin_bundle_sha256"] != artifact_by_role["plugin_bundle"]["sha256"]
        or invocation["output_evidence_root_sha256"] != evidence["evidence_root_sha256"]
        or sidecar_install["artifact_type"] != "owner-equity-sidecar-install-attestation"
        or sidecar_install["status"] != "executed"
        or sidecar_install["sidecar_wheel_sha256"] != artifact_by_role["sidecar_wheel"]["sha256"]
        or sidecar_install["sidecar_sdist_sha256"] != artifact_by_role["sidecar_sdist"]["sha256"]
        or sidecar_install["supply_chain_fingerprint"] != evidence["supply_chain_fingerprint"]
        or sidecar_install["boot_attestation_fingerprint"]
        != evidence["sidecar_boot_attestation_fingerprint"]
        or sidecar_install["execution_attestation_fingerprint"]
        != evidence["sidecar_execution_attestation_fingerprint"]
    ):
        raise ReleaseAssemblyError(
            "canary invocation did not produce the strictly reloaded evidence root"
        )
    gate_bindings = {
        "legal": ("authority_fingerprint", "legal_fingerprint"),
        "account_entitlement": ("authority_fingerprint", "account_fingerprint"),
        "supply_chain": ("authority_fingerprint", "supply_chain_fingerprint"),
        "runtime_isolation": (
            "authority_fingerprint",
            "runtime_authorization_fingerprint",
        ),
        "security_identity": ("authority_fingerprint", "security_fingerprint"),
        "session": ("attested_finalization_fingerprint", "finalization_fingerprint"),
        "sec_ir_reconciliation": (
            "cross_check_root_fingerprint",
            "cross_check_root_fingerprint",
        ),
        "six_file_archive": ("archive_fingerprint", "archive_fingerprint"),
        "publisher_pdf": (
            "publication_manifest_fingerprint",
            "publication_manifest_fingerprint",
        ),
    }
    for gate_name, (gate_field, evidence_field) in gate_bindings.items():
        if gates[gate_name][gate_field] != evidence[evidence_field]:
            raise ReleaseAssemblyError(f"{gate_name} gate rebound private typed evidence")
    if (
        gates["runtime_isolation"]["completed_runtime_fingerprint"]
        != evidence["runtime_receipt_fingerprint"]
        or gates["runtime_isolation"]["replay_authority_decision_fingerprint"]
        != evidence["replay_authority_decision_fingerprint"]
    ):
        raise ReleaseAssemblyError(
            "runtime isolation gate rebound completed replay-only authority"
        )
    if gates["publisher_pdf"]["pdf_pages"] != evidence["pdf_pages"]:
        raise ReleaseAssemblyError("Publisher gate rebound the strictly loaded PDF")
    root_payload = {
        "artifact_type": "owner-equity-rc-canary-root",
        "artifacts": artifacts,
        "candidate_commit": expected_commit,
        "candidate_tree": expected_tree,
        "evidence_root_sha256": evidence["evidence_root_sha256"],
        "executed_at": receipt["executed_at"],
        "gate_receipt_sha256": {name: gates[name]["receipt_sha256"] for name in GATE_NAMES},
        "invocation_attestation_fingerprint": invocation["invocation_attestation_fingerprint"],
        "schema_version": "2.0.0",
    }
    root_sha256 = _fingerprint(
        receipt["canary_root_sha256"],
        label="signed canary root",
    )
    if root_sha256 != _projection_sha256(root_payload):
        raise ReleaseAssemblyError("signed canary root does not replay exact typed evidence")
    encoded_signature = signature["value_base64"]
    if not isinstance(encoded_signature, str):
        raise ReleaseAssemblyError("canary signature is not base64 text")
    try:
        signature_raw = base64.b64decode(encoded_signature, validate=True)
    except (ValueError, TypeError) as exc:
        raise ReleaseAssemblyError("canary signature is not strict base64") from exc
    if len(signature_raw) != 64:
        raise ReleaseAssemblyError("canary signature length is invalid")
    signed_payload = dict(receipt)
    signed_payload.pop("signature")
    try:
        public_key.verify(signature_raw, canonical_json_bytes(signed_payload, newline=False))
    except InvalidSignature as exc:
        raise ReleaseAssemblyError("canary signature verification failed") from exc
    return receipt


def _release_source_metadata(source_root: Path, commit: str) -> dict[str, Any]:
    supply = _load_release_supply_authority(source_root, commit)
    try:
        owner = supply["project_by_name"]["owner"]["project"]
        sidecar = supply["project_by_name"]["sidecar"]["project"]
        plugin = json.loads(
            _git_bytes(
                source_root,
                commit,
                "plugins/owner-equity-research/.codex-plugin/plugin.json",
            )
        )
    except (KeyError, UnicodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseAssemblyError(f"release source metadata is invalid: {exc}") from exc
    for label, project in (("owner", owner), ("sidecar", sidecar), ("Plugin", plugin)):
        if not isinstance(project, dict):
            raise ReleaseAssemblyError(f"{label} release metadata is not an object")
    return {"owner": owner, "plugin": plugin, "sidecar": sidecar, "supply": supply}


def _canonical_artifact_basenames(source: dict[str, Any]) -> dict[str, str]:
    """Derive the closed role-to-basename mapping from exact source metadata."""
    for key, expected_name in EXPECTED_PROJECT_NAMES.items():
        project = source.get(key)
        if not isinstance(project, dict) or project.get("name") != expected_name:
            raise ReleaseAssemblyError(f"{key} project name is not the pinned release identity")
        version = project.get("version")
        if not isinstance(version, str) or not version or not SAFE_FILENAME.fullmatch(version):
            raise ReleaseAssemblyError(f"{key} project version is not filename-safe")
    owner_version = source["owner"]["version"]
    sidecar_version = source["sidecar"]["version"]
    plugin_version = source["plugin"]["version"]
    names = {
        "owner_wheel": f"owner_equity_research-{owner_version}-py3-none-any.whl",
        "owner_sdist": f"owner_equity_research-{owner_version}.tar.gz",
        "plugin_bundle": f"owner-equity-research-plugin-{plugin_version}.zip",
        "sidecar_wheel": (
            f"owner_research_futu_sidecar-{sidecar_version}-py3-none-any.whl"
        ),
        "sidecar_sdist": f"owner_research_futu_sidecar-{sidecar_version}.tar.gz",
    }
    if (
        set(names) != set(ARTIFACT_ROLES)
        or len(set(names.values())) != len(names)
        or set(names.values()) & set(GENERATED_PUBLIC_FILES)
        or any(SAFE_FILENAME.fullmatch(name) is None for name in names.values())
    ):
        raise ReleaseAssemblyError("canonical release artifact basename set is invalid")
    return names


def _sbom_wheel_target(filename: str, *, python_targets: Any) -> dict[str, Any]:
    if not isinstance(filename, str) or not filename.endswith(".whl"):
        raise ReleaseAssemblyError("derived dependency wheel filename is invalid")
    try:
        _distribution, _version, python_tag, abi_tag, platform_tag = filename[
            : -len(".whl")
        ].rsplit("-", 4)
    except ValueError as exc:
        raise ReleaseAssemblyError("derived dependency wheel tags are unavailable") from exc
    if (
        not isinstance(python_targets, list)
        or not python_targets
        or any(not isinstance(item, str) or not item for item in python_targets)
    ):
        raise ReleaseAssemblyError("derived dependency wheel Python targets are invalid")
    return {
        "abi_tags": sorted(abi_tag.split(".")),
        "kind": "wheel",
        "platform_tags": sorted(platform_tag.split(".")),
        "python_tags": sorted(python_tag.split(".")),
        "python_targets": python_targets,
    }


def _build_sbom(
    *,
    source: dict[str, Any],
    commit: str,
    tree: str,
    artifact_by_role: dict[str, dict[str, Any]],
    assembled_at: str,
    mode: str,
) -> dict[str, Any]:
    supply = source.get("supply")
    if not isinstance(supply, dict):
        raise ReleaseAssemblyError("verified dependency supply authority is missing")
    lock = supply.get("lock")
    manifest = supply.get("manifest")
    identity = supply.get("identity")
    sha256_by_path = supply.get("sha256_by_path")
    if (
        not isinstance(lock, dict)
        or not isinstance(manifest, dict)
        or not isinstance(identity, dict)
        or not isinstance(sha256_by_path, dict)
        or set(sha256_by_path) != set(DEPENDENCY_SUPPLY_AUTHORITY_PATHS)
    ):
        raise ReleaseAssemblyError("verified dependency supply authority is incomplete")

    def properties(values: dict[str, str]) -> list[dict[str, str]]:
        if any(not isinstance(value, str) for value in values.values()):
            raise ReleaseAssemblyError("SBOM property values must be text")
        return [
            {"name": name, "value": values[name]}
            for name in sorted(values)
        ]

    def compact(value: Any) -> str:
        return canonical_json_bytes(value, newline=False).decode("utf-8")

    applications = (
        (
            "owner",
            source["owner"]["name"],
            source["owner"]["version"],
            artifact_by_role["owner_wheel"]["sha256"],
            "public_release",
        ),
        (
            "sidecar",
            source["sidecar"]["name"],
            source["sidecar"]["version"],
            artifact_by_role["sidecar_wheel"]["sha256"],
            "private_canary_input",
        ),
        (
            "plugin",
            source["plugin"]["name"],
            source["plugin"]["version"],
            artifact_by_role["plugin_bundle"]["sha256"],
            "public_release",
        ),
    )
    components: list[dict[str, Any]] = []
    dependency_edges: dict[str, list[str]] = {}
    application_references: dict[str, str] = {}
    for owner_key, name, version, digest, distribution_scope in applications:
        reference = f"application:{owner_key}:{version}"
        application_references[owner_key] = reference
        components.append(
            {
                "bom-ref": reference,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "name": name,
                "properties": properties(
                    {
                        "owner.distribution_scope": distribution_scope,
                        "owner.source.commit": commit,
                        "owner.source.tree": tree,
                    }
                ),
                "type": "application",
                "version": version,
            }
        )
        dependency_edges[reference] = []

    lock_components = lock.get("components")
    manifest_artifacts = manifest.get("artifacts")
    if not isinstance(lock_components, list) or not isinstance(manifest_artifacts, list):
        raise ReleaseAssemblyError("verified dependency inventory is invalid")
    artifact_refs_by_library: dict[str, list[str]] = {}
    library_ref_by_name: dict[str, str] = {}
    for locked_component in lock_components:
        if not isinstance(locked_component, dict):
            raise ReleaseAssemblyError("verified dependency component is invalid")
        name = locked_component.get("name")
        version = locked_component.get("version")
        license_expression = locked_component.get("license_expression")
        requirements = locked_component.get("requirements")
        evidence = locked_component.get("license_evidence")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not isinstance(license_expression, str)
            or not isinstance(requirements, list)
            or not isinstance(evidence, dict)
        ):
            raise ReleaseAssemblyError("verified dependency component fields are invalid")
        reference = f"pkg:pypi/{name}@{version}"
        if name in library_ref_by_name or reference in dependency_edges:
            raise ReleaseAssemblyError("verified dependency components are not unique")
        library_ref_by_name[name] = reference
        components.append(
            {
                "bom-ref": reference,
                "licenses": [{"expression": license_expression}],
                "name": name,
                "properties": properties(
                    {
                        "owner.dependency.inventory_scope": supply["inventory_scope"],
                        "owner.dependency.license_evidence": compact(evidence),
                        "owner.dependency.requirements": compact(requirements),
                    }
                ),
                "purl": reference,
                "type": "library",
                "version": version,
            }
        )
        dependency_edges[reference] = []
        artifact_refs_by_library[name] = []
        for requirement in requirements:
            if not isinstance(requirement, dict) or requirement.get("project") not in {
                "owner",
                "sidecar",
            }:
                raise ReleaseAssemblyError("verified dependency requirement is invalid")
            dependency_edges[application_references[requirement["project"]]].append(reference)

    for artifact in manifest_artifacts:
        if not isinstance(artifact, dict):
            raise ReleaseAssemblyError("verified dependency artifact is invalid")
        component_name = artifact.get("component")
        filename = artifact.get("filename")
        digest = artifact.get("sha256")
        target = artifact.get("target")
        if (
            component_name not in library_ref_by_name
            or not isinstance(filename, str)
            or not isinstance(digest, str)
            or not isinstance(target, dict)
        ):
            raise ReleaseAssemblyError("verified dependency artifact fields are invalid")

        def append_artifact_component(
            *,
            artifact_component_name: str,
            artifact_name: str,
            artifact_sha256: str,
            artifact_target: dict[str, Any],
            artifact_role: str,
            extra_properties: dict[str, str] | None = None,
        ) -> str:
            reference = f"artifact:{artifact_sha256}:{artifact_name}"
            if reference in dependency_edges:
                raise ReleaseAssemblyError("verified dependency artifact references collide")
            target_properties = {
                f"owner.artifact.target.{key}": compact(value)
                for key, value in artifact_target.items()
            }
            target_properties.update(
                {
                    "owner.artifact.component": artifact_component_name,
                    "owner.artifact.filename": artifact_name,
                    "owner.artifact.role": artifact_role,
                }
            )
            if extra_properties:
                target_properties.update(extra_properties)
            components.append(
                {
                    "bom-ref": reference,
                    "hashes": [{"alg": "SHA-256", "content": artifact_sha256}],
                    "name": artifact_name,
                    "properties": properties(target_properties),
                    "type": "file",
                }
            )
            dependency_edges[reference] = []
            artifact_refs_by_library[artifact_component_name].append(reference)
            return reference

        source_reference = append_artifact_component(
            artifact_component_name=component_name,
            artifact_name=filename,
            artifact_sha256=digest,
            artifact_target=target,
            artifact_role="locked_artifact",
        )
        derived = artifact.get("derived_wheel")
        if derived is not None:
            if not isinstance(derived, dict) or not isinstance(derived.get("recipe"), dict):
                raise ReleaseAssemblyError("verified derived dependency artifact is invalid")
            recipe = derived["recipe"]
            derived_target = _sbom_wheel_target(
                derived.get("filename"),
                python_targets=recipe.get("python_targets"),
            )
            append_artifact_component(
                artifact_component_name=component_name,
                artifact_name=derived.get("filename"),
                artifact_sha256=derived.get("sha256"),
                artifact_target=derived_target,
                artifact_role="derived_artifact",
                extra_properties={
                    "owner.artifact.build_recipe": compact(recipe),
                    "owner.artifact.derived_from": source_reference,
                },
            )

    for name, reference in library_ref_by_name.items():
        dependency_edges[reference] = sorted(artifact_refs_by_library[name])
    for reference, children in dependency_edges.items():
        if children != sorted(set(children)):
            dependency_edges[reference] = sorted(set(children))

    supply_properties = {
        "owner.contains_credentials": "false",
        "owner.contains_raw_vendor_data": "false",
        "owner.dependency.inventory_scope": supply["inventory_scope"],
        "owner.dependency.lock.path": DEPENDENCY_LOCK_PATH,
        "owner.dependency.lock.sha256": sha256_by_path[DEPENDENCY_LOCK_PATH],
        "owner.dependency.reviewed_metadata.path": DEPENDENCY_REVIEWED_METADATA_PATH,
        "owner.dependency.reviewed_metadata.sha256": sha256_by_path[
            DEPENDENCY_REVIEWED_METADATA_PATH
        ],
        "owner.dependency.sidecar_reviewed_lock.path": (
            SIDECAR_REVIEWED_DEPENDENCY_LOCK_PATH
        ),
        "owner.dependency.sidecar_reviewed_lock.sha256": sha256_by_path[
            SIDECAR_REVIEWED_DEPENDENCY_LOCK_PATH
        ],
        "owner.dependency.supply_identity.path": DEPENDENCY_SUPPLY_IDENTITY_PATH,
        "owner.dependency.supply_identity.sha256": sha256_by_path[
            DEPENDENCY_SUPPLY_IDENTITY_PATH
        ],
        "owner.dependency.supply_manifest.path": DEPENDENCY_SUPPLY_MANIFEST_PATH,
        "owner.dependency.supply_manifest.sha256": sha256_by_path[
            DEPENDENCY_SUPPLY_MANIFEST_PATH
        ],
        "owner.dependency.validator.path": DEPENDENCY_VALIDATOR_PATH,
        "owner.dependency.validator.sha256": sha256_by_path[DEPENDENCY_VALIDATOR_PATH],
        "owner.project.pyproject.sha256": sha256_by_path["pyproject.toml"],
        "owner.release.mode": mode,
        "owner.sidecar.pyproject.sha256": sha256_by_path[
            "sidecars/futu-opend/pyproject.toml"
        ],
        "owner.source.commit": commit,
        "owner.source.tree": tree,
    }
    serial_seed = canonical_json_bytes(
        {
            "artifacts": artifact_by_role,
            "commit": commit,
            "mode": mode,
            "supply_identity": sha256_by_path[DEPENDENCY_SUPPLY_IDENTITY_PATH],
            "tree": tree,
        },
        newline=False,
    ).decode("utf-8")
    serial = uuid.uuid5(uuid.NAMESPACE_URL, serial_seed)
    return {
        "bomFormat": "CycloneDX",
        "components": sorted(components, key=lambda item: item["bom-ref"]),
        "dependencies": [
            {"dependsOn": dependency_edges[reference], "ref": reference}
            for reference in sorted(dependency_edges)
        ],
        "metadata": {
            "properties": properties(supply_properties),
            "timestamp": assembled_at,
            "tools": {
                "components": [
                    {
                        "name": "owner-equity-release-assembler",
                        "type": "application",
                        "version": "1.0.0",
                    }
                ]
            },
        },
        "serialNumber": f"urn:uuid:{serial}",
        "specVersion": "1.6",
        "version": 1,
    }


def _assert_rc_versions(source: dict[str, Any]) -> None:
    if (
        source["owner"].get("version") != "1.0.0rc1"
        or source["sidecar"].get("version") != "1.0.0rc1"
        or source["plugin"].get("version") != "1.0.0-rc.1"
    ):
        raise ReleaseAssemblyError("RC mode requires the exact unified 1.0.0rc1 versions")


def _rc_readiness_blockers() -> list[str]:
    blockers: list[str] = []
    if not (
        isinstance(RELEASE_CONTROL_TRUST_POLICY_SHA256, str)
        and HEX_64.fullmatch(RELEASE_CONTROL_TRUST_POLICY_SHA256) is not None
    ):
        blockers.append("release_control_root_not_deployed")
    try:
        from owner_research.futu_sidecar import (
            load_critical_financial_concepts,
            load_financial_field_registry,
        )

        required = {
            concept
            for concepts in load_critical_financial_concepts().values()
            for concept in concepts
        }
        mapped = {
            str(item["canonical_concept"])
            for item in load_financial_field_registry().values()
        }
    except (ImportError, KeyError, TypeError, ValueError):
        required = {"unresolved"}
        mapped = set()
    if not required.issubset(mapped):
        blockers.append("reviewed_futu_balance_cash_field_registry_not_deployed")
    return blockers


def _write_file(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise ReleaseAssemblyError(f"release file write did not complete: {path.name}")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
    finally:
        os.close(descriptor)


def _write_file_at(directory_descriptor: int, name: str, raw: bytes) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory_descriptor,
    )
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise ReleaseAssemblyError(f"release file write did not complete: {name}")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
    finally:
        os.close(descriptor)


def _rename_directory_noreplace(
    parent_descriptor: int,
    source_name: str,
    target_name: str,
) -> None:
    """Atomically publish one directory without replacing any target inode."""
    library = ctypes.CDLL(None, use_errno=True)
    function_name = "renameatx_np" if sys.platform == "darwin" else "renameat2"
    try:
        rename = getattr(library, function_name)
    except AttributeError as exc:
        raise ReleaseAssemblyError(
            "atomic no-replace release publication is unavailable"
        ) from exc
    rename.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename.restype = ctypes.c_int
    flag = 0x00000004 if sys.platform == "darwin" else 0x00000001
    ctypes.set_errno(0)
    result = rename(
        parent_descriptor,
        os.fsencode(source_name),
        parent_descriptor,
        os.fsencode(target_name),
        flag,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error, "release output already exists", target_name)
    raise OSError(error, "atomic release publication failed", target_name)


def _release_stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _release_directory_binding(value: os.stat_result) -> tuple[int, ...]:
    """Return directory identity fields unaffected by publishing one child."""
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
    )


def _preserve_failed_staging_at(
    parent_descriptor: int,
    name: str,
    *,
    expected_identity: tuple[int, ...],
    allowed_names: set[str],
) -> bool:
    """Validate failed staging without any pathname deletion or rename."""
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
    except OSError:
        return False
    try:
        if _release_stat_identity(os.fstat(descriptor)) != expected_identity:
            return False
        names = set(os.listdir(descriptor))
        if not names.issubset(allowed_names):
            return False
        for member in sorted(names):
            metadata = os.stat(member, dir_fd=descriptor, follow_symlinks=False)
            if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
                return False
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return True


def _quarantine_published_directory_at(
    parent_descriptor: int,
    name: str,
    *,
    expected_identity: tuple[int, ...],
) -> str:
    current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if _release_stat_identity(current) != expected_identity:
        raise ReleaseAssemblyError("failed release output path no longer binds its published inode")
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent_descriptor,
    )
    try:
        if _release_stat_identity(os.fstat(descriptor)) != expected_identity:
            raise ReleaseAssemblyError(
                "failed release output changed before quarantine"
            )
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
        quarantined_identity = _release_directory_binding(os.fstat(descriptor))
        quarantine = f".{name}.invalid-{uuid.uuid4().hex}"
        _rename_directory_noreplace(parent_descriptor, name, quarantine)
        quarantine_metadata = os.stat(
            quarantine,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if _release_directory_binding(quarantine_metadata) != quarantined_identity:
            raise ReleaseAssemblyError("failed release quarantine identity drifted")
        os.fsync(parent_descriptor)
    finally:
        os.close(descriptor)
    return quarantine


def _read_release_member_at(directory_descriptor: int, name: str) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_descriptor,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o444
            or before.st_size > MAXIMUM_ARTIFACT_BYTES
        ):
            raise ReleaseAssemblyError(f"published release member is unsafe: {name}")
        raw = bytearray()
        while len(raw) <= MAXIMUM_ARTIFACT_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAXIMUM_ARTIFACT_BYTES + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if (
            _release_stat_identity(before) != _release_stat_identity(after)
            or len(raw) != before.st_size
            or len(raw) > MAXIMUM_ARTIFACT_BYTES
        ):
            raise ReleaseAssemblyError(f"published release member changed while read: {name}")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _verify_sbom_closure(
    sbom: dict[str, Any],
    *,
    expected_sbom: dict[str, Any] | None,
) -> None:
    if set(sbom) != {
        "bomFormat",
        "components",
        "dependencies",
        "metadata",
        "serialNumber",
        "specVersion",
        "version",
    } or (
        sbom.get("bomFormat") != "CycloneDX"
        or sbom.get("specVersion") != "1.6"
        or sbom.get("version") != 1
        or not isinstance(sbom.get("serialNumber"), str)
        or re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", sbom["serialNumber"]) is None
    ):
        raise ReleaseAssemblyError("published SBOM envelope is not exact")
    components = sbom.get("components")
    dependencies = sbom.get("dependencies")
    metadata = sbom.get("metadata")
    if (
        not isinstance(components, list)
        or not isinstance(dependencies, list)
        or not isinstance(metadata, dict)
        or set(metadata) != {"properties", "timestamp", "tools"}
    ):
        raise ReleaseAssemblyError("published SBOM closure is invalid")
    references: list[str] = []
    types_by_reference: dict[str, str] = {}
    for component in components:
        if not isinstance(component, dict):
            raise ReleaseAssemblyError("published SBOM component is invalid")
        reference = component.get("bom-ref")
        component_type = component.get("type")
        if not isinstance(reference, str) or component_type not in {
            "application",
            "file",
            "library",
        }:
            raise ReleaseAssemblyError("published SBOM component identity is invalid")
        properties = component.get("properties")
        if not isinstance(properties, list) or any(
            not isinstance(item, dict)
            or set(item) != {"name", "value"}
            or not isinstance(item["name"], str)
            or not isinstance(item["value"], str)
            for item in properties
        ):
            raise ReleaseAssemblyError("published SBOM component properties are invalid")
        property_names = [item["name"] for item in properties]
        if property_names != sorted(set(property_names)):
            raise ReleaseAssemblyError("published SBOM component properties are not exact")
        expected_keys = {
            "application": {"bom-ref", "hashes", "name", "properties", "type", "version"},
            "file": {"bom-ref", "hashes", "name", "properties", "type"},
            "library": {
                "bom-ref",
                "licenses",
                "name",
                "properties",
                "purl",
                "type",
                "version",
            },
        }[component_type]
        if set(component) != expected_keys:
            raise ReleaseAssemblyError("published SBOM component shape is not closed")
        if component_type == "library" and (
            component.get("purl") != reference
            or not isinstance(component.get("version"), str)
            or any(character in component["version"] for character in "<>=,; ")
            or reference
            != f"pkg:pypi/{component.get('name')}@{component.get('version')}"
            or not isinstance(component.get("licenses"), list)
            or len(component["licenses"]) != 1
            or not isinstance(component["licenses"][0], dict)
            or set(component["licenses"][0]) != {"expression"}
            or not isinstance(component["licenses"][0]["expression"], str)
        ):
            raise ReleaseAssemblyError("published SBOM library identity is not exact")
        hashes = component.get("hashes")
        if component_type in {"application", "file"} and (
            not isinstance(hashes, list)
            or len(hashes) != 1
            or not isinstance(hashes[0], dict)
            or hashes[0].get("alg") != "SHA-256"
            or set(hashes[0]) != {"alg", "content"}
            or not isinstance(hashes[0].get("content"), str)
            or HEX_64.fullmatch(hashes[0]["content"]) is None
        ):
            raise ReleaseAssemblyError("published SBOM artifact hash is not exact")
        if component_type == "application" and (
            not isinstance(component.get("name"), str)
            or not isinstance(component.get("version"), str)
            or re.fullmatch(r"application:(owner|sidecar|plugin):.+", reference) is None
            or not reference.endswith(f":{component.get('version')}")
        ):
            raise ReleaseAssemblyError("published SBOM application identity is not exact")
        if component_type == "file":
            property_map = {item["name"]: item["value"] for item in properties}
            if (
                not isinstance(component.get("name"), str)
                or reference
                != f"artifact:{hashes[0]['content']}:{component.get('name')}"
                or property_map.get("owner.artifact.filename") != component.get("name")
                or property_map.get("owner.artifact.role")
                not in {"derived_artifact", "locked_artifact"}
                or "owner.artifact.component" not in property_map
                or "owner.artifact.target.kind" not in property_map
                or "owner.artifact.target.python_targets" not in property_map
            ):
                raise ReleaseAssemblyError("published SBOM file identity is not exact")
        references.append(reference)
        types_by_reference[reference] = component_type
    if references != sorted(set(references)):
        raise ReleaseAssemblyError("published SBOM component references are not exact")

    dependency_references: list[str] = []
    for edge in dependencies:
        if (
            not isinstance(edge, dict)
            or set(edge) != {"dependsOn", "ref"}
            or not isinstance(edge.get("ref"), str)
            or not isinstance(edge.get("dependsOn"), list)
            or any(not isinstance(item, str) for item in edge["dependsOn"])
            or edge["dependsOn"] != sorted(set(edge["dependsOn"]))
        ):
            raise ReleaseAssemblyError("published SBOM dependency edge is not exact")
        reference = edge["ref"]
        if reference not in types_by_reference or any(
            child not in types_by_reference for child in edge["dependsOn"]
        ):
            raise ReleaseAssemblyError("published SBOM dependency edge escapes the closure")
        parent_type = types_by_reference[reference]
        child_types = {types_by_reference[child] for child in edge["dependsOn"]}
        if (
            (parent_type == "application" and not child_types.issubset({"library"}))
            or (parent_type == "library" and not child_types.issubset({"file"}))
            or (parent_type == "file" and edge["dependsOn"])
        ):
            raise ReleaseAssemblyError("published SBOM dependency direction is invalid")
        dependency_references.append(reference)
    if dependency_references != references:
        raise ReleaseAssemblyError("published SBOM dependency graph is not closed")

    metadata_properties = metadata.get("properties")
    if not isinstance(metadata_properties, list) or any(
        not isinstance(item, dict)
        or set(item) != {"name", "value"}
        or not isinstance(item["name"], str)
        or not isinstance(item["value"], str)
        for item in metadata_properties
    ):
        raise ReleaseAssemblyError("published SBOM metadata properties are invalid")
    metadata_names = [item["name"] for item in metadata_properties]
    if metadata_names != sorted(set(metadata_names)):
        raise ReleaseAssemblyError("published SBOM metadata properties are not exact")
    if expected_sbom is not None and sbom != expected_sbom:
        raise ReleaseAssemblyError(
            "published SBOM exact component, dependency, or property closure drifted"
        )


def _verify_reloaded_release_indexes(
    *,
    generated: dict[str, bytes],
    observed: dict[str, tuple[str, int]],
    canonical_names: dict[str, str],
    expected_source_identity: dict[str, str] | None = None,
    expected_application_hashes: dict[str, str] | None = None,
    expected_sbom: dict[str, Any] | None = None,
) -> None:
    manifest = _strict_json_bytes(
        generated["release-manifest.json"],
        label="published release manifest",
    )
    sbom = _strict_json_bytes(
        generated["sbom.cdx.json"],
        label="published release SBOM",
    )
    _verify_sbom_closure(sbom, expected_sbom=expected_sbom)
    records = manifest.get("artifacts")
    expected_roles = (*PUBLIC_ARTIFACT_ROLES, "public_sbom")
    if not isinstance(records, list) or tuple(
        item.get("role") if isinstance(item, dict) else None for item in records
    ) != expected_roles:
        raise ReleaseAssemblyError("published manifest artifact inventory is not exact")
    expected_names = {
        **{role: canonical_names[role] for role in PUBLIC_ARTIFACT_ROLES},
        "public_sbom": "sbom.cdx.json",
    }
    expected_media_types = {
        **{role: ARTIFACT_TYPES[role] for role in PUBLIC_ARTIFACT_ROLES},
        "public_sbom": "application/vnd.cyclonedx+json",
    }
    for record in records:
        if set(record) != {"media_type", "name", "role", "sha256", "size"}:
            raise ReleaseAssemblyError("published manifest artifact record is not closed")
        role = record["role"]
        name = expected_names[role]
        if (
            record["name"] != name
            or record["media_type"] != expected_media_types[role]
            or not isinstance(record["size"], int)
            or isinstance(record["size"], bool)
            or record["size"] < 0
            or record["sha256"] != observed[name][0]
            or record["size"] != observed[name][1]
        ):
            raise ReleaseAssemblyError("published manifest artifact hash or size drifted")
    checksum_names = tuple(sorted(set(observed) - {"SHA256SUMS"}))
    expected_checksums = "".join(
        f"{observed[name][0]}  {name}\n" for name in checksum_names
    ).encode("ascii")
    if generated["SHA256SUMS"] != expected_checksums:
        raise ReleaseAssemblyError("published SHA256SUMS inventory or digest drifted")

    source = manifest.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"commit", "tree"}
        or any(
            not isinstance(source.get(key), str)
            or HEX_40.fullmatch(source[key]) is None
            for key in ("commit", "tree")
        )
    ):
        raise ReleaseAssemblyError("published manifest source identity is invalid")
    if expected_source_identity is not None and source != expected_source_identity:
        raise ReleaseAssemblyError("published manifest source identity drifted")
    private_inputs = manifest.get("private_canary_inputs")
    if not isinstance(private_inputs, list):
        raise ReleaseAssemblyError("published manifest private artifact inventory is invalid")
    private_by_role: dict[str, dict[str, Any]] = {}
    for item in private_inputs:
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "distribution_scope",
                "media_type",
                "role",
                "sha256",
                "size",
            }
            or not isinstance(item.get("role"), str)
            or item["role"] in private_by_role
        ):
            raise ReleaseAssemblyError("published manifest private artifact record is invalid")
        private_by_role[item["role"]] = item
    if set(private_by_role) != set(PRIVATE_CANARY_ARTIFACT_ROLES):
        raise ReleaseAssemblyError("published manifest private artifact roles are not exact")

    components = sbom.get("components")
    if not isinstance(components, list):
        raise ReleaseAssemblyError("published SBOM components are invalid")
    application_components: dict[str, dict[str, Any]] = {}
    for component in components:
        if not isinstance(component, dict) or component.get("type") != "application":
            continue
        reference = component.get("bom-ref")
        if not isinstance(reference, str):
            raise ReleaseAssemblyError("published SBOM application reference is invalid")
        match = re.fullmatch(r"application:(owner|sidecar|plugin):(.+)", reference)
        if match is None or match.group(1) in application_components:
            raise ReleaseAssemblyError("published SBOM application inventory is not exact")
        application_components[match.group(1)] = component
    if set(application_components) != {"owner", "sidecar", "plugin"}:
        raise ReleaseAssemblyError("published SBOM application inventory is not exact")
    observed_application_hashes = {
        "owner": observed[canonical_names["owner_wheel"]][0],
        "plugin": observed[canonical_names["plugin_bundle"]][0],
        "sidecar": private_by_role["sidecar_wheel"].get("sha256"),
    }
    if (
        expected_application_hashes is not None
        and observed_application_hashes != expected_application_hashes
    ):
        raise ReleaseAssemblyError("published application artifact identity drifted")
    for application, component in application_components.items():
        properties = component.get("properties")
        if not isinstance(properties, list) or any(
            not isinstance(item, dict)
            or set(item) != {"name", "value"}
            or not isinstance(item["name"], str)
            or not isinstance(item["value"], str)
            for item in properties
        ):
            raise ReleaseAssemblyError("published SBOM application properties are invalid")
        property_map = {item["name"]: item["value"] for item in properties}
        if len(property_map) != len(properties):
            raise ReleaseAssemblyError("published SBOM application properties are duplicated")
        if (
            component.get("hashes")
            != [{"alg": "SHA-256", "content": observed_application_hashes[application]}]
            or property_map.get("owner.source.commit") != source["commit"]
            or property_map.get("owner.source.tree") != source["tree"]
        ):
            raise ReleaseAssemblyError(
                "published SBOM application hash or source identity drifted"
            )


def _strict_reload_release_directory(
    output: Path,
    *,
    expected_files: dict[str, bytes],
    canonical_names: dict[str, str],
    parent_descriptor: int | None = None,
    expected_parent_identity: tuple[int, ...] | None = None,
    expected_directory_identity: tuple[int, ...] | None = None,
    expected_source_identity: dict[str, str] | None = None,
    expected_application_hashes: dict[str, str] | None = None,
    expected_sbom: dict[str, Any] | None = None,
) -> None:
    expected_names = tuple(sorted(expected_files))
    required_names = {
        *(canonical_names[role] for role in PUBLIC_ARTIFACT_ROLES),
        *GENERATED_PUBLIC_FILES,
    }
    if set(expected_names) != required_names:
        raise ReleaseAssemblyError("expected public release file set is not exact")
    owns_parent_descriptor = parent_descriptor is None
    parent_path_metadata = output.parent.lstat()
    if (
        not stat.S_ISDIR(parent_path_metadata.st_mode)
        or stat.S_ISLNK(parent_path_metadata.st_mode)
    ):
        raise ReleaseAssemblyError("published release parent is unsafe")
    if parent_descriptor is None:
        parent_descriptor = os.open(
            output.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    try:
        parent_before = os.fstat(parent_descriptor)
        parent_snapshot_identity = _release_stat_identity(parent_before)
        parent_binding = _release_directory_binding(parent_before)
        if (
            not stat.S_ISDIR(parent_before.st_mode)
            or parent_snapshot_identity != _release_stat_identity(parent_path_metadata)
            or (
                expected_parent_identity is not None
                and parent_binding != expected_parent_identity
            )
        ):
            raise ReleaseAssemblyError("published release parent identity drifted")
        path_metadata = os.stat(
            output.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        descriptor = os.open(
            output.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        try:
            before = os.fstat(descriptor)
            directory_identity = _release_stat_identity(before)
            if (
                not stat.S_ISDIR(before.st_mode)
                or stat.S_ISLNK(path_metadata.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o555
                or _release_stat_identity(path_metadata) != directory_identity
                or (
                    expected_directory_identity is not None
                    and directory_identity != expected_directory_identity
                )
                or tuple(sorted(os.listdir(descriptor))) != expected_names
            ):
                raise ReleaseAssemblyError(
                    "published release directory is unsafe or incomplete"
                )
            observed: dict[str, tuple[str, int]] = {}
            generated: dict[str, bytes] = {}
            total = 0
            for name in expected_names:
                raw = _read_release_member_at(descriptor, name)
                if raw != expected_files[name]:
                    raise ReleaseAssemblyError(
                        f"published release member bytes drifted: {name}"
                    )
                observed[name] = (hashlib.sha256(raw).hexdigest(), len(raw))
                if name in GENERATED_PUBLIC_FILES:
                    generated[name] = raw
                total += len(raw)
            after = os.fstat(descriptor)
            path_after = os.stat(
                output.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                total > MAXIMUM_RELEASE_BYTES
                or directory_identity != _release_stat_identity(after)
                or _release_stat_identity(after) != _release_stat_identity(path_after)
                or tuple(sorted(os.listdir(descriptor))) != expected_names
            ):
                raise ReleaseAssemblyError(
                    "published release directory changed during strict reload"
                )
            _verify_reloaded_release_indexes(
                generated=generated,
                observed=observed,
                canonical_names=canonical_names,
                expected_source_identity=expected_source_identity,
                expected_application_hashes=expected_application_hashes,
                expected_sbom=expected_sbom,
            )
            for name in expected_names:
                raw = _read_release_member_at(descriptor, name)
                if raw != expected_files[name]:
                    raise ReleaseAssemblyError(
                        "published release member changed after index verification: "
                        f"{name}"
                    )
            parent_after = os.fstat(parent_descriptor)
            parent_path_after = output.parent.lstat()
            final_path_metadata = os.stat(
                output.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                parent_snapshot_identity != _release_stat_identity(parent_after)
                or parent_snapshot_identity != _release_stat_identity(parent_path_after)
                or directory_identity != _release_stat_identity(final_path_metadata)
            ):
                raise ReleaseAssemblyError(
                    "published release parent changed during strict reload"
                )
        finally:
            os.close(descriptor)
    finally:
        if owns_parent_descriptor:
            os.close(parent_descriptor)


def assemble_release(
    *,
    mode: str,
    source_root: Path,
    expected_commit: str,
    expected_tree: str,
    owner_wheel: Path,
    owner_sdist: Path,
    plugin_bundle: Path,
    sidecar_wheel: Path,
    sidecar_sdist: Path,
    output_directory: Path,
    assembled_at: str,
    canary_receipt: Path | None = None,
    canary_evidence_bundle: Path | None = None,
    trusted_signer_key: Path | None = None,
    trusted_signer_key_id: str | None = None,
    verification_time: str | None = None,
) -> Path:
    """Verify every artifact first, then atomically assemble a public release directory."""

    if mode not in {"preview", "rc"}:
        raise ReleaseAssemblyError("release mode must be preview or rc")
    commit, tree = _git_identity(source_root, expected_commit, expected_tree)
    assembled_time = _parse_time(assembled_at, label="assembled_at")
    source = _release_source_metadata(source_root, commit)
    canonical_names = _canonical_artifact_basenames(source)
    artifacts = {
        "owner_wheel": owner_wheel,
        "owner_sdist": owner_sdist,
        "plugin_bundle": plugin_bundle,
        "sidecar_wheel": sidecar_wheel,
        "sidecar_sdist": sidecar_sdist,
    }
    for role in ARTIFACT_ROLES:
        if artifacts[role].name != canonical_names[role]:
            raise ReleaseAssemblyError(
                f"release artifact {role} basename is not canonical: "
                f"expected {canonical_names[role]!r}"
            )
    artifact_records: list[dict[str, Any]] = []
    artifact_bytes: dict[str, bytes] = {}
    total = 0
    with tempfile.TemporaryDirectory(prefix="owner-release-artifacts-") as temporary:
        snapshot_root = Path(temporary)
        snapshot_artifacts: dict[str, Path] = {}
        captured: dict[str, tuple[dict[str, Any], bytes]] = {}
        for role in ARTIFACT_ROLES:
            record, raw = _artifact_info(role, artifacts[role])
            snapshot = snapshot_root / record["name"]
            _write_file(snapshot, raw)
            snapshot_artifacts[role] = snapshot
            captured[role] = (record, raw)
        _verify_distributions(
            snapshot_artifacts,
            source_root=source_root,
            expected_commit=commit,
            expected_tree=tree,
        )
        for role in ARTIFACT_ROLES:
            record, raw = _artifact_info(role, snapshot_artifacts[role])
            if (record, raw) != captured[role]:
                raise ReleaseAssemblyError(
                    f"release artifact {role} changed in the verification snapshot"
                )
            artifact_records.append(record)
            if role in PUBLIC_ARTIFACT_ROLES:
                artifact_bytes[record["name"]] = raw
            total += len(raw)
    if total > MAXIMUM_RELEASE_BYTES:
        raise ReleaseAssemblyError("release artifacts exceed the cumulative byte limit")
    rc_blockers = _rc_readiness_blockers()
    artifact_by_role = {item["role"]: item for item in artifact_records}
    public_artifact_records = [artifact_by_role[role] for role in PUBLIC_ARTIFACT_ROLES]
    private_canary_inputs = [
        {
            "distribution_scope": "private_canary_input",
            "media_type": artifact_by_role[role]["media_type"],
            "role": role,
            "sha256": artifact_by_role[role]["sha256"],
            "size": artifact_by_role[role]["size"],
        }
        for role in PRIVATE_CANARY_ARTIFACT_ROLES
    ]

    receipt: dict[str, Any] | None = None
    if mode == "preview":
        if any(
            item is not None
            for item in (
                canary_receipt,
                canary_evidence_bundle,
                trusted_signer_key,
                trusted_signer_key_id,
                verification_time,
            )
        ):
            raise ReleaseAssemblyError("preview mode does not accept RC canary authority")
        release_status = "code_complete_preview"
        rc_permitted = False
    else:
        _assert_rc_versions(source)
        if (
            canary_receipt is None
            or canary_evidence_bundle is None
            or trusted_signer_key is None
            or trusted_signer_key_id is None
            or verification_time is None
        ):
            raise ReleaseAssemblyError(
                "RC mode requires a signed canary receipt and trusted preinstalled signer key"
            )
        if rc_blockers:
            raise ReleaseAssemblyError(
                "RC assembly is blocked: " + ",".join(rc_blockers)
            )
        receipt = verify_canary_receipt(
            canary_receipt,
            trusted_key_file=trusted_signer_key,
            trusted_key_id=trusted_signer_key_id,
            source_root=source_root,
            expected_commit=commit,
            expected_tree=tree,
            artifacts=artifact_records,
            evidence_directory=canary_evidence_bundle,
            verification_time_text=verification_time,
        )
        release_status = "rc_eligible_verified"
        rc_permitted = True

    sbom = _build_sbom(
        source=source,
        commit=commit,
        tree=tree,
        artifact_by_role=artifact_by_role,
        assembled_at=assembled_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        mode=mode,
    )
    sbom_raw = canonical_json_bytes(sbom)
    sbom_record = {
        "media_type": "application/vnd.cyclonedx+json",
        "name": "sbom.cdx.json",
        "role": "public_sbom",
        "sha256": hashlib.sha256(sbom_raw).hexdigest(),
        "size": len(sbom_raw),
    }
    manifest = {
        "artifact_type": "owner-equity-public-release-manifest",
        "artifacts": [*public_artifact_records, sbom_record],
        "assembled_at": assembled_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "canary": {
            "canary_root_sha256": (receipt["canary_root_sha256"] if receipt is not None else None),
            "receipt_sha256": (
                hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
                if receipt is not None
                else None
            ),
            "signer_key_id": trusted_signer_key_id if receipt is not None else None,
            "verified": receipt is not None,
        },
        "privacy": {
            "contains_account_identifiers": False,
            "contains_credentials": False,
            "contains_raw_vendor_data": False,
        },
        "private_canary_inputs": private_canary_inputs,
        "rc_blockers": rc_blockers,
        "rc_tag_permitted": rc_permitted,
        "release_mode": mode,
        "release_status": release_status,
        "schema_version": "1.0.0",
        "source": {"commit": commit, "tree": tree},
        "version": source["owner"]["version"],
    }
    manifest_raw = canonical_json_bytes(manifest)
    public_files = {
        **artifact_bytes,
        "sbom.cdx.json": sbom_raw,
        "release-manifest.json": manifest_raw,
    }
    checksums = "".join(
        f"{hashlib.sha256(raw).hexdigest()}  {name}\n" for name, raw in sorted(public_files.items())
    ).encode("ascii")
    public_files["SHA256SUMS"] = checksums

    output = output_directory.absolute()
    parent = output.parent
    parent_metadata = parent.lstat()
    if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
        raise ReleaseAssemblyError("release output parent is not a safe directory")
    parent_identity = _release_directory_binding(parent_metadata)
    parent_descriptor = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    staging_name = f".{output.name}.staging-{uuid.uuid4().hex}"
    staging_identity: tuple[int, ...] | None = None
    published_identity: tuple[int, ...] | None = None
    renamed = False
    try:
        parent_open = os.fstat(parent_descriptor)
        if parent_identity != _release_directory_binding(parent_open):
            raise ReleaseAssemblyError("release output parent identity drifted while opened")
        try:
            os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ReleaseAssemblyError("release output directory already exists")
        os.mkdir(staging_name, 0o700, dir_fd=parent_descriptor)
        staging_descriptor = os.open(
            staging_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        try:
            for name, raw in sorted(public_files.items()):
                _write_file_at(staging_descriptor, name, raw)
            os.fsync(staging_descriptor)
        finally:
            staging_identity = _release_stat_identity(os.fstat(staging_descriptor))
            os.close(staging_descriptor)
        _rename_directory_noreplace(parent_descriptor, staging_name, output.name)
        renamed = True
        output_descriptor = os.open(
            output.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        try:
            os.fchmod(output_descriptor, 0o555)
            os.fsync(output_descriptor)
            published_identity = _release_stat_identity(os.fstat(output_descriptor))
        finally:
            os.close(output_descriptor)
        os.fsync(parent_descriptor)
        _strict_reload_release_directory(
            output,
            expected_files=public_files,
            canonical_names=canonical_names,
            parent_descriptor=parent_descriptor,
            expected_parent_identity=parent_identity,
            expected_directory_identity=published_identity,
            expected_source_identity={"commit": commit, "tree": tree},
            expected_application_hashes={
                "owner": artifact_by_role["owner_wheel"]["sha256"],
                "plugin": artifact_by_role["plugin_bundle"]["sha256"],
                "sidecar": artifact_by_role["sidecar_wheel"]["sha256"],
            },
            expected_sbom=sbom,
        )
    except Exception:
        if renamed and published_identity is not None:
            _quarantine_published_directory_at(
                parent_descriptor,
                output.name,
                expected_identity=published_identity,
            )
        elif staging_identity is not None:
            _preserve_failed_staging_at(
                parent_descriptor,
                staging_name,
                expected_identity=staging_identity,
                allowed_names=set(public_files),
            )
        raise
    finally:
        os.close(parent_descriptor)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("preview", "rc"), required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--owner-wheel", type=Path, required=True)
    parser.add_argument("--owner-sdist", type=Path, required=True)
    parser.add_argument("--plugin-bundle", type=Path, required=True)
    parser.add_argument("--sidecar-wheel", type=Path, required=True)
    parser.add_argument("--sidecar-sdist", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--assembled-at", required=True)
    parser.add_argument("--canary-receipt", type=Path)
    parser.add_argument("--canary-evidence-bundle", type=Path)
    parser.add_argument("--trusted-signer-key", type=Path)
    parser.add_argument("--trusted-signer-key-id")
    parser.add_argument("--verification-time")
    args = parser.parse_args()
    try:
        output = assemble_release(
            mode=args.mode,
            source_root=args.source_root,
            expected_commit=args.expected_commit,
            expected_tree=args.expected_tree,
            owner_wheel=args.owner_wheel,
            owner_sdist=args.owner_sdist,
            plugin_bundle=args.plugin_bundle,
            sidecar_wheel=args.sidecar_wheel,
            sidecar_sdist=args.sidecar_sdist,
            output_directory=args.output_directory,
            assembled_at=args.assembled_at,
            canary_receipt=args.canary_receipt,
            canary_evidence_bundle=args.canary_evidence_bundle,
            trusted_signer_key=args.trusted_signer_key,
            trusted_signer_key_id=args.trusted_signer_key_id,
            verification_time=args.verification_time,
        )
    except (OSError, ReleaseAssemblyError) as exc:
        print(f"owner-equity-release: {exc}")
        return 1
    print(f"release artifacts assembled: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
