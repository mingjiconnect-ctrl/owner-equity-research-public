#!/usr/bin/env python3
"""Deterministically check or refresh only the additive PR3 component-lock surface."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import owner_research.component_lock as component_lock  # noqa: E402

_TOP_LEVEL_KEYS = (
    "lock_version",
    "generated_date",
    "owner_equity_research",
    "market_access_authority",
    "valuation_kernel_runtime",
    "valuation_kernel",
)
_OWNER_KEYS = ("plugin_version", "public_schema_sha256", "pr3_comprehensive")
_PR3_KEYS = (
    "manifest_version",
    "package_version",
    "extension_schema_sha256",
    "futu_authority_policy",
    "futu_resource_sha256",
    "kernel_schema_resource_sha256",
    "report_asset_sha256",
    "module_sha256",
)
_LEGACY_PR3_KEYS = tuple(
    key for key in _PR3_KEYS if key != "kernel_schema_resource_sha256"
)
_PR3_MAP_PREFIXES = {
    "extension_schema_sha256": "extension_schemas/",
    "futu_resource_sha256": "resources/futu/",
    "kernel_schema_resource_sha256": "resources/phase5-v1-kernel-schemas/",
    "report_asset_sha256": "report_assets/",
    "module_sha256": "",
}
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_DEVELOPMENT_VERSION_PATTERN = re.compile(r"(\d+\.\d+\.\d+)\.dev(\d+)")
_LOCK_MODE = 0o644
_MAXIMUM_LOCK_BYTES = 8 * 1024 * 1024
# Accepted core plus the reviewed PR3 Darwin host-path corrections. The refresher
# still cannot rewrite these pins, the kernel identity, or any public Schema.
_PINNED_FROZEN_PR1_PR2_ORDERED_SHA256 = (
    "274a46bd440b44cad673a5c647719fa27b0c89d0cb09a1985b744757f654c400"
)


@dataclass(frozen=True, slots=True)
class RefreshResult:
    changed: bool
    output_bytes: bytes


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _ordered_payload_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _plugin_version_from_package_constant(package_version: str) -> str:
    match = _DEVELOPMENT_VERSION_PATTERN.fullmatch(package_version)
    if match is None:
        raise ValueError("PR3 package version is outside the closed development version mapping")
    return f"{match.group(1)}-dev.{match.group(2)}"


def _validate_safe_digest_map(value: Any, *, label: str, prefix: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    if list(value) != sorted(value):
        raise ValueError(f"{label} is not in canonical path order")
    for path, digest in value.items():
        if not isinstance(path, str) or not isinstance(digest, str):
            raise ValueError(f"{label} must contain string paths and digests")
        logical = PurePosixPath(path)
        if (
            logical.is_absolute()
            or not logical.parts
            or ".." in logical.parts
            or "\\" in path
            or (prefix and not path.startswith(prefix))
            or _SHA256_PATTERN.fullmatch(digest) is None
        ):
            raise ValueError(f"{label} contains an unsafe or noncanonical member")


def _validate_closed_input(payload: Any, raw_bytes: bytes) -> dict[str, Any]:
    if not isinstance(payload, dict) or tuple(payload) != _TOP_LEVEL_KEYS:
        raise ValueError("component lock top-level shape or key order is not closed")
    if raw_bytes != _canonical_json_bytes(payload):
        raise ValueError("component lock input is not canonical deterministic JSON")
    if payload.get("lock_version") != "1.2.0":
        raise ValueError("component lock version is not the closed PR3 authority")
    owner = payload.get("owner_equity_research")
    if not isinstance(owner, dict) or tuple(owner) != _OWNER_KEYS:
        raise ValueError("Owner Equity Research lock shape or key order is not closed")
    if not isinstance(owner.get("public_schema_sha256"), dict):
        raise ValueError("frozen public Schema map is unavailable")
    manifest = owner.get("pr3_comprehensive")
    if not isinstance(manifest, dict) or tuple(manifest) not in {
        _LEGACY_PR3_KEYS,
        _PR3_KEYS,
    }:
        raise ValueError("PR3 comprehensive shape or key order is not closed")
    policy = manifest.get("futu_authority_policy")
    if (
        not isinstance(policy, dict)
        or tuple(policy) != ("path", "sha256")
        or policy.get("path") != component_lock._PR3_FUTU_POLICY_PATH
        or not isinstance(policy.get("sha256"), str)
        or _SHA256_PATTERN.fullmatch(policy["sha256"]) is None
    ):
        raise ValueError("PR3 Futu authority policy input is not closed")
    for label, prefix in _PR3_MAP_PREFIXES.items():
        if label == "kernel_schema_resource_sha256" and label not in manifest:
            continue
        _validate_safe_digest_map(manifest.get(label), label=label, prefix=prefix)
    return payload


def _load_closed_snapshot(lock_path: Path) -> component_lock.ComponentLockSnapshot:
    metadata = lock_path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != _LOCK_MODE
        or metadata.st_size > _MAXIMUM_LOCK_BYTES
    ):
        raise ValueError("component lock must be one bounded 0644 regular file")
    snapshot = component_lock.load_component_lock_snapshot(lock_path)
    _validate_closed_input(snapshot.payload, snapshot.raw_bytes)
    return snapshot


def _digest_map(members: dict[str, bytes], paths: list[str]) -> dict[str, str]:
    return {path: hashlib.sha256(members[path]).hexdigest() for path in sorted(paths)}


def _expected_manifest(members: dict[str, bytes]) -> dict[str, Any]:
    policy_path = component_lock._PR3_FUTU_POLICY_PATH
    policy_raw = members.get(policy_path)
    if policy_raw is None:
        raise ValueError("closed PR3 source projection omitted the Futu authority policy")
    module_paths = tuple(component_lock._PR3_MODULE_PATHS)
    if set(module_paths) - set(members):
        raise ValueError("closed PR3 source projection omitted a required module")
    return {
        "manifest_version": component_lock._PR3_MANIFEST_VERSION,
        "package_version": component_lock._PR3_PACKAGE_VERSION,
        "extension_schema_sha256": _digest_map(
            members,
            [path for path in members if path.startswith("extension_schemas/")],
        ),
        "futu_authority_policy": {
            "path": policy_path,
            "sha256": hashlib.sha256(policy_raw).hexdigest(),
        },
        "futu_resource_sha256": _digest_map(
            members,
            [
                path
                for path in members
                if path.startswith("resources/futu/") and path != policy_path
            ],
        ),
        "kernel_schema_resource_sha256": _digest_map(
            members,
            [
                path
                for path in members
                if path.startswith(
                    f"{component_lock._PR3_KERNEL_SCHEMA_RESOURCE_ROOT}/"
                )
            ],
        ),
        "report_asset_sha256": _digest_map(
            members,
            [path for path in members if path.startswith("report_assets/")],
        ),
        "module_sha256": _digest_map(members, list(module_paths)),
    }


def _frozen_projection(payload: dict[str, Any]) -> dict[str, Any]:
    frozen = copy.deepcopy(payload)
    owner = frozen["owner_equity_research"]
    del owner["plugin_version"]
    del owner["pr3_comprehensive"]
    return frozen


def _require_pinned_frozen_projection(payload: dict[str, Any]) -> None:
    if _ordered_payload_sha256(_frozen_projection(payload)) != (
        _PINNED_FROZEN_PR1_PR2_ORDERED_SHA256
    ):
        raise ValueError("frozen PR1/PR2 component-lock fields are open, reordered, or drifted")


def build_refreshed_component_lock(
    *,
    repository_root: Path,
    lock_path: Path,
) -> RefreshResult:
    root = repository_root.absolute()
    path = lock_path.absolute()
    snapshot = _load_closed_snapshot(path)
    _require_pinned_frozen_projection(snapshot.payload)
    members = component_lock._pr3_locked_snapshot(
        repository_root=root,
        package_root=None,
    )
    refreshed = copy.deepcopy(snapshot.payload)
    owner = refreshed["owner_equity_research"]
    owner["plugin_version"] = _plugin_version_from_package_constant(
        component_lock._PR3_PACKAGE_VERSION
    )
    owner["pr3_comprehensive"] = _expected_manifest(members)
    if _frozen_projection(snapshot.payload) != _frozen_projection(refreshed):
        raise ValueError("refresh attempted to change a frozen PR1/PR2 component-lock field")
    _require_pinned_frozen_projection(refreshed)
    output = _canonical_json_bytes(refreshed)
    verification = component_lock.verify_pr3_comprehensive_snapshot(
        lock_bytes=output,
        members=members,
    )
    if not verification.ok:
        raise ValueError("refreshed PR3 lock failed replay: " + "; ".join(verification.errors))
    return RefreshResult(changed=output != snapshot.raw_bytes, output_bytes=output)


def check_pr3_component_lock(*, repository_root: Path, lock_path: Path) -> tuple[str, ...]:
    try:
        result = build_refreshed_component_lock(
            repository_root=repository_root,
            lock_path=lock_path,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        return (f"PR3 component-lock refresh check failed: {exc}",)
    if result.changed:
        return ("PR3 component-lock is not the exact deterministic source projection",)
    return ()


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise OSError("component-lock staging write made no progress")
        offset += written


def _atomic_replace(lock_path: Path, *, expected_input: bytes, output: bytes) -> None:
    parent = lock_path.parent
    parent_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    parent_descriptor = os.open(parent, parent_flags)
    staging_name = f".{lock_path.name}.refresh-{secrets.token_hex(16)}.tmp"
    staging_descriptor: int | None = None
    staged = False
    try:
        parent_metadata = os.fstat(parent_descriptor)
        if not stat.S_ISDIR(parent_metadata.st_mode):
            raise ValueError("component-lock parent is not a safe directory")
        staging_descriptor = os.open(
            staging_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        staged = True
        _write_all(staging_descriptor, output)
        os.fsync(staging_descriptor)
        os.fchmod(staging_descriptor, _LOCK_MODE)
        os.fsync(staging_descriptor)
        os.close(staging_descriptor)
        staging_descriptor = None

        current = _load_closed_snapshot(lock_path)
        if current.raw_bytes != expected_input:
            raise ValueError("component lock changed while refresh output was staged")
        os.replace(
            staging_name,
            lock_path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        staged = False
        os.fsync(parent_descriptor)
        final = _load_closed_snapshot(lock_path)
        if final.raw_bytes != output:
            raise ValueError("component lock differs after atomic replacement")
    finally:
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        if staged:
            try:
                os.unlink(staging_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def write_pr3_component_lock(*, repository_root: Path, lock_path: Path) -> bool:
    snapshot = _load_closed_snapshot(lock_path.absolute())
    result = build_refreshed_component_lock(
        repository_root=repository_root,
        lock_path=lock_path,
    )
    if not result.changed:
        return False
    _atomic_replace(
        lock_path.absolute(),
        expected_input=snapshot.raw_bytes,
        output=result.output_bytes,
    )
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write", action="store_true")
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--lock", type=Path, default=ROOT / "component-lock.json")
    args = parser.parse_args()
    if args.check:
        errors = check_pr3_component_lock(
            repository_root=args.repository_root,
            lock_path=args.lock,
        )
        for error in errors:
            print(error)
        if errors:
            return 1
        print("PR3 component-lock check passed")
        return 0
    try:
        changed = write_pr3_component_lock(
            repository_root=args.repository_root,
            lock_path=args.lock,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"PR3 component-lock refresh failed: {exc}")
        return 1
    outcome = "refreshed" if changed else "already current"
    print(f"PR3 component-lock {outcome}: {args.lock}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
