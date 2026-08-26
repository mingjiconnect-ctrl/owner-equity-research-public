from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

_PINNED_KERNEL_LOCK_CANONICAL_SHA256 = (
    "45bd321a26673d46627d9a260d2fd699a994cc74cb1fb018282a20beee1e83ac"
)
_PINNED_RUNTIME_AUTHORITY_CANONICAL_SHA256 = (
    "fa65b5b91deeba9b4b7d33aaa7ec4b17017ef33f5f608c82d74cedfcaf42b4cf"
)
_PINNED_RESEARCH_SCHEMA_MAP_CANONICAL_SHA256 = (
    "23c7b640337b6cae5e54881579d16ac9f298e67b0709661589f6528b891a75d4"
)
_PR3_MANIFEST_VERSION = "1.0.0"
_PR3_PACKAGE_VERSION = "1.0.0.dev0"
_PR3_FUTU_POLICY_PATH = "resources/futu/market-authority-policy-v2.json"
_PR3_MODULE_PATHS = (
    "__init__.py",
    "component_lock.py",
    "futu_crosscheck.py",
    "futu_receipts.py",
    "futu_session.py",
    "futu_sidecar.py",
    "owner_equity_research.py",
    "owner_equity_runtime.py",
    "owner_equity_types.py",
    "owner_scorecard.py",
    "research_publisher.py",
    "research_report.py",
    "valuation_cli.py",
    "valuation_futu_market.py",
    "valuation_run.py",
    "valuation_run_archive.py",
    "valuation_run_context.py",
    "valuation_synthesis.py",
    "valuation_synthesis_types.py",
    "workflow_cli.py",
)
_PR3_MAXIMUM_MEMBER_BYTES = 64 * 1024 * 1024
_PR3_MAXIMUM_TOTAL_BYTES = 512 * 1024 * 1024
_PR3_MAXIMUM_MEMBERS = 512
_FILE_SHA256_MAXIMUM_SIZE = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class VerificationResult:
    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass(frozen=True, slots=True)
class ComponentLockSnapshot:
    """One descriptor-bound component-lock read used for both parsing and identity."""

    path: Path
    payload: dict[str, Any]
    raw_bytes: bytes
    file_sha256: str


@dataclass(slots=True)
class _PR3ReadBudget:
    member_count: int = 0
    total_bytes: int = 0

    def claim_member(self) -> int:
        if self.member_count >= _PR3_MAXIMUM_MEMBERS:
            raise ValueError("PR3 locked snapshot exceeds its member limit")
        self.member_count += 1
        return _PR3_MAXIMUM_TOTAL_BYTES - self.total_bytes

    def consume(self, size: int) -> None:
        if size > _PR3_MAXIMUM_TOTAL_BYTES - self.total_bytes:
            raise ValueError("PR3 locked snapshot exceeds its cumulative byte limit")
        self.total_bytes += size


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key in component lock: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant in component lock: {value}")


def _canonical_payload_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _read_bounded_regular_file_nofollow(
    path: Path,
    *,
    maximum_size: int = 8 * 1024 * 1024,
) -> bytes:
    absolute = Path(path).expanduser().absolute()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(absolute, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum_size
        ):
            raise ValueError("component lock must be a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            remaining = maximum_size + 1 - total
            if remaining <= 0:
                raise ValueError("component lock exceeds its size limit")
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_size:
                raise ValueError("component lock exceeds its size limit")
        after = os.fstat(descriptor)
        try:
            path_after = absolute.lstat()
        except OSError as exc:
            raise ValueError("component lock changed while being read") from exc
        before_identity = (
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
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        path_identity = (
            path_after.st_dev,
            path_after.st_ino,
            path_after.st_mode,
            path_after.st_nlink,
            path_after.st_uid,
            path_after.st_gid,
            path_after.st_size,
            path_after.st_mtime_ns,
            path_after.st_ctime_ns,
        )
        if (
            before_identity != after_identity
            or after_identity != path_identity
            or total != before.st_size
        ):
            raise ValueError("component lock changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_stable_file_bytes(
    path: Path,
    *,
    maximum_size: int = _FILE_SHA256_MAXIMUM_SIZE,
) -> bytes:
    """Read a caller-selected regular file once, bounded and without following it."""

    return _read_bounded_regular_file_nofollow(path, maximum_size=maximum_size)


def load_component_lock_snapshot(path: Path) -> ComponentLockSnapshot:
    absolute = Path(path).expanduser().absolute()
    raw = read_stable_file_bytes(absolute)
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_json_keys,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("component lock must be a JSON object")
    return ComponentLockSnapshot(
        path=absolute,
        payload=value,
        raw_bytes=raw,
        file_sha256=hashlib.sha256(raw).hexdigest(),
    )


def load_component_lock(path: Path) -> dict[str, Any]:
    return load_component_lock_snapshot(path).payload


def default_component_lock_path() -> Path:
    packaged = Path(__file__).parent / "component-lock.json"
    if packaged.is_file():
        return packaged
    repository = Path(__file__).parents[2] / "component-lock.json"
    if repository.is_file():
        return repository
    raise FileNotFoundError("component-lock.json is unavailable")


def file_sha256(path: Path) -> str:
    """Hash one stable regular file without following its final path component."""

    return hashlib.sha256(
        read_stable_file_bytes(
            path,
            maximum_size=_FILE_SHA256_MAXIMUM_SIZE,
        )
    ).hexdigest()


def _read_package_file_nofollow(
    package_root: Path,
    relative_path: str,
    *,
    maximum_size: int = 8 * 1024 * 1024,
) -> bytes:
    """Read one locked package member without following or racing a symlink."""

    logical = PurePosixPath(relative_path)
    if logical.is_absolute() or not logical.parts or ".." in logical.parts:
        raise ValueError(f"locked package path is unsafe: {relative_path}")
    path = package_root.joinpath(*logical.parts)
    current = package_root
    for part in logical.parts[:-1]:
        current /= part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"locked package parent is unsafe: {relative_path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_size:
            raise ValueError(
                f"locked package member is not a bounded regular file: {relative_path}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_size + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_size:
                raise ValueError(f"locked package member exceeds its size limit: {relative_path}")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after:
            raise ValueError(f"locked package member changed while read: {relative_path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_pr3_member_nofollow(path: Path, budget: _PR3ReadBudget) -> bytes:
    remaining_total = budget.claim_member()
    metadata = path.lstat()
    maximum_size = min(_PR3_MAXIMUM_MEMBER_BYTES, remaining_total)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > _PR3_MAXIMUM_MEMBER_BYTES
    ):
        raise ValueError(f"PR3 locked member is unsafe or oversized: {path}")
    if metadata.st_size > remaining_total:
        raise ValueError("PR3 locked snapshot exceeds its cumulative byte limit")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = maximum_size + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        try:
            path_after = path.lstat()
        except OSError as exc:
            raise ValueError(f"PR3 locked member changed while read: {path}") from exc

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
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or len(raw) != before.st_size
            or len(raw) > maximum_size
            or identity(metadata) != identity(before)
            or identity(before) != identity(after)
            or identity(after) != identity(path_after)
        ):
            raise ValueError(f"PR3 locked member changed while read: {path}")
        budget.consume(len(raw))
        return raw
    finally:
        os.close(descriptor)


def _collect_pr3_directory(
    filesystem_root: Path,
    logical_prefix: str,
    budget: _PR3ReadBudget,
) -> dict[str, bytes]:
    root_metadata = filesystem_root.lstat()
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError(f"PR3 locked directory is unsafe: {filesystem_root}")
    members: dict[str, bytes] = {}
    for current, directories, filenames in os.walk(filesystem_root, followlinks=False):
        current_path = Path(current)
        kept_directories: list[str] = []
        for directory in directories:
            child = current_path / directory
            metadata = child.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(f"PR3 locked directory contains an unsafe entry: {child}")
            kept_directories.append(directory)
        directories[:] = kept_directories
        for filename in filenames:
            path = current_path / filename
            relative = path.relative_to(filesystem_root).as_posix()
            logical_path = f"{logical_prefix}/{relative}"
            members[logical_path] = _read_pr3_member_nofollow(path, budget)
    return members


def _pr3_locked_snapshot(
    *,
    repository_root: Path | None,
    package_root: Path | None,
) -> dict[str, bytes]:
    if (repository_root is None) == (package_root is None):
        raise ValueError("exactly one PR3 source or package root is required")
    if repository_root is not None:
        module_root = repository_root / "src" / "owner_research"
        extension_root = repository_root / "extension_schemas"
        futu_root = module_root / "resources" / "futu"
        report_root = (
            repository_root
            / "plugins"
            / "owner-equity-research"
            / "skills"
            / "owner-equity-research"
            / "assets"
        )
        policy_path = (
            repository_root / "scripts" / "phase5e-futu-market-authority-policy-v2.json"
        )
    else:
        assert package_root is not None
        module_root = package_root
        extension_root = package_root / "extension_schemas"
        futu_root = package_root / "resources" / "futu"
        report_root = package_root / "report_assets"
        policy_path = package_root / _PR3_FUTU_POLICY_PATH

    members: dict[str, bytes] = {}
    budget = _PR3ReadBudget()
    for filesystem_root, logical_prefix in (
        (extension_root, "extension_schemas"),
        (futu_root, "resources/futu"),
        (report_root, "report_assets"),
    ):
        discovered = _collect_pr3_directory(filesystem_root, logical_prefix, budget)
        overlap = set(members) & set(discovered)
        if overlap:
            raise ValueError(f"PR3 locked member projection overlaps: {sorted(overlap)}")
        members.update(discovered)
    members[_PR3_FUTU_POLICY_PATH] = _read_pr3_member_nofollow(policy_path, budget)
    for relative_path in _PR3_MODULE_PATHS:
        members[relative_path] = _read_pr3_member_nofollow(
            module_root / relative_path,
            budget,
        )
    return members


def verify_pr3_comprehensive_snapshot(
    *,
    lock_bytes: bytes,
    members: dict[str, bytes],
) -> VerificationResult:
    """Verify the closed additive PR3 manifest against one byte snapshot."""

    try:
        lock = json.loads(
            lock_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(lock, dict):
            raise ValueError("component lock must be a JSON object")
        owner = lock["owner_equity_research"]
        if not isinstance(owner, dict):
            raise TypeError("owner-equity lock must be an object")
        manifest = owner["pr3_comprehensive"]
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return VerificationResult((f"PR3 comprehensive component lock is unavailable: {exc}",))

    errors: list[str] = []
    if set(lock) != {
        "lock_version",
        "generated_date",
        "owner_equity_research",
        "market_access_authority",
        "valuation_kernel_runtime",
        "valuation_kernel",
    }:
        errors.append("PR3 comprehensive top-level component-lock shape mismatch")
    if lock.get("lock_version") != "1.2.0":
        errors.append("PR3 comprehensive manifest requires component-lock 1.2.0")
    if set(owner) != {"plugin_version", "public_schema_sha256", "pr3_comprehensive"}:
        errors.append("Owner Equity Research component-lock shape mismatch")
    if owner.get("plugin_version") != "1.0.0-dev.0":
        errors.append("Owner Equity Research plugin version is not the development candidate")
    if _canonical_payload_sha256(owner.get("public_schema_sha256")) != (
        _PINNED_RESEARCH_SCHEMA_MAP_CANONICAL_SHA256
    ):
        errors.append("Frozen public research Schema map drifted")
    expected_manifest_keys = {
        "manifest_version",
        "package_version",
        "extension_schema_sha256",
        "futu_authority_policy",
        "futu_resource_sha256",
        "report_asset_sha256",
        "module_sha256",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_manifest_keys:
        return VerificationResult(
            (*errors, "PR3 comprehensive manifest shape is not the exact closed interface")
        )
    if manifest.get("manifest_version") != _PR3_MANIFEST_VERSION:
        errors.append("PR3 comprehensive manifest version mismatch")
    if manifest.get("package_version") != _PR3_PACKAGE_VERSION:
        errors.append("PR3 comprehensive package version mismatch")

    expected_maps = {
        "extension_schema_sha256": {
            path: hashlib.sha256(raw).hexdigest()
            for path, raw in members.items()
            if path.startswith("extension_schemas/")
        },
        "futu_resource_sha256": {
            path: hashlib.sha256(raw).hexdigest()
            for path, raw in members.items()
            if path.startswith("resources/futu/") and path != _PR3_FUTU_POLICY_PATH
        },
        "report_asset_sha256": {
            path: hashlib.sha256(raw).hexdigest()
            for path, raw in members.items()
            if path.startswith("report_assets/")
        },
        "module_sha256": {
            path: hashlib.sha256(members[path]).hexdigest()
            for path in _PR3_MODULE_PATHS
            if path in members
        },
    }
    for key, expected in expected_maps.items():
        locked = manifest.get(key)
        if locked != expected:
            errors.append(f"PR3 comprehensive {key} map mismatch")
    if set(expected_maps["module_sha256"]) != set(_PR3_MODULE_PATHS):
        errors.append("PR3 comprehensive required module snapshot is incomplete")

    policy = manifest.get("futu_authority_policy")
    expected_policy_raw = members.get(_PR3_FUTU_POLICY_PATH)
    if (
        not isinstance(policy, dict)
        or set(policy) != {"path", "sha256"}
        or policy.get("path") != _PR3_FUTU_POLICY_PATH
        or expected_policy_raw is None
        or policy.get("sha256") != hashlib.sha256(expected_policy_raw).hexdigest()
    ):
        errors.append("PR3 comprehensive Futu authority policy binding mismatch")
    return VerificationResult(tuple(errors))


def verify_pr3_comprehensive_lock(
    lock_path: Path | None = None,
    *,
    repository_root: Path | None = None,
    package_root: Path | None = None,
) -> VerificationResult:
    """Verify PR3 from a trusted source tree or an installed package tree."""

    path = lock_path or default_component_lock_path()
    if repository_root is not None and package_root is not None:
        return VerificationResult(("PR3 verification roots are ambiguous",))
    if repository_root is None and package_root is None:
        inferred_repository = path.absolute().parent
        if (inferred_repository / "src" / "owner_research").is_dir():
            repository_root = inferred_repository
        else:
            package_root = Path(__file__).resolve().parent
    try:
        return verify_pr3_comprehensive_snapshot(
            lock_bytes=_read_bounded_regular_file_nofollow(path),
            members=_pr3_locked_snapshot(
                repository_root=repository_root,
                package_root=package_root,
            ),
        )
    except (OSError, UnicodeError, ValueError) as exc:
        return VerificationResult((f"PR3 comprehensive package snapshot is unavailable: {exc}",))


def verify_kernel_runtime_snapshot(
    *,
    lock_bytes: bytes,
    runtime_authority_bytes: bytes,
    materializer_bytes: bytes,
    runner_bytes: bytes,
) -> VerificationResult:
    """Verify one immutable component-lock/runtime byte snapshot."""

    errors: list[str] = []
    try:
        lock = json.loads(
            lock_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(lock, dict):
            raise ValueError("component lock must be a JSON object")
        runtime = lock["valuation_kernel_runtime"]
        kernel = lock["valuation_kernel"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return VerificationResult((f"Kernel runtime component lock is unavailable: {exc}",))

    expected_lock_keys = {
        "lock_version",
        "generated_date",
        "owner_equity_research",
        "market_access_authority",
        "valuation_kernel",
        "valuation_kernel_runtime",
    }
    if set(lock) != expected_lock_keys:
        return VerificationResult(("Kernel runtime top-level component-lock shape mismatch",))

    expected_runtime_keys = {
        "authority_version",
        "runtime_authority",
        "materializer_code",
        "runner_code",
        "expected_release_wheel_sha256",
        "manifest_policy_id",
        "manifest_policy_version",
    }
    if not isinstance(runtime, dict) or set(runtime) != expected_runtime_keys:
        return VerificationResult(("Kernel runtime component-lock shape mismatch",))
    if not isinstance(kernel, dict):
        return VerificationResult(("Kernel component-lock identity is not an object",))
    if _canonical_payload_sha256(kernel) != _PINNED_KERNEL_LOCK_CANONICAL_SHA256:
        return VerificationResult(
            ("Kernel component-lock identity drifted from pinned rc.2",)
        )
    if lock.get("lock_version") != "1.2.0":
        errors.append("Kernel runtime requires component-lock 1.2.0")
    if runtime.get("authority_version") != "1.0.0":
        errors.append("Kernel runtime authority version mismatch")
    if runtime.get("manifest_policy_id") != "owner-research-pinned-kernel-runtime":
        errors.append("Kernel runtime manifest policy ID mismatch")
    if runtime.get("manifest_policy_version") != "1.0.0":
        errors.append("Kernel runtime manifest policy version mismatch")

    locked_bytes = {
        "runtime_authority": runtime_authority_bytes,
        "materializer_code": materializer_bytes,
        "runner_code": runner_bytes,
    }
    expected_paths = {
        "runtime_authority": "resources/phase5-v1-kernel-runtime/runtime-authority.json",
        "materializer_code": "valuation_kernel_materializer.py",
        "runner_code": "valuation_pinned_kernel.py",
    }
    for key in ("runtime_authority", "materializer_code", "runner_code"):
        entry = runtime.get(key)
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            errors.append(f"Kernel runtime {key} lock entry is invalid")
            continue
        relative = entry.get("path")
        expected = entry.get("sha256")
        if not isinstance(relative, str) or not isinstance(expected, str):
            errors.append(f"Kernel runtime {key} path or digest is invalid")
            continue
        if relative != expected_paths[key]:
            errors.append(f"Kernel runtime {key} path is not the closed package member")
            continue
        raw = locked_bytes[key]
        if hashlib.sha256(raw).hexdigest() != expected:
            errors.append(f"Kernel runtime {key} hash mismatch")

    authority_raw = locked_bytes.get("runtime_authority")
    if authority_raw is None:
        return VerificationResult(tuple(errors))
    try:
        authority = json.loads(
            authority_raw,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        errors.append(f"Kernel runtime authority payload is invalid: {exc}")
        return VerificationResult(tuple(errors))
    if not isinstance(authority, dict) or not isinstance(authority.get("kernel"), dict):
        errors.append("Kernel runtime authority must contain a kernel object")
        return VerificationResult(tuple(errors))
    if (
        _canonical_payload_sha256(authority)
        != _PINNED_RUNTIME_AUTHORITY_CANONICAL_SHA256
    ):
        errors.append("Kernel runtime authority drifted from its closed 1.0.0 payload")
        return VerificationResult(tuple(errors))
    authority_kernel = authority["kernel"]

    if authority.get("schema_version") != runtime.get("authority_version"):
        errors.append("Kernel runtime authority Schema version mismatch")

    if (
        authority.get("policy_id") != runtime.get("manifest_policy_id")
        or authority.get("policy_version") != runtime.get("manifest_policy_version")
    ):
        errors.append("Kernel runtime manifest policy identity mismatch")
    if authority_kernel.get("wheel_sha256") != runtime.get(
        "expected_release_wheel_sha256"
    ):
        errors.append("Kernel runtime expected wheel hash mismatch")

    cross_links = {
        "repository": "repository",
        "tag": "tag",
        "tag_object": "annotated_tag_object",
        "commit": "commit",
        "package_version": "package_version",
        "plugin_version": "plugin_version",
        "source_manifest_sha256": "source_manifest_sha256",
        "release_manifest_sha256": "release_manifest_sha256",
    }
    for authority_key, lock_key in cross_links.items():
        if authority_kernel.get(authority_key) != kernel.get(lock_key):
            errors.append(f"Kernel runtime authority drifted at {authority_key}")
    release = kernel.get("release_evidence")
    if not isinstance(release, dict) or authority_kernel.get("wheel_sha256") != release.get(
        "wheel_sha256"
    ):
        errors.append("Kernel runtime wheel differs from pinned release evidence")

    authority_schemas = authority_kernel.get("schema_sha256")
    locked_schemas = kernel.get("public_schema_sha256")
    if not isinstance(authority_schemas, dict) or not isinstance(locked_schemas, dict):
        errors.append("Kernel runtime Schema authority is invalid")
    else:
        normalized = {
            f"schemas/{name}": digest for name, digest in authority_schemas.items()
        }
        if normalized != locked_schemas:
            errors.append("Kernel runtime Schema hashes differ from component lock")

    authority_runtime = authority.get("runtime")
    expected_runtime_keys = {
        "platform",
        "python_implementations",
        "result_schema",
        "container",
        "trusted_workflow",
        "python_minors",
        "request_transport",
        "result_transport",
        "kernel_call",
        "kernel_call_count",
        "network_mode",
        "result_bytes_preserved",
    }
    if not isinstance(authority_runtime, dict) or set(authority_runtime) != expected_runtime_keys:
        errors.append("Kernel runtime execution authority shape mismatch")
        return VerificationResult(tuple(errors))
    expected_result_schema = {
        "filename": "valuation-result.schema.json",
        "sha256": authority_kernel.get("schema_sha256", {}).get(
            "valuation-result.schema.json"
        ),
    }
    if authority_runtime.get("result_schema") != expected_result_schema:
        errors.append("Kernel runtime result Schema authority drifted")

    container = authority_runtime.get("container")
    expected_container_keys = {
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
    expected_container_identity = {
        "engine": "docker",
        "engine_path": "/usr/bin/docker",
        "image_repository": "docker.io/library/python",
        "image_tag": "3.11.15-bookworm",
        "image_manifest_digest": (
            "sha256:eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
        ),
        "image_config_digest": (
            "sha256:d299dee73063206fe64248b8eb62cbef36f6baedfc2c5e2ef4c7618ad18efb3a"
        ),
        "image_reference": (
            "docker.io/library/python@"
            "sha256:eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
        ),
        "platform": "linux/amd64",
        "os": "linux",
        "architecture": "amd64",
        "python_minor": "3.11",
        "python_patch": "3.11.15",
        "python_executable": "/usr/local/bin/python3",
        "pull_policy": "never",
        "network_mode": "none",
    }
    if not isinstance(container, dict) or set(container) != expected_container_keys:
        errors.append("Kernel runtime container authority shape mismatch")
    elif any(container.get(key) != value for key, value in expected_container_identity.items()):
        errors.append("Kernel runtime container identity drifted")
    expected_trusted_workflow = {
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
    if authority_runtime.get("trusted_workflow") != expected_trusted_workflow:
        errors.append("Kernel trusted-workflow authority drifted")
    if (
        authority_runtime.get("platform") != "linux_x86_64"
        or authority_runtime.get("python_implementations") != ["cpython"]
        or set(authority_runtime.get("python_minors", {})) != {"3.11"}
        or authority_runtime.get("request_transport") != "canonical_json_stdin"
        or authority_runtime.get("result_transport") != "canonical_json_stdout"
        or authority_runtime.get("kernel_call") != "owner_valuation.run_dual_panel"
        or authority_runtime.get("kernel_call_count") != 1
        or authority_runtime.get("network_mode") != "docker_network_none"
        or authority_runtime.get("result_bytes_preserved") is not True
    ):
        errors.append("Kernel runtime execution policy drifted")

    return VerificationResult(tuple(errors))


def verify_kernel_runtime_lock(lock_path: Path | None = None) -> VerificationResult:
    """Verify the packaged runtime using one bounded no-follow byte snapshot."""

    path = lock_path or default_component_lock_path()
    package_root = Path(__file__).resolve().parent
    try:
        return verify_kernel_runtime_snapshot(
            lock_bytes=_read_bounded_regular_file_nofollow(path),
            runtime_authority_bytes=_read_package_file_nofollow(
                package_root,
                "resources/phase5-v1-kernel-runtime/runtime-authority.json",
            ),
            materializer_bytes=_read_package_file_nofollow(
                package_root,
                "valuation_kernel_materializer.py",
            ),
            runner_bytes=_read_package_file_nofollow(
                package_root,
                "valuation_pinned_kernel.py",
            ),
        )
    except (OSError, UnicodeError, ValueError) as exc:
        return VerificationResult((f"Kernel runtime package snapshot is unavailable: {exc}",))


def verify_research_schema_lock(lock_path: Path, repository_root: Path) -> VerificationResult:
    lock = load_component_lock(lock_path)
    errors: list[str] = []
    locked = lock["owner_equity_research"]["public_schema_sha256"]
    actual_paths = {
        str(path.relative_to(repository_root))
        for path in (repository_root / "schemas").glob("*.schema.json")
    }
    if set(locked) != actual_paths:
        errors.append(
            "Research schema lock set mismatch: "
            f"missing={sorted(actual_paths - set(locked))}, "
            f"extra={sorted(set(locked) - actual_paths)}"
        )
    for relative_path, expected in locked.items():
        path = repository_root / relative_path
        try:
            actual = file_sha256(path)
        except (OSError, ValueError):
            errors.append(f"Missing research schema: {relative_path}")
        else:
            if actual != expected:
                errors.append(f"Research schema hash mismatch: {relative_path}")
    return VerificationResult(tuple(errors))


def verify_future_mapping_contract(
    mapping_path: Path,
    *,
    source_repo: Path,
) -> VerificationResult:
    try:
        mapping = json.loads(read_stable_file_bytes(mapping_path).decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return VerificationResult((f"Future mapping fixture cannot be read: {exc}",))
    if not isinstance(mapping, dict):
        return VerificationResult(("Future mapping fixture must be a JSON object",))
    errors: list[str] = []
    if mapping.get("mapping_status") not in {
        "NOT_IMPLEMENTED_PHASE_1",
        "POLICY_DEFINED_PHASE_5B0",
        "RAW_IMPLEMENTED_PHASE_5B1",
        "DERIVED_IMPLEMENTED_PHASE_5B2",
        "READINESS_IMPLEMENTED_PHASE_5B3",
        "IMPLEMENTED_PHASE_5B",
    }:
        errors.append("Future mapping fixture has an unknown implementation state")

    target_path = source_repo / "schemas" / mapping.get("target_schema", "")
    try:
        target = json.loads(read_stable_file_bytes(target_path).decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return VerificationResult((f"Future mapping target schema is missing: {target_path}",))
    if not isinstance(target, dict):
        return VerificationResult(("Future mapping target schema must be a JSON object",))
    target_fact = target.get("properties", {}).get("facts", {}).get("items", {})
    target_required = set(target_fact.get("required", []))
    policies = mapping.get("target_required_field_policy", {})
    if set(policies) != target_required:
        missing = sorted(target_required - set(policies))
        extra = sorted(set(policies) - target_required)
        errors.append(
            f"Future mapping policy does not cover target required fields; "
            f"missing={missing}, extra={extra}"
        )
    if any(not isinstance(policy, str) or not policy.strip() for policy in policies.values()):
        errors.append("Future mapping policy contains an empty decision")

    eligible = mapping.get("eligible_fact", {})
    required_source = {
        "fact_id",
        "concept",
        "value_type",
        "value",
        "unit",
        "currency",
        "period",
        "source_document_id",
        "source_locator",
        "confidence",
    }
    if not required_source.issubset(eligible):
        errors.append("Eligible research fact lacks required Phase 5 source fields")
    numeric_value = isinstance(eligible.get("value"), (int, float)) and not isinstance(
        eligible.get("value"), bool
    )
    if eligible.get("value_type") != "number" or not numeric_value:
        errors.append("Only a numeric research fact may enter the future mapping boundary")
    return VerificationResult(tuple(errors))


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def verify_component_lock(
    lock_path: Path,
    *,
    source_repo: Path,
    require_clean: bool = False,
    require_pinned_head: bool = False,
) -> VerificationResult:
    lock = load_component_lock(lock_path)
    kernel = lock["valuation_kernel"]
    errors: list[str] = []

    try:
        head = _git(source_repo, "rev-parse", "HEAD")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return VerificationResult((f"Cannot read valuation-kernel checkout: {exc}",))

    if require_pinned_head and head != kernel["commit"]:
        errors.append(f"HEAD {head} does not match pinned commit {kernel['commit']}")
    try:
        tag_object = _git(source_repo, "rev-parse", kernel["tag"])
        tag_type = _git(source_repo, "cat-file", "-t", kernel["tag"])
        tag_commit = _git(source_repo, "rev-parse", f"{kernel['tag']}^{{}}")
        if tag_type != "tag":
            errors.append(f"Tag {kernel['tag']} is not annotated")
        if tag_object != kernel.get("annotated_tag_object"):
            errors.append(
                f"Tag object {tag_object} does not match pinned annotated tag object"
            )
        if tag_commit != kernel["commit"]:
            errors.append(f"Tag {kernel['tag']} resolves to {tag_commit}, not pinned commit")
    except subprocess.CalledProcessError as exc:
        errors.append(f"Cannot resolve pinned tag {kernel['tag']}: {exc.output.strip()}")

    if require_clean and _git(source_repo, "status", "--porcelain"):
        errors.append("Valuation-kernel checkout is not clean")

    project = source_repo / "pyproject.toml"
    try:
        project_text = read_stable_file_bytes(project).decode("utf-8")
    except (OSError, UnicodeError, ValueError):
        project_text = ""
    if f'version = "{kernel["package_version"]}"' not in project_text:
        errors.append("Pinned valuation package version does not match component lock")

    for field, relative in (
        ("release_manifest_sha256", "references/release_manifest.json"),
        ("source_manifest_sha256", "references/source_manifest.json"),
    ):
        path = source_repo / relative
        try:
            actual = file_sha256(path)
        except (OSError, ValueError):
            actual = None
        if actual != kernel.get(field):
            errors.append(f"Pinned valuation {relative} does not match component lock")

    schema_snapshots: dict[str, bytes] = {}
    for relative_path, expected in kernel["public_schema_sha256"].items():
        path = source_repo / relative_path
        try:
            raw = read_stable_file_bytes(path)
        except (OSError, ValueError):
            errors.append(f"Missing pinned schema: {relative_path}")
            continue
        if hashlib.sha256(raw).hexdigest() != expected:
            errors.append(f"Schema hash mismatch: {relative_path}")
            continue
        schema_snapshots[relative_path] = raw

    manifest_path = source_repo / "plugins" / "owner-valuation" / ".codex-plugin" / "plugin.json"
    try:
        manifest_raw = read_stable_file_bytes(manifest_path)
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        errors.append("Pinned valuation plugin manifest is missing")
    else:
        if not isinstance(manifest, dict):
            errors.append("Pinned valuation plugin manifest is invalid")
            manifest = {}
        if manifest.get("version") != kernel["plugin_version"]:
            errors.append("Pinned valuation plugin version does not match component lock")

    fact_schema_raw = schema_snapshots.get("schemas/fact-ledger.schema.json")
    if fact_schema_raw is not None:
        try:
            schema = json.loads(fact_schema_raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            errors.append("Pinned FactLedger schema is invalid JSON")
            schema = {}
        if not isinstance(schema, dict):
            errors.append("Pinned FactLedger schema is not a JSON object")
            schema = {}
        facts = schema.get("properties", {}).get("facts", {}).get("items", {})
        required = set(facts.get("required", []))
        future_mapping_fields = {
            "fact_id",
            "concept",
            "value",
            "unit",
            "source_id",
            "source_location",
            "as_of_date",
        }
        if not future_mapping_fields.issubset(required):
            errors.append("Pinned FactLedger no longer exposes required Phase 5 mapping fields")
        if facts.get("properties", {}).get("value", {}).get("type") != "number":
            errors.append("Pinned FactLedger value is no longer numeric-only")

    errors.extend(verify_kernel_runtime_lock(lock_path).errors)
    errors.extend(verify_pr3_comprehensive_lock(lock_path).errors)

    return VerificationResult(tuple(errors))
