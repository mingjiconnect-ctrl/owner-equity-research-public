"""Strict six-file archive for one completed Phase 5 v1 valuation run."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import stat
import sys
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema.exceptions import ValidationError as JSONSchemaValidationError

from .component_lock import (
    default_component_lock_path,
)
from .contracts import MarketReferenceSnapshot, ValuationHandoff, contract_from_dict
from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze, to_json_value
from .valuation_market_execution_types import (
    FinalRequestCompilationReceipt,
    KernelExecutionReceipt,
)
from .valuation_owner_execution import OwnerValuationExecutionResult
from .valuation_price_blind_freeze import PriceBlindInputArtifact

VALUATION_RUN_ARCHIVE_FILENAMES = (
    "valuation-handoff.json",
    "price-blind-input.json",
    "market-reference.json",
    "valuation-request.json",
    "valuation-result.json",
    "valuation-run-manifest.json",
)
VALUATION_RUN_MEMBER_MAX_BYTES = 16 * 1024 * 1024
VALUATION_RUN_ARCHIVE_MAX_BYTES = 64 * 1024 * 1024
_CONTENT_FILENAMES = VALUATION_RUN_ARCHIVE_FILENAMES[:-1]
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "archive_id",
        "issuer_id",
        "data_cutoff_date",
        "file_count",
        "file_sha256",
        "component_lock_sha256",
        "handoff_kernel_identity",
        "execution_kernel_identity",
        "price_blind_input_fingerprint",
        "protected_mckinsey_sha256",
        "protected_penman_assumptions_sha256",
        "market_reference_snapshot_id",
        "market_reference_snapshot_fingerprint",
        "valuation_handoff_id",
        "valuation_handoff_fingerprint",
        "valuation_request_sha256",
        "valuation_result_sha256",
        "valuation_result_fingerprint",
        "final_request_receipt",
        "kernel_execution_receipt",
        "manifest_fingerprint",
    }
)
_HEX = frozenset("0123456789abcdef")


class ValuationRunArchiveError(ValueError):
    """The six-file valuation archive is incomplete, unsafe, or inconsistent."""


@dataclass(frozen=True, slots=True)
class ValuationRunArchive:
    output_directory: Path
    directory_device: int
    directory_inode: int
    handoff: ValuationHandoff
    price_blind_input: PriceBlindInputArtifact
    market_reference: MarketReferenceSnapshot
    request_payload: FrozenMap
    result_payload: FrozenMap
    manifest: FrozenMap
    file_sha256: FrozenMap

    def __post_init__(self) -> None:
        object.__setattr__(self, "output_directory", Path(self.output_directory).absolute())
        if self.directory_device < 0 or self.directory_inode <= 0:
            raise ValueError("valuation archive directory identity is invalid")
        object.__setattr__(self, "request_payload", freeze(self.request_payload))
        object.__setattr__(self, "result_payload", freeze(self.result_payload))
        object.__setattr__(self, "manifest", freeze(self.manifest))
        object.__setattr__(self, "file_sha256", freeze(self.file_sha256))

    @property
    def fingerprint(self) -> str:
        return str(self.manifest["manifest_fingerprint"])


@dataclass(frozen=True, slots=True)
class _ArchiveDirectorySnapshot:
    contents: dict[str, bytes]
    device: int
    inode: int


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_file(value: Any) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _exact_sha(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 64 or set(value) - _HEX:
        raise ValuationRunArchiveError(f"{label} is not a lowercase SHA-256")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValuationRunArchiveError(f"archive JSON repeats key {key!r}")
        output[key] = value
    return output


def _json_object(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValuationRunArchiveError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValuationRunArchiveError(f"{label} must be a JSON object")
    return value


def _reject_extended_acl(descriptor: int, label: str) -> None:
    """Reject Darwin ACLs whose grants are invisible in the POSIX mode bits."""

    if sys.platform != "darwin":
        return
    library = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = library.acl_get_fd_np
    acl_get_fd_np.argtypes = (ctypes.c_int, ctypes.c_int)
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_free = library.acl_free
    acl_free.argtypes = (ctypes.c_void_p,)
    acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, 0x00000100)  # ACL_TYPE_EXTENDED
    if not acl:
        error = ctypes.get_errno()
        if error == errno.ENOENT:
            return
        raise ValuationRunArchiveError(f"{label} ACL authority is unresolved")
    acl_free(acl)
    raise ValuationRunArchiveError(f"{label} cannot carry an extended ACL")


def _read_bounded_regular(path: Path, label: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValuationRunArchiveError(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValuationRunArchiveError(f"{label} is not one bounded regular file")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise ValuationRunArchiveError(f"{label} exceeds the byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or consumed != before.st_size:
            raise ValuationRunArchiveError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _component_lock(path: Path) -> tuple[dict[str, Any], str]:
    raw = _read_bounded_regular(path, "component lock", VALUATION_RUN_MEMBER_MAX_BYTES)
    return _json_object(raw, "component lock"), _sha256(raw)


def _reject_symlink_path(path: Path) -> None:
    for candidate in (path, *path.parents):
        try:
            details = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode):
            raise ValuationRunArchiveError("valuation archive path cannot contain a symlink")


def _open_directory(path: Path, *, require_read_only: bool = False) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValuationRunArchiveError("valuation archive directory is unavailable") from exc
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode):
            raise ValuationRunArchiveError("valuation archive path is not a directory")
        if require_read_only and details.st_mode & 0o222:
            raise ValuationRunArchiveError("valuation archive directory must be read-only")
        if require_read_only:
            _reject_extended_acl(descriptor, "valuation archive directory")
    except (OSError, ValuationRunArchiveError):
        os.close(descriptor)
        raise
    return descriptor


def _read_member(
    directory_descriptor: int,
    name: str,
    *,
    remaining_archive_bytes: int,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as exc:
        raise ValuationRunArchiveError(f"archive member {name} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValuationRunArchiveError(f"archive member {name} is not a private regular file")
        if before.st_mode & 0o222:
            raise ValuationRunArchiveError(f"archive member {name} must be read-only")
        _reject_extended_acl(descriptor, f"archive member {name}")
        maximum = min(VALUATION_RUN_MEMBER_MAX_BYTES, remaining_archive_bytes)
        if before.st_size > maximum:
            raise ValuationRunArchiveError(f"archive member {name} exceeds the byte limit")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise ValuationRunArchiveError(f"archive member {name} exceeds the byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity_before = (
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
        identity_after = (
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
        if identity_before != identity_after or consumed != before.st_size:
            raise ValuationRunArchiveError(f"archive member {name} changed while being read")
        _reject_extended_acl(descriptor, f"archive member {name}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_archive_directory(path: Path) -> _ArchiveDirectorySnapshot:
    _reject_symlink_path(path)
    directory_descriptor = _open_directory(path, require_read_only=True)
    try:
        before = os.fstat(directory_descriptor)
        names = tuple(sorted(os.listdir(directory_descriptor)))
        if names != tuple(sorted(VALUATION_RUN_ARCHIVE_FILENAMES)):
            raise ValuationRunArchiveError(
                "valuation archive must contain exactly the six registered files"
            )
        contents: dict[str, bytes] = {}
        remaining = VALUATION_RUN_ARCHIVE_MAX_BYTES
        for name in names:
            content = _read_member(
                directory_descriptor,
                name,
                remaining_archive_bytes=remaining,
            )
            contents[name] = content
            remaining -= len(content)
        after_names = tuple(sorted(os.listdir(directory_descriptor)))
        after = os.fstat(directory_descriptor)
        _reject_extended_acl(directory_descriptor, "valuation archive directory")
        if (
            after_names != names
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_uid,
                before.st_gid,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_uid,
                after.st_gid,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or after.st_mode & 0o222
        ):
            raise ValuationRunArchiveError("valuation archive changed while being read")
        return _ArchiveDirectorySnapshot(
            contents=contents,
            device=after.st_dev,
            inode=after.st_ino,
        )
    finally:
        os.close(directory_descriptor)


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise ValuationRunArchiveError("valuation archive write did not complete")
        remaining = remaining[written:]


def _write_staging(parent_descriptor: int, name: str, contents: Mapping[str, bytes]) -> None:
    if (
        any(len(content) > VALUATION_RUN_MEMBER_MAX_BYTES for content in contents.values())
        or sum(len(content) for content in contents.values()) > VALUATION_RUN_ARCHIVE_MAX_BYTES
    ):
        raise ValuationRunArchiveError("valuation archive exceeds the byte limit")
    os.mkdir(name, 0o700, dir_fd=parent_descriptor)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    staging_descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        _reject_extended_acl(staging_descriptor, "valuation archive staging directory")
        for filename in VALUATION_RUN_ARCHIVE_FILENAMES:
            descriptor = os.open(
                filename,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=staging_descriptor,
            )
            try:
                _reject_extended_acl(descriptor, f"archive staging member {filename}")
                _write_all(descriptor, contents[filename])
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o444)
                _reject_extended_acl(descriptor, f"archive staging member {filename}")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if tuple(sorted(os.listdir(staging_descriptor))) != tuple(
            sorted(VALUATION_RUN_ARCHIVE_FILENAMES)
        ):
            raise ValuationRunArchiveError("valuation archive staging member set changed")
        os.fchmod(staging_descriptor, 0o555)
        details = os.fstat(staging_descriptor)
        if not stat.S_ISDIR(details.st_mode) or details.st_mode & 0o222:
            raise ValuationRunArchiveError("valuation archive staging directory is writable")
        _reject_extended_acl(staging_descriptor, "valuation archive staging directory")
        os.fsync(staging_descriptor)
    finally:
        os.close(staging_descriptor)


def _verify_staging_directory(
    staging_descriptor: int,
    contents: Mapping[str, bytes],
) -> tuple[int, int]:
    before = os.fstat(staging_descriptor)
    if not stat.S_ISDIR(before.st_mode) or before.st_mode & 0o222:
        raise ValuationRunArchiveError("valuation archive staging directory is not sealed")
    _reject_extended_acl(staging_descriptor, "valuation archive staging directory")
    names = tuple(sorted(os.listdir(staging_descriptor)))
    if names != tuple(sorted(VALUATION_RUN_ARCHIVE_FILENAMES)):
        raise ValuationRunArchiveError("valuation archive staging member set changed")
    observed: dict[str, bytes] = {}
    remaining = VALUATION_RUN_ARCHIVE_MAX_BYTES
    for filename in names:
        content = _read_member(
            staging_descriptor,
            filename,
            remaining_archive_bytes=remaining,
        )
        observed[filename] = content
        remaining -= len(content)
    after_names = tuple(sorted(os.listdir(staging_descriptor)))
    after = os.fstat(staging_descriptor)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_uid,
        before.st_gid,
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
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if (
        observed != dict(contents)
        or after_names != names
        or after_identity != before_identity
        or after.st_mode & 0o222
    ):
        raise ValuationRunArchiveError("valuation archive staging bytes changed before publication")
    _reject_extended_acl(staging_descriptor, "valuation archive staging directory")
    return after.st_dev, after.st_ino


def _rename_directory_noreplace(parent_descriptor: int, source: str, target: str) -> None:
    """Atomically publish a staged directory without replacing any target inode."""

    library = ctypes.CDLL(None, use_errno=True)
    function_name = "renameatx_np" if sys.platform == "darwin" else "renameat2"
    try:
        rename = getattr(library, function_name)
    except AttributeError as exc:
        raise ValuationRunArchiveError(
            "atomic no-replace directory publication is unavailable"
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
        os.fsencode(source),
        parent_descriptor,
        os.fsencode(target),
        flag,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error, "valuation archive target already exists", target)
    raise OSError(error, "atomic valuation archive publication failed", target)


def _remove_staging_directory(parent_descriptor: int, name: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        os.fchmod(descriptor, 0o700)
        names = tuple(sorted(os.listdir(descriptor)))
        if not set(names).issubset(VALUATION_RUN_ARCHIVE_FILENAMES):
            raise ValuationRunArchiveError("archive staging member set changed during publication")
        for filename in names:
            details = os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISREG(details.st_mode):
                raise ValuationRunArchiveError("archive staging contains an unsafe member")
            os.unlink(filename, dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent_descriptor)


def _archive_payloads(
    execution: OwnerValuationExecutionResult,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    if type(execution) is not OwnerValuationExecutionResult or execution.status != "completed":
        raise ValuationRunArchiveError("only an exact completed owner execution may be archived")
    # Reconstructing the immutable result replays all request, receipt, graph, and Handoff gates.
    execution = OwnerValuationExecutionResult(
        **{name: getattr(execution, name) for name in execution.__dataclass_fields__}
    )
    preparation = execution.preparation
    prepared = preparation.prepared_market_reference
    freeze_result = execution.expected_freeze
    request_result = execution.final_request_result
    request_receipt = execution.final_request_receipt
    kernel_receipt = execution.kernel_execution_receipt
    if (
        prepared is None
        or freeze_result is None
        or request_result.request_payload is None
        or request_result.canonical_request_json is None
        or request_result.request_sha256 is None
        or request_receipt is None
        or kernel_receipt is None
        or execution.result_bytes is None
        or len(execution.execution_handoffs) != 2
    ):
        raise ValuationRunArchiveError("completed owner execution lacks archive evidence")
    final_handoff = execution.execution_handoffs[-1]
    snapshot = prepared.snapshot
    artifact = freeze_result.artifact
    request_bytes = request_result.canonical_request_json.encode("utf-8")
    result_bytes = execution.result_bytes
    request_payload = to_json_value(request_result.request_payload)
    result_payload = _json_object(result_bytes, "valuation result")
    if request_bytes != canonical_json(request_payload).encode("utf-8"):
        raise ValuationRunArchiveError("valuation request bytes are not canonical")
    if result_bytes != canonical_json(result_payload).encode("utf-8"):
        raise ValuationRunArchiveError("valuation result stdout is not canonical")
    contents = {
        "valuation-handoff.json": _canonical_file(final_handoff.to_dict()),
        "price-blind-input.json": _canonical_file(artifact.to_dict()),
        "market-reference.json": _canonical_file(snapshot.to_dict()),
        "valuation-request.json": request_bytes,
        "valuation-result.json": result_bytes,
    }
    file_hashes = {name: _sha256(content) for name, content in contents.items()}
    identity = {
        "issuer_id": execution.issuer_id,
        "data_cutoff_date": execution.data_cutoff_date,
        "valuation_handoff_id": final_handoff.handoff_id,
        "valuation_request_sha256": file_hashes["valuation-request.json"],
        "valuation_result_sha256": file_hashes["valuation-result.json"],
    }
    component_lock, _ = _component_lock(prepared.graph.component_lock_path)
    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "artifact_type": "valuation-run-manifest",
        "archive_id": (
            f"valuation-run-archive:{execution.issuer_id}:{canonical_sha256(identity)[:24]}"
        ),
        "issuer_id": execution.issuer_id,
        "data_cutoff_date": execution.data_cutoff_date,
        "file_count": len(VALUATION_RUN_ARCHIVE_FILENAMES),
        "file_sha256": file_hashes,
        "component_lock_sha256": final_handoff.component_lock_sha256,
        "handoff_kernel_identity": final_handoff.to_dict()["kernel_identity"],
        "execution_kernel_identity": component_lock["valuation_kernel"],
        "price_blind_input_fingerprint": artifact.fingerprint,
        "protected_mckinsey_sha256": artifact.payload["protected_mckinsey_sha256"],
        "protected_penman_assumptions_sha256": artifact.payload[
            "protected_penman_assumptions_sha256"
        ],
        "market_reference_snapshot_id": snapshot.snapshot_id,
        "market_reference_snapshot_fingerprint": snapshot.fingerprint,
        "valuation_handoff_id": final_handoff.handoff_id,
        "valuation_handoff_fingerprint": final_handoff.fingerprint,
        "valuation_request_sha256": file_hashes["valuation-request.json"],
        "valuation_result_sha256": file_hashes["valuation-result.json"],
        "valuation_result_fingerprint": canonical_sha256(result_payload),
        "final_request_receipt": request_receipt.to_dict(),
        "kernel_execution_receipt": kernel_receipt.to_dict(),
    }
    manifest["manifest_fingerprint"] = canonical_sha256(manifest)
    contents["valuation-run-manifest.json"] = _canonical_file(manifest)
    return contents, manifest


def _validate_manifest(
    *,
    contents: Mapping[str, bytes],
    handoff: ValuationHandoff,
    artifact: PriceBlindInputArtifact,
    snapshot: MarketReferenceSnapshot,
    request: dict[str, Any],
    result: dict[str, Any],
    manifest: dict[str, Any],
    component_lock_path: Path,
) -> tuple[FinalRequestCompilationReceipt, KernelExecutionReceipt]:
    if set(manifest) != _MANIFEST_FIELDS:
        raise ValuationRunArchiveError("valuation run manifest fields are not closed")
    if (
        manifest["schema_version"] != "1.0.0"
        or manifest["artifact_type"] != "valuation-run-manifest"
        or manifest["file_count"] != len(VALUATION_RUN_ARCHIVE_FILENAMES)
    ):
        raise ValuationRunArchiveError("valuation run manifest identity is invalid")
    supplied_fingerprint = _exact_sha(manifest["manifest_fingerprint"], "manifest fingerprint")
    fingerprint_payload = dict(manifest)
    fingerprint_payload.pop("manifest_fingerprint")
    if supplied_fingerprint != canonical_sha256(fingerprint_payload):
        raise ValuationRunArchiveError("valuation run manifest fingerprint does not replay")
    expected_file_hashes = {name: _sha256(contents[name]) for name in _CONTENT_FILENAMES}
    if manifest["file_sha256"] != expected_file_hashes:
        raise ValuationRunArchiveError("valuation run manifest file hashes do not replay")
    for name, value in expected_file_hashes.items():
        _exact_sha(value, f"{name} SHA")
    request_sha = expected_file_hashes["valuation-request.json"]
    result_sha = expected_file_hashes["valuation-result.json"]
    result_fingerprint = canonical_sha256(result)
    artifact_payload = artifact.to_dict()
    component_lock, component_lock_sha = _component_lock(component_lock_path)
    try:
        kernel_identity = component_lock["valuation_kernel"]
    except KeyError as exc:
        raise ValuationRunArchiveError("component lock lacks valuation-kernel identity") from exc
    if (
        manifest["issuer_id"] != handoff.issuer_id
        or manifest["issuer_id"] != snapshot.issuer_id
        or manifest["issuer_id"] != artifact_payload["issuer_id"]
        or manifest["data_cutoff_date"] != handoff.data_cutoff_date
        or manifest["data_cutoff_date"] != snapshot.data_cutoff_date
        or manifest["data_cutoff_date"] != artifact_payload["data_cutoff_date"]
        or manifest["component_lock_sha256"] != component_lock_sha
        or handoff.component_lock_sha256 != component_lock_sha
        or snapshot.component_lock_sha256 != component_lock_sha
        or artifact_payload["component_lock_sha256"] != component_lock_sha
        or manifest["execution_kernel_identity"] != kernel_identity
        or artifact_payload["kernel_identity"] != kernel_identity
        or manifest["handoff_kernel_identity"] != handoff.to_dict()["kernel_identity"]
    ):
        raise ValuationRunArchiveError("archive issuer, cutoff, component lock, or kernel drifted")
    protected_mckinsey = artifact_payload["protected_mckinsey_sha256"]
    protected_penman = artifact_payload["protected_penman_assumptions_sha256"]
    if (
        manifest["price_blind_input_fingerprint"] != artifact.fingerprint
        or manifest["protected_mckinsey_sha256"] != protected_mckinsey
        or manifest["protected_penman_assumptions_sha256"] != protected_penman
        or snapshot.price_blind_input_fingerprint != artifact.fingerprint
        or snapshot.protected_mckinsey_sha256 != protected_mckinsey
        or snapshot.protected_penman_assumptions_sha256 != protected_penman
        or handoff.price_blind_input_fingerprint != artifact.fingerprint
        or handoff.protected_mckinsey_sha256 != protected_mckinsey
        or handoff.protected_penman_assumptions_sha256 != protected_penman
    ):
        raise ValuationRunArchiveError("archive changed protected price-blind inputs")
    if (
        handoff.state != "kernel_result_frozen"
        or handoff.market_reference_snapshot_id != snapshot.snapshot_id
        or handoff.valuation_request_sha256 != request_sha
        or handoff.valuation_result_sha256 != result_sha
        or manifest["market_reference_snapshot_id"] != snapshot.snapshot_id
        or manifest["market_reference_snapshot_fingerprint"] != snapshot.fingerprint
        or manifest["valuation_handoff_id"] != handoff.handoff_id
        or manifest["valuation_handoff_fingerprint"] != handoff.fingerprint
        or manifest["valuation_request_sha256"] != request_sha
        or manifest["valuation_result_sha256"] != result_sha
        or manifest["valuation_result_fingerprint"] != result_fingerprint
    ):
        raise ValuationRunArchiveError("archive request, result, Snapshot, or Handoff drifted")
    if not isinstance(request.get("fact_ledger"), dict) or not isinstance(
        request.get("assumption_ledger"), dict
    ):
        raise ValuationRunArchiveError("valuation request lacks its two ledgers")
    if (
        result.get("fact_ledger_fingerprint") != canonical_sha256(request["fact_ledger"])
        or result.get("assumption_ledger_fingerprint")
        != canonical_sha256(request["assumption_ledger"])
        or result.get("model_input_fingerprint") != request_sha
    ):
        raise ValuationRunArchiveError("valuation result fingerprint does not replay the request")
    try:
        request_receipt = FinalRequestCompilationReceipt(**manifest["final_request_receipt"])
        kernel_receipt = KernelExecutionReceipt(**manifest["kernel_execution_receipt"])
    except (TypeError, ValueError) as exc:
        raise ValuationRunArchiveError("archive execution receipt is invalid") from exc
    if (
        request_receipt.status != "validated"
        or request_receipt.reason_codes != ()
        or request_receipt.issuer_id != handoff.issuer_id
        or request_receipt.handoff_run_id != handoff.handoff_run_id
        or request_receipt.market_reference_snapshot_id != snapshot.snapshot_id
        or request_receipt.valuation_request_sha256 != request_sha
        or request_receipt.price_blind_input_after_sha256 != artifact.fingerprint
        or request_receipt.protected_mckinsey_after_sha256 != protected_mckinsey
        or request_receipt.protected_penman_after_sha256 != protected_penman
        or kernel_receipt.request_sha256 != request_sha
        or kernel_receipt.result_sha256 != result_sha
        or kernel_receipt.fact_ledger_fingerprint != result["fact_ledger_fingerprint"]
        or kernel_receipt.assumption_ledger_fingerprint != result["assumption_ledger_fingerprint"]
        or kernel_receipt.model_input_fingerprint != result["model_input_fingerprint"]
        or kernel_receipt.call_count != 1
        or kernel_receipt.status != "succeeded"
        or not kernel_receipt.result_preserved
    ):
        raise ValuationRunArchiveError("archive receipts do not bind the frozen run")
    archive_identity = {
        "issuer_id": handoff.issuer_id,
        "data_cutoff_date": handoff.data_cutoff_date,
        "valuation_handoff_id": handoff.handoff_id,
        "valuation_request_sha256": request_sha,
        "valuation_result_sha256": result_sha,
    }
    expected_archive_id = (
        f"valuation-run-archive:{handoff.issuer_id}:{canonical_sha256(archive_identity)[:24]}"
    )
    if manifest["archive_id"] != expected_archive_id:
        raise ValuationRunArchiveError("valuation archive ID is not deterministic")
    return request_receipt, kernel_receipt


def load_valuation_run_archive(
    input_directory: Path,
    *,
    component_lock_path: Path | None = None,
    expected_execution: OwnerValuationExecutionResult | None = None,
) -> ValuationRunArchive:
    """Reload the exact six files and recompute every protected cross-binding."""

    source = Path(input_directory).expanduser().absolute()
    initial_snapshot = _read_archive_directory(source)
    contents = initial_snapshot.contents
    handoff_payload = _json_object(contents["valuation-handoff.json"], "valuation Handoff")
    artifact_payload = _json_object(contents["price-blind-input.json"], "price-blind input")
    market_payload = _json_object(contents["market-reference.json"], "market reference")
    request_payload = _json_object(contents["valuation-request.json"], "valuation request")
    result_payload = _json_object(contents["valuation-result.json"], "valuation result")
    manifest_payload = _json_object(
        contents["valuation-run-manifest.json"], "valuation run manifest"
    )
    if contents["valuation-handoff.json"] != _canonical_file(handoff_payload):
        raise ValuationRunArchiveError("valuation Handoff is not canonically serialized")
    if contents["price-blind-input.json"] != _canonical_file(artifact_payload):
        raise ValuationRunArchiveError("price-blind input is not canonically serialized")
    if contents["market-reference.json"] != _canonical_file(market_payload):
        raise ValuationRunArchiveError("market reference is not canonically serialized")
    if contents["valuation-request.json"] != canonical_json(request_payload).encode("utf-8"):
        raise ValuationRunArchiveError("valuation request bytes are not canonical")
    if contents["valuation-result.json"] != canonical_json(result_payload).encode("utf-8"):
        raise ValuationRunArchiveError("valuation result bytes are not preserved canonical stdout")
    if contents["valuation-run-manifest.json"] != _canonical_file(manifest_payload):
        raise ValuationRunArchiveError("valuation run manifest is not canonically serialized")
    try:
        handoff = contract_from_dict("valuation-handoff", handoff_payload)
        snapshot = contract_from_dict("market-reference-snapshot", market_payload)
        artifact = PriceBlindInputArtifact(artifact_payload)
    except (JSONSchemaValidationError, TypeError, ValueError) as exc:
        raise ValuationRunArchiveError("archive contract payload is invalid") from exc
    if not isinstance(handoff, ValuationHandoff) or not isinstance(
        snapshot, MarketReferenceSnapshot
    ):
        raise ValuationRunArchiveError("archive contract types are invalid")
    lock_path = Path(component_lock_path or default_component_lock_path())
    _validate_manifest(
        contents=contents,
        handoff=handoff,
        artifact=artifact,
        snapshot=snapshot,
        request=request_payload,
        result=result_payload,
        manifest=manifest_payload,
        component_lock_path=lock_path,
    )
    if expected_execution is not None:
        expected_contents, _ = _archive_payloads(expected_execution)
        if dict(contents) != expected_contents:
            raise ValuationRunArchiveError("archive differs from the expected completed execution")
    final_snapshot = _read_archive_directory(source)
    if (
        final_snapshot.device,
        final_snapshot.inode,
        final_snapshot.contents,
    ) != (
        initial_snapshot.device,
        initial_snapshot.inode,
        initial_snapshot.contents,
    ):
        raise ValuationRunArchiveError("valuation archive path or bytes changed during reload")
    file_hashes = {name: _sha256(contents[name]) for name in VALUATION_RUN_ARCHIVE_FILENAMES}
    return ValuationRunArchive(
        output_directory=source,
        directory_device=final_snapshot.device,
        directory_inode=final_snapshot.inode,
        handoff=handoff,
        price_blind_input=artifact,
        market_reference=snapshot,
        request_payload=freeze(request_payload),
        result_payload=freeze(result_payload),
        manifest=freeze(manifest_payload),
        file_sha256=freeze(file_hashes),
    )


def write_valuation_run_archive(
    execution: OwnerValuationExecutionResult,
    *,
    output_directory: Path,
) -> ValuationRunArchive:
    """Atomically publish exactly six canonical, mutually bound valuation files."""

    contents, _ = _archive_payloads(execution)
    target = Path(output_directory).expanduser().absolute()
    if not target.name or target == target.parent:
        raise ValuationRunArchiveError("valuation archive output directory is unsafe")
    _reject_symlink_path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_path(target.parent)
    if target.exists() or target.is_symlink():
        existing = _read_archive_directory(target)
        if existing.contents == contents:
            return load_valuation_run_archive(target, expected_execution=execution)
        raise ValuationRunArchiveError("valuation archive exists with different content")
    parent_descriptor = _open_directory(target.parent)
    staging_name = f".{target.name}.staging-{uuid.uuid4().hex}"
    staging_descriptor: int | None = None
    published_identity: tuple[int, int] | None = None
    renamed = False
    try:
        _write_staging(parent_descriptor, staging_name, contents)
        staging_descriptor = os.open(
            staging_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        staged_identity = _verify_staging_directory(staging_descriptor, contents)
        os.fsync(staging_descriptor)
        os.fsync(parent_descriptor)
        # Darwin rejects rename(2) of a directory whose own owner-write bit is
        # clear, even when the parent grants deletion. Preserve the complete
        # 0555 seal/fsync/replay above, then open only the minimum owner
        # capability for the rename syscall and close it immediately after.
        darwin_rename_capability = sys.platform == "darwin"
        if darwin_rename_capability:
            os.fchmod(staging_descriptor, 0o700)
            _reject_extended_acl(staging_descriptor, "valuation archive staging directory")
        try:
            _rename_directory_noreplace(parent_descriptor, staging_name, target.name)
            renamed = True
        except FileExistsError as exc:
            os.close(staging_descriptor)
            staging_descriptor = None
            _remove_staging_directory(parent_descriptor, staging_name)
            try:
                existing = _read_archive_directory(target)
            except ValuationRunArchiveError as existing_exc:
                raise ValuationRunArchiveError(
                    "valuation archive exists with different content"
                ) from existing_exc
            if existing.contents == contents:
                return load_valuation_run_archive(target, expected_execution=execution)
            raise ValuationRunArchiveError(
                "valuation archive exists with different content"
            ) from exc
        if darwin_rename_capability:
            os.fchmod(staging_descriptor, 0o555)
        target_details = os.fstat(staging_descriptor)
        if (
            (target_details.st_dev, target_details.st_ino) != staged_identity
            or target_details.st_mode & 0o222
        ):
            raise ValuationRunArchiveError("published valuation archive directory is writable")
        _reject_extended_acl(staging_descriptor, "published valuation archive directory")
        published_identity = (target_details.st_dev, target_details.st_ino)
        os.fsync(staging_descriptor)
        os.fsync(parent_descriptor)
    except (OSError, ValuationRunArchiveError) as exc:
        if renamed and staging_descriptor is not None:
            try:
                target_descriptor = os.open(
                    target.name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_descriptor,
                )
                try:
                    target_details = os.fstat(target_descriptor)
                    staging_details = os.fstat(staging_descriptor)
                    if (target_details.st_dev, target_details.st_ino) != (
                        staging_details.st_dev,
                        staging_details.st_ino,
                    ):
                        raise ValuationRunArchiveError(
                            "published valuation archive path changed before rollback"
                        )
                finally:
                    os.close(target_descriptor)
                os.fchmod(staging_descriptor, 0o700)
                _rename_directory_noreplace(
                    parent_descriptor,
                    target.name,
                    staging_name,
                )
                renamed = False
                os.fsync(parent_descriptor)
            except (OSError, ValuationRunArchiveError) as rollback_exc:
                raise ValuationRunArchiveError(
                    "valuation archive sealing failed and atomic rollback was unavailable"
                ) from rollback_exc
        if staging_name in os.listdir(parent_descriptor):
            _remove_staging_directory(parent_descriptor, staging_name)
        if isinstance(exc, ValuationRunArchiveError):
            raise
        raise ValuationRunArchiveError(f"valuation archive publication failed: {exc}") from exc
    finally:
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        os.close(parent_descriptor)
    loaded = load_valuation_run_archive(target, expected_execution=execution)
    if published_identity != (loaded.directory_device, loaded.directory_inode):
        raise ValuationRunArchiveError("published valuation archive path identity changed")
    return loaded


__all__ = (
    "VALUATION_RUN_ARCHIVE_FILENAMES",
    "VALUATION_RUN_ARCHIVE_MAX_BYTES",
    "VALUATION_RUN_MEMBER_MAX_BYTES",
    "ValuationRunArchive",
    "ValuationRunArchiveError",
    "load_valuation_run_archive",
    "write_valuation_run_archive",
)
