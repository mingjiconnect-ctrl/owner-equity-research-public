"""Strict six-file archive for one completed Phase 5 v1 valuation run."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import sys
import unicodedata
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError as JSONSchemaValidationError
from referencing import Registry, Resource

from .component_lock import (
    default_component_lock_path,
)
from .contracts import (
    Fact,
    MarketReferenceSnapshot,
    SourceDocument,
    ValuationHandoff,
    contract_from_dict,
)
from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze, to_json_value
from .valuation_kernel_projection import (
    CurrentShareKernelProjection,
    KernelNumericProjectionWitness,
)
from .valuation_market_execution_policies import (
    FINAL_REQUEST_POLICY_ID,
    FINAL_REQUEST_POLICY_VERSION,
    KERNEL_EXECUTION_POLICY,
    KERNEL_EXECUTION_POLICY_ID,
    KERNEL_EXECUTION_POLICY_VERSION,
    PINNED_KERNEL_SCHEMA_SHA256,
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
        "final_request_replay_evidence",
        "final_request_projection",
        "kernel_runtime_authority",
        "kernel_execution_projection",
        "manifest_fingerprint",
    }
)
_KERNEL_EXECUTION_PROJECTION_FIELDS = frozenset(
    {
        "policy_id",
        "policy_version",
        "repository",
        "tag",
        "commit",
        "package_version",
        "plugin_version",
        "schema_sha256",
        "wheel_sha256",
        "runtime_authority_sha256",
        "runner_sha256",
        "result_schema_sha256",
        "execution_mode",
        "request_transport",
        "result_transport",
        "network_mode",
        "request_sha256",
        "result_sha256",
        "fact_ledger_fingerprint",
        "assumption_ledger_fingerprint",
        "model_input_fingerprint",
        "call_count",
        "exit_code",
        "result_preserved",
        "status",
        "reason_codes",
    }
)
_KERNEL_RUNTIME_AUTHORITY_FIELDS = frozenset(
    {
        "schema_version",
        "manifest_policy_id",
        "manifest_policy_version",
        "runtime_authority_sha256",
        "kernel",
        "result_schema_sha256",
        "transport",
    }
)
_KERNEL_RUNTIME_IDENTITY_FIELDS = frozenset(
    {
        "repository",
        "tag",
        "commit",
        "package_version",
        "plugin_version",
        "wheel_sha256",
        "runner_sha256",
    }
)
_KERNEL_RUNTIME_TRANSPORT_FIELDS = frozenset(
    {
        "kernel_call",
        "kernel_call_count",
        "network_mode",
        "request",
        "result",
        "result_bytes_preserved",
    }
)
_FINAL_REQUEST_PROJECTION_FIELDS = frozenset(
    {
        "policy_id",
        "policy_version",
        "issuer_id",
        "handoff_run_id",
        "market_reference_snapshot_id",
        "company_legal_name_value",
        "company_name_fact_id",
        "company_name_fact_fingerprint",
        "company_name_source_document_id",
        "company_name_source_document_fingerprint",
        "company_identity_binding_sha256",
        "market_provider_id",
        "market_source_document_id",
        "market_source_document_fingerprint",
        "market_source_ref_fingerprint",
        "market_quote_fact_id",
        "market_quote_fact_fingerprint",
        "market_equity_calculation_id",
        "added_source_ids",
        "added_fact_ids",
        "price_blind_fact_ledger_sha256",
        "final_fact_ledger_sha256",
        "assumption_entries_before_sha256",
        "assumption_entries_after_sha256",
        "price_blind_input_before_sha256",
        "price_blind_input_after_sha256",
        "protected_mckinsey_before_sha256",
        "protected_mckinsey_after_sha256",
        "protected_penman_before_sha256",
        "protected_penman_after_sha256",
        "valuation_request_sha256",
        "status",
        "reason_codes",
    }
)
_HEX = frozenset("0123456789abcdef")
_PINNED_KERNEL_SCHEMA_FILENAMES = (
    "assumption-ledger.schema.json",
    "fact-ledger.schema.json",
    "valuation-request.schema.json",
    "valuation-result.schema.json",
)
_PINNED_KERNEL_SCHEMA_DIRECTORY = (
    Path(__file__).parent / "resources" / "phase5-v1-kernel-schemas"
)
_RFC3339_DATETIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})\Z"
)
_MARKET_EQUITY_DERIVATION = (
    "market_price_per_current_common_share * common_shares_outstanding"
)


class ValuationRunArchiveError(ValueError):
    """The six-file valuation archive is incomplete, unsafe, or inconsistent."""


@dataclass(frozen=True, slots=True)
class _ArchiveFinalRequestProjection:
    policy_id: str
    policy_version: str
    issuer_id: str
    handoff_run_id: str
    market_reference_snapshot_id: str
    company_legal_name_value: str
    company_name_fact_id: str
    company_name_fact_fingerprint: str
    company_name_source_document_id: str
    company_name_source_document_fingerprint: str
    company_identity_binding_sha256: str
    market_provider_id: str
    market_source_document_id: str
    market_source_document_fingerprint: str
    market_source_ref_fingerprint: str
    market_quote_fact_id: str
    market_quote_fact_fingerprint: str
    market_equity_calculation_id: str
    added_source_ids: tuple[str, ...]
    added_fact_ids: tuple[str, ...]
    price_blind_fact_ledger_sha256: str
    final_fact_ledger_sha256: str
    assumption_entries_before_sha256: str
    assumption_entries_after_sha256: str
    price_blind_input_before_sha256: str
    price_blind_input_after_sha256: str
    protected_mckinsey_before_sha256: str
    protected_mckinsey_after_sha256: str
    protected_penman_before_sha256: str
    protected_penman_after_sha256: str
    valuation_request_sha256: str
    status: str
    reason_codes: tuple[str, ...]

    @classmethod
    def from_payload(cls, payload: object) -> _ArchiveFinalRequestProjection:
        if not isinstance(payload, dict) or set(payload) != _FINAL_REQUEST_PROJECTION_FIELDS:
            raise ValuationRunArchiveError("archive final-request projection is not closed")
        values = dict(payload)
        for name in ("added_source_ids", "added_fact_ids", "reason_codes"):
            value = values[name]
            if not isinstance(value, list) or any(type(item) is not str for item in value):
                raise ValuationRunArchiveError(
                    "archive final-request projection has an invalid ordered field"
                )
            values[name] = tuple(value)
        try:
            return cls(**values)
        except TypeError as exc:
            raise ValuationRunArchiveError(
                "archive final-request projection is invalid"
            ) from exc

    def __post_init__(self) -> None:
        if (
            (self.policy_id, self.policy_version)
            != (FINAL_REQUEST_POLICY_ID, FINAL_REQUEST_POLICY_VERSION)
            or self.status != "validated"
            or self.reason_codes
        ):
            raise ValuationRunArchiveError(
                "archive final-request projection policy state is invalid"
            )
        for name in (
            "company_name_fact_fingerprint",
            "company_name_source_document_fingerprint",
            "company_identity_binding_sha256",
            "market_source_document_fingerprint",
            "market_source_ref_fingerprint",
            "market_quote_fact_fingerprint",
            "price_blind_fact_ledger_sha256",
            "final_fact_ledger_sha256",
            "assumption_entries_before_sha256",
            "assumption_entries_after_sha256",
            "price_blind_input_before_sha256",
            "price_blind_input_after_sha256",
            "protected_mckinsey_before_sha256",
            "protected_mckinsey_after_sha256",
            "protected_penman_before_sha256",
            "protected_penman_after_sha256",
            "valuation_request_sha256",
        ):
            _exact_sha(getattr(self, name), name)


def _pinned_format_checker() -> FormatChecker:
    checker = FormatChecker()

    @checker.checks("date-time")
    def is_rfc3339_datetime(value: object) -> bool:
        if not isinstance(value, str):
            return True
        if _RFC3339_DATETIME.fullmatch(value) is None:
            return False
        normalized = value[:10] + "T" + value[11:]
        if normalized[-1:] in {"Z", "z"}:
            normalized = normalized[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return False
        return parsed.tzinfo is not None

    return checker


_PINNED_FORMAT_CHECKER = _pinned_format_checker()


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
    try:
        serialized = canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise ValuationRunArchiveError("archive payload is not canonical JSON") from exc
    return (serialized + "\n").encode("utf-8")


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
    def reject_constant(token: str) -> None:
        raise ValueError(f"non-finite JSON constant: {token}")

    def finite_float(token: str) -> float:
        value = float(token)
        if not math.isfinite(value):
            raise ValueError(f"non-finite JSON number: {token}")
        return value

    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
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


def _darwin_fixed_root_alias(path: Path) -> tuple[Path, Path] | None:
    absolute = Path(path).expanduser().absolute()
    # Darwin exposes /tmp, /var, and /etc as fixed root-owned aliases into
    # /private.  Normalize only that platform-owned first component; every
    # remaining component is still opened by the no-follow descriptor walk.
    if sys.platform == "darwin" and len(absolute.parts) >= 2:
        root_alias = Path(absolute.anchor) / absolute.parts[1]
        expected_target = Path("/private") / absolute.parts[1]
        try:
            alias_details = root_alias.lstat()
            alias_target = root_alias.resolve(strict=True)
        except OSError:
            pass
        else:
            if (
                stat.S_ISLNK(alias_details.st_mode)
                and alias_details.st_uid == 0
                and alias_target == expected_target
                and alias_target.is_dir()
            ):
                return root_alias, alias_target
    return None


def _open_regular_without_symlink_components(path: Path, label: str) -> int:
    absolute = Path(path).expanduser().absolute()
    fixed_alias = _darwin_fixed_root_alias(absolute)
    if fixed_alias is not None:
        absolute = fixed_alias[1].joinpath(*absolute.parts[2:])
    parts = absolute.parts
    if len(parts) < 2 or not absolute.name:
        raise ValuationRunArchiveError(f"{label} path is invalid")
    # Linux permits a trusted caller to traverse an execute-only directory when
    # it already knows the child name.  O_PATH preserves that capability without
    # granting directory-read access, while O_DIRECTORY | O_NOFOLLOW keeps every
    # component in this descriptor walk non-symlink and directory-only.  Systems
    # without O_PATH retain the portable O_RDONLY behavior.
    directory_flags = (
        getattr(os, "O_PATH", os.O_RDONLY)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(parts[0], directory_flags)
        for part in parts[1:-1]:
            next_descriptor = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(
            parts[-1],
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=descriptor,
        )
    except OSError as exc:
        raise ValuationRunArchiveError(
            f"{label} path contains an unavailable or symlinked component"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return file_descriptor


def _read_bounded_regular(path: Path, label: str, maximum: int) -> bytes:
    descriptor = _open_regular_without_symlink_components(path, label)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or before.st_size > maximum
        ):
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


def _load_pinned_kernel_schemas(component_lock: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    try:
        locked_hashes = component_lock["valuation_kernel"]["public_schema_sha256"]
    except (KeyError, TypeError) as exc:
        raise ValuationRunArchiveError("component lock lacks pinned kernel Schema hashes") from exc
    if not isinstance(locked_hashes, Mapping):
        raise ValuationRunArchiveError("component lock has invalid pinned kernel Schema hashes")
    schemas: dict[str, dict[str, Any]] = {}
    for filename in _PINNED_KERNEL_SCHEMA_FILENAMES:
        relative = f"schemas/{filename}"
        expected = locked_hashes.get(relative)
        if expected != PINNED_KERNEL_SCHEMA_SHA256[relative]:
            raise ValuationRunArchiveError(f"pinned kernel Schema identity drifted: {filename}")
        raw = _read_bounded_regular(
            _PINNED_KERNEL_SCHEMA_DIRECTORY / filename,
            f"pinned kernel Schema {filename}",
            VALUATION_RUN_MEMBER_MAX_BYTES,
        )
        if _sha256(raw) != expected:
            raise ValuationRunArchiveError(f"pinned kernel Schema bytes drifted: {filename}")
        schema = _json_object(raw, f"pinned kernel Schema {filename}")
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:  # pragma: no cover - exact locked bytes make this unreachable
            raise ValuationRunArchiveError(
                f"pinned kernel Schema is not Draft 2020-12: {filename}"
            ) from exc
        schemas[filename] = schema
    return schemas


def _validate_pinned_kernel_payloads(
    *,
    request: Mapping[str, Any],
    result: Mapping[str, Any],
    component_lock: Mapping[str, Any],
) -> None:
    schemas = _load_pinned_kernel_schemas(component_lock)
    fact_schema = schemas["fact-ledger.schema.json"]
    assumption_schema = schemas["assumption-ledger.schema.json"]
    registry = (
        Registry()
        .with_resource(fact_schema["$id"], Resource.from_contents(fact_schema))
        .with_resource(
            assumption_schema["$id"],
            Resource.from_contents(assumption_schema),
        )
    )
    validators = (
        (
            "valuation request",
            Draft202012Validator(
                schemas["valuation-request.schema.json"],
                registry=registry,
                format_checker=_PINNED_FORMAT_CHECKER,
            ),
            request,
        ),
        (
            "valuation result",
            Draft202012Validator(
                schemas["valuation-result.schema.json"],
                format_checker=_PINNED_FORMAT_CHECKER,
            ),
            result,
        ),
    )
    try:
        for label, validator, payload in validators:
            error = next(validator.iter_errors(payload), None)
            if error is not None:
                path = "$" + "".join(
                    f"[{part}]" if isinstance(part, int) else f".{part}"
                    for part in error.path
                )
                raise ValuationRunArchiveError(
                    f"{label} failed the pinned kernel Schema at {path}: {error.message}"
                )
    except ValuationRunArchiveError:
        raise
    except Exception as exc:  # pragma: no cover - dependency failure is fail-closed
        raise ValuationRunArchiveError("pinned kernel Schema could not be applied") from exc


def _reject_symlink_path(path: Path) -> None:
    absolute = Path(path).expanduser().absolute()
    fixed_alias = _darwin_fixed_root_alias(absolute)
    allowed_alias = None if fixed_alias is None else fixed_alias[0]
    for candidate in (absolute, *absolute.parents):
        try:
            details = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode) and candidate != allowed_alias:
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


def _lock_directory_descriptor(descriptor: int, *, exclusive: bool) -> None:
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    while True:
        try:
            fcntl.flock(descriptor, operation)
        except InterruptedError:
            continue
        except OSError as exc:
            raise ValuationRunArchiveError(
                "valuation archive coordination lock is unavailable"
            ) from exc
        return


def _read_member(
    directory_descriptor: int,
    name: str,
    *,
    remaining_archive_bytes: int,
) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
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


def _clone_directory_noreplace(parent_descriptor: int, source: str, target: str) -> None:
    """Atomically clone one sealed Darwin directory without exposing writable mode bits."""

    if sys.platform != "darwin":  # pragma: no cover - selected only on Darwin
        raise ValuationRunArchiveError("atomic directory cloning is Darwin-only")
    library = ctypes.CDLL(None, use_errno=True)
    try:
        clone = library.clonefileat
    except AttributeError as exc:  # pragma: no cover - all supported Darwin versions expose it
        raise ValuationRunArchiveError(
            "atomic no-replace directory publication is unavailable"
        ) from exc
    clone.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    )
    clone.restype = ctypes.c_int
    # CLONE_NOFOLLOW_ANY | CLONE_RESOLVE_BENEATH.  clonefileat is itself
    # no-replace and atomic for the complete directory hierarchy.
    flags = 0x0008 | 0x0010
    ctypes.set_errno(0)
    result = clone(
        parent_descriptor,
        os.fsencode(source),
        parent_descriptor,
        os.fsencode(target),
        flags,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error, "valuation archive target already exists", target)
    raise OSError(error, "atomic valuation archive clone publication failed", target)


def _publish_directory_noreplace(parent_descriptor: int, source: str, target: str) -> bool:
    """Publish the sealed directory and return whether the source name moved."""

    if sys.platform == "darwin":
        _clone_directory_noreplace(parent_descriptor, source, target)
        return False
    _rename_directory_noreplace(parent_descriptor, source, target)
    return True


def _rename_exchange(parent_descriptor: int, left: str, right: str) -> None:
    """Atomically exchange two Darwin names without requiring directory write bits."""

    if sys.platform != "darwin":  # pragma: no cover - selected only on Darwin
        raise ValuationRunArchiveError("atomic directory exchange is Darwin-only")
    library = ctypes.CDLL(None, use_errno=True)
    try:
        rename = library.renameatx_np
    except AttributeError as exc:  # pragma: no cover - supported Darwin versions expose it
        raise ValuationRunArchiveError("atomic directory rollback is unavailable") from exc
    rename.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename.restype = ctypes.c_int
    # RENAME_SWAP | RENAME_NOFOLLOW_ANY | RENAME_RESOLVE_BENEATH.
    flags = 0x00000002 | 0x00000010 | 0x00000020
    ctypes.set_errno(0)
    result = rename(
        parent_descriptor,
        os.fsencode(left),
        parent_descriptor,
        os.fsencode(right),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, "atomic valuation archive rollback failed", left)


def _write_read_only_placeholder(parent_descriptor: int, name: str) -> tuple[int, int]:
    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=parent_descriptor,
    )
    created = os.fstat(descriptor)
    created_identity = (created.st_dev, created.st_ino)
    succeeded = False
    try:
        _reject_extended_acl(descriptor, "valuation archive rollback placeholder")
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        _reject_extended_acl(descriptor, "valuation archive rollback placeholder")
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_mode & 0o222:
            raise ValuationRunArchiveError("valuation archive rollback placeholder is writable")
        os.fsync(descriptor)
        succeeded = True
        return created_identity
    finally:
        os.close(descriptor)
        if not succeeded:
            try:
                current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if stat.S_ISREG(current.st_mode) and (
                    current.st_dev,
                    current.st_ino,
                ) == created_identity:
                    os.unlink(name, dir_fd=parent_descriptor)


def _directory_identity(
    parent_descriptor: int,
    name: str,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> tuple[int, int]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        details = os.fstat(descriptor)
        identity = (details.st_dev, details.st_ino)
        if (
            not stat.S_ISDIR(details.st_mode)
            or (expected_identity is not None and identity != expected_identity)
        ):
            raise ValuationRunArchiveError("published valuation archive identity changed")
        return identity
    finally:
        os.close(descriptor)


def _rollback_published_directory(
    parent_descriptor: int,
    *,
    target_name: str,
    staging_name: str,
    published_identity: tuple[int, int],
    source_moved: bool,
) -> None:
    _directory_identity(
        parent_descriptor,
        target_name,
        expected_identity=published_identity,
    )
    if source_moved:
        _rename_directory_noreplace(parent_descriptor, target_name, staging_name)
        os.fsync(parent_descriptor)
        return

    placeholder_name = f".{target_name}.rollback-{uuid.uuid4().hex}"
    placeholder_identity: tuple[int, int] | None = None
    try:
        placeholder_identity = _write_read_only_placeholder(
            parent_descriptor,
            placeholder_name,
        )
        os.fsync(parent_descriptor)
        _rename_exchange(parent_descriptor, target_name, placeholder_name)
        replacement = os.stat(target_name, dir_fd=parent_descriptor, follow_symlinks=False)
        displaced = os.stat(
            placeholder_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(replacement.st_mode)
            or (replacement.st_dev, replacement.st_ino) != placeholder_identity
            or replacement.st_mode & 0o222
            or not stat.S_ISDIR(displaced.st_mode)
            or (displaced.st_dev, displaced.st_ino) != published_identity
        ):
            raise ValuationRunArchiveError("valuation archive rollback target changed")
        os.unlink(target_name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
        _remove_staging_directory(parent_descriptor, placeholder_name)
        os.fsync(parent_descriptor)
    except Exception:
        try:
            details = os.stat(
                placeholder_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISREG(details.st_mode) and placeholder_identity == (
                details.st_dev,
                details.st_ino,
            ):
                os.unlink(placeholder_name, dir_fd=parent_descriptor)
        raise


def _remove_staging_directory(
    parent_descriptor: int,
    name: str,
    *,
    expected_identity: tuple[int, int] | None = None,
    allow_writable_owned: bool = False,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        directory_details = os.fstat(descriptor)
        directory_identity = (directory_details.st_dev, directory_details.st_ino)
        directory_writable = bool(directory_details.st_mode & 0o222)
        if (
            not stat.S_ISDIR(directory_details.st_mode)
            or (directory_writable and not allow_writable_owned)
            or (
                expected_identity is not None
                and directory_identity != expected_identity
            )
        ):
            raise ValuationRunArchiveError(
                "archive staging identity or sealed mode changed during publication"
            )
        names = tuple(sorted(os.listdir(descriptor)))
        unexpected_names = tuple(
            name for name in names if name not in VALUATION_RUN_ARCHIVE_FILENAMES
        )
        if unexpected_names:
            sealing_error: BaseException | None = None
            try:
                for filename in unexpected_names:
                    member_flags = (
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_NONBLOCK", 0)
                    )
                    member_descriptor = os.open(
                        filename,
                        member_flags,
                        dir_fd=descriptor,
                    )
                    try:
                        before = os.fstat(member_descriptor)
                        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                            raise ValuationRunArchiveError(
                                "archive staging contains an unsafe unknown member"
                            )
                        _reject_extended_acl(
                            member_descriptor,
                            "archive staging unknown member",
                        )
                        os.fchmod(member_descriptor, 0o444)
                        _reject_extended_acl(
                            member_descriptor,
                            "archive staging unknown member",
                        )
                        os.fsync(member_descriptor)
                        after = os.fstat(member_descriptor)
                        if (
                            not stat.S_ISREG(after.st_mode)
                            or after.st_nlink != 1
                            or after.st_mode & 0o222
                            or (after.st_dev, after.st_ino)
                            != (before.st_dev, before.st_ino)
                        ):
                            raise ValuationRunArchiveError(
                                "archive staging unknown member could not be sealed"
                            )
                    finally:
                        os.close(member_descriptor)
            except BaseException as exc:
                sealing_error = exc
            finally:
                os.fchmod(descriptor, 0o555)
                os.fsync(descriptor)
            if sealing_error is not None:
                raise ValuationRunArchiveError(
                    "archive staging unknown member could not be quarantined"
                ) from sealing_error
            raise ValuationRunArchiveError("archive staging member set changed during publication")
        member_identities: dict[str, tuple[int, int]] = {}
        for filename in names:
            details = os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or (details.st_mode & 0o222 and not allow_writable_owned)
            ):
                if directory_writable:
                    os.fchmod(descriptor, 0o555)
                    os.fsync(descriptor)
                raise ValuationRunArchiveError("archive staging contains an unsafe member")
            member_identities[filename] = (details.st_dev, details.st_ino)
        os.fchmod(descriptor, 0o700)
        try:
            if tuple(sorted(os.listdir(descriptor))) != names:
                raise ValuationRunArchiveError(
                    "archive staging member set changed during cleanup"
                )
            for filename in names:
                details = os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISREG(details.st_mode)
                    or (details.st_dev, details.st_ino) != member_identities[filename]
                ):
                    raise ValuationRunArchiveError(
                        "archive staging member identity changed during cleanup"
                    )
                os.unlink(filename, dir_fd=descriptor)
            os.fsync(descriptor)
        except Exception:
            os.fchmod(descriptor, 0o555)
            os.fsync(descriptor)
            raise
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent_descriptor)


def _verified_runtime_manifest_payload(authority: object) -> dict[str, Any]:
    # Imported lazily because valuation_run owns the typed input authority and
    # imports this archive module at module initialization time.
    from .valuation_run import RuntimeManifestInputAuthority

    if (
        type(authority) is not RuntimeManifestInputAuthority
        or authority.status != "verified"
        or authority.manifest_payload is None
    ):
        raise ValuationRunArchiveError(
            "archive publication requires exact verified runtime-manifest authority"
        )
    return to_json_value(authority.manifest_payload)


def _validate_runtime_manifest_receipt_binding(
    runtime_manifest_authority: object,
    kernel_receipt: object,
) -> dict[str, Any]:
    manifest = _verified_runtime_manifest_payload(runtime_manifest_authority)
    try:
        matches = (
            _sha256(canonical_json(manifest).encode("utf-8"))
            == kernel_receipt.runtime_manifest_file_sha256
            and manifest["manifest_fingerprint"]
            == kernel_receipt.runtime_manifest_fingerprint
            and manifest["authority"]["sha256"]
            == kernel_receipt.runtime_authority_sha256
            and canonical_sha256(manifest["wheels"])
            == kernel_receipt.wheel_inventory_sha256
        )
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ValuationRunArchiveError(
            "runtime-manifest authority cannot replay the completed kernel receipt"
        ) from exc
    if not matches:
        raise ValuationRunArchiveError(
            "runtime-manifest authority differs from the completed kernel receipt"
        )
    return manifest


def _expected_kernel_runtime_authority(
    component_lock: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the closed, replayable runtime authority retained by the archive.

    The full host runtime manifest contains observations such as producer labels,
    container descriptions, filenames, and URIs.  Those values are useful during
    execution but cannot be independently replayed from the six public files.  The
    archive therefore retains only values fixed by the component lock and the
    execution policy.
    """

    try:
        kernel = component_lock["valuation_kernel"]
        runtime = component_lock["valuation_kernel_runtime"]
        public_schema = kernel["public_schema_sha256"]
        authority_sha = runtime["runtime_authority"]["sha256"]
        runner_sha = runtime["runner_code"]["sha256"]
    except (KeyError, TypeError) as exc:
        raise ValuationRunArchiveError(
            "component lock lacks replayable kernel runtime authority"
        ) from exc
    if not all(isinstance(value, Mapping) for value in (kernel, runtime, public_schema)):
        raise ValuationRunArchiveError(
            "component lock kernel runtime authority is invalid"
        )
    result_schema_sha = public_schema.get("schemas/valuation-result.schema.json")
    for value, label in (
        (authority_sha, "runtime authority SHA"),
        (runner_sha, "kernel runner SHA"),
        (result_schema_sha, "valuation-result Schema SHA"),
        (kernel.get("release_evidence", {}).get("wheel_sha256"), "kernel wheel SHA"),
    ):
        _exact_sha(value, label)
    payload = {
        "schema_version": "1.0.0",
        "manifest_policy_id": runtime.get("manifest_policy_id"),
        "manifest_policy_version": runtime.get("manifest_policy_version"),
        "runtime_authority_sha256": authority_sha,
        "kernel": {
            "repository": kernel.get("repository"),
            "tag": kernel.get("tag"),
            "commit": kernel.get("commit"),
            "package_version": kernel.get("package_version"),
            "plugin_version": kernel.get("plugin_version"),
            "wheel_sha256": kernel["release_evidence"]["wheel_sha256"],
            "runner_sha256": runner_sha,
        },
        "result_schema_sha256": result_schema_sha,
        "transport": {
            "kernel_call": "run_valuation",
            "kernel_call_count": 1,
            "network_mode": KERNEL_EXECUTION_POLICY.network_mode,
            "request": KERNEL_EXECUTION_POLICY.request_transport,
            "result": KERNEL_EXECUTION_POLICY.result_transport,
            "result_bytes_preserved": True,
        },
    }
    if (
        set(payload) != _KERNEL_RUNTIME_AUTHORITY_FIELDS
        or set(payload["kernel"]) != _KERNEL_RUNTIME_IDENTITY_FIELDS
        or set(payload["transport"]) != _KERNEL_RUNTIME_TRANSPORT_FIELDS
        or type(payload["manifest_policy_id"]) is not str
        or type(payload["manifest_policy_version"]) is not str
        or any(
            type(payload["kernel"][name]) is not str
            or not payload["kernel"][name]
            for name in _KERNEL_RUNTIME_IDENTITY_FIELDS
        )
    ):
        raise ValuationRunArchiveError(
            "component lock kernel runtime authority fields drifted"
        )
    return payload


def _project_verified_runtime_manifest_authority(
    runtime_manifest_authority: object,
    *,
    runner_sha256: str,
) -> dict[str, Any]:
    """Drop host-only observations from one verified runtime manifest."""

    _exact_sha(runner_sha256, "kernel runner SHA")
    manifest = _verified_runtime_manifest_payload(runtime_manifest_authority)
    kernel = manifest.get("kernel")
    authority = manifest.get("authority")
    result_schema = manifest.get("result_schema")
    transport = manifest.get("transport")
    wheels = manifest.get("wheels")
    expected_transport = {
        "kernel_call": "run_valuation",
        "kernel_call_count": 1,
        "network_mode": KERNEL_EXECUTION_POLICY.network_mode,
        "request": KERNEL_EXECUTION_POLICY.request_transport,
        "result": KERNEL_EXECUTION_POLICY.result_transport,
        "result_bytes_preserved": True,
    }
    if (
        manifest.get("schema_version") != "1.0.0"
        or type(manifest.get("manifest_policy_id")) is not str
        or type(manifest.get("manifest_policy_version")) is not str
        or not isinstance(kernel, Mapping)
        or not isinstance(authority, Mapping)
        or not isinstance(authority.get("sha256"), str)
        or not isinstance(result_schema, Mapping)
        or result_schema.get("sha256")
        != PINNED_KERNEL_SCHEMA_SHA256["schemas/valuation-result.schema.json"]
        or not isinstance(transport, Mapping)
        or any(transport.get(name) != value for name, value in expected_transport.items())
        or not isinstance(wheels, list)
        or len(
            [
                item
                for item in wheels
                if isinstance(item, Mapping)
                and item.get("role") == "kernel"
                and item.get("sha256") == kernel.get("wheel_sha256")
            ]
        )
        != 1
    ):
        raise ValuationRunArchiveError(
            "runtime-manifest authority does not replay the fixed execution policy"
        )
    _exact_sha(authority["sha256"], "runtime authority SHA")
    projection = {
        "schema_version": "1.0.0",
        "manifest_policy_id": manifest["manifest_policy_id"],
        "manifest_policy_version": manifest["manifest_policy_version"],
        "runtime_authority_sha256": authority["sha256"],
        "kernel": {
            "repository": kernel.get("repository"),
            "tag": kernel.get("tag"),
            "commit": kernel.get("commit"),
            "package_version": kernel.get("package_version"),
            "plugin_version": kernel.get("plugin_version"),
            "wheel_sha256": kernel.get("wheel_sha256"),
            "runner_sha256": runner_sha256,
        },
        "result_schema_sha256": result_schema["sha256"],
        "transport": expected_transport,
    }
    if (
        set(projection) != _KERNEL_RUNTIME_AUTHORITY_FIELDS
        or set(projection["kernel"]) != _KERNEL_RUNTIME_IDENTITY_FIELDS
        or set(projection["transport"]) != _KERNEL_RUNTIME_TRANSPORT_FIELDS
        or any(
            type(projection["kernel"][name]) is not str
            or not projection["kernel"][name]
            for name in _KERNEL_RUNTIME_IDENTITY_FIELDS
        )
    ):
        raise ValuationRunArchiveError(
            "runtime-manifest authority projection fields drifted"
        )
    return projection


def _archive_kernel_runtime_authority(
    *,
    component_lock: Mapping[str, Any],
    runtime_manifest_authority: object,
) -> dict[str, Any]:
    """Project and bind one host manifest to the component-lock authority."""

    expected = _expected_kernel_runtime_authority(component_lock)
    projected = _project_verified_runtime_manifest_authority(
        runtime_manifest_authority,
        runner_sha256=expected["kernel"]["runner_sha256"],
    )
    if projected != expected:
        raise ValuationRunArchiveError(
            "runtime-manifest authority does not replay component lock and policy"
        )
    return expected


def _expected_kernel_execution_projection(
    *,
    component_lock: Mapping[str, Any],
    runtime_authority: Mapping[str, Any],
    request_sha: str,
    result_sha: str,
    fact_ledger_sha: str,
    assumption_ledger_sha: str,
) -> dict[str, Any]:
    expected_runtime_authority = _expected_kernel_runtime_authority(component_lock)
    if to_json_value(runtime_authority) != expected_runtime_authority:
        raise ValuationRunArchiveError(
            "archived kernel runtime authority does not replay component lock"
        )
    kernel = component_lock["valuation_kernel"]
    transport = expected_runtime_authority["transport"]
    projection = {
        "policy_id": KERNEL_EXECUTION_POLICY_ID,
        "policy_version": KERNEL_EXECUTION_POLICY_VERSION,
        "repository": kernel["repository"],
        "tag": kernel["tag"],
        "commit": kernel["commit"],
        "package_version": kernel["package_version"],
        "plugin_version": kernel["plugin_version"],
        "schema_sha256": kernel["public_schema_sha256"],
        "wheel_sha256": kernel["release_evidence"]["wheel_sha256"],
        "runtime_authority_sha256": expected_runtime_authority[
            "runtime_authority_sha256"
        ],
        "runner_sha256": expected_runtime_authority["kernel"]["runner_sha256"],
        "result_schema_sha256": expected_runtime_authority[
            "result_schema_sha256"
        ],
        "execution_mode": KERNEL_EXECUTION_POLICY.execution_mode,
        "request_transport": transport["request"],
        "result_transport": transport["result"],
        "network_mode": transport["network_mode"],
        "request_sha256": request_sha,
        "result_sha256": result_sha,
        "fact_ledger_fingerprint": fact_ledger_sha,
        "assumption_ledger_fingerprint": assumption_ledger_sha,
        "model_input_fingerprint": request_sha,
        "call_count": transport["kernel_call_count"],
        "exit_code": 0,
        "result_preserved": transport["result_bytes_preserved"],
        "status": "succeeded",
        "reason_codes": [],
    }
    if set(projection) != _KERNEL_EXECUTION_PROJECTION_FIELDS:
        raise ValuationRunArchiveError("archive kernel projection fields drifted")
    return projection


def _archive_payloads(
    execution: OwnerValuationExecutionResult,
    *,
    runtime_manifest_authority: object,
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
    try:
        replayed_request_bytes = canonical_json(request_payload).encode("utf-8")
        replayed_result_bytes = canonical_json(result_payload).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValuationRunArchiveError(
            "valuation request or result is not canonical JSON"
        ) from exc
    if request_bytes != replayed_request_bytes:
        raise ValuationRunArchiveError("valuation request bytes are not canonical")
    if result_bytes != replayed_result_bytes:
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
    _validate_pinned_kernel_payloads(
        request=request_payload,
        result=result_payload,
        component_lock=component_lock,
    )
    graph = execution.validated_graph
    fact_result = request_result.fact_ledger_result
    if graph is None or fact_result is None:
        raise ValuationRunArchiveError("completed owner execution lacks its validated graph")
    company_facts = tuple(
        item
        for item in graph.facts
        if item.fact_id == request_receipt.company_name_fact_id
    )
    company_sources = tuple(
        item
        for item in graph.documents
        if item.document_id == request_receipt.company_name_source_document_id
    )
    if (
        len(company_facts) != 1
        or len(company_sources) != 1
        or type(company_facts[0]) is not Fact
        or type(company_sources[0]) is not SourceDocument
        or company_facts[0].source_document_id != company_sources[0].document_id
    ):
        raise ValuationRunArchiveError(
            "completed owner execution lacks exact company identity evidence"
        )
    _validate_runtime_manifest_receipt_binding(
        runtime_manifest_authority,
        kernel_receipt,
    )
    runtime_authority_payload = _archive_kernel_runtime_authority(
        component_lock=component_lock,
        runtime_manifest_authority=runtime_manifest_authority,
    )
    fact_ledger_sha = canonical_sha256(request_payload["fact_ledger"])
    assumption_ledger_sha = canonical_sha256(request_payload["assumption_ledger"])
    kernel_projection = _expected_kernel_execution_projection(
        component_lock=component_lock,
        runtime_authority=runtime_authority_payload,
        request_sha=file_hashes["valuation-request.json"],
        result_sha=file_hashes["valuation-result.json"],
        fact_ledger_sha=fact_ledger_sha,
        assumption_ledger_sha=assumption_ledger_sha,
    )
    retained_kernel_projection = {
        name: kernel_receipt.to_dict()[name]
        for name in _KERNEL_EXECUTION_PROJECTION_FIELDS
    }
    if retained_kernel_projection != kernel_projection:
        raise ValuationRunArchiveError(
            "completed kernel receipt does not replay archive authority"
        )
    archive_current_share_projection, numeric_projection = (
        _archive_numeric_projection_evidence(
            request=request_payload,
            snapshot=snapshot,
        )
    )
    current_share_projection_payload = archive_current_share_projection.to_dict()
    final_request_projection = {
        name: request_receipt.to_dict()[name]
        for name in _FINAL_REQUEST_PROJECTION_FIELDS
    }
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
        "final_request_replay_evidence": {
            "company_identity": {
                "fact": company_facts[0].to_dict(),
                "source_document": company_sources[0].to_dict(),
            },
            "current_share_projection": current_share_projection_payload,
            "numeric_projection": numeric_projection,
        },
        "final_request_projection": final_request_projection,
        "kernel_runtime_authority": runtime_authority_payload,
        "kernel_execution_projection": kernel_projection,
    }
    manifest["manifest_fingerprint"] = canonical_sha256(manifest)
    contents["valuation-run-manifest.json"] = _canonical_file(manifest)
    return contents, manifest


def _ledger_index(
    values: object,
    *,
    identity_field: str,
    label: str,
) -> dict[str, dict[str, Any]]:
    if not isinstance(values, list):
        raise ValuationRunArchiveError(f"{label} is not an ordered array")
    index: dict[str, dict[str, Any]] = {}
    for value in values:
        if not isinstance(value, dict) or type(value.get(identity_field)) is not str:
            raise ValuationRunArchiveError(f"{label} contains an invalid identity")
        identifier = value[identity_field]
        if identifier in index:
            raise ValuationRunArchiveError(f"{label} repeats an identity")
        index[identifier] = value
    return index


def _fact_number_from_decimal(value: str, label: str) -> int | float:
    try:
        parsed = Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValuationRunArchiveError(f"{label} is not an exact decimal") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ValuationRunArchiveError(f"{label} must be finite and positive")
    if parsed == parsed.to_integral_value():
        return int(parsed)
    projected = float(parsed)
    if Decimal(str(projected)) != parsed:
        raise ValuationRunArchiveError(f"{label} cannot replay the research Fact")
    return projected


def _archive_numeric_projection_evidence(
    *,
    request: Mapping[str, Any],
    snapshot: MarketReferenceSnapshot,
) -> tuple[CurrentShareKernelProjection, dict[str, Any]]:
    ledger = request["fact_ledger"]
    facts = _ledger_index(
        ledger["facts"],
        identity_field="fact_id",
        label="final Facts",
    )
    sources = _ledger_index(
        ledger["sources"],
        identity_field="source_id",
        label="final SourceRefs",
    )
    current_fact_id = snapshot.share_basis["shares_outstanding_fact_id"]
    quote_fact_id = snapshot.quote_fact_id
    calculation_id = snapshot.market_equity["calculation_id"]
    market_fact_id = f"derived:{calculation_id}"
    for identifier in (current_fact_id, quote_fact_id, market_fact_id):
        if identifier not in facts:
            raise ValuationRunArchiveError(
                "archive numeric projection lacks a retained request Fact"
            )

    closure: set[str] = set()
    pending = [current_fact_id]
    while pending:
        identifier = pending.pop()
        if identifier in closure:
            continue
        fact = facts.get(identifier)
        if fact is None:
            raise ValuationRunArchiveError(
                "archive current-share lineage has a dangling parent"
            )
        closure.add(identifier)
        parents = fact.get("parent_fact_ids")
        if not isinstance(parents, list):
            raise ValuationRunArchiveError(
                "archive current-share lineage parents are invalid"
            )
        pending.extend(parents)
    projected_facts = [facts[identifier] for identifier in sorted(closure)]
    source_ids = {fact["source_id"] for fact in projected_facts}
    if not source_ids.issubset(sources):
        raise ValuationRunArchiveError(
            "archive current-share lineage has a dangling SourceRef"
        )
    projected_sources = [sources[identifier] for identifier in sorted(source_ids)]

    current_witness = KernelNumericProjectionWitness.compile(
        label=f"archive-share:{current_fact_id}",
        authoritative_decimal=Decimal(
            snapshot.share_basis["current_common_shares_outstanding_decimal"]
        ),
        scale_divisor=Decimal(1_000_000),
    )
    quote_witness = KernelNumericProjectionWitness.compile(
        label=f"archive-quote:{quote_fact_id}",
        authoritative_decimal=Decimal(snapshot.quote_price_decimal),
    )
    market_witness = KernelNumericProjectionWitness.compile_from_projected_binary64(
        label=f"archive-market-equity:{market_fact_id}",
        authoritative_decimal=Decimal(snapshot.market_equity["value_decimal"]),
        projected_value=float(facts[market_fact_id]["value"]),
        scale_divisor=Decimal(1_000_000),
    )
    if (
        current_witness.kernel_value != facts[current_fact_id]["value"]
        or quote_witness.kernel_value != facts[quote_fact_id]["value"]
        or market_witness.kernel_value != facts[market_fact_id]["value"]
    ):
        raise ValuationRunArchiveError(
            "archive numeric projection does not replay request values"
        )
    arithmetic_steps = (
        {
            "step": 0,
            "operation": "archive_current_share_identity",
            "input_fact_ids": sorted(closure),
            "output_fact_id": current_fact_id,
            "output_binary64_hex": current_witness.binary64_hex,
        },
    )
    attestation = {
        "archive_projection_version": "1.0.0",
        "evidence_kind": snapshot.share_basis["evidence_kind"],
        "current_share_fact_id": current_fact_id,
        "sources_sha256": canonical_sha256(projected_sources),
        "facts_sha256": canonical_sha256(projected_facts),
        "numeric_witnesses_sha256": canonical_sha256([current_witness.to_dict()]),
        "arithmetic_steps_sha256": canonical_sha256(arithmetic_steps),
    }
    projection = CurrentShareKernelProjection(
        status="eligible",
        evidence_kind=snapshot.share_basis["evidence_kind"],
        current_share_fact_id=current_fact_id,
        sources=tuple(projected_sources),
        facts=tuple(projected_facts),
        numeric_witnesses=(current_witness,),
        arithmetic_steps=arithmetic_steps,
        research_evidence_attestation=attestation,
        research_evidence_sha256=canonical_sha256(attestation),
        issue_codes=(),
    )
    numeric = {
        "current_share_numeric_witnesses": [current_witness.to_dict()],
        "quote_projection_witness": quote_witness.to_dict(),
        "market_equity_projection_witness": market_witness.to_dict(),
    }
    return projection, numeric


def _company_identity_binding_sha256(
    *,
    issuer_id: str,
    legal_name: str,
    fact_id: str,
    fact_fingerprint: str,
    source_document_id: str,
    source_document_fingerprint: str,
) -> str:
    return canonical_sha256(
        {
            "issuer_id": issuer_id,
            "legal_name": legal_name,
            "fact": [fact_id, fact_fingerprint],
            "source_document": [source_document_id, source_document_fingerprint],
        }
    )


def _retained_company_identity_binding_sha256(
    *,
    evidence: object,
    issuer_id: str,
    data_cutoff_date: str,
    company_name: object,
    receipt: _ArchiveFinalRequestProjection,
) -> str:
    if not isinstance(evidence, dict) or set(evidence) != {
        "fact",
        "source_document",
    }:
        raise ValuationRunArchiveError("company identity evidence is not closed")
    fact_payload = evidence["fact"]
    source_payload = evidence["source_document"]
    if not isinstance(fact_payload, dict) or not isinstance(source_payload, dict):
        raise ValuationRunArchiveError("company identity evidence is not typed")
    try:
        fact = contract_from_dict("fact", fact_payload)
        source = contract_from_dict("source-document", source_payload)
    except (JSONSchemaValidationError, KeyError, TypeError, ValueError) as exc:
        raise ValuationRunArchiveError("company identity evidence is invalid") from exc
    if type(fact) is not Fact or type(source) is not SourceDocument:
        raise ValuationRunArchiveError("company identity evidence has the wrong contract types")
    canonical_name = (
        unicodedata.normalize("NFC", fact.value)
        if isinstance(fact.value, str)
        else None
    )
    fact_period_end = fact.period["end"]
    source_period_end = source.period["end"]
    if (
        type(company_name) is not str
        or canonical_name != fact.value
        or canonical_name != " ".join(canonical_name.split())
        or not canonical_name
        or fact.fact_id != receipt.company_name_fact_id
        or fact.fingerprint != receipt.company_name_fact_fingerprint
        or fact.issuer_id != issuer_id
        or fact.concept != "issuer_legal_name"
        or fact.value_type != "text"
        or fact.value != company_name
        or fact.value != receipt.company_legal_name_value
        or fact.unit is not None
        or fact.currency is not None
        or fact.derivation is not None
        or fact.parent_fact_ids
        or fact.confidence not in {"high", "medium"}
        or not isinstance(fact_period_end, str)
        or fact_period_end > data_cutoff_date
        or fact.source_document_id != source.document_id
        or source.document_id != receipt.company_name_source_document_id
        or source.fingerprint
        != receipt.company_name_source_document_fingerprint
        or source.issuer_id != issuer_id
        or source.authority_level
        not in {"primary_regulatory", "company_primary"}
        or source.published_date > data_cutoff_date
        or (
            source_period_end is not None
            and (
                not isinstance(source_period_end, str)
                or source_period_end > data_cutoff_date
            )
        )
    ):
        raise ValuationRunArchiveError(
            "company identity evidence does not replay official cutoff-safe lineage"
        )
    return _company_identity_binding_sha256(
        issuer_id=issuer_id,
        legal_name=company_name,
        fact_id=fact.fact_id,
        fact_fingerprint=fact.fingerprint,
        source_document_id=source.document_id,
        source_document_fingerprint=source.fingerprint,
    )


def _validate_final_request_replay_evidence(
    *,
    evidence: object,
    handoff: ValuationHandoff,
    snapshot: MarketReferenceSnapshot,
    request: Mapping[str, Any],
    receipt: _ArchiveFinalRequestProjection,
) -> str:
    if not isinstance(evidence, dict) or set(evidence) != {
        "company_identity",
        "current_share_projection",
        "numeric_projection",
    }:
        raise ValuationRunArchiveError("final-request replay evidence is not closed")
    expected_company_binding = _retained_company_identity_binding_sha256(
        evidence=evidence["company_identity"],
        issuer_id=handoff.issuer_id,
        data_cutoff_date=handoff.data_cutoff_date,
        company_name=request["company"]["name"],
        receipt=receipt,
    )
    expected_projection, expected_numeric = _archive_numeric_projection_evidence(
        request=request,
        snapshot=snapshot,
    )
    if (
        evidence["current_share_projection"] != expected_projection.to_dict()
        or evidence["numeric_projection"] != expected_numeric
    ):
        raise ValuationRunArchiveError(
            "final-request typed projection evidence does not replay"
        )
    return expected_company_binding


def _validate_request_receipt_replay(
    *,
    handoff: ValuationHandoff,
    artifact_payload: Mapping[str, Any],
    snapshot: MarketReferenceSnapshot,
    request: Mapping[str, Any],
    result: Mapping[str, Any],
    request_sha: str,
    request_receipt: _ArchiveFinalRequestProjection,
    company_identity_evidence: object,
) -> tuple[str, str]:
    fact_ledger = request["fact_ledger"]
    assumption_ledger = request["assumption_ledger"]
    company = request["company"]
    result_company = result["company"]
    reviewed = artifact_payload["reviewed_assumptions"]
    base_fact_ledger = reviewed["augmented_fact_ledger_payload"]
    base_assumption_ledger = reviewed["assumption_ledger_payload"]
    classification: Mapping[str, Any] | None = None
    phase5c = artifact_payload.get("phase5c_readiness")
    if isinstance(phase5c, Mapping):
        reconciliation = phase5c.get("reconciliation_result")
        if isinstance(reconciliation, Mapping):
            phase5b = reconciliation.get("phase5b_readiness_result")
            if isinstance(phase5b, Mapping):
                candidate = phase5b.get("classification")
                if isinstance(candidate, Mapping):
                    classification = candidate
    if not all(
        isinstance(value, Mapping)
        for value in (
            fact_ledger,
            assumption_ledger,
            company,
            result_company,
            reviewed,
            base_fact_ledger,
            base_assumption_ledger,
        )
    ):
        raise ValuationRunArchiveError("archive ledgers or company identity are invalid")

    fact_ledger_sha = canonical_sha256(fact_ledger)
    assumption_ledger_sha = canonical_sha256(assumption_ledger)
    base_fact_ledger_sha = canonical_sha256(base_fact_ledger)
    assumptions_sha = canonical_sha256(assumption_ledger["assumptions"])
    if (
        fact_ledger["entity_id"] != handoff.issuer_id
        or base_fact_ledger["entity_id"] != handoff.issuer_id
        or fact_ledger["valuation_date"] != snapshot.trading_date
        or base_fact_ledger["valuation_date"] != snapshot.trading_date
        or fact_ledger["reporting_currency"] != snapshot.quote_currency
        or base_fact_ledger["reporting_currency"] != snapshot.quote_currency
        or request["model_unit"] != f"{snapshot.quote_currency} millions"
        or request["share_unit"] != "millions shares"
        or assumption_ledger["fact_ledger_fingerprint"] != fact_ledger_sha
        or base_assumption_ledger["fact_ledger_fingerprint"]
        != base_fact_ledger_sha
        or assumption_ledger["schema_version"]
        != base_assumption_ledger["schema_version"]
        or assumption_ledger["assumptions"]
        != base_assumption_ledger["assumptions"]
        or reviewed["assumption_entries_sha256"] != assumptions_sha
        or result_company
        != {"name": company["name"], "type": company["type"]}
        or result["schema_version"] != request["schema_version"]
        or company["type"] != "nonfinancial_operating_company"
        or type(company["classification_rationale"]) is not str
        or not company["classification_rationale"].strip()
        or not isinstance(company["source_fact_ids"], list)
        or not company["source_fact_ids"]
        or len(company["source_fact_ids"]) != len(set(company["source_fact_ids"]))
        or (
            classification is not None
            and (
                company["type"] != classification["company_type"]
                or company["classification_rationale"] != classification["rationale"]
                or company["source_fact_ids"] != classification["mapped_fact_ids"]
            )
        )
    ):
        raise ValuationRunArchiveError(
            "archive request identity, ledgers, or result company do not replay"
        )

    base_sources = _ledger_index(
        base_fact_ledger["sources"],
        identity_field="source_id",
        label="price-blind SourceRefs",
    )
    final_sources = _ledger_index(
        fact_ledger["sources"],
        identity_field="source_id",
        label="final SourceRefs",
    )
    base_facts = _ledger_index(
        base_fact_ledger["facts"],
        identity_field="fact_id",
        label="price-blind Facts",
    )
    final_facts = _ledger_index(
        fact_ledger["facts"],
        identity_field="fact_id",
        label="final Facts",
    )
    if any(final_sources.get(key) != value for key, value in base_sources.items()) or any(
        final_facts.get(key) != value for key, value in base_facts.items()
    ):
        raise ValuationRunArchiveError("final FactLedger changed price-blind evidence")
    if any(fact_id not in final_facts for fact_id in company["source_fact_ids"]):
        raise ValuationRunArchiveError("request company has dangling classification evidence")
    added_source_ids = tuple(sorted(set(final_sources) - set(base_sources)))
    added_fact_ids = tuple(sorted(set(final_facts) - set(base_facts)))

    market_source = final_sources.get(request_receipt.market_source_document_id)
    quote_fact = final_facts.get(request_receipt.market_quote_fact_id)
    share_fact_id = snapshot.share_basis["shares_outstanding_fact_id"]
    share_fact = final_facts.get(share_fact_id)
    market_fact_id = f"derived:{request_receipt.market_equity_calculation_id}"
    market_fact = final_facts.get(market_fact_id)
    if market_source is None or quote_fact is None or share_fact is None or market_fact is None:
        raise ValuationRunArchiveError("final FactLedger lacks governed market evidence")
    raw_sha = snapshot.raw_evidence["raw_response_sha256"]
    route_authority = {
        "human_reviewed_file": (
            "provider:human-reviewed-file",
            "market-equity",
        ),
        "governed_vendor": (
            "provider:futu-opend-sidecar",
            "futu-market-equity",
        ),
    }.get(snapshot.evidence_mode)
    if route_authority is None:
        raise ValuationRunArchiveError("market evidence route is not archive eligible")
    expected_provider_id, calculation_kind = route_authority
    expected_calculation_id = (
        f"calc:{handoff.issuer_id}:{calculation_kind}:"
        f"{snapshot.trading_date}:{raw_sha[:16]}"
    )
    market_document = {
        "schema_version": "1.0.0",
        "document_id": market_source["source_id"],
        "issuer_id": handoff.issuer_id,
        "document_type": "market-quote",
        "period": {"start": None, "end": snapshot.trading_date},
        "published_date": market_source["published_date"],
        "retrieved_at": market_source["retrieved_at"],
        "source_url": market_source["url"],
        "authority_level": "market_reference",
        "content_sha256": raw_sha,
    }
    research_quote_fact = {
        "schema_version": "2.0.0",
        "fact_id": quote_fact["fact_id"],
        "issuer_id": handoff.issuer_id,
        "concept": "market_quote_close",
        "value_type": "number",
        "value": _fact_number_from_decimal(snapshot.quote_price_decimal, "market quote"),
        "unit": "currency_per_share",
        "currency": snapshot.quote_currency,
        "period": {"start": None, "end": snapshot.trading_date},
        "source_document_id": market_source["source_id"],
        "source_locator": snapshot.quote_source_locator,
        "derivation": None,
        "parent_fact_ids": [],
        "confidence": "high",
    }
    expected_quote_fact = {
        "fact_id": snapshot.quote_fact_id,
        "concept": "market_price_per_current_common_share",
        "value": float(Decimal(snapshot.quote_price_decimal)),
        "unit": f"{snapshot.quote_currency} per share",
        "category": "market_price",
        "source_id": market_source["source_id"],
        "source_location": snapshot.quote_source_locator,
        "as_of_date": snapshot.trading_date,
        "currency": snapshot.quote_currency,
        "period_start": None,
        "period_end": None,
        "confidence": "high",
        "raw": True,
        "parent_fact_ids": [],
        "derivation": None,
        "equity_bridge_role": None,
    }
    share_value = Decimal(str(share_fact["value"]))
    authoritative_shares = Decimal(
        snapshot.share_basis["current_common_shares_outstanding_decimal"]
    )
    expected_market_fact = {
        "fact_id": market_fact_id,
        "concept": "market_equity_value",
        "value": float(quote_fact["value"]) * float(share_fact["value"]),
        "unit": f"{snapshot.quote_currency} millions",
        "category": "market_price",
        "source_id": market_source["source_id"],
        "source_location": f"derived:{request_receipt.market_equity_calculation_id}",
        "as_of_date": snapshot.trading_date,
        "currency": snapshot.quote_currency,
        "period_start": None,
        "period_end": None,
        "confidence": share_fact["confidence"],
        "raw": False,
        "parent_fact_ids": [quote_fact["fact_id"], share_fact_id],
        "derivation": _MARKET_EQUITY_DERIVATION,
        "equity_bridge_role": None,
    }
    if (
        market_source["source_id"] != snapshot.quote_source_document_id
        or market_source["publisher"] != request_receipt.market_provider_id
        or market_source["locator"]
        != f"document_id={market_source['source_id']};content_sha256={raw_sha}"
        or market_source["local_path"] is not None
        or market_source["primary"] is not False
        or canonical_sha256(market_source)
        != request_receipt.market_source_ref_fingerprint
        or canonical_sha256(market_document)
        != request_receipt.market_source_document_fingerprint
        or quote_fact != expected_quote_fact
        or canonical_sha256(research_quote_fact)
        != request_receipt.market_quote_fact_fingerprint
        or share_fact["concept"] != "common_shares_outstanding"
        or share_fact["unit"] != "millions shares"
        or share_fact["category"] != "share_count"
        or share_fact["currency"] is not None
        or share_fact["as_of_date"] != snapshot.trading_date
        or share_value != authoritative_shares / Decimal(1_000_000)
        or market_fact != expected_market_fact
        or snapshot.future_kernel_request_v2["share_denominator_fact_id"]
        != share_fact_id
        or request["mckinsey"]["equity_bridge"]["share_denominator_fact_id"]
        != share_fact_id
        or request["penman"]["market_equity_value_fact_id"] != market_fact_id
    ):
        raise ValuationRunArchiveError("governed market request projection does not replay")

    expected_company_binding = _validate_final_request_replay_evidence(
        evidence=company_identity_evidence,
        handoff=handoff,
        snapshot=snapshot,
        request=request,
        receipt=request_receipt,
    )
    if (
        request_receipt.policy_id != FINAL_REQUEST_POLICY_ID
        or request_receipt.policy_version != FINAL_REQUEST_POLICY_VERSION
        or request_receipt.status != "validated"
        or request_receipt.reason_codes
        or request_receipt.issuer_id != handoff.issuer_id
        or request_receipt.handoff_run_id != handoff.handoff_run_id
        or request_receipt.market_reference_snapshot_id != snapshot.snapshot_id
        or request_receipt.company_legal_name_value != company["name"]
        or request_receipt.company_identity_binding_sha256
        != expected_company_binding
        or request_receipt.market_provider_id != expected_provider_id
        or request_receipt.market_source_document_id
        != snapshot.quote_source_document_id
        or request_receipt.market_quote_fact_id != snapshot.quote_fact_id
        or request_receipt.market_equity_calculation_id
        != snapshot.market_equity["calculation_id"]
        or request_receipt.market_equity_calculation_id != expected_calculation_id
        or request_receipt.added_source_ids != added_source_ids
        or request_receipt.added_fact_ids != added_fact_ids
        or request_receipt.price_blind_fact_ledger_sha256
        != base_fact_ledger_sha
        or request_receipt.final_fact_ledger_sha256 != fact_ledger_sha
        or request_receipt.assumption_entries_before_sha256 != assumptions_sha
        or request_receipt.assumption_entries_after_sha256 != assumptions_sha
        or request_receipt.price_blind_input_before_sha256
        != artifact_payload["price_blind_input_fingerprint"]
        or request_receipt.price_blind_input_after_sha256
        != artifact_payload["price_blind_input_fingerprint"]
        or request_receipt.protected_mckinsey_before_sha256
        != artifact_payload["protected_mckinsey_sha256"]
        or request_receipt.protected_mckinsey_after_sha256
        != artifact_payload["protected_mckinsey_sha256"]
        or request_receipt.protected_penman_before_sha256
        != artifact_payload["protected_penman_assumptions_sha256"]
        or request_receipt.protected_penman_after_sha256
        != artifact_payload["protected_penman_assumptions_sha256"]
        or request_receipt.valuation_request_sha256 != request_sha
    ):
        raise ValuationRunArchiveError(
            "archive final-request receipt does not replay retained evidence"
        )
    return fact_ledger_sha, assumption_ledger_sha


def _validate_kernel_projection_replay(
    *,
    component_lock: Mapping[str, Any],
    runtime_authority_payload: object,
    projection: object,
    request_sha: str,
    result_sha: str,
    fact_ledger_sha: str,
    assumption_ledger_sha: str,
) -> None:
    if not isinstance(projection, dict) or set(projection) != (
        _KERNEL_EXECUTION_PROJECTION_FIELDS
    ):
        raise ValuationRunArchiveError("archive kernel projection is not closed")
    if not isinstance(runtime_authority_payload, Mapping):
        raise ValuationRunArchiveError("archive kernel runtime authority is not an object")
    expected = _expected_kernel_execution_projection(
        component_lock=component_lock,
        runtime_authority=runtime_authority_payload,
        request_sha=request_sha,
        result_sha=result_sha,
        fact_ledger_sha=fact_ledger_sha,
        assumption_ledger_sha=assumption_ledger_sha,
    )
    if projection != expected:
        raise ValuationRunArchiveError(
            "archive kernel projection does not replay typed authority"
        )


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
) -> Mapping[str, Any]:
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
    _validate_pinned_kernel_payloads(
        request=request,
        result=result,
        component_lock=component_lock,
    )
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
        request_projection = manifest["final_request_projection"]
        request_receipt = _ArchiveFinalRequestProjection.from_payload(
            request_projection
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValuationRunArchiveError("archive final-request projection is invalid") from exc
    try:
        fact_ledger_sha, assumption_ledger_sha = _validate_request_receipt_replay(
            handoff=handoff,
            artifact_payload=artifact_payload,
            snapshot=snapshot,
            request=request,
            result=result,
            request_sha=request_sha,
            request_receipt=request_receipt,
            company_identity_evidence=manifest["final_request_replay_evidence"],
        )
        _validate_kernel_projection_replay(
            component_lock=component_lock,
            runtime_authority_payload=manifest["kernel_runtime_authority"],
            projection=manifest["kernel_execution_projection"],
            request_sha=request_sha,
            result_sha=result_sha,
            fact_ledger_sha=fact_ledger_sha,
            assumption_ledger_sha=assumption_ledger_sha,
        )
    except ValuationRunArchiveError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ValuationRunArchiveError(
            "archive receipts cannot be replayed from the retained evidence"
        ) from exc
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
    return component_lock


def _load_valuation_run_archive_unlocked(
    input_directory: Path,
    *,
    component_lock_path: Path | None = None,
    expected_execution: OwnerValuationExecutionResult | None = None,
    expected_runtime_manifest_authority: object | None = None,
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
    component_lock = _validate_manifest(
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
        try:
            replayed_execution = OwnerValuationExecutionResult(
                **{
                    name: getattr(expected_execution, name)
                    for name in expected_execution.__dataclass_fields__
                }
            )
            prepared = replayed_execution.preparation.prepared_market_reference
            freeze_result = replayed_execution.expected_freeze
            request_result = replayed_execution.final_request_result
            if (
                replayed_execution.status != "completed"
                or prepared is None
                or freeze_result is None
                or request_result.canonical_request_json is None
                or replayed_execution.result_bytes is None
                or len(replayed_execution.execution_handoffs) != 2
            ):
                raise ValueError("expected execution is incomplete")
            expected_contents = {
                "valuation-handoff.json": _canonical_file(
                    replayed_execution.execution_handoffs[-1].to_dict()
                ),
                "price-blind-input.json": _canonical_file(
                    freeze_result.artifact.to_dict()
                ),
                "market-reference.json": _canonical_file(prepared.snapshot.to_dict()),
                "valuation-request.json": request_result.canonical_request_json.encode(
                    "utf-8"
                ),
                "valuation-result.json": replayed_execution.result_bytes,
            }
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValuationRunArchiveError(
                "expected completed execution cannot be replayed"
            ) from exc
        if any(contents[name] != value for name, value in expected_contents.items()):
            raise ValuationRunArchiveError(
                "archive differs from the expected completed execution"
            )
    if expected_runtime_manifest_authority is not None:
        if expected_execution is None:
            raise ValuationRunArchiveError(
                "full runtime-manifest authority requires its expected execution"
            )
        kernel_receipt = replayed_execution.kernel_execution_receipt
        if kernel_receipt is None:
            raise ValuationRunArchiveError(
                "expected execution lacks its kernel receipt"
            )
        _validate_runtime_manifest_receipt_binding(
            expected_runtime_manifest_authority,
            kernel_receipt,
        )
        expected_runtime_authority = _archive_kernel_runtime_authority(
            component_lock=component_lock,
            runtime_manifest_authority=expected_runtime_manifest_authority,
        )
        if manifest_payload["kernel_runtime_authority"] != expected_runtime_authority:
            raise ValuationRunArchiveError(
                "archive differs from the expected runtime-manifest authority"
            )
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


def load_valuation_run_archive(
    input_directory: Path,
    *,
    component_lock_path: Path | None = None,
    expected_execution: OwnerValuationExecutionResult | None = None,
    expected_runtime_manifest_authority: object | None = None,
) -> ValuationRunArchive:
    """Reload one finalized archive while excluding an in-progress publisher."""

    source = Path(input_directory).expanduser().absolute()
    _reject_symlink_path(source.parent)
    parent_descriptor = _open_directory(source.parent)
    try:
        _lock_directory_descriptor(parent_descriptor, exclusive=False)
        return _load_valuation_run_archive_unlocked(
            source,
            component_lock_path=component_lock_path,
            expected_execution=expected_execution,
            expected_runtime_manifest_authority=expected_runtime_manifest_authority,
        )
    finally:
        os.close(parent_descriptor)


def write_valuation_run_archive(
    execution: OwnerValuationExecutionResult,
    *,
    output_directory: Path,
    runtime_manifest_authority: object,
) -> ValuationRunArchive:
    """Atomically publish exactly six canonical, mutually bound valuation files."""

    contents, _ = _archive_payloads(
        execution,
        runtime_manifest_authority=runtime_manifest_authority,
    )
    target = Path(output_directory).expanduser().absolute()
    if not target.name or target == target.parent:
        raise ValuationRunArchiveError("valuation archive output directory is unsafe")
    _reject_symlink_path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_path(target.parent)
    parent_descriptor = _open_directory(target.parent)
    staging_name = f".{target.name}.staging-{uuid.uuid4().hex}"
    staging_descriptor: int | None = None
    staged_identity: tuple[int, int] | None = None
    published_identity: tuple[int, int] | None = None
    published = False
    source_moved = False
    try:
        _lock_directory_descriptor(parent_descriptor, exclusive=True)
        _reject_symlink_path(target)
        if target.exists() or target.is_symlink():
            existing = _read_archive_directory(target)
            if existing.contents == contents:
                return _load_valuation_run_archive_unlocked(
                    target,
                    expected_execution=execution,
                    expected_runtime_manifest_authority=runtime_manifest_authority,
                )
            raise ValuationRunArchiveError(
                "valuation archive exists with different content"
            )
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
        try:
            source_moved = _publish_directory_noreplace(
                parent_descriptor,
                staging_name,
                target.name,
            )
            published = True
        except FileExistsError as exc:
            os.close(staging_descriptor)
            staging_descriptor = None
            _remove_staging_directory(
                parent_descriptor,
                staging_name,
                expected_identity=staged_identity,
            )
            try:
                existing = _read_archive_directory(target)
            except ValuationRunArchiveError as existing_exc:
                raise ValuationRunArchiveError(
                    "valuation archive exists with different content"
                ) from existing_exc
            if existing.contents == contents:
                return _load_valuation_run_archive_unlocked(
                    target,
                    expected_execution=execution,
                    expected_runtime_manifest_authority=runtime_manifest_authority,
                )
            raise ValuationRunArchiveError(
                "valuation archive exists with different content"
            ) from exc
        target_details = os.stat(
            target.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(target_details.st_mode):
            raise ValuationRunArchiveError("published valuation archive is not a directory")
        published_identity = (target_details.st_dev, target_details.st_ino)
        if source_moved and published_identity != staged_identity:
            raise ValuationRunArchiveError("published valuation archive identity changed")
        target_descriptor = os.open(
            target.name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        try:
            if _verify_staging_directory(target_descriptor, contents) != published_identity:
                raise ValuationRunArchiveError(
                    "published valuation archive bytes or identity changed"
                )
            _reject_extended_acl(target_descriptor, "published valuation archive directory")
            os.fsync(target_descriptor)
        finally:
            os.close(target_descriptor)
        os.fsync(parent_descriptor)
        loaded = _load_valuation_run_archive_unlocked(
            target,
            expected_execution=execution,
            expected_runtime_manifest_authority=runtime_manifest_authority,
        )
        if published_identity != (loaded.directory_device, loaded.directory_inode):
            raise ValuationRunArchiveError("published valuation archive path identity changed")
        if not source_moved:
            os.close(staging_descriptor)
            staging_descriptor = None
            _remove_staging_directory(
                parent_descriptor,
                staging_name,
                expected_identity=staged_identity,
            )
            os.fsync(parent_descriptor)
        return loaded
    except Exception as exc:
        if staging_descriptor is not None:
            os.close(staging_descriptor)
            staging_descriptor = None
        rollback_error: Exception | None = None
        cleanup_error: Exception | None = None
        if published:
            try:
                if published_identity is None:
                    raise ValuationRunArchiveError(
                        "published valuation archive identity was not captured"
                    )
                _rollback_published_directory(
                    parent_descriptor,
                    target_name=target.name,
                    staging_name=staging_name,
                    published_identity=published_identity,
                    source_moved=source_moved,
                )
                published = False
            except Exception as rollback_exc:
                rollback_error = rollback_exc
        if staging_name in os.listdir(parent_descriptor):
            try:
                _remove_staging_directory(
                    parent_descriptor,
                    staging_name,
                    expected_identity=staged_identity,
                    allow_writable_owned=staged_identity is None,
                )
            except Exception as staging_cleanup_exc:
                cleanup_error = staging_cleanup_exc
        if rollback_error is not None:
            raise ValuationRunArchiveError(
                "valuation archive validation failed and atomic rollback was unavailable"
            ) from rollback_error
        if cleanup_error is not None:
            raise ValuationRunArchiveError(
                "valuation archive validation failed and staging cleanup was unavailable"
            ) from cleanup_error
        if isinstance(exc, ValuationRunArchiveError):
            raise
        raise ValuationRunArchiveError(
            f"valuation archive publication failed: {type(exc).__name__}"
        ) from exc
    finally:
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        os.close(parent_descriptor)


__all__ = (
    "VALUATION_RUN_ARCHIVE_FILENAMES",
    "VALUATION_RUN_ARCHIVE_MAX_BYTES",
    "VALUATION_RUN_MEMBER_MAX_BYTES",
    "ValuationRunArchive",
    "ValuationRunArchiveError",
    "load_valuation_run_archive",
    "write_valuation_run_archive",
)
