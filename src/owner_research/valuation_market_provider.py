"""Provider-neutral market-reference boundary for the Phase 5 v1 vertical slice.

The core package never fetches a quote.  A provider returns a reviewed, immutable
description of external evidence.  The release-candidate provider implemented here
reads a human-reviewed JSON receipt plus the referenced raw file and verifies both
before any market data can enter the valuation graph.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pwd
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal, Inexact, InvalidOperation, Rounded, localcontext
from pathlib import Path
from typing import Any, ClassVar, Literal, Protocol
from urllib.parse import urlsplit

from .component_lock import load_component_lock
from .fingerprints import canonical_json, canonical_sha256, to_json_value
from .validation import ContractGraph
from .valuation_market_access import (
    GovernedMarketQuoteReceipt,
    MarketAccessResult,
    MarketProviderQuery,
    _current_authorization,
    _graph_already_consumed,
)
from .valuation_market_authority import load_market_access_authority
from .valuation_market_calendar import MarketCalendarError, select_latest_completed_session
from .valuation_market_execution_policies import (
    MARKET_QUOTE_POLICY_ID,
    MARKET_QUOTE_POLICY_VERSION,
    phase5e_policy_sha256,
)
from .valuation_market_execution_types import MarketQuoteReceipt, MarketQuoteRequest
from .valuation_market_runtime import assert_secret_free_surface
from .valuation_price_blind_freeze import (
    PriceBlindFreezeCompilationResult,
    PriceBlindFreezeError,
    load_price_blind_input_artifact,
)
from .valuation_security_identity import (
    SecurityIdentityCompilationResult,
    compile_security_identity,
)

REVIEWED_FILE_PROVIDER_ID = "provider:human-reviewed-file"
REVIEWED_FILE_PROVIDER_VERSION = "1.0.0"
REVIEWED_FILE_PRICE_BASIS = "reviewed_unadjusted_regular_session_close"
REVIEWED_FILE_ENDPOINT_ID = "reviewed-file"
REVIEWED_FILE_CALENDAR_ID = "reviewed-session-receipt"
REVIEWED_FILE_AUTHORITY_KIND = "human_reviewed_file"
REVIEWED_FILE_USAGE_SCOPE = "release_candidate"
REVIEWED_FILE_REVIEWER = "human:mingji"
_DECIMAL_PATTERN = __import__("re").compile(
    r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$"
)
_MAX_REVIEW_RECEIPT_BYTES = 64 * 1024
_MAX_RAW_EVIDENCE_BYTES = 16 * 1024 * 1024
_REVIEWED_RAW_CONTENT_TYPES = frozenset(
    {
        "application/json",
        "application/octet-stream",
        "application/pdf",
        "text/csv",
        "text/plain",
    }
)
_AUTHORIZATION_STATE_BASE = (
    Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local" / "state" / "owner-research"
)


def _durable_flush(descriptor: int) -> None:
    """Fail closed on the strongest local durability primitive."""

    if sys.platform == "darwin":
        command = getattr(fcntl, "F_FULLFSYNC", None)
        if command is None:
            raise OSError("Darwin F_FULLFSYNC is unavailable")
        fcntl.fcntl(descriptor, command)
        return
    os.fsync(descriptor)


def _fd_extended_acl_text(descriptor: int) -> str | None:
    """Return a Darwin extended ACL in its stable text form, when present."""

    if sys.platform != "darwin":
        return None
    library = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = library.acl_get_fd_np
    acl_get_fd_np.argtypes = (ctypes.c_int, ctypes.c_int)
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_to_text = library.acl_to_text
    acl_to_text.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t))
    acl_to_text.restype = ctypes.c_void_p
    acl_free = library.acl_free
    acl_free.argtypes = (ctypes.c_void_p,)
    acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, 0x00000100)  # ACL_TYPE_EXTENDED
    if not acl:
        error = ctypes.get_errno()
        if error == errno.ENOENT:
            return None
        raise OSError(error, "extended ACL inspection failed")
    try:
        length = ctypes.c_ssize_t()
        text_pointer = acl_to_text(acl, ctypes.byref(length))
        if not text_pointer:
            error = ctypes.get_errno()
            raise OSError(error, "extended ACL serialization failed")
        try:
            return ctypes.string_at(text_pointer, length.value).decode("utf-8")
        finally:
            acl_free(text_pointer)
    finally:
        acl_free(acl)


def _fd_has_extended_acl(descriptor: int) -> bool:
    """Return whether a Darwin file descriptor carries an extended ACL."""

    return _fd_extended_acl_text(descriptor) is not None


def _reject_extended_acl(descriptor: int, label: str) -> None:
    try:
        has_acl = _fd_has_extended_acl(descriptor)
    except OSError as exc:
        raise ValueError(f"{label} ACL authority is unresolved") from exc
    if has_acl:
        raise ValueError(f"{label} cannot carry an extended ACL")


def _reject_write_granting_acl(descriptor: int, label: str) -> None:
    """Allow a trusted-anchor deny ACL but reject any access-granting entry."""

    try:
        acl_text = _fd_extended_acl_text(descriptor)
    except OSError as exc:
        raise ValueError(f"{label} ACL authority is unresolved") from exc
    if acl_text is None:
        return
    entries = tuple(
        line.strip()
        for line in acl_text.splitlines()
        if line.strip() and not line.startswith("!#acl")
    )
    if any(":allow:" in entry for entry in entries):
        raise ValueError(f"{label} ACL grants unsafe access")


def _private_authorization_directory(
    path: Path,
    *,
    create: bool,
) -> os.stat_result:
    """Descriptor-walk a private namespace and create missing user-owned nodes safely."""

    if any(component in {"", ".", ".."} for component in path.parts):
        raise ValueError("market-authorization store path is invalid")
    absolute = path.absolute()
    components = absolute.parts[1:]
    if (
        not absolute.is_absolute()
        or not components
        or any(component in {"", ".", ".."} for component in components)
    ):
        raise ValueError("market-authorization store path is invalid")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_descriptor = os.open(os.sep, flags)
    except OSError as exc:
        raise ValueError("market-authorization trusted anchor is unavailable") from exc
    current_uid = os.getuid()
    user_anchor_seen = False
    final_metadata: os.stat_result | None = None
    try:
        for index, component in enumerate(components):
            try:
                child_descriptor = os.open(component, flags, dir_fd=parent_descriptor)
            except FileNotFoundError:
                if not create or not user_anchor_seen:
                    raise ValueError("market-authorization store is unavailable") from None
                try:
                    os.mkdir(component, mode=0o700, dir_fd=parent_descriptor)
                    child_descriptor = os.open(component, flags, dir_fd=parent_descriptor)
                    os.fchmod(child_descriptor, 0o700)
                except OSError as exc:
                    raise ValueError(
                        "market-authorization store could not be created safely"
                    ) from exc
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(
                        "market-authorization store cannot contain a symlink"
                    ) from exc
                raise ValueError("market-authorization store is unavailable") from exc
            try:
                metadata = os.fstat(child_descriptor)
                if not stat.S_ISDIR(metadata.st_mode):
                    raise ValueError("market-authorization path is not a directory")
                writable_by_others = bool(metadata.st_mode & 0o022)
                root_owned_sticky_anchor = (
                    metadata.st_uid == 0
                    and bool(metadata.st_mode & stat.S_ISVTX)
                )
                if writable_by_others and not root_owned_sticky_anchor:
                    raise ValueError(
                        "market-authorization store ancestor is group/other writable"
                    )
                if user_anchor_seen:
                    if metadata.st_uid != current_uid:
                        raise ValueError(
                            "market-authorization private chain changed ownership"
                        )
                    _reject_extended_acl(
                        child_descriptor,
                        "market-authorization private directory",
                    )
                elif metadata.st_uid == current_uid:
                    user_anchor_seen = True
                    _reject_write_granting_acl(
                        child_descriptor,
                        "market-authorization trusted anchor",
                    )
                elif metadata.st_uid == 0:
                    _reject_write_granting_acl(
                        child_descriptor,
                        "market-authorization root-owned ancestor",
                    )
                else:
                    raise ValueError("market-authorization path has an untrusted owner")
                if create and user_anchor_seen:
                    try:
                        _durable_flush(child_descriptor)
                        _durable_flush(parent_descriptor)
                    except OSError as exc:
                        raise ValueError(
                            "market-authorization directory creation is not durable"
                        ) from exc
                if index == len(components) - 1:
                    final_metadata = metadata
            finally:
                os.close(parent_descriptor)
                parent_descriptor = child_descriptor
        if not user_anchor_seen or final_metadata is None:
            raise ValueError("market-authorization store lacks a trusted user anchor")
        return final_metadata
    finally:
        os.close(parent_descriptor)


def _timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include an offset")
    return parsed.astimezone(UTC)


def _timestamp_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("clock readings must include an offset")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _canonical_utc_timestamp(value: str, label: str) -> datetime:
    parsed = _timestamp(value, label)
    if value != _timestamp_text(parsed):
        raise ValueError(f"{label} must be canonical UTC with a Z suffix")
    return parsed


def _decimal(value: str, label: str) -> Decimal:
    if not isinstance(value, str) or not _DECIMAL_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be a canonical decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ValueError(f"{label} must be finite and positive")
    return parsed


def exact_decimal_product(left: str, right: str) -> Decimal:
    """Multiply finite canonical decimal strings without ambient-context rounding."""

    left_value = _decimal(left, "left operand")
    right_value = _decimal(right, "right operand")
    precision = len(left_value.as_tuple().digits) + len(right_value.as_tuple().digits) + 2
    with localcontext() as context:
        context.prec = max(precision, 32)
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        return left_value * right_value


def _sha(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _read_regular_file(path: Path, *, label: str, maximum_bytes: int) -> bytes:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    components = path.parts
    if not components:
        raise ValueError(f"{label} is unreadable")
    if path.is_absolute():
        anchor = os.sep
        components = components[1:]
    else:
        anchor = "."
    if not components or any(component in {"", ".", ".."} for component in components):
        raise ValueError(f"{label} must have a symlink-free canonical path")
    try:
        parent_descriptor = os.open(anchor, directory_flags)
    except OSError as exc:
        raise ValueError(f"{label} is unreadable") from exc
    descriptor: int | None = None
    try:
        for component in components[:-1]:
            try:
                child_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=parent_descriptor,
                )
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(
                        f"{label} path cannot contain a symlink"
                    ) from exc
                raise ValueError(f"{label} is unreadable") from exc
            os.close(parent_descriptor)
            parent_descriptor = child_descriptor
        try:
            descriptor = os.open(
                components[-1],
                file_flags,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ValueError(f"{label} must be a regular non-symlink file") from exc
            raise ValueError(f"{label} is unreadable") from exc
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a regular non-symlink file")
        if (
            metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o022
            or metadata.st_nlink != 1
        ):
            raise ValueError(
                f"{label} must be account-owned, singly linked, and not group/other writable"
            )
        _reject_extended_acl(descriptor, label)
        if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
            raise ValueError(f"{label} size is outside the governed limit")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size or len(payload) > maximum_bytes:
            raise ValueError(f"{label} changed while it was being read")
        return payload
    except OSError as exc:
        raise ValueError(f"{label} is unreadable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _read_json_object(raw: bytes) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"reviewed market receipt repeats field {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("reviewed market receipt is unreadable") from exc
    if not isinstance(payload, dict):
        raise ValueError("reviewed market receipt must be a JSON object")
    return payload


@dataclass(frozen=True, slots=True)
class RunClock:
    """Deterministic two-reading clock owned by the caller, not the provider."""

    request_started_at: str
    retrieved_at: str

    def __post_init__(self) -> None:
        started = _timestamp(self.request_started_at, "request start")
        retrieved = _timestamp(self.retrieved_at, "retrieval time")
        if retrieved < started:
            raise ValueError("retrieval time precedes request start")


@dataclass(frozen=True, slots=True)
class MarketReferenceRequest:
    authorization_handoff_id: str
    authorization_handoff_fingerprint: str
    authorization_transitioned_at: str
    price_blind_input_fingerprint: str
    issuer_id: str
    data_cutoff_date: str
    security_id: str
    ticker: str
    mic: str
    share_class: str
    quote_currency: str
    expected_trading_date: str
    request_started_at: str
    request_fingerprint: str

    def __post_init__(self) -> None:
        date.fromisoformat(self.data_cutoff_date)
        date.fromisoformat(self.expected_trading_date)
        _sha(self.authorization_handoff_fingerprint, "authorization Handoff fingerprint")
        _sha(self.price_blind_input_fingerprint, "price-blind input fingerprint")
        if _timestamp(self.request_started_at, "request start") < _timestamp(
            self.authorization_transitioned_at,
            "authorization transition",
        ):
            raise ValueError("market request precedes price-blind authorization")
        if self.request_fingerprint != self.expected_fingerprint():
            raise ValueError("market-reference request fingerprint mismatch")

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("request_fingerprint")
        return payload

    def expected_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())


@dataclass(frozen=True, slots=True)
class RawMarketQuote:
    provider_id: str
    provider_version: str
    authority_kind: Literal["human_reviewed_file", "governed_vendor"]
    issuer_id: str
    security_id: str
    ticker: str
    mic: str
    share_class: str
    trading_date: str
    quote_timestamp: str
    close_decimal: str
    currency: str
    price_basis: str
    session_kind: str
    source_url: str
    source_locator: str
    source_published_date: str
    source_retrieved_at: str
    raw_evidence_sha256: str
    raw_content_type: str
    reviewer_id: str
    reviewed_at: str
    authorization_handoff_id: str
    authorization_handoff_fingerprint: str
    price_blind_input_fingerprint: str
    review_statement: str
    review_receipt_sha256: str

    def __post_init__(self) -> None:
        date.fromisoformat(self.trading_date)
        date.fromisoformat(self.source_published_date)
        _canonical_utc_timestamp(self.quote_timestamp, "quote timestamp")
        _canonical_utc_timestamp(self.source_retrieved_at, "source retrieval time")
        _canonical_utc_timestamp(self.reviewed_at, "review time")
        _decimal(self.close_decimal, "reviewed close")
        _sha(self.raw_evidence_sha256, "raw evidence SHA")
        _sha(self.review_receipt_sha256, "review receipt SHA")
        _sha(self.authorization_handoff_fingerprint, "authorization Handoff fingerprint")
        _sha(self.price_blind_input_fingerprint, "price-blind input fingerprint")
        if (
            type(self.raw_content_type) is not str
            or self.raw_content_type not in _REVIEWED_RAW_CONTENT_TYPES
        ):
            raise ValueError("reviewed raw content type is not registered")
        if self.price_basis != REVIEWED_FILE_PRICE_BASIS:
            raise ValueError("reviewed receipt is not an unadjusted regular-session close")
        if self.session_kind != "regular" or self.reviewer_id != REVIEWED_FILE_REVIEWER:
            raise ValueError("reviewed receipt lacks the named-human regular-session review")
        parsed_source = urlsplit(self.source_url)
        if (
            parsed_source.scheme != "https"
            or not parsed_source.netloc
            or parsed_source.username is not None
            or parsed_source.password is not None
            or parsed_source.query
            or parsed_source.fragment
        ):
            raise ValueError("reviewed market source must be a credential-free HTTPS URL")
        if not self.source_locator.strip():
            raise ValueError("reviewed market source locator is required")
        if self.review_statement != "human_verified_source_date_security_close_and_currency":
            raise ValueError("reviewed market receipt lacks its fixed review statement")
        assert_secret_free_surface(self.to_dict(), "reviewed market quote")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class MarketAuthorizationReservation:
    """Provider-call preflight reservation keyed only by the Handoff identity."""

    schema_version: str
    reservation_id: str
    authorization_handoff_id: str
    authorization_handoff_fingerprint: str
    price_blind_input_fingerprint: str
    request_fingerprint: str
    issuer_id: str
    security_id: str
    reserved_at: str
    store_authority_sha256: str
    store_instance_sha256: str

    def __post_init__(self) -> None:
        if self.schema_version != "1.0.0":
            raise ValueError("market-authorization reservation version is unsupported")
        expected_identity = canonical_sha256(
            {
                "authorization_handoff_id": self.authorization_handoff_id,
                "authorization_handoff_fingerprint": (
                    self.authorization_handoff_fingerprint
                ),
            }
        )
        if self.reservation_id != (
            f"market-authorization-reservation:{expected_identity[:24]}"
        ):
            raise ValueError("market-authorization reservation identity is invalid")
        for value, label in (
            (self.authorization_handoff_fingerprint, "authorization Handoff fingerprint"),
            (self.price_blind_input_fingerprint, "price-blind input fingerprint"),
            (self.request_fingerprint, "market-reference request fingerprint"),
            (self.store_authority_sha256, "authorization store authority SHA"),
            (self.store_instance_sha256, "authorization store instance SHA"),
        ):
            _sha(value, label)
        _timestamp(self.reserved_at, "market-authorization reservation time")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class MarketAuthorizationConsumption:
    """Durable, one-use witness for one price-blind market authorization."""

    schema_version: str
    consumption_id: str
    authorization_handoff_id: str
    authorization_handoff_fingerprint: str
    price_blind_input_fingerprint: str
    request_fingerprint: str
    market_access_result_fingerprint: str
    quote_fingerprint: str
    review_receipt_sha256: str
    raw_response_sha256: str
    consumed_at: str
    reservation_fingerprint: str
    store_authority_sha256: str
    store_instance_sha256: str

    def __post_init__(self) -> None:
        if self.schema_version != "1.0.0":
            raise ValueError("market-authorization consumption version is unsupported")
        expected_identity = canonical_sha256(
            {
                "handoff": self.authorization_handoff_id,
                "request": self.request_fingerprint,
            }
        )
        if self.consumption_id != (
            f"market-authorization-consumption:{expected_identity[:24]}"
        ):
            raise ValueError("market-authorization consumption identity is invalid")
        for value, label in (
            (self.authorization_handoff_fingerprint, "authorization Handoff fingerprint"),
            (self.price_blind_input_fingerprint, "price-blind input fingerprint"),
            (self.request_fingerprint, "market-reference request fingerprint"),
            (self.market_access_result_fingerprint, "market-access result fingerprint"),
            (self.quote_fingerprint, "reviewed quote fingerprint"),
            (self.review_receipt_sha256, "review receipt SHA"),
            (self.raw_response_sha256, "raw response SHA"),
            (self.reservation_fingerprint, "market-authorization reservation fingerprint"),
            (self.store_authority_sha256, "authorization store authority SHA"),
            (self.store_instance_sha256, "authorization store instance SHA"),
        ):
            _sha(value, label)
        _timestamp(self.consumed_at, "market-authorization consumption time")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


class MarketReferenceProvider(Protocol):
    provider_id: str
    authority_kind: Literal["human_reviewed_file", "governed_vendor"]

    def acquire(self, request: MarketReferenceRequest) -> RawMarketQuote: ...


@dataclass(frozen=True, slots=True)
class ReviewedFileMarketProvider:
    """Read a named-human receipt and verify its external raw evidence by content hash."""

    review_file: Path
    raw_evidence_file: Path
    provider_id: ClassVar[str] = REVIEWED_FILE_PROVIDER_ID
    authority_kind: ClassVar[Literal["human_reviewed_file"]] = REVIEWED_FILE_AUTHORITY_KIND

    def acquire(self, request: MarketReferenceRequest) -> RawMarketQuote:
        review_bytes = _read_regular_file(
            self.review_file,
            label="reviewed market receipt",
            maximum_bytes=_MAX_REVIEW_RECEIPT_BYTES,
        )
        payload = _read_json_object(review_bytes)
        allowed = {
            "schema_version",
            "issuer_id",
            "security_id",
            "ticker",
            "mic",
            "share_class",
            "trading_date",
            "quote_timestamp",
            "close_decimal",
            "currency",
            "price_basis",
            "session_kind",
            "source_url",
            "source_locator",
            "source_published_date",
            "source_retrieved_at",
            "raw_evidence_sha256",
            "raw_content_type",
            "reviewer_id",
            "reviewed_at",
            "authorization_handoff_id",
            "authorization_handoff_fingerprint",
            "price_blind_input_fingerprint",
            "review_statement",
        }
        if set(payload) != allowed or payload.get("schema_version") != "1.0.0":
            raise ValueError("reviewed market receipt has an unknown or missing field")
        raw_bytes = _read_regular_file(
            self.raw_evidence_file,
            label="raw market evidence",
            maximum_bytes=_MAX_RAW_EVIDENCE_BYTES,
        )
        raw_sha = hashlib.sha256(raw_bytes).hexdigest()
        if raw_sha != payload["raw_evidence_sha256"]:
            raise ValueError("reviewed market raw evidence SHA mismatch")
        expected = {
            "issuer_id": request.issuer_id,
            "security_id": request.security_id,
            "ticker": request.ticker,
            "mic": request.mic,
            "share_class": request.share_class,
            "trading_date": request.expected_trading_date,
            "currency": request.quote_currency,
            "authorization_handoff_id": request.authorization_handoff_id,
            "authorization_handoff_fingerprint": request.authorization_handoff_fingerprint,
            "price_blind_input_fingerprint": request.price_blind_input_fingerprint,
        }
        if any(payload[name] != value for name, value in expected.items()):
            raise ValueError("reviewed market receipt does not match the authorized security")
        assert_secret_free_surface(payload, "reviewed market receipt")
        review_sha = hashlib.sha256(review_bytes).hexdigest()
        quote = RawMarketQuote(
            provider_id=self.provider_id,
            provider_version=REVIEWED_FILE_PROVIDER_VERSION,
            authority_kind=self.authority_kind,
            review_receipt_sha256=review_sha,
            **{key: payload[key] for key in allowed if key != "schema_version"},
        )
        if quote.raw_evidence_sha256 != raw_sha:
            raise ValueError("reviewed market evidence changed during acquisition")
        return quote


@dataclass(frozen=True, slots=True)
class MarketReferenceAcquisition:
    access_result: MarketAccessResult
    request: MarketReferenceRequest
    quote: RawMarketQuote
    authorization_reservation: MarketAuthorizationReservation
    authorization_consumption: MarketAuthorizationConsumption
    review_file: Path
    raw_evidence_file: Path

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(
            {
                "access_result": self.access_result,
                "request": self.request,
                "quote": self.quote,
                "authorization_reservation": self.authorization_reservation,
                "authorization_consumption": self.authorization_consumption,
            }
        )


def _authorization_store_policy(component_lock_path: Path) -> tuple[str, str]:
    lock = load_component_lock(component_lock_path)
    authority = lock.get("market_access_authority")
    store = authority.get("authorization_consumption_store") if isinstance(
        authority,
        dict,
    ) else None
    expected_keys = {
        "code_sha256",
        "key_policy",
        "module_path",
        "namespace",
        "policy_id",
        "policy_version",
        "root_policy",
    }
    module_path = Path(__file__).resolve()
    if (
        not isinstance(store, dict)
        or set(store) != expected_keys
        or store["policy_id"] != "handoff-global-filesystem-reservation"
        or store["policy_version"] != "1.0.0"
        or store["key_policy"] != "authorization_handoff_id_and_fingerprint"
        or store["namespace"] != "market-authorizations-v1"
        or store["root_policy"] != "module_import_user_state_home"
        or store["module_path"] != module_path.name
        or store["code_sha256"] != hashlib.sha256(module_path.read_bytes()).hexdigest()
    ):
        raise ValueError("market-authorization store authority drifted")
    return store["namespace"], canonical_sha256(store)


def _authorization_store_root(
    component_lock_path: Path,
    *,
    create: bool,
) -> tuple[Path, str, str]:
    namespace, authority_sha256 = _authorization_store_policy(component_lock_path)
    base = _AUTHORIZATION_STATE_BASE.absolute()
    root = base / namespace
    metadata = _private_authorization_directory(root, create=create)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError("market-authorization store is not private")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(root, directory_flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise ValueError("market-authorization store identity changed")
            _reject_extended_acl(descriptor, "market-authorization store")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ValueError("market-authorization store is unavailable") from exc
    store_instance_sha256 = canonical_sha256(
        {
            "store_authority_sha256": authority_sha256,
            "root": str(root),
            "uid": os.getuid(),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        }
    )
    return root, authority_sha256, store_instance_sha256


def _authorization_record_paths(
    component_lock_path: Path,
    *,
    authorization_handoff_id: str,
    authorization_handoff_fingerprint: str,
    create_store: bool,
) -> tuple[Path, Path, Path, str, str]:
    root, authority_sha256, store_instance_sha256 = _authorization_store_root(
        component_lock_path,
        create=create_store,
    )
    identity = canonical_sha256(
        {
            "authorization_handoff_id": authorization_handoff_id,
            "authorization_handoff_fingerprint": authorization_handoff_fingerprint,
        }
    )
    stem = f"market-authorization-{identity}"
    authorization_directory = root / stem
    return (
        authorization_directory,
        authorization_directory / "reservation.json",
        authorization_directory / "consumption.json",
        authority_sha256,
        store_instance_sha256,
    )


def _write_new_authorization_record(
    path: Path,
    payload_value: dict[str, Any],
    *,
    exists_message: str,
) -> None:
    payload = (canonical_json(payload_value) + "\n").encode("utf-8")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ValueError(exists_message) from exc
    except OSError as exc:
        raise ValueError("market-authorization consumption store is unavailable") from exc
    try:
        _reject_extended_acl(descriptor, "market-authorization record")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("market-authorization consumption write made no progress")
            offset += written
        os.fchmod(descriptor, 0o400)
        _reject_extended_acl(descriptor, "market-authorization record")
        _durable_flush(descriptor)
    except OSError as exc:
        raise ValueError("market-authorization consumption could not be recorded") from exc
    finally:
        os.close(descriptor)
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o400
        ):
            raise ValueError("market-authorization record is not a private regular file")
        parent_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            _durable_flush(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as exc:
        raise ValueError("market-authorization consumption could not be sealed") from exc


def _reserve_market_authorization(
    component_lock_path: Path,
    reservation: MarketAuthorizationReservation,
) -> None:
    (
        authorization_directory,
        reservation_path,
        _,
        authority_sha256,
        store_instance_sha256,
    ) = _authorization_record_paths(
        component_lock_path,
        authorization_handoff_id=reservation.authorization_handoff_id,
        authorization_handoff_fingerprint=reservation.authorization_handoff_fingerprint,
        create_store=True,
    )
    try:
        authorization_directory.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ValueError("market authorization was already reserved or consumed") from exc
    except OSError as exc:
        raise ValueError("market-authorization reservation directory is unavailable") from exc
    directory_descriptor = os.open(
        authorization_directory,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        parent_descriptor = os.open(
            authorization_directory.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        os.close(directory_descriptor)
        raise ValueError(
            "market-authorization reservation parent is unavailable"
        ) from exc
    try:
        metadata = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ValueError("market-authorization reservation directory is not private")
        _reject_extended_acl(
            directory_descriptor,
            "market-authorization reservation directory",
        )
        try:
            _durable_flush(directory_descriptor)
            _durable_flush(parent_descriptor)
        except OSError as exc:
            raise ValueError(
                "market-authorization reservation directory is not durable"
            ) from exc
    finally:
        os.close(parent_descriptor)
        os.close(directory_descriptor)
    if (
        reservation.store_authority_sha256 != authority_sha256
        or reservation.store_instance_sha256 != store_instance_sha256
    ):
        raise ValueError("market-authorization reservation store authority mismatch")
    _write_new_authorization_record(
        reservation_path,
        reservation.to_dict(),
        exists_message="market authorization was already reserved or consumed",
    )


def _complete_market_authorization(
    component_lock_path: Path,
    reservation: MarketAuthorizationReservation,
    consumption: MarketAuthorizationConsumption,
) -> None:
    (
        authorization_directory,
        reservation_path,
        consumption_path,
        authority_sha256,
        store_instance_sha256,
    ) = _authorization_record_paths(
        component_lock_path,
        authorization_handoff_id=consumption.authorization_handoff_id,
        authorization_handoff_fingerprint=consumption.authorization_handoff_fingerprint,
        create_store=False,
    )
    _verify_authorization_record(
        reservation_path,
        reservation.to_dict(),
        label="market-authorization reservation",
    )
    if (
        consumption.reservation_fingerprint != reservation.fingerprint
        or consumption.store_authority_sha256 != authority_sha256
        or consumption.store_instance_sha256 != store_instance_sha256
    ):
        raise ValueError("market-authorization completion binding changed")
    _write_new_authorization_record(
        consumption_path,
        consumption.to_dict(),
        exists_message="market authorization was already consumed",
    )
    try:
        os.chmod(authorization_directory, 0o500)
        directory_descriptor = os.open(authorization_directory, os.O_RDONLY)
        try:
            _reject_extended_acl(
                directory_descriptor,
                "market-authorization directory",
            )
            _durable_flush(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        raise ValueError("market-authorization directory could not be sealed") from exc


def _verify_authorization_record(
    path: Path,
    expected_value: dict[str, Any],
    *,
    label: str,
) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o400
    ):
        raise ValueError(f"{label} is not a private regular file")
    actual = _read_regular_file(
        path,
        label=label,
        maximum_bytes=16 * 1024,
    )
    expected = (canonical_json(expected_value) + "\n").encode("utf-8")
    if actual != expected:
        raise ValueError(f"{label} does not replay")


def _verify_authorization_consumption(
    component_lock_path: Path,
    reservation: MarketAuthorizationReservation,
    consumption: MarketAuthorizationConsumption,
) -> None:
    (
        authorization_directory,
        reservation_path,
        consumption_path,
        authority_sha256,
        store_instance_sha256,
    ) = _authorization_record_paths(
        component_lock_path,
        authorization_handoff_id=consumption.authorization_handoff_id,
        authorization_handoff_fingerprint=consumption.authorization_handoff_fingerprint,
        create_store=False,
    )
    try:
        directory_metadata = authorization_directory.lstat()
    except OSError as exc:
        raise ValueError("market-authorization store authority does not replay") from exc
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or directory_metadata.st_uid != os.getuid()
        or stat.S_IMODE(directory_metadata.st_mode) != 0o500
        or reservation.store_authority_sha256 != authority_sha256
        or reservation.store_instance_sha256 != store_instance_sha256
        or consumption.store_authority_sha256 != authority_sha256
        or consumption.store_instance_sha256 != store_instance_sha256
        or consumption.reservation_fingerprint != reservation.fingerprint
    ):
        raise ValueError("market-authorization store authority does not replay")
    directory_descriptor = os.open(
        authorization_directory,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        _reject_extended_acl(directory_descriptor, "market-authorization directory")
    finally:
        os.close(directory_descriptor)
    _verify_authorization_record(
        reservation_path,
        reservation.to_dict(),
        label="market-authorization reservation",
    )
    _verify_authorization_record(
        consumption_path,
        consumption.to_dict(),
        label="market-authorization consumption",
    )


def reviewed_file_authority_hashes(
    component_lock_path: Path,
    *,
    calendar_dataset_sha256: str,
) -> dict[str, str]:
    """Load the reviewed-file registration from the immutable component lock."""

    lock = load_component_lock(component_lock_path)
    authority = lock.get("market_access_authority")
    if not isinstance(authority, dict):
        raise ValueError("component lock lacks market-access authority")
    registration = authority.get("reviewed_file_provider")
    expected_keys = {
        "adapter_sha256",
        "authority_kind",
        "endpoint_id",
        "module_path",
        "parser_sha256",
        "price_basis",
        "provider_id",
        "provider_version",
    }
    if not isinstance(registration, dict) or set(registration) != expected_keys:
        raise ValueError("component lock lacks the reviewed-file provider registration")
    module_path = Path(__file__).resolve()
    if (
        registration["provider_id"] != REVIEWED_FILE_PROVIDER_ID
        or registration["provider_version"] != REVIEWED_FILE_PROVIDER_VERSION
        or registration["authority_kind"] != REVIEWED_FILE_AUTHORITY_KIND
        or registration["endpoint_id"] != REVIEWED_FILE_ENDPOINT_ID
        or registration["price_basis"] != REVIEWED_FILE_PRICE_BASIS
        or registration["module_path"] != module_path.name
        or registration["adapter_sha256"] != hashlib.sha256(module_path.read_bytes()).hexdigest()
        or registration["parser_sha256"] != registration["adapter_sha256"]
    ):
        raise ValueError("reviewed-file provider registration drifted")
    _sha(calendar_dataset_sha256, "calendar dataset SHA")
    provider_registration_sha256 = canonical_sha256(registration)
    provider_registry_sha256 = canonical_sha256(
        {
            "locked_registry_sha256": authority["provider_registry"]["sha256"],
            "release_candidate_registration_sha256": provider_registration_sha256,
        }
    )
    calendar_registry_sha256 = authority["calendar_registry"]["sha256"]
    authority_sha256 = canonical_sha256(
        {
            "component_lock_authority": authority,
            "provider_registry_sha256": provider_registry_sha256,
            "calendar_registry_sha256": calendar_registry_sha256,
        }
    )
    return {
        "authority_sha256": authority_sha256,
        "provider_registry_sha256": provider_registry_sha256,
        "provider_registration_sha256": provider_registration_sha256,
        "adapter_sha256": registration["adapter_sha256"],
        "parser_sha256": registration["parser_sha256"],
        "calendar_registry_sha256": calendar_registry_sha256,
        "calendar_dataset_sha256": calendar_dataset_sha256,
    }


def acquire_reviewed_market_reference(
    *,
    price_blind_artifact_directory: Path,
    graph: ContractGraph,
    expected_freeze: PriceBlindFreezeCompilationResult,
    expected_security: SecurityIdentityCompilationResult,
    provider: ReviewedFileMarketProvider,
    clock: RunClock,
) -> MarketReferenceAcquisition:
    """Acquire one reviewed quote after the price-blind Handoff authorizes market access."""

    if (
        type(provider) is not ReviewedFileMarketProvider
        or getattr(provider.acquire, "__func__", None) is not ReviewedFileMarketProvider.acquire
    ):
        raise ValueError("reviewed-file provider implementation is not component-owned")
    if _graph_already_consumed(graph, expected_freeze):
        raise ValueError("market authorization was already consumed")
    try:
        loaded = load_price_blind_input_artifact(
            price_blind_artifact_directory,
            graph=graph,
            expected_result=expected_freeze,
        )
    except (PriceBlindFreezeError, ValueError) as exc:
        raise ValueError("price-blind artifact replay failed") from exc
    authorization = loaded.handoffs[-1]
    if authorization.state != "market_reference_allowed" or not _current_authorization(
        graph, loaded
    ):
        raise ValueError("market authorization is not current")
    artifact = loaded.artifact.to_dict()
    if artifact["component_lock_sha256"] != hashlib.sha256(
        graph.component_lock_path.read_bytes()
    ).hexdigest():
        raise ValueError("price-blind component lock drifted")
    replayed_security = compile_security_identity(
        graph=graph,
        expected_freeze=loaded,
        proposal=expected_security.proposal,
    )
    if replayed_security.fingerprint != expected_security.fingerprint:
        raise ValueError("security identity replay mismatch")
    security = replayed_security.decision
    closure = replayed_security.evidence_closure
    if replayed_security.status != "eligible" or security is None or closure is None:
        raise ValueError("security identity is not valuation eligible")
    if security.issuer_id != artifact["issuer_id"]:
        raise ValueError("security identity does not match the price-blind issuer")
    try:
        authority = load_market_access_authority(graph.component_lock_path)
        selection = select_latest_completed_session(
            authority,
            mic=security.exchange,
            cutoff_date=date.fromisoformat(authorization.data_cutoff_date),
            observed_at=_timestamp(clock.request_started_at, "request start"),
        )
    except (MarketCalendarError, OSError, TypeError, ValueError) as exc:
        raise ValueError("market calendar authority is unresolved") from exc
    request_payload = {
        "authorization_handoff_id": authorization.handoff_id,
        "authorization_handoff_fingerprint": authorization.fingerprint,
        "authorization_transitioned_at": authorization.transitioned_at,
        "price_blind_input_fingerprint": artifact["price_blind_input_fingerprint"],
        "issuer_id": security.issuer_id,
        "data_cutoff_date": artifact["data_cutoff_date"],
        "security_id": security.security_id,
        "ticker": security.ticker,
        "mic": security.exchange,
        "share_class": security.share_class,
        "quote_currency": security.quote_currency,
        "expected_trading_date": selection.session.trading_date,
        "request_started_at": clock.request_started_at,
    }
    request = MarketReferenceRequest(
        **request_payload,
        request_fingerprint=canonical_sha256(request_payload),
    )
    _, store_authority_sha256, store_instance_sha256 = _authorization_store_root(
        graph.component_lock_path,
        create=True,
    )
    reservation_identity = canonical_sha256(
        {
            "authorization_handoff_id": authorization.handoff_id,
            "authorization_handoff_fingerprint": authorization.fingerprint,
        }
    )
    reservation = MarketAuthorizationReservation(
        schema_version="1.0.0",
        reservation_id=f"market-authorization-reservation:{reservation_identity[:24]}",
        authorization_handoff_id=authorization.handoff_id,
        authorization_handoff_fingerprint=authorization.fingerprint,
        price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
        request_fingerprint=request.request_fingerprint,
        issuer_id=security.issuer_id,
        security_id=security.security_id,
        reserved_at=clock.request_started_at,
        store_authority_sha256=store_authority_sha256,
        store_instance_sha256=store_instance_sha256,
    )
    _reserve_market_authorization(graph.component_lock_path, reservation)
    try:
        quote = provider.acquire(request)
    except Exception as exc:
        raise ValueError(f"reviewed market provider call failed: {exc}") from exc
    expected_quote_identity = {
        "provider_id": REVIEWED_FILE_PROVIDER_ID,
        "provider_version": REVIEWED_FILE_PROVIDER_VERSION,
        "authority_kind": REVIEWED_FILE_AUTHORITY_KIND,
        "issuer_id": request.issuer_id,
        "security_id": request.security_id,
        "ticker": request.ticker,
        "mic": request.mic,
        "share_class": request.share_class,
        "currency": request.quote_currency,
        "authorization_handoff_id": request.authorization_handoff_id,
        "authorization_handoff_fingerprint": request.authorization_handoff_fingerprint,
        "price_blind_input_fingerprint": request.price_blind_input_fingerprint,
    }
    if any(getattr(quote, field) != value for field, value in expected_quote_identity.items()):
        raise ValueError("reviewed market provider returned an unauthorized quote identity")
    retrieved = _timestamp(clock.retrieved_at, "retrieval time")
    authorization_time = _timestamp(authorization.transitioned_at, "authorization transition")
    source_retrieved = _timestamp(quote.source_retrieved_at, "source retrieval time")
    reviewed = _timestamp(quote.reviewed_at, "review time")
    started = _timestamp(clock.request_started_at, "request start")
    quote_time = _timestamp(quote.quote_timestamp, "quote timestamp")
    session_close = _timestamp(selection.session.closed_at, "session close")
    trading_date = date.fromisoformat(quote.trading_date)
    published_date = date.fromisoformat(quote.source_published_date)
    data_cutoff_date = date.fromisoformat(str(artifact["data_cutoff_date"]))
    if not (
        authorization_time <= source_retrieved <= reviewed <= started <= retrieved
        and quote.trading_date == selection.session.trading_date
        and quote_time == session_close
        and quote_time <= source_retrieved
        and trading_date <= published_date <= data_cutoff_date
        and published_date <= source_retrieved.date()
    ):
        raise ValueError("reviewed quote chronology or completed-session identity is invalid")
    hashes = reviewed_file_authority_hashes(
        graph.component_lock_path,
        calendar_dataset_sha256=selection.dataset_sha256,
    )
    query = MarketProviderQuery(
        authorization_handoff_id=authorization.handoff_id,
        issuer_id=security.issuer_id,
        data_cutoff_date=artifact["data_cutoff_date"],
        security_id=security.security_id,
        ticker=security.ticker,
        exchange=security.exchange,
        share_class=security.share_class,
        quote_currency=security.quote_currency,
        reporting_currency=security.reporting_currency,
        trading_calendar_id=selection.calendar_id,
        expected_trading_date=quote.trading_date,
        price_basis=REVIEWED_FILE_PRICE_BASIS,
        session_kind="regular",
    )
    low_request_payload = {
        "request_id": f"market-quote-request:{request.request_fingerprint[:24]}",
        "policy_id": MARKET_QUOTE_POLICY_ID,
        "policy_version": MARKET_QUOTE_POLICY_VERSION,
        "policy_sha256": phase5e_policy_sha256(),
        "authorization_handoff_id": authorization.handoff_id,
        "authorization_transitioned_at": authorization.transitioned_at,
        "issuer_id": security.issuer_id,
        "data_cutoff_date": artifact["data_cutoff_date"],
        "security_id": security.security_id,
        "ticker": security.ticker,
        "exchange": security.exchange,
        "share_class": security.share_class,
        "quote_currency": security.quote_currency,
        "reporting_currency": security.reporting_currency,
        "price_basis": REVIEWED_FILE_PRICE_BASIS,
        "session_kind": "regular",
        "provider_id": REVIEWED_FILE_PROVIDER_ID,
        "provider_version": REVIEWED_FILE_PROVIDER_VERSION,
        "provider_registration_sha256": hashes["provider_registration_sha256"],
        "endpoint": REVIEWED_FILE_ENDPOINT_ID,
        "trading_calendar_id": selection.calendar_id,
        "request_started_at": clock.request_started_at,
    }
    low_request = MarketQuoteRequest(
        **low_request_payload,
        request_fingerprint=canonical_sha256(low_request_payload),
    )
    receipt = MarketQuoteReceipt(
        receipt_id=f"market-quote-receipt:{quote.review_receipt_sha256[:24]}",
        request_id=low_request.request_id,
        request_fingerprint=low_request.request_fingerprint,
        authorization_handoff_id=authorization.handoff_id,
        authorization_transitioned_at=authorization.transitioned_at,
        issuer_id=security.issuer_id,
        data_cutoff_date=artifact["data_cutoff_date"],
        security_id=security.security_id,
        ticker=security.ticker,
        exchange=security.exchange,
        share_class=security.share_class,
        provider_id=REVIEWED_FILE_PROVIDER_ID,
        provider_version=REVIEWED_FILE_PROVIDER_VERSION,
        endpoint=REVIEWED_FILE_ENDPOINT_ID,
        trading_calendar_id=selection.calendar_id,
        request_started_at=clock.request_started_at,
        retrieved_at=clock.retrieved_at,
        trading_date=quote.trading_date,
        latest_completed_session_date=selection.session.trading_date,
        quote_timestamp=quote.quote_timestamp,
        session_kind="regular",
        session_status="completed",
        instrument_status="active",
        price_basis=REVIEWED_FILE_PRICE_BASIS,
        quote_price=quote.close_decimal,
        quote_currency=quote.currency,
        raw_response_sha256=quote.raw_evidence_sha256,
    )
    governed = GovernedMarketQuoteReceipt(
        receipt=receipt,
        **hashes,
        calendar_selection_fingerprint=canonical_sha256(
            {
                "calendar_id": selection.calendar_id,
                "trading_date": quote.trading_date,
                "dataset_sha256": selection.dataset_sha256,
                "review_receipt_sha256": quote.review_receipt_sha256,
            }
        ),
        security_compilation_fingerprint=replayed_security.fingerprint,
        security_evidence_closure_sha256=closure.closure_sha256,
        raw_response_sha256=quote.raw_evidence_sha256,
        evidence_mode="human_reviewed_file",
    )
    access = MarketAccessResult(
        status="eligible",
        issuer_id=artifact["issuer_id"],
        data_cutoff_date=artifact["data_cutoff_date"],
        authorization_handoff_id=authorization.handoff_id,
        price_blind_input_fingerprint=artifact["price_blind_input_fingerprint"],
        protected_mckinsey_sha256=artifact["protected_mckinsey_sha256"],
        protected_penman_assumptions_sha256=artifact[
            "protected_penman_assumptions_sha256"
        ],
        provider_call_count=1,
        query=query,
        request=low_request,
        receipt=governed,
        quarantined_raw_response_sha256=None,
        issue_codes=(),
    )
    assert_secret_free_surface(to_json_value(request), "reviewed market request")
    assert_secret_free_surface(governed.to_dict(), "governed market receipt")
    assert_secret_free_surface(access.to_dict(), "reviewed market access result")
    consumption_identity = canonical_sha256(
        {
            "handoff": authorization.handoff_id,
            "request": request.request_fingerprint,
        }
    )
    consumption_payload = {
        "schema_version": "1.0.0",
        "consumption_id": (
            f"market-authorization-consumption:{consumption_identity[:24]}"
        ),
        "authorization_handoff_id": authorization.handoff_id,
        "authorization_handoff_fingerprint": authorization.fingerprint,
        "price_blind_input_fingerprint": artifact["price_blind_input_fingerprint"],
        "request_fingerprint": request.request_fingerprint,
        "market_access_result_fingerprint": access.fingerprint,
        "quote_fingerprint": quote.fingerprint,
        "review_receipt_sha256": quote.review_receipt_sha256,
        "raw_response_sha256": quote.raw_evidence_sha256,
        "consumed_at": clock.retrieved_at,
        "reservation_fingerprint": reservation.fingerprint,
        "store_authority_sha256": store_authority_sha256,
        "store_instance_sha256": store_instance_sha256,
    }
    consumption = MarketAuthorizationConsumption(**consumption_payload)
    _complete_market_authorization(
        graph.component_lock_path,
        reservation,
        consumption,
    )
    return MarketReferenceAcquisition(
        access_result=access,
        request=request,
        quote=quote,
        authorization_reservation=reservation,
        authorization_consumption=consumption,
        review_file=provider.review_file,
        raw_evidence_file=provider.raw_evidence_file,
    )


def replay_reviewed_market_reference(
    *,
    price_blind_artifact_directory: Path,
    graph: ContractGraph,
    expected_freeze: PriceBlindFreezeCompilationResult,
    expected_security: SecurityIdentityCompilationResult,
    expected_acquisition: MarketReferenceAcquisition,
) -> MarketReferenceAcquisition:
    """Re-read both reviewed files and replay every pre-market authority before promotion."""

    receipt = expected_acquisition.access_result.receipt
    if receipt is None:
        raise ValueError("reviewed market acquisition lacks its governed receipt")
    reservation = expected_acquisition.authorization_reservation
    consumption = expected_acquisition.authorization_consumption
    if (
        reservation.authorization_handoff_id
        != expected_acquisition.request.authorization_handoff_id
        or reservation.authorization_handoff_fingerprint
        != expected_acquisition.request.authorization_handoff_fingerprint
        or reservation.price_blind_input_fingerprint
        != expected_acquisition.request.price_blind_input_fingerprint
        or reservation.request_fingerprint
        != expected_acquisition.request.request_fingerprint
        or consumption.authorization_handoff_id
        != expected_acquisition.request.authorization_handoff_id
        or consumption.authorization_handoff_fingerprint
        != expected_acquisition.request.authorization_handoff_fingerprint
        or consumption.price_blind_input_fingerprint
        != expected_acquisition.request.price_blind_input_fingerprint
        or consumption.request_fingerprint
        != expected_acquisition.request.request_fingerprint
        or consumption.market_access_result_fingerprint
        != expected_acquisition.access_result.fingerprint
        or consumption.quote_fingerprint != expected_acquisition.quote.fingerprint
        or consumption.review_receipt_sha256
        != expected_acquisition.quote.review_receipt_sha256
        or consumption.raw_response_sha256
        != expected_acquisition.quote.raw_evidence_sha256
        or consumption.consumed_at != receipt.receipt.retrieved_at
        or consumption.reservation_fingerprint != reservation.fingerprint
        or consumption.store_authority_sha256 != reservation.store_authority_sha256
    ):
        raise ValueError(
            "reviewed market acquisition does not replay: "
            "authorization consumption binding changed"
        )
    _verify_authorization_consumption(
        graph.component_lock_path,
        reservation,
        consumption,
    )
    loaded = load_price_blind_input_artifact(
        price_blind_artifact_directory,
        graph=graph,
        expected_result=expected_freeze,
    )
    authorization = loaded.handoffs[-1]
    if authorization.state != "market_reference_allowed" or not _current_authorization(
        graph,
        loaded,
    ):
        raise ValueError("market authorization is not current during replay")
    replayed_security = compile_security_identity(
        graph=graph,
        expected_freeze=loaded,
        proposal=expected_security.proposal,
    )
    if replayed_security != expected_security or replayed_security.decision is None:
        raise ValueError("security identity changed during market replay")
    selection = select_latest_completed_session(
        load_market_access_authority(graph.component_lock_path),
        mic=replayed_security.decision.exchange,
        cutoff_date=date.fromisoformat(authorization.data_cutoff_date),
        observed_at=_timestamp(
            expected_acquisition.request.request_started_at,
            "request start",
        ),
    )
    governed = expected_acquisition.access_result.receipt
    expected_hashes = reviewed_file_authority_hashes(
        graph.component_lock_path,
        calendar_dataset_sha256=selection.dataset_sha256,
    )
    if (
        selection.session.trading_date
        != expected_acquisition.request.expected_trading_date
        or any(getattr(governed, name) != value for name, value in expected_hashes.items())
    ):
        raise ValueError("market authority changed during replay")
    replayed_quote = ReviewedFileMarketProvider(
        expected_acquisition.review_file,
        expected_acquisition.raw_evidence_file,
    ).acquire(expected_acquisition.request)
    if replayed_quote != expected_acquisition.quote:
        raise ValueError("reviewed market acquisition does not replay from governed evidence")
    return expected_acquisition


__all__ = ()
