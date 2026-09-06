from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
import struct
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from ctypes import CDLL, POINTER, byref, c_int, c_uint
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from fractions import Fraction
from functools import cache
from math import gcd
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze, to_json_value
from .futu_receipts import (
    FUTU_SCHEMA_VERSION,
    PINNED_FUTU_API_DISTRIBUTION_SHA256,
    PINNED_FUTU_API_VERSION,
    PINNED_PROTOBUF_DESCRIPTOR_SET_SHA256,
    PINNED_SDK_OPERATION_REGISTRY_SHA256,
    FutuAuthorityDecision,
    FutuDataRequestReceipt,
    FutuDataResponseReceipt,
    FutuEvidenceBundle,
    FutuFrozenConclusionReceipt,
    FutuHistoricalKlineQuotaReceipt,
    FutuObservation,
    FutuReceiptError,
    FutuRuntimeIsolationAuthorization,
    FutuRuntimeIsolationReceipt,
    FutuSecurityIdentityReceipt,
    FutuSupplyChainReceipt,
    SignatureVerifier,
    content_identity,
    futu_request_parameters_sha256,
    load_futu_signed_receipt,
    signed_receipt_identity,
)

WIRE_SCHEMA_VERSION = "3.0.0"
GLOBAL_STATE_PROTOCOL_ID = 1002
MAXIMUM_PAGES_PER_PROTOCOL = 64
MAXIMUM_RAW_BYTES_PER_RESPONSE = 16 * 1024 * 1024
MAXIMUM_RAW_BYTES_PER_RUN = 256 * 1024 * 1024
MAXIMUM_OPERATIONS_PER_RUN = 128
MAXIMUM_PAGE_KEY_BYTES = 4096
MAXIMUM_RESOURCE_BYTES = 1024 * 1024
MAXIMUM_WIRE_REQUEST_BYTES = 1024 * 1024

_RESOURCE_DIRECTORY = Path(__file__).parent / "resources" / "futu"
_STAGES = {
    "runtime_authority",
    "valuation_pre_price_verification",
    "market_reference",
    "peer_comparable_reference",
    "post_valuation_context",
}
_PEER_COMPARABLE_PROTOCOL_IDS = frozenset({3103, 3202})
_OPTIONAL_AVAILABILITY_PROTOCOL_IDS = frozenset(
    {3229, 3230, 3232, 3244, 3245, 3246}
)
_REVENUE_BREAKDOWN_DIMENSION_TYPES = frozenset({1, 2, 4, 8})
_REVENUE_RATIO_ABSOLUTE_TOLERANCE = Decimal("0.1")
_FORBIDDEN_KEY_PARTS = frozenset(
    {
        "cookie",
        "credential",
        "password",
        "privatekey",
        "secret",
        "token",
    }
)
_FORBIDDEN_EXACT_KEYS = frozenset(
    {
        "account",
        "accountdata",
        "accountid",
        "accountnumber",
        "auth",
        "authorization",
        "balance",
        "cash",
        "holding",
        "holdings",
        "host",
        "order",
        "orderid",
        "port",
        "position",
        "positions",
        "trade",
        "tradeid",
    }
)
_HEX_64 = re.compile(r"[a-f0-9]{64}\Z")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_ADMITTED_FINANCIAL_FIELD_REGISTRY: ContextVar[Mapping[str, FrozenMap] | None] = (
    ContextVar("admitted_financial_field_registry", default=None)
)


def _expected_resolved_local_path(path: Path) -> Path:
    """Normalize only a verified platform-owned Darwin root alias."""

    absolute = Path(path).expanduser().absolute()
    if (
        sys.platform == "darwin"
        and len(absolute.parts) >= 2
        and absolute.parts[1] in {"etc", "tmp", "var"}
    ):
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
                return alias_target.joinpath(*absolute.parts[2:])
    return absolute


_PARAMETER_KEYS: dict[int, frozenset[str]] = {
    3103: frozenset(
        {
            "start",
            "end",
            "ktype",
            "autype",
            "fields",
            "max_count",
            "extended_time",
            "session",
        }
    ),
    3104: frozenset({"get_detail"}),
    3202: frozenset(),
    3227: frozenset({"statement_type", "financial_type", "currency_code", "num"}),
    3228: frozenset({"date", "financial_type", "currency_code"}),
    3229: frozenset(),
    3230: frozenset({"rating_dimension_type", "uid", "num"}),
    3232: frozenset(),
    3234: frozenset(),
    3235: frozenset(),
    3236: frozenset(),
    3243: frozenset(),
    3244: frozenset(),
    3245: frozenset({"leader_name"}),
    3246: frozenset({"currency_code", "num"}),
}

_CONCEPT_MAP: dict[tuple[str, str], str] = {
    ("market_price", "close"): "futu_unadjusted_daily_close_candidate",
    ("market_price", "volume"): "futu_daily_volume",
    ("analyst_consensus", "average_target_price"): "analyst_average_target_price",
    ("analyst_consensus", "highest_target_price"): "analyst_highest_target_price",
    ("analyst_consensus", "lowest_target_price"): "analyst_lowest_target_price",
    ("analyst_ratings", "rating"): "analyst_consensus_rating",
    ("valuation_context", "pe_ttm"): "vendor_pe_ttm",
    ("valuation_context", "pb"): "vendor_pb",
    ("valuation_context", "ps_ttm"): "vendor_ps_ttm",
    ("corporate_actions", "stock_split_event"): "stock_split_event",
}
_CRITICAL_FINANCIAL_CONCEPTS = MappingProxyType(
    {
        "balance_sheet": (
            "cash_and_cash_equivalents",
            "common_equity",
            "interest_bearing_debt",
            "total_assets",
            "total_liabilities",
        ),
        "cash_flow": (
            "capital_expenditure_outflow",
            "operating_cash_flow",
        ),
    }
)


class FutuSidecarError(ValueError):
    """Raised for an invalid host plan or untrusted sidecar envelope."""


class FutuSidecarTransport(Protocol):
    """Injected quote-only transport implemented outside the research wheel.

    A real implementation may talk to a pinned OpenD process in the isolated VM. The only
    capability exposed to this package is one bounded canonical-JSON request/response exchange.
    """

    def exchange(self, request_bytes: bytes, *, maximum_response_bytes: int) -> bytes: ...


@dataclass(frozen=True, slots=True)
class UnixSocketFutuSidecarTransport:
    """Concrete local-only transport for the separately attested sidecar.

    The closed wire protocol is a four-byte unsigned big-endian length followed by one
    canonical-JSON payload in each direction.  TCP, hostnames, ports, credentials, retries,
    and generic raw commands are intentionally absent.
    """

    socket_path: Path
    expected_uid: int
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        path = Path(self.socket_path)
        if not path.is_absolute() or "\0" in os.fspath(path):
            raise FutuSidecarError("sidecar socket path must be an absolute local path")
        if type(self.expected_uid) is not int or self.expected_uid < 0:
            raise FutuSidecarError("sidecar socket owner is invalid")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not 0 < float(self.timeout_seconds) <= 60
        ):
            raise FutuSidecarError("sidecar timeout must be between zero and 60 seconds")
        if len(os.fsencode(path)) > 100:
            raise FutuSidecarError("sidecar socket path exceeds the portable AF_UNIX limit")
        object.__setattr__(self, "socket_path", path)
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))

    def exchange(self, request_bytes: bytes, *, maximum_response_bytes: int) -> bytes:
        if not isinstance(request_bytes, bytes) or not request_bytes:
            raise FutuSidecarError("sidecar request must be non-empty bytes")
        if len(request_bytes) > MAXIMUM_WIRE_REQUEST_BYTES:
            raise FutuSidecarError("sidecar request exceeds the closed wire limit")
        if (
            type(maximum_response_bytes) is not int
            or not 1 <= maximum_response_bytes <= MAXIMUM_RAW_BYTES_PER_RESPONSE
        ):
            raise FutuSidecarError("sidecar response limit is invalid")
        endpoint_identity = self._validate_endpoint()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.connect(os.fspath(self.socket_path))
                if self._validate_endpoint() != endpoint_identity:
                    raise FutuSidecarError("sidecar socket identity changed during connect")
                if _connected_peer_uid(connection) != self.expected_uid:
                    raise FutuSidecarError("sidecar peer UID differs from the authorized owner")
                connection.sendall(struct.pack(">I", len(request_bytes)))
                connection.sendall(request_bytes)
                header = _recv_exact(connection, 4)
                response_size = struct.unpack(">I", header)[0]
                if not 1 <= response_size <= maximum_response_bytes:
                    raise FutuSidecarError("sidecar framed response exceeds the caller limit")
                return _recv_exact(connection, response_size)
        except FutuSidecarError:
            raise
        except (OSError, TimeoutError) as exc:
            raise FutuSidecarError("isolated sidecar exchange failed") from exc

    def _validate_endpoint(self) -> tuple[int, int]:
        parent = self.socket_path.parent
        try:
            parent_stat = parent.lstat()
            endpoint_stat = self.socket_path.lstat()
            resolved_parent = parent.resolve(strict=True)
            resolved_endpoint = self.socket_path.resolve(strict=True)
        except OSError as exc:
            raise FutuSidecarError("isolated sidecar endpoint is unavailable") from exc
        if (
            resolved_parent != _expected_resolved_local_path(parent)
            or resolved_endpoint != _expected_resolved_local_path(self.socket_path)
        ):
            raise FutuSidecarError("sidecar endpoint cannot traverse a symbolic link")
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != self.expected_uid
            or parent_stat.st_mode & 0o022
        ):
            raise FutuSidecarError("sidecar directory is not owner-controlled")
        if (
            not stat.S_ISSOCK(endpoint_stat.st_mode)
            or endpoint_stat.st_uid != self.expected_uid
            or endpoint_stat.st_mode & 0o022
        ):
            raise FutuSidecarError("sidecar endpoint is not an owner-controlled Unix socket")
        return endpoint_stat.st_dev, endpoint_stat.st_ino


def _connected_peer_uid(connection: socket.socket) -> int:
    """Return the kernel-authenticated Unix peer UID or fail closed."""
    if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
        try:
            credentials = connection.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("3i"),
            )
            _pid, uid, _gid = struct.unpack("3i", credentials)
        except (OSError, struct.error) as exc:
            raise FutuSidecarError("Linux SO_PEERCRED validation failed") from exc
        if uid < 0:
            raise FutuSidecarError("Linux SO_PEERCRED returned an invalid UID")
        return uid
    if sys.platform == "darwin":
        try:
            libc = CDLL(None)
            getpeereid = libc.getpeereid
            getpeereid.argtypes = (c_int, POINTER(c_uint), POINTER(c_uint))
            getpeereid.restype = c_int
            uid = c_uint()
            gid = c_uint()
            if getpeereid(connection.fileno(), byref(uid), byref(gid)) != 0:
                raise OSError("getpeereid failed")
        except (AttributeError, OSError) as exc:
            raise FutuSidecarError("macOS getpeereid validation failed") from exc
        return int(uid.value)
    raise FutuSidecarError("Unix peer credentials are unsupported on this platform")


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise FutuSidecarError("sidecar closed an incomplete framed response")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


_BOOT_ATTESTATION_FIELDS = {
    "schema_version",
    "receipt_id",
    "receipt_kind",
    "run_id",
    "session_id",
    "challenge_nonce",
    "boot_nonce",
    "supply_attestation",
    "runtime_authorization_fingerprint",
    "request_plan_fingerprint",
    "startup_checkpoint",
    "signer_public_key_hex",
    "issued_at",
    "signature_algorithm",
    "signer_key_id",
    "signature_hex",
}
_FETCH_ATTESTATION_FIELDS = {
    "session_id",
    "sequence",
    "boot_receipt_id",
    "signature_algorithm",
    "signer_key_id",
    "signature_hex",
}
_FINALIZE_RESPONSE_FIELDS = {
    "wire_schema_version",
    "command",
    "run_id",
    "session_id",
    "sequence",
    "runtime_isolation_receipt",
    "execution_attestation_receipt",
}
_ABORT_RESPONSE_FIELDS = {
    "wire_schema_version",
    "command",
    "run_id",
    "session_id",
    "sequence",
    "abort_attestation",
}
_ABORT_ATTESTATION_FIELDS = {
    "schema_version",
    "receipt_id",
    "receipt_kind",
    "run_id",
    "session_id",
    "boot_receipt_id",
    "sequence",
    "reason_code",
    "issued_at",
    "signature_algorithm",
    "signer_key_id",
    "signature_hex",
}
_ABORT_REASON_CODES = frozenset(
    {
        "host_failure",
        "sidecar_response_invalid",
        "quote_login_lost",
        "caller_abort",
    }
)
_EXECUTION_ATTESTATION_FIELDS = {
    "schema_version",
    "receipt_id",
    "receipt_kind",
    "run_id",
    "session_id",
    "boot_receipt_id",
    "supply_attestation",
    "runtime_authorization_fingerprint",
    "request_plan_fingerprint",
    "conditional_plan_disposition",
    "ordered_executions",
    "ordered_execution_root_sha256",
    "checkpoint_root_sha256",
    "started_at",
    "ended_at",
    "issued_at",
    "signature_algorithm",
    "signer_key_id",
    "signature_hex",
}
_EXECUTION_RECORD_FIELDS = {
    "request_id",
    "request_fingerprint",
    "response_fingerprint",
    "protocol_id",
    "page_index",
    "serial_number",
    "request_frame_sha256",
    "response_frame_sha256",
    "frame_exchange_sha256",
    "raw_plaintext_sha256",
    "encrypted_object_sha256",
    "observation_sha256",
}


@dataclass(frozen=True, slots=True)
class FutuSidecarBootAttestation:
    receipt: FrozenMap

    def __post_init__(self) -> None:
        materialized = to_json_value(self.receipt)
        if not isinstance(materialized, dict) or set(materialized) != _BOOT_ATTESTATION_FIELDS:
            raise FutuSidecarError("sidecar boot attestation fields are not closed")
        object.__setattr__(self, "receipt", freeze(materialized))

    @property
    def receipt_id(self) -> str:
        return str(self.receipt["receipt_id"])

    @property
    def session_id(self) -> str:
        return str(self.receipt["session_id"])

    @property
    def signer_key_id(self) -> str:
        return str(self.receipt["signer_key_id"])

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self.receipt)


@dataclass(frozen=True, slots=True)
class FutuSidecarExecutionAttestation:
    receipt: FrozenMap

    def __post_init__(self) -> None:
        materialized = to_json_value(self.receipt)
        if not isinstance(materialized, dict) or set(materialized) != _EXECUTION_ATTESTATION_FIELDS:
            raise FutuSidecarError("sidecar execution attestation fields are not closed")
        records = materialized["ordered_executions"]
        if (
            not isinstance(records, list)
            or not records
            or any(
                not isinstance(item, dict) or set(item) != _EXECUTION_RECORD_FIELDS
                for item in records
            )
        ):
            raise FutuSidecarError("sidecar ordered execution records are invalid")
        disposition = materialized["conditional_plan_disposition"]
        disposition_fields = {
            "status",
            "skipped_plan_indices",
            "reason_code",
            "conclusion_receipt_id",
            "conclusion_fingerprint",
        }
        if not isinstance(disposition, dict) or set(disposition) != disposition_fields:
            raise FutuSidecarError("sidecar conditional-plan disposition is invalid")
        skipped = disposition["skipped_plan_indices"]
        completed = disposition["status"] == "completed"
        if (
            disposition["status"] not in {"completed", "skipped"}
            or not isinstance(skipped, list)
            or any(type(index) is not int or index < 0 for index in skipped)
            or skipped != sorted(set(skipped))
            or completed
            != (
                not skipped
                and disposition["reason_code"] is None
                and disposition["conclusion_receipt_id"] is None
                and disposition["conclusion_fingerprint"] is None
            )
            or (
                not completed
                and (
                    not skipped
                    or disposition["reason_code"]
                    != "partial_or_contested_conclusion"
                    or not isinstance(disposition["conclusion_receipt_id"], str)
                    or not isinstance(disposition["conclusion_fingerprint"], str)
                    or _HEX_64.fullmatch(disposition["conclusion_fingerprint"]) is None
                )
            )
        ):
            raise FutuSidecarError("sidecar conditional-plan disposition is invalid")
        object.__setattr__(self, "receipt", freeze(materialized))

    @property
    def receipt_id(self) -> str:
        return str(self.receipt["receipt_id"])

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self.receipt)


@dataclass(frozen=True, slots=True)
class FutuSidecarAbortAttestation:
    """Signed proof that the sidecar closed one open quote-only session."""

    receipt: FrozenMap

    def __post_init__(self) -> None:
        materialized = to_json_value(self.receipt)
        if not isinstance(materialized, dict) or set(materialized) != _ABORT_ATTESTATION_FIELDS:
            raise FutuSidecarError("sidecar abort attestation fields are not closed")
        object.__setattr__(self, "receipt", freeze(materialized))

    @property
    def receipt_id(self) -> str:
        return str(self.receipt["receipt_id"])

    @property
    def reason_code(self) -> str:
        return str(self.receipt["reason_code"])

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self.receipt)


@dataclass(frozen=True, slots=True)
class FutuAttestedSessionFinalization:
    boot_attestation: FutuSidecarBootAttestation
    runtime_receipt: FutuRuntimeIsolationReceipt
    execution_attestation: FutuSidecarExecutionAttestation
    skipped_conditional_conclusion: FutuFrozenConclusionReceipt | None = None

    def __post_init__(self) -> None:
        if (
            type(self.boot_attestation) is not FutuSidecarBootAttestation
            or type(self.runtime_receipt) is not FutuRuntimeIsolationReceipt
            or type(self.execution_attestation) is not FutuSidecarExecutionAttestation
            or self.execution_attestation.receipt["session_id"]
            != self.boot_attestation.session_id
            or self.execution_attestation.receipt["boot_receipt_id"]
            != self.boot_attestation.receipt_id
            or self.execution_attestation.receipt["run_id"] != self.runtime_receipt.run_id
        ):
            raise FutuSidecarError("sidecar finalization authorities are not aligned")
        disposition = to_json_value(
            self.execution_attestation.receipt["conditional_plan_disposition"]
        )
        conclusion = self.skipped_conditional_conclusion
        if conclusion is None:
            if disposition != {
                "status": "completed",
                "skipped_plan_indices": [],
                "reason_code": None,
                "conclusion_receipt_id": None,
                "conclusion_fingerprint": None,
            }:
                raise FutuSidecarError("completed sidecar plan has a skip disposition")
        elif (
            type(conclusion) is not FutuFrozenConclusionReceipt
            or disposition["status"] != "skipped"
            or disposition["reason_code"] != "partial_or_contested_conclusion"
            or disposition["conclusion_receipt_id"] != conclusion.receipt_id
            or disposition["conclusion_fingerprint"] != conclusion.fingerprint
        ):
            raise FutuSidecarError("sidecar conditional-plan disposition is rebound")

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "boot_attestation": self.boot_attestation.to_dict(),
            "runtime_receipt": self.runtime_receipt.to_dict(),
            "execution_attestation": self.execution_attestation.to_dict(),
        }


def _conditional_plan_disposition(
    *,
    runtime_authorization: FutuRuntimeIsolationAuthorization,
    plan_position: int,
    plan_page_index: int,
    skipped_conclusion: FutuFrozenConclusionReceipt | None,
) -> dict[str, Any]:
    plan = runtime_authorization.request_plan
    if plan_position == len(plan) and plan_page_index == 0:
        if skipped_conclusion is not None:
            raise FutuSidecarError("completed request plan cannot bind a skip conclusion")
        return {
            "status": "completed",
            "skipped_plan_indices": [],
            "reason_code": None,
            "conclusion_receipt_id": None,
            "conclusion_fingerprint": None,
        }
    remaining = plan[plan_position:]
    if (
        plan_page_index != 0
        or not remaining
        or any(item["activation_condition"] != "eligible_conclusion_only" for item in remaining)
        or type(skipped_conclusion) is not FutuFrozenConclusionReceipt
        or skipped_conclusion.run_id != runtime_authorization.run_id
        or skipped_conclusion.composite_valuation.status not in {"blocked", "contested"}
        or skipped_conclusion.owner_scorecard.recommendation != "无法评级"
    ):
        raise FutuSidecarError(
            "only an exact partial or contested conclusion may skip the conditional suffix"
        )
    return {
        "status": "skipped",
        "skipped_plan_indices": [item["plan_index"] for item in remaining],
        "reason_code": "partial_or_contested_conclusion",
        "conclusion_receipt_id": skipped_conclusion.receipt_id,
        "conclusion_fingerprint": skipped_conclusion.fingerprint,
    }


class AttestedFutuSidecarSession:
    """Stateful signed v3 client for one isolated quote-only sidecar session."""

    def __init__(
        self,
        *,
        transport: UnixSocketFutuSidecarTransport,
        run_id: str,
        supply_chain: FutuSupplyChainReceipt,
        runtime_authorization: FutuRuntimeIsolationAuthorization,
        verifier: SignatureVerifier,
        expected_signer_key_id: str,
        boot_attestation: FutuSidecarBootAttestation,
    ) -> None:
        self._transport = transport
        self.run_id = run_id
        self.supply_chain = supply_chain
        self.runtime_authorization = runtime_authorization
        self.verifier = verifier
        self.expected_signer_key_id = expected_signer_key_id
        self.boot_attestation = boot_attestation
        self._sequence = 0
        self._plan_position = 0
        self._plan_page_index = 0
        self._finalization: FutuAttestedSessionFinalization | None = None
        self._abort_attestation: FutuSidecarAbortAttestation | None = None

    @classmethod
    def open(
        cls,
        *,
        socket_path: Path,
        expected_uid: int,
        timeout_seconds: float,
        run_id: str,
        supply_chain: FutuSupplyChainReceipt,
        runtime_authorization: FutuRuntimeIsolationAuthorization,
        verifier: SignatureVerifier,
        expected_signer_key_id: str,
    ) -> AttestedFutuSidecarSession:
        if (
            type(supply_chain) is not FutuSupplyChainReceipt
            or type(runtime_authorization) is not FutuRuntimeIsolationAuthorization
            or runtime_authorization.run_id != run_id
            or runtime_authorization.supply_chain_fingerprint != supply_chain.fingerprint
            or expected_signer_key_id
            != runtime_authorization.sidecar_attestor_key_id
            or _KEY_ID.fullmatch(expected_signer_key_id) is None
        ):
            raise FutuSidecarError("attested sidecar open authority is invalid")
        challenge_nonce = os.urandom(32).hex()
        transport = UnixSocketFutuSidecarTransport(
            socket_path=socket_path,
            expected_uid=expected_uid,
            timeout_seconds=timeout_seconds,
        )
        request = {
            "wire_schema_version": WIRE_SCHEMA_VERSION,
            "command": "open_quote_only_session",
            "run_id": run_id,
            "challenge_nonce": challenge_nonce,
            "expected_supply_attestation": _supply_attestation(supply_chain),
            "expected_runtime_authorization_fingerprint": runtime_authorization.fingerprint,
            "expected_authorized_security_codes": to_json_value(
                runtime_authorization.authorized_security_codes
            ),
            "expected_request_plan": to_json_value(runtime_authorization.request_plan),
            "expected_request_plan_fingerprint": (
                runtime_authorization.request_plan_fingerprint
            ),
            "expected_maximum_planned_requests": (
                runtime_authorization.maximum_planned_requests
            ),
            "expected_maximum_pages_per_protocol": (
                runtime_authorization.maximum_pages_per_protocol
            ),
            "expected_signer_key_id": expected_signer_key_id,
        }
        raw = transport.exchange(
            canonical_json(request).encode("utf-8"),
            maximum_response_bytes=MAXIMUM_RAW_BYTES_PER_RESPONSE,
        )
        response = _load_wire_object(raw, "sidecar open response")
        response = _exact_members(
            response,
            {"wire_schema_version", "command", "run_id", "session_id", "boot_attestation"},
            "sidecar open response",
        )
        if (
            response["wire_schema_version"] != WIRE_SCHEMA_VERSION
            or response["command"] != "open_quote_only_session"
            or response["run_id"] != run_id
        ):
            raise FutuSidecarError("sidecar open response does not bind the request")
        boot_payload = _exact_members(
            response["boot_attestation"],
            _BOOT_ATTESTATION_FIELDS,
            "sidecar boot attestation",
        )
        _verify_signed_sidecar_object(
            boot_payload,
            verifier=verifier,
            expected_signer_key_id=expected_signer_key_id,
        )
        _validate_boot_attestation(
            boot_payload,
            run_id=run_id,
            session_id=response["session_id"],
            challenge_nonce=challenge_nonce,
            supply_chain=supply_chain,
            runtime_authorization=runtime_authorization,
        )
        boot_issued = _utc_datetime(boot_payload["issued_at"], "boot issued_at")
        startup_observed = _utc_datetime(
            boot_payload["startup_checkpoint"]["observed_at"],
            "startup observed_at",
        )
        authorized_from = _utc_datetime(runtime_authorization.valid_from, "valid_from")
        authorization_expires = _utc_datetime(
            runtime_authorization.expires_at, "runtime authorization expires_at"
        )
        if not (
            authorized_from <= startup_observed <= boot_issued < authorization_expires
        ):
            raise FutuSidecarError("sidecar boot chronology is outside runtime authorization")
        boot = FutuSidecarBootAttestation(freeze(boot_payload))
        return cls(
            transport=transport,
            run_id=run_id,
            supply_chain=supply_chain,
            runtime_authorization=runtime_authorization,
            verifier=verifier,
            expected_signer_key_id=expected_signer_key_id,
            boot_attestation=boot,
        )

    @property
    def session_id(self) -> str:
        return self.boot_attestation.session_id

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def finalization(self) -> FutuAttestedSessionFinalization | None:
        return self._finalization

    @property
    def abort_attestation(self) -> FutuSidecarAbortAttestation | None:
        return self._abort_attestation

    def exchange(self, request_bytes: bytes, *, maximum_response_bytes: int) -> bytes:
        if self._finalization is not None or self._abort_attestation is not None:
            raise FutuSidecarError("closed sidecar session cannot fetch data")
        request = _exact_members(
            _load_wire_object(request_bytes, "sidecar fetch request"),
            {
                "wire_schema_version",
                "command",
                "run_id",
                "request_id",
                "request_fingerprint",
                "protocol",
                "security",
                "parameters",
                "page_index",
                "page_key",
                "expected_supply_attestation",
                "global_state_guards",
            },
            "sidecar fetch request",
        )
        if (
            request.get("wire_schema_version") != WIRE_SCHEMA_VERSION
            or request.get("command") != "fetch_quote_data_with_global_state_guards"
            or request.get("run_id") != self.run_id
            or request.get("expected_supply_attestation")
            != _supply_attestation(self.supply_chain)
        ):
            raise FutuSidecarError("sidecar fetch request is outside the open session")
        protocol = _exact_members(request["protocol"], {"id", "name"}, "fetch protocol")
        security = _exact_members(
            request["security"], {"market", "code", "security_id"}, "fetch security"
        )
        if security["market"] != "US":
            raise FutuSidecarError("sidecar fetch security market is not authorized")
        plan_position, plan_page_index = self._match_request_plan(
            security_code=security["code"],
            protocol_id=protocol["id"],
            parameters=request["parameters"],
            page_index=request["page_index"],
            page_key=request["page_key"],
        )
        sequence = self._sequence + 1
        if sequence > self.runtime_authorization.maximum_planned_requests:
            raise FutuSidecarError("sidecar fetch count exceeds the signed request plan")
        wire_request = {
            **request,
            "session_id": self.session_id,
            "sequence": sequence,
            "boot_receipt_id": self.boot_attestation.receipt_id,
        }
        raw = self._transport.exchange(
            canonical_json(wire_request).encode("utf-8"),
            maximum_response_bytes=maximum_response_bytes,
        )
        response = _load_wire_object(raw, "signed sidecar fetch response")
        expected_inner_fields = {
            "wire_schema_version",
            "command",
            "run_id",
            "request_id",
            "request_fingerprint",
            "protocol_id",
            "page_index",
            "supply_attestation",
            "pre_global_state",
            "data_response",
            "post_global_state",
        }
        if set(response) != expected_inner_fields | _FETCH_ATTESTATION_FIELDS:
            raise FutuSidecarError("signed sidecar fetch response fields are not closed")
        _verify_signed_sidecar_object(
            response,
            verifier=self.verifier,
            expected_signer_key_id=self.expected_signer_key_id,
        )
        if (
            response["session_id"] != self.session_id
            or response["sequence"] != sequence
            or response["boot_receipt_id"] != self.boot_attestation.receipt_id
        ):
            raise FutuSidecarError("signed sidecar fetch response was replayed or reordered")
        data_response = response.get("data_response")
        if not isinstance(data_response, dict) or type(data_response.get("terminal")) is not bool:
            raise FutuSidecarError("signed sidecar response lacks a terminal plan state")
        plan_item = self.runtime_authorization.request_plan[plan_position]
        if data_response["terminal"]:
            next_plan_position = plan_position + 1
            next_plan_page_index = 0
        else:
            if (
                plan_item["pagination_mode"] != "internal"
                or plan_page_index + 1 >= plan_item["maximum_pages"]
            ):
                raise FutuSidecarError("signed sidecar response exceeds its page plan")
            next_plan_position = plan_position
            next_plan_page_index = plan_page_index + 1
        self._sequence = sequence
        self._plan_position = next_plan_position
        self._plan_page_index = next_plan_page_index
        inner = {
            key: value for key, value in response.items() if key not in _FETCH_ATTESTATION_FIELDS
        }
        return canonical_json(inner).encode("utf-8")

    def _match_request_plan(
        self,
        *,
        security_code: Any,
        protocol_id: Any,
        parameters: Any,
        page_index: Any,
        page_key: Any,
    ) -> tuple[int, int]:
        if (
            not isinstance(security_code, str)
            or type(protocol_id) is not int
            or not isinstance(parameters, dict)
            or type(page_index) is not int
            or page_index < 0
            or (page_key is not None and not isinstance(page_key, str))
        ):
            raise FutuSidecarError("sidecar fetch request-plan fields are invalid")
        parameters_sha256 = futu_request_parameters_sha256(parameters)
        plan = self.runtime_authorization.request_plan
        if page_index == 0:
            if page_key is not None:
                raise FutuSidecarError("first request page cannot carry an internal page key")
            if self._plan_position >= len(plan):
                raise FutuSidecarError("sidecar fetch exceeds the signed request plan")
            item = plan[self._plan_position]
            if (
                item["security_code"] != security_code
                or item["protocol_id"] != protocol_id
                or item["parameters_sha256"] != parameters_sha256
            ):
                raise FutuSidecarError(
                    "sidecar fetch is absent or reordered in the signed plan"
                )
            return self._plan_position, 0
        if self._plan_position >= len(plan) or page_index != self._plan_page_index:
            raise FutuSidecarError("sidecar fetch page is replayed or reordered")
        item = plan[self._plan_position]
        if (
            item["pagination_mode"] != "internal"
            or item["security_code"] != security_code
            or item["protocol_id"] != protocol_id
            or item["parameters_sha256"] != parameters_sha256
            or not page_key
            or page_index >= item["maximum_pages"]
        ):
            raise FutuSidecarError("sidecar fetch page escaped the signed request plan")
        return self._plan_position, page_index

    def finalize(
        self,
        *,
        expected_executions: Sequence[FutuSidecarExecution],
        skipped_conditional_conclusion: FutuFrozenConclusionReceipt | None = None,
    ) -> FutuAttestedSessionFinalization:
        if (
            self._finalization is not None
            or self._abort_attestation is not None
            or self._sequence == 0
        ):
            raise FutuSidecarError("sidecar session cannot be finalized in its current state")
        conditional_disposition = _conditional_plan_disposition(
            runtime_authorization=self.runtime_authorization,
            plan_position=self._plan_position,
            plan_page_index=self._plan_page_index,
            skipped_conclusion=skipped_conditional_conclusion,
        )
        executions = tuple(expected_executions)
        expected_records = _expected_execution_attestation_records(executions)
        if len(expected_records) != self._sequence:
            raise FutuSidecarError("sidecar fetch count differs from retained executions")
        sequence = self._sequence + 1
        request = {
            "wire_schema_version": WIRE_SCHEMA_VERSION,
            "command": "finalize_quote_only_session",
            "run_id": self.run_id,
            "session_id": self.session_id,
            "boot_receipt_id": self.boot_attestation.receipt_id,
            "sequence": sequence,
            "conditional_plan_disposition": conditional_disposition,
        }
        raw = self._transport.exchange(
            canonical_json(request).encode("utf-8"),
            maximum_response_bytes=MAXIMUM_RAW_BYTES_PER_RESPONSE,
        )
        response = _exact_members(
            _load_wire_object(raw, "sidecar finalize response"),
            _FINALIZE_RESPONSE_FIELDS,
            "sidecar finalize response",
        )
        if (
            response["wire_schema_version"] != WIRE_SCHEMA_VERSION
            or response["command"] != "finalize_quote_only_session"
            or response["run_id"] != self.run_id
            or response["session_id"] != self.session_id
            or response["sequence"] != sequence
        ):
            raise FutuSidecarError("sidecar finalize response was replayed or reordered")
        runtime_payload = _exact_members(
            response["runtime_isolation_receipt"],
            set(load_futu_schema_fields("futu-runtime-isolation-receipt")),
            "sidecar runtime receipt",
        )
        _verify_signed_sidecar_object(
            runtime_payload,
            verifier=self.verifier,
            expected_signer_key_id=self.expected_signer_key_id,
        )
        runtime = load_futu_signed_receipt(
            "futu-runtime-isolation-receipt", runtime_payload
        )
        assert type(runtime) is FutuRuntimeIsolationReceipt
        authorization = self.runtime_authorization
        if (
            runtime.run_id != authorization.run_id
            or runtime.policy_sha256 != authorization.policy_sha256
            or runtime.component_lock_sha256 != authorization.component_lock_sha256
            or runtime.account_scope_sha256 != authorization.account_scope_sha256
            or runtime.supply_chain_fingerprint != authorization.supply_chain_fingerprint
            or runtime.runtime_authorization_fingerprint != authorization.fingerprint
            or runtime.request_plan_fingerprint != authorization.request_plan_fingerprint
            or runtime.authorization_window_seconds
            != authorization.authorization_window_seconds
            or runtime.vm_image_sha256 != authorization.vm_image_sha256
            or runtime.opend_version != authorization.opend_version
            or runtime.opend_server_version != self.supply_chain.opend_server_version
            or runtime.opend_server_build_no
            != self.supply_chain.opend_server_build_no
            or runtime.allowed_protocol_ids != authorization.allowed_protocol_ids
            or runtime.quarantined
            or to_json_value(runtime.checkpoints[0])
            != to_json_value(self.boot_attestation.receipt["startup_checkpoint"])
        ):
            raise FutuSidecarError("completed runtime receipt changed its pre-run authority")
        runtime_started = _utc_datetime(runtime.started_at, "runtime started_at")
        runtime_ended = _utc_datetime(runtime.ended_at, "runtime ended_at")
        authorization_valid_from = _utc_datetime(
            authorization.valid_from, "runtime authorization valid_from"
        )
        authorization_expires = _utc_datetime(
            authorization.expires_at, "runtime authorization expires_at"
        )
        if not authorization_valid_from <= runtime_started <= runtime_ended < authorization_expires:
            raise FutuSidecarError("completed runtime escaped its one-session authority window")
        execution_payload = _exact_members(
            response["execution_attestation_receipt"],
            _EXECUTION_ATTESTATION_FIELDS,
            "sidecar execution attestation",
        )
        _verify_signed_sidecar_object(
            execution_payload,
            verifier=self.verifier,
            expected_signer_key_id=self.expected_signer_key_id,
        )
        _validate_execution_attestation(
            execution_payload,
            run_id=self.run_id,
            session_id=self.session_id,
            boot_receipt_id=self.boot_attestation.receipt_id,
            supply_chain=self.supply_chain,
            runtime_receipt=runtime,
            expected_records=expected_records,
            expected_conditional_disposition=conditional_disposition,
        )
        execution_attestation = FutuSidecarExecutionAttestation(
            freeze(execution_payload)
        )
        finalization = FutuAttestedSessionFinalization(
            boot_attestation=self.boot_attestation,
            runtime_receipt=runtime,
            execution_attestation=execution_attestation,
            skipped_conditional_conclusion=skipped_conditional_conclusion,
        )
        self._sequence = sequence
        self._plan_position = len(self.runtime_authorization.request_plan)
        self._plan_page_index = 0
        self._finalization = finalization
        return finalization

    def abort(self, reason_code: str = "caller_abort") -> FutuSidecarAbortAttestation:
        """Close the sidecar session once and retain its signed close attestation."""
        if self._finalization is not None:
            raise FutuSidecarError("finalized sidecar session cannot be aborted")
        if self._abort_attestation is not None:
            if self._abort_attestation.reason_code != reason_code:
                raise FutuSidecarError("sidecar session was already aborted for another reason")
            return self._abort_attestation
        if reason_code not in _ABORT_REASON_CODES:
            raise FutuSidecarError("sidecar abort reason code is not closed")
        sequence = self._sequence + 1
        request = {
            "wire_schema_version": WIRE_SCHEMA_VERSION,
            "command": "abort_quote_only_session",
            "run_id": self.run_id,
            "session_id": self.session_id,
            "boot_receipt_id": self.boot_attestation.receipt_id,
            "sequence": sequence,
            "reason_code": reason_code,
        }
        raw = self._transport.exchange(
            canonical_json(request).encode("utf-8"),
            maximum_response_bytes=MAXIMUM_RAW_BYTES_PER_RESPONSE,
        )
        response = _exact_members(
            _load_wire_object(raw, "sidecar abort response"),
            _ABORT_RESPONSE_FIELDS,
            "sidecar abort response",
        )
        if (
            response["wire_schema_version"] != WIRE_SCHEMA_VERSION
            or response["command"] != "abort_quote_only_session"
            or response["run_id"] != self.run_id
            or response["session_id"] != self.session_id
            or response["sequence"] != sequence
        ):
            raise FutuSidecarError("sidecar abort response was replayed or reordered")
        payload = _exact_members(
            response["abort_attestation"],
            _ABORT_ATTESTATION_FIELDS,
            "sidecar abort attestation",
        )
        _verify_signed_sidecar_object(
            payload,
            verifier=self.verifier,
            expected_signer_key_id=self.expected_signer_key_id,
        )
        if (
            payload["schema_version"] != FUTU_SCHEMA_VERSION
            or payload["receipt_kind"] != "futu-sidecar-abort"
            or payload["run_id"] != self.run_id
            or payload["session_id"] != self.session_id
            or payload["boot_receipt_id"] != self.boot_attestation.receipt_id
            or payload["sequence"] != sequence
            or payload["reason_code"] != reason_code
            or payload["receipt_id"]
            != signed_receipt_identity("futu-sidecar-abort:", payload)
        ):
            raise FutuSidecarError("sidecar abort attestation was rebound")
        issued_at = _utc_datetime(payload["issued_at"], "abort issued_at")
        boot_issued = _utc_datetime(
            self.boot_attestation.receipt["issued_at"], "boot issued_at"
        )
        authorization_expires = _utc_datetime(
            self.runtime_authorization.expires_at,
            "runtime authorization expires_at",
        )
        if not boot_issued <= issued_at < authorization_expires:
            raise FutuSidecarError("sidecar abort chronology is outside runtime authority")
        attestation = FutuSidecarAbortAttestation(freeze(payload))
        self._sequence = sequence
        self._abort_attestation = attestation
        return attestation


def _load_wire_object(raw: bytes, label: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAXIMUM_RAW_BYTES_PER_RESPONSE:
        raise FutuSidecarError(f"{label} exceeds its byte limit")
    try:
        text = raw.decode("utf-8")
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FutuSidecarError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or text != canonical_json(payload):
        raise FutuSidecarError(f"{label} must be one canonical JSON object")
    return payload


def _verify_signed_sidecar_object(
    payload: Mapping[str, Any],
    *,
    verifier: SignatureVerifier,
    expected_signer_key_id: str,
) -> None:
    materialized = to_json_value(payload)
    if not isinstance(materialized, dict):
        raise FutuSidecarError("sidecar signature payload must be an object")
    signature_hex = materialized.pop("signature_hex", None)
    if (
        materialized.get("signature_algorithm") != "ed25519"
        or materialized.get("signer_key_id") != expected_signer_key_id
        or not isinstance(signature_hex, str)
    ):
        raise FutuSidecarError("sidecar signature identity is invalid")
    try:
        valid = verifier.verify(
            signer_key_id=expected_signer_key_id,
            payload=canonical_json(materialized).encode("utf-8"),
            signature_hex=signature_hex,
        )
    except Exception as exc:
        raise FutuSidecarError("sidecar signature verification failed") from exc
    if not valid:
        raise FutuSidecarError("sidecar signature verification failed")


def _validate_boot_attestation(
    payload: dict[str, Any],
    *,
    run_id: str,
    session_id: Any,
    challenge_nonce: str,
    supply_chain: FutuSupplyChainReceipt,
    runtime_authorization: FutuRuntimeIsolationAuthorization,
) -> None:
    expected_supply = _supply_attestation(supply_chain)
    if (
        payload["schema_version"] != FUTU_SCHEMA_VERSION
        or payload["receipt_kind"] != "futu-sidecar-boot-attestation"
        or payload["run_id"] != run_id
        or payload["session_id"] != session_id
        or payload["challenge_nonce"] != challenge_nonce
        or payload["supply_attestation"] != expected_supply
        or payload["runtime_authorization_fingerprint"]
        != runtime_authorization.fingerprint
        or payload["request_plan_fingerprint"]
        != runtime_authorization.request_plan_fingerprint
        or not isinstance(payload["boot_nonce"], str)
        or len(payload["boot_nonce"]) != 64
        or _HEX_64.fullmatch(payload["boot_nonce"]) is None
        or not isinstance(payload["signer_public_key_hex"], str)
        or _HEX_64.fullmatch(payload["signer_public_key_hex"]) is None
    ):
        raise FutuSidecarError("sidecar boot attestation does not bind the open request")
    _utc_datetime(payload["issued_at"], "boot attestation issued_at")
    startup = _validate_runtime_checkpoint(
        payload["startup_checkpoint"], expected_kind="startup"
    )
    if (
        startup["opend_server_version"] != supply_chain.opend_server_version
        or startup["opend_server_build_no"] != supply_chain.opend_server_build_no
    ):
        raise FutuSidecarError("sidecar boot OpenD identity differs from pinned supply")
    computed_session_id = canonical_sha256(
        {
            "domain": "owner-research-futu-session-v1",
            "run_id": run_id,
            "challenge_nonce": challenge_nonce,
            "boot_nonce": payload["boot_nonce"],
            "supply_attestation": expected_supply,
            "runtime_authorization_fingerprint": runtime_authorization.fingerprint,
            "request_plan_fingerprint": runtime_authorization.request_plan_fingerprint,
            "startup_checkpoint": startup,
            "signer_public_key_hex": payload["signer_public_key_hex"],
        }
    )
    unsigned = dict(payload)
    if (
        computed_session_id != session_id
        or payload["receipt_id"]
        != signed_receipt_identity("futu-sidecar-boot:", unsigned)
    ):
        raise FutuSidecarError("sidecar boot attestation identity is invalid")


def _validate_runtime_checkpoint(value: Any, *, expected_kind: str) -> dict[str, Any]:
    checkpoint = _exact_members(
        value,
        {
            "checkpoint",
            "protocol_id",
            "serial_number",
            "global_state_request_fingerprint",
            "global_state_response_fingerprint",
            "observed_at",
            "qot_logined",
            "trd_logined",
            "opend_server_version",
            "opend_server_build_no",
        },
        "sidecar runtime checkpoint",
    )
    if (
        checkpoint["checkpoint"] != expected_kind
        or checkpoint["protocol_id"] != GLOBAL_STATE_PROTOCOL_ID
        or type(checkpoint["serial_number"]) is not int
        or checkpoint["serial_number"] <= 0
        or checkpoint["qot_logined"] is not True
        or type(checkpoint["trd_logined"]) is not bool
        or type(checkpoint["opend_server_version"]) is not int
        or checkpoint["opend_server_version"] <= 0
        or type(checkpoint["opend_server_build_no"]) is not int
        or checkpoint["opend_server_build_no"] <= 0
    ):
        raise FutuSidecarError("sidecar runtime checkpoint is not quote-only")
    _require_sha256(
        checkpoint["global_state_request_fingerprint"],
        "sidecar GlobalState request fingerprint",
    )
    _require_sha256(
        checkpoint["global_state_response_fingerprint"],
        "sidecar GlobalState response fingerprint",
    )
    _utc_datetime(checkpoint["observed_at"], "sidecar checkpoint observed_at")
    return checkpoint


def _expected_execution_attestation_records(
    executions: tuple[FutuSidecarExecution, ...],
) -> tuple[dict[str, Any], ...]:
    records: list[dict[str, Any]] = []
    for execution in executions:
        response_by_request = {item.request_id: item for item in execution.responses}
        for request in execution.requests:
            response = response_by_request.get(request.request_id)
            if response is None:
                raise FutuSidecarError("retained execution lacks a response")
            observation_payloads = [
                item.to_dict()
                for item in execution.observations
                if item.response_fingerprint == response.fingerprint
            ]
            records.append(
                {
                    "request_id": request.request_id,
                    "request_fingerprint": request.fingerprint,
                    "response_fingerprint": response.fingerprint,
                    "protocol_id": request.protocol_id,
                    "page_index": request.page_index,
                    "raw_plaintext_sha256": response.raw_plaintext_sha256,
                    "encrypted_object_sha256": response.encrypted_object_sha256,
                    "observation_sha256": canonical_sha256(observation_payloads),
                }
            )
    return tuple(records)


def _replay_executions_against_request_plan(
    executions: Sequence[FutuSidecarExecution],
    runtime_authorization: FutuRuntimeIsolationAuthorization,
) -> tuple[int, int]:
    plan = runtime_authorization.request_plan
    position = 0
    expected_page = 0
    for execution in executions:
        responses = {item.request_id: item for item in execution.responses}
        for request in execution.requests:
            if position >= len(plan):
                raise FutuSidecarError("retained execution exceeds the signed request plan")
            item = plan[position]
            response = responses.get(request.request_id)
            if (
                response is None
                or request.protocol_id != item["protocol_id"]
                or futu_request_parameters_sha256(request.parameters)
                != item["parameters_sha256"]
                or request.page_index != expected_page
            ):
                raise FutuSidecarError("retained execution was reordered against its request plan")
            if response.terminal:
                position += 1
                expected_page = 0
            else:
                if (
                    item["pagination_mode"] != "internal"
                    or expected_page + 1 >= item["maximum_pages"]
                ):
                    raise FutuSidecarError("retained execution exceeded its page plan")
                expected_page += 1
    return position, expected_page


def _validate_execution_attestation(
    payload: dict[str, Any],
    *,
    run_id: str,
    session_id: str,
    boot_receipt_id: str,
    supply_chain: FutuSupplyChainReceipt,
    runtime_receipt: FutuRuntimeIsolationReceipt,
    expected_records: tuple[dict[str, Any], ...],
    expected_conditional_disposition: Mapping[str, Any],
) -> None:
    records = payload["ordered_executions"]
    if (
        payload["schema_version"] != FUTU_SCHEMA_VERSION
        or payload["receipt_kind"] != "futu-sidecar-execution-attestation"
        or payload["run_id"] != run_id
        or payload["session_id"] != session_id
        or payload["boot_receipt_id"] != boot_receipt_id
        or payload["supply_attestation"] != _supply_attestation(supply_chain)
        or payload["runtime_authorization_fingerprint"]
        != runtime_receipt.runtime_authorization_fingerprint
        or payload["request_plan_fingerprint"]
        != runtime_receipt.request_plan_fingerprint
        or payload["conditional_plan_disposition"]
        != to_json_value(expected_conditional_disposition)
        or payload["ordered_execution_root_sha256"] != canonical_sha256(records)
        or payload["checkpoint_root_sha256"]
        != canonical_sha256(runtime_receipt.to_dict()["checkpoints"])
        or len(records) != len(expected_records)
    ):
        raise FutuSidecarError("sidecar execution attestation root or authority is invalid")
    for actual, expected in zip(records, expected_records, strict=True):
        if not isinstance(actual, dict) or set(actual) != _EXECUTION_RECORD_FIELDS:
            raise FutuSidecarError("sidecar execution attestation record is invalid")
        if any(actual[key] != value for key, value in expected.items()):
            raise FutuSidecarError("sidecar execution attestation was rebound")
        if type(actual["serial_number"]) is not int or actual["serial_number"] <= 0:
            raise FutuSidecarError("sidecar execution serial number is invalid")
        for key in _EXECUTION_RECORD_FIELDS - {
            "page_index",
            "protocol_id",
            "request_id",
            "serial_number",
        }:
            _require_sha256(actual[key], f"sidecar execution {key}")
    _utc_datetime(payload["started_at"], "sidecar execution started_at")
    _utc_datetime(payload["ended_at"], "sidecar execution ended_at")
    _utc_datetime(payload["issued_at"], "sidecar execution issued_at")
    if (
        payload["started_at"] != runtime_receipt.started_at
        or payload["ended_at"] != runtime_receipt.ended_at
        or payload["issued_at"] != runtime_receipt.issued_at
        or payload["receipt_id"]
        != signed_receipt_identity("futu-sidecar-execution:", payload)
    ):
        raise FutuSidecarError("sidecar execution attestation identity is invalid")


def validate_futu_attested_session_finalization(
    finalization: FutuAttestedSessionFinalization,
    *,
    expected_executions: Sequence[FutuSidecarExecution],
    supply_chain: FutuSupplyChainReceipt,
    runtime_authorization: FutuRuntimeIsolationAuthorization,
    verifier: SignatureVerifier,
) -> None:
    """Replay both signed session receipts against exact retained executions."""
    if type(finalization) is not FutuAttestedSessionFinalization:
        raise FutuSidecarError("attested finalization requires the exact typed object")
    boot = finalization.boot_attestation.to_dict()
    execution = finalization.execution_attestation.to_dict()
    runtime = finalization.runtime_receipt
    signer_key_id = runtime_authorization.sidecar_attestor_key_id
    _verify_signed_sidecar_object(
        boot,
        verifier=verifier,
        expected_signer_key_id=signer_key_id,
    )
    _validate_boot_attestation(
        boot,
        run_id=runtime.run_id,
        session_id=finalization.boot_attestation.session_id,
        challenge_nonce=boot["challenge_nonce"],
        supply_chain=supply_chain,
        runtime_authorization=runtime_authorization,
    )
    _verify_signed_sidecar_object(
        runtime.to_dict(),
        verifier=verifier,
        expected_signer_key_id=signer_key_id,
    )
    _verify_signed_sidecar_object(
        execution,
        verifier=verifier,
        expected_signer_key_id=signer_key_id,
    )
    if (
        runtime.run_id != runtime_authorization.run_id
        or runtime.policy_sha256 != runtime_authorization.policy_sha256
        or runtime.component_lock_sha256
        != runtime_authorization.component_lock_sha256
        or runtime.account_scope_sha256 != runtime_authorization.account_scope_sha256
        or runtime.supply_chain_fingerprint
        != runtime_authorization.supply_chain_fingerprint
        or runtime.runtime_authorization_fingerprint
        != runtime_authorization.fingerprint
        or runtime.request_plan_fingerprint
        != runtime_authorization.request_plan_fingerprint
        or runtime.authorization_window_seconds
        != runtime_authorization.authorization_window_seconds
        or runtime.vm_image_sha256 != runtime_authorization.vm_image_sha256
        or runtime.opend_version != runtime_authorization.opend_version
        or runtime.opend_server_version != supply_chain.opend_server_version
        or runtime.opend_server_build_no != supply_chain.opend_server_build_no
        or runtime.allowed_protocol_ids != runtime_authorization.allowed_protocol_ids
        or runtime.quarantined
        or to_json_value(runtime.checkpoints[0]) != boot["startup_checkpoint"]
    ):
        raise FutuSidecarError("attested runtime receipt changed its pre-run authorization")
    runtime_started = _utc_datetime(runtime.started_at, "runtime started_at")
    runtime_ended = _utc_datetime(runtime.ended_at, "runtime ended_at")
    authorization_valid_from = _utc_datetime(
        runtime_authorization.valid_from, "runtime authorization valid_from"
    )
    authorization_expires = _utc_datetime(
        runtime_authorization.expires_at, "runtime authorization expires_at"
    )
    if not authorization_valid_from <= runtime_started <= runtime_ended < authorization_expires:
        raise FutuSidecarError("attested runtime escaped its one-session authority window")
    executions = tuple(expected_executions)
    plan_position, plan_page_index = _replay_executions_against_request_plan(
        executions,
        runtime_authorization,
    )
    conditional_disposition = _conditional_plan_disposition(
        runtime_authorization=runtime_authorization,
        plan_position=plan_position,
        plan_page_index=plan_page_index,
        skipped_conclusion=finalization.skipped_conditional_conclusion,
    )
    _validate_execution_attestation(
        execution,
        run_id=runtime.run_id,
        session_id=finalization.boot_attestation.session_id,
        boot_receipt_id=finalization.boot_attestation.receipt_id,
        supply_chain=supply_chain,
        runtime_receipt=runtime,
        expected_records=_expected_execution_attestation_records(executions),
        expected_conditional_disposition=conditional_disposition,
    )


def load_futu_attested_session_finalization(
    payload: Mapping[str, Any],
    *,
    expected_executions: Sequence[FutuSidecarExecution],
    supply_chain: FutuSupplyChainReceipt,
    runtime_authorization: FutuRuntimeIsolationAuthorization,
    verifier: SignatureVerifier,
    skipped_conditional_conclusion: FutuFrozenConclusionReceipt | None = None,
) -> FutuAttestedSessionFinalization:
    """Strictly reconstruct and replay a signed WIRE v3 finalization object."""
    values = _exact_members(
        payload,
        {"boot_attestation", "runtime_receipt", "execution_attestation"},
        "attested sidecar finalization",
    )
    boot_payload = _exact_members(
        values["boot_attestation"],
        _BOOT_ATTESTATION_FIELDS,
        "sidecar boot attestation",
    )
    runtime_payload = _exact_members(
        values["runtime_receipt"],
        set(load_futu_schema_fields("futu-runtime-isolation-receipt")),
        "sidecar runtime receipt",
    )
    execution_payload = _exact_members(
        values["execution_attestation"],
        _EXECUTION_ATTESTATION_FIELDS,
        "sidecar execution attestation",
    )
    runtime = load_futu_signed_receipt(
        "futu-runtime-isolation-receipt", runtime_payload
    )
    if type(runtime) is not FutuRuntimeIsolationReceipt:  # pragma: no cover - closed map
        raise FutuSidecarError("sidecar finalization runtime type is invalid")
    finalization = FutuAttestedSessionFinalization(
        boot_attestation=FutuSidecarBootAttestation(freeze(boot_payload)),
        runtime_receipt=runtime,
        execution_attestation=FutuSidecarExecutionAttestation(freeze(execution_payload)),
        skipped_conditional_conclusion=skipped_conditional_conclusion,
    )
    validate_futu_attested_session_finalization(
        finalization,
        expected_executions=expected_executions,
        supply_chain=supply_chain,
        runtime_authorization=runtime_authorization,
        verifier=verifier,
    )
    return finalization


def load_futu_sidecar_boot_attestation(
    payload: Mapping[str, Any],
    *,
    supply_chain: FutuSupplyChainReceipt,
    runtime_authorization: FutuRuntimeIsolationAuthorization,
    verifier: SignatureVerifier,
    expected_signer_key_id: str,
) -> FutuSidecarBootAttestation:
    """Strictly load a signed boot receipt for replay or bounded host tests."""
    boot_payload = _exact_members(
        payload,
        _BOOT_ATTESTATION_FIELDS,
        "sidecar boot attestation",
    )
    _verify_signed_sidecar_object(
        boot_payload,
        verifier=verifier,
        expected_signer_key_id=expected_signer_key_id,
    )
    _validate_boot_attestation(
        boot_payload,
        run_id=runtime_authorization.run_id,
        session_id=boot_payload["session_id"],
        challenge_nonce=boot_payload["challenge_nonce"],
        supply_chain=supply_chain,
        runtime_authorization=runtime_authorization,
    )
    boot_issued = _utc_datetime(boot_payload["issued_at"], "boot issued_at")
    startup_observed = _utc_datetime(
        boot_payload["startup_checkpoint"]["observed_at"],
        "startup observed_at",
    )
    authorized_from = _utc_datetime(runtime_authorization.valid_from, "valid_from")
    authorization_expires = _utc_datetime(
        runtime_authorization.expires_at,
        "runtime authorization expires_at",
    )
    if not authorized_from <= startup_observed <= boot_issued < authorization_expires:
        raise FutuSidecarError("sidecar boot chronology is outside runtime authorization")
    return FutuSidecarBootAttestation(freeze(boot_payload))


def load_futu_schema_fields(schema_name: str) -> tuple[str, ...]:
    from .futu_receipts import load_futu_schema

    schema = load_futu_schema(schema_name)
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise FutuSidecarError("Futu receipt schema has no closed property set")
    return tuple(properties)


@dataclass(frozen=True, slots=True)
class FutuRequestSpec:
    stage: str
    protocol_id: int
    parameters: FrozenMap
    expected_trading_date: str | None = None
    price_blind_freeze_fingerprint: str | None = None
    frozen_conclusion: FutuFrozenConclusionReceipt | None = None

    def __post_init__(self) -> None:
        if self.stage not in _STAGES:
            raise FutuSidecarError(f"unsupported Futu execution stage: {self.stage}")
        object.__setattr__(self, "parameters", freeze(self.parameters))
        _validate_parameters(self.protocol_id, self.parameters, self.expected_trading_date)
        if (self.stage == "runtime_authority") != (self.protocol_id == 3104):
            raise FutuSidecarError(
                "runtime-authority request specs are reserved for protocol 3104"
            )
        if self.stage == "market_reference" and self.expected_trading_date is None:
            raise FutuSidecarError("market-reference request requires expected_trading_date")
        if (
            self.stage == "peer_comparable_reference"
            and self.protocol_id == 3103
            and self.expected_trading_date is None
        ):
            raise FutuSidecarError("peer daily-close request requires expected_trading_date")
        if (
            self.expected_trading_date is not None
            and not (
                self.stage == "market_reference"
                or (self.stage == "peer_comparable_reference" and self.protocol_id == 3103)
            )
        ):
            raise FutuSidecarError("expected_trading_date is valid only for market reference")
        if self.stage in {"post_valuation_context", "peer_comparable_reference"}:
            if self.price_blind_freeze_fingerprint is None:
                raise FutuSidecarError(
                    "post-freeze Futu request requires a price-blind freeze fingerprint"
                )
            _require_sha256(
                self.price_blind_freeze_fingerprint,
                "price_blind_freeze_fingerprint",
            )
        elif self.price_blind_freeze_fingerprint is not None:
            raise FutuSidecarError(
                "price_blind_freeze_fingerprint is valid only after valuation freeze"
            )
        if (self.frozen_conclusion is not None) != (
            self.stage == "post_valuation_context"
        ):
            raise FutuSidecarError(
                "only post-valuation requests may retain a frozen conclusion receipt"
            )
        if self.frozen_conclusion is not None and type(
            self.frozen_conclusion
        ) is not FutuFrozenConclusionReceipt:
            raise FutuSidecarError("frozen conclusion must use the exact receipt type")
        if self.expected_trading_date is not None:
            try:
                date.fromisoformat(self.expected_trading_date)
            except ValueError as exc:
                raise FutuSidecarError("expected_trading_date must be an ISO date") from exc


@dataclass(frozen=True, slots=True)
class FutuSidecarExecution:
    bundle: FutuEvidenceBundle
    requests: tuple[FutuDataRequestReceipt, ...]
    responses: tuple[FutuDataResponseReceipt, ...]
    observations: tuple[FutuObservation, ...]
    history_quota: FutuHistoricalKlineQuotaReceipt | None = None

    def __post_init__(self) -> None:
        quota_requests = tuple(item for item in self.requests if item.protocol_id == 3104)
        if self.history_quota is None:
            if quota_requests and self.bundle.status == "complete":
                raise FutuSidecarError("protocol 3104 execution lacks its typed quota receipt")
            return
        if type(self.history_quota) is not FutuHistoricalKlineQuotaReceipt:
            raise FutuSidecarError("history quota has the wrong exact receipt type")
        if len(quota_requests) != 1 or self.requests[0] != quota_requests[0]:
            raise FutuSidecarError("protocol 3104 must be the first and only quota request")
        quota_request = quota_requests[0]
        response_by_request = {item.request_id: item for item in self.responses}
        quota_response = response_by_request.get(quota_request.request_id)
        if (
            quota_request.stage != "runtime_authority"
            or quota_request.parameters != FrozenMap({"get_detail": True})
            or quota_response is None
            or quota_response.status != "completed"
            or self.history_quota.run_id != self.bundle.run_id
            or self.history_quota.source_request_fingerprint != quota_request.fingerprint
            or self.history_quota.source_response_fingerprint != quota_response.fingerprint
        ):
            raise FutuSidecarError("typed history quota is rebound from its execution")
        replayed = _build_history_quota_receipt(
            request=quota_request,
            response=quota_response,
            observations=tuple(
                item
                for item in self.observations
                if item.response_fingerprint == quota_response.fingerprint
            ),
            account_scope_sha256=self.history_quota.account_scope_sha256,
            runtime_authorization_fingerprint=(
                self.history_quota.runtime_authorization_fingerprint
            ),
            runtime_request_plan=self.history_quota.runtime_request_plan,
            request_plan_fingerprint=self.history_quota.request_plan_fingerprint,
        )
        if replayed.to_dict() != self.history_quota.to_dict():
            raise FutuSidecarError("typed history quota no longer replays from retained evidence")


def validate_futu_execution_replay(
    execution: FutuSidecarExecution,
    *,
    authority: FutuAuthorityDecision,
    security_identity: FutuSecurityIdentityReceipt,
    supply_chain: FutuSupplyChainReceipt,
) -> None:
    """Validate a cached public object graph under current replay authority."""
    bundle = execution.bundle
    if authority.status != "eligible":
        raise FutuSidecarError("cache replay requires current eligible authority")
    if bundle.authority_decision_fingerprint != authority.fingerprint:
        raise FutuSidecarError("cached bundle is bound to a different authority decision")
    if authority.security_identity_fingerprint != security_identity.fingerprint:
        raise FutuSidecarError("cached execution security identity is not currently authorized")
    if authority.receipt_fingerprints.get("supply_chain") != supply_chain.fingerprint:
        raise FutuSidecarError("cached execution supply chain is not currently authorized")
    if bundle.run_id != authority.run_id:
        raise FutuSidecarError("cached bundle run does not match replay authority")
    if (
        bundle.issuer_id != security_identity.issuer_id
        or bundle.security_id != security_identity.security_id
    ):
        raise FutuSidecarError("cached bundle security scope is invalid")
    if len(execution.requests) * 3 > MAXIMUM_OPERATIONS_PER_RUN:
        raise FutuSidecarError("cached execution exceeds the operation-count limit")
    if execution.history_quota is not None and (
        execution.history_quota.runtime_authorization_fingerprint
        != authority.receipt_fingerprints.get("runtime_authorization")
    ):
        raise FutuSidecarError("cached history quota is bound to another runtime authority")

    expected_request_refs = tuple(
        _reference(item.request_id, item.fingerprint) for item in execution.requests
    )
    expected_response_refs = tuple(
        _reference(item.response_id, item.fingerprint) for item in execution.responses
    )
    expected_observation_refs = tuple(
        _reference(item.observation_id, item.fingerprint) for item in execution.observations
    )
    if to_json_value(bundle.requests) != list(expected_request_refs):
        raise FutuSidecarError("cached request references do not match the bundle")
    if to_json_value(bundle.responses) != list(expected_response_refs):
        raise FutuSidecarError("cached response references do not match the bundle")
    if to_json_value(bundle.observations) != list(expected_observation_refs):
        raise FutuSidecarError("cached observation references do not match the bundle")
    if bundle.cross_checks:
        raise FutuSidecarError("sidecar replay validates the pre-cross-check base bundle only")

    registry = load_protocol_registry()
    request_by_id: dict[str, FutuDataRequestReceipt] = {}
    prior_request: FutuDataRequestReceipt | None = None
    prior_response: FutuDataResponseReceipt | None = None
    for request in execution.requests:
        if request.request_id in request_by_id:
            raise FutuSidecarError("cached execution contains a duplicate request")
        request_by_id[request.request_id] = request
        protocol = registry.get(request.protocol_id)
        if (
            protocol is None
            or not _protocol_allowed_in_stage(request.protocol_id, protocol["stage"], request.stage)
            or protocol["name"] != request.protocol_name
            or protocol["data_family"] != request.data_family
        ):
            raise FutuSidecarError("cached request is outside the protocol registry")
        if (
            request.authority_decision_fingerprint != authority.fingerprint
            or request.security_identity_fingerprint != security_identity.fingerprint
            or request.issuer_id != security_identity.issuer_id
            or request.security_id != security_identity.security_id
            or request.run_id != bundle.run_id
            or (
                request.stage != bundle.stage
                and not (
                    bundle.stage == "valuation_pre_price_verification"
                    and request.protocol_id == 3104
                    and request.stage == "runtime_authority"
                )
            )
        ):
            raise FutuSidecarError("cached request identity is not bound to the bundle")
        if request.page_index == 0:
            if request.previous_page_key_sha256 is not None:
                raise FutuSidecarError("first cached page cannot bind a previous page key")
        elif (
            prior_request is None
            or prior_request.protocol_id != request.protocol_id
            or prior_request.page_index + 1 != request.page_index
            or prior_response is None
            or prior_response.request_id not in request_by_id
            or prior_response.next_key_sha256 != request.previous_page_key_sha256
        ):
            raise FutuSidecarError("cached pagination chain is incomplete")
        prior_request = request
        prior_response = next(
            (
                response
                for response in execution.responses
                if response.request_id == request.request_id
            ),
            None,
        )

    seen_response_ids: set[str] = set()
    response_fingerprints: set[str] = set()
    response_protocols: dict[str, int] = {}
    responses_by_fingerprint: dict[str, FutuDataResponseReceipt] = {}
    cumulative_raw_bytes = 0
    for response in execution.responses:
        request = request_by_id.get(response.request_id)
        if request is None or response.request_fingerprint != request.fingerprint:
            raise FutuSidecarError("cached response is not bound to a cached request")
        if response.response_id in seen_response_ids:
            raise FutuSidecarError("cached execution contains a duplicate response")
        seen_response_ids.add(response.response_id)
        response_fingerprints.add(response.fingerprint)
        response_protocols[response.fingerprint] = request.protocol_id
        responses_by_fingerprint[response.fingerprint] = response
        if response.run_id != bundle.run_id or response.page_index != request.page_index:
            raise FutuSidecarError("cached response run or page identity is invalid")
        if response.parser_sha256 != supply_chain.parser_sha256:
            raise FutuSidecarError("cached response parser is outside the supply-chain receipt")
        if (
            response.pre_global_state_request_fingerprint
            != _global_state_request_fingerprint(request, "pre")
            or response.post_global_state_request_fingerprint
            != _global_state_request_fingerprint(request, "post")
        ):
            raise FutuSidecarError("cached response GlobalState binding is invalid")
        cumulative_raw_bytes += response.raw_byte_count
    if cumulative_raw_bytes > MAXIMUM_RAW_BYTES_PER_RUN:
        raise FutuSidecarError("cached execution exceeds the cumulative raw-byte limit")

    seen_observations: set[str] = set()
    for observation in execution.observations:
        if observation.observation_id in seen_observations:
            raise FutuSidecarError("cached execution contains a duplicate observation")
        seen_observations.add(observation.observation_id)
        if observation.response_fingerprint not in response_fingerprints:
            raise FutuSidecarError("cached observation is not bound to a cached response")
        if (
            observation.issuer_id != bundle.issuer_id
            or observation.security_id != bundle.security_id
            or (
                observation.use_scope != bundle.stage
                and not (
                    bundle.stage == "valuation_pre_price_verification"
                    and observation.data_family == "historical_kline_quota"
                    and observation.use_scope == "runtime_authority"
                )
            )
        ):
            raise FutuSidecarError("cached observation identity is not bound to the bundle")
    observations_by_response: dict[str, list[FutuObservation]] = {}
    for observation in execution.observations:
        observations_by_response.setdefault(observation.response_fingerprint, []).append(
            observation
        )
    for response_fingerprint, response in responses_by_fingerprint.items():
        request = request_by_id[response.request_id]
        wire_projection = tuple(
            _wire_observation_projection(item)
            for item in observations_by_response.get(response_fingerprint, ())
        )
        if request.protocol_id == 3228:
            _prepare_revenue_breakdown_wire_observations(wire_projection)
        elif request.protocol_id == 3234:
            _prepare_dividend_wire_observations(wire_projection)
        elif request.protocol_id == 3236:
            _prepare_split_wire_observations(
                wire_projection,
                request=request,
                terminal=response.terminal,
            )
    if 3236 in response_protocols.values():
        _validate_split_execution_observations(
            tuple(
                item
                for item in execution.observations
                if response_protocols[item.response_fingerprint] == 3236
            )
        )
    if bundle.status == "complete" and (
        bundle.issues or any(response.status != "completed" for response in execution.responses)
    ):
        raise FutuSidecarError("cached complete bundle contains an incomplete response")


@dataclass(frozen=True, slots=True)
class FutuDailyCloseAdapterResult:
    schema_version: str
    issuer_id: str
    security_id: str
    trading_date: str
    close_decimal: str
    currency: str
    market_reference_basis: str
    source_observation_id: str
    source_observation_fingerprint: str
    source_request_fingerprint: str
    semantics_evidence_fingerprint: str
    adapter_fingerprint: str

    def __post_init__(self) -> None:
        if self.schema_version != FUTU_SCHEMA_VERSION:
            raise FutuSidecarError("daily-close adapter schema version is invalid")
        if self.market_reference_basis != "official_unadjusted_close":
            raise FutuSidecarError("daily-close adapter cannot choose another price basis")
        _require_sha256(self.adapter_fingerprint, "adapter_fingerprint")
        payload = self.to_dict()
        payload.pop("adapter_fingerprint")
        if self.adapter_fingerprint != canonical_sha256(payload):
            raise FutuSidecarError("daily-close adapter fingerprint is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "issuer_id": self.issuer_id,
            "security_id": self.security_id,
            "trading_date": self.trading_date,
            "close_decimal": self.close_decimal,
            "currency": self.currency,
            "market_reference_basis": self.market_reference_basis,
            "source_observation_id": self.source_observation_id,
            "source_observation_fingerprint": self.source_observation_fingerprint,
            "source_request_fingerprint": self.source_request_fingerprint,
            "semantics_evidence_fingerprint": self.semantics_evidence_fingerprint,
            "adapter_fingerprint": self.adapter_fingerprint,
        }


@cache
def load_protocol_registry() -> Mapping[int, FrozenMap]:
    payload = _read_resource_json("protocol-registry-v1.json")
    if set(payload) != {"protocols", "registry_id", "registry_version"}:
        raise FutuSidecarError("protocol registry has an unexpected member set")
    if payload["registry_id"] != "futu-quote-only-protocol-registry":
        raise FutuSidecarError("protocol registry ID is invalid")
    protocols: dict[int, FrozenMap] = {}
    for item in payload["protocols"]:
        base_fields = {
            "data_family",
            "market_scope",
            "name",
            "protocol_id",
            "required_for_complete",
            "stage",
        }
        if not isinstance(item, dict) or set(item) not in {
            frozenset(base_fields),
            frozenset(
                {
                    *base_fields,
                    "us_product_disposition",
                    "us_reason_code",
                    "us_primary_authority",
                }
            ),
        }:
            raise FutuSidecarError("protocol registry entry is invalid")
        protocol_id = item["protocol_id"]
        if type(protocol_id) is not int or protocol_id in protocols:
            raise FutuSidecarError("protocol registry IDs must be unique integers")
        if protocol_id != GLOBAL_STATE_PROTOCOL_ID and protocol_id not in _PARAMETER_KEYS:
            raise FutuSidecarError("protocol registry is broader than the host parameter allowlist")
        if not isinstance(item["name"], str) or (
            protocol_id == GLOBAL_STATE_PROTOCOL_ID
            and item["name"] != "GetGlobalState"
        ):
            raise FutuSidecarError("protocol registry operation name is invalid")
        market_scope = item["market_scope"]
        if (
            not isinstance(market_scope, list)
            or not market_scope
            or any(not isinstance(mic, str) or not mic for mic in market_scope)
            or len(set(market_scope)) != len(market_scope)
        ):
            raise FutuSidecarError("protocol registry market scope is invalid")
        protocols[protocol_id] = freeze(item)
    if set(protocols) != {GLOBAL_STATE_PROTOCOL_ID, *_PARAMETER_KEYS}:
        raise FutuSidecarError("protocol registry does not exactly match the quote-only allowlist")
    if protocols[GLOBAL_STATE_PROTOCOL_ID]["stage"] != "runtime_authority":
        raise FutuSidecarError("GetGlobalState must remain an internal runtime authority operation")
    if set(protocols[3235]["market_scope"]).intersection({"XNAS", "XNYS"}):
        raise FutuSidecarError("Futu buyback protocol cannot be enabled for the US product")
    if (
        set(protocols[3235])
        != {
            *base_fields,
            "us_product_disposition",
            "us_reason_code",
            "us_primary_authority",
        }
        or protocols[3235]["us_product_disposition"] != "not_supported"
        or protocols[3235]["us_reason_code"] != "sec_primary_us_buyback"
        or protocols[3235]["us_primary_authority"] != "SEC_IR"
        or any(
            "us_product_disposition" in protocol
            for protocol_id, protocol in protocols.items()
            if protocol_id != 3235
        )
    ):
        raise FutuSidecarError("US buyback disposition is not explicit and closed")
    authority_sources = _load_interface_authority_registry()
    if set(authority_sources) != set(protocols):
        raise FutuSidecarError("official interface authority does not cover every protocol")
    sdk_adapters = load_sdk_adapter_registry()
    if set(sdk_adapters) != set(protocols):
        raise FutuSidecarError("pinned SDK adapter registry does not cover every protocol")
    for protocol_id, protocol in protocols.items():
        source = authority_sources[protocol_id]
        if (
            source["protocol_name"] != protocol["name"]
            or source["market_scope"] != protocol["market_scope"]
        ):
            raise FutuSidecarError("official interface authority is rebound to another protocol")
    return MappingProxyType(protocols)


@cache
def _load_interface_authority_registry() -> Mapping[int, FrozenMap]:
    payload = _read_resource_json("interface-authority-registry-v1.json")
    if set(payload) != {"registry_id", "registry_version", "sources"}:
        raise FutuSidecarError("interface authority registry has an unexpected member set")
    if (
        payload["registry_id"] != "futu-official-interface-authority"
        or payload["registry_version"] != "1.0.0"
    ):
        raise FutuSidecarError("interface authority registry identity is invalid")
    sources: dict[int, FrozenMap] = {}
    for item in payload["sources"]:
        if not isinstance(item, dict) or set(item) != {
            "html_sha256",
            "market_scope",
            "protocol_id",
            "protocol_name",
            "retrieved_on",
            "semantic_constraints",
            "url",
        }:
            raise FutuSidecarError("interface authority entry is invalid")
        protocol_id = item["protocol_id"]
        if type(protocol_id) is not int or protocol_id in sources:
            raise FutuSidecarError("interface authority protocol IDs must be unique integers")
        _require_sha256(item["html_sha256"], "official interface HTML SHA-256")
        try:
            date.fromisoformat(item["retrieved_on"])
        except (TypeError, ValueError) as exc:
            raise FutuSidecarError("interface authority retrieval date is invalid") from exc
        if (
            not isinstance(item["url"], str)
            or not item["url"].startswith("https://openapi.futunn.com/")
            or not isinstance(item["protocol_name"], str)
            or not item["protocol_name"]
            or not isinstance(item["market_scope"], list)
            or not item["market_scope"]
            or len(set(item["market_scope"])) != len(item["market_scope"])
            or not isinstance(item["semantic_constraints"], list)
            or not item["semantic_constraints"]
            or any(
                not isinstance(constraint, str) or not constraint.strip()
                for constraint in item["semantic_constraints"]
            )
        ):
            raise FutuSidecarError("interface authority source metadata is invalid")
        sources[protocol_id] = freeze(item)
    return MappingProxyType(sources)


@cache
def load_sdk_adapter_registry() -> Mapping[int, FrozenMap]:
    """Load the exact callable surface of the pinned official Python SDK."""
    try:
        with (_RESOURCE_DIRECTORY / "sdk-adapter-registry-v1.json").open("rb") as handle:
            registry_raw = handle.read(MAXIMUM_RESOURCE_BYTES + 1)
    except OSError as exc:
        raise FutuSidecarError("SDK adapter registry is unavailable") from exc
    if (
        len(registry_raw) > MAXIMUM_RESOURCE_BYTES
        or hashlib.sha256(registry_raw).hexdigest()
        != PINNED_SDK_OPERATION_REGISTRY_SHA256
    ):
        raise FutuSidecarError("SDK adapter registry bytes drifted from the pinned identity")
    payload = _read_resource_json("sdk-adapter-registry-v1.json")
    if set(payload) != {
        "adapters",
        "registry_id",
        "registry_version",
        "sdk_distribution",
    }:
        raise FutuSidecarError("SDK adapter registry has an unexpected member set")
    if (
        payload["registry_id"] != "futu-python-sdk-adapter-registry"
        or payload["registry_version"] != "1.0.0"
    ):
        raise FutuSidecarError("SDK adapter registry identity is invalid")
    distribution = payload["sdk_distribution"]
    if not isinstance(distribution, dict) or set(distribution) != {
        "archive_sha256",
        "open_context_base_sha256",
        "open_quote_context_sha256",
        "package",
        "protobuf_descriptor_set_sha256",
        "version",
    }:
        raise FutuSidecarError("SDK distribution identity is invalid")
    if (
        distribution["package"] != "futu-api"
        or distribution["version"] != PINNED_FUTU_API_VERSION
        or distribution["archive_sha256"]
        != PINNED_FUTU_API_DISTRIBUTION_SHA256
        or distribution["protobuf_descriptor_set_sha256"]
        != PINNED_PROTOBUF_DESCRIPTOR_SET_SHA256
    ):
        raise FutuSidecarError("SDK adapter registry is not pinned to the accepted release")
    for name in (
        "archive_sha256",
        "open_context_base_sha256",
        "open_quote_context_sha256",
        "protobuf_descriptor_set_sha256",
    ):
        _require_sha256(distribution[name], f"SDK distribution {name}")

    expected_fields = {
        "defaulted_parameter_names",
        "generated_descriptor_sha256",
        "host_parameter_names",
        "injected_parameter_names",
        "internal_pagination_parameter",
        "pagination_mode",
        "protocol_id",
        "sdk_method",
        "sdk_parameter_names",
    }
    adapters: dict[int, FrozenMap] = {}
    for item in payload["adapters"]:
        if not isinstance(item, dict) or set(item) != expected_fields:
            raise FutuSidecarError("SDK adapter entry is invalid")
        protocol_id = item["protocol_id"]
        if type(protocol_id) is not int or protocol_id in adapters:
            raise FutuSidecarError("SDK adapter protocol IDs must be unique integers")
        if not isinstance(item["sdk_method"], str) or not item["sdk_method"].strip():
            raise FutuSidecarError("SDK adapter method is invalid")
        _require_sha256(
            item["generated_descriptor_sha256"],
            "SDK generated protocol descriptor SHA-256",
        )
        parameter_groups = (
            item["sdk_parameter_names"],
            item["host_parameter_names"],
            item["injected_parameter_names"],
            item["defaulted_parameter_names"],
        )
        if any(
            not isinstance(group, list)
            or len(group) != len(set(group))
            or any(not isinstance(name, str) or not name for name in group)
            for group in parameter_groups
        ):
            raise FutuSidecarError("SDK adapter parameter list is invalid")
        sdk_parameters, host_parameters, injected, defaulted = map(
            set, parameter_groups
        )
        pagination = item["internal_pagination_parameter"]
        if pagination is not None and (
            not isinstance(pagination, str) or pagination not in sdk_parameters
        ):
            raise FutuSidecarError("SDK adapter pagination binding is invalid")
        claimed = host_parameters | injected | defaulted | ({pagination} if pagination else set())
        if (
            claimed != sdk_parameters
            or sum(
                name in group
                for name in sdk_parameters
                for group in (host_parameters, injected, defaulted, {pagination})
            )
            != len(sdk_parameters)
        ):
            raise FutuSidecarError("SDK adapter parameters are not exactly partitioned")
        if item["pagination_mode"] not in {"none", "internal", "single_page"} or (
            (pagination is None) != (item["pagination_mode"] == "none")
        ):
            raise FutuSidecarError("SDK adapter pagination mode is invalid")
        expected_host = set(_PARAMETER_KEYS.get(protocol_id, ()))
        if host_parameters != expected_host:
            raise FutuSidecarError("SDK adapter host parameters drifted from the allowlist")
        adapters[protocol_id] = freeze(item)
    expected_protocols = {GLOBAL_STATE_PROTOCOL_ID, *_PARAMETER_KEYS}
    if set(adapters) != expected_protocols:
        raise FutuSidecarError("SDK adapter registry is incomplete or over-broad")
    return MappingProxyType(adapters)


def _normalize_financial_display_name(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise FutuSidecarError("financial field display name must be non-empty")
    if len(value.encode("utf-8")) > 512:
        raise FutuSidecarError("financial field display name exceeds the byte limit")
    normalized = " ".join(unicodedata.normalize("NFKC", value).casefold().split())
    if not normalized:
        raise FutuSidecarError("financial field display name has no normalized identity")
    return normalized


@cache
def _load_packaged_financial_field_registry_payload() -> dict[str, Any]:
    return json.loads(
        canonical_json(_read_resource_json("financial-field-registry-v1.json"))
    )


@cache
def _load_packaged_financial_field_registry() -> Mapping[str, FrozenMap]:
    return _validate_financial_field_registry_payload(
        _load_packaged_financial_field_registry_payload()
    )


def load_financial_field_registry() -> Mapping[str, FrozenMap]:
    admitted = _ADMITTED_FINANCIAL_FIELD_REGISTRY.get()
    if admitted is not None:
        return admitted
    return _load_packaged_financial_field_registry()


@contextmanager
def reviewed_financial_field_registry_scope(
    registry: Mapping[str, FrozenMap],
):
    token = _ADMITTED_FINANCIAL_FIELD_REGISTRY.set(registry)
    try:
        yield
    finally:
        _ADMITTED_FINANCIAL_FIELD_REGISTRY.reset(token)


def load_reviewed_financial_field_registry(
    *,
    execution: FutuSidecarExecution,
    admission_payload: Mapping[str, Any] | None,
) -> Mapping[str, FrozenMap]:
    if admission_payload is None:
        return _load_packaged_financial_field_registry()
    payload = _exact_members(
        admission_payload,
        {
            "futu_api_version",
            "market",
            "mappings",
            "registry_id",
            "registry_version",
        },
        "reviewed financial field admission",
    )
    if (
        payload["registry_id"] != "futu-reviewed-financial-field-admission"
        or payload["registry_version"] != "1.0.0"
        or payload["futu_api_version"] != PINNED_FUTU_API_VERSION
        or not isinstance(payload["market"], str)
        or not payload["market"].isascii()
        or not payload["market"].isupper()
        or not payload["market"]
    ):
        raise FutuSidecarError("reviewed financial field admission identity is invalid")
    raw_mappings = payload["mappings"]
    if not isinstance(raw_mappings, list) or not raw_mappings:
        raise FutuSidecarError("reviewed financial field admission mappings are invalid")
    request_by_id = {item.request_id: item for item in execution.requests}
    market_values = {
        item.value
        for item in execution.observations
        if item.field_id == "vendor_security_market" and isinstance(item.value, str)
    }
    if market_values != {payload["market"]}:
        raise FutuSidecarError("reviewed financial field admission identity is invalid")
    observations_by_response: dict[str, tuple[FutuObservation, ...]] = {}
    for response in execution.responses:
        observations_by_response[response.fingerprint] = tuple(
            item
            for item in execution.observations
            if item.response_fingerprint == response.fingerprint
        )
    admitted_mappings: list[dict[str, Any]] = []
    for raw_item in raw_mappings:
        item = _exact_members(
            raw_item,
            {
                "accounting_standard_scope",
                "canonical_concept",
                "display_name",
                "field_id",
                "source_raw_plaintext_sha256",
                "statement_type",
            },
            "reviewed financial field admission mapping",
        )
        field_id = item["field_id"]
        statement_type = item["statement_type"]
        display_name = item["display_name"]
        accounting_standard = item["accounting_standard_scope"]
        concept = item["canonical_concept"]
        source_hash = item["source_raw_plaintext_sha256"]
        if (
            not isinstance(field_id, str)
            or not field_id.isascii()
            or not field_id.isdecimal()
            or str(int(field_id)) != field_id
            or not isinstance(statement_type, str)
            or statement_type not in {"income", "balance_sheet", "cash_flow"}
            or not isinstance(accounting_standard, str)
            or not accounting_standard
            or accounting_standard != accounting_standard.strip()
            or not isinstance(concept, str)
            or concept not in _CRITICAL_FINANCIAL_CONCEPTS.get(statement_type, ())
            or not isinstance(display_name, str)
            or display_name != display_name.strip()
            or not display_name
            or not isinstance(source_hash, str)
            or _HEX_64.fullmatch(source_hash) is None
        ):
            raise FutuSidecarError("reviewed financial field admission mapping is invalid")
        normalized_display_name = _normalize_financial_display_name(display_name)
        expected_period_kind = "stock" if statement_type == "balance_sheet" else "flow"
        source_matches = [
            (request, response)
            for response in execution.responses
            if response.status == "completed"
            and response.qot_logined
            and response.raw_plaintext_sha256 == source_hash
            for request in (request_by_id.get(response.request_id),)
            if request is not None
            and request.protocol_id == 3227
            and request.parameters.get("statement_type")
            == {
                "income": 1,
                "balance_sheet": 2,
                "cash_flow": 3,
            }[statement_type]
        ]
        if len(source_matches) != 1:
            raise FutuSidecarError(
                "reviewed financial field admission source response does not replay"
            )
        request, response = source_matches[0]
        source_observations = observations_by_response.get(response.fingerprint, ())
        descriptors = [
            item
            for item in source_observations
            if item.field_id == f"{_FINANCIAL_STRUCTURE_PREFIX}{field_id}"
        ]
        values = [item for item in source_observations if item.field_id == field_id]
        if len(descriptors) != 1 or not values:
            raise FutuSidecarError(
                "reviewed financial field admission does not match captured structureList evidence"
            )
        descriptor = descriptors[0]
        if (
            descriptor.data_family != "financial_statements"
            or descriptor.value != display_name
            or descriptor.qualifiers.get("financial_field_id") != field_id
            or descriptor.qualifiers.get("futu_api_version") != payload["futu_api_version"]
            or descriptor.qualifiers.get("normalized_display_name")
            != normalized_display_name
            or descriptor.qualifiers.get("statement_type") != statement_type
        ):
            raise FutuSidecarError(
                "reviewed financial field admission does not match captured structureList evidence"
            )
        if any(
            item.data_family != "financial_statements"
            or item.unit != "currency_units"
            or item.qualifiers.get("accounting_standard") != accounting_standard
            or item.qualifiers.get("futu_api_version") != payload["futu_api_version"]
            or item.qualifiers.get("normalized_financial_field_display_name")
            != normalized_display_name
            or item.qualifiers.get("statement_type") != statement_type
            or item.qualifiers.get("period_kind") != expected_period_kind
            for item in values
        ):
            raise FutuSidecarError(
                "reviewed financial field admission does not match captured structureList evidence"
            )
        admitted_mappings.append(
            {
                "accounting_standard_scope": accounting_standard,
                "canonical_concept": concept,
                "data_family": "financial_statements",
                "field_id": field_id,
                "futu_api_version": payload["futu_api_version"],
                "materiality_tier": "kernel_required",
                "normalized_display_name": normalized_display_name,
                "period_kind": expected_period_kind,
                "sign_convention": "reported_signed",
                "statement_type": statement_type,
                "unit": "currency_units",
            }
        )
    merged_payload = dict(_load_packaged_financial_field_registry_payload())
    merged_payload["mappings"] = [
        *merged_payload["mappings"],
        *admitted_mappings,
    ]
    return _validate_financial_field_registry_payload(merged_payload)


def _validate_financial_field_registry_payload(
    payload: dict[str, Any],
) -> Mapping[str, FrozenMap]:
    if set(payload) != {
        "critical_concepts",
        "mappings",
        "registry_id",
        "registry_version",
        "unknown_field_policy",
        "unmapped_critical_concept_policy",
    }:
        raise FutuSidecarError("financial field registry has an unexpected member set")
    if (
        payload["unknown_field_policy"] != "not_comparable"
        or payload["unmapped_critical_concept_policy"]
        != "block_before_price_blind_refreeze"
        or payload["critical_concepts"]
        != {key: list(values) for key, values in _CRITICAL_FINANCIAL_CONCEPTS.items()}
    ):
        raise FutuSidecarError("financial field registry must fail closed on unknown fields")
    if (
        payload["registry_id"] != "futu-financial-field-registry"
        or payload["registry_version"] != "1.0.0"
        or not isinstance(payload["mappings"], list)
    ):
        raise FutuSidecarError("financial field registry identity is invalid")
    mappings: dict[str, FrozenMap] = {}
    statement_concepts: set[tuple[str, str]] = set()
    for item in payload["mappings"]:
        if not isinstance(item, dict) or set(item) != {
            "accounting_standard_scope",
            "canonical_concept",
            "data_family",
            "field_id",
            "futu_api_version",
            "materiality_tier",
            "normalized_display_name",
            "period_kind",
            "sign_convention",
            "statement_type",
            "unit",
        }:
            raise FutuSidecarError("financial field mapping is invalid")
        field_id = item["field_id"]
        statement_type = item["statement_type"]
        period_kind = item["period_kind"]
        concept = item["canonical_concept"]
        materiality_tier = item["materiality_tier"]
        if (
            not isinstance(field_id, str)
            or not field_id.isascii()
            or not field_id.isdecimal()
            or str(int(field_id)) != field_id
            or not isinstance(concept, str)
            or not concept
            or len(concept.encode("utf-8")) > 128
            or item["accounting_standard_scope"] != "US_GAAP"
            or item["data_family"] != "financial_statements"
            or item["futu_api_version"] != PINNED_FUTU_API_VERSION
            or not isinstance(item["normalized_display_name"], str)
            or _normalize_financial_display_name(item["normalized_display_name"])
            != item["normalized_display_name"]
            or statement_type not in {"income", "balance_sheet", "cash_flow"}
            or period_kind
            != ("stock" if statement_type == "balance_sheet" else "flow")
            or item["sign_convention"] != "reported_signed"
            or item["unit"] != "currency_units"
            or materiality_tier not in {"kernel_required", "context_only"}
        ):
            raise FutuSidecarError("financial field mapping semantics are invalid")
        critical_statement = next(
            (
                name
                for name, concepts in _CRITICAL_FINANCIAL_CONCEPTS.items()
                if concept in concepts
            ),
            None,
        )
        if critical_statement is not None and (
            statement_type != critical_statement or materiality_tier != "kernel_required"
        ):
            raise FutuSidecarError(
                "critical financial mapping has the wrong statement or materiality"
            )
        statement_concept = (statement_type, concept)
        if field_id in mappings or statement_concept in statement_concepts:
            raise FutuSidecarError(
                "financial field IDs and statement concepts must be unique"
            )
        mappings[field_id] = freeze(item)
        statement_concepts.add(statement_concept)
    if not mappings:
        raise FutuSidecarError("financial field registry cannot be empty")
    return MappingProxyType(mappings)


def load_critical_financial_concepts() -> Mapping[str, tuple[str, ...]]:
    """Return the closed concepts that must have reviewed vendor mappings before refreeze."""

    load_financial_field_registry()
    return _CRITICAL_FINANCIAL_CONCEPTS


@cache
def load_issue_codes() -> frozenset[str]:
    payload = _read_resource_json("issue-code-registry-v1.json")
    if set(payload) != {"issue_codes", "registry_id", "registry_version"}:
        raise FutuSidecarError("issue registry has an unexpected member set")
    codes = payload["issue_codes"]
    if not isinstance(codes, list) or any(not isinstance(code, str) for code in codes):
        raise FutuSidecarError("issue registry is invalid")
    if len(set(codes)) != len(codes):
        raise FutuSidecarError("issue registry contains duplicate codes")
    return frozenset(codes)


def _read_resource_json(name: str) -> dict[str, Any]:
    try:
        with (_RESOURCE_DIRECTORY / name).open("rb") as handle:
            raw = handle.read(MAXIMUM_RESOURCE_BYTES + 1)
    except OSError as exc:
        raise FutuSidecarError(f"Futu resource is unavailable: {name}") from exc
    if len(raw) > MAXIMUM_RESOURCE_BYTES:
        raise FutuSidecarError(f"Futu resource exceeds byte limit: {name}")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FutuSidecarError(f"Futu resource is invalid JSON: {name}") from exc
    if not isinstance(payload, dict):
        raise FutuSidecarError(f"Futu resource must be an object: {name}")
    return payload


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FutuSidecarError(f"duplicate JSON member is forbidden: {key}")
        result[key] = value
    return result


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None:
        raise FutuSidecarError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _utc_datetime(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise FutuSidecarError(f"{label} must be a date-time string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FutuSidecarError(f"{label} must be an RFC 3339 date-time") from exc
    if parsed.tzinfo is None:
        raise FutuSidecarError(f"{label} must include a UTC offset")
    return parsed.astimezone(UTC)


def _exact_members(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise FutuSidecarError(f"{label} has an unexpected member set")
    return value


def _plain_json_value(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 8:
        raise FutuSidecarError(f"{label} exceeds maximum nesting depth")
    if value is None or isinstance(value, (str, bool)) or type(value) is int:
        return
    if isinstance(value, list):
        if len(value) > 128:
            raise FutuSidecarError(f"{label} contains too many values")
        for index, item in enumerate(value):
            _plain_json_value(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 64:
            raise FutuSidecarError(f"{label} contains too many members")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise FutuSidecarError(f"{label} contains an invalid member name")
            normalized = re.sub(r"[^a-z]", "", key.lower())
            if normalized in _FORBIDDEN_EXACT_KEYS or any(
                part in normalized for part in _FORBIDDEN_KEY_PARTS
            ):
                raise FutuSidecarError(f"{label} contains a forbidden capability key")
            _plain_json_value(item, f"{label}.{key}", depth=depth + 1)
        return
    raise FutuSidecarError(f"{label} contains a non-JSON or floating-point value")


def _validate_parameters(
    protocol_id: int,
    parameters: Mapping[str, Any],
    expected_trading_date: str | None,
) -> None:
    registry = load_protocol_registry()
    if protocol_id == GLOBAL_STATE_PROTOCOL_ID or protocol_id not in registry:
        raise FutuSidecarError("caller cannot request this protocol")
    materialized = to_json_value(parameters)
    if not isinstance(materialized, dict):
        raise FutuSidecarError("Futu request parameters must be an object")
    _plain_json_value(materialized, "parameters")
    allowed = _PARAMETER_KEYS[protocol_id]
    if not set(materialized).issubset(allowed):
        raise FutuSidecarError("Futu request contains an unrecognized protocol parameter")
    if protocol_id == 3103:
        expected = {
            "start": expected_trading_date,
            "end": expected_trading_date,
            "ktype": "K_DAY",
            "autype": "NONE",
            "fields": ["CLOSE", "VOLUME"],
            "max_count": 1,
            "extended_time": False,
            "session": "RTH",
        }
        if materialized != expected:
            raise FutuSidecarError(
                "daily close request must be K_DAY/AuType.NONE with Session.RTH"
            )
    elif protocol_id == 3104:
        if materialized != {"get_detail": True}:
            raise FutuSidecarError(
                "history quota request must fetch the complete seven-day detail set"
            )
    elif protocol_id == 3227:
        required = {"statement_type", "financial_type", "currency_code", "num"}
        if set(materialized) != required:
            raise FutuSidecarError("financial-statement parameters must be explicit")
        if (
            type(materialized["statement_type"]) is not int
            or materialized["statement_type"] not in {1, 2, 3, 4}
        ):
            raise FutuSidecarError("financial statement_type is outside the allowlist")
        _validate_financial_page_parameters(materialized)
    elif protocol_id == 3228:
        expected = {"date": 0, "financial_type": 7, "currency_code": "USD"}
        if materialized != expected:
            raise FutuSidecarError(
                "revenue-breakdown snapshot must use latest annual USD parameters"
            )
    elif protocol_id == 3230:
        expected = {"rating_dimension_type": 1, "uid": None, "num": 20}
        if materialized != expected:
            raise FutuSidecarError(
                "rating summary must use the fixed institution-list page request"
            )
    elif protocol_id == 3246:
        if materialized != {"currency_code": "USD", "num": 50}:
            raise FutuSidecarError(
                "operational-efficiency request must use fixed USD pagination"
            )
    elif protocol_id == 3244:
        if materialized:
            raise FutuSidecarError("executive-list request accepts no caller parameters")
    elif protocol_id == 3245:
        if (
            set(materialized) != {"leader_name"}
            or not isinstance(materialized["leader_name"], str)
            or not materialized["leader_name"].strip()
            or len(materialized["leader_name"].encode("utf-8")) > 512
        ):
            raise FutuSidecarError(
                "executive background requires one bounded leader_name pass-back"
            )
    elif materialized:
        raise FutuSidecarError("this quote-only protocol accepts no caller parameters")


def _validate_financial_page_parameters(parameters: Mapping[str, Any]) -> None:
    if parameters["financial_type"] != 7:
        raise FutuSidecarError("financial_type must be the evidenced ANNUAL selector 7")
    if parameters["currency_code"] != "USD":
        raise FutuSidecarError("US valuation cross-check data must be requested in USD")
    if type(parameters["num"]) is not int or not 1 <= parameters["num"] <= 50:
        raise FutuSidecarError("financial vendor page size must be between 1 and 50")


def _blocked_execution(
    *,
    authority: FutuAuthorityDecision,
    run_id: str,
    issuer_id: str,
    security_id: str,
    stage: str,
    status: str,
    issues: Sequence[str],
    requests: Sequence[FutuDataRequestReceipt] = (),
    responses: Sequence[FutuDataResponseReceipt] = (),
    observations: Sequence[FutuObservation] = (),
    history_quota: FutuHistoricalKlineQuotaReceipt | None = None,
) -> FutuSidecarExecution:
    bundle = _make_bundle(
        authority=authority,
        run_id=run_id,
        issuer_id=issuer_id,
        security_id=security_id,
        stage=stage,
        status=status,
        issues=issues,
        requests=requests,
        responses=responses,
        observations=observations,
    )
    return FutuSidecarExecution(
        bundle=bundle,
        requests=tuple(requests),
        responses=tuple(responses),
        observations=tuple(observations),
        history_quota=history_quota,
    )


def execute_futu_plan(
    *,
    transport: FutuSidecarTransport,
    authority: FutuAuthorityDecision,
    runtime_authorization: FutuRuntimeIsolationAuthorization | None = None,
    security_identity: FutuSecurityIdentityReceipt | None,
    supply_chain: FutuSupplyChainReceipt | None,
    run_id: str,
    issuer_id: str,
    security_id: str,
    stage: str,
    data_cutoff_date: str,
    request_started_at: str,
    specs: Sequence[FutuRequestSpec],
) -> FutuSidecarExecution:
    """Execute a bounded quote-only plan with no retry or implicit fallback."""
    if stage not in _STAGES:
        raise FutuSidecarError(f"unsupported Futu execution stage: {stage}")
    if authority.run_id != run_id:
        return _blocked_execution(
            authority=authority,
            run_id=run_id,
            issuer_id=issuer_id,
            security_id=security_id,
            stage=stage,
            status="blocked",
            issues=("account_scope_mismatch",),
        )
    if authority.evaluation_scope != "live_preflight":
        return _blocked_execution(
            authority=authority,
            run_id=run_id,
            issuer_id=issuer_id,
            security_id=security_id,
            stage=stage,
            status="blocked",
            issues=("runtime_isolation_missing",),
        )
    if authority.status != "eligible":
        return _blocked_execution(
            authority=authority,
            run_id=run_id,
            issuer_id=issuer_id,
            security_id=security_id,
            stage=stage,
            status=authority.status,
            issues=authority.issue_codes,
        )
    binding_issues: set[str] = set()
    if runtime_authorization is None:
        binding_issues.add("runtime_isolation_missing")
    elif (
        authority.receipt_fingerprints.get("runtime_authorization")
        != runtime_authorization.fingerprint
        or runtime_authorization.run_id != run_id
    ):
        binding_issues.add("runtime_isolation_missing")
    if security_identity is None:
        binding_issues.add("security_identity_missing")
    elif (
        authority.security_identity_fingerprint != security_identity.fingerprint
        or security_identity.issuer_id != issuer_id
        or security_identity.security_id != security_id
    ):
        binding_issues.add("security_scope_invalid")
    if supply_chain is None:
        binding_issues.add("supply_chain_missing")
    elif authority.receipt_fingerprints.get("supply_chain") != supply_chain.fingerprint:
        binding_issues.add("supply_chain_mismatch")
    if binding_issues:
        return _blocked_execution(
            authority=authority,
            run_id=run_id,
            issuer_id=issuer_id,
            security_id=security_id,
            stage=stage,
            status="blocked",
            issues=tuple(binding_issues),
        )
    assert security_identity is not None
    assert supply_chain is not None
    assert runtime_authorization is not None

    try:
        started_at = _utc_datetime(request_started_at, "request_started_at")
        evaluated_at = _utc_datetime(authority.evaluated_at, "authority evaluated_at")
        authorized_from = _utc_datetime(runtime_authorization.valid_from, "valid_from")
        authorization_expires = _utc_datetime(
            runtime_authorization.expires_at,
            "runtime authorization expires_at",
        )
    except FutuSidecarError:
        return _blocked_execution(
            authority=authority,
            run_id=run_id,
            issuer_id=issuer_id,
            security_id=security_id,
            stage=stage,
            status="blocked",
            issues=("runtime_isolation_missing",),
        )
    if not (authorized_from <= evaluated_at <= started_at < authorization_expires):
        return _blocked_execution(
            authority=authority,
            run_id=run_id,
            issuer_id=issuer_id,
            security_id=security_id,
            stage=stage,
            status="blocked",
            issues=("runtime_isolation_missing",),
        )

    try:
        cutoff = date.fromisoformat(data_cutoff_date)
    except ValueError:
        return _blocked_execution(
            authority=authority,
            run_id=run_id,
            issuer_id=issuer_id,
            security_id=security_id,
            stage=stage,
            status="blocked",
            issues=("expected_trading_date_invalid",),
        )

    plan_specs = tuple(specs)
    mixed_pre_price_plan = (
        stage == "valuation_pre_price_verification"
        and bool(plan_specs)
        and plan_specs[0].stage == "runtime_authority"
        and plan_specs[0].protocol_id == 3104
        and all(
            spec.stage == "valuation_pre_price_verification"
            for spec in plan_specs[1:]
        )
        and all(spec.protocol_id != 3104 for spec in plan_specs[1:])
    )
    if not mixed_pre_price_plan and any(spec.stage != stage for spec in plan_specs):
        return _blocked_execution(
            authority=authority,
            run_id=run_id,
            issuer_id=issuer_id,
            security_id=security_id,
            stage=stage,
            status="blocked",
            issues=("protocol_not_allowed",),
        )
    conclusions = {
        spec.frozen_conclusion.fingerprint
        for spec in plan_specs
        if spec.frozen_conclusion is not None
    }
    if stage == "post_valuation_context":
        conclusion = plan_specs[0].frozen_conclusion if plan_specs else None
        if (
            conclusion is None
            or len(conclusions) != 1
            or any(spec.frozen_conclusion != conclusion for spec in plan_specs)
            or conclusion.run_id != run_id
            or conclusion.issuer_id != issuer_id
            or conclusion.security_id != security_id
            or started_at
            <= _utc_datetime(conclusion.conclusion_frozen_at, "conclusion_frozen_at")
        ):
            return _blocked_execution(
                authority=authority,
                run_id=run_id,
                issuer_id=issuer_id,
                security_id=security_id,
                stage=stage,
                status="blocked",
                issues=("frozen_conclusion_invalid",),
            )
    registry = load_protocol_registry()
    planned_protocols = {spec.protocol_id for spec in plan_specs}
    required_protocols = {
        protocol_id
        for protocol_id, item in registry.items()
        if item["stage"] == stage
        and item["required_for_complete"]
        and security_identity.mic in item["market_scope"]
    }
    if stage == "runtime_authority":
        required_protocols = {3104}
    elif stage == "valuation_pre_price_verification":
        required_protocols.add(3104)
    if stage == "peer_comparable_reference":
        required_protocols = set(_PEER_COMPARABLE_PROTOCOL_IDS)
    if not required_protocols.issubset(planned_protocols):
        return _blocked_execution(
            authority=authority,
            run_id=run_id,
            issuer_id=issuer_id,
            security_id=security_id,
            stage=stage,
            status="blocked",
            issues=("required_protocol_missing",),
        )
    if not planned_protocols.issubset(authority.allowed_protocol_ids):
        return _blocked_execution(
            authority=authority,
            run_id=run_id,
            issuer_id=issuer_id,
            security_id=security_id,
            stage=stage,
            status="blocked",
            issues=("protocol_not_allowed",),
        )
    for spec in plan_specs:
        protocol = registry.get(spec.protocol_id)
        if (
            protocol is None
            or not _protocol_allowed_in_stage(
                spec.protocol_id,
                protocol["stage"],
                spec.stage,
            )
            or security_identity.mic not in protocol["market_scope"]
        ):
            return _blocked_execution(
                authority=authority,
                run_id=run_id,
                issuer_id=issuer_id,
                security_id=security_id,
                stage=stage,
                status="blocked",
                issues=("protocol_not_allowed",),
            )
        if protocol["data_family"] not in authority.allowed_data_families:
            return _blocked_execution(
                authority=authority,
                run_id=run_id,
                issuer_id=issuer_id,
                security_id=security_id,
                stage=stage,
                status="blocked",
                issues=("data_family_not_entitled",),
            )
        if (
            spec.protocol_id == 3103
            and authority.daily_close_semantics_evidence_fingerprint is None
        ):
            return _blocked_execution(
                authority=authority,
                run_id=run_id,
                issuer_id=issuer_id,
                security_id=security_id,
                stage=stage,
                status="blocked",
                issues=("daily_close_semantics_unproven",),
            )
        if spec.expected_trading_date is not None and date.fromisoformat(
            spec.expected_trading_date
        ) > cutoff:
            return _blocked_execution(
                authority=authority,
                run_id=run_id,
                issuer_id=issuer_id,
                security_id=security_id,
                stage=stage,
                status="blocked",
                issues=("expected_trading_date_invalid",),
            )

    history_plan = tuple(
        sorted(
            {
                str(item["security_code"])
                for item in runtime_authorization.request_plan
                if item["protocol_id"] == 3103
            }
        )
    )
    quota_plan_items = tuple(
        item for item in runtime_authorization.request_plan if item["protocol_id"] == 3104
    )
    if (
        stage == "valuation_pre_price_verification"
        and (
            not mixed_pre_price_plan
            or history_plan != tuple(sorted(runtime_authorization.authorized_security_codes))
            or len(quota_plan_items) != 1
            or runtime_authorization.request_plan[0] != quota_plan_items[0]
            or quota_plan_items[0]["parameters_sha256"]
            != futu_request_parameters_sha256({"get_detail": True})
        )
    ):
        return _blocked_execution(
            authority=authority,
            run_id=run_id,
            issuer_id=issuer_id,
            security_id=security_id,
            stage=stage,
            status="blocked",
            issues=("historical_kline_quota_plan_mismatch",),
        )

    requests: list[FutuDataRequestReceipt] = []
    responses: list[FutuDataResponseReceipt] = []
    observations: list[FutuObservation] = []
    issues: set[str] = set()
    raw_byte_count = 0
    operation_count = 0
    history_quota: FutuHistoricalKlineQuotaReceipt | None = None

    for spec in plan_specs:
        protocol = registry[spec.protocol_id]
        page_key: str | None = None
        seen_page_keys: set[str] = set()
        protocol_request_start = len(requests)
        protocol_observation_start = len(observations)
        protocol_response_start = len(responses)
        for page_index in range(MAXIMUM_PAGES_PER_PROTOCOL):
            operation_count += 3  # pre-GlobalState, data operation, post-GlobalState
            if operation_count > MAXIMUM_OPERATIONS_PER_RUN:
                return _blocked_execution(
                    authority=authority,
                    run_id=run_id,
                    issuer_id=issuer_id,
                    security_id=security_id,
                    stage=stage,
                    status="blocked",
                    issues=(*issues, "request_limit_exceeded"),
                    requests=requests,
                    responses=responses,
                    observations=observations,
                )
            request = _make_request(
                authority=authority,
                security_identity=security_identity,
                run_id=run_id,
                stage=spec.stage,
                protocol=protocol,
                parameters=spec.parameters,
                page_index=page_index,
                previous_page_key=page_key,
                data_cutoff_date=data_cutoff_date,
                expected_trading_date=spec.expected_trading_date,
                price_blind_freeze_fingerprint=spec.price_blind_freeze_fingerprint,
                frozen_conclusion=spec.frozen_conclusion,
                request_started_at=request_started_at,
            )
            requests.append(request)
            wire_request = _wire_request(
                request=request,
                security_identity=security_identity,
                supply_chain=supply_chain,
                page_key=page_key,
            )
            try:
                raw_envelope = transport.exchange(
                    canonical_json(wire_request).encode("utf-8"),
                    maximum_response_bytes=MAXIMUM_RAW_BYTES_PER_RESPONSE,
                )
                envelope = _parse_envelope(
                    raw_envelope,
                    request=request,
                    supply_chain=supply_chain,
                )
                guard_states = (
                    envelope["pre_global_state"],
                    envelope["post_global_state"],
                )
                if any(
                    not state["qot_logined"]
                    or state["ret_type"] != 0
                    or state["err_code"] != 0
                    for state in guard_states
                ):
                    return _blocked_execution(
                        authority=authority,
                        run_id=run_id,
                        issuer_id=issuer_id,
                        security_id=security_id,
                        stage=stage,
                        status="blocked",
                        issues=(*issues, "qot_login_false"),
                        requests=requests,
                        responses=responses,
                        observations=observations,
                    )
                response, page_observations, next_page_key = _materialize_page(
                    envelope=envelope,
                    request=request,
                    parser_sha256=supply_chain.parser_sha256,
                )
                if spec.protocol_id == 3228 and (
                    not response.terminal or next_page_key is not None
                ):
                    raise FutuSidecarError(
                        "revenue-breakdown snapshot is a non-paginated operation"
                    )
            except (FutuSidecarError, FutuReceiptError, OSError, RuntimeError):
                issues.add("sidecar_response_invalid")
                if protocol["required_for_complete"]:
                    return _blocked_execution(
                        authority=authority,
                        run_id=run_id,
                        issuer_id=issuer_id,
                        security_id=security_id,
                        stage=stage,
                        status="blocked",
                        issues=tuple(issues),
                        requests=requests,
                        responses=responses,
                        observations=observations,
                    )
                break
            responses.append(response)
            raw_byte_count += response.raw_byte_count
            if raw_byte_count > MAXIMUM_RAW_BYTES_PER_RUN:
                return _blocked_execution(
                    authority=authority,
                    run_id=run_id,
                    issuer_id=issuer_id,
                    security_id=security_id,
                    stage=stage,
                    status="blocked",
                    issues=(*issues, "raw_byte_limit_exceeded"),
                    requests=requests,
                    responses=responses,
                    observations=observations,
                )
            if response.status == "quarantined":
                return _blocked_execution(
                    authority=authority,
                    run_id=run_id,
                    issuer_id=issuer_id,
                    security_id=security_id,
                    stage=stage,
                    status="quarantined",
                    issues=(*issues, "runtime_quarantined"),
                    requests=requests,
                    responses=responses,
                    observations=observations,
                )
            if response.status == "blocked":
                issue = (
                    "qot_login_false"
                    if not response.qot_logined
                    else "sidecar_response_invalid"
                )
                issues.add(issue)
                if protocol["required_for_complete"]:
                    return _blocked_execution(
                        authority=authority,
                        run_id=run_id,
                        issuer_id=issuer_id,
                        security_id=security_id,
                        stage=stage,
                        status="blocked",
                        issues=tuple(issues),
                        requests=requests,
                        responses=responses,
                        observations=observations,
                    )
                break
            observations.extend(page_observations)
            if response.terminal:
                break
            if next_page_key is None:
                issues.add("pagination_incomplete")
                break
            page_key_digest = hashlib.sha256(next_page_key.encode("utf-8")).hexdigest()
            if page_key_digest in seen_page_keys:
                issues.add("pagination_loop")
                break
            seen_page_keys.add(page_key_digest)
            page_key = next_page_key
        else:
            issues.add("pagination_incomplete")

        if issues.intersection({"pagination_incomplete", "pagination_loop"}) and protocol[
            "required_for_complete"
        ]:
            return _blocked_execution(
                authority=authority,
                run_id=run_id,
                issuer_id=issuer_id,
                security_id=security_id,
                stage=stage,
                status="blocked",
                issues=tuple(issues),
                requests=requests,
                responses=responses,
                observations=observations,
            )
        protocol_observations = observations[protocol_observation_start:]
        if spec.protocol_id == 3236:
            try:
                _validate_split_execution_observations(tuple(protocol_observations))
            except FutuSidecarError:
                return _blocked_execution(
                    authority=authority,
                    run_id=run_id,
                    issuer_id=issuer_id,
                    security_id=security_id,
                    stage=stage,
                    status="blocked",
                    issues=(*issues, "sidecar_response_invalid"),
                    requests=requests,
                    responses=responses,
                    observations=observations,
                )
        if spec.protocol_id == 3104:
            try:
                quota_responses = responses[protocol_response_start:]
                if len(quota_responses) != 1:
                    raise FutuSidecarError("history quota response must be exactly one page")
                history_quota = _build_history_quota_receipt(
                    request=requests[protocol_request_start],
                    response=quota_responses[0],
                    observations=protocol_observations,
                    account_scope_sha256=runtime_authorization.account_scope_sha256,
                    runtime_authorization_fingerprint=runtime_authorization.fingerprint,
                    runtime_request_plan=runtime_authorization.request_plan,
                    request_plan_fingerprint=runtime_authorization.request_plan_fingerprint,
                )
            except (FutuReceiptError, FutuSidecarError, IndexError):
                return _blocked_execution(
                    authority=authority,
                    run_id=run_id,
                    issuer_id=issuer_id,
                    security_id=security_id,
                    stage=stage,
                    status="blocked",
                    issues=(*issues, "historical_kline_quota_missing"),
                    requests=requests,
                    responses=responses,
                    observations=observations,
                )
            if not history_quota.sufficient:
                return _blocked_execution(
                    authority=authority,
                    run_id=run_id,
                    issuer_id=issuer_id,
                    security_id=security_id,
                    stage=stage,
                    status="blocked",
                    issues=(*issues, "historical_kline_quota_insufficient"),
                    requests=requests,
                    responses=responses,
                    observations=observations,
                    history_quota=history_quota,
                )
        if spec.protocol_id == 3103:
            try:
                if len(responses[protocol_response_start:]) != 1:
                    raise FutuSidecarError("daily close response must be exactly one page")
                _validate_daily_close_observations(
                    protocol_observations,
                    expected_trading_date=spec.expected_trading_date,
                )
            except FutuSidecarError:
                return _blocked_execution(
                    authority=authority,
                    run_id=run_id,
                    issuer_id=issuer_id,
                    security_id=security_id,
                    stage=stage,
                    status="blocked",
                    issues=(*issues, "sidecar_response_invalid"),
                    requests=requests,
                    responses=responses,
                    observations=observations,
                )

    status = "partial" if issues else "complete"
    bundle = _make_bundle(
        authority=authority,
        run_id=run_id,
        issuer_id=issuer_id,
        security_id=security_id,
        stage=stage,
        status=status,
        issues=tuple(issues),
        requests=requests,
        responses=responses,
        observations=observations,
    )
    return FutuSidecarExecution(
        bundle=bundle,
        requests=tuple(requests),
        responses=tuple(responses),
        observations=tuple(observations),
        history_quota=history_quota,
    )


def _make_request(
    *,
    authority: FutuAuthorityDecision,
    security_identity: FutuSecurityIdentityReceipt,
    run_id: str,
    stage: str,
    protocol: Mapping[str, Any],
    parameters: Mapping[str, Any],
    page_index: int,
    previous_page_key: str | None,
    data_cutoff_date: str,
    expected_trading_date: str | None,
    price_blind_freeze_fingerprint: str | None,
    frozen_conclusion: FutuFrozenConclusionReceipt | None,
    request_started_at: str,
) -> FutuDataRequestReceipt:
    values: dict[str, Any] = {
        "schema_version": FUTU_SCHEMA_VERSION,
        "run_id": run_id,
        "stage": stage,
        "issuer_id": security_identity.issuer_id,
        "security_id": security_identity.security_id,
        "security_identity_fingerprint": security_identity.fingerprint,
        "data_family": protocol["data_family"],
        "protocol_id": protocol["protocol_id"],
        "protocol_name": protocol["name"],
        "parameters": to_json_value(parameters),
        "page_index": page_index,
        "previous_page_key_sha256": (
            hashlib.sha256(previous_page_key.encode("utf-8")).hexdigest()
            if previous_page_key is not None
            else None
        ),
        "data_cutoff_date": data_cutoff_date,
        "expected_trading_date": expected_trading_date,
        "price_blind_freeze_fingerprint": price_blind_freeze_fingerprint,
        "frozen_conclusion_receipt_id": (
            None if frozen_conclusion is None else frozen_conclusion.receipt_id
        ),
        "frozen_conclusion_fingerprint": (
            None if frozen_conclusion is None else frozen_conclusion.fingerprint
        ),
        "authority_decision_fingerprint": authority.fingerprint,
        "request_started_at": request_started_at,
    }
    request_id, fingerprint = content_identity(
        "futu-request:",
        values,
        object_id_field="request_id",
        fingerprint_field="request_fingerprint",
    )
    return FutuDataRequestReceipt(
        request_id=request_id,
        request_fingerprint=fingerprint,
        **values,
    )


def _global_state_request_fingerprint(request: FutuDataRequestReceipt, phase: str) -> str:
    return canonical_sha256(
        {
            "schema_version": WIRE_SCHEMA_VERSION,
            "operation": "GetGlobalState",
            "protocol_id": GLOBAL_STATE_PROTOCOL_ID,
            "run_id": request.run_id,
            "bound_data_request_fingerprint": request.fingerprint,
            "phase": phase,
        }
    )


def _wire_request(
    *,
    request: FutuDataRequestReceipt,
    security_identity: FutuSecurityIdentityReceipt,
    supply_chain: FutuSupplyChainReceipt,
    page_key: str | None,
) -> dict[str, Any]:
    return {
        "wire_schema_version": WIRE_SCHEMA_VERSION,
        "command": "fetch_quote_data_with_global_state_guards",
        "run_id": request.run_id,
        "request_id": request.request_id,
        "request_fingerprint": request.fingerprint,
        "protocol": {
            "id": request.protocol_id,
            "name": request.protocol_name,
        },
        "security": {
            "market": "US",
            "code": security_identity.vendor_code,
            "security_id": security_identity.vendor_security_id,
        },
        "parameters": to_json_value(request.parameters),
        "page_index": request.page_index,
        "page_key": page_key,
        "expected_supply_attestation": _supply_attestation(supply_chain),
        "global_state_guards": {
            "protocol_id": GLOBAL_STATE_PROTOCOL_ID,
            "required_pre_request_fingerprint": _global_state_request_fingerprint(
                request, "pre"
            ),
            "required_post_request_fingerprint": _global_state_request_fingerprint(
                request, "post"
            ),
            "qot_logined": True,
        },
    }


def _parse_envelope(
    raw_envelope: bytes,
    *,
    request: FutuDataRequestReceipt,
    supply_chain: FutuSupplyChainReceipt,
) -> dict[str, Any]:
    if not isinstance(raw_envelope, bytes):
        raise FutuSidecarError("sidecar transport must return bytes")
    if len(raw_envelope) > MAXIMUM_RAW_BYTES_PER_RESPONSE:
        raise FutuSidecarError("sidecar envelope exceeds the response byte limit")
    try:
        text = raw_envelope.decode("utf-8")
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FutuSidecarError("sidecar response is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or text != canonical_json(payload):
        raise FutuSidecarError("sidecar response must use canonical JSON")
    envelope = _exact_members(
        payload,
        {
            "wire_schema_version",
            "command",
            "run_id",
            "request_id",
            "request_fingerprint",
            "protocol_id",
            "page_index",
            "supply_attestation",
            "pre_global_state",
            "data_response",
            "post_global_state",
        },
        "sidecar response",
    )
    expected_bindings = {
        "wire_schema_version": WIRE_SCHEMA_VERSION,
        "command": "fetch_quote_data_with_global_state_guards",
        "run_id": request.run_id,
        "request_id": request.request_id,
        "request_fingerprint": request.fingerprint,
        "protocol_id": request.protocol_id,
        "page_index": request.page_index,
    }
    if any(envelope[key] != value for key, value in expected_bindings.items()):
        raise FutuSidecarError("sidecar response does not bind the request")
    if envelope["supply_attestation"] != _supply_attestation(supply_chain):
        raise FutuSidecarError("sidecar response supply attestation does not replay")
    _validate_global_state(
        envelope["pre_global_state"],
        request=request,
        phase="pre",
        supply_chain=supply_chain,
    )
    _validate_global_state(
        envelope["post_global_state"],
        request=request,
        phase="post",
        supply_chain=supply_chain,
    )
    return envelope


def _supply_attestation(supply_chain: FutuSupplyChainReceipt) -> dict[str, Any]:
    return {
        "supply_receipt_fingerprint": supply_chain.fingerprint,
        "provider_id": supply_chain.provider_id,
        "provider_version": supply_chain.provider_version,
        "opend_version": supply_chain.opend_version,
        "opend_server_version": supply_chain.opend_server_version,
        "opend_server_build_no": supply_chain.opend_server_build_no,
        "futu_api_version": supply_chain.futu_api_version,
        "futu_api_distribution_sha256": supply_chain.futu_api_distribution_sha256,
        "sdk_operation_registry_sha256": supply_chain.sdk_operation_registry_sha256,
        "protobuf_descriptor_set_sha256": supply_chain.protobuf_descriptor_set_sha256,
        "protocol_descriptor_sha256": supply_chain.protocol_descriptor_sha256,
        "facade_sha256": supply_chain.facade_sha256,
        "adapter_sha256": supply_chain.adapter_sha256,
        "parser_sha256": supply_chain.parser_sha256,
    }


def _validate_global_state(
    value: Any,
    *,
    request: FutuDataRequestReceipt,
    phase: str,
    supply_chain: FutuSupplyChainReceipt,
) -> dict[str, Any]:
    state = _exact_members(
        value,
        {
            "operation",
            "protocol_id",
            "serial_number",
            "request_fingerprint",
            "response_fingerprint",
            "retrieved_at",
            "ret_type",
            "err_code",
            "qot_logined",
            "trd_logined",
            "opend_server_version",
            "opend_server_build_no",
        },
        f"{phase} GlobalState",
    )
    if state["operation"] != "GetGlobalState" or state["protocol_id"] != 1002:
        raise FutuSidecarError("GlobalState operation is not bound to protocol 1002")
    if state["request_fingerprint"] != _global_state_request_fingerprint(request, phase):
        raise FutuSidecarError("GlobalState request fingerprint is not bound")
    response_payload = dict(state)
    response_fingerprint = response_payload.pop("response_fingerprint")
    if response_fingerprint != canonical_sha256(response_payload):
        raise FutuSidecarError("GlobalState response fingerprint is invalid")
    for label in (
        "serial_number",
        "ret_type",
        "err_code",
        "opend_server_version",
        "opend_server_build_no",
    ):
        if type(state[label]) is not int:
            raise FutuSidecarError(f"GlobalState {label} must be an integer")
    for label in ("qot_logined", "trd_logined"):
        if type(state[label]) is not bool:
            raise FutuSidecarError(f"GlobalState {label} must be boolean")
    _utc_datetime(state["retrieved_at"], "GlobalState retrieved_at")
    if (
        state["opend_server_version"] <= 0
        or state["opend_server_build_no"] <= 0
        or state["opend_server_version"] != supply_chain.opend_server_version
        or state["opend_server_build_no"] != supply_chain.opend_server_build_no
    ):
        raise FutuSidecarError("GlobalState OpenD identity differs from pinned supply")
    return state


_FINANCIAL_STATEMENT_SEMANTICS = {
    1: ("income", "flow"),
    2: ("balance_sheet", "stock"),
    3: ("cash_flow", "flow"),
    4: ("main_index", "mixed"),
}
_FINANCIAL_STRUCTURE_PREFIX = "financial_structure:"
_FINANCIAL_VALUE_QUALIFIERS = {
    "accounting_standard",
    "auditor_report",
    "financial_type",
    "fiscal_year",
    "period_kind",
    "statement_type",
    "vendor_period",
}
_FINANCIAL_STRUCTURE_QUALIFIERS = {
    "financial_field_id",
    "futu_api_version",
    "normalized_display_name",
    "statement_type",
}


def _canonical_calendar_date(value: Any, label: str) -> date:
    if not isinstance(value, str):
        raise FutuSidecarError(f"{label} must be a canonical date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise FutuSidecarError(f"{label} must be a canonical date") from exc
    if parsed.isoformat() != value:
        raise FutuSidecarError(f"{label} must be a canonical date")
    return parsed


def _financial_structure_descriptor(
    item: Mapping[str, Any],
    *,
    expected_statement_type: str,
) -> tuple[str, str]:
    field_id = item.get("field_id")
    if not isinstance(field_id, str) or not field_id.startswith(
        _FINANCIAL_STRUCTURE_PREFIX
    ):
        raise FutuSidecarError("financial structure descriptor identity is invalid")
    descriptor_id = field_id.removeprefix(_FINANCIAL_STRUCTURE_PREFIX)
    if not descriptor_id.isascii() or not descriptor_id.isdigit() or str(
        int(descriptor_id)
    ) != descriptor_id or int(descriptor_id) <= 0:
        raise FutuSidecarError("financial structure fieldId must be a positive integer")
    qualifiers = item.get("qualifiers")
    if not isinstance(qualifiers, dict) or set(qualifiers) != _FINANCIAL_STRUCTURE_QUALIFIERS:
        raise FutuSidecarError("financial structure descriptor qualifiers are invalid")
    display_name = item.get("value")
    normalized = _normalize_financial_display_name(display_name)
    if (
        qualifiers["financial_field_id"] != descriptor_id
        or qualifiers["futu_api_version"] != PINNED_FUTU_API_VERSION
        or qualifiers["normalized_display_name"] != normalized
        or qualifiers["statement_type"] != expected_statement_type
        or item.get("period") != {"start": None, "end": None}
        or item.get("value_type") != "text"
        or item.get("unit") is not None
        or item.get("currency") is not None
        or item.get("binary64_hex") is not None
        or item.get("exact_binary64_decimal") is not None
    ):
        raise FutuSidecarError("financial structure descriptor does not replay")
    return descriptor_id, normalized


def _prepare_financial_wire_observations(
    observations: Sequence[Any],
    *,
    request: FutuDataRequestReceipt,
) -> tuple[dict[str, Any], ...]:
    statement_selector = request.parameters.get("statement_type")
    if type(statement_selector) is not int or statement_selector not in (
        _FINANCIAL_STATEMENT_SEMANTICS
    ):
        raise FutuSidecarError("financial response is not bound to a statement selector")
    expected_statement_type, expected_period_kind = _FINANCIAL_STATEMENT_SEMANTICS[
        statement_selector
    ]
    descriptors: dict[str, str] = {}
    value_items: list[dict[str, Any]] = []
    descriptor_items: list[dict[str, Any]] = []
    period_metadata: dict[str, tuple[int, str, str]] = {}
    field_periods: set[tuple[str, str]] = set()

    for raw_item in observations:
        item = _exact_members(
            raw_item,
            {
                "field_id",
                "period",
                "qualifiers",
                "value_type",
                "value",
                "unit",
                "currency",
                "binary64_hex",
                "exact_binary64_decimal",
            },
            "financial wire observation",
        )
        field_id = item["field_id"]
        if isinstance(field_id, str) and field_id.startswith(
            _FINANCIAL_STRUCTURE_PREFIX
        ):
            descriptor_id, normalized_name = _financial_structure_descriptor(
                item,
                expected_statement_type=expected_statement_type,
            )
            if descriptor_id in descriptors:
                raise FutuSidecarError("financial structure fieldId is duplicated")
            descriptors[descriptor_id] = normalized_name
            descriptor_items.append(dict(item))
            continue
        if (
            not isinstance(field_id, str)
            or not field_id.isascii()
            or not field_id.isdigit()
            or str(int(field_id)) != field_id
            or int(field_id) <= 0
        ):
            raise FutuSidecarError("financial report fieldId must be a positive integer")
        qualifiers = item["qualifiers"]
        if not isinstance(qualifiers, dict) or set(qualifiers) != _FINANCIAL_VALUE_QUALIFIERS:
            raise FutuSidecarError("financial report qualifiers are invalid")
        fiscal_year = qualifiers["fiscal_year"]
        vendor_period = qualifiers["vendor_period"]
        auditor_report = qualifiers["auditor_report"]
        accounting_standard = qualifiers["accounting_standard"]
        if (
            type(qualifiers["financial_type"]) is not int
            or qualifiers["financial_type"] != 7
            or type(fiscal_year) is not int
            or fiscal_year <= 0
            or not isinstance(accounting_standard, str)
            or accounting_standard != accounting_standard.strip()
            or not accounting_standard
            or len(accounting_standard.encode("utf-8")) > 128
            or not isinstance(vendor_period, str)
            or vendor_period != vendor_period.strip()
            or not vendor_period
            or len(vendor_period.encode("utf-8")) > 256
            or not isinstance(auditor_report, str)
            or len(auditor_report.encode("utf-8")) > 4096
            or qualifiers["statement_type"] != expected_statement_type
            or qualifiers["period_kind"] != expected_period_kind
        ):
            raise FutuSidecarError("financial report period metadata is invalid")
        period = _exact_members(item["period"], {"start", "end"}, "financial period")
        period_end = _canonical_calendar_date(period["end"], "financial period end")
        if period["start"] is not None:
            _canonical_calendar_date(period["start"], "financial period start")
        period_key = period_end.isoformat()
        metadata = (fiscal_year, vendor_period, accounting_standard)
        previous_metadata = period_metadata.setdefault(period_key, metadata)
        if previous_metadata != metadata:
            raise FutuSidecarError("financial period metadata is internally inconsistent")
        field_period = (field_id, period_key)
        if field_period in field_periods:
            raise FutuSidecarError("financial report repeats a field within one period")
        field_periods.add(field_period)
        value_items.append(dict(item))

    if not descriptors or not value_items:
        raise FutuSidecarError("financial response lacks structure or report values")
    if any(item["field_id"] not in descriptors for item in value_items):
        raise FutuSidecarError("financial report field is absent from structureList")
    fiscal_years = [metadata[0] for metadata in period_metadata.values()]
    if len(set(fiscal_years)) != len(fiscal_years):
        raise FutuSidecarError("annual financial response repeats a fiscal year")

    ordered_periods = sorted(period_metadata, key=date.fromisoformat)
    derived_starts: dict[str, str | None] = {period: None for period in ordered_periods}
    if expected_period_kind == "flow":
        for previous_key, current_key in zip(
            ordered_periods, ordered_periods[1:], strict=False
        ):
            previous_end = date.fromisoformat(previous_key)
            current_end = date.fromisoformat(current_key)
            previous_year = period_metadata[previous_key][0]
            current_year = period_metadata[current_key][0]
            days = (current_end - previous_end).days
            if current_year == previous_year + 1 and 350 <= days <= 380:
                derived_starts[current_key] = (previous_end + timedelta(days=1)).isoformat()

    normalized_values: list[dict[str, Any]] = []
    for item in value_items:
        period = item["period"]
        period_end = period["end"]
        derived_start = derived_starts[period_end]
        if expected_period_kind == "flow":
            if period["start"] not in {None, derived_start}:
                raise FutuSidecarError("financial flow start does not replay annual periods")
            status = (
                "consecutive_annual_period"
                if derived_start is not None
                else "annual_predecessor_unavailable"
            )
            derivation = (
                "previous_annual_period_end_plus_one_day"
                if derived_start is not None
                else "not_derivable"
            )
        else:
            if period["start"] is not None:
                raise FutuSidecarError("financial stock period must not carry a start date")
            status = "instant"
            derivation = "not_applicable"
        qualifiers = dict(item["qualifiers"])
        qualifiers.update(
            {
                "financial_period_start_derivation": derivation,
                "financial_period_status": status,
                "futu_api_version": PINNED_FUTU_API_VERSION,
                "normalized_financial_field_display_name": descriptors[item["field_id"]],
            }
        )
        normalized = dict(item)
        normalized["period"] = {"start": derived_start, "end": period_end}
        normalized["qualifiers"] = qualifiers
        normalized_values.append(normalized)
    return (*descriptor_items, *normalized_values)


_WIRE_OBSERVATION_MEMBERS = {
    "field_id",
    "period",
    "qualifiers",
    "value_type",
    "value",
    "unit",
    "currency",
    "binary64_hex",
    "exact_binary64_decimal",
}


def _wire_observation_item(value: Any, label: str) -> dict[str, Any]:
    return _exact_members(value, _WIRE_OBSERVATION_MEMBERS, label)


def _wire_observation_projection(observation: FutuObservation) -> dict[str, Any]:
    return {
        "field_id": observation.field_id,
        "period": to_json_value(observation.period),
        "qualifiers": to_json_value(observation.qualifiers),
        "value_type": observation.value_type,
        "value": observation.value,
        "unit": observation.unit,
        "currency": observation.currency,
        "binary64_hex": observation.binary64_hex,
        "exact_binary64_decimal": observation.exact_binary64_decimal,
    }


def reproject_execution_with_financial_field_registry(
    execution: FutuSidecarExecution,
    *,
    registry: Mapping[str, FrozenMap],
) -> FutuSidecarExecution:
    request_by_id = {item.request_id: item for item in execution.requests}
    response_by_fingerprint = {item.fingerprint: item for item in execution.responses}
    with reviewed_financial_field_registry_scope(registry):
        observations = tuple(
            _materialize_observation(
                _wire_observation_projection(item),
                request=request_by_id[response_by_fingerprint[item.response_fingerprint].request_id],
                response=response_by_fingerprint[item.response_fingerprint],
            )
            if item.data_family == "financial_statements"
            else item
            for item in execution.observations
        )
    if tuple(item.to_dict() for item in observations) == tuple(
        item.to_dict() for item in execution.observations
    ):
        return execution
    bundle_values = execution.bundle.to_dict()
    bundle_values["observations"] = [
        _reference(item.observation_id, item.fingerprint) for item in observations
    ]
    bundle_values.pop("bundle_id")
    bundle_values.pop("bundle_fingerprint")
    bundle_id, bundle_fingerprint = content_identity(
        "futu-bundle:",
        bundle_values,
        object_id_field="bundle_id",
        fingerprint_field="bundle_fingerprint",
    )
    bundle = FutuEvidenceBundle(
        bundle_id=bundle_id,
        bundle_fingerprint=bundle_fingerprint,
        **bundle_values,
    )
    return FutuSidecarExecution(
        bundle=bundle,
        requests=execution.requests,
        responses=execution.responses,
        observations=observations,
        history_quota=execution.history_quota,
    )


def _wire_decimal(item: Mapping[str, Any], label: str) -> Decimal:
    if item["value_type"] != "number" or not isinstance(item["value"], str):
        raise FutuSidecarError(f"{label} is not one canonical numeric observation")
    try:
        value = Decimal(item["value"])
    except (ArithmeticError, ValueError) as exc:
        raise FutuSidecarError(f"{label} is not a finite decimal") from exc
    if not value.is_finite():
        raise FutuSidecarError(f"{label} is not a finite decimal")
    return value


def _validate_empty_set_wire_observation(
    item: Mapping[str, Any],
    *,
    field_id: str,
    qualifiers: Mapping[str, Any],
    label: str,
) -> None:
    if (
        item["field_id"] != field_id
        or item["period"] != {"start": None, "end": None}
        or item["qualifiers"] != qualifiers
        or item["value_type"] != "null"
        or item["value"] is not None
        or item["unit"] is not None
        or item["currency"] is not None
        or item["binary64_hex"] is not None
        or item["exact_binary64_decimal"] is not None
    ):
        raise FutuSidecarError(f"{label} is invalid")


def _prepare_revenue_breakdown_wire_observations(
    observations: Sequence[Any],
) -> tuple[dict[str, Any], ...]:
    normalized = [
        _wire_observation_item(item, "revenue-breakdown wire observation")
        for item in observations
    ]
    empty_markers = [
        item for item in normalized if item["field_id"] == "revenue_breakdown_segment_set"
    ]
    if empty_markers:
        if len(normalized) != 1:
            raise FutuSidecarError("revenue-breakdown empty set is mixed with actual data")
        _validate_empty_set_wire_observation(
            empty_markers[0],
            field_id="revenue_breakdown_segment_set",
            qualifiers={
                "reason_code": "official_no_data",
                "segment_set_status": "empty",
            },
            label="revenue-breakdown empty-set disposition",
        )
        return tuple(normalized)
    if not normalized:
        raise FutuSidecarError("revenue-breakdown response lacks data or a typed empty set")

    segments: dict[str, dict[str, Any]] = {}
    dimension_names: dict[int, set[str]] = {}
    for item in normalized:
        qualifiers = item["qualifiers"]
        if not isinstance(qualifiers, dict):
            raise FutuSidecarError("revenue-breakdown qualifiers are invalid")
        field_id = item["field_id"]
        expected_qualifiers = {
            "dimension_type",
            "normalized_segment_name",
            "segment_identity",
            "segment_name",
            "vendor_period",
        }
        if field_id == "revenue_breakdown_ratio":
            expected_qualifiers.add("ratio_basis")
        elif field_id != "revenue_breakdown_main_operating_income":
            raise FutuSidecarError("revenue-breakdown field identity is invalid")
        if set(qualifiers) != expected_qualifiers:
            raise FutuSidecarError("revenue-breakdown qualifiers are incomplete")
        dimension_type = qualifiers["dimension_type"]
        segment_name = qualifiers["segment_name"]
        normalized_name = qualifiers["normalized_segment_name"]
        vendor_period = qualifiers["vendor_period"]
        if (
            type(dimension_type) is not int
            or dimension_type not in _REVENUE_BREAKDOWN_DIMENSION_TYPES
            or not isinstance(segment_name, str)
            or segment_name != segment_name.strip()
            or not segment_name
            or len(segment_name.encode("utf-8")) > 512
            or not isinstance(normalized_name, str)
            or _normalize_financial_display_name(segment_name) != normalized_name
            or re.fullmatch(r"[1-9][0-9]{3}/FY", vendor_period) is None
            or item["period"] != {"start": None, "end": None}
        ):
            raise FutuSidecarError("revenue-breakdown segment identity is invalid")
        expected_identity = canonical_sha256(
            {
                "dimension_type": dimension_type,
                "normalized_segment_name": normalized_name,
                "vendor_period": vendor_period,
                "currency": "USD",
            }
        )
        identity = qualifiers["segment_identity"]
        if identity != expected_identity:
            raise FutuSidecarError("revenue-breakdown segment identity does not replay")
        names = dimension_names.setdefault(dimension_type, set())
        existing = segments.setdefault(
            identity,
            {
                "dimension_type": dimension_type,
                "normalized_name": normalized_name,
                "income": None,
                "ratio": None,
            },
        )
        if (
            existing["dimension_type"] != dimension_type
            or existing["normalized_name"] != normalized_name
        ):
            raise FutuSidecarError("revenue-breakdown segment identity was rebound")
        value = _wire_decimal(item, "revenue-breakdown value")
        if field_id == "revenue_breakdown_main_operating_income":
            if (
                existing["income"] is not None
                or value < 0
                or item["unit"] != "currency_units"
                or item["currency"] != "USD"
            ):
                raise FutuSidecarError("revenue-breakdown income is invalid")
            existing["income"] = value
        else:
            if (
                existing["ratio"] is not None
                or not 0 <= value <= 100
                or qualifiers["ratio_basis"] != "main_operating_income"
                or item["unit"] != "percent"
                or item["currency"] is not None
            ):
                raise FutuSidecarError("revenue-breakdown ratio is invalid")
            existing["ratio"] = value
        if item["binary64_hex"] is None or item["exact_binary64_decimal"] is None:
            raise FutuSidecarError("revenue-breakdown binary64 evidence is missing")
        names.add(normalized_name)

    if any(item["income"] is None or item["ratio"] is None for item in segments.values()):
        raise FutuSidecarError("revenue-breakdown segment pair is incomplete")
    if any(
        len(names)
        != sum(
            item["dimension_type"] == dimension_type for item in segments.values()
        )
        for dimension_type, names in dimension_names.items()
    ):
        raise FutuSidecarError("revenue-breakdown normalized segment name is duplicated")
    for dimension_type in dimension_names:
        group = [
            item for item in segments.values() if item["dimension_type"] == dimension_type
        ]
        total_income = sum((item["income"] for item in group), Decimal(0))
        total_ratio = sum((item["ratio"] for item in group), Decimal(0))
        if total_income <= 0 or abs(total_ratio - Decimal(100)) > (
            _REVENUE_RATIO_ABSOLUTE_TOLERANCE
        ):
            raise FutuSidecarError("revenue-breakdown group does not reconcile to its total")
        for item in group:
            expected_ratio = item["income"] / total_income * Decimal(100)
            if abs(item["ratio"] - expected_ratio) > _REVENUE_RATIO_ABSOLUTE_TOLERANCE:
                raise FutuSidecarError(
                    "revenue-breakdown ratio does not reconcile to operating income"
                )
    return tuple(normalized)


def _prepare_dividend_wire_observations(
    observations: Sequence[Any],
) -> tuple[dict[str, Any], ...]:
    normalized = [
        _wire_observation_item(item, "dividend wire observation") for item in observations
    ]
    empty_markers = [item for item in normalized if item["field_id"] == "dividend_event_set"]
    if empty_markers:
        if len(normalized) != 1:
            raise FutuSidecarError("dividend empty set is mixed with actual data")
        _validate_empty_set_wire_observation(
            empty_markers[0],
            field_id="dividend_event_set",
            qualifiers={
                "event_set_status": "empty",
                "reason_code": "official_no_data",
            },
            label="dividend empty-set disposition",
        )
        return tuple(normalized)
    if not normalized:
        raise FutuSidecarError("dividend response lacks events or a typed empty set")

    identities: set[str] = set()
    required_qualifiers = {
        "event_identity",
        "ex_date",
        "fiscal_year",
        "payable_date",
        "process",
        "publication_date",
        "record_date",
    }
    for item in normalized:
        qualifiers = item["qualifiers"]
        statement = item["value"]
        if (
            item["field_id"] != "dividend_event"
            or not isinstance(qualifiers, dict)
            or set(qualifiers) != required_qualifiers
            or item["value_type"] != "text"
            or not isinstance(statement, str)
            or statement != statement.strip()
            or not statement
            or len(statement.encode("utf-8")) > 2048
            or qualifiers["process"] is not None
            or qualifiers["fiscal_year"] is not None
            or item["unit"] is not None
            or item["currency"] is not None
            or item["binary64_hex"] is not None
            or item["exact_binary64_decimal"] is not None
        ):
            raise FutuSidecarError("US common-stock dividend event is invalid")
        publication = _canonical_calendar_date(
            qualifiers["publication_date"], "dividend publication date"
        ).isoformat()
        dates: dict[str, str | None] = {}
        for key, label in (
            ("record_date", "record date"),
            ("ex_date", "ex date"),
            ("payable_date", "payable date"),
        ):
            raw = qualifiers[key]
            dates[key] = (
                None
                if raw is None
                else _canonical_calendar_date(raw, f"dividend {label}").isoformat()
            )
        expected_identity = canonical_sha256(
            {
                "publication_date": publication,
                "statement": statement,
                "record_date": dates["record_date"],
                "ex_date": dates["ex_date"],
                "payable_date": dates["payable_date"],
                "process": None,
                "fiscal_year": None,
            }
        )
        if (
            qualifiers["event_identity"] != expected_identity
            or expected_identity in identities
            or item["period"]
            != {"start": None, "end": dates["ex_date"] or publication}
        ):
            raise FutuSidecarError("dividend event identity does not replay")
        identities.add(expected_identity)
    return tuple(normalized)


def _split_rate_ratio(value: str) -> tuple[str, str]:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or len(value.encode("utf-8")) > 128
    ):
        raise FutuSidecarError("stock-split raw rate is invalid")
    matched = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)->([0-9]+(?:\.[0-9]+)?)", value)
    if matched is None:
        raise FutuSidecarError("stock-split rate is not an exact before-to-after ratio")
    before, after = (Decimal(part) for part in matched.groups())
    if before <= 0 or after <= 0:
        raise FutuSidecarError("stock-split ratio members must be positive")
    ratio = Fraction(after) / Fraction(before)
    return str(ratio.numerator), str(ratio.denominator)


def _prepare_split_wire_observations(
    observations: Sequence[Any],
    *,
    request: FutuDataRequestReceipt,
    terminal: bool,
) -> tuple[dict[str, Any], ...]:
    normalized: list[dict[str, Any]] = []
    identities: set[tuple[str, str | None, str, str, str]] = set()
    current_shares_markers = 0
    empty_event_markers = 0
    required_qualifiers = {
        "announcement_date",
        "current_shares_status",
        "effective_date",
        "event_type",
        "rate_denominator",
        "rate_numerator",
        "rate_raw",
        "reform_type",
    }
    for raw_item in observations:
        item = _wire_observation_item(raw_item, "stock-split wire observation")
        qualifiers = item["qualifiers"]
        if item["field_id"] == "current_common_shares":
            if (
                item["period"] != {"start": None, "end": None}
                or qualifiers
                != {
                    "reason_code": "us_3236_shares_after_effect_not_supported",
                    "verification_status": "vendor_not_supported",
                }
                or item["value_type"] != "null"
                or item["value"] is not None
                or item["unit"] is not None
                or item["currency"] is not None
                or item["binary64_hex"] is not None
                or item["exact_binary64_decimal"] is not None
            ):
                raise FutuSidecarError("current-shares vendor disposition is invalid")
            current_shares_markers += 1
            normalized.append(dict(item))
            continue
        if item["field_id"] == "stock_split_event_set":
            if (
                item["period"] != {"start": None, "end": None}
                or qualifiers
                != {
                    "event_set_status": "empty",
                    "reason_code": "official_no_data",
                }
                or item["value_type"] != "null"
                or item["value"] is not None
                or item["unit"] is not None
                or item["currency"] is not None
                or item["binary64_hex"] is not None
                or item["exact_binary64_decimal"] is not None
            ):
                raise FutuSidecarError("stock-split empty-set disposition is invalid")
            empty_event_markers += 1
            normalized.append(dict(item))
            continue
        if not isinstance(qualifiers, dict) or set(qualifiers) != required_qualifiers:
            raise FutuSidecarError("stock-split qualifiers are invalid")
        announcement = _canonical_calendar_date(
            qualifiers["announcement_date"], "stock-split announcement date"
        )
        effective_raw = qualifiers["effective_date"]
        effective = (
            None
            if effective_raw is None
            else _canonical_calendar_date(effective_raw, "stock-split effective date")
        )
        if effective is not None:
            raise FutuSidecarError("US stock-split observation cannot assert an effective date")
        reform_type = qualifiers["reform_type"]
        if (
            not isinstance(reform_type, str)
            or reform_type != reform_type.strip()
            or not reform_type
            or len(reform_type.encode("utf-8")) > 256
        ):
            raise FutuSidecarError("stock-split reform type is invalid")
        numerator, denominator = _split_rate_ratio(qualifiers["rate_raw"])
        event_type = (
            "stock_split_completed"
            if int(numerator) > int(denominator)
            else "reverse_stock_split_completed"
            if int(numerator) < int(denominator)
            else None
        )
        if (
            qualifiers["rate_numerator"] != numerator
            or qualifiers["rate_denominator"] != denominator
            or qualifiers["event_type"] != event_type
            or event_type is None
            or gcd(int(numerator), int(denominator)) != 1
            or qualifiers["current_shares_status"] != "vendor_not_supported"
            or item["field_id"] != "stock_split_event"
            or item["period"]
            != {
                "start": None,
                "end": announcement.isoformat(),
            }
            or item["value_type"] != "text"
            or item["value"] != f"{numerator}/{denominator}"
            or item["unit"] != "split_ratio"
            or item["currency"] is not None
            or item["binary64_hex"] is not None
            or item["exact_binary64_decimal"] is not None
        ):
            raise FutuSidecarError("stock-split event does not replay exactly")
        identity = (
            announcement.isoformat(),
            None if effective is None else effective.isoformat(),
            reform_type,
            numerator,
            denominator,
        )
        if identity in identities:
            raise FutuSidecarError("stock-split event is duplicated")
        identities.add(identity)
        normalized.append(dict(item))
    expected_current_share_markers = 1 if request.page_index == 0 else 0
    valid_empty_set = (
        request.page_index == 0
        and terminal
        and not identities
        and empty_event_markers == 1
    )
    valid_first_page_continuation = (
        request.page_index == 0
        and not terminal
        and not identities
        and empty_event_markers == 0
    )
    if (
        current_shares_markers != expected_current_share_markers
        or empty_event_markers > 1
        or (identities and empty_event_markers)
        or (
            not identities
            and not valid_empty_set
            and not valid_first_page_continuation
        )
    ):
        raise FutuSidecarError("stock-split event/disposition set is incomplete")
    return tuple(normalized)


def _validate_split_execution_observations(
    observations: Sequence[FutuObservation],
) -> None:
    current_share_markers = tuple(
        item for item in observations if item.field_id == "current_common_shares"
    )
    empty_event_markers = tuple(
        item for item in observations if item.field_id == "stock_split_event_set"
    )
    events = tuple(item for item in observations if item.field_id == "stock_split_event")
    identities = {
        (
            item.qualifiers.get("announcement_date"),
            item.qualifiers.get("reform_type"),
            item.qualifiers.get("rate_numerator"),
            item.qualifiers.get("rate_denominator"),
        )
        for item in events
    }
    if (
        len(current_share_markers) != 1
        or len(empty_event_markers) > 1
        or bool(events) == bool(empty_event_markers)
        or len(identities) != len(events)
        or any(item.qualifiers.get("effective_date") is not None for item in events)
        or any(
            item.period
            != FrozenMap(
                {
                    "start": None,
                    "end": item.qualifiers.get("announcement_date"),
                }
            )
            for item in events
        )
    ):
        raise FutuSidecarError("stock-split execution event set is incomplete or duplicated")


def _materialize_page(
    *,
    envelope: Mapping[str, Any],
    request: FutuDataRequestReceipt,
    parser_sha256: str,
) -> tuple[FutuDataResponseReceipt, tuple[FutuObservation, ...], str | None]:
    pre = envelope["pre_global_state"]
    post = envelope["post_global_state"]
    data = _exact_members(
        envelope["data_response"],
        {
            "serial_number",
            "retrieved_at",
            "ret_type",
            "err_code",
            "next_key",
            "terminal",
            "raw_evidence",
            "observations",
        },
        "data response",
    )
    for label in ("serial_number", "ret_type", "err_code"):
        if type(data[label]) is not int:
            raise FutuSidecarError(f"data response {label} must be an integer")
    if not (
        pre["serial_number"] < data["serial_number"] < post["serial_number"]
    ):
        raise FutuSidecarError("GlobalState operations do not bracket the data response")
    if not isinstance(data["retrieved_at"], str) or type(data["terminal"]) is not bool:
        raise FutuSidecarError("data response metadata types are invalid")
    if not (
        _utc_datetime(pre["retrieved_at"], "pre GlobalState retrieved_at")
        <= _utc_datetime(data["retrieved_at"], "data response retrieved_at")
        <= _utc_datetime(post["retrieved_at"], "post GlobalState retrieved_at")
    ):
        raise FutuSidecarError("GlobalState timestamps do not bracket the data response")
    next_key = data["next_key"]
    if next_key is not None:
        if (
            not isinstance(next_key, str)
            or not next_key
            or len(next_key.encode("utf-8")) > MAXIMUM_PAGE_KEY_BYTES
        ):
            raise FutuSidecarError("pagination key is invalid")
    if data["terminal"] and next_key not in {None, "-1"}:
        raise FutuSidecarError("terminal response cannot advertise another page")
    if not data["terminal"] and next_key in {None, "-1"}:
        raise FutuSidecarError("non-terminal response must include a next page key")
    raw = _exact_members(
        data["raw_evidence"],
        {
            "evidence_kind",
            "raw_plaintext_sha256",
            "encrypted_object_sha256",
            "cas_locator",
            "envelope_key_id",
            "raw_byte_count",
        },
        "encrypted CAS receipt",
    )
    if raw["evidence_kind"] != "opend_protobuf_s2c_frame":
        raise FutuSidecarError(
            "sidecar raw evidence must be the captured OpenD protobuf S2C frame"
        )
    plaintext_sha = _require_sha256(raw["raw_plaintext_sha256"], "raw_plaintext_sha256")
    encrypted_sha = _require_sha256(
        raw["encrypted_object_sha256"], "encrypted_object_sha256"
    )
    if plaintext_sha == encrypted_sha:
        raise FutuSidecarError("encrypted CAS object must not reuse the plaintext digest")
    if raw["cas_locator"] != f"cas://sha256/{encrypted_sha}":
        raise FutuSidecarError("encrypted CAS locator is invalid")
    if not isinstance(raw["envelope_key_id"], str) or _KEY_ID.fullmatch(
        raw["envelope_key_id"]
    ) is None:
        raise FutuSidecarError("envelope key ID is invalid")
    if (
        type(raw["raw_byte_count"]) is not int
        or raw["raw_byte_count"] < 0
        or raw["raw_byte_count"] > MAXIMUM_RAW_BYTES_PER_RESPONSE
    ):
        raise FutuSidecarError("raw response byte count is outside the limit")

    qot_logined = bool(pre["qot_logined"] and post["qot_logined"])
    trd_logined = bool(pre["trd_logined"] or post["trd_logined"])
    control_ok = all(
        state["ret_type"] == 0 and state["err_code"] == 0 for state in (pre, post)
    )
    if not qot_logined or not control_ok or data["ret_type"] != 0 or data["err_code"] != 0:
        status = "blocked"
    else:
        status = "completed"

    response_values: dict[str, Any] = {
        "schema_version": FUTU_SCHEMA_VERSION,
        "request_id": request.request_id,
        "request_fingerprint": request.fingerprint,
        "run_id": request.run_id,
        "serial_number": data["serial_number"],
        "retrieved_at": data["retrieved_at"],
        "ret_type": data["ret_type"],
        "err_code": data["err_code"],
        "status": status,
        "qot_logined": qot_logined,
        "trd_logined": trd_logined,
        "pre_global_state_serial_number": pre["serial_number"],
        "pre_global_state_trd_logined": pre["trd_logined"],
        "pre_global_state_request_fingerprint": pre["request_fingerprint"],
        "pre_global_state_response_fingerprint": pre["response_fingerprint"],
        "post_global_state_serial_number": post["serial_number"],
        "post_global_state_trd_logined": post["trd_logined"],
        "post_global_state_request_fingerprint": post["request_fingerprint"],
        "post_global_state_response_fingerprint": post["response_fingerprint"],
        "raw_evidence_kind": raw["evidence_kind"],
        "raw_plaintext_sha256": plaintext_sha,
        "encrypted_object_sha256": encrypted_sha,
        "cas_locator": raw["cas_locator"],
        "envelope_key_id": raw["envelope_key_id"],
        "raw_byte_count": raw["raw_byte_count"],
        "page_index": request.page_index,
        "next_key_sha256": (
            hashlib.sha256(next_key.encode("utf-8")).hexdigest()
            if next_key not in {None, "-1"}
            else None
        ),
        "terminal": data["terminal"],
        "parser_sha256": parser_sha256,
    }
    response_id, response_fingerprint = content_identity(
        "futu-response:",
        response_values,
        object_id_field="response_id",
        fingerprint_field="response_fingerprint",
    )
    response = FutuDataResponseReceipt(
        response_id=response_id,
        response_fingerprint=response_fingerprint,
        **response_values,
    )
    if response.status != "completed":
        return response, (), None
    wire_observations = data["observations"]
    if not isinstance(wire_observations, list) or len(wire_observations) > 10000:
        raise FutuSidecarError("sidecar observation collection is invalid")
    if request.protocol_id == 3243 and not wire_observations:
        raise FutuSidecarError("required company-profile response is empty")
    availability = [
        item
        for item in wire_observations
        if isinstance(item, dict) and item.get("field_id") == "availability"
    ]
    if request.protocol_id in _OPTIONAL_AVAILABILITY_PROTOCOL_IDS and (
        not wire_observations or (availability and len(wire_observations) != 1)
    ):
        raise FutuSidecarError(
            "optional Futu protocol must return data or one typed unavailable marker"
        )
    if request.protocol_id == 3227:
        wire_observations = list(
            _prepare_financial_wire_observations(wire_observations, request=request)
        )
    elif request.protocol_id == 3228:
        wire_observations = list(
            _prepare_revenue_breakdown_wire_observations(wire_observations)
        )
    elif request.protocol_id == 3234:
        wire_observations = list(_prepare_dividend_wire_observations(wire_observations))
    elif request.protocol_id == 3236:
        wire_observations = list(
            _prepare_split_wire_observations(
                wire_observations,
                request=request,
                terminal=response.terminal,
            )
        )
    observations = tuple(
        _materialize_observation(item, request=request, response=response)
        for item in wire_observations
    )
    return response, observations, None if next_key == "-1" else next_key


def _build_history_quota_receipt(
    *,
    request: FutuDataRequestReceipt,
    response: FutuDataResponseReceipt,
    observations: Sequence[FutuObservation],
    account_scope_sha256: str,
    runtime_authorization_fingerprint: str,
    runtime_request_plan: Sequence[Mapping[str, Any]],
    request_plan_fingerprint: str,
) -> FutuHistoricalKlineQuotaReceipt:
    if (
        request.protocol_id != 3104
        or request.stage != "runtime_authority"
        or request.parameters != FrozenMap({"get_detail": True})
        or response.request_id != request.request_id
        or response.request_fingerprint != request.fingerprint
        or response.status != "completed"
    ):
        raise FutuSidecarError("history quota source request or response is invalid")
    source = tuple(observations)
    if any(
        item.response_fingerprint != response.fingerprint
        or item.data_family != "historical_kline_quota"
        or item.use_scope != "runtime_authority"
        or item.comparison_eligible
        for item in source
    ):
        raise FutuSidecarError("history quota observations escaped their source response")
    aggregates: dict[str, FutuObservation] = {}
    details: list[FrozenMap] = []
    aggregate_fields = {"history_quota_used", "history_quota_remaining"}
    aggregate_qualifiers = {
        "get_detail": True,
        "quota_kind": "historical_candlestick_distinct_security_7d",
        "quota_window_days": 7,
    }
    for item in source:
        if item.field_id in aggregate_fields:
            if item.field_id in aggregates:
                raise FutuSidecarError("history quota contains a duplicate aggregate")
            if (
                to_json_value(item.period) != {"start": None, "end": None}
                or to_json_value(item.qualifiers) != aggregate_qualifiers
                or item.value_type != "number"
                or item.unit != "distinct_securities"
                or item.currency is not None
                or item.binary64_hex is not None
            ):
                raise FutuSidecarError("history quota aggregate shape is invalid")
            aggregates[item.field_id] = item
            continue
        if item.field_id != "history_quota_detail":
            raise FutuSidecarError("history quota contains an unknown observation")
        qualifiers = to_json_value(item.qualifiers)
        expected_detail_fields = {
            "last_request_at",
            "raw_market_code",
            "raw_security_code",
            "source_request_time",
            "source_request_timestamp",
            "vendor_security_code",
        }
        if (
            not isinstance(qualifiers, dict)
            or set(qualifiers) != expected_detail_fields
            or to_json_value(item.period) != {"start": None, "end": None}
            or item.value_type != "text"
            or item.unit is not None
            or item.currency is not None
            or item.binary64_hex is not None
            or item.exact_binary64_decimal is not None
        ):
            raise FutuSidecarError("history quota detail observation is invalid")
        expected_value = qualifiers["vendor_security_code"]
        if expected_value is None:
            expected_value = (
                f'{qualifiers["raw_market_code"]}:{qualifiers["raw_security_code"]}'
            )
        if item.value != expected_value:
            raise FutuSidecarError("history quota detail value is rebound")
        details.append(freeze(qualifiers))
    if set(aggregates) != aggregate_fields:
        raise FutuSidecarError("history quota aggregates are incomplete")

    def nonnegative_integer(field_id: str) -> int:
        value = aggregates[field_id].value
        try:
            parsed = Decimal(str(value))
        except (ArithmeticError, ValueError) as exc:
            raise FutuSidecarError("history quota count is invalid") from exc
        if parsed < 0 or parsed != parsed.to_integral_value():
            raise FutuSidecarError("history quota count must be a non-negative integer")
        return int(parsed)

    plan = tuple(freeze(item) for item in runtime_request_plan)
    planned = tuple(
        sorted(
            {
                str(item["security_code"])
                for item in plan
                if item["protocol_id"] == 3103
            }
        )
    )
    visible_codes = {
        str(item["vendor_security_code"])
        for item in details
        if item["vendor_security_code"] is not None
    }
    already = tuple(sorted(set(planned).intersection(visible_codes)))
    required_incremental = len(planned) - len(already)
    remaining = nonnegative_integer("history_quota_remaining")
    values: dict[str, Any] = {
        "schema_version": FUTU_SCHEMA_VERSION,
        "run_id": request.run_id,
        "account_scope_sha256": account_scope_sha256,
        "runtime_authorization_fingerprint": runtime_authorization_fingerprint,
        "runtime_request_plan": plan,
        "request_plan_fingerprint": request_plan_fingerprint,
        "protocol_id": 3104,
        "observed_at": response.retrieved_at,
        "quota_kind": "historical_candlestick_distinct_security_7d",
        "quota_window_days": 7,
        "used_quota": nonnegative_integer("history_quota_used"),
        "remaining_quota": remaining,
        "detail_records": tuple(details),
        "planned_history_security_codes": planned,
        "already_counted_security_codes": already,
        "required_incremental_security_count": required_incremental,
        "sufficient": remaining >= required_incremental,
        "source_request_fingerprint": request.fingerprint,
        "source_response_fingerprint": response.fingerprint,
    }
    receipt_id, receipt_fingerprint = content_identity(
        "futu-history-quota:",
        values,
        object_id_field="receipt_id",
        fingerprint_field="receipt_fingerprint",
    )
    return FutuHistoricalKlineQuotaReceipt(
        receipt_id=receipt_id,
        receipt_fingerprint=receipt_fingerprint,
        **values,
    )


def _materialize_observation(
    value: Any,
    *,
    request: FutuDataRequestReceipt,
    response: FutuDataResponseReceipt,
) -> FutuObservation:
    item = _exact_members(
        value,
        {
            "field_id",
            "period",
            "qualifiers",
            "value_type",
            "value",
            "unit",
            "currency",
            "binary64_hex",
            "exact_binary64_decimal",
        },
        "sidecar observation",
    )
    if not isinstance(item["field_id"], str) or not item["field_id"]:
        raise FutuSidecarError("sidecar observation field_id is invalid")
    if item["field_id"] == "availability":
        if (
            request.protocol_id not in _OPTIONAL_AVAILABILITY_PROTOCOL_IDS
            or item["qualifiers"]
            != {
                "availability_status": "unavailable",
                "reason_code": "official_no_data",
            }
            or item["value_type"] != "null"
            or item["value"] is not None
            or item["unit"] is not None
            or item["currency"] is not None
            or item["binary64_hex"] is not None
            or item["exact_binary64_decimal"] is not None
        ):
            raise FutuSidecarError("optional protocol unavailable marker is invalid")
    period = _exact_members(item["period"], {"start", "end"}, "observation period")
    if any(value is not None and not isinstance(value, str) for value in period.values()):
        raise FutuSidecarError("observation period values must be dates or null")
    qualifiers = item["qualifiers"]
    if not isinstance(qualifiers, dict):
        raise FutuSidecarError("observation qualifiers must be an object")
    _plain_json_value(qualifiers, "observation qualifiers")
    financial_mapping = None
    if request.data_family in {"financial_statements", "revenue_breakdown"}:
        candidate_mapping = load_financial_field_registry().get(item["field_id"])
        if candidate_mapping is not None and _financial_mapping_applies(
            candidate_mapping,
            qualifiers=qualifiers,
            unit=item["unit"],
            data_family=request.data_family,
        ):
            financial_mapping = candidate_mapping
    if request.data_family == "corporate_actions" and item["field_id"] == (
        "stock_split_event"
    ):
        canonical_concept = qualifiers.get("event_type")
    else:
        canonical_concept = (
            financial_mapping["canonical_concept"]
            if financial_mapping is not None
            else _CONCEPT_MAP.get((request.data_family, item["field_id"]))
        )
    source_role = (
        "governed_broker_vendor" if request.data_family == "market_price" else "vendor_secondary"
    )
    point_in_time_status = (
        "point_in_time" if request.data_family == "market_price" else "current_snapshot"
    )
    observation_values: dict[str, Any] = {
        "schema_version": FUTU_SCHEMA_VERSION,
        "issuer_id": request.issuer_id,
        "security_id": request.security_id,
        "data_family": request.data_family,
        "field_id": item["field_id"],
        "canonical_concept": canonical_concept,
        "period": period,
        "qualifiers": qualifiers,
        "value_type": item["value_type"],
        "value": item["value"],
        "unit": item["unit"],
        "currency": item["currency"],
        "binary64_hex": item["binary64_hex"],
        "exact_binary64_decimal": item["exact_binary64_decimal"],
        "response_fingerprint": response.fingerprint,
        "retrieved_at": response.retrieved_at,
        "point_in_time_status": point_in_time_status,
        "source_role": source_role,
        "use_scope": request.stage,
        "comparison_eligible": canonical_concept is not None,
    }
    observation_id, observation_fingerprint = content_identity(
        "futu-observation:",
        observation_values,
        object_id_field="observation_id",
        fingerprint_field="observation_fingerprint",
    )
    return FutuObservation(
        observation_id=observation_id,
        observation_fingerprint=observation_fingerprint,
        **observation_values,
    )


def _financial_mapping_applies(
    mapping: Mapping[str, Any],
    *,
    qualifiers: Mapping[str, Any],
    unit: Any,
    data_family: str,
) -> bool:
    required_qualifiers = {
        "accounting_standard": mapping["accounting_standard_scope"],
        "futu_api_version": mapping["futu_api_version"],
        "normalized_financial_field_display_name": mapping["normalized_display_name"],
        "statement_type": mapping["statement_type"],
        "period_kind": mapping["period_kind"],
    }
    if mapping["period_kind"] == "flow":
        required_qualifiers.update(
            {
                "financial_period_start_derivation": (
                    "previous_annual_period_end_plus_one_day"
                ),
                "financial_period_status": "consecutive_annual_period",
            }
        )
    elif mapping["period_kind"] == "stock":
        required_qualifiers.update(
            {
                "financial_period_start_derivation": "not_applicable",
                "financial_period_status": "instant",
            }
        )
    return (
        data_family == mapping["data_family"]
        and mapping["sign_convention"] == "reported_signed"
        and unit == mapping["unit"]
        and all(qualifiers.get(key) == value for key, value in required_qualifiers.items())
    )


def _validate_daily_close_observations(
    observations: Sequence[FutuObservation],
    *,
    expected_trading_date: str | None,
) -> None:
    if expected_trading_date is None or len(observations) != 2:
        raise FutuSidecarError("daily close response must contain exactly one price row")
    by_field = {observation.field_id: observation for observation in observations}
    if set(by_field) != {"close", "volume"}:
        raise FutuSidecarError("daily close row must contain close and volume")
    close = by_field["close"]
    volume = by_field["volume"]
    if (
        close.period["end"] != expected_trading_date
        or volume.period["end"] != expected_trading_date
    ):
        raise FutuSidecarError("daily close row date does not match the expected trading date")
    if close.value_type != "number" or Decimal(str(close.value)) <= 0:
        raise FutuSidecarError("daily close must be finite and positive")
    if close.unit != "currency_per_share" or close.currency != "USD":
        raise FutuSidecarError("daily close must be USD per share")
    if volume.value_type != "number" or Decimal(str(volume.value)) <= 0:
        raise FutuSidecarError("daily close volume must be positive")
    if volume.unit != "shares" or volume.currency is not None:
        raise FutuSidecarError("daily volume unit must be shares")


def adapt_futu_daily_close_to_market_reference(
    *,
    authority: FutuAuthorityDecision,
    request: FutuDataRequestReceipt,
    response: FutuDataResponseReceipt,
    observation: FutuObservation,
) -> FutuDailyCloseAdapterResult:
    """Explicitly map an eligible Futu candidate to the frozen market price-basis label."""
    evidence = authority.daily_close_semantics_evidence_fingerprint
    if authority.status != "eligible" or evidence is None:
        raise FutuSidecarError("daily-close semantics gate is not eligible")
    if (
        request.stage not in {"market_reference", "peer_comparable_reference"}
        or request.protocol_id != 3103
        or request.expected_trading_date is None
        or response.status != "completed"
        or response.request_id != request.request_id
        or response.request_fingerprint != request.fingerprint
        or observation.response_fingerprint != response.fingerprint
        or observation.issuer_id != request.issuer_id
        or observation.security_id != request.security_id
        or observation.canonical_concept != "futu_unadjusted_daily_close_candidate"
        or observation.field_id != "close"
        or observation.period["end"] != request.expected_trading_date
        or observation.value_type != "number"
        or observation.unit != "currency_per_share"
        or observation.currency != "USD"
        or Decimal(str(observation.value)) <= 0
    ):
        raise FutuSidecarError("daily-close observation is not eligible for adaptation")
    values = {
        "schema_version": FUTU_SCHEMA_VERSION,
        "issuer_id": observation.issuer_id,
        "security_id": observation.security_id,
        "trading_date": request.expected_trading_date,
        "close_decimal": str(observation.value),
        "currency": "USD",
        "market_reference_basis": "official_unadjusted_close",
        "source_observation_id": observation.observation_id,
        "source_observation_fingerprint": observation.fingerprint,
        "source_request_fingerprint": request.fingerprint,
        "semantics_evidence_fingerprint": evidence,
    }
    return FutuDailyCloseAdapterResult(
        adapter_fingerprint=canonical_sha256(values),
        **values,
    )


def _protocol_allowed_in_stage(
    protocol_id: int,
    registry_stage: str,
    requested_stage: str,
) -> bool:
    if requested_stage == "peer_comparable_reference":
        return protocol_id in _PEER_COMPARABLE_PROTOCOL_IDS
    return registry_stage == requested_stage


def _reference(object_id: str, fingerprint: str) -> dict[str, str]:
    return {"object_id": object_id, "fingerprint": fingerprint}


def _make_bundle(
    *,
    authority: FutuAuthorityDecision,
    run_id: str,
    issuer_id: str,
    security_id: str,
    stage: str,
    status: str,
    issues: Sequence[str],
    requests: Sequence[FutuDataRequestReceipt],
    responses: Sequence[FutuDataResponseReceipt],
    observations: Sequence[FutuObservation],
) -> FutuEvidenceBundle:
    normalized_issues = tuple(sorted(set(issues)))
    unknown = set(normalized_issues).difference(load_issue_codes())
    if unknown:
        raise FutuSidecarError(f"unregistered Futu issue code: {sorted(unknown)[0]}")
    values: dict[str, Any] = {
        "schema_version": FUTU_SCHEMA_VERSION,
        "run_id": run_id,
        "issuer_id": issuer_id,
        "security_id": security_id,
        "stage": stage,
        "status": status,
        "authority_decision_fingerprint": authority.fingerprint,
        "requests": [_reference(item.request_id, item.fingerprint) for item in requests],
        "responses": [_reference(item.response_id, item.fingerprint) for item in responses],
        "observations": [
            _reference(item.observation_id, item.fingerprint) for item in observations
        ],
        "cross_checks": [],
        "issues": list(normalized_issues),
    }
    bundle_id, bundle_fingerprint = content_identity(
        "futu-bundle:",
        values,
        object_id_field="bundle_id",
        fingerprint_field="bundle_fingerprint",
    )
    return FutuEvidenceBundle(
        bundle_id=bundle_id,
        bundle_fingerprint=bundle_fingerprint,
        **values,
    )
