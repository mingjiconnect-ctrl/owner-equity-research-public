from __future__ import annotations

import copy
import json
import math
import re
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import cache
from pathlib import Path
from typing import Any, ClassVar, Protocol

from jsonschema import Draft202012Validator, FormatChecker

from .fingerprints import FrozenMap, canonical_json, canonical_sha256, freeze, to_json_value
from .valuation_synthesis_types import (
    CompositeValuationResult,
    OwnerScorecard,
    retained_authority_replay_scope,
)

FUTU_SCHEMA_VERSION = "1.0.0"
FUTU_POLICY_VERSION = "2.0.0"
FUTU_RUNTIME_AUTHORIZATION_MAX_SECONDS = 15 * 60
FUTU_RUNTIME_AUTHORIZATION_MAX_ISSUANCE_SKEW_SECONDS = 5 * 60
FUTU_RUNTIME_MAXIMUM_PAGES_PER_PROTOCOL = 64
FUTU_RUNTIME_MAXIMUM_PLANNED_REQUESTS = 128
PINNED_FUTU_API_VERSION = "10.10.7008"
PINNED_FUTU_API_DISTRIBUTION_SHA256 = (
    "3c607c7dce02a3a2b308f3424420277a360d7b3a4ba4508b39eaa4ff11271f98"
)
PINNED_SDK_OPERATION_REGISTRY_SHA256 = (
    "48be8aa86fd9c5fc5b5a3b201939c0bd4386b23dbe408d9f30a8e190ce3bbc4a"
)
PINNED_PROTOBUF_DESCRIPTOR_SET_SHA256 = (
    "c2b13581ef9acdbe2b9a95da26b95d6321058f7beb27b56fef90908519e312f8"
)
FUTU_INFRASTRUCTURE_PROTOCOL_IDS = frozenset({1001, 1002, 1004})
FUTU_US_PRODUCT_PROTOCOL_IDS = frozenset(
    {
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
    }
)
FUTU_RUNTIME_PROTOCOL_IDS = tuple(
    sorted(FUTU_INFRASTRUCTURE_PROTOCOL_IDS | FUTU_US_PRODUCT_PROTOCOL_IDS)
)

_SCHEMA_DIRECTORY = (
    Path(__file__).parent / "resources" / "futu" / "extension_schemas" / "v1"
)
_SCHEMA_NAMES = frozenset(
    {
        "futu-account-entitlement-receipt",
        "futu-cross-check-receipt",
        "futu-frozen-conclusion-receipt",
        "futu-historical-kline-quota-receipt",
        "futu-data-request-receipt",
        "futu-data-response-receipt",
        "futu-evidence-bundle",
        "futu-legal-rights-receipt",
        "futu-market-execution-evidence",
        "futu-market-execution-publication-manifest",
        "futu-observation",
        "futu-observation-disposition-receipt",
        "futu-observation-disposition-publication-bundle",
        "futu-partial-session-publication-manifest",
        "futu-peer-evidence-set",
        "futu-peer-session-evidence",
        "futu-runtime-isolation-authorization",
        "futu-runtime-isolation-receipt",
        "futu-security-identity-receipt",
        "futu-session-evidence",
        "futu-session-publication-manifest",
        "futu-supply-chain-receipt",
    }
)
_MAXIMUM_EXTENSION_SCHEMA_BYTES = 256 * 1024
_CANONICAL_DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_VENDOR_SECURITY_CODE = re.compile(r"US\.[A-Z0-9][A-Z0-9.-]{0,31}\Z")
_SIGNER_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_RUNTIME_PLAN_PROTOCOL_IDS = frozenset(
    {
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
    }
)
_INTERNALLY_PAGED_PROTOCOL_IDS = frozenset({3227, 3230, 3236, 3246})


def _encoded_opend_server_version(version: str) -> int:
    """Encode the pinned dotted OpenD version as returned by GlobalState.serverVer."""
    parts = version.split(".") if isinstance(version, str) else []
    if (
        len(parts) != 3
        or any(not item.isascii() or not item.isdecimal() for item in parts)
        or any(len(item) > 1 and item.startswith("0") for item in parts)
    ):
        raise FutuReceiptError("OpenD version must be a canonical major.minor.patch string")
    major, minor, patch = (int(item) for item in parts)
    if not (1 <= major <= 99 and 0 <= minor <= 99 and 0 <= patch <= 99_999):
        raise FutuReceiptError("OpenD version components are outside the serverVer encoding")
    return major * 10_000_000 + minor * 100_000 + patch


class FutuReceiptError(ValueError):
    """Raised when a Futu extension object violates its closed contract."""


class SignatureVerifier(Protocol):
    """Verifier supplied by the trusted host; the wheel carries no signing keys."""

    def verify(
        self,
        *,
        signer_key_id: str,
        payload: bytes,
        signature_hex: str,
    ) -> bool: ...


@cache
def _load_futu_schema(name: str) -> dict[str, Any]:
    if name not in _SCHEMA_NAMES:
        raise KeyError(f"Unknown Futu extension schema: {name}")
    path = _SCHEMA_DIRECTORY / f"{name}.schema.json"
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAXIMUM_EXTENSION_SCHEMA_BYTES + 1)
        if len(raw) > _MAXIMUM_EXTENSION_SCHEMA_BYTES:
            raise FutuReceiptError(f"Futu extension schema exceeds byte limit: {name}")
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FutuReceiptError(f"Futu extension schema is unavailable: {name}") from exc
    if not isinstance(payload, dict):
        raise FutuReceiptError(f"Futu extension schema must be an object: {name}")
    return payload


def load_futu_schema(name: str) -> dict[str, Any]:
    """Load a detached Futu schema without extending the frozen public schema map."""
    return copy.deepcopy(_load_futu_schema(name))


@cache
def futu_schema_validator(name: str) -> Draft202012Validator:
    schema = _load_futu_schema(name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_futu_payload(name: str, payload: Mapping[str, Any]) -> None:
    errors = sorted(
        futu_schema_validator(name).iter_errors(to_json_value(payload)),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        raise FutuReceiptError(f"{name} validation failed at {location}: {error.message}")


def _utc_datetime(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FutuReceiptError(f"{label} must be an RFC 3339 date-time") from exc
    if parsed.tzinfo is None:
        raise FutuReceiptError(f"{label} must include a UTC offset")
    return parsed.astimezone(UTC)


def _canonical_decimal(value: str, label: str) -> Decimal:
    if not isinstance(value, str) or _CANONICAL_DECIMAL.fullmatch(value) is None:
        raise FutuReceiptError(f"{label} must be a canonical decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise FutuReceiptError(f"{label} must be a canonical decimal string") from exc
    if not parsed.is_finite():
        raise FutuReceiptError(f"{label} must be finite")
    return parsed


def _identity_digest(payload: Mapping[str, Any], *identity_fields: str) -> str:
    return canonical_sha256(
        {key: value for key, value in payload.items() if key not in identity_fields}
    )


@dataclass(frozen=True, slots=True)
class FutuContract:
    SCHEMA_NAME: ClassVar[str]

    def __post_init__(self) -> None:
        payload = {field.name: to_json_value(getattr(self, field.name)) for field in fields(self)}
        validate_futu_payload(self.SCHEMA_NAME, payload)
        for field in fields(self):
            object.__setattr__(self, field.name, freeze(getattr(self, field.name)))

    def to_dict(self) -> dict[str, Any]:
        return {field.name: to_json_value(getattr(self, field.name)) for field in fields(self)}

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _validate_signed_receipt(receipt: FutuContract, prefix: str) -> None:
    payload = receipt.to_dict()
    expected = f"{prefix}{_identity_digest(payload, 'receipt_id', 'signature_hex')}"
    if payload["receipt_id"] != expected:
        raise FutuReceiptError("receipt_id does not bind the complete unsigned receipt identity")


def signed_receipt_identity(
    prefix: str,
    values: Mapping[str, Any],
) -> str:
    """Return the deterministic ID to use before signing a receipt."""
    payload = {key: to_json_value(value) for key, value in values.items()}
    payload.pop("receipt_id", None)
    payload.pop("signature_hex", None)
    return f"{prefix}{canonical_sha256(payload)}"


def signed_receipt_payload(receipt: FutuContract) -> bytes:
    payload = receipt.to_dict()
    if "signature_hex" not in payload or "receipt_id" not in payload:
        raise FutuReceiptError("object is not a signed Futu receipt")
    payload.pop("signature_hex")
    return canonical_json(payload).encode("utf-8")


def futu_request_parameters_sha256(parameters: Mapping[str, Any]) -> str:
    """Commit the exact caller-controlled SDK parameter object used by one plan item."""
    materialized = to_json_value(parameters)
    if not isinstance(materialized, dict):
        raise FutuReceiptError("Futu request parameters must be an object")
    return canonical_sha256(materialized)


def build_futu_runtime_request_plan_item(
    *,
    plan_index: int,
    security_code: str,
    protocol_id: int,
    parameters: Mapping[str, Any],
    maximum_pages: int = 1,
    activation_condition: str | None = None,
) -> FrozenMap:
    """Build one closed pre-authorized operation; page keys remain sidecar-internal."""
    pagination_mode = (
        "internal" if protocol_id in _INTERNALLY_PAGED_PROTOCOL_IDS else "none"
    )
    condition = (
        "eligible_conclusion_only"
        if protocol_id in {3229, 3230, 3232}
        else "always"
    )
    if activation_condition is not None:
        condition = activation_condition
    item = {
        "plan_index": plan_index,
        "security_code": security_code,
        "protocol_id": protocol_id,
        "parameters_sha256": futu_request_parameters_sha256(parameters),
        "pagination_mode": pagination_mode,
        "maximum_pages": maximum_pages,
        "activation_condition": condition,
    }
    _validate_runtime_request_plan_item(item)
    return freeze(item)


def _validate_runtime_request_plan_item(item: Mapping[str, Any]) -> None:
    expected_fields = {
        "plan_index",
        "security_code",
        "protocol_id",
        "parameters_sha256",
        "pagination_mode",
        "maximum_pages",
        "activation_condition",
    }
    if set(item) != expected_fields:
        raise FutuReceiptError("runtime request-plan item fields are not closed")
    protocol_id = item["protocol_id"]
    maximum_pages = item["maximum_pages"]
    expected_mode = (
        "internal" if protocol_id in _INTERNALLY_PAGED_PROTOCOL_IDS else "none"
    )
    if (
        type(item["plan_index"]) is not int
        or item["plan_index"] < 0
        or not isinstance(item["security_code"], str)
        or _VENDOR_SECURITY_CODE.fullmatch(item["security_code"]) is None
        or type(protocol_id) is not int
        or protocol_id not in _RUNTIME_PLAN_PROTOCOL_IDS
        or not isinstance(item["parameters_sha256"], str)
        or _SHA256.fullmatch(item["parameters_sha256"]) is None
        or item["pagination_mode"] != expected_mode
        or type(maximum_pages) is not int
        or not 1 <= maximum_pages <= FUTU_RUNTIME_MAXIMUM_PAGES_PER_PROTOCOL
        or (expected_mode == "none" and maximum_pages != 1)
        or item["activation_condition"]
        != (
            "eligible_conclusion_only"
            if protocol_id in {3229, 3230, 3232}
            else "always"
        )
    ):
        raise FutuReceiptError("runtime request-plan item is invalid")


@dataclass(frozen=True, slots=True)
class FutuLegalRightsReceipt(FutuContract):
    SCHEMA_NAME: ClassVar[str] = "futu-legal-rights-receipt"
    schema_version: str
    receipt_id: str
    policy_sha256: str
    component_lock_sha256: str
    account_scope_sha256: str
    agreement_sha256: str
    allowed_mics: tuple[str, ...]
    allowed_currencies: tuple[str, ...]
    allowed_data_families: tuple[str, ...]
    allowed_protocol_ids: tuple[int, ...]
    rights: FrozenMap
    effective_at: str
    issued_at: str
    expires_at: str
    revoked_at: str | None
    signature_algorithm: str
    signer_key_id: str
    signature_hex: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_signed_receipt(self, "futu-legal:")
        effective = _utc_datetime(self.effective_at, "effective_at")
        issued = _utc_datetime(self.issued_at, "issued_at")
        expires = _utc_datetime(self.expires_at, "expires_at")
        if max(effective, issued) >= expires:
            raise FutuReceiptError("legal receipt must be effective and issued before expiry")
        if self.revoked_at is not None and _utc_datetime(self.revoked_at, "revoked_at") < effective:
            raise FutuReceiptError("revoked_at cannot precede effective_at")


@dataclass(frozen=True, slots=True)
class FutuAccountEntitlementReceipt(FutuContract):
    SCHEMA_NAME: ClassVar[str] = "futu-account-entitlement-receipt"
    schema_version: str
    receipt_id: str
    run_id: str
    policy_sha256: str
    component_lock_sha256: str
    account_scope_sha256: str
    observed_at: str
    global_state_response_fingerprint: str
    qot_logined: bool
    trd_logined: bool
    entitlements: FrozenMap
    delay_class: str
    promotion_status: str
    quota_remaining: int
    protocol_version: str
    challenge_nonce: str
    issued_at: str
    expires_at: str
    signature_algorithm: str
    signer_key_id: str
    signature_hex: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_signed_receipt(self, "futu-account:")
        observed = _utc_datetime(self.observed_at, "observed_at")
        issued = _utc_datetime(self.issued_at, "issued_at")
        expires = _utc_datetime(self.expires_at, "expires_at")
        if observed > issued or issued >= expires:
            raise FutuReceiptError("account receipt chronology is invalid")


@dataclass(frozen=True, slots=True)
class FutuHistoricalKlineQuotaReceipt(FutuContract):
    """Attested 3104 quota projection bound to one signed sidecar response.

    The receipt deliberately carries no raw vendor payload.  Its source request and
    response fingerprints are retained in the signed sidecar execution chain, while
    this closed projection proves the exact distinct-security budget used by the host.
    """

    SCHEMA_NAME: ClassVar[str] = "futu-historical-kline-quota-receipt"
    schema_version: str
    receipt_id: str
    run_id: str
    account_scope_sha256: str
    runtime_authorization_fingerprint: str
    runtime_request_plan: tuple[FrozenMap, ...]
    request_plan_fingerprint: str
    protocol_id: int
    observed_at: str
    quota_kind: str
    quota_window_days: int
    used_quota: int
    remaining_quota: int
    detail_records: tuple[FrozenMap, ...]
    planned_history_security_codes: tuple[str, ...]
    already_counted_security_codes: tuple[str, ...]
    required_incremental_security_count: int
    sufficient: bool
    source_request_fingerprint: str
    source_response_fingerprint: str
    receipt_fingerprint: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_content_identity(
            self,
            prefix="futu-history-quota:",
            object_id_field="receipt_id",
            fingerprint_field="receipt_fingerprint",
        )
        observed = _utc_datetime(self.observed_at, "quota observed_at")
        if (
            self.protocol_id != 3104
            or self.quota_kind != "historical_candlestick_distinct_security_7d"
            or self.quota_window_days != 7
        ):
            raise FutuReceiptError("historical K-line quota authority is invalid")
        planned = tuple(self.planned_history_security_codes)
        already = tuple(self.already_counted_security_codes)
        request_plan = tuple(self.runtime_request_plan)
        for index, item in enumerate(request_plan):
            _validate_runtime_request_plan_item(item)
            if item["plan_index"] != index:
                raise FutuReceiptError("historical K-line runtime plan is reordered")
        history_codes = tuple(
            sorted(
                {
                    str(item["security_code"])
                    for item in request_plan
                    if item["protocol_id"] == 3103
                }
            )
        )
        quota_items = tuple(item for item in request_plan if item["protocol_id"] == 3104)
        if (
            not 6 <= len(planned) <= 16
            or planned != tuple(sorted(set(planned)))
            or any(_VENDOR_SECURITY_CODE.fullmatch(item) is None for item in planned)
            or already != tuple(sorted(set(already)))
            or not set(already).issubset(planned)
            or not request_plan
            or len(request_plan) > FUTU_RUNTIME_MAXIMUM_PLANNED_REQUESTS
            or self.request_plan_fingerprint
            != canonical_sha256(to_json_value(request_plan))
            or history_codes != planned
            or len(quota_items) != 1
            or request_plan[0] != quota_items[0]
            or quota_items[0]["parameters_sha256"]
            != futu_request_parameters_sha256({"get_detail": True})
        ):
            raise FutuReceiptError("historical K-line quota security plan is invalid")
        details = tuple(self.detail_records)
        identities: set[tuple[int, str]] = set()
        visible_us_codes: set[str] = set()
        window_start = observed - timedelta(days=self.quota_window_days)
        for item in details:
            materialized = to_json_value(item)
            if not isinstance(materialized, dict) or set(materialized) != {
                "last_request_at",
                "raw_market_code",
                "raw_security_code",
                "source_request_time",
                "source_request_timestamp",
                "vendor_security_code",
            }:
                raise FutuReceiptError("historical K-line quota detail is not closed")
            identity = (
                materialized["raw_market_code"],
                materialized["raw_security_code"],
            )
            last_request = _utc_datetime(
                materialized["last_request_at"],
                "quota detail last_request_at",
            )
            if (
                type(identity[0]) is not int
                or identity[0] < 0
                or not isinstance(identity[1], str)
                or not identity[1]
                or identity in identities
                or not isinstance(materialized["source_request_time"], str)
                or not materialized["source_request_time"].strip()
                or (
                    materialized["source_request_timestamp"] is not None
                    and (
                        type(materialized["source_request_timestamp"]) is not int
                        or materialized["source_request_timestamp"] <= 0
                    )
                )
                or not window_start <= last_request <= observed
            ):
                raise FutuReceiptError("historical K-line quota detail is invalid")
            identities.add(identity)
            vendor_code = materialized["vendor_security_code"]
            if vendor_code is not None:
                if (
                    not isinstance(vendor_code, str)
                    or _VENDOR_SECURITY_CODE.fullmatch(vendor_code) is None
                    or vendor_code in visible_us_codes
                ):
                    raise FutuReceiptError("historical K-line quota US detail is invalid")
                visible_us_codes.add(vendor_code)
        expected_already = tuple(sorted(set(planned).intersection(visible_us_codes)))
        expected_incremental = len(planned) - len(expected_already)
        if (
            self.used_quota != len(details)
            or self.remaining_quota < 0
            or already != expected_already
            or self.required_incremental_security_count != expected_incremental
            or self.sufficient != (self.remaining_quota >= expected_incremental)
        ):
            raise FutuReceiptError("historical K-line quota arithmetic is invalid")

    @property
    def fingerprint(self) -> str:
        return self.receipt_fingerprint


@dataclass(frozen=True, slots=True)
class FutuSupplyChainReceipt(FutuContract):
    SCHEMA_NAME: ClassVar[str] = "futu-supply-chain-receipt"
    schema_version: str
    receipt_id: str
    policy_sha256: str
    component_lock_sha256: str
    provider_id: str
    provider_version: str
    opend_version: str
    opend_server_version: int
    opend_server_build_no: int
    futu_api_version: str
    futu_api_distribution_sha256: str
    sdk_operation_registry_sha256: str
    protobuf_descriptor_set_sha256: str
    official_distribution_url: str
    distribution_sha256: str
    publisher_signature_status: str
    protocol_descriptor_sha256: str
    facade_sha256: str
    adapter_sha256: str
    parser_sha256: str
    vm_image_sha256: str
    sbom_sha256: str
    license_sha256: str
    daily_close_semantics_evidence_kind: str
    daily_close_semantics_evidence_sha256: str | None
    issued_at: str
    expires_at: str
    signature_algorithm: str
    signer_key_id: str
    signature_hex: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_signed_receipt(self, "futu-supply:")
        if _utc_datetime(self.issued_at, "issued_at") >= _utc_datetime(
            self.expires_at, "expires_at"
        ):
            raise FutuReceiptError("supply-chain receipt must be issued before expiry")
        if (
            self.futu_api_version != PINNED_FUTU_API_VERSION
            or self.futu_api_distribution_sha256
            != PINNED_FUTU_API_DISTRIBUTION_SHA256
            or self.sdk_operation_registry_sha256
            != PINNED_SDK_OPERATION_REGISTRY_SHA256
            or self.protobuf_descriptor_set_sha256
            != PINNED_PROTOBUF_DESCRIPTOR_SET_SHA256
        ):
            raise FutuReceiptError("supply-chain receipt drifted from the pinned Futu SDK")
        if (
            type(self.opend_server_version) is not int
            or self.opend_server_version <= 0
            or type(self.opend_server_build_no) is not int
            or self.opend_server_build_no <= 0
            or self.opend_server_version
            != _encoded_opend_server_version(self.opend_version)
        ):
            raise FutuReceiptError(
                "supply-chain receipt lacks the pinned OpenD server identity"
            )
        evidence_is_none = self.daily_close_semantics_evidence_kind == "none"
        if evidence_is_none != (self.daily_close_semantics_evidence_sha256 is None):
            raise FutuReceiptError(
                "daily-close semantics evidence kind and digest must be present together"
            )


@dataclass(frozen=True, slots=True)
class FutuRuntimeIsolationAuthorization(FutuContract):
    """Signed, pre-run authorization for one isolated quote-only OpenD session."""

    SCHEMA_NAME: ClassVar[str] = "futu-runtime-isolation-authorization"
    schema_version: str
    receipt_id: str
    run_id: str
    policy_sha256: str
    component_lock_sha256: str
    account_scope_sha256: str
    supply_chain_fingerprint: str
    vm_image_sha256: str
    opend_version: str
    rootless: bool
    credentials_location: str
    host_opend_port_mapped: bool
    generic_raw_send_enabled: bool
    logging_enabled: bool
    reminder_push_enabled: bool
    automatic_quote_right_takeover_enabled: bool
    trade_and_account_protocols_rejected_before_opend: bool
    allowed_protocol_ids: tuple[int, ...]
    authorized_security_codes: tuple[str, ...]
    request_plan: tuple[FrozenMap, ...]
    request_plan_fingerprint: str
    maximum_planned_requests: int
    maximum_pages_per_protocol: int
    sidecar_attestor_key_id: str
    authorization_window_seconds: int
    issued_at: str
    valid_from: str
    expires_at: str
    signature_algorithm: str
    signer_key_id: str
    signature_hex: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_signed_receipt(self, "futu-runtime-authorization:")
        issued = _utc_datetime(self.issued_at, "issued_at")
        valid_from = _utc_datetime(self.valid_from, "valid_from")
        expires = _utc_datetime(self.expires_at, "expires_at")
        if not (issued <= valid_from < expires):
            raise FutuReceiptError("runtime authorization chronology is invalid")
        if (
            self.authorization_window_seconds
            != FUTU_RUNTIME_AUTHORIZATION_MAX_SECONDS
            or valid_from - issued
            > timedelta(seconds=FUTU_RUNTIME_AUTHORIZATION_MAX_ISSUANCE_SKEW_SECONDS)
            or expires - valid_from
            > timedelta(seconds=FUTU_RUNTIME_AUTHORIZATION_MAX_SECONDS)
        ):
            raise FutuReceiptError("runtime authorization exceeds its one-session window")
        if (
            not 6 <= len(self.authorized_security_codes) <= 16
            or len(set(self.authorized_security_codes))
            != len(self.authorized_security_codes)
            or any(
                _VENDOR_SECURITY_CODE.fullmatch(code) is None
                for code in self.authorized_security_codes
            )
            or not self.request_plan
            or len(self.request_plan) > FUTU_RUNTIME_MAXIMUM_PLANNED_REQUESTS
            or self.maximum_pages_per_protocol
            != FUTU_RUNTIME_MAXIMUM_PAGES_PER_PROTOCOL
            or _SIGNER_KEY_ID.fullmatch(self.sidecar_attestor_key_id) is None
            or self.allowed_protocol_ids != FUTU_RUNTIME_PROTOCOL_IDS
        ):
            raise FutuReceiptError("runtime authorization security or request plan is invalid")
        for index, item in enumerate(self.request_plan):
            _validate_runtime_request_plan_item(item)
            if (
                item["plan_index"] != index
                or item["security_code"] not in self.authorized_security_codes
                or item["protocol_id"] not in self.allowed_protocol_ids
            ):
                raise FutuReceiptError("runtime request plan escaped its signed authority")
        conditions = tuple(item["activation_condition"] for item in self.request_plan)
        first_conditional = next(
            (index for index, value in enumerate(conditions) if value != "always"),
            len(conditions),
        )
        if any(value != "eligible_conclusion_only" for value in conditions[first_conditional:]):
            raise FutuReceiptError(
                "runtime request plan conditional operations must form one suffix"
            )
        if self.request_plan[0]["security_code"] != self.authorized_security_codes[0]:
            raise FutuReceiptError("runtime request plan must begin with the target security")
        maximum_requests = sum(item["maximum_pages"] for item in self.request_plan)
        if (
            self.maximum_planned_requests != maximum_requests
            or maximum_requests > FUTU_RUNTIME_MAXIMUM_PLANNED_REQUESTS
            or self.request_plan_fingerprint
            != canonical_sha256(to_json_value(self.request_plan))
        ):
            raise FutuReceiptError("runtime request-plan fingerprint or limits are invalid")


@dataclass(frozen=True, slots=True)
class FutuRuntimeIsolationReceipt(FutuContract):
    SCHEMA_NAME: ClassVar[str] = "futu-runtime-isolation-receipt"
    schema_version: str
    receipt_id: str
    run_id: str
    policy_sha256: str
    component_lock_sha256: str
    account_scope_sha256: str
    supply_chain_fingerprint: str
    runtime_authorization_fingerprint: str
    request_plan_fingerprint: str
    authorization_window_seconds: int
    vm_image_sha256: str
    opend_version: str
    opend_server_version: int
    opend_server_build_no: int
    rootless: bool
    credentials_location: str
    host_opend_port_mapped: bool
    generic_raw_send_enabled: bool
    logging_enabled: bool
    reminder_push_enabled: bool
    automatic_quote_right_takeover_enabled: bool
    trade_and_account_protocols_rejected_before_opend: bool
    allowed_protocol_ids: tuple[int, ...]
    checkpoints: tuple[FrozenMap, ...]
    quarantined: bool
    started_at: str
    ended_at: str
    issued_at: str
    expires_at: str
    signature_algorithm: str
    signer_key_id: str
    signature_hex: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_signed_receipt(self, "futu-runtime:")
        started = _utc_datetime(self.started_at, "started_at")
        ended = _utc_datetime(self.ended_at, "ended_at")
        issued = _utc_datetime(self.issued_at, "issued_at")
        expires = _utc_datetime(self.expires_at, "expires_at")
        if not (started <= ended <= issued < expires):
            raise FutuReceiptError("runtime receipt chronology is invalid")
        if self.authorization_window_seconds != FUTU_RUNTIME_AUTHORIZATION_MAX_SECONDS:
            raise FutuReceiptError("runtime receipt authorization window is invalid")
        if (
            self.allowed_protocol_ids != FUTU_RUNTIME_PROTOCOL_IDS
            or type(self.opend_server_version) is not int
            or self.opend_server_version <= 0
            or type(self.opend_server_build_no) is not int
            or self.opend_server_build_no <= 0
            or self.opend_server_version
            != _encoded_opend_server_version(self.opend_version)
        ):
            raise FutuReceiptError("runtime receipt protocol or OpenD identity is invalid")
        checkpoints = tuple(item["checkpoint"] for item in self.checkpoints)
        if checkpoints[0] != "startup" or checkpoints[-1] != "pre_shutdown":
            raise FutuReceiptError("runtime checkpoints must begin at startup and end at shutdown")
        if len({item["serial_number"] for item in self.checkpoints}) != len(self.checkpoints):
            raise FutuReceiptError("runtime checkpoint serial numbers must be unique")
        checkpoint_times = tuple(
            _utc_datetime(item["observed_at"], "checkpoint observed_at")
            for item in self.checkpoints
        )
        if checkpoint_times != tuple(sorted(checkpoint_times)) or any(
            observed < started or observed > ended for observed in checkpoint_times
        ):
            raise FutuReceiptError("runtime checkpoint chronology is invalid")
        for fingerprint_field in (
            "global_state_request_fingerprint",
            "global_state_response_fingerprint",
        ):
            if len({item[fingerprint_field] for item in self.checkpoints}) != len(
                self.checkpoints
            ):
                raise FutuReceiptError("runtime GlobalState fingerprints must be unique")
        if any(
            item["opend_server_version"] != self.opend_server_version
            or item["opend_server_build_no"] != self.opend_server_build_no
            for item in self.checkpoints
        ):
            raise FutuReceiptError(
                "runtime GlobalState checkpoints drifted from the pinned OpenD identity"
            )


@dataclass(frozen=True, slots=True)
class FutuSecurityIdentityReceipt(FutuContract):
    SCHEMA_NAME: ClassVar[str] = "futu-security-identity-receipt"
    schema_version: str
    receipt_id: str
    policy_sha256: str
    component_lock_sha256: str
    issuer_id: str
    cik: str
    security_id: str
    ticker: str
    mic: str
    currency: str
    share_class: str
    vendor_market: str
    vendor_code: str
    vendor_security_id: str
    vendor_security_type: str
    vendor_exchange_type: str
    effective_from: str
    effective_to: str | None
    official_evidence_fingerprint: str
    static_response_fingerprint: str
    reviewer_id: str
    issued_at: str
    signature_algorithm: str
    signer_key_id: str
    signature_hex: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_signed_receipt(self, "futu-security:")
        if self.vendor_code != f"US.{self.ticker}":
            raise FutuReceiptError("vendor_code must bind the reviewed US ticker")
        if self.effective_to is not None and self.effective_to < self.effective_from:
            raise FutuReceiptError("security identity effective period is invalid")
        _utc_datetime(self.issued_at, "issued_at")


FutuSignedReceipt = (
    FutuLegalRightsReceipt
    | FutuAccountEntitlementReceipt
    | FutuSupplyChainReceipt
    | FutuRuntimeIsolationAuthorization
    | FutuRuntimeIsolationReceipt
    | FutuSecurityIdentityReceipt
)

_SIGNED_RECEIPT_TYPES: dict[str, type[FutuSignedReceipt]] = {
    "futu-account-entitlement-receipt": FutuAccountEntitlementReceipt,
    "futu-legal-rights-receipt": FutuLegalRightsReceipt,
    "futu-runtime-isolation-authorization": FutuRuntimeIsolationAuthorization,
    "futu-runtime-isolation-receipt": FutuRuntimeIsolationReceipt,
    "futu-security-identity-receipt": FutuSecurityIdentityReceipt,
    "futu-supply-chain-receipt": FutuSupplyChainReceipt,
}


def load_futu_signed_receipt(
    schema_name: str,
    payload: Mapping[str, Any],
) -> FutuSignedReceipt:
    """Strictly reconstruct one signed receipt from a canonical-JSON object.

    Byte limits, no-follow file access, duplicate-key rejection, and canonical-JSON
    enforcement belong to the caller that acquired the bytes.  This boundary closes the
    schema/type conversion and returns only an exact immutable receipt.
    """
    receipt_type = _SIGNED_RECEIPT_TYPES.get(schema_name)
    if receipt_type is None:
        raise FutuReceiptError(f"unsupported signed Futu receipt type: {schema_name}")
    materialized = to_json_value(payload)
    if not isinstance(materialized, dict):
        raise FutuReceiptError("signed Futu receipt payload must be an object")
    validate_futu_payload(schema_name, materialized)
    try:
        return receipt_type(**materialized)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, FutuReceiptError):
            raise
        raise FutuReceiptError("signed Futu receipt reconstruction failed") from exc


@dataclass(frozen=True, slots=True)
class FutuAuthoritySet:
    legal: FutuLegalRightsReceipt | None = None
    account: FutuAccountEntitlementReceipt | None = None
    supply_chain: FutuSupplyChainReceipt | None = None
    runtime_authorization: FutuRuntimeIsolationAuthorization | None = None
    runtime: FutuRuntimeIsolationReceipt | None = None
    security_identity: FutuSecurityIdentityReceipt | None = None


def load_futu_authority_set(payload: Mapping[str, Any]) -> FutuAuthoritySet:
    """Reload the six closed authority slots without accepting untyped dictionaries."""
    materialized = to_json_value(payload)
    expected = {
        "legal",
        "account",
        "supply_chain",
        "runtime_authorization",
        "runtime",
        "security_identity",
    }
    if not isinstance(materialized, dict) or set(materialized) != expected:
        raise FutuReceiptError("Futu authority-set member set is not closed")
    schema_by_slot = {
        "legal": "futu-legal-rights-receipt",
        "account": "futu-account-entitlement-receipt",
        "supply_chain": "futu-supply-chain-receipt",
        "runtime_authorization": "futu-runtime-isolation-authorization",
        "runtime": "futu-runtime-isolation-receipt",
        "security_identity": "futu-security-identity-receipt",
    }
    loaded: dict[str, FutuSignedReceipt | None] = {}
    for slot, schema_name in schema_by_slot.items():
        value = materialized[slot]
        loaded[slot] = (
            None if value is None else load_futu_signed_receipt(schema_name, value)
        )
    return FutuAuthoritySet(**loaded)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class FutuAuthorityDecision:
    schema_version: str
    run_id: str
    evaluation_scope: str
    evaluated_at: str
    status: str
    policy_sha256: str
    component_lock_sha256: str
    issue_codes: tuple[str, ...]
    receipt_fingerprints: FrozenMap
    allowed_data_families: tuple[str, ...]
    allowed_protocol_ids: tuple[int, ...]
    security_identity_fingerprint: str | None
    daily_close_semantics_evidence_fingerprint: str | None

    def __post_init__(self) -> None:
        if self.schema_version != FUTU_SCHEMA_VERSION:
            raise FutuReceiptError("authority decision schema version is invalid")
        if self.evaluation_scope not in {"live_preflight", "replay_only"}:
            raise FutuReceiptError("authority decision evaluation scope is invalid")
        _utc_datetime(self.evaluated_at, "evaluated_at")
        if self.status not in {"eligible", "blocked", "quarantined"}:
            raise FutuReceiptError("authority decision status is invalid")
        issue_codes = tuple(sorted(set(self.issue_codes)))
        allowed_families = tuple(sorted(set(self.allowed_data_families)))
        allowed_protocols = tuple(sorted(set(self.allowed_protocol_ids)))
        object.__setattr__(self, "issue_codes", issue_codes)
        object.__setattr__(self, "allowed_data_families", allowed_families)
        object.__setattr__(self, "allowed_protocol_ids", allowed_protocols)
        object.__setattr__(self, "receipt_fingerprints", freeze(self.receipt_fingerprints))
        if self.status == "eligible" and issue_codes:
            raise FutuReceiptError("eligible authority decision cannot contain issues")
        if self.status != "eligible" and not issue_codes:
            raise FutuReceiptError("non-eligible authority decision must contain typed issues")

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "evaluation_scope": self.evaluation_scope,
            "evaluated_at": self.evaluated_at,
            "status": self.status,
            "policy_sha256": self.policy_sha256,
            "component_lock_sha256": self.component_lock_sha256,
            "issue_codes": list(self.issue_codes),
            "receipt_fingerprints": to_json_value(self.receipt_fingerprints),
            "allowed_data_families": list(self.allowed_data_families),
            "allowed_protocol_ids": list(self.allowed_protocol_ids),
            "security_identity_fingerprint": self.security_identity_fingerprint,
            "daily_close_semantics_evidence_fingerprint": (
                self.daily_close_semantics_evidence_fingerprint
            ),
        }


@dataclass(frozen=True, slots=True)
class FutuFrozenConclusionReceipt:
    """Exact proprietary conclusion frozen before any analyst-context request."""

    schema_version: str
    run_id: str
    issuer_id: str
    security_id: str
    composite_valuation: CompositeValuationResult
    owner_scorecard: OwnerScorecard
    conclusion_frozen_at: str
    receipt_id: str
    receipt_fingerprint: str

    @retained_authority_replay_scope
    def __post_init__(self) -> None:
        if (
            type(self.composite_valuation) is not CompositeValuationResult
            or type(self.owner_scorecard) is not OwnerScorecard
        ):
            raise FutuReceiptError("frozen conclusion requires exact typed results")
        try:
            self.composite_valuation.__post_init__()
            self.owner_scorecard.__post_init__()
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise FutuReceiptError(
                "frozen conclusion retained authority no longer replays"
            ) from exc
        if (
            self.schema_version != FUTU_SCHEMA_VERSION
            or self.composite_valuation.issuer_id != self.issuer_id
            or self.owner_scorecard.issuer_id != self.issuer_id
            or self.owner_scorecard.composite_valuation_fingerprint
            != self.composite_valuation.fingerprint
            or self.owner_scorecard._composite_authority != self.composite_valuation
        ):
            raise FutuReceiptError("frozen conclusion does not retain exact aligned results")
        _utc_datetime(self.conclusion_frozen_at, "conclusion_frozen_at")
        expected_id, expected_fingerprint = content_identity(
            "futu-conclusion-freeze:",
            self._manifest_values(),
            object_id_field="receipt_id",
            fingerprint_field="receipt_fingerprint",
        )
        if self.receipt_id != expected_id or self.receipt_fingerprint != expected_fingerprint:
            raise FutuReceiptError("frozen conclusion identity is invalid")
        validate_futu_payload("futu-frozen-conclusion-receipt", self.to_dict())

    def _manifest_values(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "issuer_id": self.issuer_id,
            "security_id": self.security_id,
            "composite_valuation": {
                "object_id": self.composite_valuation.result_id,
                "fingerprint": self.composite_valuation.fingerprint,
            },
            "owner_scorecard": {
                "object_id": self.owner_scorecard.scorecard_id,
                "fingerprint": self.owner_scorecard.fingerprint,
            },
            "conclusion_frozen_at": self.conclusion_frozen_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._manifest_values(),
            "receipt_id": self.receipt_id,
            "receipt_fingerprint": self.receipt_fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        return self.receipt_fingerprint


def build_futu_frozen_conclusion_receipt(
    *,
    run_id: str,
    security_id: str,
    composite_valuation: CompositeValuationResult,
    owner_scorecard: OwnerScorecard,
    conclusion_frozen_at: str,
) -> FutuFrozenConclusionReceipt:
    """Build only from the exact schema-validated composite and scorecard objects."""
    if type(composite_valuation) is not CompositeValuationResult or type(
        owner_scorecard
    ) is not OwnerScorecard:
        raise FutuReceiptError("conclusion freeze requires exact typed results")
    values = {
        "schema_version": FUTU_SCHEMA_VERSION,
        "run_id": run_id,
        "issuer_id": composite_valuation.issuer_id,
        "security_id": security_id,
        "composite_valuation": {
            "object_id": composite_valuation.result_id,
            "fingerprint": composite_valuation.fingerprint,
        },
        "owner_scorecard": {
            "object_id": owner_scorecard.scorecard_id,
            "fingerprint": owner_scorecard.fingerprint,
        },
        "conclusion_frozen_at": conclusion_frozen_at,
    }
    receipt_id, receipt_fingerprint = content_identity(
        "futu-conclusion-freeze:",
        values,
        object_id_field="receipt_id",
        fingerprint_field="receipt_fingerprint",
    )
    return FutuFrozenConclusionReceipt(
        schema_version=FUTU_SCHEMA_VERSION,
        run_id=run_id,
        issuer_id=composite_valuation.issuer_id,
        security_id=security_id,
        composite_valuation=composite_valuation,
        owner_scorecard=owner_scorecard,
        conclusion_frozen_at=conclusion_frozen_at,
        receipt_id=receipt_id,
        receipt_fingerprint=receipt_fingerprint,
    )


def _signature_valid(receipt: FutuContract, verifier: SignatureVerifier | None) -> bool:
    if verifier is None:
        return False
    try:
        payload = receipt.to_dict()
        return bool(
            verifier.verify(
                signer_key_id=payload["signer_key_id"],
                payload=signed_receipt_payload(receipt),
                signature_hex=payload["signature_hex"],
            )
        )
    except Exception:
        return False


def _receipt_is_current(receipt: FutuContract, now: datetime) -> bool:
    expires_at = getattr(receipt, "expires_at", None)
    if expires_at is not None and _utc_datetime(expires_at, "expires_at") <= now:
        return False
    issued_at = getattr(receipt, "issued_at", None)
    return issued_at is None or _utc_datetime(issued_at, "issued_at") <= now


def evaluate_futu_authority(
    authority: FutuAuthoritySet,
    *,
    verifier: SignatureVerifier | None,
    now: datetime,
    run_id: str,
    policy_sha256: str,
    component_lock_sha256: str,
    required_data_families: Sequence[str],
    required_protocol_ids: Sequence[int],
    required_right: str = "valuation",
    purpose: str = "live_preflight",
) -> FutuAuthorityDecision:
    """Evaluate either pre-run live authority or a completed-session replay authority.

    A completed :class:`FutuRuntimeIsolationReceipt` is post-run evidence.  It is
    intentionally incapable of authorizing a transport call; callers must present a
    distinct :class:`FutuRuntimeIsolationAuthorization` for ``live_preflight``.
    """
    if now.tzinfo is None:
        raise FutuReceiptError("now must be timezone-aware")
    if purpose not in {"live_preflight", "replay_only"}:
        raise FutuReceiptError("authority purpose must be live_preflight or replay_only")
    now_utc = now.astimezone(UTC)
    required_protocol_set = {1002, *required_protocol_ids}
    issues: set[str] = set()
    fingerprints: dict[str, str] = {}
    runtime_authority: FutuRuntimeIsolationAuthorization | FutuRuntimeIsolationReceipt | None = (
        authority.runtime_authorization
        if purpose == "live_preflight"
        else authority.runtime
    )
    runtime_name = "runtime_authorization" if purpose == "live_preflight" else "runtime"
    named_receipts: tuple[tuple[str, FutuContract | None, str], ...] = (
        ("legal", authority.legal, "legal_right_missing"),
        ("account", authority.account, "account_entitlement_missing"),
        ("supply_chain", authority.supply_chain, "supply_chain_missing"),
        (runtime_name, runtime_authority, "runtime_isolation_missing"),
        ("security_identity", authority.security_identity, "security_identity_missing"),
    )
    for name, receipt, missing_code in named_receipts:
        if receipt is None:
            issues.add(missing_code)
            continue
        fingerprints[name] = receipt.fingerprint
        if not _signature_valid(receipt, verifier):
            issues.add("authority_signature_invalid")
        if not _receipt_is_current(receipt, now_utc):
            issues.add("authority_expired")
        receipt_payload = receipt.to_dict()
        if receipt_payload["policy_sha256"] != policy_sha256:
            issues.add("policy_mismatch")
        if receipt_payload["component_lock_sha256"] != component_lock_sha256:
            issues.add("component_lock_mismatch")

    legal = authority.legal
    account = authority.account
    supply = authority.supply_chain
    runtime = runtime_authority
    security = authority.security_identity

    if legal is not None:
        if _utc_datetime(legal.effective_at, "effective_at") > now_utc:
            issues.add("legal_right_missing")
        if (
            legal.revoked_at is not None
            and _utc_datetime(legal.revoked_at, "revoked_at") <= now_utc
        ):
            issues.add("legal_right_missing")
        if required_right not in legal.rights or not legal.rights[required_right]:
            issues.add("legal_right_missing")
        if not legal.rights["raw_retention"] or not legal.rights["audit_replay"]:
            issues.add("legal_right_missing")
        if not set(required_data_families).issubset(legal.allowed_data_families):
            issues.add("data_family_not_entitled")
        if not required_protocol_set.issubset(legal.allowed_protocol_ids):
            issues.add("protocol_not_allowed")

    if account is not None:
        if account.run_id != run_id:
            issues.add("account_scope_mismatch")
        if not account.qot_logined:
            issues.add("qot_login_false")
        if account.trd_logined:
            issues.add("trade_login_true")
        observed_at = _utc_datetime(account.observed_at, "account observed_at")
        if (
            purpose == "live_preflight"
            and (observed_at > now_utc or now_utc - observed_at > timedelta(minutes=5))
        ):
            issues.add("global_state_binding_invalid")
        for family in required_data_families:
            if account.entitlements.get(family) != "granted":
                issues.add("data_family_not_entitled")
        if "market_price" in required_data_families and (
            account.delay_class != "real_time"
            or account.promotion_status == "unknown"
        ):
            issues.add("api_quote_permission_unknown")
        # The account projection is not the history-quota authority. Protocol 3104
        # is always executed first and is the sole authority for the exact
        # target-plus-peer seven-day incremental budget. In particular, an account
        # scalar of zero is valid when every planned subject is already counted.

    if security is not None:
        if legal is not None and (
            security.mic not in legal.allowed_mics
            or security.currency not in legal.allowed_currencies
        ):
            issues.add("security_scope_invalid")
        if security.share_class != "common" or security.mic not in {"XNAS", "XNYS"}:
            issues.add("security_scope_invalid")
        today = now_utc.date().isoformat()
        if security.effective_from > today or (
            security.effective_to is not None and security.effective_to < today
        ):
            issues.add("security_scope_invalid")

    if runtime is not None:
        if runtime.run_id != run_id:
            issues.add("account_scope_mismatch")
        if legal is not None and runtime.account_scope_sha256 != legal.account_scope_sha256:
            issues.add("account_scope_mismatch")
        unsafe_isolation = (
            not runtime.rootless
            or runtime.credentials_location != "isolated_vm_tmpfs"
            or runtime.host_opend_port_mapped
            or runtime.generic_raw_send_enabled
            or runtime.logging_enabled
            or runtime.reminder_push_enabled
            or runtime.automatic_quote_right_takeover_enabled
            or not runtime.trade_and_account_protocols_rejected_before_opend
        )
        if unsafe_isolation:
            issues.add("runtime_isolation_missing")
        if not required_protocol_set.issubset(runtime.allowed_protocol_ids):
            issues.add("protocol_not_allowed")
        if (
            isinstance(runtime, FutuRuntimeIsolationAuthorization)
            and security is not None
            and security.vendor_code not in runtime.authorized_security_codes
        ):
            issues.add("security_scope_invalid")
        if isinstance(runtime, FutuRuntimeIsolationReceipt):
            if any(not item["qot_logined"] for item in runtime.checkpoints):
                issues.add("qot_login_false")
            if any(item["trd_logined"] for item in runtime.checkpoints):
                issues.add("trade_login_true")
            if runtime.quarantined:
                issues.add("trade_login_true")

    if legal is not None and account is not None:
        if account.account_scope_sha256 != legal.account_scope_sha256:
            issues.add("account_scope_mismatch")
        if isinstance(runtime, FutuRuntimeIsolationReceipt):
            startup = runtime.checkpoints[0]
            if (
                startup["checkpoint"] != "startup"
                or account.global_state_response_fingerprint
                != startup["global_state_response_fingerprint"]
            ):
                issues.add("global_state_binding_invalid")

    if supply is not None and runtime is not None:
        if runtime.supply_chain_fingerprint != supply.fingerprint:
            issues.add("supply_chain_mismatch")
        if runtime.vm_image_sha256 != supply.vm_image_sha256:
            issues.add("supply_chain_mismatch")
        if runtime.opend_version != supply.opend_version:
            issues.add("supply_chain_mismatch")

    if account is not None and supply is not None:
        if account.protocol_version != supply.futu_api_version:
            issues.add("account_protocol_version_mismatch")

    status = "blocked"
    if "trade_login_true" in issues:
        status = "quarantined"
    elif not issues:
        status = "eligible"

    allowed_families = (
        tuple(
            family
            for family in legal.allowed_data_families
            if account is not None and account.entitlements.get(family) == "granted"
        )
        if legal is not None
        else ()
    )
    allowed_protocols = (
        tuple(
            protocol_id
            for protocol_id in legal.allowed_protocol_ids
            if runtime is not None and protocol_id in runtime.allowed_protocol_ids
        )
        if legal is not None
        else ()
    )
    return FutuAuthorityDecision(
        schema_version=FUTU_SCHEMA_VERSION,
        run_id=run_id,
        evaluation_scope=purpose,
        evaluated_at=now_utc.isoformat().replace("+00:00", "Z"),
        status=status,
        policy_sha256=policy_sha256,
        component_lock_sha256=component_lock_sha256,
        issue_codes=tuple(issues),
        receipt_fingerprints=FrozenMap(fingerprints),
        allowed_data_families=allowed_families,
        allowed_protocol_ids=allowed_protocols,
        security_identity_fingerprint=security.fingerprint if security is not None else None,
        daily_close_semantics_evidence_fingerprint=(
            supply.daily_close_semantics_evidence_sha256
            if supply is not None
            and supply.daily_close_semantics_evidence_kind
            in {"pinned_opend_proto_canary", "written_authority"}
            else None
        ),
    )


def _validate_content_identity(
    contract: FutuContract,
    *,
    prefix: str,
    object_id_field: str,
    fingerprint_field: str,
) -> None:
    payload = contract.to_dict()
    digest = _identity_digest(payload, object_id_field, fingerprint_field)
    if payload[object_id_field] != f"{prefix}{digest}" or payload[fingerprint_field] != digest:
        raise FutuReceiptError(
            f"{object_id_field} and {fingerprint_field} must bind the complete object"
        )


@dataclass(frozen=True, slots=True)
class FutuDataRequestReceipt(FutuContract):
    SCHEMA_NAME: ClassVar[str] = "futu-data-request-receipt"
    schema_version: str
    request_id: str
    run_id: str
    stage: str
    issuer_id: str
    security_id: str
    security_identity_fingerprint: str
    data_family: str
    protocol_id: int
    protocol_name: str
    parameters: FrozenMap
    page_index: int
    previous_page_key_sha256: str | None
    data_cutoff_date: str
    expected_trading_date: str | None
    price_blind_freeze_fingerprint: str | None
    frozen_conclusion_receipt_id: str | None
    frozen_conclusion_fingerprint: str | None
    authority_decision_fingerprint: str
    request_started_at: str
    request_fingerprint: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_content_identity(
            self,
            prefix="futu-request:",
            object_id_field="request_id",
            fingerprint_field="request_fingerprint",
        )
        if (self.page_index == 0) != (self.previous_page_key_sha256 is None):
            raise FutuReceiptError("request page index and previous page-key hash are inconsistent")
        if self.stage == "market_reference":
            if (
                self.expected_trading_date is None
                or self.price_blind_freeze_fingerprint is not None
            ):
                raise FutuReceiptError("market-reference request identity is invalid")
        elif self.stage == "peer_comparable_reference":
            if self.price_blind_freeze_fingerprint is None or (
                (self.protocol_id == 3103) != (self.expected_trading_date is not None)
            ):
                raise FutuReceiptError("peer-comparable request identity is invalid")
        elif self.expected_trading_date is not None:
            raise FutuReceiptError("only market-reference requests may bind a trading date")
        if (self.stage in {"post_valuation_context", "peer_comparable_reference"}) != (
            self.price_blind_freeze_fingerprint is not None
        ):
            raise FutuReceiptError(
                "post-valuation request must bind exactly one price-blind freeze"
            )
        conclusion_bound = (
            self.frozen_conclusion_receipt_id is not None
            and self.frozen_conclusion_fingerprint is not None
        )
        if (self.frozen_conclusion_receipt_id is None) != (
            self.frozen_conclusion_fingerprint is None
        ) or conclusion_bound != (self.stage == "post_valuation_context"):
            raise FutuReceiptError(
                "only post-valuation requests may bind one exact frozen conclusion"
            )

    @property
    def fingerprint(self) -> str:
        return self.request_fingerprint


@dataclass(frozen=True, slots=True)
class FutuDataResponseReceipt(FutuContract):
    SCHEMA_NAME: ClassVar[str] = "futu-data-response-receipt"
    schema_version: str
    response_id: str
    request_id: str
    request_fingerprint: str
    run_id: str
    serial_number: int
    retrieved_at: str
    ret_type: int
    err_code: int
    status: str
    qot_logined: bool
    trd_logined: bool
    pre_global_state_serial_number: int
    pre_global_state_request_fingerprint: str
    pre_global_state_response_fingerprint: str
    post_global_state_serial_number: int
    post_global_state_request_fingerprint: str
    post_global_state_response_fingerprint: str
    raw_evidence_kind: str
    raw_plaintext_sha256: str
    encrypted_object_sha256: str
    cas_locator: str
    envelope_key_id: str
    raw_byte_count: int
    page_index: int
    next_key_sha256: str | None
    terminal: bool
    parser_sha256: str
    response_fingerprint: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_content_identity(
            self,
            prefix="futu-response:",
            object_id_field="response_id",
            fingerprint_field="response_fingerprint",
        )
        if self.status == "completed" and (self.ret_type != 0 or self.err_code != 0):
            raise FutuReceiptError("completed response must have zero return and error codes")
        if self.trd_logined and self.status != "quarantined":
            raise FutuReceiptError("trade-login response must be quarantined")
        if not self.qot_logined and self.status == "completed":
            raise FutuReceiptError("completed response must prove quote login")
        if self.status == "completed" and self.raw_byte_count <= 0:
            raise FutuReceiptError("completed response must bind a non-empty raw object")
        if self.raw_evidence_kind != "opend_protobuf_s2c_frame":
            raise FutuReceiptError(
                "response raw evidence must commit the captured OpenD protobuf S2C frame"
            )
        if self.terminal != (self.next_key_sha256 is None):
            raise FutuReceiptError(
                "response terminal state and next page-key hash are inconsistent"
            )
        if not (
            self.pre_global_state_serial_number
            < self.serial_number
            < self.post_global_state_serial_number
        ):
            raise FutuReceiptError("bound GlobalState operations must bracket the data response")
        expected_locator = f"cas://sha256/{self.encrypted_object_sha256}"
        if self.cas_locator != expected_locator:
            raise FutuReceiptError("CAS locator must bind the encrypted object digest")

    @property
    def fingerprint(self) -> str:
        return self.response_fingerprint


@dataclass(frozen=True, slots=True)
class FutuObservation(FutuContract):
    SCHEMA_NAME: ClassVar[str] = "futu-observation"
    schema_version: str
    observation_id: str
    issuer_id: str
    security_id: str
    data_family: str
    field_id: str
    canonical_concept: str | None
    period: FrozenMap
    qualifiers: FrozenMap
    value_type: str
    value: str | bool | None
    unit: str | None
    currency: str | None
    binary64_hex: str | None
    exact_binary64_decimal: str | None
    response_fingerprint: str
    retrieved_at: str
    point_in_time_status: str
    source_role: str
    use_scope: str
    comparison_eligible: bool
    observation_fingerprint: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_content_identity(
            self,
            prefix="futu-observation:",
            object_id_field="observation_id",
            fingerprint_field="observation_fingerprint",
        )
        if self.value_type == "number":
            if not isinstance(self.value, str):
                raise FutuReceiptError("numeric observation value must be a decimal string")
            _canonical_decimal(self.value, "value")
        elif self.value_type == "text" and not isinstance(self.value, str):
            raise FutuReceiptError("text observation value must be a string")
        elif self.value_type == "boolean" and not isinstance(self.value, bool):
            raise FutuReceiptError("boolean observation value must be boolean")
        elif self.value_type == "null" and self.value is not None:
            raise FutuReceiptError("null observation value must be null")
        binary_pair = (self.binary64_hex, self.exact_binary64_decimal)
        if (binary_pair[0] is None) != (binary_pair[1] is None):
            raise FutuReceiptError("binary64 evidence fields must be present together")
        if self.binary64_hex is not None:
            if self.value_type != "number":
                raise FutuReceiptError("binary64 evidence is valid only for numeric observations")
            binary_value = struct.unpack(">d", bytes.fromhex(self.binary64_hex))[0]
            if not math.isfinite(binary_value):
                raise FutuReceiptError("binary64 observation must be finite")
            exact = str(Decimal.from_float(binary_value))
            if self.exact_binary64_decimal != exact:
                raise FutuReceiptError("exact_binary64_decimal does not bind binary64_hex")
            assert isinstance(self.value, str)
            if struct.pack(">d", float(Decimal(self.value))).hex() != self.binary64_hex:
                raise FutuReceiptError("numeric value does not round-trip to binary64_hex")
        if self.canonical_concept is None and self.comparison_eligible:
            raise FutuReceiptError("unmapped vendor field cannot be comparison eligible")
        if self.field_id == "availability" and (
            self.canonical_concept is not None
            or self.value_type != "null"
            or self.value is not None
            or self.unit is not None
            or self.currency is not None
            or self.binary64_hex is not None
            or self.exact_binary64_decimal is not None
            or self.comparison_eligible
            or to_json_value(self.qualifiers)
            != {
                "availability_status": "unavailable",
                "reason_code": "official_no_data",
            }
        ):
            raise FutuReceiptError("optional protocol availability marker is invalid")
        if self.data_family in {"financial_statements", "revenue_breakdown"}:
            if self.source_role != "vendor_secondary":
                raise FutuReceiptError("Futu financial observations are vendor-secondary only")
            if self.point_in_time_status != "current_snapshot":
                raise FutuReceiptError(
                    "Futu financial observations cannot assert historical point-in-time status"
                )
        elif self.data_family == "market_price":
            if (
                self.source_role != "governed_broker_vendor"
                or self.point_in_time_status != "point_in_time"
                or self.use_scope
                not in {"market_reference", "peer_comparable_reference"}
            ):
                raise FutuReceiptError("Futu market-price observation authority is invalid")
        elif (
            self.source_role != "vendor_secondary"
            or self.point_in_time_status != "current_snapshot"
        ):
            raise FutuReceiptError(
                "non-price Futu observations are current-snapshot vendor-secondary data"
            )

    @property
    def fingerprint(self) -> str:
        return self.observation_fingerprint


@dataclass(frozen=True, slots=True)
class FutuObservationDispositionReceipt(FutuContract):
    """Closed, replayable reason why one pre-price vendor observation was not cross-checked."""

    SCHEMA_NAME: ClassVar[str] = "futu-observation-disposition-receipt"
    schema_version: str
    receipt_id: str
    run_id: str
    issuer_id: str
    security_id: str
    execution_bundle_id: str
    execution_bundle_fingerprint: str
    vendor_observation_id: str
    vendor_observation_fingerprint: str
    protocol_id: int
    data_family: str
    field_id: str
    status: str
    reason_code: str
    created_at: str
    receipt_fingerprint: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_content_identity(
            self,
            prefix="futu-observation-disposition:",
            object_id_field="receipt_id",
            fingerprint_field="receipt_fingerprint",
        )
        if (self.status == "unavailable") != (self.reason_code == "official_no_data"):
            raise FutuReceiptError(
                "unavailable observation disposition must use official_no_data"
            )
        if (self.status == "verified_context_only") != (
            self.reason_code == "official_event_set_consistent"
        ):
            raise FutuReceiptError(
                "verified context disposition must bind an official event-set check"
            )

    @property
    def fingerprint(self) -> str:
        return self.receipt_fingerprint


@dataclass(frozen=True, slots=True)
class FutuCrossCheckReceipt(FutuContract):
    SCHEMA_NAME: ClassVar[str] = "futu-cross-check-receipt"
    schema_version: str
    receipt_id: str
    issuer_id: str
    contract_graph_fingerprint: str
    official_operand_fingerprint: str
    official_object_type: str
    official_object_id: str
    official_object_fingerprint: str
    official_authority: str
    vendor_observation_id: str
    vendor_observation_fingerprint: str
    canonical_concept: str
    comparison_rule: str
    result: str
    materiality: str
    status: str
    resolution: str | None
    reviewer_id: str | None
    vendor_may_overwrite: bool
    created_at: str
    receipt_fingerprint: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_content_identity(
            self,
            prefix="futu-crosscheck:",
            object_id_field="receipt_id",
            fingerprint_field="receipt_fingerprint",
        )
        if self.vendor_may_overwrite:
            raise FutuReceiptError("vendor observations can never overwrite SEC/IR evidence")
        if self.result == "conflict" and self.status not in {"review_required", "resolved"}:
            raise FutuReceiptError("vendor conflict must require or record human review")
        if (self.resolution is None) != (self.reviewer_id is None):
            raise FutuReceiptError("review resolution and reviewer must be present together")
        if self.status == "resolved" and self.result == "conflict" and self.reviewer_id is None:
            raise FutuReceiptError("resolved conflict must bind a human reviewer")

    @property
    def fingerprint(self) -> str:
        return self.receipt_fingerprint


@dataclass(frozen=True, slots=True)
class FutuEvidenceBundle(FutuContract):
    SCHEMA_NAME: ClassVar[str] = "futu-evidence-bundle"
    schema_version: str
    bundle_id: str
    run_id: str
    issuer_id: str
    security_id: str
    stage: str
    status: str
    authority_decision_fingerprint: str | None
    requests: tuple[FrozenMap, ...]
    responses: tuple[FrozenMap, ...]
    observations: tuple[FrozenMap, ...]
    cross_checks: tuple[FrozenMap, ...]
    issues: tuple[str, ...]
    bundle_fingerprint: str

    def __post_init__(self) -> None:
        FutuContract.__post_init__(self)
        _validate_content_identity(
            self,
            prefix="futu-bundle:",
            object_id_field="bundle_id",
            fingerprint_field="bundle_fingerprint",
        )
        if tuple(sorted(set(self.issues))) != self.issues:
            raise FutuReceiptError("bundle issues must be sorted and unique")
        if self.status == "complete" and self.issues:
            raise FutuReceiptError("complete bundle cannot contain issues")
        if self.status in {"blocked", "quarantined"} and not self.issues:
            raise FutuReceiptError("non-executable bundle must contain a typed issue")
        if self.status == "partial" and not self.issues:
            raise FutuReceiptError("partial bundle must contain a typed issue")
        for collection in (
            self.requests,
            self.responses,
            self.observations,
            self.cross_checks,
        ):
            references = tuple((item["object_id"], item["fingerprint"]) for item in collection)
            if len(set(references)) != len(references):
                raise FutuReceiptError("bundle references must be unique")

    @property
    def fingerprint(self) -> str:
        return self.bundle_fingerprint


def content_identity(
    prefix: str,
    values: Mapping[str, Any],
    *,
    object_id_field: str,
    fingerprint_field: str,
) -> tuple[str, str]:
    """Compute deterministic IDs for request, response, observation, and bundle factories."""
    payload = {key: to_json_value(value) for key, value in values.items()}
    payload.pop(object_id_field, None)
    payload.pop(fingerprint_field, None)
    digest = canonical_sha256(payload)
    if _SHA256.fullmatch(digest) is None:  # pragma: no cover - hashlib invariant
        raise AssertionError("SHA-256 implementation returned an invalid digest")
    return f"{prefix}{digest}", digest
