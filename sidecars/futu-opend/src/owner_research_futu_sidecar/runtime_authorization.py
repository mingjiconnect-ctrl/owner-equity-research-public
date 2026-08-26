from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import (
    SidecarContractError,
    canonical_bytes,
    canonical_sha256,
    load_canonical_json,
    require_exact_members,
    require_sha256,
    signed_identity,
)
from .frame_guard import DEFAULT_US_QUOTE_PROTOCOL_IDS, INFRASTRUCTURE_PROTOCOL_IDS

MAXIMUM_AUTHORIZATION_BYTES = 1024 * 1024
MAXIMUM_KEYRING_BYTES = 1024 * 1024
MAXIMUM_PLANNED_REQUESTS = 128
MAXIMUM_PAGES_PER_PROTOCOL = 64
_CODE = re.compile(r"US\.[A-Z0-9][A-Z0-9.-]{0,31}\Z")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_INTERNALLY_PAGED = frozenset({3227, 3230, 3236, 3246})
_CONDITIONAL = frozenset({3229, 3230, 3232})
_PLAN_FIELDS = {
    "plan_index",
    "security_code",
    "protocol_id",
    "parameters_sha256",
    "pagination_mode",
    "maximum_pages",
    "activation_condition",
}
_AUTHORIZATION_FIELDS = {
    "schema_version",
    "receipt_id",
    "run_id",
    "policy_sha256",
    "component_lock_sha256",
    "account_scope_sha256",
    "supply_chain_fingerprint",
    "vm_image_sha256",
    "opend_version",
    "rootless",
    "credentials_location",
    "host_opend_port_mapped",
    "generic_raw_send_enabled",
    "logging_enabled",
    "reminder_push_enabled",
    "automatic_quote_right_takeover_enabled",
    "trade_and_account_protocols_rejected_before_opend",
    "allowed_protocol_ids",
    "authorized_security_codes",
    "request_plan",
    "request_plan_fingerprint",
    "maximum_planned_requests",
    "maximum_pages_per_protocol",
    "sidecar_attestor_key_id",
    "authorization_window_seconds",
    "issued_at",
    "valid_from",
    "expires_at",
    "signature_algorithm",
    "signer_key_id",
    "signature_hex",
}
_KEYRING_FIELDS = {
    "schema_version",
    "artifact_type",
    "keyring_id",
    "algorithm",
    "keys",
    "keyring_fingerprint",
}


class RuntimeAuthorizationError(SidecarContractError):
    """Raised when the preopened authorization authority cannot be replayed."""


@dataclass(frozen=True, slots=True)
class RuntimeRequestPlanItem:
    plan_index: int
    security_code: str
    protocol_id: int
    parameters_sha256: str
    pagination_mode: str
    maximum_pages: int
    activation_condition: str

    @classmethod
    def from_value(cls, value: Any) -> RuntimeRequestPlanItem:
        item = require_exact_members(value, _PLAN_FIELDS, "runtime request-plan item")
        return cls(**item)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_index": self.plan_index,
            "security_code": self.security_code,
            "protocol_id": self.protocol_id,
            "parameters_sha256": self.parameters_sha256,
            "pagination_mode": self.pagination_mode,
            "maximum_pages": self.maximum_pages,
            "activation_condition": self.activation_condition,
        }


@dataclass(frozen=True, slots=True)
class VerifiedRuntimeAuthorization:
    payload: dict[str, Any]
    fingerprint: str
    authorization_signer_key_id: str
    authorization_keyring_fingerprint: str

    @property
    def request_plan(self) -> tuple[RuntimeRequestPlanItem, ...]:
        return tuple(
            RuntimeRequestPlanItem.from_value(item)
            for item in self.payload["request_plan"]
        )

    @property
    def authorized_security_codes(self) -> tuple[str, ...]:
        return tuple(self.payload["authorized_security_codes"])


def verify_runtime_authorization(
    *,
    authorization_raw: bytes,
    keyring_raw: bytes,
    expected_sidecar_attestor_key_id: str,
) -> VerifiedRuntimeAuthorization:
    authorization = require_exact_members(
        load_canonical_json(authorization_raw, label="runtime authorization"),
        _AUTHORIZATION_FIELDS,
        "runtime authorization",
    )
    keyring = require_exact_members(
        load_canonical_json(keyring_raw, label="authorization-role keyring"),
        _KEYRING_FIELDS,
        "authorization-role keyring",
    )
    if (
        keyring["schema_version"] != "1.0.0"
        or keyring["artifact_type"] != "owner-research-public-keyring"
        or keyring["algorithm"] != "ed25519"
        or not isinstance(keyring["keyring_id"], str)
        or not keyring["keyring_id"].startswith("keyring:")
        or not isinstance(keyring["keys"], list)
        or len(keyring["keys"]) != 1
    ):
        raise RuntimeAuthorizationError(
            "authorization role keyring must contain exactly one configured role key"
        )
    key_record = require_exact_members(
        keyring["keys"][0], {"key_id", "public_key_hex"}, "authorization role key"
    )
    key_id = key_record["key_id"]
    public_key_hex = key_record["public_key_hex"]
    if (
        not isinstance(key_id, str)
        or _KEY_ID.fullmatch(key_id) is None
        or not isinstance(public_key_hex, str)
        or len(public_key_hex) != 64
    ):
        raise RuntimeAuthorizationError("authorization role public key is invalid")
    keyring_identity = {
        "keyring_id": keyring["keyring_id"],
        "algorithm": "ed25519",
        "keys": {key_id: public_key_hex},
    }
    if keyring["keyring_fingerprint"] != canonical_sha256(keyring_identity):
        raise RuntimeAuthorizationError("authorization role keyring fingerprint is invalid")
    if (
        authorization["schema_version"] != "1.0.0"
        or authorization["signature_algorithm"] != "ed25519"
        or authorization["signer_key_id"] != key_id
        or authorization["sidecar_attestor_key_id"]
        != expected_sidecar_attestor_key_id
        or authorization["receipt_id"]
        != signed_identity("futu-runtime-authorization:", authorization)
    ):
        raise RuntimeAuthorizationError("runtime authorization signing identity is invalid")
    unsigned = dict(authorization)
    signature_hex = unsigned.pop("signature_hex")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(signature_hex), canonical_bytes(unsigned)
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise RuntimeAuthorizationError("runtime authorization signature is invalid") from exc
    _validate_authorization_values(authorization)
    return VerifiedRuntimeAuthorization(
        payload=dict(authorization),
        fingerprint=canonical_sha256(authorization),
        authorization_signer_key_id=key_id,
        authorization_keyring_fingerprint=keyring["keyring_fingerprint"],
    )


def _validate_authorization_values(value: dict[str, Any]) -> None:
    for key in (
        "policy_sha256",
        "component_lock_sha256",
        "account_scope_sha256",
        "supply_chain_fingerprint",
        "vm_image_sha256",
        "request_plan_fingerprint",
    ):
        require_sha256(value[key], key)
    static_valid = (
        isinstance(value["run_id"], str)
        and bool(value["run_id"])
        and isinstance(value["opend_version"], str)
        and bool(value["opend_version"])
        and value["rootless"] is True
        and value["credentials_location"] == "isolated_vm_tmpfs"
        and value["host_opend_port_mapped"] is False
        and value["generic_raw_send_enabled"] is False
        and value["logging_enabled"] is False
        and value["reminder_push_enabled"] is False
        and value["automatic_quote_right_takeover_enabled"] is False
        and value["trade_and_account_protocols_rejected_before_opend"] is True
        and value["authorization_window_seconds"] == 900
        and value["maximum_pages_per_protocol"] == MAXIMUM_PAGES_PER_PROTOCOL
    )
    allowed = value["allowed_protocol_ids"]
    closed_protocols = sorted(
        set(INFRASTRUCTURE_PROTOCOL_IDS) | set(DEFAULT_US_QUOTE_PROTOCOL_IDS)
    )
    codes = value["authorized_security_codes"]
    plan = value["request_plan"]
    if (
        not static_valid
        or allowed != closed_protocols
        or not isinstance(codes, list)
        or not 6 <= len(codes) <= 16
        or len(set(codes)) != len(codes)
        or any(not isinstance(code, str) or _CODE.fullmatch(code) is None for code in codes)
        or not isinstance(plan, list)
    ):
        raise RuntimeAuthorizationError("runtime authorization scope is invalid")
    validate_request_plan(
        authorized_security_codes=codes,
        request_plan=plan,
        request_plan_fingerprint=value["request_plan_fingerprint"],
        maximum_planned_requests=value["maximum_planned_requests"],
        maximum_pages_per_protocol=value["maximum_pages_per_protocol"],
        allowed_protocol_ids=allowed,
    )
    issued = _parse_time(value["issued_at"], "authorization issued_at")
    valid_from = _parse_time(value["valid_from"], "authorization valid_from")
    expires = _parse_time(value["expires_at"], "authorization expires_at")
    if not (
        issued <= valid_from < expires
        and valid_from - issued <= timedelta(minutes=5)
        and expires - valid_from <= timedelta(minutes=15)
        and expires > datetime.now(UTC)
    ):
        raise RuntimeAuthorizationError("runtime authorization chronology is invalid")


def validate_request_plan(
    *,
    authorized_security_codes: Sequence[Any],
    request_plan: Sequence[Any],
    request_plan_fingerprint: Any,
    maximum_planned_requests: Any,
    maximum_pages_per_protocol: Any,
    allowed_protocol_ids: Sequence[Any],
) -> tuple[RuntimeRequestPlanItem, ...]:
    codes = tuple(authorized_security_codes)
    if (
        not 6 <= len(codes) <= 16
        or len(set(codes)) != len(codes)
        or any(not isinstance(code, str) or _CODE.fullmatch(code) is None for code in codes)
        or not 1 <= len(request_plan) <= MAXIMUM_PLANNED_REQUESTS
        or maximum_pages_per_protocol != MAXIMUM_PAGES_PER_PROTOCOL
    ):
        raise RuntimeAuthorizationError("runtime request-plan scope is invalid")
    allowed = set(allowed_protocol_ids)
    materialized: list[dict[str, Any]] = []
    typed: list[RuntimeRequestPlanItem] = []
    seen_conditional = False
    maximum_requests = 0
    for index, item_value in enumerate(request_plan):
        item = RuntimeRequestPlanItem.from_value(item_value)
        protocol_id = item.protocol_id
        expected_mode = "internal" if protocol_id in _INTERNALLY_PAGED else "none"
        expected_condition = (
            "eligible_conclusion_only" if protocol_id in _CONDITIONAL else "always"
        )
        maximum_pages = item.maximum_pages
        if (
            item.plan_index != index
            or item.security_code not in codes
            or type(protocol_id) is not int
            or protocol_id not in DEFAULT_US_QUOTE_PROTOCOL_IDS
            or protocol_id in INFRASTRUCTURE_PROTOCOL_IDS
            or protocol_id not in allowed
            or require_sha256(item.parameters_sha256, "plan parameters SHA-256")
            != item.parameters_sha256
            or item.pagination_mode != expected_mode
            or type(maximum_pages) is not int
            or not 1 <= maximum_pages <= MAXIMUM_PAGES_PER_PROTOCOL
            or (expected_mode == "none" and maximum_pages != 1)
            or item.activation_condition != expected_condition
            or (seen_conditional and expected_condition == "always")
        ):
            raise RuntimeAuthorizationError("runtime request-plan item is invalid")
        seen_conditional |= expected_condition == "eligible_conclusion_only"
        maximum_requests += maximum_pages
        typed.append(item)
        materialized.append(item.to_dict())
    if (
        typed[0].security_code != codes[0]
        or typed[0].protocol_id != 3104
        or typed[0].parameters_sha256 != canonical_sha256({"get_detail": True})
        or sum(item.protocol_id == 3104 for item in typed) != 1
        or require_sha256(request_plan_fingerprint, "request-plan fingerprint")
        != canonical_sha256(materialized)
        or maximum_planned_requests != maximum_requests
        or maximum_requests > MAXIMUM_PLANNED_REQUESTS
    ):
        raise RuntimeAuthorizationError("runtime request-plan identity is invalid")
    return tuple(typed)


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise RuntimeAuthorizationError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeAuthorizationError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise RuntimeAuthorizationError(f"{label} is invalid")
    return parsed.astimezone(UTC)


__all__ = (
    "MAXIMUM_AUTHORIZATION_BYTES",
    "MAXIMUM_KEYRING_BYTES",
    "RuntimeAuthorizationError",
    "RuntimeRequestPlanItem",
    "VerifiedRuntimeAuthorization",
    "validate_request_plan",
    "verify_runtime_authorization",
)
