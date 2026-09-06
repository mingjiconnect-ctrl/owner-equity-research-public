from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

from owner_research_futu_sidecar.attestation import Ed25519Attestor, RuntimeClaims
from owner_research_futu_sidecar.canonical import (
    canonical_bytes,
    canonical_sha256,
    signed_identity,
)
from owner_research_futu_sidecar.frame_guard import (
    DEFAULT_US_QUOTE_PROTOCOL_IDS,
    INFRASTRUCTURE_PROTOCOL_IDS,
)
from owner_research_futu_sidecar.runtime_authorization import RuntimeRequestPlanItem

AUTHORIZED_CODES = (
    "US.AAPL",
    "US.MSFT",
    "US.GOOGL",
    "US.AMZN",
    "US.META",
    "US.NVDA",
)
ALLOWED_PROTOCOL_IDS = tuple(
    sorted(set(INFRASTRUCTURE_PROTOCOL_IDS) | set(DEFAULT_US_QUOTE_PROTOCOL_IDS))
)
AUTHORIZATION_SIGNER_SEED = b"\x71" * 32
AUTHORIZATION_SIGNER_KEY_ID = "test-runtime-authorization-role"


def request_plan(
    *,
    security_code: str = "US.AAPL",
    protocol_id: int = 3243,
    parameters: dict[str, Any] | None = None,
    maximum_pages: int = 1,
    activation_condition: str = "always",
) -> list[dict[str, Any]]:
    values = {} if parameters is None else parameters
    plan = [
        {
            "plan_index": 0,
            "security_code": "US.AAPL",
            "protocol_id": 3104,
            "parameters_sha256": canonical_sha256({"get_detail": True}),
            "pagination_mode": "none",
            "maximum_pages": 1,
            "activation_condition": "always",
        }
    ]
    if protocol_id == 3104:
        return plan
    plan.append(
        {
            "plan_index": 1,
            "security_code": security_code,
            "protocol_id": protocol_id,
            "parameters_sha256": canonical_sha256(values),
            "pagination_mode": (
                "internal" if protocol_id in {3227, 3230, 3236, 3246} else "none"
            ),
            "maximum_pages": maximum_pages,
            "activation_condition": activation_condition,
        }
    )
    return plan


def signed_runtime_authority(
    *,
    run_id: str,
    sidecar_signer_key_id: str,
    supply_fingerprint: str = "a" * 64,
    opend_version: str = "10.10.7008",
    plan: list[dict[str, Any]] | None = None,
    native_macos: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    runtime_plan = request_plan() if plan is None else plan
    now = datetime.now(UTC)
    issued = now.isoformat(timespec="microseconds").replace("+00:00", "Z")
    valid_from = (now + timedelta(microseconds=1)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    expires = (now + timedelta(minutes=10)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    unsigned: dict[str, Any] = {
        "schema_version": "2.0.0" if native_macos else "1.0.0",
        "receipt_id": "",
        "run_id": run_id,
        "policy_sha256": "1" * 64,
        "component_lock_sha256": "2" * 64,
        "account_scope_sha256": "3" * 64,
        "supply_chain_fingerprint": supply_fingerprint,
        "vm_image_sha256": None if native_macos else "4" * 64,
        "opend_version": opend_version,
        "rootless": True,
        "credentials_location": (
            "user_managed_macos_opend" if native_macos else "isolated_vm_tmpfs"
        ),
        "host_opend_port_mapped": False,
        "generic_raw_send_enabled": False,
        "logging_enabled": False,
        "reminder_push_enabled": False,
        "automatic_quote_right_takeover_enabled": False,
        "trade_and_account_protocols_rejected_before_opend": True,
        "allowed_protocol_ids": list(ALLOWED_PROTOCOL_IDS),
        "authorized_security_codes": list(AUTHORIZED_CODES),
        "request_plan": runtime_plan,
        "request_plan_fingerprint": canonical_sha256(runtime_plan),
        "maximum_planned_requests": sum(item["maximum_pages"] for item in runtime_plan),
        "maximum_pages_per_protocol": 64,
        "sidecar_attestor_key_id": sidecar_signer_key_id,
        "authorization_window_seconds": 900,
        "issued_at": issued,
        "valid_from": valid_from,
        "expires_at": expires,
    }
    signer = Ed25519Attestor.from_private_bytes(
        AUTHORIZATION_SIGNER_SEED,
        signer_key_id=AUTHORIZATION_SIGNER_KEY_ID,
    )
    identity_values = {
        **unsigned,
        "signature_algorithm": "ed25519",
        "signer_key_id": AUTHORIZATION_SIGNER_KEY_ID,
    }
    unsigned["receipt_id"] = signed_identity(
        "futu-runtime-authorization:", identity_values
    )
    authorization = signer.sign(unsigned)
    keyring_identity = {
        "keyring_id": "keyring:test-runtime-authorization-role",
        "algorithm": "ed25519",
        "keys": {AUTHORIZATION_SIGNER_KEY_ID: signer.public_key_hex},
    }
    keyring = {
        "schema_version": "1.0.0",
        "artifact_type": "owner-research-public-keyring",
        "keyring_id": keyring_identity["keyring_id"],
        "algorithm": "ed25519",
        "keys": [
            {
                "key_id": AUTHORIZATION_SIGNER_KEY_ID,
                "public_key_hex": signer.public_key_hex,
            }
        ],
        "keyring_fingerprint": canonical_sha256(keyring_identity),
    }
    return authorization, keyring


def runtime_claims(
    *,
    authorization: dict[str, Any],
) -> RuntimeClaims:
    return RuntimeClaims(
        authorized_run_id=authorization["run_id"],
        runtime_authorization_fingerprint=canonical_sha256(authorization),
        authorization_issued_at=authorization["issued_at"],
        valid_from=authorization["valid_from"],
        authorization_window_seconds=authorization["authorization_window_seconds"],
        policy_sha256=authorization["policy_sha256"],
        component_lock_sha256=authorization["component_lock_sha256"],
        account_scope_sha256=authorization["account_scope_sha256"],
        supply_chain_fingerprint=authorization["supply_chain_fingerprint"],
        vm_image_sha256=authorization["vm_image_sha256"],
        opend_version=authorization["opend_version"],
        allowed_protocol_ids=tuple(authorization["allowed_protocol_ids"]),
        authorized_security_codes=tuple(authorization["authorized_security_codes"]),
        request_plan=tuple(
            RuntimeRequestPlanItem.from_value(item)
            for item in authorization["request_plan"]
        ),
        request_plan_fingerprint=authorization["request_plan_fingerprint"],
        maximum_planned_requests=authorization["maximum_planned_requests"],
        maximum_pages_per_protocol=authorization["maximum_pages_per_protocol"],
        sidecar_attestor_key_id=authorization["sidecar_attestor_key_id"],
        expires_at=authorization["expires_at"],
    )


def authority_fds(
    authorization: dict[str, Any], keyring: dict[str, Any]
) -> tuple[int, int]:
    authorization_read, authorization_write = os.pipe()
    keyring_read, keyring_write = os.pipe()
    os.write(authorization_write, canonical_bytes(authorization))
    os.write(keyring_write, canonical_bytes(keyring))
    os.close(authorization_write)
    os.close(keyring_write)
    return authorization_read, keyring_read


def open_expectations(authorization: dict[str, Any]) -> dict[str, Any]:
    return {
        "expected_runtime_authorization_fingerprint": canonical_sha256(authorization),
        "expected_authorized_security_codes": authorization[
            "authorized_security_codes"
        ],
        "expected_request_plan": authorization["request_plan"],
        "expected_request_plan_fingerprint": authorization[
            "request_plan_fingerprint"
        ],
        "expected_maximum_planned_requests": authorization[
            "maximum_planned_requests"
        ],
        "expected_maximum_pages_per_protocol": authorization[
            "maximum_pages_per_protocol"
        ],
    }


def completed_disposition() -> dict[str, Any]:
    return {
        "status": "completed",
        "skipped_plan_indices": [],
        "reason_code": None,
        "conclusion_receipt_id": None,
        "conclusion_fingerprint": None,
    }
