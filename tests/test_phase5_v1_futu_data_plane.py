from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import threading
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from owner_research.contracts import Fact, SourceDocument
from owner_research.fingerprints import (
    FrozenMap,
    canonical_json,
    canonical_sha256,
    to_json_value,
)
from owner_research.futu_crosscheck import (
    FutuCrossCheckError,
    bind_crosschecks_to_bundle,
    build_official_evidence_operand,
    contract_graph_fingerprint,
    crosscheck_vendor_observation,
    resolve_crosscheck,
)
from owner_research.futu_receipts import (
    FUTU_RUNTIME_PROTOCOL_IDS,
    FUTU_SCHEMA_VERSION,
    FutuAccountEntitlementReceipt,
    FutuAuthorityDecision,
    FutuAuthoritySet,
    FutuFrozenConclusionReceipt,
    FutuLegalRightsReceipt,
    FutuObservationDispositionReceipt,
    FutuReceiptError,
    FutuRuntimeIsolationAuthorization,
    FutuRuntimeIsolationReceipt,
    FutuSecurityIdentityReceipt,
    FutuSupplyChainReceipt,
    build_futu_frozen_conclusion_receipt,
    build_futu_runtime_request_plan_item,
    content_identity,
    evaluate_futu_authority,
    load_futu_authority_set,
    load_futu_schema,
    load_futu_signed_receipt,
    signed_receipt_identity,
    validate_futu_payload,
)
from owner_research.futu_session import (
    FutuMarketExecutionEvidence,
    FutuMarketExecutionPublicationManifest,
    FutuPeerEvidenceSet,
    FutuPeerSessionEvidence,
    FutuSessionEvidence,
    FutuSessionEvidenceError,
    FutuSessionPublicationManifest,
    build_futu_market_execution_publication_manifest,
    build_futu_observation_dispositions,
    build_futu_peer_evidence_set,
    build_futu_peer_session_evidence,
    build_futu_session_publication_manifest,
    finalize_futu_market_execution_evidence,
    finalize_futu_session_evidence,
    futu_static_identity_projection_fingerprint,
    validate_futu_market_execution_evidence,
    validate_futu_market_execution_publication_manifest,
    validate_futu_session_evidence_replay,
    validate_futu_session_publication_manifest,
)
from owner_research.futu_sidecar import (
    MAXIMUM_RAW_BYTES_PER_RESPONSE,
    WIRE_SCHEMA_VERSION,
    AttestedFutuSidecarSession,
    FutuAttestedSessionFinalization,
    FutuRequestSpec,
    FutuSidecarError,
    FutuSidecarExecution,
    UnixSocketFutuSidecarTransport,
    adapt_futu_daily_close_to_market_reference,
    execute_futu_plan,
    load_financial_field_registry,
    load_futu_attested_session_finalization,
    load_protocol_registry,
    load_sdk_adapter_registry,
    validate_futu_execution_replay,
)
from owner_research.owner_equity_types import compile_futu_optional_data_request_specs
from owner_research.research_bundle_validation import dependency_closure
from owner_research.validation import ContractGraph
from owner_research.valuation_price_blind_freeze import PriceBlindFreezeCompilationResult
from owner_research.valuation_synthesis_types import (
    CompositeValuationResult,
    NamedHumanReviewAuthority,
    OwnerScorecard,
    build_named_human_review_authority,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
HASH_E = "e" * 64
HASH_F = "f" * 64
POLICY_SHA256 = HASH_A
COMPONENT_LOCK_SHA256 = HASH_B
ACCOUNT_SCOPE_SHA256 = HASH_C
RUN_ID = "run:futu-test"
ISSUER_ID = "issuer:0000320193"
SECURITY_ID = "security:AAPL:XNAS:common"
NOW = datetime(2026, 8, 15, 0, 58, tzinfo=UTC)
ISSUED = "2026-08-14T00:00:00Z"
EXPIRES = "2026-08-16T00:00:00Z"
RUNTIME_AUTHORIZATION_EXPIRES = "2026-08-15T01:11:00Z"


def _static_identity_projection_values(
    vendor_code: str,
    *,
    mic: str = "XNAS",
) -> dict[str, Any]:
    ticker = vendor_code.removeprefix("US.")
    vendor_security_id = str(int(canonical_sha256({"vendor_code": vendor_code})[:12], 16))
    return {
        "vendor_security_market": "US",
        "vendor_security_code": vendor_code,
        "security_type": "COMMON_EQUITY",
        "listing_mic": mic,
        "listing_date": "2020-01-01",
        "delisting": False,
        "vendor_security_id": vendor_security_id,
        "lot_size": "100",
        "security_name": f"{ticker} Test Corporation",
        "raw_exchange_type": 5 if mic == "XNAS" else 4,
        "raw_market_code": 11,
        "raw_security_type": 3,
    }


def _wire_static_identity_observations(
    vendor_code: str,
    *,
    mic: str = "XNAS",
    overrides: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if overrides is not None and "listing_mic" in overrides:
        mic = str(overrides["listing_mic"])
    values = _static_identity_projection_values(vendor_code, mic=mic)
    values.update(overrides or {})
    qualifiers = {
        key: values[key]
        for key in ("raw_exchange_type", "raw_market_code", "raw_security_type")
    }
    field_contracts = (
        ("vendor_security_market", "text", None),
        ("vendor_security_code", "text", None),
        ("security_type", "text", None),
        ("listing_mic", "text", None),
        ("listing_date", "text", None),
        ("delisting", "boolean", None),
        ("vendor_security_id", "number", None),
        ("lot_size", "number", "shares"),
        ("security_name", "text", None),
    )
    return [
        {
            "field_id": field_id,
            "period": {"start": None, "end": None},
            "qualifiers": qualifiers,
            "value_type": value_type,
            "value": values[field_id],
            "unit": unit,
            "currency": None,
            "binary64_hex": None,
            "exact_binary64_decimal": None,
        }
        for field_id, value_type, unit in field_contracts
    ]


def _runtime_request_plan(
    *,
    target_vendor_code: str = "US.AAPL",
    peer_count: int = 5,
    trading_date: str = "2026-08-14",
    profile: str = "full",
    optional_pre_price_specs: tuple[FutuRequestSpec, ...] = (),
) -> tuple[tuple[str, ...], tuple[FrozenMap, ...]]:
    peer_codes = tuple(f"US.P{index:02d}" for index in range(1, peer_count + 1))
    authorized_codes = (target_vendor_code, *peer_codes)
    pre_operations: list[tuple[str, int, dict[str, Any], int]] = [
        (target_vendor_code, 3104, {"get_detail": True}, 1),
        (target_vendor_code, 3202, {}, 1),
        *(
            (
                target_vendor_code,
                3227,
                {
                    "statement_type": statement_type,
                    "financial_type": 7,
                    "currency_code": "USD",
                    "num": 10,
                },
                10,
            )
            for statement_type in (1, 2, 3)
        ),
        (
            target_vendor_code,
            3228,
            {"date": 0, "financial_type": 7, "currency_code": "USD"},
            1,
        ),
        (target_vendor_code, 3234, {}, 1),
        (target_vendor_code, 3236, {}, 10),
        (target_vendor_code, 3243, {}, 1),
    ]
    pre_operations.extend(
        (
            target_vendor_code,
            spec.protocol_id,
            to_json_value(spec.parameters),
            50 if spec.protocol_id == 3246 else 1,
        )
        for spec in optional_pre_price_specs
    )
    market_operation = (
        target_vendor_code,
        3103,
        {
            "start": trading_date,
            "end": trading_date,
            "ktype": "K_DAY",
            "autype": "NONE",
            "fields": ["CLOSE", "VOLUME"],
            "max_count": 1,
            "extended_time": False,
            "session": "RTH",
        },
        1,
    )
    if profile == "market":
        operations = [market_operation]
    elif profile == "pre_price":
        operations = [
            *pre_operations,
            market_operation,
            *(
                (
                    code,
                    3103,
                    {
                        "start": trading_date,
                        "end": trading_date,
                        "ktype": "K_DAY",
                        "autype": "NONE",
                        "fields": ["CLOSE", "VOLUME"],
                        "max_count": 1,
                        "extended_time": False,
                        "session": "RTH",
                    },
                    1,
                )
                for code in peer_codes
            ),
        ]
    elif profile == "full":
        operations = [*pre_operations, market_operation]
    else:
        raise ValueError("unknown Futu fixture request-plan profile")
    if profile == "full":
        for code in peer_codes:
            operations.extend(
                (
                    (code, 3202, {}, 1),
                    (
                        code,
                        3103,
                        {
                            "start": trading_date,
                            "end": trading_date,
                            "ktype": "K_DAY",
                            "autype": "NONE",
                            "fields": ["CLOSE", "VOLUME"],
                            "max_count": 1,
                            "extended_time": False,
                            "session": "RTH",
                        },
                        1,
                    ),
                )
            )
        operations.extend(
            (
                (target_vendor_code, 3229, {}, 1),
                (
                    target_vendor_code,
                    3230,
                    {"rating_dimension_type": 1, "uid": None, "num": 20},
                    20,
                ),
                (target_vendor_code, 3232, {}, 1),
            )
        )
    plan = tuple(
        build_futu_runtime_request_plan_item(
            plan_index=index,
            security_code=code,
            protocol_id=protocol_id,
            parameters=parameters,
            maximum_pages=maximum_pages,
        )
        for index, (code, protocol_id, parameters, maximum_pages) in enumerate(operations)
    )
    return authorized_codes, plan
GLOBAL_STATE_FINGERPRINT = HASH_D


class DeterministicVerifier:
    def verify(
        self,
        *,
        signer_key_id: str,
        payload: bytes,
        signature_hex: str,
    ) -> bool:
        expected = hashlib.sha512(signer_key_id.encode("utf-8") + b"\0" + payload).hexdigest()
        return signature_hex == expected


def _signed_payload(prefix: str, values: dict[str, Any]) -> dict[str, Any]:
    values = dict(values)
    values["signature_algorithm"] = "ed25519"
    values["signer_key_id"] = "test-key"
    values["receipt_id"] = signed_receipt_identity(prefix, values)
    signature_payload = dict(values)
    signature = hashlib.sha512(
        b"test-key\0" + canonical_json(signature_payload).encode("utf-8")
    ).hexdigest()
    values["signature_hex"] = signature
    return values


def _signed(cls: type[Any], prefix: str, values: dict[str, Any]):
    return cls(**_signed_payload(prefix, values))


def _resigned_payload(prefix: str, values: dict[str, Any]) -> dict[str, Any]:
    unsigned = dict(values)
    unsigned.pop("receipt_id", None)
    unsigned.pop("signature_algorithm", None)
    unsigned.pop("signer_key_id", None)
    unsigned.pop("signature_hex", None)
    return _signed_payload(prefix, unsigned)


def _signed_wire_payload(values: dict[str, Any]) -> dict[str, Any]:
    payload = {
        **values,
        "signature_algorithm": "ed25519",
        "signer_key_id": "test-key",
    }
    payload["signature_hex"] = hashlib.sha512(
        b"test-key\0" + canonical_json(payload).encode("utf-8")
    ).hexdigest()
    return payload


def _authorities(
    *,
    qot_logined: bool = True,
    trd_logined: bool = False,
    valid_daily_close_semantics: bool = True,
    denied_family: str | None = None,
    target_vendor_code: str = "US.AAPL",
    peer_count: int = 5,
    trading_date: str = "2026-08-14",
    request_plan_profile: str = "full",
    optional_pre_price_specs: tuple[FutuRequestSpec, ...] = (),
    account_quota_remaining: int = 100,
    account_protocol_version: str = "10.10.7008",
    account_delay_class: str = "real_time",
    account_promotion_status: str = "normal",
) -> tuple[FutuAuthoritySet, FutuSecurityIdentityReceipt, FutuSupplyChainReceipt]:
    registry = load_protocol_registry()
    protocols = tuple(registry)
    data_families = tuple(sorted({item["data_family"] for item in registry.values()}))
    legal = _signed(
        FutuLegalRightsReceipt,
        "futu-legal:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "policy_sha256": POLICY_SHA256,
            "component_lock_sha256": COMPONENT_LOCK_SHA256,
            "account_scope_sha256": ACCOUNT_SCOPE_SHA256,
            "agreement_sha256": HASH_D,
            "allowed_mics": ["XNAS", "XNYS"],
            "allowed_currencies": ["USD"],
            "allowed_data_families": list(data_families),
            "allowed_protocol_ids": list(protocols),
            "rights": {
                "internal_research": True,
                "valuation": True,
                "raw_retention": True,
                "audit_replay": True,
                "derived_private_report": True,
                "derived_public_report": False,
            },
            "effective_at": "2026-08-13T00:00:00Z",
            "issued_at": ISSUED,
            "expires_at": EXPIRES,
            "revoked_at": None,
        },
    )
    supply = _signed(
        FutuSupplyChainReceipt,
        "futu-supply:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "policy_sha256": POLICY_SHA256,
            "component_lock_sha256": COMPONENT_LOCK_SHA256,
            "provider_id": "provider:futu-opend-sidecar",
            "provider_version": "1.0.0",
            "opend_version": "10.9.5208",
            "opend_server_version": 100_905_208,
            "opend_server_build_no": 1,
            "futu_api_version": "10.10.7008",
            "futu_api_distribution_sha256": (
                "3c607c7dce02a3a2b308f3424420277a360d7b3a4ba4508b39eaa4ff11271f98"
            ),
            "sdk_operation_registry_sha256": (
                "48be8aa86fd9c5fc5b5a3b201939c0bd4386b23dbe408d9f30a8e190ce3bbc4a"
            ),
            "protobuf_descriptor_set_sha256": (
                "c2b13581ef9acdbe2b9a95da26b95d6321058f7beb27b56fef90908519e312f8"
            ),
            "official_distribution_url": "https://openapi.futunn.com/opend.zip",
            "distribution_sha256": HASH_D,
            "publisher_signature_status": "verified",
            "protocol_descriptor_sha256": HASH_E,
            "facade_sha256": HASH_F,
            "adapter_sha256": HASH_A,
            "parser_sha256": HASH_B,
            "vm_image_sha256": HASH_C,
            "sbom_sha256": HASH_D,
            "license_sha256": HASH_E,
            "daily_close_semantics_evidence_kind": (
                "pinned_opend_proto_canary" if valid_daily_close_semantics else "none"
            ),
            "daily_close_semantics_evidence_sha256": (
                HASH_F if valid_daily_close_semantics else None
            ),
            "issued_at": ISSUED,
            "expires_at": EXPIRES,
        },
    )
    authorized_security_codes, request_plan = _runtime_request_plan(
        target_vendor_code=target_vendor_code,
        peer_count=peer_count,
        trading_date=trading_date,
        profile=request_plan_profile,
        optional_pre_price_specs=optional_pre_price_specs,
    )
    runtime_authorization = _signed(
        FutuRuntimeIsolationAuthorization,
        "futu-runtime-authorization:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "run_id": RUN_ID,
            "policy_sha256": POLICY_SHA256,
            "component_lock_sha256": COMPONENT_LOCK_SHA256,
            "account_scope_sha256": ACCOUNT_SCOPE_SHA256,
            "supply_chain_fingerprint": supply.fingerprint,
            "vm_image_sha256": supply.vm_image_sha256,
            "opend_version": supply.opend_version,
            "rootless": True,
            "credentials_location": "isolated_vm_tmpfs",
            "host_opend_port_mapped": False,
            "generic_raw_send_enabled": False,
            "logging_enabled": False,
            "reminder_push_enabled": False,
            "automatic_quote_right_takeover_enabled": False,
            "trade_and_account_protocols_rejected_before_opend": True,
            "allowed_protocol_ids": list(FUTU_RUNTIME_PROTOCOL_IDS),
            "authorized_security_codes": list(authorized_security_codes),
            "request_plan": to_json_value(request_plan),
            "request_plan_fingerprint": canonical_sha256(to_json_value(request_plan)),
            "maximum_planned_requests": sum(
                item["maximum_pages"] for item in request_plan
            ),
            "maximum_pages_per_protocol": 64,
            "sidecar_attestor_key_id": "test-key",
            "authorization_window_seconds": 900,
            "issued_at": "2026-08-15T00:55:00Z",
            "valid_from": "2026-08-15T00:56:00Z",
            "expires_at": RUNTIME_AUTHORIZATION_EXPIRES,
        },
    )
    checkpoints = [
        {
            "checkpoint": "startup",
            "protocol_id": 1002,
            "serial_number": 1,
            "global_state_request_fingerprint": HASH_E,
            "global_state_response_fingerprint": GLOBAL_STATE_FINGERPRINT,
            "observed_at": "2026-08-14T00:00:01Z",
            "qot_logined": qot_logined,
            "trd_logined": trd_logined,
            "opend_server_version": supply.opend_server_version,
            "opend_server_build_no": supply.opend_server_build_no,
        },
        {
            "checkpoint": "pre_shutdown",
            "protocol_id": 1002,
            "serial_number": 2,
            "global_state_request_fingerprint": HASH_F,
            "global_state_response_fingerprint": HASH_E,
            "observed_at": "2026-08-14T00:00:02Z",
            "qot_logined": qot_logined,
            "trd_logined": trd_logined,
            "opend_server_version": supply.opend_server_version,
            "opend_server_build_no": supply.opend_server_build_no,
        },
    ]
    runtime = _signed(
        FutuRuntimeIsolationReceipt,
        "futu-runtime:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "run_id": RUN_ID,
            "policy_sha256": POLICY_SHA256,
            "component_lock_sha256": COMPONENT_LOCK_SHA256,
            "account_scope_sha256": ACCOUNT_SCOPE_SHA256,
            "supply_chain_fingerprint": supply.fingerprint,
            "runtime_authorization_fingerprint": runtime_authorization.fingerprint,
            "request_plan_fingerprint": runtime_authorization.request_plan_fingerprint,
            "authorization_window_seconds": 900,
            "vm_image_sha256": supply.vm_image_sha256,
            "opend_version": supply.opend_version,
            "opend_server_version": supply.opend_server_version,
            "opend_server_build_no": supply.opend_server_build_no,
            "rootless": True,
            "credentials_location": "isolated_vm_tmpfs",
            "host_opend_port_mapped": False,
            "generic_raw_send_enabled": False,
            "logging_enabled": False,
            "reminder_push_enabled": False,
            "automatic_quote_right_takeover_enabled": False,
            "trade_and_account_protocols_rejected_before_opend": True,
            "allowed_protocol_ids": list(FUTU_RUNTIME_PROTOCOL_IDS),
            "checkpoints": checkpoints,
            "quarantined": trd_logined,
            "started_at": "2026-08-14T00:00:00Z",
            "ended_at": "2026-08-14T00:00:03Z",
            "issued_at": "2026-08-14T00:00:04Z",
            "expires_at": EXPIRES,
        },
    )
    account = _signed(
        FutuAccountEntitlementReceipt,
        "futu-account:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "run_id": RUN_ID,
            "policy_sha256": POLICY_SHA256,
            "component_lock_sha256": COMPONENT_LOCK_SHA256,
            "account_scope_sha256": ACCOUNT_SCOPE_SHA256,
            "observed_at": "2026-08-15T00:57:00Z",
            "global_state_response_fingerprint": GLOBAL_STATE_FINGERPRINT,
            "qot_logined": qot_logined,
            "trd_logined": trd_logined,
            "entitlements": {
                family: "denied" if family == denied_family else "granted"
                for family in data_families
            },
            "delay_class": account_delay_class,
            "promotion_status": account_promotion_status,
            "quota_remaining": account_quota_remaining,
            "protocol_version": account_protocol_version,
            "challenge_nonce": HASH_F,
            "issued_at": "2026-08-15T00:57:30Z",
            "expires_at": EXPIRES,
        },
    )
    static_identity = _static_identity_projection_values(target_vendor_code)
    security = _signed(
        FutuSecurityIdentityReceipt,
        "futu-security:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "policy_sha256": POLICY_SHA256,
            "component_lock_sha256": COMPONENT_LOCK_SHA256,
            "issuer_id": ISSUER_ID,
            "cik": "0000320193",
            "security_id": SECURITY_ID,
            "ticker": "AAPL",
            "mic": "XNAS",
            "currency": "USD",
            "share_class": "common",
            "vendor_market": "US",
            "vendor_code": "US.AAPL",
            "vendor_security_id": static_identity["vendor_security_id"],
            "vendor_security_type": "STOCK",
            "vendor_exchange_type": "NASDAQ",
            "effective_from": "2026-01-01",
            "effective_to": None,
            "official_evidence_fingerprint": HASH_E,
            "static_response_fingerprint": (
                futu_static_identity_projection_fingerprint(**static_identity)
            ),
            "reviewer_id": "human:test-reviewer",
            "issued_at": ISSUED,
        },
    )
    return (
        FutuAuthoritySet(
            legal=legal,
            account=account,
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            runtime=runtime,
            security_identity=security,
        ),
        security,
        supply,
    )


def _decision(
    *,
    qot_logined: bool = True,
    trd_logined: bool = False,
    valid_signature: bool = True,
    valid_daily_close_semantics: bool = True,
    stage: str = "market_reference",
    denied_family: str | None = None,
) -> tuple[
    FutuAuthorityDecision,
    FutuSecurityIdentityReceipt,
    FutuSupplyChainReceipt,
    FutuRuntimeIsolationAuthorization,
]:
    authorities, security, supply = _authorities(
        qot_logined=qot_logined,
        trd_logined=trd_logined,
        valid_daily_close_semantics=valid_daily_close_semantics,
        denied_family=denied_family,
        request_plan_profile=(
            "pre_price" if stage == "valuation_pre_price_verification" else "market"
        ),
    )
    registry = load_protocol_registry()
    required_protocols = [
        protocol_id
        for protocol_id, item in registry.items()
        if item["stage"] == stage and item["required_for_complete"]
    ]
    required_families = sorted(
        {registry[protocol_id]["data_family"] for protocol_id in required_protocols}
    )
    verifier = DeterministicVerifier() if valid_signature else None
    decision = evaluate_futu_authority(
        authorities,
        verifier=verifier,
        now=NOW,
        run_id=RUN_ID,
        policy_sha256=POLICY_SHA256,
        component_lock_sha256=COMPONENT_LOCK_SHA256,
        required_data_families=required_families,
        required_protocol_ids=required_protocols,
    )
    assert authorities.runtime_authorization is not None
    return decision, security, supply, authorities.runtime_authorization


def _daily_close_spec(trading_date: str = "2026-08-14") -> FutuRequestSpec:
    return FutuRequestSpec(
        stage="market_reference",
        protocol_id=3103,
        parameters=FrozenMap(
            {
                "start": trading_date,
                "end": trading_date,
                "ktype": "K_DAY",
                "autype": "NONE",
                "fields": ["CLOSE", "VOLUME"],
                "max_count": 1,
                "extended_time": False,
                "session": "RTH",
            }
        ),
        expected_trading_date=trading_date,
    )


def _pre_price_specs() -> tuple[FutuRequestSpec, ...]:
    return (
        FutuRequestSpec("runtime_authority", 3104, FrozenMap({"get_detail": True})),
        FutuRequestSpec("valuation_pre_price_verification", 3202, FrozenMap({})),
        *(
            FutuRequestSpec(
                "valuation_pre_price_verification",
                3227,
                FrozenMap(
                    {
                        "statement_type": statement_type,
                        "financial_type": 7,
                        "currency_code": "USD",
                        "num": 10,
                    }
                ),
            )
            for statement_type in (1, 2, 3)
        ),
        FutuRequestSpec(
            "valuation_pre_price_verification",
            3228,
            FrozenMap({"date": 0, "financial_type": 7, "currency_code": "USD"}),
        ),
        FutuRequestSpec("valuation_pre_price_verification", 3234, FrozenMap({})),
        FutuRequestSpec("valuation_pre_price_verification", 3236, FrozenMap({})),
        FutuRequestSpec("valuation_pre_price_verification", 3243, FrozenMap({})),
    )


class NoCallTransport:
    calls = 0

    def exchange(self, request_bytes: bytes, *, maximum_response_bytes: int) -> bytes:
        self.calls += 1
        raise AssertionError("transport must not be called")


class FakeTransport:
    def __init__(
        self,
        *,
        qot_logined: bool = True,
        trd_logined: bool = False,
        canonical: bool = True,
        next_key: str | None = None,
        terminal: bool = True,
        tamper_global_binding: bool = False,
        financial_value: str = "416161000000",
        serial_offset: int = 0,
        retrieved_at: str = "2026-08-15T01:00:01Z",
        pre_guard_at: str = "2026-08-15T01:00:00Z",
        post_guard_at: str = "2026-08-15T01:00:02Z",
        evidence_seed: str = "default",
        advance_seconds_per_call: int = 0,
        raw_evidence_kind: str = "opend_protobuf_s2c_frame",
        pagination_protocol_id: int | None = None,
        tamper_supply_attestation: bool = False,
        static_mic: str = "XNAS",
        static_identity_overrides: dict[str, Any] | None = None,
        split_observation: dict[str, Any] | None = None,
        history_quota_remaining: int = 100,
        history_quota_details: tuple[str, ...] = (),
    ) -> None:
        self.qot_logined = qot_logined
        self.trd_logined = trd_logined
        self.canonical = canonical
        self.next_key = next_key
        self.terminal = terminal
        self.tamper_global_binding = tamper_global_binding
        self.financial_value = financial_value
        self.serial_offset = serial_offset
        self.retrieved_at = retrieved_at
        self.pre_guard_at = pre_guard_at
        self.post_guard_at = post_guard_at
        self.evidence_seed = evidence_seed
        self.advance_seconds_per_call = advance_seconds_per_call
        self.raw_evidence_kind = raw_evidence_kind
        self.pagination_protocol_id = pagination_protocol_id
        self.tamper_supply_attestation = tamper_supply_attestation
        self.static_mic = static_mic
        self.static_identity_overrides = static_identity_overrides
        self.split_observation = split_observation
        self.history_quota_remaining = history_quota_remaining
        self.history_quota_details = history_quota_details
        self.calls: list[dict[str, Any]] = []

    def exchange(self, request_bytes: bytes, *, maximum_response_bytes: int) -> bytes:
        assert maximum_response_bytes == MAXIMUM_RAW_BYTES_PER_RESPONSE
        request = json.loads(request_bytes)
        assert request_bytes == canonical_json(request).encode("utf-8")
        self.calls.append(request)
        protocol_id = request["protocol"]["id"]
        paginate_this_protocol = (
            self.pagination_protocol_id is None
            or self.pagination_protocol_id == protocol_id
        )
        base_serial = self.serial_offset + (len(self.calls) * 10)
        time_offset = timedelta(
            seconds=(len(self.calls) - 1) * self.advance_seconds_per_call
        )

        def offset_time(value: str) -> str:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) + time_offset
            return parsed.isoformat().replace("+00:00", "Z")

        def global_state(phase: str, serial: int) -> dict[str, Any]:
            fingerprint_key = f"required_{phase}_request_fingerprint"
            request_fingerprint = request["global_state_guards"][fingerprint_key]
            if self.tamper_global_binding and phase == "post":
                request_fingerprint = HASH_A
            state = {
                "operation": "GetGlobalState",
                "protocol_id": 1002,
                "serial_number": serial,
                "request_fingerprint": request_fingerprint,
                "retrieved_at": offset_time(
                    self.pre_guard_at if phase == "pre" else self.post_guard_at
                ),
                "ret_type": 0,
                "err_code": 0,
                "qot_logined": self.qot_logined,
                "trd_logined": self.trd_logined,
                "opend_server_version": request["expected_supply_attestation"][
                    "opend_server_version"
                ],
                "opend_server_build_no": request["expected_supply_attestation"][
                    "opend_server_build_no"
                ],
            }
            state["response_fingerprint"] = canonical_sha256(state)
            return state

        observations: list[dict[str, Any]] = []
        if protocol_id == 3104:
            aggregate_qualifiers = {
                "get_detail": True,
                "quota_kind": "historical_candlestick_distinct_security_7d",
                "quota_window_days": 7,
            }
            observations = [
                _wire_observation(
                    field_id="history_quota_used",
                    value=str(len(self.history_quota_details)),
                    unit="distinct_securities",
                    currency=None,
                    period_end=None,
                    qualifiers=aggregate_qualifiers,
                ),
                _wire_observation(
                    field_id="history_quota_remaining",
                    value=str(self.history_quota_remaining),
                    unit="distinct_securities",
                    currency=None,
                    period_end=None,
                    qualifiers=aggregate_qualifiers,
                ),
                *(
                    {
                        "field_id": "history_quota_detail",
                        "period": {"start": None, "end": None},
                        "qualifiers": {
                            "last_request_at": "2026-08-14T16:00:00Z",
                            "raw_market_code": 11,
                            "raw_security_code": code.removeprefix("US."),
                            "source_request_time": "2026-08-14 12:00:00",
                            "source_request_timestamp": 1786723200,
                            "vendor_security_code": code,
                        },
                        "value_type": "text",
                        "value": code,
                        "unit": None,
                        "currency": None,
                        "binary64_hex": None,
                        "exact_binary64_decimal": None,
                    }
                    for code in self.history_quota_details
                ),
            ]
        elif protocol_id == 3202:
            observations = _wire_static_identity_observations(
                request["security"]["code"],
                mic=self.static_mic,
                overrides=self.static_identity_overrides,
            )
        elif protocol_id == 3103:
            trading_date = request["parameters"]["start"]
            observations = [
                _wire_observation(
                    field_id="close",
                    value="227.16",
                    unit="currency_per_share",
                    currency="USD",
                    period_end=trading_date,
                ),
                _wire_observation(
                    field_id="volume",
                    value="44000000",
                    unit="shares",
                    currency=None,
                    period_end=trading_date,
                ),
            ]
        elif protocol_id == 3227:
            statement_selector = request["parameters"]["statement_type"]
            statement_type, period_kind, field_id, display_name = {
                1: ("income", "flow", "5001", "Total Revenue"),
                2: (
                    "balance_sheet",
                    "stock",
                    "900001",
                    "Synthetic Balance Item",
                ),
                3: ("cash_flow", "flow", "900002", "Synthetic Cash Flow Item"),
                4: ("main_index", "mixed", "900003", "Synthetic Main Index Item"),
            }[statement_selector]
            common_qualifiers = {
                "accounting_standard": "US_GAAP",
                "auditor_report": "",
                "financial_type": 7,
                "period_kind": period_kind,
                "statement_type": statement_type,
                "vendor_period": "FY",
            }
            observations = [
                _wire_financial_structure_observation(
                    field_id=field_id,
                    display_name=display_name,
                    statement_type=statement_type,
                ),
                _wire_observation(
                    field_id=field_id,
                    value=self.financial_value,
                    unit="currency_units",
                    currency="USD",
                    period_start=None,
                    period_end="2026-09-26",
                    qualifiers={
                        **common_qualifiers,
                        "fiscal_year": 2026,
                    },
                ),
                _wire_observation(
                    field_id=field_id,
                    value=self.financial_value,
                    unit="currency_units",
                    currency="USD",
                    period_start=None,
                    period_end="2025-09-28",
                    qualifiers={
                        **common_qualifiers,
                        "fiscal_year": 2025,
                    },
                ),
            ]
        elif protocol_id == 3236:
            page_index = request["page_index"]
            split_observation = self.split_observation
            if (
                split_observation is None
                and paginate_this_protocol
                and not self.terminal
                and page_index > 0
            ):
                announcement_date = (
                    date(2020, 7, 30) - timedelta(days=page_index)
                ).isoformat()
                split_observation = _wire_split_observation(
                    announcement_date=announcement_date,
                    effective_date=None,
                )
            observations = [
                *(
                    [_wire_current_shares_vendor_disposition()]
                    if page_index == 0
                    else []
                ),
                *(
                    [_wire_empty_split_event_set()]
                    if (
                        split_observation is None
                        and page_index == 0
                        and (self.terminal or not paginate_this_protocol)
                    )
                    else [split_observation]
                    if split_observation is not None
                    else []
                ),
            ]
        elif protocol_id == 3228:
            observations = [_wire_empty_revenue_breakdown_segment_set()]
        elif protocol_id == 3234:
            observations = [_wire_empty_dividend_event_set()]
        elif protocol_id == 3243:
            observations = [
                {
                    "field_id": "business_summary",
                    "period": {"start": None, "end": None},
                    "qualifiers": {},
                    "value_type": "text",
                    "value": "Pinned test company profile",
                    "unit": None,
                    "currency": None,
                    "binary64_hex": None,
                    "exact_binary64_decimal": None,
                }
            ]
        elif protocol_id in {
            3229,
            3230,
            3232,
            3244,
            3245,
            3246,
        }:
            observations = [
                {
                    "field_id": "availability",
                    "period": {"start": None, "end": None},
                    "qualifiers": {
                        "availability_status": "unavailable",
                        "reason_code": "official_no_data",
                    },
                    "value_type": "null",
                    "value": None,
                    "unit": None,
                    "currency": None,
                    "binary64_hex": None,
                    "exact_binary64_decimal": None,
                }
            ]
        encrypted = hashlib.sha256(
            f"encrypted:{self.evidence_seed}:{len(self.calls)}".encode()
        ).hexdigest()
        raw = hashlib.sha256(
            f"raw:{self.evidence_seed}:{len(self.calls)}".encode()
        ).hexdigest()
        envelope = {
            "wire_schema_version": WIRE_SCHEMA_VERSION,
            "command": "fetch_quote_data_with_global_state_guards",
            "run_id": request["run_id"],
            "request_id": request["request_id"],
            "request_fingerprint": request["request_fingerprint"],
            "protocol_id": protocol_id,
            "page_index": request["page_index"],
            "supply_attestation": request["expected_supply_attestation"],
            "pre_global_state": global_state("pre", base_serial),
            "data_response": {
                "serial_number": base_serial + 1,
                "retrieved_at": offset_time(self.retrieved_at),
                "ret_type": 0,
                "err_code": 0,
                "next_key": self.next_key if paginate_this_protocol else None,
                "terminal": self.terminal if paginate_this_protocol else True,
                "raw_evidence": {
                    "evidence_kind": self.raw_evidence_kind,
                    "raw_plaintext_sha256": raw,
                    "encrypted_object_sha256": encrypted,
                    "cas_locator": f"cas://sha256/{encrypted}",
                    "envelope_key_id": "kms:futu-test-key",
                    "raw_byte_count": 2048,
                },
                "observations": observations,
            },
            "post_global_state": global_state("post", base_serial + 2),
        }
        if self.tamper_supply_attestation:
            envelope["supply_attestation"] = {
                **envelope["supply_attestation"],
                "futu_api_version": "10.10.7007",
            }
        if self.canonical:
            return canonical_json(envelope).encode("utf-8")
        return json.dumps(envelope, indent=2).encode("utf-8")


class OversizedTransport:
    def exchange(self, request_bytes: bytes, *, maximum_response_bytes: int) -> bytes:
        return b"x" * (maximum_response_bytes + 1)


class MutatingFinancialTransport(FakeTransport):
    def __init__(self, mutation: str) -> None:
        super().__init__(evidence_seed=f"financial-{mutation}")
        self.mutation = mutation

    def exchange(self, request_bytes: bytes, *, maximum_response_bytes: int) -> bytes:
        raw = super().exchange(
            request_bytes,
            maximum_response_bytes=maximum_response_bytes,
        )
        request = json.loads(request_bytes)
        if request["protocol"]["id"] != 3227 or request["parameters"][
            "statement_type"
        ] != 1:
            return raw
        envelope = json.loads(raw)
        observations = envelope["data_response"]["observations"]
        if self.mutation == "duplicate_descriptor":
            observations.insert(1, dict(observations[0]))
        elif self.mutation == "blank_descriptor":
            observations[0]["value"] = ""
            observations[0]["qualifiers"]["normalized_display_name"] = ""
        elif self.mutation == "rename_descriptor":
            observations[0]["value"] = "Net Sales"
            observations[0]["qualifiers"]["normalized_display_name"] = "net sales"
        elif self.mutation == "drop_previous":
            del observations[-1]
        elif self.mutation == "income_statement_enum":
            observations[0]["qualifiers"]["statement_type"] = "income_statement"
            for observation in observations[1:]:
                observation["qualifiers"]["statement_type"] = "income_statement"
        else:  # pragma: no cover - test helper construction is closed below
            raise AssertionError(f"unknown financial mutation: {self.mutation}")
        return canonical_json(envelope).encode("utf-8")


class EmptyRequiredCompanyProfileTransport(FakeTransport):
    def exchange(self, request_bytes: bytes, *, maximum_response_bytes: int) -> bytes:
        raw = super().exchange(
            request_bytes,
            maximum_response_bytes=maximum_response_bytes,
        )
        request = json.loads(request_bytes)
        if request["protocol"]["id"] != 3243:
            return raw
        envelope = json.loads(raw)
        envelope["data_response"]["observations"] = []
        return canonical_json(envelope).encode("utf-8")


def _wire_observation(
    *,
    field_id: str,
    value: str,
    unit: str,
    currency: str | None,
    period_start: str | None = None,
    period_end: str | None,
    qualifiers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "field_id": field_id,
        "period": {"start": period_start, "end": period_end},
        "qualifiers": qualifiers or {},
        "value_type": "number",
        "value": value,
        "unit": unit,
        "currency": currency,
        "binary64_hex": None,
        "exact_binary64_decimal": None,
    }


def _wire_financial_structure_observation(
    *,
    field_id: str,
    display_name: str,
    statement_type: str,
) -> dict[str, Any]:
    normalized_display_name = " ".join(display_name.casefold().split())
    return {
        "field_id": f"financial_structure:{field_id}",
        "period": {"start": None, "end": None},
        "qualifiers": {
            "financial_field_id": field_id,
            "futu_api_version": "10.10.7008",
            "normalized_display_name": normalized_display_name,
            "statement_type": statement_type,
        },
        "value_type": "text",
        "value": display_name,
        "unit": None,
        "currency": None,
        "binary64_hex": None,
        "exact_binary64_decimal": None,
    }


def _wire_split_observation(
    *,
    announcement_date: str = "2020-07-30",
    effective_date: str | None = None,
    reform_type: str = "Split",
    rate_raw: str = "1->4",
    rate_numerator: str = "4",
    rate_denominator: str = "1",
) -> dict[str, Any]:
    return {
        "field_id": "stock_split_event",
        "period": {
            "start": None,
            "end": effective_date or announcement_date,
        },
        "qualifiers": {
            "announcement_date": announcement_date,
            "current_shares_status": "vendor_not_supported",
            "effective_date": effective_date,
            "event_type": (
                "stock_split_completed"
                if int(rate_numerator) > int(rate_denominator)
                else "reverse_stock_split_completed"
            ),
            "rate_denominator": rate_denominator,
            "rate_numerator": rate_numerator,
            "rate_raw": rate_raw,
            "reform_type": reform_type,
        },
        "value_type": "text",
        "value": f"{rate_numerator}/{rate_denominator}",
        "unit": "split_ratio",
        "currency": None,
        "binary64_hex": None,
        "exact_binary64_decimal": None,
    }


def _wire_current_shares_vendor_disposition() -> dict[str, Any]:
    return {
        "field_id": "current_common_shares",
        "period": {"start": None, "end": None},
        "qualifiers": {
            "reason_code": "us_3236_shares_after_effect_not_supported",
            "verification_status": "vendor_not_supported",
        },
        "value_type": "null",
        "value": None,
        "unit": None,
        "currency": None,
        "binary64_hex": None,
        "exact_binary64_decimal": None,
    }


def _wire_empty_split_event_set() -> dict[str, Any]:
    return {
        "field_id": "stock_split_event_set",
        "period": {"start": None, "end": None},
        "qualifiers": {
            "event_set_status": "empty",
            "reason_code": "official_no_data",
        },
        "value_type": "null",
        "value": None,
        "unit": None,
        "currency": None,
        "binary64_hex": None,
        "exact_binary64_decimal": None,
    }


def _wire_empty_revenue_breakdown_segment_set() -> dict[str, Any]:
    return {
        "field_id": "revenue_breakdown_segment_set",
        "period": {"start": None, "end": None},
        "qualifiers": {
            "reason_code": "official_no_data",
            "segment_set_status": "empty",
        },
        "value_type": "null",
        "value": None,
        "unit": None,
        "currency": None,
        "binary64_hex": None,
        "exact_binary64_decimal": None,
    }


def _wire_empty_dividend_event_set() -> dict[str, Any]:
    return {
        "field_id": "dividend_event_set",
        "period": {"start": None, "end": None},
        "qualifiers": {
            "event_set_status": "empty",
            "reason_code": "official_no_data",
        },
        "value_type": "null",
        "value": None,
        "unit": None,
        "currency": None,
        "binary64_hex": None,
        "exact_binary64_decimal": None,
    }


def _official_graph(
    *,
    value: str = "416161000000",
    issuer_id: str = ISSUER_ID,
) -> tuple[ContractGraph, Fact]:
    source = SourceDocument(
        schema_version="1.0.0",
        document_id="document:sec-revenue",
        issuer_id=issuer_id,
        document_type="10-K",
        period=FrozenMap({"start": "2025-09-29", "end": "2026-09-26"}),
        published_date="2026-08-14",
        retrieved_at="2026-08-15T00:30:00Z",
        source_url="https://www.sec.gov/Archives/edgar/data/320193/test.htm",
        authority_level="primary_regulatory",
        content_sha256=HASH_A,
    )
    fact = Fact(
        schema_version="2.0.0",
        fact_id="fact:sec-revenue",
        issuer_id=issuer_id,
        concept="revenue",
        value_type="number",
        value=int(value),
        unit="currency_units",
        currency="USD",
        period=FrozenMap({"start": "2025-09-29", "end": "2026-09-26"}),
        source_document_id=source.document_id,
        source_locator="xbrl:us-gaap:RevenueFromContractWithCustomerExcludingAssessedTax",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    graph = ContractGraph(documents=(source,), facts=(fact,))
    graph.validate()
    return graph, fact


def _official_split_graph(*, ratio: int = 4) -> tuple[ContractGraph, Fact]:
    source = SourceDocument(
        schema_version="1.0.0",
        document_id="document:sec-split",
        issuer_id=ISSUER_ID,
        document_type="8-K",
        period=FrozenMap({"start": None, "end": "2020-08-31"}),
        published_date="2020-08-31",
        retrieved_at="2026-08-15T00:30:00Z",
        source_url="https://www.sec.gov/Archives/edgar/data/320193/split.htm",
        authority_level="primary_regulatory",
        content_sha256=HASH_B,
    )
    fact = Fact(
        schema_version="2.0.0",
        fact_id="fact:sec-stock-split:2020-08-31",
        issuer_id=ISSUER_ID,
        concept="stock_split_completed",
        value_type="number",
        value=ratio,
        unit="ratio",
        currency=None,
        period=FrozenMap({"start": None, "end": "2020-08-31"}),
        source_document_id=source.document_id,
        source_locator="sec:8-k:stock-split",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    graph = ContractGraph(documents=(source,), facts=(fact,))
    graph.validate()
    return graph, fact


def _official_critical_financial_graph(
    concept: str,
    *,
    flow: bool,
) -> tuple[ContractGraph, Fact]:
    period = FrozenMap(
        {
            "start": "2025-09-29" if flow else None,
            "end": "2026-09-26",
        }
    )
    source = SourceDocument(
        schema_version="1.0.0",
        document_id=f"document:sec:{concept}",
        issuer_id=ISSUER_ID,
        document_type="10-K",
        period=period,
        published_date="2026-08-14",
        retrieved_at="2026-08-15T00:30:00Z",
        source_url=f"https://www.sec.gov/Archives/edgar/data/320193/{concept}.htm",
        authority_level="primary_regulatory",
        content_sha256=HASH_D,
    )
    fact = Fact(
        schema_version="2.0.0",
        fact_id=f"fact:sec:{concept}",
        issuer_id=ISSUER_ID,
        concept=concept,
        value_type="number",
        value=100,
        unit="currency_units",
        currency="USD",
        period=period,
        source_document_id=source.document_id,
        source_locator=f"xbrl:us-gaap:{concept}",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    graph = ContractGraph(documents=(source,), facts=(fact,))
    graph.validate()
    return graph, fact


def _frozen_conclusion(
    *,
    composite_valuation: CompositeValuationResult,
    owner_scorecard: OwnerScorecard,
    frozen_at: str = "2026-08-15T01:06:00Z",
    security_id: str = SECURITY_ID,
) -> FutuFrozenConclusionReceipt:
    return build_futu_frozen_conclusion_receipt(
        run_id=RUN_ID,
        security_id=security_id,
        composite_valuation=composite_valuation,
        owner_scorecard=owner_scorecard,
        conclusion_frozen_at=frozen_at,
    )


@dataclass(frozen=True, slots=True)
class CompleteFutuSessionFixture:
    session: FutuSessionEvidence
    publication_manifest: FutuSessionPublicationManifest
    market_execution_evidence: FutuMarketExecutionEvidence
    peer_evidence_set: FutuPeerEvidenceSet
    frozen_conclusion: FutuFrozenConclusionReceipt
    pre_execution: FutuSidecarExecution
    optional_data_review: NamedHumanReviewAuthority
    live_authority_set: FutuAuthoritySet
    completed_authority_set: FutuAuthoritySet
    authority_decision: FutuAuthorityDecision
    verifier: DeterministicVerifier


@dataclass(frozen=True, slots=True)
class FutuPeerEvidenceFixture:
    peer_evidence_set: FutuPeerEvidenceSet
    peer_sessions: tuple[FutuPeerSessionEvidence, ...]
    verifier: DeterministicVerifier


def _security_receipt(
    *,
    issuer_id: str,
    security_id: str,
    ticker: str,
    mic: str = "XNAS",
) -> FutuSecurityIdentityReceipt:
    static_identity = _static_identity_projection_values(f"US.{ticker}", mic=mic)
    return _signed(
        FutuSecurityIdentityReceipt,
        "futu-security:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "policy_sha256": POLICY_SHA256,
            "component_lock_sha256": COMPONENT_LOCK_SHA256,
            "issuer_id": issuer_id,
            "cik": f"{int(canonical_sha256(issuer_id)[:8], 16) % 10_000_000_000:010d}",
            "security_id": security_id,
            "ticker": ticker,
            "mic": mic,
            "currency": "USD",
            "share_class": "common",
            "vendor_market": "US",
            "vendor_code": f"US.{ticker}",
            "vendor_security_id": static_identity["vendor_security_id"],
            "vendor_security_type": "STOCK",
            "vendor_exchange_type": "NASDAQ" if mic == "XNAS" else "NYSE",
            "effective_from": "2026-01-01",
            "effective_to": None,
            "official_evidence_fingerprint": canonical_sha256(
                {"issuer_id": issuer_id, "security_id": security_id, "source": "official"}
            ),
            "static_response_fingerprint": (
                futu_static_identity_projection_fingerprint(**static_identity)
            ),
            "reviewer_id": "human:test-reviewer",
            "issued_at": ISSUED,
        },
    )


def _live_decision(
    authority_set: FutuAuthoritySet,
    *,
    protocols: tuple[int, ...],
) -> FutuAuthorityDecision:
    registry = load_protocol_registry()
    return evaluate_futu_authority(
        authority_set,
        verifier=DeterministicVerifier(),
        now=NOW,
        run_id=RUN_ID,
        policy_sha256=POLICY_SHA256,
        component_lock_sha256=COMPONENT_LOCK_SHA256,
        required_data_families=tuple(
            sorted({registry[item]["data_family"] for item in protocols})
        ),
        required_protocol_ids=protocols,
        purpose="live_preflight",
    )


def _peer_specs(
    freeze_fingerprint: str,
    trading_date: str = "2026-08-14",
) -> tuple[FutuRequestSpec, ...]:
    market = _daily_close_spec(trading_date)
    return (
        FutuRequestSpec(
            "peer_comparable_reference",
            3202,
            FrozenMap({}),
            price_blind_freeze_fingerprint=freeze_fingerprint,
        ),
        FutuRequestSpec(
            "peer_comparable_reference",
            3103,
            market.parameters,
            expected_trading_date=market.expected_trading_date,
            price_blind_freeze_fingerprint=freeze_fingerprint,
        ),
    )


def _completed_runtime_receipt(
    authority_set: FutuAuthoritySet,
    *,
    responses: tuple[Any, ...],
    ended_at: str,
) -> FutuRuntimeIsolationReceipt:
    supply = authority_set.supply_chain
    runtime_authorization = authority_set.runtime_authorization
    assert supply is not None
    assert runtime_authorization is not None
    checkpoints: list[dict[str, Any]] = [
        {
            "checkpoint": "startup",
            "protocol_id": 1002,
            "serial_number": 1,
            "global_state_request_fingerprint": HASH_E,
            "global_state_response_fingerprint": GLOBAL_STATE_FINGERPRINT,
            "observed_at": "2026-08-15T00:57:00Z",
            "qot_logined": True,
            "trd_logined": False,
            "opend_server_version": supply.opend_server_version,
            "opend_server_build_no": supply.opend_server_build_no,
        }
    ]
    for response in responses:
        retrieved = datetime.fromisoformat(response.retrieved_at.replace("Z", "+00:00"))
        checkpoints.extend(
            (
                {
                    "checkpoint": "pre_request",
                    "protocol_id": 1002,
                    "serial_number": response.pre_global_state_serial_number,
                    "global_state_request_fingerprint": (
                        response.pre_global_state_request_fingerprint
                    ),
                    "global_state_response_fingerprint": (
                        response.pre_global_state_response_fingerprint
                    ),
                    "observed_at": (retrieved - timedelta(seconds=1))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "qot_logined": True,
                    "trd_logined": False,
                    "opend_server_version": supply.opend_server_version,
                    "opend_server_build_no": supply.opend_server_build_no,
                },
                {
                    "checkpoint": "post_request",
                    "protocol_id": 1002,
                    "serial_number": response.post_global_state_serial_number,
                    "global_state_request_fingerprint": (
                        response.post_global_state_request_fingerprint
                    ),
                    "global_state_response_fingerprint": (
                        response.post_global_state_response_fingerprint
                    ),
                    "observed_at": (retrieved + timedelta(seconds=1))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "qot_logined": True,
                    "trd_logined": False,
                    "opend_server_version": supply.opend_server_version,
                    "opend_server_build_no": supply.opend_server_build_no,
                },
            )
        )
    checkpoints.append(
        {
            "checkpoint": "pre_shutdown",
            "protocol_id": 1002,
            "serial_number": 99_999,
            "global_state_request_fingerprint": HASH_F,
            "global_state_response_fingerprint": HASH_E,
            "observed_at": ended_at,
            "qot_logined": True,
            "trd_logined": False,
            "opend_server_version": supply.opend_server_version,
            "opend_server_build_no": supply.opend_server_build_no,
        }
    )
    issued = datetime.fromisoformat(ended_at.replace("Z", "+00:00")) + timedelta(seconds=1)
    return _signed(
        FutuRuntimeIsolationReceipt,
        "futu-runtime:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "run_id": RUN_ID,
            "policy_sha256": POLICY_SHA256,
            "component_lock_sha256": COMPONENT_LOCK_SHA256,
            "account_scope_sha256": ACCOUNT_SCOPE_SHA256,
            "supply_chain_fingerprint": supply.fingerprint,
            "runtime_authorization_fingerprint": runtime_authorization.fingerprint,
            "request_plan_fingerprint": runtime_authorization.request_plan_fingerprint,
            "authorization_window_seconds": 900,
            "vm_image_sha256": supply.vm_image_sha256,
            "opend_version": supply.opend_version,
            "opend_server_version": supply.opend_server_version,
            "opend_server_build_no": supply.opend_server_build_no,
            "rootless": True,
            "credentials_location": "isolated_vm_tmpfs",
            "host_opend_port_mapped": False,
            "generic_raw_send_enabled": False,
            "logging_enabled": False,
            "reminder_push_enabled": False,
            "automatic_quote_right_takeover_enabled": False,
            "trade_and_account_protocols_rejected_before_opend": True,
            "allowed_protocol_ids": list(runtime_authorization.allowed_protocol_ids),
            "checkpoints": checkpoints,
            "quarantined": False,
            "started_at": "2026-08-15T00:57:00Z",
            "ended_at": ended_at,
            "issued_at": issued.isoformat().replace("+00:00", "Z"),
            "expires_at": EXPIRES,
        },
    )


def build_futu_attested_finalization_fixture(
    *,
    executions: tuple[Any, ...],
    runtime_receipt: FutuRuntimeIsolationReceipt,
    supply_chain: FutuSupplyChainReceipt,
    runtime_authorization: FutuRuntimeIsolationAuthorization,
    verifier: DeterministicVerifier,
    skipped_conditional_conclusion: FutuFrozenConclusionReceipt | None = None,
) -> FutuAttestedSessionFinalization:
    """Build deterministic signed WIRE v2 receipts, then strict-load and replay them."""
    if (
        runtime_receipt.runtime_authorization_fingerprint
        != runtime_authorization.fingerprint
    ):
        raise ValueError("fixture runtime receipt is bound to another authorization")
    supply_attestation = {
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
    runtime_payload = runtime_receipt.to_dict()
    startup_checkpoint = runtime_payload["checkpoints"][0]
    challenge_nonce = HASH_A
    boot_nonce = HASH_B
    signer_public_key_hex = HASH_C
    session_id = canonical_sha256(
        {
            "domain": "owner-research-futu-session-v1",
            "run_id": runtime_receipt.run_id,
            "challenge_nonce": challenge_nonce,
            "boot_nonce": boot_nonce,
            "supply_attestation": supply_attestation,
            "runtime_authorization_fingerprint": runtime_authorization.fingerprint,
            "request_plan_fingerprint": runtime_authorization.request_plan_fingerprint,
            "startup_checkpoint": startup_checkpoint,
            "signer_public_key_hex": signer_public_key_hex,
        }
    )
    boot = _signed_payload(
        "futu-sidecar-boot:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "receipt_kind": "futu-sidecar-boot-attestation",
            "run_id": runtime_receipt.run_id,
            "session_id": session_id,
            "challenge_nonce": challenge_nonce,
            "boot_nonce": boot_nonce,
            "supply_attestation": supply_attestation,
            "runtime_authorization_fingerprint": runtime_authorization.fingerprint,
            "request_plan_fingerprint": runtime_authorization.request_plan_fingerprint,
            "startup_checkpoint": startup_checkpoint,
            "signer_public_key_hex": signer_public_key_hex,
            "issued_at": runtime_receipt.started_at,
        },
    )
    records: list[dict[str, Any]] = []
    plan_position = 0
    for execution in executions:
        response_by_request = {item.request_id: item for item in execution.responses}
        for request in execution.requests:
            response = response_by_request[request.request_id]
            plan_item = runtime_authorization.request_plan[plan_position]
            if (
                request.protocol_id != plan_item["protocol_id"]
                or canonical_sha256(to_json_value(request.parameters))
                != plan_item["parameters_sha256"]
                or request.page_index != 0
                or not response.terminal
            ):
                raise ValueError("fixture execution is not terminal in request-plan order")
            plan_position += 1
            observations = [
                item.to_dict()
                for item in execution.observations
                if item.response_fingerprint == response.fingerprint
            ]
            record_seed = {
                "request_fingerprint": request.fingerprint,
                "response_fingerprint": response.fingerprint,
            }
            records.append(
                {
                    "request_id": request.request_id,
                    "request_fingerprint": request.fingerprint,
                    "response_fingerprint": response.fingerprint,
                    "protocol_id": request.protocol_id,
                    "page_index": request.page_index,
                    "serial_number": response.serial_number,
                    "request_frame_sha256": canonical_sha256(
                        {**record_seed, "frame": "request"}
                    ),
                    "response_frame_sha256": canonical_sha256(
                        {**record_seed, "frame": "response"}
                    ),
                    "frame_exchange_sha256": canonical_sha256(
                        {**record_seed, "frame": "exchange"}
                    ),
                    "raw_plaintext_sha256": response.raw_plaintext_sha256,
                    "encrypted_object_sha256": response.encrypted_object_sha256,
                    "observation_sha256": canonical_sha256(observations),
                }
            )
    remaining_plan = runtime_authorization.request_plan[plan_position:]
    if remaining_plan:
        if (
            type(skipped_conditional_conclusion) is not FutuFrozenConclusionReceipt
            or any(
                item["activation_condition"] != "eligible_conclusion_only"
                for item in remaining_plan
            )
        ):
            raise ValueError(
                "fixture cannot skip request plan without an exact contested conclusion"
            )
        conditional_disposition = {
            "status": "skipped",
            "skipped_plan_indices": [item["plan_index"] for item in remaining_plan],
            "reason_code": "partial_or_contested_conclusion",
            "conclusion_receipt_id": skipped_conditional_conclusion.receipt_id,
            "conclusion_fingerprint": skipped_conditional_conclusion.fingerprint,
        }
    else:
        conditional_disposition = {
            "status": "completed",
            "skipped_plan_indices": [],
            "reason_code": None,
            "conclusion_receipt_id": None,
            "conclusion_fingerprint": None,
        }
    execution_attestation = _signed_payload(
        "futu-sidecar-execution:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "receipt_kind": "futu-sidecar-execution-attestation",
            "run_id": runtime_receipt.run_id,
            "session_id": session_id,
            "boot_receipt_id": boot["receipt_id"],
            "supply_attestation": supply_attestation,
            "runtime_authorization_fingerprint": runtime_authorization.fingerprint,
            "request_plan_fingerprint": runtime_authorization.request_plan_fingerprint,
            "conditional_plan_disposition": conditional_disposition,
            "ordered_executions": records,
            "ordered_execution_root_sha256": canonical_sha256(records),
            "checkpoint_root_sha256": canonical_sha256(runtime_payload["checkpoints"]),
            "started_at": runtime_receipt.started_at,
            "ended_at": runtime_receipt.ended_at,
            "issued_at": runtime_receipt.issued_at,
        },
    )
    return load_futu_attested_session_finalization(
        {
            "boot_attestation": boot,
            "runtime_receipt": runtime_payload,
            "execution_attestation": execution_attestation,
        },
        expected_executions=executions,
        supply_chain=supply_chain,
        runtime_authorization=runtime_authorization,
        verifier=verifier,
        skipped_conditional_conclusion=skipped_conditional_conclusion,
    )


def build_futu_peer_evidence_fixture(
    price_blind_freeze: PriceBlindFreezeCompilationResult,
    *,
    target_security_id: str = "security:acme:common",
    peer_count: int = 5,
    trading_date: str = "2026-08-14",
    data_cutoff_date: str | None = None,
    target_vendor_code: str = "US.ACME",
    shared_live_authority: FutuAuthoritySet | None = None,
    verifier: DeterministicVerifier | None = None,
) -> FutuPeerEvidenceFixture:
    """Build only the post-freeze peer calls needed by retained synthesis authority."""
    if type(price_blind_freeze) is not PriceBlindFreezeCompilationResult:
        raise TypeError("fixture requires the exact price-blind freeze")
    if not 5 <= peer_count <= 15:
        raise ValueError("fixture peer count must be five to fifteen")
    if type(target_security_id) is not str or not target_security_id:
        raise ValueError("fixture target security identity is required")
    cutoff = trading_date if data_cutoff_date is None else data_cutoff_date
    if date.fromisoformat(trading_date) > date.fromisoformat(cutoff):
        raise ValueError("fixture trading date cannot follow its data cutoff")
    verifier = DeterministicVerifier() if verifier is None else verifier
    if shared_live_authority is None:
        base_authority, _, supply = _authorities(
            target_vendor_code=target_vendor_code,
            peer_count=peer_count,
            trading_date=trading_date,
            request_plan_profile="full",
        )
        live_authority = replace(base_authority, runtime=None)
    else:
        live_authority = shared_live_authority
        if type(live_authority) is not FutuAuthoritySet:
            raise ValueError("fixture shared live authority has the wrong exact type")
        supply = live_authority.supply_chain
        if (
            live_authority.runtime is not None
            or supply is None
            or live_authority.runtime_authorization is None
            or live_authority.runtime_authorization.authorized_security_codes[0]
            != target_vendor_code
        ):
            raise ValueError("fixture shared live authority is not the exact target plan")
    runtime_authorization = live_authority.runtime_authorization
    assert runtime_authorization is not None
    freeze_fingerprint = price_blind_freeze.artifact.fingerprint
    peer_sessions: list[FutuPeerSessionEvidence] = []
    peer_base = datetime(2026, 8, 15, 1, 1, tzinfo=UTC)
    for index in range(1, peer_count + 1):
        peer_ticker = f"P{index:02d}"
        peer_issuer = f"issuer:peer:{index:02d}"
        peer_security_id = f"security:{peer_ticker}:XNAS:common"
        peer_security = _security_receipt(
            issuer_id=peer_issuer,
            security_id=peer_security_id,
            ticker=peer_ticker,
        )
        peer_authority = replace(live_authority, security_identity=peer_security)
        peer_decision = _live_decision(peer_authority, protocols=(3103, 3202))
        started = peer_base + timedelta(seconds=(index - 1) * 20)
        retrieved = started + timedelta(seconds=1)
        post_guard = started + timedelta(seconds=2)
        execution = execute_futu_plan(
            transport=FakeTransport(
                serial_offset=20_000 + (index * 1_000),
                retrieved_at=retrieved.isoformat().replace("+00:00", "Z"),
                pre_guard_at=started.isoformat().replace("+00:00", "Z"),
                post_guard_at=post_guard.isoformat().replace("+00:00", "Z"),
                evidence_seed=f"peer-{index:02d}",
                advance_seconds_per_call=3,
            ),
            authority=peer_decision,
            runtime_authorization=runtime_authorization,
            security_identity=peer_security,
            supply_chain=supply,
            run_id=RUN_ID,
            issuer_id=peer_issuer,
            security_id=peer_security_id,
            stage="peer_comparable_reference",
            data_cutoff_date=cutoff,
            request_started_at=started.isoformat().replace("+00:00", "Z"),
            specs=_peer_specs(freeze_fingerprint, trading_date),
        )
        close = next(
            item
            for item in execution.observations
            if item.canonical_concept == "futu_unadjusted_daily_close_candidate"
        )
        daily_close = adapt_futu_daily_close_to_market_reference(
            authority=peer_decision,
            request=execution.requests[1],
            response=execution.responses[1],
            observation=close,
        )
        peer_sessions.append(
            build_futu_peer_session_evidence(
                authority_set=peer_authority,
                authority_decision=peer_decision,
                execution=execution,
                daily_close=daily_close,
                price_blind_freeze=price_blind_freeze,
                verifier=verifier,
            )
        )
    peer_set = build_futu_peer_evidence_set(
        target_security_id=target_security_id,
        price_blind_freeze=price_blind_freeze,
        peers=tuple(peer_sessions),
        verifier=verifier,
    )
    return FutuPeerEvidenceFixture(
        peer_evidence_set=peer_set,
        peer_sessions=tuple(peer_sessions),
        verifier=verifier,
    )


def build_complete_futu_session_fixture(
    price_blind_freeze: PriceBlindFreezeCompilationResult,
    *,
    composite_valuation: CompositeValuationResult,
    owner_scorecard: OwnerScorecard,
    peer_count: int = 5,
    optional_data_review: NamedHumanReviewAuthority | None = None,
) -> CompleteFutuSessionFixture:
    """Reusable exact target+peer+post session for integration tests."""
    if type(price_blind_freeze) is not PriceBlindFreezeCompilationResult:
        raise TypeError("fixture requires the exact price-blind freeze")
    if not 5 <= peer_count <= 15:
        raise ValueError("fixture peer count must be five to fifteen")
    verifier = DeterministicVerifier()
    issuer_id = str(price_blind_freeze.artifact.payload["issuer_id"])
    if (
        composite_valuation.issuer_id != issuer_id
        or owner_scorecard.issuer_id != issuer_id
        or owner_scorecard.composite_valuation_fingerprint
        != composite_valuation.fingerprint
    ):
        raise ValueError("fixture conclusion objects are not aligned to the frozen issuer")
    basis = composite_valuation.basis_receipt
    ticker = str(basis["ticker"])
    security_id = str(basis["security_id"])
    mic = str(basis["listing_mic"])
    run_result = composite_valuation._run_result
    archive = run_result.archive
    if archive is None:
        raise ValueError("fixture composite lacks its strict completed archive")
    trading_date = archive.market_reference.trading_date
    data_cutoff_date = str(price_blind_freeze.artifact.payload["data_cutoff_date"])
    if optional_data_review is None:
        graph = run_result.input_receipt.graph
        research_bundle = graph.research_bundles[0]
        roots = tuple(
            object_id
            for reference in research_bundle.module_references
            for object_id in reference["object_ids"]
        )
        closure = dependency_closure(graph, roots)
        object_type, fact = next(
            (object_type, item)
            for object_type, item in closure.values()
            if object_type == "Fact"
        )
        optional_data_review = build_named_human_review_authority(
            scope="futu_optional_data_plan",
            graph=graph,
            research_bundle=research_bundle,
            reviewer_id="human:futu-data-reviewer",
            reviewed_at="2026-08-15T00:58:00Z",
            rationale="Freeze optional vendor context before any Futu request.",
            reviewed_payload={
                "company_executives": False,
                "executive_background_leader_name": None,
                "operational_efficiency": True,
                "us_buybacks_disposition": "not_supported_for_us_sec_primary",
            },
            evidence_bindings=(
                {
                    "object_type": object_type,
                    "object_id": fact.fact_id,
                    "fingerprint": fact.fingerprint,
                },
            ),
        )
    optional_specs = compile_futu_optional_data_request_specs(optional_data_review)
    base_authority, _, supply = _authorities(
        target_vendor_code=f"US.{ticker}",
        peer_count=peer_count,
        trading_date=trading_date,
        request_plan_profile="full",
        optional_pre_price_specs=optional_specs,
    )
    security = _security_receipt(
        issuer_id=issuer_id,
        security_id=security_id,
        ticker=ticker,
        mic=mic,
    )
    live_authority = replace(
        base_authority,
        runtime=None,
        security_identity=security,
    )
    planned_protocols = tuple(
        sorted(
            {
                item.protocol_id
                for item in (*_pre_price_specs(), *optional_specs)
            }
            | {3103, 3229, 3230, 3232}
        )
    )
    decision = _live_decision(live_authority, protocols=planned_protocols)
    assert decision.status == "eligible"
    runtime_authorization = live_authority.runtime_authorization
    assert runtime_authorization is not None

    pre_execution = execute_futu_plan(
        transport=FakeTransport(
            serial_offset=1_000,
            retrieved_at="2026-08-15T00:59:01Z",
            pre_guard_at="2026-08-15T00:59:00Z",
            post_guard_at="2026-08-15T00:59:02Z",
            evidence_seed="target-pre",
            advance_seconds_per_call=3,
            static_mic=mic,
        ),
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=issuer_id,
        security_id=security_id,
        stage="valuation_pre_price_verification",
        data_cutoff_date=data_cutoff_date,
        request_started_at="2026-08-15T00:59:00Z",
        specs=(*_pre_price_specs(), *optional_specs),
    )
    market_execution = execute_futu_plan(
        transport=FakeTransport(
            serial_offset=10_000,
            retrieved_at="2026-08-15T01:00:01Z",
            pre_guard_at="2026-08-15T01:00:00Z",
            post_guard_at="2026-08-15T01:00:02Z",
            evidence_seed="target-market",
        ),
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=issuer_id,
        security_id=security_id,
        stage="market_reference",
        data_cutoff_date=data_cutoff_date,
        request_started_at="2026-08-15T01:00:00Z",
        specs=(_daily_close_spec(trading_date),),
    )
    graph, fact = _official_graph(issuer_id=issuer_id)
    operand = build_official_evidence_operand(graph=graph, official_object=fact)
    vendor = next(
        item for item in pre_execution.observations if item.canonical_concept == "revenue"
    )
    crosscheck = crosscheck_vendor_observation(
        graph=graph,
        official=operand,
        vendor=vendor,
        created_at="2026-08-15T00:59:30Z",
    )
    market_evidence = finalize_futu_market_execution_evidence(
        authority_set=live_authority,
        authority_decision=decision,
        executions=(pre_execution, market_execution),
        contract_graph=graph,
        official_operands=(operand,),
        cross_checks=(crosscheck,),
        checkpoint_at="2026-08-15T01:00:03Z",
        verifier=verifier,
    )

    freeze_fingerprint = price_blind_freeze.artifact.fingerprint
    peer_base = datetime(2026, 8, 15, 1, 1, tzinfo=UTC)
    peer_fixture = build_futu_peer_evidence_fixture(
        price_blind_freeze,
        target_security_id=security_id,
        peer_count=peer_count,
        trading_date=trading_date,
        data_cutoff_date=data_cutoff_date,
        target_vendor_code=f"US.{ticker}",
        shared_live_authority=live_authority,
        verifier=verifier,
    )
    peer_set = peer_fixture.peer_evidence_set
    peer_sessions = peer_fixture.peer_sessions

    conclusion_at = peer_base + timedelta(seconds=(peer_count * 20) + 10)
    frozen_conclusion = _frozen_conclusion(
        composite_valuation=composite_valuation,
        owner_scorecard=owner_scorecard,
        frozen_at=conclusion_at.isoformat().replace("+00:00", "Z"),
        security_id=security_id,
    )
    post_started = conclusion_at + timedelta(minutes=1)
    post_execution = execute_futu_plan(
        transport=FakeTransport(
            serial_offset=80_000,
            retrieved_at=(post_started + timedelta(seconds=1))
            .isoformat()
            .replace("+00:00", "Z"),
            pre_guard_at=post_started.isoformat().replace("+00:00", "Z"),
            post_guard_at=(post_started + timedelta(seconds=2))
            .isoformat()
            .replace("+00:00", "Z"),
            evidence_seed="target-post",
            advance_seconds_per_call=3,
        ),
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=issuer_id,
        security_id=security_id,
        stage="post_valuation_context",
        data_cutoff_date=data_cutoff_date,
        request_started_at=post_started.isoformat().replace("+00:00", "Z"),
        specs=(
            FutuRequestSpec(
                "post_valuation_context",
                3229,
                FrozenMap({}),
                price_blind_freeze_fingerprint=freeze_fingerprint,
                frozen_conclusion=frozen_conclusion,
            ),
            FutuRequestSpec(
                "post_valuation_context",
                3230,
                FrozenMap({"rating_dimension_type": 1, "uid": None, "num": 20}),
                price_blind_freeze_fingerprint=freeze_fingerprint,
                frozen_conclusion=frozen_conclusion,
            ),
            FutuRequestSpec(
                "post_valuation_context",
                3232,
                FrozenMap({}),
                price_blind_freeze_fingerprint=freeze_fingerprint,
                frozen_conclusion=frozen_conclusion,
            ),
        ),
    )
    ordered_responses = (
        *pre_execution.responses,
        *market_execution.responses,
        *(response for peer in peer_sessions for response in peer.execution.responses),
        *post_execution.responses,
    )
    ended_at = (post_started + timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    runtime = _completed_runtime_receipt(
        live_authority,
        responses=ordered_responses,
        ended_at=ended_at,
    )
    ordered_executions = (
        pre_execution,
        market_execution,
        *(peer.execution for peer in peer_sessions),
        post_execution,
    )
    attested_finalization = build_futu_attested_finalization_fixture(
        executions=ordered_executions,
        runtime_receipt=runtime,
        supply_chain=supply,
        runtime_authorization=runtime_authorization,
        verifier=verifier,
    )
    completed_authority = replace(live_authority, runtime=runtime)
    finalized_at = (
        datetime.fromisoformat(ended_at.replace("Z", "+00:00")) + timedelta(seconds=2)
    ).isoformat().replace("+00:00", "Z")
    session = finalize_futu_session_evidence(
        authority_set=completed_authority,
        authority_decision=decision,
        market_execution_evidence=market_evidence,
        peer_evidence_set=peer_set,
        frozen_conclusion=frozen_conclusion,
        attested_finalization=attested_finalization,
        post_valuation_execution=post_execution,
        finalized_at=finalized_at,
        verifier=verifier,
    )
    publication = build_futu_session_publication_manifest(session, verifier=verifier)
    return CompleteFutuSessionFixture(
        session=session,
        publication_manifest=publication,
        market_execution_evidence=market_evidence,
        peer_evidence_set=peer_set,
        frozen_conclusion=frozen_conclusion,
        pre_execution=pre_execution,
        optional_data_review=optional_data_review,
        live_authority_set=live_authority,
        completed_authority_set=completed_authority,
        authority_decision=decision,
        verifier=verifier,
    )


def _execute_market(
    transport: Any,
    *,
    decision: FutuAuthorityDecision | None = None,
    security: FutuSecurityIdentityReceipt | None = None,
    supply: FutuSupplyChainReceipt | None = None,
    runtime_authorization: FutuRuntimeIsolationAuthorization | None = None,
):
    if (
        decision is None
        or security is None
        or supply is None
        or runtime_authorization is None
    ):
        decision, security, supply, runtime_authorization = _decision()
    return execute_futu_plan(
        transport=transport,
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="market_reference",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=(_daily_close_spec(),),
    )


def _execute_pre_price(transport: Any):
    decision, security, supply, runtime_authorization = _decision(
        stage="valuation_pre_price_verification"
    )
    return execute_futu_plan(
        transport=transport,
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_pre_price_specs(),
    )


def test_futu_schemas_are_packaged_extensions_not_frozen_root_members() -> None:
    repository = Path(__file__).parents[1]
    assert not tuple((repository / "schemas").glob("futu-*.schema.json"))
    extension = repository / "src/owner_research/resources/futu/extension_schemas/v1"
    expected = {
        "futu-account-entitlement-receipt.schema.json",
        "futu-cross-check-receipt.schema.json",
        "futu-data-request-receipt.schema.json",
        "futu-data-response-receipt.schema.json",
        "futu-evidence-bundle.schema.json",
        "futu-frozen-conclusion-receipt.schema.json",
        "futu-historical-kline-quota-receipt.schema.json",
        "futu-legal-rights-receipt.schema.json",
        "futu-market-execution-evidence.schema.json",
        "futu-market-execution-publication-manifest.schema.json",
        "futu-observation.schema.json",
        "futu-observation-disposition-receipt.schema.json",
        "futu-observation-disposition-publication-bundle.schema.json",
        "futu-partial-session-publication-manifest.schema.json",
        "futu-peer-evidence-set.schema.json",
        "futu-peer-session-evidence.schema.json",
        "futu-runtime-isolation-authorization.schema.json",
        "futu-runtime-isolation-receipt.schema.json",
        "futu-security-identity-receipt.schema.json",
        "futu-session-evidence.schema.json",
        "futu-session-publication-manifest.schema.json",
        "futu-supply-chain-receipt.schema.json",
    }
    assert {item.name for item in extension.glob("futu-*.schema.json")} == expected
    for filename in expected:
        schema = load_futu_schema(filename.removesuffix(".schema.json"))
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_protocol_registry_is_closed_and_excludes_account_ownership_and_short_data() -> None:
    registry = load_protocol_registry()
    assert set(registry) == {
        1002,
        3103,
        3104,
        3202,
        3227,
        3228,
        3229,
        3230,
        3232,
        3234,
        3235,
        3236,
        3243,
        3244,
        3245,
        3246,
    }
    assert registry[1002]["name"] == "GetGlobalState"
    assert registry[3104]["name"] == "Qot_RequestHistoryKLQuota"
    assert registry[3104]["stage"] == "runtime_authority"
    assert set(registry[3235]["market_scope"]).isdisjoint({"XNAS", "XNYS"})
    assert registry[3235]["required_for_complete"] is False
    assert registry[3235]["us_product_disposition"] == "not_supported"
    assert registry[3235]["us_reason_code"] == "sec_primary_us_buyback"
    assert registry[3235]["us_primary_authority"] == "SEC_IR"
    assert registry[3243]["required_for_complete"] is True
    assert {3237, 3238, 3239, 3240, 3241, 3242, 3248, 3249}.isdisjoint(registry)
    assert all("Trd_" not in item["name"] for item in registry.values())
    fields = load_financial_field_registry()
    assert {
        field_id: item["canonical_concept"] for field_id, item in fields.items()
    } == {
        "5001": "revenue",
        "5034": "operating_income",
        "5040": "pretax_income",
        "5043": "income_tax_expense",
        "5045": "net_income",
    }
    assert {item["futu_api_version"] for item in fields.values()} == {"10.10.7008"}
    assert fields["5001"]["normalized_display_name"] == "total revenue"
    assert {item["statement_type"] for item in fields.values()} == {"income"}
    assert {"6001", "7001"}.isdisjoint(fields)
    assert 3235 not in {item.protocol_id for item in _pre_price_specs()}
    policy = json.loads(
        (Path(__file__).parents[1] / "scripts/phase5e-futu-market-authority-policy-v2.json")
        .read_bytes()
        .decode("utf-8")
    )
    policy_protocols = policy["protocol_allowlist"]
    assert policy_protocols["runtime_authority"] == [1002, 3104]
    assert set(policy_protocols["valuation_pre_price_verification"]) == {
        protocol_id
        for protocol_id, item in registry.items()
        if item["stage"] == "valuation_pre_price_verification"
        and set(item["market_scope"]).intersection({"XNAS", "XNYS"})
    }
    assert policy_protocols["market_reference"] == [3103]
    assert policy_protocols["post_valuation_context"] == [3229, 3230, 3232]
    sdk = load_sdk_adapter_registry()
    assert set(sdk) == set(registry)
    assert sdk[3228]["sdk_method"] == "get_financials_revenue_breakdown"
    assert sdk[3228]["host_parameter_names"] == (
        "date",
        "financial_type",
        "currency_code",
    )
    assert sdk[3228]["pagination_mode"] == "none"
    assert sdk[3244]["host_parameter_names"] == ()
    assert sdk[3245]["host_parameter_names"] == ("leader_name",)
    assert sdk[3246]["sdk_parameter_names"] == (
        "code",
        "num",
        "next_key",
        "currency_code",
    )
    assert "financial_type" not in sdk[3246]["sdk_parameter_names"]


def test_reviewed_balance_and_cash_registry_can_load_without_code_id_changes() -> None:
    import owner_research.futu_sidecar as sidecar_module

    payload = json.loads(
        (
            Path(sidecar_module.__file__).parent
            / "resources/futu/financial-field-registry-v1.json"
        ).read_text(encoding="utf-8")
    )
    next_id = 910000
    for statement_type, concepts in payload["critical_concepts"].items():
        for concept in concepts:
            payload["mappings"].append(
                {
                    "accounting_standard_scope": "US_GAAP",
                    "canonical_concept": concept,
                    "data_family": "financial_statements",
                    "field_id": str(next_id),
                    "futu_api_version": "10.10.7008",
                    "materiality_tier": "kernel_required",
                    "normalized_display_name": concept.replace("_", " "),
                    "period_kind": (
                        "stock" if statement_type == "balance_sheet" else "flow"
                    ),
                    "sign_convention": "reported_signed",
                    "statement_type": statement_type,
                    "unit": "currency_units",
                }
            )
            next_id += 1

    mappings = sidecar_module._validate_financial_field_registry_payload(payload)
    mapped = {str(item["canonical_concept"]) for item in mappings.values()}
    required = {
        concept
        for concepts in payload["critical_concepts"].values()
        for concept in concepts
    }
    assert required.issubset(mapped)


def test_completed_runtime_receipt_cannot_authorize_a_live_transport_call() -> None:
    authorities, security, supply = _authorities()
    completed_only = replace(authorities, runtime_authorization=None)
    replay = evaluate_futu_authority(
        completed_only,
        verifier=DeterministicVerifier(),
        now=NOW,
        run_id=RUN_ID,
        policy_sha256=POLICY_SHA256,
        component_lock_sha256=COMPONENT_LOCK_SHA256,
        required_data_families=("market_price",),
        required_protocol_ids=(3103,),
        purpose="replay_only",
    )
    assert replay.status == "eligible"
    assert replay.evaluation_scope == "replay_only"
    transport = NoCallTransport()
    result = execute_futu_plan(
        transport=transport,
        authority=replay,
        runtime_authorization=None,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="market_reference",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=(_daily_close_spec(),),
    )
    assert result.bundle.status == "blocked"
    assert result.bundle.issues == ("runtime_isolation_missing",)
    assert transport.calls == 0


def test_missing_signed_authority_returns_typed_block_without_transport_call() -> None:
    decision = evaluate_futu_authority(
        FutuAuthoritySet(),
        verifier=DeterministicVerifier(),
        now=NOW,
        run_id=RUN_ID,
        policy_sha256=POLICY_SHA256,
        component_lock_sha256=COMPONENT_LOCK_SHA256,
        required_data_families=("market_price",),
        required_protocol_ids=(3103,),
    )
    transport = NoCallTransport()
    result = execute_futu_plan(
        transport=transport,
        authority=decision,
        security_identity=None,
        supply_chain=None,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="market_reference",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=(_daily_close_spec(),),
    )
    assert decision.status == "blocked"
    assert result.bundle.status == "blocked"
    assert "legal_right_missing" in result.bundle.issues
    assert transport.calls == 0


@pytest.mark.parametrize(
    ("qot_logined", "trd_logined", "status", "issue"),
    [
        (False, False, "blocked", "qot_login_false"),
        (True, True, "quarantined", "trade_login_true"),
    ],
)
def test_authority_login_state_fails_closed(
    qot_logined: bool,
    trd_logined: bool,
    status: str,
    issue: str,
) -> None:
    decision, _, _, _ = _decision(qot_logined=qot_logined, trd_logined=trd_logined)
    assert decision.status == status
    assert issue in decision.issue_codes


def test_authority_signature_is_host_verified_and_missing_verifier_blocks() -> None:
    decision, _, _, _ = _decision(valid_signature=False)
    assert decision.status == "blocked"
    assert "authority_signature_invalid" in decision.issue_codes


def test_authority_decision_exposes_only_account_and_runtime_intersection() -> None:
    decision, security, supply, runtime_authorization = _decision(
        denied_family="financial_statements"
    )
    assert decision.status == "eligible"
    assert "financial_statements" not in decision.allowed_data_families
    result = execute_futu_plan(
        transport=NoCallTransport(),
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_pre_price_specs(),
    )
    assert result.bundle.status == "blocked"
    assert result.bundle.issues == ("data_family_not_entitled",)


def test_signed_receipt_is_immutable_and_identity_bound() -> None:
    authorities, _, _ = _authorities()
    assert authorities.account is not None
    with pytest.raises(TypeError):
        authorities.account.entitlements["market_price"] = "denied"  # type: ignore[index]
    values = authorities.account.to_dict()
    values["quota_remaining"] = 99
    with pytest.raises(FutuReceiptError, match="receipt_id"):
        FutuAccountEntitlementReceipt(**values)


def test_signed_receipt_and_authority_set_loaders_reconstruct_exact_types() -> None:
    authorities, _, _ = _authorities()
    assert authorities.legal is not None
    loaded_legal = load_futu_signed_receipt(
        "futu-legal-rights-receipt", authorities.legal.to_dict()
    )
    assert type(loaded_legal) is FutuLegalRightsReceipt
    assert loaded_legal == authorities.legal
    authority_payload = {
        "legal": authorities.legal.to_dict(),
        "account": authorities.account.to_dict(),
        "supply_chain": authorities.supply_chain.to_dict(),
        "runtime_authorization": authorities.runtime_authorization.to_dict(),
        "runtime": None,
        "security_identity": authorities.security_identity.to_dict(),
    }
    loaded = load_futu_authority_set(authority_payload)
    assert loaded == replace(authorities, runtime=None)
    authority_payload["unexpected"] = None
    with pytest.raises(FutuReceiptError, match="member set"):
        load_futu_authority_set(authority_payload)


@pytest.mark.parametrize(
    ("issued_at", "valid_from", "expires_at"),
    (
        (
            "2026-08-15T00:55:00Z",
            "2026-08-15T00:56:00Z",
            "2026-08-15T01:11:01Z",
        ),
        (
            "2026-08-15T00:50:59Z",
            "2026-08-15T00:56:00Z",
            "2026-08-15T01:11:00Z",
        ),
    ),
)
def test_runtime_authorization_rejects_long_or_stale_one_session_windows(
    issued_at: str,
    valid_from: str,
    expires_at: str,
) -> None:
    authorities, _, _ = _authorities()
    assert authorities.runtime_authorization is not None
    payload = authorities.runtime_authorization.to_dict()
    payload.update(
        {
            "issued_at": issued_at,
            "valid_from": valid_from,
            "expires_at": expires_at,
        }
    )
    payload.pop("receipt_id")
    payload.pop("signature_hex")
    with pytest.raises(FutuReceiptError, match="one-session window"):
        FutuRuntimeIsolationAuthorization(
            **_signed_payload("futu-runtime-authorization:", payload)
        )


def test_valid_pre_price_plan_keeps_futu_financials_vendor_secondary_and_current_snapshot() -> None:
    decision, security, supply, runtime_authorization = _decision(
        stage="valuation_pre_price_verification"
    )
    transport = FakeTransport()
    result = execute_futu_plan(
        transport=transport,
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_pre_price_specs(),
    )
    assert result.bundle.status == "complete"
    financial_requests = tuple(item for item in result.requests if item.protocol_id == 3227)
    assert [item.parameters["statement_type"] for item in financial_requests] == [1, 2, 3]
    response_request_ids = {item.request_id for item in result.responses}
    assert all(item.request_id in response_request_ids for item in financial_requests)
    financial_observations = tuple(
        item for item in result.observations if item.data_family == "financial_statements"
    )
    assert {item.qualifiers["statement_type"] for item in financial_observations} == {
        "income",
        "balance_sheet",
        "cash_flow",
    }
    assert all(
        item.source_role == "vendor_secondary"
        and item.point_in_time_status == "current_snapshot"
        for item in financial_observations
    )
    revenue = next(item for item in result.observations if item.canonical_concept == "revenue")
    assert revenue.source_role == "vendor_secondary"
    assert revenue.point_in_time_status == "current_snapshot"
    assert revenue.comparison_eligible is True
    assert revenue.period == FrozenMap({"start": "2025-09-29", "end": "2026-09-26"})
    assert result.history_quota is not None
    assert result.history_quota.sufficient is True
    assert result.history_quota.planned_history_security_codes == (
        "US.AAPL",
        "US.P01",
        "US.P02",
        "US.P03",
        "US.P04",
        "US.P05",
    )
    assert revenue.qualifiers["financial_period_start_derivation"] == (
        "previous_annual_period_end_plus_one_day"
    )
    prior_revenue = next(
        item
        for item in result.observations
        if item.field_id == "5001" and item.period["end"] == "2025-09-28"
    )
    assert prior_revenue.canonical_concept is None
    assert prior_revenue.comparison_eligible is False
    assert prior_revenue.qualifiers["financial_period_status"] == (
        "annual_predecessor_unavailable"
    )
    assert result.requests[0].protocol_id == 3104
    assert result.requests[0].stage == "runtime_authority"
    assert all(
        item.stage == "valuation_pre_price_verification" for item in result.requests[1:]
    )


def test_account_scalar_zero_does_not_preempt_3104_when_all_subjects_already_counted() -> None:
    authority_set, security, supply = _authorities(account_quota_remaining=0)
    decision = _live_decision(
        authority_set,
        protocols=(3104, 3103, 3202, 3227, 3228, 3234, 3236, 3243),
    )
    assert decision.status == "eligible"
    planned = ("US.AAPL", "US.P01", "US.P02", "US.P03", "US.P04", "US.P05")
    transport = FakeTransport(
        history_quota_remaining=0,
        history_quota_details=planned,
    )
    assert authority_set.runtime_authorization is not None
    result = execute_futu_plan(
        transport=transport,
        authority=decision,
        runtime_authorization=authority_set.runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_pre_price_specs(),
    )
    assert result.bundle.status == "complete"
    assert result.history_quota is not None
    assert result.history_quota.remaining_quota == 0
    assert result.history_quota.required_incremental_security_count == 0
    assert result.history_quota.already_counted_security_codes == planned
    assert [item["protocol"]["id"] for item in transport.calls[:1]] == [3104]


def test_signed_3104_insufficient_quota_blocks_before_first_data_call() -> None:
    decision, security, supply, runtime_authorization = _decision(
        stage="valuation_pre_price_verification"
    )
    transport = FakeTransport(history_quota_remaining=0)
    result = execute_futu_plan(
        transport=transport,
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_pre_price_specs(),
    )
    assert result.bundle.status == "blocked"
    assert result.bundle.issues == ("historical_kline_quota_insufficient",)
    assert result.history_quota is not None
    assert result.history_quota.required_incremental_security_count == 6
    assert [item["protocol"]["id"] for item in transport.calls] == [3104]


def test_target_plus_five_peers_requires_six_distinct_history_subjects() -> None:
    result = _execute_pre_price(FakeTransport())
    quota = result.history_quota
    assert quota is not None
    assert quota.planned_history_security_codes == (
        "US.AAPL",
        "US.P01",
        "US.P02",
        "US.P03",
        "US.P04",
        "US.P05",
    )
    assert quota.required_incremental_security_count == 6


def test_zero_remaining_quota_is_valid_when_every_subject_is_already_counted() -> None:
    planned = ("US.AAPL", "US.P01", "US.P02", "US.P03", "US.P04", "US.P05")
    result = _execute_pre_price(
        FakeTransport(
            history_quota_remaining=0,
            history_quota_details=planned,
        )
    )
    assert result.bundle.status == "complete"
    quota = result.history_quota
    assert quota is not None
    assert quota.already_counted_security_codes == planned
    assert quota.required_incremental_security_count == 0
    assert quota.sufficient is True


def test_already_counted_subjects_reduce_incremental_quota_exactly() -> None:
    decision, security, supply, runtime_authorization = _decision(
        stage="valuation_pre_price_verification"
    )
    transport = FakeTransport(
        history_quota_remaining=3,
        history_quota_details=("US.AAPL", "US.P01", "US.P02"),
    )
    result = execute_futu_plan(
        transport=transport,
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_pre_price_specs(),
    )
    assert result.bundle.status == "complete"
    quota = result.history_quota
    assert quota is not None
    assert quota.already_counted_security_codes == ("US.AAPL", "US.P01", "US.P02")
    assert quota.required_incremental_security_count == 3
    assert quota.remaining_quota == 3
    assert quota.sufficient is True


def test_quota_detail_or_plan_rebind_is_rejected() -> None:
    result = _execute_pre_price(FakeTransport())
    quota = result.history_quota
    assert quota is not None
    with pytest.raises(FutuReceiptError):
        replace(
            quota,
            planned_history_security_codes=tuple(
                reversed(quota.planned_history_security_codes)
            ),
        )
    with pytest.raises(FutuReceiptError):
        replace(quota, remaining_quota=quota.remaining_quota + 1)


def test_account_protocol_version_must_match_pinned_supply_chain() -> None:
    authority_set, _, _ = _authorities(account_protocol_version="10.9")
    decision = _live_decision(authority_set, protocols=(3104, 3103))
    assert decision.status == "blocked"
    assert "account_protocol_version_mismatch" in decision.issue_codes


@pytest.mark.parametrize(
    ("delay_class", "promotion_status"),
    (("unknown", "normal"), ("delayed", "normal"), ("real_time", "unknown")),
)
def test_unknown_or_delayed_quote_permission_is_forbidden(
    delay_class: str,
    promotion_status: str,
) -> None:
    authority_set, _, _ = _authorities(
        account_delay_class=delay_class,
        account_promotion_status=promotion_status,
    )
    decision = _live_decision(authority_set, protocols=(3104, 3103))
    assert decision.status == "blocked"
    assert "api_quote_permission_unknown" in decision.issue_codes


def test_history_quota_protocol_is_exact_once_quote_only_and_rate_bounded() -> None:
    decision, security, supply, runtime_authorization = _decision(
        stage="valuation_pre_price_verification"
    )
    transport = FakeTransport()
    result = execute_futu_plan(
        transport=transport,
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_pre_price_specs(),
    )
    assert result.bundle.status == "complete"
    protocol_ids = [item["protocol"]["id"] for item in transport.calls]
    assert protocol_ids[0] == 3104
    assert protocol_ids.count(3104) == 1
    assert all(
        item["global_state_guards"]["qot_logined"] is True
        and item["global_state_guards"]["trd_logined"] is False
        for item in transport.calls
    )
    history_items = tuple(
        item for item in runtime_authorization.request_plan if item["protocol_id"] == 3103
    )
    assert len(history_items) == 6
    assert len({item["security_code"] for item in history_items}) == 6
    assert len(history_items) <= 60


@pytest.mark.parametrize(
    "mutation",
    ["duplicate_descriptor", "blank_descriptor", "income_statement_enum"],
)
def test_financial_structure_and_statement_enum_drift_block_before_comparison(
    mutation: str,
) -> None:
    result = _execute_pre_price(MutatingFinancialTransport(mutation))
    assert result.bundle.status == "blocked"
    assert "sidecar_response_invalid" in result.bundle.issues
    assert not tuple(
        item for item in result.observations if item.canonical_concept == "revenue"
    )


def test_financial_mapping_binds_normalized_structure_name_and_complete_flow_period() -> None:
    renamed = _execute_pre_price(MutatingFinancialTransport("rename_descriptor"))
    assert renamed.bundle.status == "complete"
    income_values = tuple(
        item
        for item in renamed.observations
        if item.data_family == "financial_statements" and item.field_id == "5001"
    )
    assert income_values
    assert all(item.canonical_concept is None for item in income_values)
    assert all(item.comparison_eligible is False for item in income_values)

    incomplete = _execute_pre_price(MutatingFinancialTransport("drop_previous"))
    assert incomplete.bundle.status == "complete"
    current = next(
        item
        for item in incomplete.observations
        if item.data_family == "financial_statements" and item.field_id == "5001"
    )
    assert current.period == FrozenMap({"start": None, "end": "2026-09-26"})
    assert current.qualifiers["financial_period_status"] == (
        "annual_predecessor_unavailable"
    )
    assert current.canonical_concept is None
    assert current.comparison_eligible is False


def test_required_company_profile_cannot_complete_with_an_empty_response() -> None:
    result = _execute_pre_price(EmptyRequiredCompanyProfileTransport())
    assert result.bundle.status == "blocked"
    assert result.bundle.issues == ("sidecar_response_invalid",)


def test_stock_split_event_preserves_exact_ratio_dates_and_never_claims_current_shares() -> None:
    result = _execute_pre_price(
        FakeTransport(
            evidence_seed="typed-split",
            split_observation=_wire_split_observation(),
        )
    )
    assert result.bundle.status == "complete"
    split = next(
        item for item in result.observations if item.field_id == "stock_split_event"
    )
    current_shares = next(
        item
        for item in result.observations
        if item.field_id == "current_common_shares"
    )
    assert split.canonical_concept == "stock_split_completed"
    assert split.value == "4/1"
    assert split.period == FrozenMap({"start": None, "end": "2020-07-30"})
    assert split.qualifiers == FrozenMap(
        {
            "announcement_date": "2020-07-30",
            "current_shares_status": "vendor_not_supported",
            "effective_date": None,
            "event_type": "stock_split_completed",
            "rate_denominator": "1",
            "rate_numerator": "4",
            "rate_raw": "1->4",
            "reform_type": "Split",
        }
    )
    assert "sharesAfterEffect" not in canonical_json(split.to_dict())
    assert current_shares.value is None
    assert current_shares.qualifiers["verification_status"] == "vendor_not_supported"


@pytest.mark.parametrize(
    "split_observation",
    [
        _wire_split_observation(rate_numerator="5"),
        _wire_split_observation(effective_date="2020-07-01"),
        {
            **_wire_split_observation(),
            "qualifiers": {
                **_wire_split_observation()["qualifiers"],
                "sharesAfterEffect": "1000000",
            },
        },
    ],
)
def test_stock_split_rebinding_and_shares_after_effect_are_rejected(
    split_observation: dict[str, Any],
) -> None:
    result = _execute_pre_price(
        FakeTransport(
            evidence_seed="invalid-split",
            split_observation=split_observation,
        )
    )
    assert result.bundle.status == "blocked"
    assert "sidecar_response_invalid" in result.bundle.issues


def test_unmapped_critical_financial_fields_block_before_refreeze() -> None:
    import owner_research.owner_equity_runtime as runtime_module

    execution = SimpleNamespace(
        observations=(),
        bundle=SimpleNamespace(issuer_id=ISSUER_ID),
    )
    with pytest.raises(runtime_module._LiveBlocked) as blocked:
        runtime_module._official_crosschecks(
            graph=ContractGraph(),
            execution=execution,
            created_at="2026-08-15T01:00:00Z",
        )
    assert blocked.value.issue_codes == (
        "futu_nonprice:critical_financial_field_not_mapped",
    )


@pytest.mark.parametrize(
    ("statement_type", "concept"),
    (
        ("balance_sheet", "cash_and_cash_equivalents"),
        ("balance_sheet", "common_equity"),
        ("balance_sheet", "interest_bearing_debt"),
        ("balance_sheet", "total_assets"),
        ("balance_sheet", "total_liabilities"),
        ("cash_flow", "capital_expenditure_outflow"),
        ("cash_flow", "operating_cash_flow"),
    ),
)
def test_balance_sheet_and_cash_flow_critical_conflicts_block_before_refreeze(
    statement_type: str,
    concept: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import owner_research.owner_equity_runtime as runtime_module

    monkeypatch.setattr(
        runtime_module,
        "load_critical_financial_concepts",
        lambda: {statement_type: (concept,)},
    )
    monkeypatch.setattr(
        runtime_module,
        "load_financial_field_registry",
        lambda: {
            "reviewed-field": FrozenMap(
                {
                    "canonical_concept": concept,
                }
            )
        },
    )
    graph, fact = _official_critical_financial_graph(
        concept,
        flow=statement_type == "cash_flow",
    )
    vendor_fingerprint = canonical_sha256({"vendor": concept})
    vendor = SimpleNamespace(
        source_role="vendor_secondary",
        comparison_eligible=True,
        issuer_id=ISSUER_ID,
        canonical_concept=concept,
        period=fact.period,
        value_type="number",
        value="101",
        unit="currency_units",
        currency="USD",
        observation_id=f"futu-observation:{vendor_fingerprint}",
        fingerprint=vendor_fingerprint,
        data_family="financial_statements",
        field_id="reviewed-field",
        qualifiers=FrozenMap({"statement_type": statement_type}),
    )
    current_shares = SimpleNamespace(
        source_role="vendor_secondary",
        comparison_eligible=False,
        canonical_concept=None,
        data_family="corporate_actions",
        field_id="current_common_shares",
        value_type="null",
        value=None,
        qualifiers=FrozenMap(
            {
                "reason_code": "us_3236_shares_after_effect_not_supported",
                "verification_status": "vendor_not_supported",
            }
        ),
    )
    execution = SimpleNamespace(
        observations=(vendor, current_shares),
        bundle=SimpleNamespace(issuer_id=ISSUER_ID),
    )
    with pytest.raises(runtime_module._LiveBlocked) as blocked:
        runtime_module._official_crosschecks(
            graph=graph,
            execution=execution,
            created_at="2026-08-15T01:00:00Z",
        )
    assert blocked.value.issue_codes == (
        "futu_nonprice:sec_futu_material_conflict",
    )


def test_split_event_set_is_bidirectional_and_ratio_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import owner_research.owner_equity_runtime as runtime_module

    monkeypatch.setattr(runtime_module, "load_critical_financial_concepts", lambda: {})
    monkeypatch.setattr(runtime_module, "load_financial_field_registry", lambda: {})
    result = _execute_pre_price(
        FakeTransport(
            evidence_seed="split-crosscheck",
            split_observation=_wire_split_observation(),
        )
    )
    split = next(
        item for item in result.observations if item.field_id == "stock_split_event"
    )
    current_shares = next(
        item
        for item in result.observations
        if item.field_id == "current_common_shares"
    )

    def execution(*observations: object) -> SimpleNamespace:
        return SimpleNamespace(
            observations=observations,
            bundle=SimpleNamespace(issuer_id=ISSUER_ID),
        )

    graph, _ = _official_split_graph(ratio=4)
    operands, receipts = runtime_module._official_crosschecks(
        graph=graph,
        execution=execution(split, current_shares),
        created_at="2026-08-15T01:00:00Z",
    )
    assert len(operands) == len(receipts) == 1
    assert receipts[0].comparison_rule == (
        "exact_split_ratio_us_announcement_only"
    )
    assert receipts[0].result == "consistent"

    with pytest.raises(runtime_module._LiveBlocked) as vendor_only:
        runtime_module._official_crosschecks(
            graph=ContractGraph(),
            execution=execution(split, current_shares),
            created_at="2026-08-15T01:00:00Z",
        )
    assert vendor_only.value.issue_codes == (
        "futu_nonprice:official_fact_missing_or_ambiguous",
    )

    with pytest.raises(runtime_module._LiveBlocked) as official_only:
        runtime_module._official_crosschecks(
            graph=graph,
            execution=execution(current_shares),
            created_at="2026-08-15T01:00:00Z",
        )
    assert official_only.value.issue_codes == (
        "futu_nonprice:sec_futu_split_event_set_conflict",
    )

    conflict_graph, _ = _official_split_graph(ratio=5)
    with pytest.raises(runtime_module._LiveBlocked) as ratio_conflict:
        runtime_module._official_crosschecks(
            graph=conflict_graph,
            execution=execution(split, current_shares),
            created_at="2026-08-15T01:00:00Z",
        )
    assert ratio_conflict.value.issue_codes == (
        "futu_nonprice:sec_futu_material_conflict",
    )


def test_real_us_split_announcement_only_matches_reviewed_official_event_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import owner_research.owner_equity_runtime as runtime_module

    monkeypatch.setattr(runtime_module, "load_critical_financial_concepts", lambda: {})
    monkeypatch.setattr(runtime_module, "load_financial_field_registry", lambda: {})
    result = _execute_pre_price(
        FakeTransport(
            evidence_seed="us-announcement-only-split",
            split_observation=_wire_split_observation(effective_date=None),
        )
    )
    split = next(
        item for item in result.observations if item.field_id == "stock_split_event"
    )
    current_shares = next(
        item
        for item in result.observations
        if item.field_id == "current_common_shares"
    )
    graph, _ = _official_split_graph(ratio=4)
    execution = SimpleNamespace(
        observations=(split, current_shares),
        bundle=SimpleNamespace(issuer_id=ISSUER_ID),
    )

    operands, receipts = runtime_module._official_crosschecks(
        graph=graph,
        execution=execution,
        created_at="2026-08-15T01:00:00Z",
    )

    assert len(operands) == len(receipts) == 1
    assert receipts[0].comparison_rule == (
        "exact_split_ratio_us_announcement_only"
    )
    assert receipts[0].result == "consistent"


def test_futu_sec_ir_dividend_event_sets_are_bidirectional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import owner_research.owner_equity_runtime as runtime_module

    monkeypatch.setattr(runtime_module, "load_critical_financial_concepts", lambda: {})
    monkeypatch.setattr(runtime_module, "load_financial_field_registry", lambda: {})
    dividend = SimpleNamespace(
        source_role="vendor_secondary",
        comparison_eligible=False,
        canonical_concept=None,
        issuer_id=ISSUER_ID,
        data_family="corporate_actions",
        field_id="dividend_event",
        qualifiers=FrozenMap({"publication_date": "2026-07-30"}),
    )
    current_shares = SimpleNamespace(
        source_role="vendor_secondary",
        comparison_eligible=False,
        canonical_concept=None,
        data_family="corporate_actions",
        field_id="current_common_shares",
        value_type="null",
        value=None,
        qualifiers=FrozenMap(
            {
                "reason_code": "us_3236_shares_after_effect_not_supported",
                "verification_status": "vendor_not_supported",
            }
        ),
    )
    official_event = SimpleNamespace(
        issuer_id=ISSUER_ID,
        event_type="dividend",
        announcement_date="2026-07-30",
    )

    def execution(*observations: object) -> SimpleNamespace:
        return SimpleNamespace(
            observations=observations,
            bundle=SimpleNamespace(issuer_id=ISSUER_ID),
        )

    graph = ContractGraph(capital_allocation_events=(official_event,))
    operands, receipts = runtime_module._official_crosschecks(
        graph=graph,
        execution=execution(dividend, current_shares),
        created_at="2026-08-15T01:00:00Z",
    )
    assert operands == receipts == ()

    with pytest.raises(runtime_module._LiveBlocked) as vendor_only:
        runtime_module._official_crosschecks(
            graph=ContractGraph(),
            execution=execution(dividend, current_shares),
            created_at="2026-08-15T01:00:00Z",
        )
    assert vendor_only.value.issue_codes == (
        "futu_nonprice:sec_futu_dividend_event_set_conflict",
    )

    with pytest.raises(runtime_module._LiveBlocked) as official_only:
        runtime_module._official_crosschecks(
            graph=graph,
            execution=execution(current_shares),
            created_at="2026-08-15T01:00:00Z",
        )
    assert official_only.value.issue_codes == (
        "futu_nonprice:sec_futu_dividend_event_set_conflict",
    )


@pytest.mark.parametrize(
    ("protocol_id", "typed_field_id"),
    (
        (3228, "revenue_breakdown_segment_set"),
        (3234, "dividend_event_set"),
    ),
)
def test_required_3228_3234_empty_semantics_are_typed_and_policy_bound(
    protocol_id: int,
    typed_field_id: str,
) -> None:
    execution = _execute_pre_price(FakeTransport(evidence_seed=f"typed-empty-{protocol_id}"))
    response = next(
        item
        for item in execution.responses
        if next(
            request
            for request in execution.requests
            if request.request_id == item.request_id
        ).protocol_id
        == protocol_id
    )
    observations = tuple(
        item
        for item in execution.observations
        if item.response_fingerprint == response.fingerprint
    )
    assert tuple(item.field_id for item in observations) == (typed_field_id,)
    assert observations[0].qualifiers["reason_code"] == "official_no_data"

    class GenericEmptyTransport(FakeTransport):
        def exchange(
            self,
            request_bytes: bytes,
            *,
            maximum_response_bytes: int,
        ) -> bytes:
            request = json.loads(request_bytes)
            raw = super().exchange(
                request_bytes,
                maximum_response_bytes=maximum_response_bytes,
            )
            if request["protocol"]["id"] != protocol_id:
                return raw
            payload = json.loads(raw)
            payload["data_response"]["observations"] = [
                {
                    "field_id": "availability",
                    "period": {"start": None, "end": None},
                    "qualifiers": {
                        "availability_status": "unavailable",
                        "reason_code": "official_no_data",
                    },
                    "value_type": "null",
                    "value": None,
                    "unit": None,
                    "currency": None,
                    "binary64_hex": None,
                    "exact_binary64_decimal": None,
                }
            ]
            return canonical_json(payload).encode("utf-8")

    blocked = _execute_pre_price(
        GenericEmptyTransport(evidence_seed=f"generic-empty-{protocol_id}")
    )
    assert blocked.bundle.status == "blocked"
    assert blocked.bundle.issues == ("sidecar_response_invalid",)


def _preprice_disposition_fixture() -> tuple[
    FutuSidecarExecution,
    ContractGraph,
    object,
    object,
    tuple[FutuObservationDispositionReceipt, ...],
]:
    execution = _execute_pre_price(FakeTransport(evidence_seed="observation-dispositions"))
    graph, fact = _official_graph()
    vendor = next(
        item
        for item in execution.observations
        if item.canonical_concept == "revenue" and item.period == fact.period
    )
    operand = build_official_evidence_operand(graph=graph, official_object=fact)
    cross_check = crosscheck_vendor_observation(
        graph=graph,
        official=operand,
        vendor=vendor,
        created_at="2026-08-15T01:00:00Z",
    )
    assert cross_check.result == "consistent"
    dispositions = build_futu_observation_dispositions(
        executions=(execution,),
        cross_checks=(cross_check,),
        created_at="2026-08-15T01:00:00Z",
    )
    return execution, graph, operand, cross_check, dispositions


def test_every_preprice_vendor_observation_has_crosscheck_or_typed_disposition() -> None:
    execution, _graph, _operand, cross_check, dispositions = (
        _preprice_disposition_fixture()
    )
    vendor_ids = {
        item.observation_id
        for item in execution.observations
        if item.source_role == "vendor_secondary"
    }
    crosschecked_ids = {cross_check.vendor_observation_id}
    disposition_ids = {item.vendor_observation_id for item in dispositions}
    assert not crosschecked_ids.intersection(disposition_ids)
    assert crosschecked_ids.union(disposition_ids) == vendor_ids
    unknown = next(
        item
        for item in dispositions
        if item.data_family == "financial_statements" and item.field_id == "900001"
    )
    assert unknown.status == "not_applicable"
    assert unknown.reason_code == "unknown_noncritical_statement_field"
    assert any(
        item.field_id == "revenue_breakdown_segment_set"
        and item.status == "unavailable"
        for item in dispositions
    )
    assert any(
        item.field_id == "dividend_event_set" and item.status == "unavailable"
        for item in dispositions
    )

    with pytest.raises(
        FutuSessionEvidenceError,
        match="comparison-eligible vendor observation lacks an exact cross-check",
    ):
        build_futu_observation_dispositions(
            executions=(execution,),
            cross_checks=(),
            created_at="2026-08-15T01:00:00Z",
        )


def test_disposition_rebind_to_other_observation_or_response_is_rejected() -> None:
    import owner_research.futu_session as session_module

    execution, graph, operand, cross_check, dispositions = (
        _preprice_disposition_fixture()
    )
    first, second = dispositions[:2]
    values = first.to_dict()
    values.pop("receipt_id")
    values.pop("receipt_fingerprint")
    values.update(
        {
            "vendor_observation_id": second.vendor_observation_id,
            "vendor_observation_fingerprint": second.vendor_observation_fingerprint,
            "protocol_id": second.protocol_id,
            "data_family": second.data_family,
            "field_id": second.field_id,
            "status": second.status,
            "reason_code": second.reason_code,
        }
    )
    receipt_id, receipt_fingerprint = content_identity(
        "futu-observation-disposition:",
        values,
        object_id_field="receipt_id",
        fingerprint_field="receipt_fingerprint",
    )
    rebound = FutuObservationDispositionReceipt(
        receipt_id=receipt_id,
        receipt_fingerprint=receipt_fingerprint,
        **values,
    )
    rebound_set = (rebound, *dispositions[1:])
    with pytest.raises(
        FutuSessionEvidenceError,
        match="cross-check or disposition coverage|dispositions no longer replay",
    ):
        session_module._validate_graph_crosschecks(
            graph=graph,
            graph_fingerprint=contract_graph_fingerprint(graph),
            executions=(execution,),
            official_operands=(operand,),
            cross_checks=(cross_check,),
            observation_dispositions=rebound_set,
            disposition_created_at="2026-08-15T01:00:00Z",
        )


def test_current_common_shares_vendor_status_cannot_be_rebound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import owner_research.owner_equity_runtime as runtime_module

    monkeypatch.setattr(runtime_module, "load_critical_financial_concepts", lambda: {})
    monkeypatch.setattr(runtime_module, "load_financial_field_registry", lambda: {})
    result = _execute_pre_price(FakeTransport(evidence_seed="shares-disposition"))
    marker = next(
        item
        for item in result.observations
        if item.field_id == "current_common_shares"
    )
    rebound = SimpleNamespace(
        **{
            field: getattr(marker, field)
            for field in (
                "source_role",
                "comparison_eligible",
                "canonical_concept",
                "data_family",
                "field_id",
                "value_type",
                "value",
            )
        },
        qualifiers=FrozenMap({"verification_status": "verified"}),
    )
    execution = SimpleNamespace(
        observations=(rebound,),
        bundle=SimpleNamespace(issuer_id=ISSUER_ID),
    )
    with pytest.raises(runtime_module._LiveBlocked) as blocked:
        runtime_module._official_crosschecks(
            graph=ContractGraph(),
            execution=execution,
            created_at="2026-08-15T01:00:00Z",
        )
    assert blocked.value.issue_codes == (
        "futu_nonprice:current_common_shares_identity_conflict",
    )


def test_signed_pre_price_plan_rejects_missing_reordered_and_typed_statement_drift() -> None:
    authorities, _, _ = _authorities(request_plan_profile="pre_price")
    runtime_authorization = authorities.runtime_authorization
    assert runtime_authorization is not None
    session = object.__new__(AttestedFutuSidecarSession)
    session.runtime_authorization = runtime_authorization
    session._plan_page_index = 0

    def parameters(statement_type: object) -> dict[str, object]:
        return {
            "statement_type": statement_type,
            "financial_type": 7,
            "currency_code": "USD",
            "num": 10,
        }

    for plan_position, statement_type in zip((2, 3, 4), (1, 2, 3), strict=True):
        session._plan_position = plan_position
        assert session._match_request_plan(
            security_code="US.AAPL",
            protocol_id=3227,
            parameters=parameters(statement_type),
            page_index=0,
            page_key=None,
        ) == (plan_position, 0)

    for plan_position, statement_type in ((2, 2), (3, 3), (2, True), (2, "1")):
        session._plan_position = plan_position
        with pytest.raises(FutuSidecarError, match="absent or reordered"):
            session._match_request_plan(
                security_code="US.AAPL",
                protocol_id=3227,
                parameters=parameters(statement_type),
                page_index=0,
                page_key=None,
            )


def test_optional_operating_metrics_no_data_is_typed_unavailable_not_comparable() -> None:
    decision, security, supply, runtime_authorization = _decision(
        stage="valuation_pre_price_verification"
    )
    result = execute_futu_plan(
        transport=FakeTransport(evidence_seed="optional-no-data"),
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=(
            *_pre_price_specs(),
            FutuRequestSpec(
                "valuation_pre_price_verification",
                3246,
                FrozenMap({"num": 50, "currency_code": "USD"}),
            ),
        ),
    )
    marker = next(item for item in result.observations if item.field_id == "availability")
    assert result.bundle.status == "complete"
    assert marker.value_type == "null"
    assert marker.value is None
    assert marker.comparison_eligible is False
    assert marker.canonical_concept is None
    assert marker.qualifiers == FrozenMap(
        {
            "availability_status": "unavailable",
            "reason_code": "official_no_data",
        }
    )


def test_daily_close_is_gated_then_adapted_only_at_explicit_boundary() -> None:
    decision, security, supply, runtime_authorization = _decision()
    result = _execute_market(
        FakeTransport(),
        decision=decision,
        security=security,
        supply=supply,
        runtime_authorization=runtime_authorization,
    )
    assert result.bundle.status == "complete"
    close = next(item for item in result.observations if item.field_id == "close")
    assert close.canonical_concept == "futu_unadjusted_daily_close_candidate"
    request = result.requests[0]
    assert request.parameters["session"] == "RTH"
    adapted = adapt_futu_daily_close_to_market_reference(
        authority=decision,
        request=request,
        response=result.responses[0],
        observation=close,
    )
    assert adapted.market_reference_basis == "official_unadjusted_close"
    assert adapted.semantics_evidence_fingerprint == HASH_F


def test_daily_close_without_pinned_semantics_proof_blocks_before_transport() -> None:
    decision, security, supply, runtime_authorization = _decision(
        valid_daily_close_semantics=False
    )
    assert decision.status == "eligible"
    transport = NoCallTransport()
    result = _execute_market(
        transport,
        decision=decision,
        security=security,
        supply=supply,
        runtime_authorization=runtime_authorization,
    )
    assert result.bundle.status == "blocked"
    assert result.bundle.issues == ("daily_close_semantics_unproven",)
    assert transport.calls == 0


def test_peer_quote_plan_is_exact_static_then_daily_close_and_uses_peer_scope() -> None:
    decision, security, supply, runtime_authorization = _decision(
        stage="peer_comparable_reference"
    )
    transport = FakeTransport(evidence_seed="peer-scope")
    result = execute_futu_plan(
        transport=transport,
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="peer_comparable_reference",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_peer_specs(HASH_F),
    )
    assert result.bundle.status == "complete"
    assert [item["protocol"]["id"] for item in transport.calls] == [3202, 3103]
    prices = [item for item in result.observations if item.data_family == "market_price"]
    assert prices
    assert all(item.use_scope == "peer_comparable_reference" for item in prices)


def test_unix_socket_transport_sends_exactly_one_bounded_frame(tmp_path: Path) -> None:
    suffix = hashlib.sha256(os.fsencode(tmp_path)).hexdigest()[:12]
    socket_directory = Path("/private/tmp") / f"futu-test-{suffix}"
    socket_directory.mkdir(mode=0o700)
    socket_path = socket_directory / "sidecar.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(socket_path))
    socket_path.chmod(0o600)
    listener.listen(1)
    request = canonical_json({"command": "bounded-test", "nonce": HASH_A}).encode()
    response = canonical_json({"status": "ok"}).encode()
    captured: dict[str, bytes] = {}
    server_errors: list[BaseException] = []

    def serve_one_frame() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                header = _socket_recv_exact(connection, 4)
                payload_size = struct.unpack(">I", header)[0]
                captured["payload"] = _socket_recv_exact(connection, payload_size)
                connection.settimeout(0.05)
                try:
                    captured["trailing"] = connection.recv(1)
                except TimeoutError:
                    captured["trailing"] = b""
                connection.sendall(struct.pack(">I", len(response)))
                connection.sendall(response)
        except BaseException as exc:  # pragma: no cover - asserted in caller thread
            server_errors.append(exc)
        finally:
            listener.close()

    server = threading.Thread(target=serve_one_frame, daemon=True)
    server.start()
    transport = UnixSocketFutuSidecarTransport(
        socket_path=socket_path,
        expected_uid=os.getuid(),
        timeout_seconds=1,
    )
    assert transport.exchange(request, maximum_response_bytes=1024) == response
    server.join(timeout=1)
    assert not server.is_alive()
    assert server_errors == []
    assert captured == {"payload": request, "trailing": b""}
    socket_path.unlink()
    socket_directory.rmdir()


def _socket_recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise AssertionError("test server received an incomplete frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def test_attested_uds_open_and_abort_are_signed_bound_and_exact_once(
    tmp_path: Path,
) -> None:
    authorities, _, supply = _authorities()
    runtime_authorization = authorities.runtime_authorization
    assert runtime_authorization is not None
    suffix = hashlib.sha256(f"attested:{tmp_path}".encode()).hexdigest()[:12]
    socket_directory = Path("/private/tmp") / f"futu-attested-{suffix}"
    socket_directory.mkdir(mode=0o700)
    socket_path = socket_directory / "sidecar.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(socket_path))
    socket_path.chmod(0o600)
    listener.listen(2)
    calls: list[dict[str, Any]] = []
    server_errors: list[BaseException] = []

    def receive(connection: socket.socket) -> dict[str, Any]:
        size = struct.unpack(">I", _socket_recv_exact(connection, 4))[0]
        return json.loads(_socket_recv_exact(connection, size))

    def send(connection: socket.socket, payload: dict[str, Any]) -> None:
        raw = canonical_json(payload).encode("utf-8")
        connection.sendall(struct.pack(">I", len(raw)))
        connection.sendall(raw)

    def serve_open_then_abort() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                request = receive(connection)
                calls.append(request)
                assert set(request) == {
                    "wire_schema_version",
                    "command",
                    "run_id",
                    "challenge_nonce",
                    "expected_supply_attestation",
                    "expected_runtime_authorization_fingerprint",
                    "expected_authorized_security_codes",
                    "expected_request_plan",
                    "expected_request_plan_fingerprint",
                    "expected_maximum_planned_requests",
                    "expected_maximum_pages_per_protocol",
                    "expected_signer_key_id",
                }
                assert request["expected_runtime_authorization_fingerprint"] == (
                    runtime_authorization.fingerprint
                )
                startup = {
                    "checkpoint": "startup",
                    "protocol_id": 1002,
                    "serial_number": 1,
                    "global_state_request_fingerprint": HASH_D,
                    "global_state_response_fingerprint": HASH_E,
                        "observed_at": "2026-08-15T00:57:00Z",
                        "qot_logined": True,
                        "trd_logined": False,
                        "opend_server_version": supply.opend_server_version,
                        "opend_server_build_no": supply.opend_server_build_no,
                    }
                session_id = canonical_sha256(
                    {
                        "domain": "owner-research-futu-session-v1",
                        "run_id": RUN_ID,
                        "challenge_nonce": request["challenge_nonce"],
                        "boot_nonce": HASH_B,
                        "supply_attestation": request["expected_supply_attestation"],
                        "runtime_authorization_fingerprint": (
                            runtime_authorization.fingerprint
                        ),
                        "request_plan_fingerprint": (
                            runtime_authorization.request_plan_fingerprint
                        ),
                        "startup_checkpoint": startup,
                        "signer_public_key_hex": HASH_C,
                    }
                )
                boot = _signed_payload(
                    "futu-sidecar-boot:",
                    {
                        "schema_version": FUTU_SCHEMA_VERSION,
                        "receipt_kind": "futu-sidecar-boot-attestation",
                        "run_id": RUN_ID,
                        "session_id": session_id,
                        "challenge_nonce": request["challenge_nonce"],
                        "boot_nonce": HASH_B,
                        "supply_attestation": request["expected_supply_attestation"],
                        "runtime_authorization_fingerprint": (
                            runtime_authorization.fingerprint
                        ),
                        "request_plan_fingerprint": (
                            runtime_authorization.request_plan_fingerprint
                        ),
                        "startup_checkpoint": startup,
                        "signer_public_key_hex": HASH_C,
                        "issued_at": "2026-08-15T00:57:01Z",
                    },
                )
                send(
                    connection,
                    {
                        "wire_schema_version": WIRE_SCHEMA_VERSION,
                        "command": "open_quote_only_session",
                        "run_id": RUN_ID,
                        "session_id": session_id,
                        "boot_attestation": boot,
                    },
                )
            connection, _ = listener.accept()
            with connection:
                request = receive(connection)
                calls.append(request)
                assert request == {
                    "wire_schema_version": WIRE_SCHEMA_VERSION,
                    "command": "abort_quote_only_session",
                    "run_id": RUN_ID,
                    "session_id": session_id,
                    "boot_receipt_id": boot["receipt_id"],
                    "sequence": 1,
                    "reason_code": "caller_abort",
                }
                abort = _signed_payload(
                    "futu-sidecar-abort:",
                    {
                        "schema_version": FUTU_SCHEMA_VERSION,
                        "receipt_kind": "futu-sidecar-abort",
                        "run_id": RUN_ID,
                        "session_id": session_id,
                        "boot_receipt_id": boot["receipt_id"],
                        "sequence": 1,
                        "reason_code": "caller_abort",
                        "issued_at": "2026-08-15T00:57:02Z",
                    },
                )
                send(
                    connection,
                    {
                        "wire_schema_version": WIRE_SCHEMA_VERSION,
                        "command": "abort_quote_only_session",
                        "run_id": RUN_ID,
                        "session_id": session_id,
                        "sequence": 1,
                        "abort_attestation": abort,
                    },
                )
        except BaseException as exc:  # pragma: no cover - asserted by caller
            server_errors.append(exc)
        finally:
            listener.close()

    server = threading.Thread(target=serve_open_then_abort, daemon=True)
    server.start()
    session = AttestedFutuSidecarSession.open(
        socket_path=socket_path,
        expected_uid=os.getuid(),
        timeout_seconds=1,
        run_id=RUN_ID,
        supply_chain=supply,
        runtime_authorization=runtime_authorization,
        verifier=DeterministicVerifier(),
        expected_signer_key_id="test-key",
    )
    first = session.abort()
    assert session.abort() is first
    assert first.reason_code == "caller_abort"
    with pytest.raises(FutuSidecarError, match="another reason"):
        session.abort("host_failure")
    server.join(timeout=1)
    assert not server.is_alive()
    assert server_errors == []
    assert [item["command"] for item in calls] == [
        "open_quote_only_session",
        "abort_quote_only_session",
    ]
    socket_path.unlink()
    socket_directory.rmdir()


@pytest.mark.parametrize(
    ("tamper", "error"),
    (
        ("session", "replayed or reordered"),
        ("sequence", "replayed or reordered"),
        ("boot", "replayed or reordered"),
        ("signature", "signature verification failed"),
    ),
)
def test_attested_fetch_rejects_signed_session_sequence_and_signature_rebinding(
    tamper: str,
    error: str,
) -> None:
    decision, security, supply, runtime_authorization = _decision()
    authority_set, _, _ = _authorities(request_plan_profile="market")
    live_authority = replace(authority_set, runtime=None)
    expected = _execute_market(
        FakeTransport(evidence_seed="signed-fetch-bootstrap"),
        decision=decision,
        security=security,
        supply=supply,
        runtime_authorization=runtime_authorization,
    )
    runtime = _completed_runtime_receipt(
        live_authority,
        responses=expected.responses,
        ended_at="2026-08-15T01:00:05Z",
    )
    finalization = build_futu_attested_finalization_fixture(
        executions=(expected,),
        runtime_receipt=runtime,
        supply_chain=supply,
        runtime_authorization=runtime_authorization,
        verifier=DeterministicVerifier(),
    )

    class SignedFetchTransport:
        def exchange(self, request_bytes: bytes, *, maximum_response_bytes: int) -> bytes:
            assert maximum_response_bytes == MAXIMUM_RAW_BYTES_PER_RESPONSE
            request = json.loads(request_bytes)
            session_id = request["session_id"]
            sequence = request["sequence"]
            boot_receipt_id = request["boot_receipt_id"]
            if tamper == "session":
                session_id = HASH_A
            elif tamper == "sequence":
                sequence += 1
            elif tamper == "boot":
                boot_receipt_id = f"futu-sidecar-boot:{HASH_A}"
            response = _signed_wire_payload(
                {
                    "wire_schema_version": WIRE_SCHEMA_VERSION,
                    "command": "fetch_quote_data_with_global_state_guards",
                    "run_id": RUN_ID,
                    "request_id": request["request_id"],
                    "request_fingerprint": request["request_fingerprint"],
                    "protocol_id": 3103,
                    "page_index": 0,
                    "supply_attestation": request["expected_supply_attestation"],
                    "pre_global_state": {},
                    "data_response": {},
                    "post_global_state": {},
                    "session_id": session_id,
                    "sequence": sequence,
                    "boot_receipt_id": boot_receipt_id,
                }
            )
            if tamper == "signature":
                response["signature_hex"] = "0" * 128
            return canonical_json(response).encode("utf-8")

    session = AttestedFutuSidecarSession(
        transport=SignedFetchTransport(),  # type: ignore[arg-type]
        run_id=RUN_ID,
        supply_chain=supply,
        runtime_authorization=runtime_authorization,
        verifier=DeterministicVerifier(),
        expected_signer_key_id="test-key",
        boot_attestation=finalization.boot_attestation,
    )
    request = canonical_json(
        {
            "wire_schema_version": WIRE_SCHEMA_VERSION,
            "command": "fetch_quote_data_with_global_state_guards",
            "run_id": RUN_ID,
            "request_id": f"futu-request:{HASH_A}",
            "request_fingerprint": HASH_B,
            "protocol": {"id": 3103, "name": "Qot_RequestHistoryKL"},
            "security": {
                "market": "US",
                "code": "US.AAPL",
                "security_id": security.vendor_security_id,
            },
            "parameters": to_json_value(_daily_close_spec().parameters),
            "page_index": 0,
            "page_key": None,
            "expected_supply_attestation": finalization.boot_attestation.receipt[
                "supply_attestation"
            ],
            "global_state_guards": {},
        }
    ).encode("utf-8")
    with pytest.raises(FutuSidecarError, match=error):
        session.exchange(
            request,
            maximum_response_bytes=MAXIMUM_RAW_BYTES_PER_RESPONSE,
        )
    assert session.sequence == 0


@pytest.mark.parametrize(
    ("mutation", "error"),
    (
        ("security_code", "absent or reordered"),
        ("extra_protocol", "absent or reordered"),
        ("parameters", "absent or reordered"),
        ("page", "replayed or reordered"),
    ),
)
def test_attested_host_rejects_same_uid_request_plan_escape_before_transport(
    mutation: str,
    error: str,
) -> None:
    decision, security, supply, runtime_authorization = _decision()
    authority_set, _, _ = _authorities(request_plan_profile="market")
    expected = _execute_market(
        FakeTransport(evidence_seed="request-plan-bootstrap"),
        decision=decision,
        security=security,
        supply=supply,
        runtime_authorization=runtime_authorization,
    )
    runtime = _completed_runtime_receipt(
        replace(authority_set, runtime=None),
        responses=expected.responses,
        ended_at="2026-08-15T01:00:05Z",
    )
    finalization = build_futu_attested_finalization_fixture(
        executions=(expected,),
        runtime_receipt=runtime,
        supply_chain=supply,
        runtime_authorization=runtime_authorization,
        verifier=DeterministicVerifier(),
    )
    transport = NoCallTransport()
    session = AttestedFutuSidecarSession(
        transport=transport,  # type: ignore[arg-type]
        run_id=RUN_ID,
        supply_chain=supply,
        runtime_authorization=runtime_authorization,
        verifier=DeterministicVerifier(),
        expected_signer_key_id="test-key",
        boot_attestation=finalization.boot_attestation,
    )
    request = expected.requests[0]
    wire = {
        "wire_schema_version": WIRE_SCHEMA_VERSION,
        "command": "fetch_quote_data_with_global_state_guards",
        "run_id": RUN_ID,
        "request_id": request.request_id,
        "request_fingerprint": request.fingerprint,
        "protocol": {"id": request.protocol_id, "name": request.protocol_name},
        "security": {
            "market": "US",
            "code": "US.AAPL",
            "security_id": security.vendor_security_id,
        },
        "parameters": to_json_value(request.parameters),
        "page_index": 0,
        "page_key": None,
        "expected_supply_attestation": finalization.boot_attestation.receipt[
            "supply_attestation"
        ],
        "global_state_guards": {},
    }
    if mutation == "security_code":
        wire["security"]["code"] = "US.MSFT"
    elif mutation == "extra_protocol":
        wire["protocol"] = {"id": 3202, "name": "Qot_GetStaticInfo"}
    elif mutation == "parameters":
        wire["parameters"]["start"] = "2026-08-13"
    else:
        wire["page_index"] = 1
        wire["page_key"] = "unexpected-page"
    with pytest.raises(FutuSidecarError, match=error):
        session.exchange(
            canonical_json(wire).encode("utf-8"),
            maximum_response_bytes=MAXIMUM_RAW_BYTES_PER_RESPONSE,
        )
    assert transport.calls == 0
    with pytest.raises(FutuSidecarError, match="current state"):
        session.finalize(expected_executions=(expected,))


def test_attested_open_rejects_attestor_key_not_bound_by_signed_runtime_authority(
    tmp_path: Path,
) -> None:
    authorities, _, supply = _authorities(request_plan_profile="market")
    runtime_authorization = authorities.runtime_authorization
    assert runtime_authorization is not None
    with pytest.raises(FutuSidecarError, match="open authority"):
        AttestedFutuSidecarSession.open(
            socket_path=tmp_path / "missing.sock",
            expected_uid=os.getuid(),
            timeout_seconds=1,
            run_id=RUN_ID,
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            verifier=DeterministicVerifier(),
            expected_signer_key_id="another-role-key",
        )


def test_attested_finalize_closes_session_and_cannot_be_rebound_to_abort() -> None:
    decision, security, supply, runtime_authorization = _decision()
    authority_set, _, _ = _authorities(request_plan_profile="market")
    live_authority = replace(authority_set, runtime=None)
    expected = _execute_market(
        FakeTransport(evidence_seed="signed-finalize-bootstrap"),
        decision=decision,
        security=security,
        supply=supply,
        runtime_authorization=runtime_authorization,
    )
    runtime = _completed_runtime_receipt(
        live_authority,
        responses=expected.responses,
        ended_at="2026-08-15T01:00:05Z",
    )
    signed_finalization = build_futu_attested_finalization_fixture(
        executions=(expected,),
        runtime_receipt=runtime,
        supply_chain=supply,
        runtime_authorization=runtime_authorization,
        verifier=DeterministicVerifier(),
    )

    class FinalizingTransport:
        def exchange(self, request_bytes: bytes, *, maximum_response_bytes: int) -> bytes:
            assert maximum_response_bytes == MAXIMUM_RAW_BYTES_PER_RESPONSE
            request = json.loads(request_bytes)
            if request["command"] == "fetch_quote_data_with_global_state_guards":
                response = _signed_wire_payload(
                    {
                        "wire_schema_version": WIRE_SCHEMA_VERSION,
                        "command": request["command"],
                        "run_id": RUN_ID,
                        "request_id": request["request_id"],
                        "request_fingerprint": request["request_fingerprint"],
                        "protocol_id": 3103,
                        "page_index": 0,
                        "supply_attestation": request["expected_supply_attestation"],
                        "pre_global_state": {},
                        "data_response": {"terminal": True},
                        "post_global_state": {},
                        "session_id": request["session_id"],
                        "sequence": request["sequence"],
                        "boot_receipt_id": request["boot_receipt_id"],
                    }
                )
            else:
                assert request["command"] == "finalize_quote_only_session"
                response = {
                    "wire_schema_version": WIRE_SCHEMA_VERSION,
                    "command": request["command"],
                    "run_id": RUN_ID,
                    "session_id": request["session_id"],
                    "sequence": request["sequence"],
                    "runtime_isolation_receipt": (
                        signed_finalization.runtime_receipt.to_dict()
                    ),
                    "execution_attestation_receipt": (
                        signed_finalization.execution_attestation.to_dict()
                    ),
                }
            return canonical_json(response).encode("utf-8")

    session = AttestedFutuSidecarSession(
        transport=FinalizingTransport(),  # type: ignore[arg-type]
        run_id=RUN_ID,
        supply_chain=supply,
        runtime_authorization=runtime_authorization,
        verifier=DeterministicVerifier(),
        expected_signer_key_id="test-key",
        boot_attestation=signed_finalization.boot_attestation,
    )
    request = expected.requests[0]
    session.exchange(
        canonical_json(
            {
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "command": "fetch_quote_data_with_global_state_guards",
                "run_id": RUN_ID,
                "request_id": request.request_id,
                "request_fingerprint": request.fingerprint,
                "protocol": {"id": request.protocol_id, "name": request.protocol_name},
                "security": {
                    "market": "US",
                    "code": "US.AAPL",
                    "security_id": security.vendor_security_id,
                },
                "parameters": to_json_value(request.parameters),
                "page_index": request.page_index,
                "page_key": None,
                "expected_supply_attestation": (
                    signed_finalization.boot_attestation.receipt["supply_attestation"]
                ),
                "global_state_guards": {},
            }
        ).encode("utf-8"),
        maximum_response_bytes=MAXIMUM_RAW_BYTES_PER_RESPONSE,
    )
    with pytest.raises(FutuSidecarError, match="exceeds the signed request plan"):
        session.exchange(
            canonical_json(
                {
                    "wire_schema_version": WIRE_SCHEMA_VERSION,
                    "command": "fetch_quote_data_with_global_state_guards",
                    "run_id": RUN_ID,
                    "request_id": request.request_id,
                    "request_fingerprint": request.fingerprint,
                    "protocol": {
                        "id": request.protocol_id,
                        "name": request.protocol_name,
                    },
                    "security": {
                        "market": "US",
                        "code": "US.AAPL",
                        "security_id": security.vendor_security_id,
                    },
                    "parameters": to_json_value(request.parameters),
                    "page_index": request.page_index,
                    "page_key": None,
                    "expected_supply_attestation": (
                        signed_finalization.boot_attestation.receipt[
                            "supply_attestation"
                        ]
                    ),
                    "global_state_guards": {},
                }
            ).encode("utf-8"),
            maximum_response_bytes=MAXIMUM_RAW_BYTES_PER_RESPONSE,
        )
    completed = session.finalize(expected_executions=(expected,))
    assert completed == signed_finalization
    with pytest.raises(FutuSidecarError, match="cannot be aborted"):
        session.abort()
    with pytest.raises(FutuSidecarError, match="cannot be finalized"):
        session.finalize(expected_executions=(expected,))


def test_live_global_state_guards_quarantine_trade_transition() -> None:
    result = _execute_market(FakeTransport(trd_logined=True))
    assert result.bundle.status == "quarantined"
    assert "trade_login_true" in result.bundle.issues
    assert result.responses == ()


def test_live_global_state_binding_tamper_is_blocked() -> None:
    result = _execute_market(FakeTransport(tamper_global_binding=True))
    assert result.bundle.status == "blocked"
    assert "sidecar_response_invalid" in result.bundle.issues


def test_sidecar_supply_attestation_must_replay_the_signed_sdk_identity() -> None:
    result = _execute_market(FakeTransport(tamper_supply_attestation=True))
    assert result.bundle.status == "blocked"
    assert result.bundle.issues == ("sidecar_response_invalid",)


def test_resigned_supply_and_echoed_attestation_cannot_rebind_live_authority() -> None:
    decision, security, supply, runtime_authorization = _decision()
    values = supply.to_dict()
    for field in ("receipt_id", "signature_hex"):
        values.pop(field)
    values.update(
        {
            "provider_version": "1.0.1",
            "protocol_descriptor_sha256": HASH_A,
            "facade_sha256": HASH_B,
            "adapter_sha256": HASH_C,
            "parser_sha256": HASH_D,
        }
    )
    rebound_supply = _signed(FutuSupplyChainReceipt, "futu-supply:", values)
    transport = FakeTransport()
    result = _execute_market(
        transport,
        decision=decision,
        security=security,
        supply=rebound_supply,
        runtime_authorization=runtime_authorization,
    )
    assert result.bundle.status == "blocked"
    assert result.bundle.issues == ("supply_chain_mismatch",)
    assert transport.calls == []


def test_noncanonical_and_oversized_sidecar_responses_are_blocked() -> None:
    noncanonical = _execute_market(FakeTransport(canonical=False))
    oversized = _execute_market(OversizedTransport())
    assert noncanonical.bundle.status == "blocked"
    assert oversized.bundle.status == "blocked"
    assert noncanonical.bundle.issues == ("sidecar_response_invalid",)
    assert oversized.bundle.issues == ("sidecar_response_invalid",)


def test_sidecar_rejects_derived_json_masquerading_as_raw_opend_frame() -> None:
    result = _execute_market(FakeTransport(raw_evidence_kind="sdk_dataframe_json"))
    assert result.bundle.status == "blocked"
    assert result.bundle.issues == ("sidecar_response_invalid",)


def test_revenue_breakdown_rejects_pagination_not_supported_by_official_sdk() -> None:
    decision, security, supply, runtime_authorization = _decision(
        stage="valuation_pre_price_verification"
    )
    transport = FakeTransport(
        next_key="forbidden",
        terminal=False,
        pagination_protocol_id=3228,
    )
    result = execute_futu_plan(
        transport=transport,
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_pre_price_specs(),
    )
    assert result.bundle.status == "blocked"
    assert result.bundle.issues == ("sidecar_response_invalid",)
    assert [item["protocol"]["id"] for item in transport.calls] == [
        3104,
        3202,
        3227,
        3227,
        3227,
        3228,
    ]


def test_pagination_loop_is_detected_without_retry_or_mutable_latest_cache() -> None:
    decision, security, supply, runtime_authorization = _decision(
        stage="valuation_pre_price_verification"
    )
    transport = FakeTransport(
        next_key="opaque-page-key",
        terminal=False,
        pagination_protocol_id=3236,
    )
    result = execute_futu_plan(
        transport=transport,
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_pre_price_specs(),
    )
    assert result.bundle.status == "blocked"
    assert "pagination_loop" in result.bundle.issues
    assert [item["protocol"]["id"] for item in transport.calls] == [
        3104,
        3202,
        3227,
        3227,
        3227,
        3228,
        3234,
        3236,
        3236,
    ]
    split_requests = tuple(item for item in result.requests if item.protocol_id == 3236)
    assert split_requests[1].previous_page_key_sha256 == hashlib.sha256(
        b"opaque-page-key"
    ).hexdigest()
    assert "opaque-page-key" not in canonical_json(result.bundle.to_dict())


def test_wire_and_public_objects_never_contain_credentials_or_raw_payload() -> None:
    transport = FakeTransport()
    result = _execute_market(transport)
    wire = canonical_json(transport.calls[0])
    public = canonical_json(
        {
            "bundle": result.bundle.to_dict(),
            "requests": [item.to_dict() for item in result.requests],
            "responses": [item.to_dict() for item in result.responses],
            "observations": [item.to_dict() for item in result.observations],
        }
    )
    for forbidden in ("password", "credential", "private_key", "raw_payload", "order_id"):
        assert forbidden not in wire.lower()
        assert forbidden not in public.lower()
    response = result.responses[0]
    assert response.cas_locator == f"cas://sha256/{response.encrypted_object_sha256}"
    assert response.raw_plaintext_sha256 != response.encrypted_object_sha256


def test_protocol_and_post_freeze_routing_are_fail_closed() -> None:
    with pytest.raises(FutuSidecarError, match="cannot request"):
        FutuRequestSpec("post_valuation_context", 3237, FrozenMap({}), HASH_F)
    with pytest.raises(FutuSidecarError, match="price-blind freeze"):
        FutuRequestSpec("post_valuation_context", 3229, FrozenMap({}))
    exact_rth = {
        "start": "2026-08-14",
        "end": "2026-08-14",
        "ktype": "K_DAY",
        "autype": "NONE",
        "fields": ["CLOSE", "VOLUME"],
        "max_count": 1,
        "extended_time": False,
        "session": "RTH",
    }
    FutuRequestSpec(
        "market_reference",
        3103,
        FrozenMap(exact_rth),
        "2026-08-14",
    )
    with pytest.raises(FutuSidecarError, match="Session.RTH"):
        FutuRequestSpec(
            "market_reference",
            3103,
            FrozenMap({**exact_rth, "session": "ALL"}),
            "2026-08-14",
        )


def test_sdk_parameter_surface_rejects_documentation_and_fixture_drift() -> None:
    annual_financials = {
        "statement_type": 1,
        "financial_type": 7,
        "currency_code": "USD",
        "num": 10,
    }
    for statement_type in (1, 2, 3):
        FutuRequestSpec(
            "valuation_pre_price_verification",
            3227,
            FrozenMap({**annual_financials, "statement_type": statement_type}),
        )
    for invalid_statement_type in (True, "1", 0, 5):
        with pytest.raises(FutuSidecarError, match="statement_type"):
            FutuRequestSpec(
                "valuation_pre_price_verification",
                3227,
                FrozenMap(
                    {**annual_financials, "statement_type": invalid_statement_type}
                ),
            )
    for unsupported_financial_type in (0, 1, 2, 3, 4, 5, 6, 9, 10, 11):
        with pytest.raises(FutuSidecarError, match="ANNUAL selector 7"):
            FutuRequestSpec(
                "valuation_pre_price_verification",
                3227,
                FrozenMap(
                    {
                        **annual_financials,
                        "financial_type": unsupported_financial_type,
                    }
                ),
            )
    FutuRequestSpec(
        "valuation_pre_price_verification",
        3228,
        FrozenMap({"date": 0, "financial_type": 7, "currency_code": "USD"}),
    )
    with pytest.raises(FutuSidecarError, match="unrecognized"):
        FutuRequestSpec(
            "valuation_pre_price_verification",
            3228,
            FrozenMap({"financial_type": 7, "currency_code": "USD", "num": 10}),
        )
    FutuRequestSpec("valuation_pre_price_verification", 3244, FrozenMap({}))
    with pytest.raises(FutuSidecarError, match="unrecognized"):
        FutuRequestSpec(
            "valuation_pre_price_verification", 3244, FrozenMap({"num": 10})
        )
    FutuRequestSpec(
        "valuation_pre_price_verification",
        3245,
        FrozenMap({"leader_name": "Named Executive"}),
    )
    with pytest.raises(FutuSidecarError, match="unrecognized"):
        FutuRequestSpec(
            "valuation_pre_price_verification",
            3245,
            FrozenMap({"executive_id": "executive:test"}),
        )
    FutuRequestSpec(
        "valuation_pre_price_verification",
        3246,
        FrozenMap({"num": 50, "currency_code": "USD"}),
    )
    with pytest.raises(FutuSidecarError, match="unrecognized"):
        FutuRequestSpec(
            "valuation_pre_price_verification",
            3246,
            FrozenMap(
                {
                    "financial_type": 7,
                    "num": 50,
                    "currency_code": "USD",
                }
            ),
        )


def test_execution_and_receipts_are_deterministic_for_identical_replay() -> None:
    decision, security, supply, _ = _decision()
    first = _execute_market(FakeTransport())
    second = _execute_market(FakeTransport())
    assert first.bundle.to_dict() == second.bundle.to_dict()
    assert [item.to_dict() for item in first.requests] == [
        item.to_dict() for item in second.requests
    ]
    assert [item.to_dict() for item in first.responses] == [
        item.to_dict() for item in second.responses
    ]
    validate_futu_execution_replay(
        first,
        authority=decision,
        security_identity=security,
        supply_chain=supply,
    )


def test_replay_rejects_coordinated_bundle_object_rebinding() -> None:
    decision, security, supply, runtime_authorization = _decision()
    valid = _execute_market(
        FakeTransport(),
        decision=decision,
        security=security,
        supply=supply,
        runtime_authorization=runtime_authorization,
    )
    foreign_decision, foreign_security, foreign_supply, foreign_runtime_authorization = _decision(
        stage="valuation_pre_price_verification"
    )
    foreign = execute_futu_plan(
        transport=FakeTransport(),
        authority=foreign_decision,
        runtime_authorization=foreign_runtime_authorization,
        security_identity=foreign_security,
        supply_chain=foreign_supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_pre_price_specs(),
    )
    rebound = replace(valid, bundle=foreign.bundle)
    with pytest.raises(FutuSidecarError, match="authority decision|request references"):
        validate_futu_execution_replay(
            rebound,
            authority=decision,
            security_identity=security,
            supply_chain=supply,
        )


def test_schema_rejects_unknown_public_raw_member() -> None:
    result = _execute_market(FakeTransport())
    payload = result.responses[0].to_dict()
    payload["raw_payload"] = "forbidden"
    with pytest.raises(FutuReceiptError, match="raw_payload"):
        validate_futu_payload("futu-data-response-receipt", payload)


def test_crosscheck_never_overwrites_official_evidence() -> None:
    decision, security, supply, runtime_authorization = _decision(
        stage="valuation_pre_price_verification"
    )
    result = execute_futu_plan(
        transport=FakeTransport(),
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_pre_price_specs(),
    )
    vendor = next(item for item in result.observations if item.canonical_concept == "revenue")
    graph, fact = _official_graph()
    official = build_official_evidence_operand(
        graph=graph,
        official_object=fact,
    )
    consistent = crosscheck_vendor_observation(
        graph=graph,
        official=official,
        vendor=vendor,
        created_at="2026-08-15T01:01:00Z",
    )
    assert consistent.result == "consistent"
    assert consistent.materiality == "kernel_required"
    assert consistent.vendor_may_overwrite is False

    conflict_result = execute_futu_plan(
        transport=FakeTransport(financial_value="420000000000"),
        authority=decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=ISSUER_ID,
        security_id=SECURITY_ID,
        stage="valuation_pre_price_verification",
        data_cutoff_date="2026-08-14",
        request_started_at="2026-08-15T00:59:59Z",
        specs=_pre_price_specs(),
    )
    conflicting_vendor = next(
        item for item in conflict_result.observations if item.canonical_concept == "revenue"
    )
    conflict = crosscheck_vendor_observation(
        graph=graph,
        official=official,
        vendor=conflicting_vendor,
        created_at="2026-08-15T01:02:00Z",
    )
    assert conflict.result == "conflict"
    assert conflict.status == "review_required"
    reviewed_bundle = bind_crosschecks_to_bundle(conflict_result.bundle, (conflict,))
    assert reviewed_bundle.status == "partial"
    assert reviewed_bundle.issues == ("vendor_conflict_review_required",)
    assert reviewed_bundle.cross_checks[0]["object_id"] == conflict.receipt_id
    resolved = resolve_crosscheck(
        conflict,
        reviewer_id="human:controller",
        resolution="official_evidence_confirmed_vendor_rejected",
    )
    assert resolved.status == "resolved"
    assert resolved.vendor_may_overwrite is False
    assert official.value == "416161000000"


def test_official_operand_rejects_graph_outside_object_rehash_and_rebind() -> None:
    graph, fact = _official_graph(value="416161000000")
    foreign_graph, foreign_fact = _official_graph(value="420000000000")
    assert foreign_graph != graph
    with pytest.raises(FutuCrossCheckError, match="rebound outside the graph"):
        build_official_evidence_operand(graph=graph, official_object=foreign_fact)
    operand = build_official_evidence_operand(graph=graph, official_object=fact)
    with pytest.raises(FutuCrossCheckError, match="fingerprint"):
        replace(operand, object_fingerprint=HASH_B)
    with pytest.raises(FutuCrossCheckError, match="fingerprint"):
        replace(operand, operand_fingerprint=HASH_B)


def test_peer_evidence_fixture_closes_five_exact_post_freeze_sessions(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from test_phase5d5_price_blind_freeze import _compile

    _, freeze = _compile(sample_payloads, monkeypatch)
    fixture = build_futu_peer_evidence_fixture(freeze)
    assert len(fixture.peer_evidence_set.peers) == 5
    assert fixture.peer_evidence_set.target_security_id == "security:acme:common"
    assert fixture.peer_evidence_set.peers == fixture.peer_sessions
    assert all(
        tuple(request.protocol_id for request in peer.execution.requests) == (3202, 3103)
        for peer in fixture.peer_sessions
    )


def test_complete_session_replays_target_peers_conclusion_runtime_and_publication(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from test_phase5_v1_valuation_synthesis import _complete_synthesis

    *_, composite, _scores, scorecard = _complete_synthesis(
        sample_payloads,
        monkeypatch,
        tmp_path,
    )
    freeze = composite._run_result.input_receipt.expected_freeze
    fixture = build_complete_futu_session_fixture(
        freeze,
        composite_valuation=composite,
        owner_scorecard=scorecard,
    )
    validate_futu_market_execution_evidence(
        fixture.market_execution_evidence,
        verifier=fixture.verifier,
    )
    validate_futu_session_evidence_replay(
        fixture.session,
        verifier=fixture.verifier,
    )
    validate_futu_session_publication_manifest(
        fixture.publication_manifest,
        source_session=fixture.session,
        verifier=fixture.verifier,
    )
    reloaded = FutuSessionPublicationManifest.from_dict(
        fixture.publication_manifest.to_dict()
    )
    assert reloaded == fixture.publication_manifest
    market_publication = build_futu_market_execution_publication_manifest(
        fixture.market_execution_evidence,
        verifier=fixture.verifier,
    )
    validate_futu_market_execution_publication_manifest(
        market_publication,
        source_evidence=fixture.market_execution_evidence,
        verifier=fixture.verifier,
    )
    assert FutuMarketExecutionPublicationManifest.from_dict(
        market_publication.to_dict()
    ) == market_publication
    assert market_publication.source_evidence_fingerprint == (
        fixture.market_execution_evidence.fingerprint
    )
    assert len(fixture.peer_evidence_set.peers) == 5
    assert fixture.session.market_execution_evidence == fixture.market_execution_evidence
    assert fixture.session.peer_evidence_set == fixture.peer_evidence_set
    assert fixture.session.frozen_conclusion == fixture.frozen_conclusion
    assert fixture.market_execution_evidence.authority_set.runtime is None
    assert all(peer.authority_set.runtime is None for peer in fixture.peer_evidence_set.peers)
    response_count = len(fixture.publication_manifest.responses)
    assert len(fixture.completed_authority_set.runtime.checkpoints) == 2 + 2 * response_count
    assert fixture.publication_manifest.session_fingerprint == fixture.session.fingerprint

    supply = fixture.completed_authority_set.supply_chain
    runtime_authorization = fixture.completed_authority_set.runtime_authorization
    security = fixture.completed_authority_set.security_identity
    assert supply is not None
    assert runtime_authorization is not None
    assert security is not None
    partial_ordered_executions = (
        *fixture.market_execution_evidence.executions,
        *(peer.execution for peer in fixture.peer_evidence_set.peers),
    )
    partial_responses = tuple(
        response
        for execution in partial_ordered_executions
        for response in execution.responses
    )
    partial_ended = (
        max(
            datetime.fromisoformat(item.retrieved_at.replace("Z", "+00:00"))
            for item in partial_responses
        )
        + timedelta(seconds=5)
    ).isoformat().replace("+00:00", "Z")
    partial_runtime = _completed_runtime_receipt(
        fixture.live_authority_set,
        responses=partial_responses,
        ended_at=partial_ended,
    )
    with pytest.raises(ValueError, match="without an exact contested conclusion"):
        build_futu_attested_finalization_fixture(
            executions=partial_ordered_executions,
            runtime_receipt=partial_runtime,
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            verifier=fixture.verifier,
        )
    ordered_executions = (
        fixture.session.executions[0],
        fixture.session.executions[1],
        *(peer.execution for peer in fixture.peer_evidence_set.peers),
        fixture.session.executions[2],
    )
    finalization_payload = fixture.session.attested_finalization.to_dict()

    cas_rebind = json.loads(canonical_json(finalization_payload))
    cas_records = cas_rebind["execution_attestation"]["ordered_executions"]
    cas_records[0]["raw_plaintext_sha256"] = HASH_A
    cas_rebind["execution_attestation"]["ordered_execution_root_sha256"] = (
        canonical_sha256(cas_records)
    )
    cas_rebind["execution_attestation"] = _resigned_payload(
        "futu-sidecar-execution:",
        cas_rebind["execution_attestation"],
    )
    with pytest.raises(FutuSidecarError, match="rebound"):
        load_futu_attested_session_finalization(
            cas_rebind,
            expected_executions=ordered_executions,
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            verifier=fixture.verifier,
        )

    checkpoint_rebind = json.loads(canonical_json(finalization_payload))
    checkpoint_rebind["execution_attestation"]["checkpoint_root_sha256"] = HASH_A
    checkpoint_rebind["execution_attestation"] = _resigned_payload(
        "futu-sidecar-execution:",
        checkpoint_rebind["execution_attestation"],
    )
    with pytest.raises(FutuSidecarError, match="root or authority"):
        load_futu_attested_session_finalization(
            checkpoint_rebind,
            expected_executions=ordered_executions,
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            verifier=fixture.verifier,
        )

    authorization_rebind = json.loads(canonical_json(finalization_payload))
    authorization_rebind["runtime_receipt"]["runtime_authorization_fingerprint"] = HASH_A
    authorization_rebind["runtime_receipt"] = _resigned_payload(
        "futu-runtime:",
        authorization_rebind["runtime_receipt"],
    )
    with pytest.raises(FutuSidecarError, match="pre-run authorization"):
        load_futu_attested_session_finalization(
            authorization_rebind,
            expected_executions=ordered_executions,
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            verifier=fixture.verifier,
        )

    boot_rebind = json.loads(canonical_json(finalization_payload))
    boot_rebind["boot_attestation"]["session_id"] = HASH_A
    boot_rebind["boot_attestation"] = _resigned_payload(
        "futu-sidecar-boot:",
        boot_rebind["boot_attestation"],
    )
    with pytest.raises(FutuSidecarError, match="authorities are not aligned"):
        load_futu_attested_session_finalization(
            boot_rebind,
            expected_executions=ordered_executions,
            supply_chain=supply,
            runtime_authorization=runtime_authorization,
            verifier=fixture.verifier,
        )

    post_spec = FutuRequestSpec(
        "post_valuation_context",
        3229,
        FrozenMap({}),
        price_blind_freeze_fingerprint=freeze.artifact.fingerprint,
        frozen_conclusion=fixture.frozen_conclusion,
    )
    chronology_paradox = execute_futu_plan(
        transport=NoCallTransport(),
        authority=fixture.authority_decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=fixture.session.issuer_id,
        security_id=fixture.session.security_id,
        stage="post_valuation_context",
        data_cutoff_date=fixture.session.executions[2].requests[0].data_cutoff_date,
        request_started_at=fixture.frozen_conclusion.conclusion_frozen_at,
        specs=(post_spec,),
    )
    assert chronology_paradox.bundle.status == "blocked"
    assert chronology_paradox.bundle.issues == ("frozen_conclusion_invalid",)

    foreign_conclusion = build_futu_frozen_conclusion_receipt(
        run_id="run:futu-other",
        security_id=fixture.session.security_id,
        composite_valuation=composite,
        owner_scorecard=scorecard,
        conclusion_frozen_at=fixture.frozen_conclusion.conclusion_frozen_at,
    )
    foreign_spec = FutuRequestSpec(
        "post_valuation_context",
        3229,
        FrozenMap({}),
        price_blind_freeze_fingerprint=freeze.artifact.fingerprint,
        frozen_conclusion=foreign_conclusion,
    )
    after_conclusion = (
        datetime.fromisoformat(
            fixture.frozen_conclusion.conclusion_frozen_at.replace("Z", "+00:00")
        )
        + timedelta(seconds=1)
    ).isoformat().replace("+00:00", "Z")
    foreign_run = execute_futu_plan(
        transport=NoCallTransport(),
        authority=fixture.authority_decision,
        runtime_authorization=runtime_authorization,
        security_identity=security,
        supply_chain=supply,
        run_id=RUN_ID,
        issuer_id=fixture.session.issuer_id,
        security_id=fixture.session.security_id,
        stage="post_valuation_context",
        data_cutoff_date=fixture.session.executions[2].requests[0].data_cutoff_date,
        request_started_at=after_conclusion,
        specs=(foreign_spec,),
    )
    assert foreign_run.bundle.status == "blocked"
    assert foreign_run.bundle.issues == ("frozen_conclusion_invalid",)
