from __future__ import annotations

import copy
import hashlib
import json
import shutil
from dataclasses import fields as dataclass_fields
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace
from typing import Any

import pytest
import test_phase5_v1_market_slice as market_slice_fixtures
import test_phase5d5_price_blind_freeze as price_blind_fixtures
from test_phase5_v1_futu_data_plane import (
    DeterministicVerifier,
    _signed,
    _static_identity_projection_values,
    _wire_current_shares_vendor_disposition,
    _wire_empty_dividend_event_set,
    _wire_empty_revenue_breakdown_segment_set,
    _wire_empty_split_event_set,
    _wire_financial_structure_observation,
    _wire_observation,
    _wire_static_identity_observations,
    build_futu_attested_finalization_fixture,
)
from test_phase5_v1_market_slice import _unacquired_inputs
from test_phase5_v1_owner_execution import (
    TEST_RUNTIME_MANIFEST,
    TEST_RUNTIME_MANIFEST_FILE_SHA256,
    _runner_result,
)
from test_phase5_v1_owner_execution import (
    _compiled as _compiled_request,
)
from test_phase5_v1_valuation_synthesis import (
    _basis_and_forward,
    _bundle_fact_binding,
    _peer_graphs_and_inputs,
    _pinned_kernel_fixture,
    _review,
    _run_pinned_kernel_oracle,
)

import owner_research.valuation_futu_market as futu_market
import owner_research.valuation_market_provider as market_provider_module
import owner_research.valuation_owner_execution as owner_execution_module
import owner_research.valuation_run as run_module
from owner_research.contracts import Fact
from owner_research.fingerprints import (
    FrozenMap,
    canonical_json,
    canonical_sha256,
    to_json_value,
)
from owner_research.futu_crosscheck import (
    build_official_evidence_operand,
    crosscheck_vendor_observation,
)
from owner_research.futu_receipts import (
    FUTU_RUNTIME_PROTOCOL_IDS,
    FUTU_SCHEMA_VERSION,
    PINNED_FUTU_API_DISTRIBUTION_SHA256,
    PINNED_FUTU_API_VERSION,
    PINNED_PROTOBUF_DESCRIPTOR_SET_SHA256,
    PINNED_SDK_OPERATION_REGISTRY_SHA256,
    FutuAccountEntitlementReceipt,
    FutuAuthoritySet,
    FutuLegalRightsReceipt,
    FutuRuntimeIsolationAuthorization,
    FutuRuntimeIsolationReceipt,
    FutuSecurityIdentityReceipt,
    FutuSupplyChainReceipt,
    build_futu_frozen_conclusion_receipt,
    build_futu_runtime_request_plan_item,
    evaluate_futu_authority,
)
from owner_research.futu_session import (
    FutuMarketExecutionEvidence,
    FutuSessionEvidenceError,
    build_futu_market_execution_publication_manifest,
    build_futu_observation_disposition_publication_bundle,
    build_futu_peer_evidence_set,
    build_futu_peer_session_evidence,
    finalize_futu_market_execution_evidence,
    futu_static_identity_projection_fingerprint,
    validate_futu_observation_disposition_publication_bundle,
)
from owner_research.futu_sidecar import (
    FutuRequestSpec,
    FutuSidecarError,
    adapt_futu_daily_close_to_market_reference,
    execute_futu_plan,
    load_protocol_registry,
)
from owner_research.owner_scorecard import (
    LENS_COMPONENTS,
    build_owner_scorecard,
    build_score_v2,
    resolve_score_review_authority,
)
from owner_research.valuation_assumption_types import AssumptionCandidateCompilationResult
from owner_research.valuation_kernel_projection import project_current_share_lineage
from owner_research.valuation_market_provider import (
    MarketAuthorizationConsumption,
    ReviewedFileMarketProvider,
    RunClock,
)
from owner_research.valuation_owner_execution import OwnerValuationExecutionClock
from owner_research.valuation_owner_preparation import prepare_owner_valuation
from owner_research.valuation_price_blind_freeze import (
    PriceBlindFreezeAuthorization,
    write_price_blind_input_artifact,
)
from owner_research.valuation_run import (
    RuntimeManifestInputAuthority,
    ValuationRunAuthority,
    ValuationRunClock,
    run_owner_valuation,
)
from owner_research.valuation_synthesis import (
    build_comparable_valuation,
    build_composite_valuation,
    build_reviewed_peer_set_authority,
)

ROOT = Path(__file__).parents[1]
RUN_ID = "run:futu-market-bridge"
ACCOUNT_SCOPE_SHA256 = "c" * 64
STARTUP_STATE_SHA256 = canonical_sha256({"checkpoint": "startup"})
ISSUED_AT = "2026-02-16T23:00:00Z"
EXPIRES_AT = "2027-02-16T23:00:00Z"
AUTHORITY_EVALUATED_AT = datetime(2026, 7, 14, 0, 55, tzinfo=UTC)
PRE_PRICE_REQUEST_AT = "2026-07-14T00:56:00Z"
MARKET_REQUEST_AT = "2026-07-14T01:00:00Z"
MARKET_RETRIEVED_AT = "2026-07-14T01:00:01Z"
MARKET_CHECKPOINT_AT = "2026-07-14T01:00:02Z"
POST_CONTEXT_REQUEST_AT = "2026-07-14T01:08:00Z"
RUNTIME_AUTHORIZATION_EXPIRES_AT = "2026-07-14T01:09:00Z"


def _actual_governance() -> tuple[str, str]:
    lock_sha = hashlib.sha256((ROOT / "component-lock.json").read_bytes()).hexdigest()
    policy_sha = hashlib.sha256(
        (
            ROOT
            / "scripts/phase5e-futu-market-authority-policy-v2.json"
        ).read_bytes()
    ).hexdigest()
    return lock_sha, policy_sha


def _runtime_request_plan(security_compilation) -> tuple[tuple[str, ...], tuple[FrozenMap, ...]]:
    decision = security_compilation.decision
    assert decision is not None
    target_code = f"US.{decision.ticker}"
    peer_codes = tuple(f"US.P{index:02d}" for index in range(1, 6))
    registry = load_protocol_registry()
    operations: list[tuple[str, int, FrozenMap, int]] = [
        (target_code, 3104, FrozenMap({"get_detail": True}), 1),
        *[
        (
            target_code,
            protocol_id,
            _parameters(protocol_id),
            10 if protocol_id == 3227 else 1,
        )
        for protocol_id, item in registry.items()
        if item["stage"] == "valuation_pre_price_verification"
        and item["required_for_complete"]
        and decision.exchange in item["market_scope"]
        ],
    ]
    financial_index = next(
        index for index, item in enumerate(operations) if item[1] == 3227
    )
    operations[financial_index : financial_index + 1] = [
        (
            target_code,
            3227,
            FrozenMap(
                {
                    "statement_type": statement_type,
                    "financial_type": 7,
                    "currency_code": "USD",
                    "num": 10,
                }
            ),
            10,
        )
        for statement_type in (1, 2, 3)
    ]
    daily_close_parameters = FrozenMap(
        {
            "start": security_compilation.proposal.data_cutoff_date,
            "end": security_compilation.proposal.data_cutoff_date,
            "ktype": "K_DAY",
            "autype": "NONE",
            "fields": ["CLOSE", "VOLUME"],
            "max_count": 1,
            "extended_time": False,
            "session": "RTH",
        }
    )
    operations.append((target_code, 3103, daily_close_parameters, 1))
    for peer_code in peer_codes:
        operations.extend(
            (
                (peer_code, 3202, FrozenMap({}), 1),
                (peer_code, 3103, daily_close_parameters, 1),
            )
        )
    operations.extend(
        (target_code, protocol_id, _parameters(protocol_id), 1)
        for protocol_id in (3229, 3230, 3232)
    )
    plan = tuple(
        build_futu_runtime_request_plan_item(
            plan_index=index,
            security_code=security_code,
            protocol_id=protocol_id,
            parameters=parameters,
            maximum_pages=maximum_pages,
        )
        for index, (security_code, protocol_id, parameters, maximum_pages) in enumerate(
            operations
        )
    )
    return (target_code, *peer_codes), plan


def _receipt_authority(
    security_compilation,
    *,
    valid_daily_close_semantics: bool = True,
) -> tuple[FutuAuthoritySet, Any]:
    decision = security_compilation.decision
    assert decision is not None
    component_lock_sha256, policy_sha256 = _actual_governance()
    registry = load_protocol_registry()
    protocol_ids = FUTU_RUNTIME_PROTOCOL_IDS
    families = tuple(sorted({item["data_family"] for item in registry.values()}))
    legal = _signed(
        FutuLegalRightsReceipt,
        "futu-legal:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "policy_sha256": policy_sha256,
            "component_lock_sha256": component_lock_sha256,
            "account_scope_sha256": ACCOUNT_SCOPE_SHA256,
            "agreement_sha256": canonical_sha256({"agreement": "test"}),
            "allowed_mics": ["XNAS", "XNYS"],
            "allowed_currencies": ["USD"],
            "allowed_data_families": list(families),
            "allowed_protocol_ids": list(FUTU_RUNTIME_PROTOCOL_IDS),
            "rights": {
                "internal_research": True,
                "valuation": True,
                "raw_retention": True,
                "audit_replay": True,
                "derived_private_report": True,
                "derived_public_report": False,
            },
            "effective_at": "2026-01-01T00:00:00Z",
            "issued_at": ISSUED_AT,
            "expires_at": EXPIRES_AT,
            "revoked_at": None,
        },
    )
    supply = _signed(
        FutuSupplyChainReceipt,
        "futu-supply:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "policy_sha256": policy_sha256,
            "component_lock_sha256": component_lock_sha256,
            "provider_id": futu_market.FUTU_MARKET_PROVIDER_ID,
            "provider_version": "1.0.0",
            "opend_version": "10.9.5208",
            "opend_server_version": 100_905_208,
            "opend_server_build_no": 1,
            "futu_api_version": PINNED_FUTU_API_VERSION,
            "futu_api_distribution_sha256": PINNED_FUTU_API_DISTRIBUTION_SHA256,
            "sdk_operation_registry_sha256": PINNED_SDK_OPERATION_REGISTRY_SHA256,
            "protobuf_descriptor_set_sha256": PINNED_PROTOBUF_DESCRIPTOR_SET_SHA256,
            "official_distribution_url": "https://openapi.futunn.com/opend.zip",
            "distribution_sha256": canonical_sha256({"distribution": "test"}),
            "publisher_signature_status": "verified",
            "protocol_descriptor_sha256": canonical_sha256({"protocol": "test"}),
            "facade_sha256": canonical_sha256({"facade": "test"}),
            "adapter_sha256": canonical_sha256({"adapter": "test"}),
            "parser_sha256": canonical_sha256({"parser": "test"}),
            "vm_image_sha256": canonical_sha256({"vm": "test"}),
            "sbom_sha256": canonical_sha256({"sbom": "test"}),
            "license_sha256": canonical_sha256({"license": "test"}),
            "daily_close_semantics_evidence_kind": (
                "pinned_opend_proto_canary"
                if valid_daily_close_semantics
                else "none"
            ),
            "daily_close_semantics_evidence_sha256": (
                canonical_sha256({"daily_close": "test"})
                if valid_daily_close_semantics
                else None
            ),
            "issued_at": ISSUED_AT,
            "expires_at": EXPIRES_AT,
        },
    )
    authorized_security_codes, request_plan = _runtime_request_plan(
        security_compilation
    )
    runtime_authorization = _signed(
        FutuRuntimeIsolationAuthorization,
        "futu-runtime-authorization:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "run_id": RUN_ID,
            "policy_sha256": policy_sha256,
            "component_lock_sha256": component_lock_sha256,
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
            "allowed_protocol_ids": list(protocol_ids),
            "authorized_security_codes": list(authorized_security_codes),
            "request_plan": to_json_value(request_plan),
            "request_plan_fingerprint": canonical_sha256(to_json_value(request_plan)),
            "maximum_planned_requests": sum(
                item["maximum_pages"] for item in request_plan
            ),
            "maximum_pages_per_protocol": 64,
            "sidecar_attestor_key_id": "test-key",
            "authorization_window_seconds": 900,
            "issued_at": "2026-07-14T00:53:00Z",
            "valid_from": "2026-07-14T00:54:00Z",
            "expires_at": RUNTIME_AUTHORIZATION_EXPIRES_AT,
        },
    )
    account = _signed(
        FutuAccountEntitlementReceipt,
        "futu-account:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "run_id": RUN_ID,
            "policy_sha256": policy_sha256,
            "component_lock_sha256": component_lock_sha256,
            "account_scope_sha256": ACCOUNT_SCOPE_SHA256,
            "observed_at": "2026-07-14T00:54:00Z",
            "global_state_response_fingerprint": STARTUP_STATE_SHA256,
            "qot_logined": True,
            "trd_logined": False,
            "entitlements": {family: "granted" for family in families},
            "delay_class": "real_time",
            "promotion_status": "normal",
            "quota_remaining": 100,
            "protocol_version": "10.10.7008",
            "challenge_nonce": canonical_sha256({"challenge": "test"}),
            "issued_at": "2026-07-14T00:54:01Z",
            "expires_at": EXPIRES_AT,
        },
    )
    static_identity = _static_identity_projection_values(
        f"US.{decision.ticker}", mic=decision.exchange
    )
    security = _signed(
        FutuSecurityIdentityReceipt,
        "futu-security:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "policy_sha256": policy_sha256,
            "component_lock_sha256": component_lock_sha256,
            "issuer_id": decision.issuer_id,
            "cik": "0000000001",
            "security_id": decision.security_id,
            "ticker": decision.ticker,
            "mic": decision.exchange,
            "currency": decision.quote_currency,
            "share_class": decision.share_class,
            "vendor_market": "US",
            "vendor_code": f"US.{decision.ticker}",
            "vendor_security_id": static_identity["vendor_security_id"],
            "vendor_security_type": "STOCK",
            "vendor_exchange_type": "NYSE",
            "effective_from": "2026-01-01",
            "effective_to": None,
            "official_evidence_fingerprint": security_compilation.fingerprint,
            "static_response_fingerprint": (
                futu_static_identity_projection_fingerprint(**static_identity)
            ),
            "reviewer_id": "human:test-reviewer",
            "issued_at": ISSUED_AT,
        },
    )
    authority_set = FutuAuthoritySet(
        legal=legal,
        account=account,
        supply_chain=supply,
        runtime_authorization=runtime_authorization,
        runtime=None,
        security_identity=security,
    )
    required_protocols = tuple(
        protocol_id
        for protocol_id, item in registry.items()
        if item["stage"] in {
            "valuation_pre_price_verification",
            "market_reference",
            "post_valuation_context",
        }
        and (
            item["required_for_complete"]
            or protocol_id in {3103, 3229, 3230, 3232}
        )
        and decision.exchange in item["market_scope"]
    )
    required_families = tuple(
        sorted({registry[item]["data_family"] for item in required_protocols})
    )
    authority_decision = evaluate_futu_authority(
        authority_set,
        verifier=DeterministicVerifier(),
        now=AUTHORITY_EVALUATED_AT,
        run_id=RUN_ID,
        policy_sha256=policy_sha256,
        component_lock_sha256=component_lock_sha256,
        required_data_families=required_families,
        required_protocol_ids=required_protocols,
        purpose="live_preflight",
    )
    assert authority_decision.status == "eligible"
    return authority_set, authority_decision


def _wire_number(
    *,
    field_id: str,
    value: str,
    unit: str,
    currency: str | None,
    period_end: str,
    qualifiers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "field_id": field_id,
        "period": {"start": None, "end": period_end},
        "qualifiers": qualifiers or {},
        "value_type": "number",
        "value": value,
        "unit": unit,
        "currency": currency,
        "binary64_hex": None,
        "exact_binary64_decimal": None,
    }


class BridgeTransport:
    def __init__(
        self,
        *,
        trading_date: str,
        close: str = "50.125",
        close_currency: str = "USD",
        close_qualifiers: dict[str, Any] | None = None,
        target_mic: str = "XNYS",
    ) -> None:
        self.trading_date = trading_date
        self.close = close
        self.close_currency = close_currency
        self.target_mic = target_mic
        self.close_qualifiers = (
            {
                "autype": "NONE",
                "ktype": "K_DAY",
                "price_basis": "vendor_unadjusted_daily_close_rth_requested",
                "rth_semantics_attested": False,
                "session": "RTH",
            }
            if close_qualifiers is None
            else dict(close_qualifiers)
        )
        self.calls: list[dict[str, Any]] = []
        self.guard_records: list[dict[str, Any]] = []
        self.responses: list[bytes] = []
        self.static_identity_overrides_by_code: dict[str, dict[str, Any]] = {}

    def exchange(self, request_bytes: bytes, *, maximum_response_bytes: int) -> bytes:
        request = json.loads(request_bytes)
        assert request_bytes == canonical_json(request).encode("utf-8")
        self.calls.append(request)
        protocol_id = request["protocol"]["id"]
        call_index = len(self.calls)
        serial = 10 + (call_index * 3)
        if request["security"]["code"].startswith("US.P"):
            peer_index = int(request["security"]["code"].removeprefix("US.P"))
            peer_second = 1 if protocol_id == 3202 else 4
            retrieved = datetime(
                2026,
                7,
                14,
                1,
                peer_index + 2,
                peer_second,
                tzinfo=UTC,
            )
        elif protocol_id in {3103}:
            retrieved = datetime(2026, 7, 14, 1, 0, 1, tzinfo=UTC)
        elif protocol_id in {3229, 3230, 3232}:
            post_index = sum(
                call["protocol"]["id"] in {3229, 3230, 3232}
                for call in self.calls
            )
            retrieved = datetime(
                2026,
                7,
                14,
                1,
                8,
                1 + ((post_index - 1) * 3),
                tzinfo=UTC,
            )
        else:
            retrieved = datetime(
                2026,
                7,
                14,
                0,
                56,
                1 + ((call_index - 1) * 3),
                tzinfo=UTC,
            )

        def global_state(phase: str, state_serial: int, observed: datetime) -> dict[str, Any]:
            required = request["global_state_guards"][
                f"required_{phase}_request_fingerprint"
            ]
            value = {
                "operation": "GetGlobalState",
                "protocol_id": 1002,
                "serial_number": state_serial,
                "request_fingerprint": required,
                "retrieved_at": observed.isoformat().replace("+00:00", "Z"),
                "ret_type": 0,
                "err_code": 0,
                "qot_logined": True,
                "trd_logined": False,
                "opend_server_version": request["expected_supply_attestation"][
                    "opend_server_version"
                ],
                "opend_server_build_no": request["expected_supply_attestation"][
                    "opend_server_build_no"
                ],
            }
            value["response_fingerprint"] = canonical_sha256(value)
            return value

        pre = global_state("pre", serial, retrieved - timedelta(seconds=1))
        post = global_state("post", serial + 2, retrieved + timedelta(seconds=1))
        self.guard_records.extend((pre, post))
        observations: list[dict[str, Any]] = []
        if protocol_id == 3104:
            quota_qualifiers = {
                "get_detail": True,
                "quota_kind": "historical_candlestick_distinct_security_7d",
                "quota_window_days": 7,
            }
            observations = [
                {
                    "field_id": "history_quota_used",
                    "period": {"start": None, "end": None},
                    "qualifiers": quota_qualifiers,
                    "value_type": "number",
                    "value": "0",
                    "unit": "distinct_securities",
                    "currency": None,
                    "binary64_hex": None,
                    "exact_binary64_decimal": None,
                },
                {
                    "field_id": "history_quota_remaining",
                    "period": {"start": None, "end": None},
                    "qualifiers": quota_qualifiers,
                    "value_type": "number",
                    "value": "100",
                    "unit": "distinct_securities",
                    "currency": None,
                    "binary64_hex": None,
                    "exact_binary64_decimal": None,
                },
            ]
        elif protocol_id == 3202:
            vendor_code = request["security"]["code"]
            observations = _wire_static_identity_observations(
                vendor_code,
                mic="XNAS" if vendor_code.startswith("US.P") else self.target_mic,
                overrides=self.static_identity_overrides_by_code.get(vendor_code),
            )
        elif protocol_id == 3227:
            statement_type, period_kind, field_id, display_name = {
                1: ("income", "flow", "5001", "Total Revenue"),
                2: ("balance_sheet", "stock", "900001", "Synthetic Balance Item"),
                3: ("cash_flow", "flow", "900002", "Synthetic Cash Flow Item"),
            }[request["parameters"]["statement_type"]]
            qualifiers = {
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
                    value="1250" if statement_type == "income" else "100",
                    unit="currency_units",
                    currency="USD",
                    period_end="2025-12-31",
                    qualifiers={**qualifiers, "fiscal_year": 2025},
                ),
                _wire_observation(
                    field_id=field_id,
                    value="1100" if statement_type == "income" else "90",
                    unit="currency_units",
                    currency="USD",
                    period_end="2024-12-31",
                    qualifiers={**qualifiers, "fiscal_year": 2024},
                ),
            ]
        elif protocol_id == 3236:
            observations = [
                _wire_current_shares_vendor_disposition(),
                _wire_empty_split_event_set(),
            ]
        elif protocol_id == 3228:
            observations = [_wire_empty_revenue_breakdown_segment_set()]
        elif protocol_id == 3234:
            observations = [_wire_empty_dividend_event_set()]
        elif protocol_id in {3229, 3230, 3232, 3244, 3245, 3246}:
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
        elif protocol_id == 3243:
            observations = [
                {
                    "field_id": "business_summary",
                    "period": {"start": None, "end": None},
                    "qualifiers": {},
                    "value_type": "text",
                    "value": "Pinned bridge company profile",
                    "unit": None,
                    "currency": None,
                    "binary64_hex": None,
                    "exact_binary64_decimal": None,
                }
            ]
        elif protocol_id == 3103:
            observations = [
                _wire_number(
                    field_id="close",
                    value=self.close,
                    unit="currency_per_share",
                    currency=self.close_currency,
                    period_end=self.trading_date,
                    qualifiers=self.close_qualifiers,
                ),
                _wire_number(
                    field_id="volume",
                    value="1000000",
                    unit="shares",
                    currency=None,
                    period_end=self.trading_date,
                    qualifiers=self.close_qualifiers,
                ),
            ]
        raw_sha = canonical_sha256(
            {"request": request["request_fingerprint"], "close": self.close}
        )
        encrypted_sha = canonical_sha256(
            {"raw": raw_sha, "private_encrypted_cas": True}
        )
        envelope = {
            "wire_schema_version": request["wire_schema_version"],
            "command": "fetch_quote_data_with_global_state_guards",
            "run_id": request["run_id"],
            "request_id": request["request_id"],
            "request_fingerprint": request["request_fingerprint"],
            "protocol_id": protocol_id,
            "page_index": request["page_index"],
            "supply_attestation": request["expected_supply_attestation"],
            "pre_global_state": pre,
            "data_response": {
                "serial_number": serial + 1,
                "retrieved_at": retrieved.isoformat().replace("+00:00", "Z"),
                "ret_type": 0,
                "err_code": 0,
                "next_key": None,
                "terminal": True,
                "raw_evidence": {
                    "evidence_kind": "opend_protobuf_s2c_frame",
                    "raw_plaintext_sha256": raw_sha,
                    "encrypted_object_sha256": encrypted_sha,
                    "cas_locator": f"cas://sha256/{encrypted_sha}",
                    "envelope_key_id": "kms:futu-test-key",
                    "raw_byte_count": 2048,
                },
                "observations": observations,
            },
            "post_global_state": post,
        }
        encoded = canonical_json(envelope).encode("utf-8")
        assert len(encoded) < maximum_response_bytes
        self.responses.append(encoded)
        return encoded


def _parameters(protocol_id: int) -> FrozenMap:
    if protocol_id == 3227:
        return FrozenMap(
            {
                "statement_type": 1,
                "financial_type": 7,
                "currency_code": "USD",
                "num": 10,
            }
        )
    if protocol_id == 3104:
        return FrozenMap({"get_detail": True})
    if protocol_id == 3228:
        return FrozenMap(
            {"date": 0, "financial_type": 7, "currency_code": "USD"}
        )
    if protocol_id == 3246:
        return FrozenMap(
            {"financial_type": 7, "currency_code": "USD", "num": 10}
        )
    if protocol_id == 3230:
        return FrozenMap({"rating_dimension_type": 1, "uid": None, "num": 20})
    if protocol_id == 3244:
        return FrozenMap({})
    if protocol_id == 3245:
        return FrozenMap({"leader_name": "Test Executive"})
    return FrozenMap({})


def _stage_specs(
    stage: str,
    *,
    mic: str,
    freeze_fingerprint: str | None = None,
    frozen_conclusion=None,
) -> tuple[FutuRequestSpec, ...]:
    registry = load_protocol_registry()
    if stage == "post_valuation_context":
        protocols = (3229, 3230, 3232)
    else:
        protocols = tuple(
            protocol_id
            for protocol_id, item in registry.items()
            if item["stage"] == stage
            and item["required_for_complete"]
            and mic in item["market_scope"]
        )
    requests = tuple(
        (protocol_id, _parameters(protocol_id))
        for protocol_id in protocols
    )
    if stage == "valuation_pre_price_verification":
        requests = ((3104, _parameters(3104)),) + tuple(
            request
            for protocol_id, parameters in requests
            for request in (
                tuple(
                    (
                        protocol_id,
                        FrozenMap(
                            {
                                **to_json_value(parameters),
                                "statement_type": statement_type,
                            }
                        ),
                    )
                    for statement_type in (1, 2, 3)
                )
                if protocol_id == 3227
                else ((protocol_id, parameters),)
            )
        )
    return tuple(
        FutuRequestSpec(
            stage="runtime_authority" if protocol_id == 3104 else stage,
            protocol_id=protocol_id,
            parameters=parameters,
            price_blind_freeze_fingerprint=freeze_fingerprint,
            frozen_conclusion=frozen_conclusion,
        )
        for protocol_id, parameters in requests
    )


def _bridge_context(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
    *,
    close: str = "2.9",
    close_qualifiers: dict[str, Any] | None = None,
    current_share_value: int | float = 10_000_000,
):
    def write_rebound_price_blind_artifact(*args, output_directory, **kwargs):
        # The upstream fixture first writes its pre-Phase-5c artifact. Remove that
        # test-only intermediate before writing the rebound artifact so setup does
        # not exercise the production writer's prohibited different-byte overwrite.
        shutil.rmtree(output_directory, ignore_errors=True)
        kwargs.pop("overwrite", None)
        return write_price_blind_input_artifact(
            *args,
            output_directory=output_directory,
            **kwargs,
        )

    monkeypatch.setattr(
        market_slice_fixtures,
        "write_price_blind_input_artifact",
        write_rebound_price_blind_artifact,
    )
    monkeypatch.setattr(
        market_provider_module,
        "_AUTHORIZATION_STATE_BASE",
        tmp_path / "authorization-state",
    )
    # Temporary until the parent performs the exact final PR3 component-lock freeze.
    monkeypatch.setattr(
        market_provider_module,
        "_authorization_store_policy",
        lambda _component_lock_path: (
            "market-authorizations-v1",
            canonical_sha256({"bridge_fixture": "authorization_store_policy"}),
        ),
    )
    monkeypatch.setattr(
        price_blind_fixtures,
        "PriceBlindFreezeAuthorization",
        lambda **values: PriceBlindFreezeAuthorization(
            **{
                **values,
                "authorized_at": "2026-07-14T00:58:00Z",
            }
        ),
    )
    official_payloads = copy.deepcopy(sample_payloads)
    official_payloads["valuation-assumption-candidate"]["value"] = 0.09
    official_payloads["source-document"]["source_url"] = (
        "https://www.sec.gov/Archives/edgar/data/1/acme-2025-10k.htm"
    )
    graph, freeze, directory, security, _, _ = _unacquired_inputs(
        official_payloads,
        monkeypatch,
        tmp_path,
        current_share_value=current_share_value,
    )
    assert security.decision is not None
    company_source = graph.documents[0]
    company_fact = Fact(
        schema_version="2.0.0",
        fact_id="fact:acme:issuer-legal-name",
        issuer_id=security.decision.issuer_id,
        concept="issuer_legal_name",
        value_type="text",
        value="ACME Corporation",
        unit=None,
        currency=None,
        period={"start": None, "end": security.proposal.data_cutoff_date},
        source_document_id=company_source.document_id,
        source_locator="cover:issuer-legal-name",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    vendor_revenue_fact = Fact(
        schema_version="2.0.0",
        fact_id="fact:acme:futu-revenue-crosscheck:2025",
        issuer_id=security.decision.issuer_id,
        concept="revenue",
        value_type="number",
        value=1250,
        unit="currency_units",
        currency="USD",
        period={"start": "2025-01-01", "end": "2025-12-31"},
        source_document_id=company_source.document_id,
        source_locator="p. 47, Futu secondary cross-check basis",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    graph = replace(
        graph,
        facts=(*graph.facts, company_fact, vendor_revenue_fact),
    )
    graph.validate()
    authority_set, authority_decision = _receipt_authority(security)
    assert authority_set.security_identity is not None
    assert authority_set.supply_chain is not None
    assert authority_set.runtime_authorization is not None
    transport = BridgeTransport(
        trading_date=security.proposal.data_cutoff_date,
        close=close,
        close_qualifiers=close_qualifiers,
    )
    pre_price = execute_futu_plan(
        transport=transport,
        authority=authority_decision,
        runtime_authorization=authority_set.runtime_authorization,
        security_identity=authority_set.security_identity,
        supply_chain=authority_set.supply_chain,
        run_id=RUN_ID,
        issuer_id=authority_set.security_identity.issuer_id,
        security_id=authority_set.security_identity.security_id,
        stage="valuation_pre_price_verification",
        data_cutoff_date=security.proposal.data_cutoff_date,
        request_started_at=PRE_PRICE_REQUEST_AT,
        specs=_stage_specs(
            "valuation_pre_price_verification",
            mic=authority_set.security_identity.mic,
        ),
    )
    assert pre_price.bundle.status == "complete", pre_price.bundle.issues
    # Temporary until the parent performs the exact final PR3 component-lock freeze.
    monkeypatch.setattr(futu_market, "_local_governance", lambda _: _actual_governance())
    ticket = futu_market.reserve_futu_market_reference(
        price_blind_artifact_directory=directory,
        graph=graph,
        expected_freeze=freeze,
        expected_security=security,
        authority_set=authority_set,
        authority_decision=authority_decision,
        security_identity=authority_set.security_identity,
        supply_chain=authority_set.supply_chain,
        request_started_at=MARKET_REQUEST_AT,
        verifier=DeterministicVerifier(),
    )
    market = execute_futu_plan(
        transport=transport,
        authority=authority_decision,
        runtime_authorization=authority_set.runtime_authorization,
        security_identity=authority_set.security_identity,
        supply_chain=authority_set.supply_chain,
        run_id=RUN_ID,
        issuer_id=ticket.request.issuer_id,
        security_id=ticket.request.security_id,
        stage="market_reference",
        data_cutoff_date=ticket.request.data_cutoff_date,
        request_started_at=ticket.request.request_started_at,
        specs=(futu_market.build_futu_daily_close_request_spec(ticket),),
    )
    assert market.bundle.status == "complete"
    revenue_observation = next(
        item for item in pre_price.observations if item.canonical_concept == "revenue"
    )
    revenue_operand = build_official_evidence_operand(
        graph=graph,
        official_object=vendor_revenue_fact,
    )
    revenue_crosscheck = crosscheck_vendor_observation(
        graph=graph,
        official=revenue_operand,
        vendor=revenue_observation,
        created_at="2026-07-14T00:59:30Z",
    )
    evidence = finalize_futu_market_execution_evidence(
        authority_set=authority_set,
        authority_decision=authority_decision,
        executions=(pre_price, market),
        contract_graph=graph,
        official_operands=(revenue_operand,),
        cross_checks=(revenue_crosscheck,),
        checkpoint_at=MARKET_CHECKPOINT_AT,
        verifier=DeterministicVerifier(),
    )
    provider = futu_market.bind_futu_market_reference_provider(
        ticket=ticket,
        market_execution_evidence=evidence,
        verifier=DeterministicVerifier(),
    )
    return {
        "graph": graph,
        "freeze": freeze,
        "directory": directory,
        "security": security,
        "authority_set": authority_set,
        "authority_decision": authority_decision,
        "transport": transport,
        "pre_price": pre_price,
        "market": market,
        "evidence": evidence,
        "official_operands": (revenue_operand,),
        "cross_checks": (revenue_crosscheck,),
        "ticket": ticket,
        "provider": provider,
    }


def _prepare(context):
    return prepare_owner_valuation(
        graph=context["graph"],
        price_blind_artifact_directory=context["directory"],
        expected_freeze=context["freeze"],
        expected_security=context["security"],
        market_provider=context["provider"],
        clock=RunClock(
            request_started_at=MARKET_REQUEST_AT,
            retrieved_at=MARKET_RETRIEVED_AT,
        ),
    )


def _candidate_compilation(freeze) -> AssumptionCandidateCompilationResult:
    payload = to_json_value(freeze.artifact.payload["assumption_candidates"])
    return AssumptionCandidateCompilationResult(
        **{key: value for key, value in payload.items() if key != "candidates"},
        candidates=freeze.candidates,
    )


def _run_fixed_valuation(context, monkeypatch, tmp_path: Path):
    freeze = context["freeze"]
    kernel_repository, kernel_example = _pinned_kernel_fixture()
    company_fact = next(
        item for item in context["graph"].facts if item.concept == "issuer_legal_name"
    )
    company_source = next(
        item
        for item in context["graph"].documents
        if item.document_id == company_fact.source_document_id
    )
    monkeypatch.setattr(
        owner_execution_module,
        "_governed_company_name",
        lambda _prepared: (company_fact.value, company_fact, company_source),
    )
    compiled_results = []
    kernel_calls: list[tuple[bytes, dict[str, Any]]] = []

    def compile_request(**kwargs):
        compiled = _compiled_request(kwargs["preparation"])
        request = to_json_value(compiled.request_payload)
        wacc_assumption_id = request["assumption_ledger"]["assumptions"][0][
            "assumption_id"
        ]
        request["mckinsey"]["scenarios"] = [
            {"name": name, "wacc_assumption_id": wacc_assumption_id}
            for name in ("black_swan", "bear", "base", "bull")
        ]
        compiled = replace(
            compiled,
            request_payload=request,
            canonical_request_json=canonical_json(request),
            request_sha256=canonical_sha256(request),
        )
        compiled_results.append(compiled)
        return compiled

    def run_kernel(request_bytes: bytes, **kwargs):
        assert len(compiled_results) == 1
        kernel_calls.append((request_bytes, kwargs))
        compiled = compiled_results[0]
        base = _runner_result(compiled)
        request = json.loads(request_bytes)
        assert request == to_json_value(compiled.request_payload)
        result_payload = _run_pinned_kernel_oracle(
            kernel_example,
            kernel_repository=kernel_repository,
        )
        result_payload.update(
            {
                "assumption_ledger_fingerprint": canonical_sha256(
                    request["assumption_ledger"]
                ),
                "fact_ledger_fingerprint": canonical_sha256(
                    request["fact_ledger"]
                ),
                "model_input_fingerprint": compiled.request_sha256,
            }
        )
        assert tuple(
            scenario["name"]
            for scenario in result_payload["panels"]["mckinsey"]["scenarios"]
        ) == ("black_swan", "bear", "base", "bull")
        result_bytes = canonical_json(result_payload).encode("utf-8")
        return SimpleNamespace(
            **{
                **base.__dict__,
                "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
                "result_bytes": result_bytes,
            }
        )

    monkeypatch.setattr(
        owner_execution_module,
        "compile_final_valuation_request",
        compile_request,
    )
    monkeypatch.setattr(owner_execution_module, "execute_pinned_kernel", run_kernel)
    monkeypatch.setattr(
        run_module,
        "_replay_assumption_inputs",
        lambda **_kwargs: _candidate_compilation(freeze),
    )
    monkeypatch.setattr(
        run_module,
        "_verify_runtime_supply",
        lambda **_kwargs: RuntimeManifestInputAuthority.verified(TEST_RUNTIME_MANIFEST),
    )
    execution_start = datetime.fromisoformat(MARKET_RETRIEVED_AT.replace("Z", "+00:00"))
    clock = ValuationRunClock(
        market=RunClock(MARKET_REQUEST_AT, MARKET_RETRIEVED_AT),
        execution=OwnerValuationExecutionClock(
            (execution_start + timedelta(microseconds=1)).isoformat(),
            (execution_start + timedelta(microseconds=2)).isoformat(),
        ),
    )
    authority = ValuationRunAuthority(
        price_blind_artifact_directory=context["directory"],
        expected_freeze=freeze,
        expected_security=context["security"],
        kernel_repository=kernel_repository,
        runtime_manifest=Path("/runtime/manifest.json"),
        runtime_manifest_file_sha256=TEST_RUNTIME_MANIFEST_FILE_SHA256,
        cas_root=Path("/runtime/cas"),
    )
    result = run_owner_valuation(
        graph=context["graph"],
        bundle_artifact_directory=tmp_path / "bundle",
        assumption_proposals=(),
        assumption_reviews=(),
        market_provider=context["provider"],
        kernel_wheel=tmp_path / "kernel.whl",
        output_directory=tmp_path / "six-file-archive",
        clock=clock,
        authority=authority,
    )
    assert result.status == "completed", result.issue_codes
    assert result.execution is not None
    assert result.execution.kernel_execution_receipt is not None
    assert result.execution.kernel_execution_receipt.call_count == 1
    assert len(compiled_results) == 1
    assert len(kernel_calls) == 1
    assert kernel_calls[0][0] == compiled_results[0].canonical_request_json.encode("utf-8")
    return result


def _completed_runtime(authority_set: FutuAuthoritySet, executions) -> FutuRuntimeIsolationReceipt:
    assert authority_set.supply_chain is not None
    assert authority_set.runtime_authorization is not None
    responses = tuple(
        response for execution in executions for response in execution.responses
    )
    checkpoints: list[dict[str, Any]] = [
        {
            "checkpoint": "startup",
            "protocol_id": 1002,
            "serial_number": 1,
            "global_state_request_fingerprint": canonical_sha256(
                {"runtime": "startup-request"}
            ),
            "global_state_response_fingerprint": STARTUP_STATE_SHA256,
            "observed_at": "2026-07-14T00:54:00Z",
            "qot_logined": True,
            "trd_logined": False,
            "opend_server_version": authority_set.supply_chain.opend_server_version,
            "opend_server_build_no": authority_set.supply_chain.opend_server_build_no,
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
                    "opend_server_version": authority_set.supply_chain.opend_server_version,
                    "opend_server_build_no": authority_set.supply_chain.opend_server_build_no,
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
                    "opend_server_version": authority_set.supply_chain.opend_server_version,
                    "opend_server_build_no": authority_set.supply_chain.opend_server_build_no,
                },
            )
        )
    checkpoints.append(
        {
            "checkpoint": "pre_shutdown",
            "protocol_id": 1002,
            "serial_number": max(item["serial_number"] for item in checkpoints) + 1,
            "global_state_request_fingerprint": canonical_sha256(
                {"runtime": "shutdown-request"}
            ),
            "global_state_response_fingerprint": canonical_sha256(
                {"runtime": "shutdown-response"}
            ),
            "observed_at": "2026-07-14T01:08:30Z",
            "qot_logined": True,
            "trd_logined": False,
            "opend_server_version": authority_set.supply_chain.opend_server_version,
            "opend_server_build_no": authority_set.supply_chain.opend_server_build_no,
        }
    )
    return _signed(
        FutuRuntimeIsolationReceipt,
        "futu-runtime:",
        {
            "schema_version": FUTU_SCHEMA_VERSION,
            "run_id": RUN_ID,
            "policy_sha256": authority_set.supply_chain.policy_sha256,
            "component_lock_sha256": authority_set.supply_chain.component_lock_sha256,
            "account_scope_sha256": ACCOUNT_SCOPE_SHA256,
            "supply_chain_fingerprint": authority_set.supply_chain.fingerprint,
            "runtime_authorization_fingerprint": (
                authority_set.runtime_authorization.fingerprint
            ),
            "request_plan_fingerprint": (
                authority_set.runtime_authorization.request_plan_fingerprint
            ),
            "authorization_window_seconds": 900,
            "vm_image_sha256": authority_set.supply_chain.vm_image_sha256,
            "opend_version": authority_set.supply_chain.opend_version,
            "opend_server_version": authority_set.supply_chain.opend_server_version,
            "opend_server_build_no": authority_set.supply_chain.opend_server_build_no,
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
            "quarantined": False,
            "started_at": "2026-07-14T00:54:00Z",
            "ended_at": "2026-07-14T01:08:30Z",
            "issued_at": "2026-07-14T01:08:31Z",
            "expires_at": RUNTIME_AUTHORIZATION_EXPIRES_AT,
        },
    )


def _frozen_conclusion(
    context,
    *,
    run_result,
    peer_evidence_set,
    frozen_at: str,
):
    security = context["authority_set"].security_identity
    assert security is not None
    execution = run_result.execution
    assert execution is not None
    request = to_json_value(execution.final_request_result.request_payload)
    share_fact_id = request["mckinsey"]["equity_bridge"][
        "share_denominator_fact_id"
    ]
    penman = request["penman"]
    current_noa_fact_id = penman.get("current_noa_fact_id") or share_fact_id
    nfo_fact_id = (
        penman.get("net_financial_obligations_fact_id")
        or penman["market_equity_value_fact_id"]
    )
    facts = {item["fact_id"]: item for item in request["fact_ledger"]["facts"]}
    basis, forward = _basis_and_forward(
        run_result,
        current_noa_fact_id=current_noa_fact_id,
        nfo_fact_id=nfo_fact_id,
        share_value=str(facts[share_fact_id]["value"]),
        nfo_value=str(facts[nfo_fact_id]["value"]),
    )
    peer_graphs, selected_peers, metric_inputs = _peer_graphs_and_inputs(
        peer_evidence_set
    )
    selection_review = _review(
        run_result,
        scope="peer_set_selection",
        reviewed_at="2026-07-14T01:00:30Z",
        reviewed_payload={
            "selection_frozen_at": "2026-07-14T01:00:30Z",
            "peers": selected_peers,
            "registered_metrics": ["price_earnings", "price_fcf"],
            "missing_data_policy": "complete_case_all_preselected_peers",
        },
    )
    forecast_review = _review(
        run_result,
        scope="comparable_forecast",
        reviewed_at="2026-07-14T01:00:20Z",
        reviewed_payload={"metric_inputs": metric_inputs},
    )
    peer_authority = build_reviewed_peer_set_authority(
        run_result=run_result,
        selection_review=selection_review,
        forecast_review=forecast_review,
        peer_graphs=peer_graphs,
        futu_peer_evidence_set=peer_evidence_set,
        verifier=DeterministicVerifier(),
    )
    comparables = build_comparable_valuation(
        run_result,
        basis_receipt=basis,
        peer_authority=peer_authority,
    )
    composite = build_composite_valuation(
        run_result,
        basis_receipt=basis,
        forward_reoi=forward,
        comparables=comparables,
    )
    binding = _bundle_fact_binding(run_result)
    scores = []
    for lens, component_ids in LENS_COMPONENTS.items():
        components = [
            {
                "component_id": component_id,
                "status": "complete",
                "score": "17",
                "confidence_percent": "90",
                "rationale": "Bound evidence supports the fixed component score.",
                "evidence_bindings": [binding],
                "missing_evidence": [],
                "red_flags": [],
            }
            for component_id in component_ids
        ]
        planned_review = _review(
            run_result,
            scope=f"score:{lens}",
            reviewed_at="2026-07-14T01:07:00Z",
            reviewed_payload={
                "composite_valuation_fingerprint": composite.fingerprint,
                "components": components,
            },
        )
        scores.append(
            build_score_v2(
                composite_valuation=composite,
                review_authority=resolve_score_review_authority(
                    composite_valuation=composite,
                    planned_review=planned_review,
                ),
            )
        )
    scorecard = build_owner_scorecard(
        composite_valuation=composite,
        lens_scores=tuple(scores),
    )
    return build_futu_frozen_conclusion_receipt(
        run_id=RUN_ID,
        security_id=security.security_id,
        composite_valuation=composite,
        owner_scorecard=scorecard,
        conclusion_frozen_at=frozen_at,
    )


def _peer_evidence_set(context):
    authority_set = context["authority_set"]
    target_security = authority_set.security_identity
    runtime_authorization = authority_set.runtime_authorization
    supply_chain = authority_set.supply_chain
    assert target_security is not None
    assert runtime_authorization is not None
    assert supply_chain is not None
    verifier = DeterministicVerifier()
    peers = []
    executions = []
    base_spec = futu_market.build_futu_daily_close_request_spec(context["ticket"])
    for index in range(5):
        values = target_security.to_dict()
        for key in ("receipt_id", "signature_algorithm", "signer_key_id", "signature_hex"):
            values.pop(key)
        ticker = f"P{index + 1:02d}"
        static_identity = _static_identity_projection_values(f"US.{ticker}")
        values.update(
            {
                "issuer_id": f"issuer:peer:{index:03d}",
                "security_id": f"security:{ticker}:XNAS:common",
                "ticker": ticker,
                "mic": "XNAS",
                "vendor_code": f"US.{ticker}",
                "vendor_security_id": static_identity["vendor_security_id"],
                "vendor_exchange_type": "NASDAQ",
                "official_evidence_fingerprint": canonical_sha256(
                    {"peer": ticker, "reviewed": True}
                ),
                "static_response_fingerprint": (
                    futu_static_identity_projection_fingerprint(**static_identity)
                ),
            }
        )
        peer_security = _signed(
            FutuSecurityIdentityReceipt,
            "futu-security:",
            values,
        )
        peer_authority_set = replace(
            authority_set,
            security_identity=peer_security,
        )
        peer_decision = evaluate_futu_authority(
            peer_authority_set,
            verifier=verifier,
            now=AUTHORITY_EVALUATED_AT,
            run_id=RUN_ID,
            policy_sha256=context["authority_decision"].policy_sha256,
            component_lock_sha256=context["authority_decision"].component_lock_sha256,
            required_data_families=("market_price", "security_identity"),
            required_protocol_ids=(3103, 3202),
            purpose="live_preflight",
        )
        assert peer_decision.status == "eligible"
        started_at = f"2026-07-14T01:0{index + 2}:00Z"
        execution = execute_futu_plan(
            transport=context["transport"],
            authority=peer_decision,
            runtime_authorization=runtime_authorization,
            security_identity=peer_security,
            supply_chain=supply_chain,
            run_id=RUN_ID,
            issuer_id=peer_security.issuer_id,
            security_id=peer_security.security_id,
            stage="peer_comparable_reference",
            data_cutoff_date=context["ticket"].request.data_cutoff_date,
            request_started_at=started_at,
            specs=(
                FutuRequestSpec(
                    stage="peer_comparable_reference",
                    protocol_id=3202,
                    parameters=FrozenMap({}),
                    price_blind_freeze_fingerprint=context["freeze"].artifact.fingerprint,
                ),
                FutuRequestSpec(
                    stage="peer_comparable_reference",
                    protocol_id=3103,
                    parameters=base_spec.parameters,
                    expected_trading_date=base_spec.expected_trading_date,
                    price_blind_freeze_fingerprint=context["freeze"].artifact.fingerprint,
                ),
            ),
        )
        assert execution.bundle.status == "complete", execution.bundle.issues
        close_observation = next(
            item
            for item in execution.observations
            if item.canonical_concept == "futu_unadjusted_daily_close_candidate"
        )
        daily_close = adapt_futu_daily_close_to_market_reference(
            authority=peer_decision,
            request=execution.requests[1],
            response=execution.responses[1],
            observation=close_observation,
        )
        peers.append(
            build_futu_peer_session_evidence(
                authority_set=peer_authority_set,
                authority_decision=peer_decision,
                execution=execution,
                daily_close=daily_close,
                price_blind_freeze=context["freeze"],
                verifier=verifier,
            )
        )
        executions.append(execution)
    peer_set = build_futu_peer_evidence_set(
        target_security_id=target_security.security_id,
        price_blind_freeze=context["freeze"],
        peers=tuple(peers),
        verifier=verifier,
    )
    return peer_set, tuple(executions)


def test_target_static_identity_projection_rebind_fails_closed(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    context = _bridge_context(sample_payloads, monkeypatch, tmp_path)
    authority_set = context["authority_set"]
    security = authority_set.security_identity
    runtime_authorization = authority_set.runtime_authorization
    supply_chain = authority_set.supply_chain
    assert security is not None
    assert runtime_authorization is not None
    assert supply_chain is not None
    rebound_values = security.to_dict()
    for key in ("receipt_id", "signature_algorithm", "signer_key_id", "signature_hex"):
        rebound_values.pop(key)
    rebound_projection = _static_identity_projection_values(
        security.vendor_code, mic=security.mic
    )
    rebound_projection["security_name"] = "Rebound Identity Corporation"
    rebound_values["static_response_fingerprint"] = (
        futu_static_identity_projection_fingerprint(**rebound_projection)
    )
    rebound_security = _signed(
        FutuSecurityIdentityReceipt,
        "futu-security:",
        rebound_values,
    )
    rebound_authority = replace(authority_set, security_identity=rebound_security)
    decision = context["authority_decision"]
    rebound_decision = evaluate_futu_authority(
        rebound_authority,
        verifier=DeterministicVerifier(),
        now=AUTHORITY_EVALUATED_AT,
        run_id=RUN_ID,
        policy_sha256=decision.policy_sha256,
        component_lock_sha256=decision.component_lock_sha256,
        required_data_families=decision.allowed_data_families,
        required_protocol_ids=decision.allowed_protocol_ids,
        purpose="live_preflight",
    )
    transport = BridgeTransport(
        trading_date=context["ticket"].request.data_cutoff_date,
        target_mic=rebound_security.mic,
    )
    pre_price = execute_futu_plan(
        transport=transport,
        authority=rebound_decision,
        runtime_authorization=runtime_authorization,
        security_identity=rebound_security,
        supply_chain=supply_chain,
        run_id=RUN_ID,
        issuer_id=rebound_security.issuer_id,
        security_id=rebound_security.security_id,
        stage="valuation_pre_price_verification",
        data_cutoff_date=context["ticket"].request.data_cutoff_date,
        request_started_at=PRE_PRICE_REQUEST_AT,
        specs=_stage_specs(
            "valuation_pre_price_verification",
            mic=rebound_security.mic,
        ),
    )
    market = execute_futu_plan(
        transport=transport,
        authority=rebound_decision,
        runtime_authorization=runtime_authorization,
        security_identity=rebound_security,
        supply_chain=supply_chain,
        run_id=RUN_ID,
        issuer_id=rebound_security.issuer_id,
        security_id=rebound_security.security_id,
        stage="market_reference",
        data_cutoff_date=context["ticket"].request.data_cutoff_date,
        request_started_at=MARKET_REQUEST_AT,
        specs=(futu_market.build_futu_daily_close_request_spec(context["ticket"]),),
    )
    with pytest.raises(FutuSessionEvidenceError, match="signed fingerprint"):
        finalize_futu_market_execution_evidence(
            authority_set=rebound_authority,
            authority_decision=rebound_decision,
            executions=(pre_price, market),
            contract_graph=context["graph"],
            official_operands=(),
            cross_checks=(),
            checkpoint_at=MARKET_CHECKPOINT_AT,
            verifier=DeterministicVerifier(),
        )


def test_target_static_code_mic_type_and_listing_conflicts_fail_closed(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    context = _bridge_context(sample_payloads, monkeypatch, tmp_path)
    authority_set = context["authority_set"]
    security = authority_set.security_identity
    runtime_authorization = authority_set.runtime_authorization
    supply_chain = authority_set.supply_chain
    assert security is not None
    assert runtime_authorization is not None
    assert supply_chain is not None
    cases = (
        {"vendor_security_code": "US.FAKE"},
        {"listing_mic": "XNAS"},
        {"security_type": "ADR"},
        {"listing_date": "2026-02-01"},
    )
    for overrides in cases:
        transport = BridgeTransport(
            trading_date=context["ticket"].request.data_cutoff_date,
            target_mic=security.mic,
        )
        transport.static_identity_overrides_by_code[security.vendor_code] = overrides
        pre_price = execute_futu_plan(
            transport=transport,
            authority=context["authority_decision"],
            runtime_authorization=runtime_authorization,
            security_identity=security,
            supply_chain=supply_chain,
            run_id=RUN_ID,
            issuer_id=security.issuer_id,
            security_id=security.security_id,
            stage="valuation_pre_price_verification",
            data_cutoff_date=context["ticket"].request.data_cutoff_date,
            request_started_at=PRE_PRICE_REQUEST_AT,
            specs=_stage_specs(
                "valuation_pre_price_verification",
                mic=security.mic,
            ),
        )
        with pytest.raises(FutuSessionEvidenceError):
            finalize_futu_market_execution_evidence(
                authority_set=authority_set,
                authority_decision=context["authority_decision"],
                executions=(pre_price, context["market"]),
                contract_graph=context["graph"],
                official_operands=(),
                cross_checks=(),
                checkpoint_at=MARKET_CHECKPOINT_AT,
                verifier=DeterministicVerifier(),
            )


def test_peer_static_identity_mic_mismatch_fails_closed(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    context = _bridge_context(sample_payloads, monkeypatch, tmp_path)
    context["transport"].static_identity_overrides_by_code["US.P01"] = {
        "listing_mic": "XNYS"
    }
    with pytest.raises(FutuSessionEvidenceError, match="observation semantics"):
        _peer_evidence_set(context)


def test_two_stage_futu_checkpoint_builds_existing_kernel_input_without_post_prefetch(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    context = _bridge_context(sample_payloads, monkeypatch, tmp_path)
    post_protocols = {3229, 3230, 3232}
    assert type(context["evidence"]) is FutuMarketExecutionEvidence
    assert tuple(item.bundle.stage for item in context["evidence"].executions) == (
        "valuation_pre_price_verification",
        "market_reference",
    )
    preprice_vendor_ids = {
        item.observation_id
        for item in context["pre_price"].observations
        if item.source_role == "vendor_secondary"
    }
    crosschecked_ids = {
        item.vendor_observation_id for item in context["evidence"].cross_checks
    }
    disposition_ids = {
        item.vendor_observation_id
        for item in context["evidence"].observation_dispositions
    }
    assert crosschecked_ids.isdisjoint(disposition_ids)
    assert crosschecked_ids | disposition_ids == preprice_vendor_ids
    market_manifest = build_futu_market_execution_publication_manifest(
        context["evidence"],
        verifier=DeterministicVerifier(),
    )
    disposition_bundle = build_futu_observation_disposition_publication_bundle(
        context["evidence"],
        verifier=DeterministicVerifier(),
    )
    validate_futu_observation_disposition_publication_bundle(
        disposition_bundle,
        market_manifest=market_manifest,
    )
    assert [item["receipt_id"] for item in disposition_bundle.dispositions] == [
        item.receipt_id for item in context["evidence"].observation_dispositions
    ]
    assert post_protocols.isdisjoint(
        call["protocol"]["id"] for call in context["transport"].calls
    )

    run_result = _run_fixed_valuation(context, monkeypatch, tmp_path)
    assert replace(run_result) == run_result
    preparation = run_result.preparation
    assert preparation is not None
    assert preparation.status == "prepared"
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    snapshot = prepared.snapshot
    assert snapshot.evidence_mode == "governed_vendor"
    assert snapshot.source_authority_kind == "governed_vendor"
    assert snapshot.usage_scope == "production"
    assert snapshot.raw_evidence["store_kind"] == "content_addressed_store"
    assert snapshot.raw_evidence["locator"] == context["market"].responses[0].cas_locator
    assert snapshot.raw_evidence["raw_response_sha256"] == (
        context["market"].responses[0].raw_plaintext_sha256
    )
    prepared.graph.validate()

    projection = project_current_share_lineage(prepared)
    assert projection.status == "eligible", projection.issue_codes
    assert projection.current_share_fact_id == (
        snapshot.share_basis["shares_outstanding_fact_id"]
    )
    assert post_protocols.isdisjoint(
        call["protocol"]["id"] for call in context["transport"].calls
    )


def test_unknown_noncritical_statement_field_is_allowed_only_with_disposition(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    import owner_research.futu_session as session_module

    context = _bridge_context(sample_payloads, monkeypatch, tmp_path)
    evidence = context["evidence"]
    unknown = tuple(
        item
        for item in evidence.observation_dispositions
        if item.reason_code == "unknown_noncritical_statement_field"
    )
    assert unknown
    omitted = tuple(
        item
        for item in evidence.observation_dispositions
        if item.receipt_id != unknown[0].receipt_id
    )

    with pytest.raises(FutuSessionEvidenceError, match="disjoint cross-check or disposition"):
        session_module._validate_graph_crosschecks(
            graph=evidence.contract_graph,
            graph_fingerprint=evidence.contract_graph_fingerprint,
            executions=evidence.executions,
            official_operands=evidence.official_operands,
            cross_checks=evidence.cross_checks,
            observation_dispositions=omitted,
            disposition_created_at=evidence.checkpoint_at,
        )


def test_snapshot_validation_replays_acquisition_and_evidence_graph_once(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    context = _bridge_context(sample_payloads, monkeypatch, tmp_path)
    preparation = _prepare(context)
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    evidence_graph = context["evidence"].contract_graph

    replay_calls = 0
    evidence_graph_validation_calls = 0
    original_replay = futu_market.replay_futu_market_reference_acquisition
    original_validate = type(evidence_graph).validate

    def counted_replay(*args, **kwargs):
        nonlocal replay_calls
        replay_calls += 1
        return original_replay(*args, **kwargs)

    def counted_validate(graph):
        nonlocal evidence_graph_validation_calls
        if graph is evidence_graph:
            evidence_graph_validation_calls += 1
        return original_validate(graph)

    monkeypatch.setattr(
        futu_market,
        "replay_futu_market_reference_acquisition",
        counted_replay,
    )
    monkeypatch.setattr(type(evidence_graph), "validate", counted_validate)

    prepared.graph.validate()

    assert replay_calls == 1
    assert evidence_graph_validation_calls == 1


def test_graph_fingerprint_caches_are_constructor_derived_and_rebind_closed(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    context = _bridge_context(sample_payloads, monkeypatch, tmp_path)
    ticket = context["ticket"]
    evidence = context["evidence"]
    ticket_cache = next(
        item
        for item in dataclass_fields(type(ticket))
        if item.name == "_contract_graph_fingerprint"
    )
    evidence_cache = next(
        item
        for item in dataclass_fields(type(evidence))
        if item.name == "_contract_graph_fingerprint"
    )
    assert not ticket_cache.init
    assert not evidence_cache.init
    with pytest.raises(ValueError, match="init=False"):
        replace(ticket, _contract_graph_fingerprint="0" * 64)
    with pytest.raises(ValueError, match="init=False"):
        replace(evidence, _contract_graph_fingerprint="0" * 64)

    rebound_graph = replace(
        context["graph"],
        facts=tuple(reversed(context["graph"].facts)),
    )
    rebound_ticket = replace(ticket, contract_graph=rebound_graph)
    assert rebound_ticket.contract_graph_fingerprint != ticket.contract_graph_fingerprint
    with pytest.raises(
        FutuSessionEvidenceError,
        match="market-execution checkpoint identity",
    ):
        replace(evidence, contract_graph=rebound_graph)
    with pytest.raises(ValueError, match="rebound to another ticket"):
        futu_market.FutuMarketReferenceProvider(
            ticket=rebound_ticket,
            market_execution_evidence=evidence,
            daily_close=context["provider"].daily_close,
            verifier=DeterministicVerifier(),
        )

    preparation = _prepare(context)
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    acquisition = (
        prepared.graph.market_reference_validation_contexts[0]
        .vendor_market_acquisition
    )
    object.__setattr__(
        acquisition.ticket,
        "_contract_graph_fingerprint",
        "0" * 64,
    )
    object.__setattr__(
        acquisition.market_execution_evidence,
        "_contract_graph_fingerprint",
        "0" * 64,
    )
    with pytest.raises(ValueError, match="ContractGraph was rebound"):
        futu_market.replay_futu_market_reference_acquisition(
            graph=prepared.graph,
            expected_acquisition=acquisition,
        )


def test_post_context_is_rejected_from_pre_kernel_checkpoint_and_must_extend_later(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    phase_started = perf_counter()

    def phase(label: str) -> None:
        nonlocal phase_started
        now = perf_counter()
        print(f"bridge-profile {label}: {now - phase_started:.3f}s")
        phase_started = now

    context = _bridge_context(sample_payloads, monkeypatch, tmp_path)
    phase("context")
    authority_set = context["authority_set"]
    assert authority_set.runtime_authorization is not None
    assert authority_set.security_identity is not None
    assert authority_set.supply_chain is not None
    call_count = len(context["transport"].calls)
    with pytest.raises(FutuSidecarError, match="frozen conclusion receipt"):
        _stage_specs(
            "post_valuation_context",
            mic=authority_set.security_identity.mic,
            freeze_fingerprint=context["freeze"].artifact.fingerprint,
        )
    assert len(context["transport"].calls) == call_count

    run_result = _run_fixed_valuation(context, monkeypatch, tmp_path)
    phase("fixed-run")
    preparation = run_result.preparation
    assert preparation is not None
    assert preparation.status == "prepared"
    acquisition = (
        preparation.prepared_market_reference.graph.market_reference_validation_contexts[0]
        .vendor_market_acquisition
    )
    peer_set, peer_executions = _peer_evidence_set(context)
    phase("peer-evidence")
    conclusion = _frozen_conclusion(
        context,
        run_result=run_result,
        peer_evidence_set=peer_set,
        frozen_at="2026-07-14T01:07:30Z",
    )
    phase("frozen-conclusion")
    post = execute_futu_plan(
        transport=context["transport"],
        authority=context["authority_decision"],
        runtime_authorization=authority_set.runtime_authorization,
        security_identity=authority_set.security_identity,
        supply_chain=authority_set.supply_chain,
        run_id=RUN_ID,
        issuer_id=authority_set.security_identity.issuer_id,
        security_id=authority_set.security_identity.security_id,
        stage="post_valuation_context",
        data_cutoff_date=context["security"].proposal.data_cutoff_date,
        request_started_at=POST_CONTEXT_REQUEST_AT,
        specs=_stage_specs(
            "post_valuation_context",
            mic=authority_set.security_identity.mic,
            freeze_fingerprint=context["freeze"].artifact.fingerprint,
            frozen_conclusion=conclusion,
        ),
    )
    assert post.bundle.status == "complete"
    phase("post-execution")
    with pytest.raises(ValueError, match="exactly two stages"):
        finalize_futu_market_execution_evidence(
            authority_set=authority_set,
            authority_decision=context["authority_decision"],
            executions=(context["pre_price"], context["market"], post),
            contract_graph=context["graph"],
            official_operands=(),
            cross_checks=(),
            checkpoint_at=MARKET_CHECKPOINT_AT,
            verifier=DeterministicVerifier(),
        )
    ordered_executions = (
        context["pre_price"],
        context["market"],
        *peer_executions,
        post,
    )
    runtime = _completed_runtime(authority_set, ordered_executions)
    attested_finalization = build_futu_attested_finalization_fixture(
        executions=ordered_executions,
        runtime_receipt=runtime,
        supply_chain=authority_set.supply_chain,
        runtime_authorization=authority_set.runtime_authorization,
        verifier=DeterministicVerifier(),
    )
    phase("runtime-finalization")
    completion = futu_market.complete_futu_market_session(
        acquisition=acquisition,
        authority_set=replace(authority_set, runtime=runtime),
        authority_decision=context["authority_decision"],
        peer_evidence_set=peer_set,
        frozen_conclusion=conclusion,
        attested_finalization=attested_finalization,
        post_valuation_execution=post,
        finalized_at="2026-07-14T01:08:32Z",
        verifier=DeterministicVerifier(),
    )
    phase("positive-completion")
    assert completion.session_evidence.executions[2].bundle.stage == (
        "post_valuation_context"
    )
    assert completion.session_evidence.market_execution_evidence is context["evidence"]
    assert completion.session_evidence.peer_evidence_set is peer_set
    assert completion.session_evidence.frozen_conclusion is conclusion
    assert completion.to_dict()["market_execution_evidence_fingerprint"] == (
        context["evidence"].fingerprint
    )

    foreign_context = _bridge_context(
        sample_payloads,
        monkeypatch,
        tmp_path / "same-issuer-foreign-run",
    )
    foreign_preparation = _prepare(foreign_context)
    phase("foreign-acquisition")
    assert foreign_preparation.status == "prepared"
    assert foreign_preparation.issuer_id == preparation.issuer_id
    assert foreign_preparation.prepared_market_reference is not None
    foreign_acquisition = (
        foreign_preparation.prepared_market_reference.graph
        .market_reference_validation_contexts[0]
        .vendor_market_acquisition
    )
    assert foreign_acquisition != acquisition
    with pytest.raises(ValueError, match="rebound from another valuation run"):
        futu_market.complete_futu_market_session(
            acquisition=foreign_acquisition,
            authority_set=replace(authority_set, runtime=runtime),
            authority_decision=context["authority_decision"],
            peer_evidence_set=peer_set,
            frozen_conclusion=conclusion,
            attested_finalization=attested_finalization,
            post_valuation_execution=post,
            finalized_at="2026-07-14T01:08:32Z",
            verifier=DeterministicVerifier(),
        )
    phase("cross-run-rejection")


def test_futu_provider_and_reviewed_file_authorities_cannot_masquerade(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    context = _bridge_context(sample_payloads, monkeypatch, tmp_path)
    assert type(context["provider"]) is futu_market.FutuMarketReferenceProvider
    assert not isinstance(context["provider"], ReviewedFileMarketProvider)
    preparation = _prepare(context)
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    validation_context = prepared.graph.market_reference_validation_contexts[0]
    forged_receipt = replace(
        validation_context.market_access_result.receipt,
        evidence_mode="human_reviewed_file",
    )
    forged_access = replace(
        validation_context.market_access_result,
        receipt=forged_receipt,
    )
    with pytest.raises(ValueError, match="human-reviewed validation context"):
        replace(validation_context, market_access_result=forged_access)

    daily_close_payload = context["provider"].daily_close.to_dict()
    daily_close_payload["semantics_evidence_fingerprint"] = "0" * 64
    daily_close_payload.pop("adapter_fingerprint")
    rebound_daily_close = replace(
        context["provider"].daily_close,
        semantics_evidence_fingerprint="0" * 64,
        adapter_fingerprint=canonical_sha256(daily_close_payload),
    )
    with pytest.raises(ValueError, match="daily-close evidence does not replay"):
        futu_market.FutuMarketReferenceProvider(
            ticket=context["ticket"],
            market_execution_evidence=context["evidence"],
            daily_close=rebound_daily_close,
            verifier=DeterministicVerifier(),
        )
    with pytest.raises(ValueError, match="governed RTH daily close"):
        _bridge_context(
            sample_payloads,
            monkeypatch,
            tmp_path / "rth-qualifier-rebind",
            close_qualifiers={
                "autype": "NONE",
                "ktype": "K_DAY",
                "price_basis": "official_unadjusted_rth_close",
                "rth_semantics_attested": True,
                "session": "RTH",
            },
        )


def test_component_owned_registry_and_single_use_authorization_are_closed(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    context = _bridge_context(sample_payloads, monkeypatch, tmp_path)

    no_semantics_authority, no_semantics_decision = _receipt_authority(
        context["security"],
        valid_daily_close_semantics=False,
    )
    transport_call_count = len(context["transport"].calls)
    with pytest.raises(ValueError, match="not registered for governed daily close"):
        futu_market.reserve_futu_market_reference(
            price_blind_artifact_directory=context["directory"],
            graph=context["graph"],
            expected_freeze=context["freeze"],
            expected_security=context["security"],
            authority_set=no_semantics_authority,
            authority_decision=no_semantics_decision,
            security_identity=no_semantics_authority.security_identity,
            supply_chain=no_semantics_authority.supply_chain,
            request_started_at=MARKET_REQUEST_AT,
            verifier=DeterministicVerifier(),
        )
    assert len(context["transport"].calls) == transport_call_count

    foreign_registration = replace(
        context["ticket"].registration,
        component_lock_sha256="0" * 64,
    )
    with pytest.raises(ValueError, match="authorities do not replay"):
        replace(context["ticket"], registration=foreign_registration)

    forged_fingerprints = dict(context["authority_decision"].receipt_fingerprints)
    forged_fingerprints["legal"] = "0" * 64
    forged_decision = replace(
        context["authority_decision"],
        receipt_fingerprints=FrozenMap(forged_fingerprints),
    )
    with pytest.raises(ValueError, match="authority decision does not replay"):
        futu_market.reserve_futu_market_reference(
            price_blind_artifact_directory=context["directory"],
            graph=context["graph"],
            expected_freeze=context["freeze"],
            expected_security=context["security"],
            authority_set=context["authority_set"],
            authority_decision=forged_decision,
            security_identity=context["authority_set"].security_identity,
            supply_chain=context["authority_set"].supply_chain,
            request_started_at=MARKET_REQUEST_AT,
            verifier=DeterministicVerifier(),
        )

    class UnregisteredProvider(futu_market.FutuMarketReferenceProvider):
        pass

    rogue = UnregisteredProvider(
        ticket=context["provider"].ticket,
        market_execution_evidence=context["provider"].market_execution_evidence,
        daily_close=context["provider"].daily_close,
        verifier=DeterministicVerifier(),
    )
    with pytest.raises(TypeError, match="component-owned"):
        prepare_owner_valuation(
            graph=context["graph"],
            price_blind_artifact_directory=context["directory"],
            expected_freeze=context["freeze"],
            expected_security=context["security"],
            market_provider=rogue,
            clock=RunClock(MARKET_REQUEST_AT, MARKET_RETRIEVED_AT),
        )

    assert _prepare(context).status == "prepared"
    with pytest.raises(ValueError, match="already consumed"):
        _prepare(context)


def test_coordinated_session_cas_and_consumption_rebind_hits_durable_witness(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    context = _bridge_context(sample_payloads, monkeypatch, tmp_path, close="50.125")
    preparation = _prepare(context)
    prepared = preparation.prepared_market_reference
    assert prepared is not None
    original = (
        prepared.graph.market_reference_validation_contexts[0].vendor_market_acquisition
    )

    foreign_transport = BridgeTransport(
        trading_date=context["ticket"].request.expected_trading_date,
        close="51.250",
    )
    authority_set = context["authority_set"]
    assert authority_set.runtime_authorization is not None
    assert authority_set.security_identity is not None
    assert authority_set.supply_chain is not None
    foreign_market = execute_futu_plan(
        transport=foreign_transport,
        authority=context["authority_decision"],
        runtime_authorization=authority_set.runtime_authorization,
        security_identity=authority_set.security_identity,
        supply_chain=authority_set.supply_chain,
        run_id=RUN_ID,
        issuer_id=context["ticket"].request.issuer_id,
        security_id=context["ticket"].request.security_id,
        stage="market_reference",
        data_cutoff_date=context["ticket"].request.data_cutoff_date,
        request_started_at=MARKET_REQUEST_AT,
        specs=(futu_market.build_futu_daily_close_request_spec(context["ticket"]),),
    )
    foreign_evidence = finalize_futu_market_execution_evidence(
        authority_set=authority_set,
        authority_decision=context["authority_decision"],
        executions=(context["pre_price"], foreign_market),
        contract_graph=context["graph"],
        official_operands=context["official_operands"],
        cross_checks=context["cross_checks"],
        checkpoint_at=MARKET_CHECKPOINT_AT,
        verifier=DeterministicVerifier(),
    )
    foreign_provider = futu_market.bind_futu_market_reference_provider(
        ticket=context["ticket"],
        market_execution_evidence=foreign_evidence,
        verifier=DeterministicVerifier(),
    )
    access, execution, request, response, observation = futu_market._governed_access(
        graph=context["graph"],
        expected_freeze=context["freeze"],
        expected_security=context["security"],
        provider=foreign_provider,
        clock=RunClock(MARKET_REQUEST_AT, MARKET_RETRIEVED_AT),
    )
    consumption = MarketAuthorizationConsumption(
        schema_version="1.0.0",
        consumption_id=original.authorization_consumption.consumption_id,
        authorization_handoff_id=context["ticket"].request.authorization_handoff_id,
        authorization_handoff_fingerprint=(
            context["ticket"].request.authorization_handoff_fingerprint
        ),
        price_blind_input_fingerprint=(
            context["ticket"].request.price_blind_input_fingerprint
        ),
        request_fingerprint=context["ticket"].request.request_fingerprint,
        market_access_result_fingerprint=access.fingerprint,
        quote_fingerprint=foreign_provider.daily_close.adapter_fingerprint,
        review_receipt_sha256=foreign_evidence.fingerprint,
        raw_response_sha256=response.raw_plaintext_sha256,
        consumed_at=response.retrieved_at,
        reservation_fingerprint=context["ticket"].reservation.fingerprint,
        store_authority_sha256=context["ticket"].reservation.store_authority_sha256,
        store_instance_sha256=context["ticket"].reservation.store_instance_sha256,
    )
    forged = futu_market.FutuMarketReferenceAcquisition(
        ticket=context["ticket"],
        market_execution_evidence=foreign_evidence,
        execution=execution,
        request=request,
        response=response,
        observation=observation,
        daily_close=foreign_provider.daily_close,
        access_result=access,
        authorization_consumption=consumption,
        verifier=DeterministicVerifier(),
    )
    with pytest.raises(ValueError, match="consumption does not replay"):
        futu_market.replay_futu_market_reference_acquisition(
            graph=prepared.graph,
            expected_acquisition=forged,
        )


def test_issuer_date_currency_and_price_basis_mismatches_fail_closed(
    sample_payloads,
    monkeypatch,
    tmp_path: Path,
) -> None:
    context = _bridge_context(sample_payloads, monkeypatch, tmp_path)
    authority_set = context["authority_set"]
    security = authority_set.security_identity
    assert security is not None
    rebound_values = security.to_dict()
    for key in ("receipt_id", "signature_algorithm", "signer_key_id", "signature_hex"):
        rebound_values.pop(key)
    rebound_values["issuer_id"] = "issuer:foreign"
    rebound = _signed(FutuSecurityIdentityReceipt, "futu-security:", rebound_values)
    rebound_authority = replace(authority_set, security_identity=rebound)
    rebound_decision = evaluate_futu_authority(
        rebound_authority,
        verifier=DeterministicVerifier(),
        now=AUTHORITY_EVALUATED_AT,
        run_id=RUN_ID,
        policy_sha256=context["authority_decision"].policy_sha256,
        component_lock_sha256=context["authority_decision"].component_lock_sha256,
        required_data_families=("market_price",),
        required_protocol_ids=(3103,),
        purpose="live_preflight",
    )
    with pytest.raises(ValueError, match="Futu and official security"):
        futu_market.reserve_futu_market_reference(
            price_blind_artifact_directory=context["directory"],
            graph=context["graph"],
            expected_freeze=context["freeze"],
            expected_security=context["security"],
            authority_set=rebound_authority,
            authority_decision=rebound_decision,
            security_identity=rebound,
            supply_chain=authority_set.supply_chain,
            request_started_at=MARKET_REQUEST_AT,
            verifier=DeterministicVerifier(),
        )

    wrong_date_spec = replace(
        futu_market.build_futu_daily_close_request_spec(context["ticket"]),
        expected_trading_date="2026-06-29",
        parameters=FrozenMap(
            {
                **dict(
                    futu_market.build_futu_daily_close_request_spec(
                        context["ticket"]
                    ).parameters
                ),
                "start": "2026-06-29",
                "end": "2026-06-29",
            }
        ),
    )
    wrong_date = execute_futu_plan(
        transport=BridgeTransport(trading_date="2026-06-29"),
        authority=context["authority_decision"],
        runtime_authorization=authority_set.runtime_authorization,
        security_identity=security,
        supply_chain=authority_set.supply_chain,
        run_id=RUN_ID,
        issuer_id=security.issuer_id,
        security_id=security.security_id,
        stage="market_reference",
        data_cutoff_date=context["ticket"].request.data_cutoff_date,
        request_started_at=MARKET_REQUEST_AT,
        specs=(wrong_date_spec,),
    )
    wrong_date_evidence = finalize_futu_market_execution_evidence(
        authority_set=authority_set,
        authority_decision=context["authority_decision"],
        executions=(context["pre_price"], wrong_date),
        contract_graph=context["graph"],
        official_operands=context["official_operands"],
        cross_checks=context["cross_checks"],
        checkpoint_at=MARKET_CHECKPOINT_AT,
        verifier=DeterministicVerifier(),
    )
    with pytest.raises(ValueError, match="governed RTH daily close"):
        futu_market.bind_futu_market_reference_provider(
            ticket=context["ticket"],
            market_execution_evidence=wrong_date_evidence,
            verifier=DeterministicVerifier(),
        )

    bad_currency = BridgeTransport(
        trading_date=context["ticket"].request.expected_trading_date,
        close_currency="EUR",
    )
    currency_execution = execute_futu_plan(
        transport=bad_currency,
        authority=context["authority_decision"],
        runtime_authorization=authority_set.runtime_authorization,
        security_identity=security,
        supply_chain=authority_set.supply_chain,
        run_id=RUN_ID,
        issuer_id=security.issuer_id,
        security_id=security.security_id,
        stage="market_reference",
        data_cutoff_date=context["ticket"].request.data_cutoff_date,
        request_started_at=MARKET_REQUEST_AT,
        specs=(futu_market.build_futu_daily_close_request_spec(context["ticket"]),),
    )
    close_observation = next(
        item for item in currency_execution.observations if item.field_id == "close"
    )
    with pytest.raises(ValueError, match="not eligible for adaptation"):
        adapt_futu_daily_close_to_market_reference(
            authority=context["authority_decision"],
            request=currency_execution.requests[0],
            response=currency_execution.responses[0],
            observation=close_observation,
        )

    with pytest.raises(ValueError, match="cannot choose another price basis"):
        replace(
            context["provider"].daily_close,
            market_reference_basis="adjusted_close",
        )
