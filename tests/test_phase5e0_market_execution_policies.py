from __future__ import annotations

import ast
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import owner_research
from owner_research.fingerprints import canonical_sha256
from owner_research.schema_store import SCHEMA_NAMES
from owner_research.valuation_market_execution_policies import (
    FINAL_REQUEST_POLICY_ID,
    FINAL_REQUEST_POLICY_VERSION,
    KERNEL_EXECUTION_POLICY_ID,
    KERNEL_EXECUTION_POLICY_VERSION,
    MARKET_QUOTE_POLICY_ID,
    MARKET_QUOTE_POLICY_VERSION,
    PHASE5E_POLICIES,
    PINNED_KERNEL_SCHEMA_SHA256,
    SECURITY_IDENTITY_POLICY_ID,
    SECURITY_IDENTITY_POLICY_VERSION,
    SHARE_BASIS_POLICY_ID,
    SHARE_BASIS_POLICY_VERSION,
    phase5e_policy_sha256,
)
from owner_research.valuation_market_execution_types import (
    FinalRequestCompilationReceipt,
    KernelExecutionReceipt,
    MarketQuoteReceipt,
    MarketQuoteRequest,
    SecurityIdentityDecision,
    ShareBasisDecision,
)

ROOT = Path(__file__).parents[1]
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64


def _market_request(**changes: object) -> MarketQuoteRequest:
    payload: dict[str, object] = {
        "request_id": "market-request:fixture:2026-07-10",
        "policy_id": MARKET_QUOTE_POLICY_ID,
        "policy_version": MARKET_QUOTE_POLICY_VERSION,
        "policy_sha256": phase5e_policy_sha256(),
        "authorization_handoff_id": "valuation-handoff:fixture:run-1:v4",
        "authorization_transitioned_at": "2026-07-11T01:00:00+00:00",
        "issuer_id": "issuer:fixture",
        "data_cutoff_date": "2026-07-11",
        "security_id": "security:fixture:common",
        "ticker": "FIX",
        "exchange": "XNYS",
        "share_class": "common",
        "quote_currency": "USD",
        "reporting_currency": "USD",
        "price_basis": "official_unadjusted_close",
        "session_kind": "regular",
        "provider_id": "provider:recorded-fixture",
        "provider_version": "1.0.0",
        "provider_registration_sha256": SHA_A,
        "endpoint": "recorded://market/fixture/2026-07-10",
        "trading_calendar_id": "calendar:XNYS:1.0.0",
        "request_started_at": "2026-07-11T01:01:00+00:00",
    }
    payload.update(changes)
    payload["request_fingerprint"] = canonical_sha256(payload)
    return MarketQuoteRequest(**payload)  # type: ignore[arg-type]


def _market_receipt(**changes: object) -> MarketQuoteReceipt:
    request = _market_request()
    payload: dict[str, object] = {
        "receipt_id": "market-receipt:fixture:2026-07-10",
        "request_id": request.request_id,
        "request_fingerprint": request.request_fingerprint,
        "authorization_handoff_id": request.authorization_handoff_id,
        "authorization_transitioned_at": request.authorization_transitioned_at,
        "issuer_id": request.issuer_id,
        "data_cutoff_date": request.data_cutoff_date,
        "security_id": request.security_id,
        "ticker": request.ticker,
        "exchange": request.exchange,
        "share_class": request.share_class,
        "provider_id": request.provider_id,
        "provider_version": request.provider_version,
        "endpoint": request.endpoint,
        "trading_calendar_id": request.trading_calendar_id,
        "request_started_at": request.request_started_at,
        "retrieved_at": "2026-07-11T01:02:00+00:00",
        "trading_date": "2026-07-10",
        "latest_completed_session_date": "2026-07-10",
        "quote_timestamp": "2026-07-10T20:00:00+00:00",
        "session_kind": "regular",
        "session_status": "completed",
        "instrument_status": "active",
        "price_basis": "official_unadjusted_close",
        "quote_price": "50.125",
        "quote_currency": "USD",
        "raw_response_sha256": SHA_B,
    }
    payload.update(changes)
    return MarketQuoteReceipt(**payload)  # type: ignore[arg-type]


def _security(**changes: object) -> SecurityIdentityDecision:
    payload: dict[str, object] = {
        "decision_id": "security-decision:fixture",
        "policy_id": SECURITY_IDENTITY_POLICY_ID,
        "policy_version": SECURITY_IDENTITY_POLICY_VERSION,
        "issuer_id": "issuer:fixture",
        "security_id": "security:fixture:common",
        "ticker": "FIX",
        "exchange": "XNYS",
        "share_class": "common",
        "security_structure": "single_primary_common",
        "quote_currency": "USD",
        "reporting_currency": "USD",
        "disposition": "eligible",
        "reason_codes": (),
    }
    payload.update(changes)
    return SecurityIdentityDecision(**payload)  # type: ignore[arg-type]


def _shares(**changes: object) -> ShareBasisDecision:
    payload: dict[str, object] = {
        "decision_id": "share-basis-decision:fixture",
        "policy_id": SHARE_BASIS_POLICY_ID,
        "policy_version": SHARE_BASIS_POLICY_VERSION,
        "issuer_id": "issuer:fixture",
        "security_id": "security:fixture:common",
        "share_fact_id": "fact:fixture:current-common-shares:2026-07-10",
        "basis_kind": "current_common_shares_outstanding",
        "evidence_kind": "direct_point_in_time",
        "as_of_date": "2026-07-10",
        "quote_date": "2026-07-10",
        "split_factor": "1",
        "corporate_action_evidence_ids": ("fact:fixture:no-corporate-action",),
        "disposition": "eligible",
        "reason_codes": (),
    }
    payload.update(changes)
    return ShareBasisDecision(**payload)  # type: ignore[arg-type]


def _request_receipt(**changes: object) -> FinalRequestCompilationReceipt:
    payload: dict[str, object] = {
        "receipt_id": "request-receipt:fixture",
        "policy_id": FINAL_REQUEST_POLICY_ID,
        "policy_version": FINAL_REQUEST_POLICY_VERSION,
        "issuer_id": "issuer:fixture",
        "handoff_run_id": "valuation-run:fixture",
        "market_reference_snapshot_id": "market-reference:fixture",
        "added_source_ids": ("source:fixture:market",),
        "added_fact_ids": ("fact:fixture:quote", "fact:fixture:market-equity"),
        "price_blind_fact_ledger_sha256": SHA_A,
        "final_fact_ledger_sha256": SHA_B,
        "assumption_entries_before_sha256": SHA_C,
        "assumption_entries_after_sha256": SHA_C,
        "price_blind_input_before_sha256": SHA_D,
        "price_blind_input_after_sha256": SHA_D,
        "protected_mckinsey_before_sha256": SHA_E,
        "protected_mckinsey_after_sha256": SHA_E,
        "protected_penman_before_sha256": SHA_F,
        "protected_penman_after_sha256": SHA_F,
        "valuation_request_sha256": "1" * 64,
        "status": "validated",
        "reason_codes": (),
    }
    payload.update(changes)
    return FinalRequestCompilationReceipt(**payload)  # type: ignore[arg-type]


def _kernel_receipt(**changes: object) -> KernelExecutionReceipt:
    payload: dict[str, object] = {
        "receipt_id": "kernel-execution:fixture",
        "policy_id": KERNEL_EXECUTION_POLICY_ID,
        "policy_version": KERNEL_EXECUTION_POLICY_VERSION,
        "repository": "mingjiconnect-ctrl/owner-valuation-kernel",
        "tag": "v2.0.0-rc.2",
        "commit": "be9b0773d5a78f5f8a33ba982494512668df85fe",
        "package_version": "2.0.0rc2",
        "plugin_version": "2.0.0-rc.2",
        "schema_sha256": PINNED_KERNEL_SCHEMA_SHA256,
        "wheel_sha256": SHA_A,
        "dependency_wheelhouse_sha256": SHA_B,
        "execution_mode": "isolated_subprocess",
        "request_transport": "canonical_json_stdin",
        "result_transport": "canonical_json_stdout",
        "network_mode": "disabled",
        "request_sha256": SHA_C,
        "result_sha256": SHA_D,
        "exit_code": 0,
        "result_preserved": True,
        "status": "succeeded",
        "reason_codes": (),
    }
    payload.update(changes)
    return KernelExecutionReceipt(**payload)  # type: ignore[arg-type]


def test_phase5e0_keeps_43_public_contracts_and_defines_five_closed_policies() -> None:
    assert len(SCHEMA_NAMES) == 43
    assert set(PHASE5E_POLICIES) == {
        "market_quote",
        "security_identity",
        "share_basis",
        "final_request",
        "kernel_execution",
    }
    assert len(phase5e_policy_sha256()) == 64


def test_internal_records_are_immutable_and_order_independent() -> None:
    shares = _shares(
        corporate_action_evidence_ids=("fact:z", "fact:a"),
    )
    reversed_shares = _shares(
        corporate_action_evidence_ids=("fact:a", "fact:z"),
    )
    assert shares.fingerprint == reversed_shares.fingerprint
    with pytest.raises(FrozenInstanceError):
        shares.split_factor = "2"  # type: ignore[misc]


def test_market_request_requires_physical_authorization_precedence() -> None:
    with pytest.raises(ValueError, match="before Handoff authorization"):
        _market_request(request_started_at="2026-07-11T00:59:59+00:00")


@pytest.mark.parametrize(
    "changes",
    (
        {"price_basis": "adjusted_close"},
        {"price_basis": "intraday"},
        {"session_kind": "after_hours"},
    ),
)
def test_market_request_rejects_noncanonical_price_or_session(changes) -> None:
    with pytest.raises(ValueError):
        _market_request(**changes)


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"retrieved_at": "2026-07-11T01:00:30+00:00"}, "timing"),
        ({"trading_date": "2026-07-12"}, "cutoff"),
        ({"session_status": "in_progress"}, "completed"),
        ({"instrument_status": "halted"}, "halted"),
        ({"latest_completed_session_date": "2026-07-09"}, "latest completed"),
        ({"price_basis": "adjusted_close"}, "price basis"),
        ({"quote_price": "0"}, "positive"),
    ),
)
def test_market_receipt_rejects_invalid_timing_session_or_quote(changes, message) -> None:
    with pytest.raises(ValueError, match=message):
        _market_receipt(**changes)


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        (
            {
                "security_structure": "adr_or_depositary_receipt",
                "disposition": "eligible",
            },
            "one primary common",
        ),
        ({"quote_currency": "EUR"}, "reporting currency"),
        ({"share_class": "preferred"}, "must be common"),
    ),
)
def test_security_identity_rejects_adr_multiclass_or_cross_currency(changes, message) -> None:
    with pytest.raises(ValueError, match=message):
        _security(**changes)


def test_unsupported_security_is_explicitly_specialist_required() -> None:
    decision = _security(
        security_structure="dual_or_multi_class_different_prices",
        disposition="specialist_required",
        reason_codes=("dual_class_security_unsupported",),
    )
    assert decision.disposition == "specialist_required"


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"basis_kind": "weighted_average_eps_diluted"}, "non-current"),
        ({"basis_kind": "potential_shares"}, "non-current"),
        ({"basis_kind": "authorized_or_reserved_shares"}, "non-current"),
        ({"as_of_date": "2025-12-31"}, "quote date"),
        ({"split_factor": "2"}, "split factor 1"),
    ),
)
def test_share_basis_requires_quote_date_current_shares_and_factor_one(
    changes, message
) -> None:
    with pytest.raises(ValueError, match=message):
        _shares(**changes)


def test_non_one_split_is_specialist_required_not_silently_used() -> None:
    decision = _shares(
        split_factor="2",
        evidence_kind=None,
        disposition="specialist_required",
        reason_codes=("split_factor_unsupported",),
    )
    assert decision.disposition == "specialist_required"


@pytest.mark.parametrize(
    "changes",
    (
        {"assumption_entries_after_sha256": "9" * 64},
        {"price_blind_input_after_sha256": "9" * 64},
        {"protected_mckinsey_after_sha256": "9" * 64},
        {"protected_penman_after_sha256": "9" * 64},
    ),
)
def test_final_request_receipt_rejects_any_protected_drift(changes) -> None:
    with pytest.raises(ValueError, match="protected bytes changed"):
        _request_receipt(**changes)


def test_final_request_receipt_allows_only_one_source_and_two_market_facts() -> None:
    with pytest.raises(ValueError, match="exactly one source and two market Facts"):
        _request_receipt(added_fact_ids=("fact:quote",))


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"commit": "0" * 40}, "identity drifted"),
        ({"execution_mode": "in_process"}, "isolated subprocess"),
        ({"network_mode": "enabled"}, "network must be disabled"),
        ({"result_preserved": False}, "preserve"),
    ),
)
def test_kernel_execution_receipt_rejects_drift_or_unsafe_execution(changes, message) -> None:
    with pytest.raises(ValueError, match=message):
        _kernel_receipt(**changes)


def test_kernel_execution_schema_map_is_frozen() -> None:
    receipt = _kernel_receipt()
    with pytest.raises(TypeError):
        receipt.schema_sha256["schemas/fact-ledger.schema.json"] = SHA_F  # type: ignore[index]


def test_phase5e0_fixture_and_forbidden_production_surfaces() -> None:
    fixture = json.loads(
        (ROOT / "tests/fixtures/phase5e0/adversarial-cases.json").read_text(
            encoding="utf-8"
        )
    )
    assert len(fixture["cases"]) >= 60
    assert len(fixture["cases"]) == len(set(fixture["cases"]))
    for name in (
        "acquire_governed_market_quote",
        "build_market_reference_snapshot",
        "compile_final_valuation_request",
        "run_pinned_valuation_kernel",
        "write_valuation_artifacts",
        "MarketQuoteRequest",
        "MarketQuoteReceipt",
        "KernelExecutionReceipt",
    ):
        assert not hasattr(owner_research, name)


def test_phase5e_overlay_matrices_are_unique_and_referentially_closed() -> None:
    interface = json.loads(
        (ROOT / "docs/phase5e-interface-matrix.json").read_text(encoding="utf-8")
    )
    failures = json.loads(
        (ROOT / "docs/phase5e-failure-mode-matrix.json").read_text(encoding="utf-8")
    )
    strategy_ids = [item["strategy_id"] for item in interface["strategies"]]
    failure_ids = [item["failure_id"] for item in failures["failures"]]
    referenced_failures = {
        failure_id for item in interface["mappings"] for failure_id in item["failure_ids"]
    }
    assert interface["extends_frozen_artifact"] == "docs/phase5-interface-matrix.json"
    assert failures["extends_frozen_artifact"] == "docs/phase5-failure-mode-matrix.json"
    assert len(strategy_ids) == len(set(strategy_ids))
    assert len(failure_ids) == len(set(failure_ids))
    assert referenced_failures <= set(failure_ids)


def test_phase5e0_modules_have_no_network_kernel_or_production_definitions() -> None:
    for relative in (
        "src/owner_research/valuation_market_execution_policies.py",
        "src/owner_research/valuation_market_execution_types.py",
    ):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        assert not imports & {"httpx", "requests", "urllib", "owner_valuation", "socket"}
        definitions = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        assert not any(
            name.startswith(("acquire_", "build_", "compile_", "fetch_", "run_", "write_"))
            for name in definitions
        )
