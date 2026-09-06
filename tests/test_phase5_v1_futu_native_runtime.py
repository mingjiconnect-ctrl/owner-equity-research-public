from dataclasses import replace

import pytest
from test_phase5_v1_futu_data_plane import (
    COMPONENT_LOCK_SHA256,
    NOW,
    POLICY_SHA256,
    RUN_ID,
    DeterministicVerifier,
    _authorities,
    _resigned_payload,
)

from owner_research.futu_receipts import (
    FutuReceiptError,
    FutuRuntimeIsolationAuthorization,
    FutuRuntimeIsolationReceipt,
    FutuSupplyChainReceipt,
    evaluate_futu_authority,
    load_futu_signed_receipt,
    validate_futu_payload,
)


def _native_authorities():
    authority, _, supply = _authorities(trd_logined=True)
    supply = FutuSupplyChainReceipt(
        **_resigned_payload(
            "futu-supply:",
            {
                **supply.to_dict(),
                "schema_version": "2.0.0",
                "vm_image_sha256": None,
            },
        )
    )
    authorization = FutuRuntimeIsolationAuthorization(
        **_resigned_payload(
            "futu-runtime-authorization:",
            {
                **authority.runtime_authorization.to_dict(),
                "schema_version": "2.0.0",
                "vm_image_sha256": None,
                "credentials_location": "user_managed_macos_opend",
                "supply_chain_fingerprint": supply.fingerprint,
            },
        )
    )
    runtime = FutuRuntimeIsolationReceipt(
        **_resigned_payload(
            "futu-runtime:",
            {
                **authority.runtime.to_dict(),
                "schema_version": "2.0.0",
                "vm_image_sha256": None,
                "credentials_location": "user_managed_macos_opend",
                "supply_chain_fingerprint": supply.fingerprint,
                "runtime_authorization_fingerprint": authorization.fingerprint,
            },
        )
    )
    return replace(
        authority, supply_chain=supply, runtime_authorization=authorization, runtime=runtime
    )


def _decision(authority, purpose):
    return evaluate_futu_authority(
        authority,
        verifier=DeterministicVerifier(),
        now=NOW,
        run_id=RUN_ID,
        policy_sha256=POLICY_SHA256,
        component_lock_sha256=COMPONENT_LOCK_SHA256,
        required_data_families=("market_price",),
        required_protocol_ids=(3103,),
        purpose=purpose,
    )


@pytest.mark.parametrize("purpose", ["live_preflight", "replay_only"])
def test_native_mac_authority_retains_quote_only_semantics(purpose):
    authority = _native_authorities()
    decision = _decision(authority, purpose)
    assert decision.status == "eligible"
    assert decision.issue_codes == ()
    assert all(not 2000 <= item < 3000 for item in decision.allowed_protocol_ids)
    assert authority.account.trd_logined is True
    assert authority.runtime.vm_image_sha256 is None
    assert authority.runtime.credentials_location == "user_managed_macos_opend"


@pytest.mark.parametrize(
    "attribute,prefix",
    [
        ("supply_chain", "futu-supply:"),
        ("runtime_authorization", "futu-runtime-authorization:"),
        ("runtime", "futu-runtime:"),
    ],
)
def test_native_receipt_roundtrips_and_cannot_claim_a_vm(attribute, prefix):
    receipt = getattr(_native_authorities(), attribute)
    assert load_futu_signed_receipt(receipt.SCHEMA_NAME, receipt.to_dict()) == receipt
    assert receipt.to_dict()["schema_version"] == "2.0.0"
    for patch in ({"vm_image_sha256": "a" * 64}, {"schema_version": "1.0.0"}):
        with pytest.raises(FutuReceiptError):
            type(receipt)(**_resigned_payload(prefix, {**receipt.to_dict(), **patch}))


@pytest.mark.parametrize(
    "field,value",
    [
        ("credentials_location", "isolated_vm_tmpfs"),
        ("rootless", False),
        ("host_opend_port_mapped", True),
        ("generic_raw_send_enabled", True),
        ("logging_enabled", True),
        ("reminder_push_enabled", True),
        ("automatic_quote_right_takeover_enabled", True),
        ("trade_and_account_protocols_rejected_before_opend", False),
    ],
)
def test_native_runtime_rejects_unsupported_execution_claims(field, value):
    authority = _native_authorities()
    with pytest.raises(FutuReceiptError):
        FutuRuntimeIsolationAuthorization(
            **_resigned_payload(
                "futu-runtime-authorization:",
                {**authority.runtime_authorization.to_dict(), field: value},
            )
        )
    # Completed observations may retain an unsafe boolean for diagnosis, but
    # must never become eligible replay authority.
    try:
        runtime = FutuRuntimeIsolationReceipt(
            **_resigned_payload(
                "futu-runtime:",
                {**authority.runtime.to_dict(), field: value},
            )
        )
    except FutuReceiptError:
        return
    decision = _decision(replace(authority, runtime=runtime), "replay_only")
    assert decision.status == "blocked"
    assert "runtime_isolation_missing" in decision.issue_codes


def test_native_runtime_cannot_mix_with_linux_supply():
    authority = _native_authorities()
    _, _, linux_supply = _authorities()
    for purpose in ("live_preflight", "replay_only"):
        result = _decision(replace(authority, supply_chain=linux_supply), purpose)
        assert result.status == "blocked"
        assert "supply_chain_mismatch" in result.issue_codes


def test_native_mode_does_not_waive_other_authorities():
    authority = _native_authorities()
    for attribute in ("legal", "account", "supply_chain", "security_identity"):
        assert (
            _decision(replace(authority, **{attribute: None}), "live_preflight").status == "blocked"
        )


def test_version_two_does_not_expand_unrelated_futu_contracts():
    authority = _native_authorities()
    with pytest.raises(FutuReceiptError, match="Unsupported Futu schema version"):
        validate_futu_payload(
            authority.account.SCHEMA_NAME,
            {
                **authority.account.to_dict(),
                "schema_version": "2.0.0",
            },
        )


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize(
    "attribute,prefix",
    [
        ("supply_chain", "futu-supply:"),
        ("runtime", "futu-runtime:"),
    ],
)
def test_opend_version_and_build_match_real_wire_encoding(native, attribute, prefix):
    authority = _native_authorities() if native else _authorities()[0]
    receipt = getattr(authority, attribute)
    payload = {
        **receipt.to_dict(),
        "opend_version": "10.10.7008",
        "opend_server_version": 1010,
        "opend_server_build_no": 7008,
    }
    if attribute == "runtime":
        payload["checkpoints"] = [
            {**item, "opend_server_version": 1010, "opend_server_build_no": 7008}
            for item in payload["checkpoints"]
        ]
    actual = type(receipt)(**_resigned_payload(prefix, payload))
    assert actual.opend_server_version == 1010
    assert actual.opend_server_build_no == 7008
    for patch in (
        {"opend_server_version": 101007008},
        {"opend_server_build_no": 1},
        {"opend_version": "10.10.7009"},
        {"opend_version": "10.010.7008"},
    ):
        with pytest.raises(FutuReceiptError):
            type(receipt)(**_resigned_payload(prefix, {**payload, **patch}))
