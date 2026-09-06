from __future__ import annotations

import importlib
import os
import shutil
import socket
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import owner_research_futu_sidecar.server as sidecar_server
from owner_research_futu_sidecar.attestation import (
    AttestationError,
    Ed25519Attestor,
    SessionController,
    SessionStatus,
)
from owner_research_futu_sidecar.canonical import canonical_sha256
from owner_research_futu_sidecar.cas import EncryptedCas
from owner_research_futu_sidecar.frame_guard import (
    FrameGuardError,
    FrameGuardProxy,
)
from owner_research_futu_sidecar.opend_adapter import OfficialFutuAdapter
from owner_research_futu_sidecar.operation_registry import (
    PINNED_SDK_SDIST_SHA256,
    PINNED_SDK_VERSION,
    PROTOBUF_DESCRIPTOR_SET_SHA256,
    SDK_ADAPTER_REGISTRY_SHA256,
)
from owner_research_futu_sidecar.server import (
    FutuSidecarServer,
    FutuSidecarServerError,
    FutuSidecarService,
)
from owner_research_futu_sidecar.supervisor import (
    SupervisorAttestorClient,
    serve_attestor,
)
from owner_research_futu_sidecar.wire import (
    MAXIMUM_REQUEST_BYTES,
    MAXIMUM_RESPONSE_BYTES,
    WIRE_SCHEMA_VERSION,
    receive_message,
    send_message,
)

from .auth_helpers import (
    authority_fds,
    completed_disposition,
    open_expectations,
    request_plan,
    runtime_claims,
    signed_runtime_authority,
)
from .fake_opend import FakeOpenD


def _exchange(path: Path, payload: dict[str, object]) -> dict[str, object]:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with connection:
        connection.connect(os.fspath(path))
        send_message(connection, payload, maximum=MAXIMUM_REQUEST_BYTES)
        response = receive_message(connection, maximum=MAXIMUM_RESPONSE_BYTES)
    assert response is not None
    return response


def _supply() -> dict[str, object]:
    return {
        "supply_receipt_fingerprint": "a" * 64,
        "provider_id": "futu-opend-official",
        "provider_version": "1.0.0.dev0",
        "opend_version": "10.10.7008",
        "opend_server_version": 101007008,
        "opend_server_build_no": 1,
        "futu_api_version": PINNED_SDK_VERSION,
        "futu_api_distribution_sha256": PINNED_SDK_SDIST_SHA256,
        "sdk_operation_registry_sha256": SDK_ADAPTER_REGISTRY_SHA256,
        "protobuf_descriptor_set_sha256": PROTOBUF_DESCRIPTOR_SET_SHA256,
        "protocol_descriptor_sha256": "b" * 64,
        "facade_sha256": "c" * 64,
        "adapter_sha256": "d" * 64,
        "parser_sha256": "e" * 64,
    }


def test_history_sdk_hidden_pagination_is_quarantined(tmp_path: Path) -> None:
    fake = FakeOpenD(history_empty_then_next=True)
    fake.start()
    guard = FrameGuardProxy(upstream_host="127.0.0.1", upstream_port=fake.port)
    guard.start()
    private_home = tmp_path / "hidden-page-sdk-home"
    private_home.mkdir(mode=0o700)
    adapter = OfficialFutuAdapter(guard=guard, private_home=private_home)
    try:
        with pytest.raises(FrameGuardError, match="more than one protocol exchange"):
            adapter.fetch(
                protocol_id=3103,
                code="US.AAPL",
                parameters={
                    "start": "2026-08-14",
                    "end": "2026-08-14",
                    "ktype": "K_DAY",
                    "autype": "NONE",
                    "fields": ["CLOSE", "VOLUME"],
                    "max_count": 1,
                    "extended_time": False,
                    "session": "RTH",
                },
                page_key=None,
            )
        assert guard.quarantined
        assert guard.quarantine_reason == "sdk_facade_call_emitted_multiple_exchanges"
        assert fake.protocols.count(3103) == 2
        assert fake.history_request_shapes[1]["next_key"] == b"hidden-sdk-page-2"
    finally:
        adapter.close()
        fake.close()


def test_pinned_sdk_fake_opend_exercises_every_allowed_data_protocol(
    tmp_path: Path,
) -> None:
    fake = FakeOpenD(push_notify_before_profile=False)
    fake.start()
    guard = FrameGuardProxy(upstream_host="127.0.0.1", upstream_port=fake.port)
    guard.start()
    private_home = tmp_path / "all-protocol-sdk-home"
    private_home.mkdir(mode=0o700)
    adapter = OfficialFutuAdapter(guard=guard, private_home=private_home)
    calls = (
        (3104, {"get_detail": True}),
        (3202, {}),
        (
            3227,
            {
                "statement_type": 1,
                "financial_type": 7,
                "currency_code": "USD",
                "num": 10,
            },
        ),
        (3228, {"date": 0, "financial_type": 7, "currency_code": "USD"}),
        (3229, {}),
        (3230, {"rating_dimension_type": 1, "uid": None, "num": 20}),
        (3232, {}),
        (3234, {}),
        (3236, {}),
        (3243, {}),
        (3244, {}),
        (3245, {"leader_name": "Test Executive"}),
        (3246, {"num": 50, "currency_code": "USD"}),
    )
    expected_request_fields = {
        3104: ("bGetDetail", "header"),
        3202: ("market", "secType", "securityList", "header"),
        3227: ("security", "statementType", "financialType", "currencyCode", "num"),
        3228: ("security", "date", "financialType", "currencyCode"),
        3229: ("security",),
        3230: ("security", "ratingDimensionType", "num"),
        3232: ("security",),
        3234: ("security",),
        3236: ("security",),
        3243: ("security",),
        3244: ("security",),
        3245: ("security", "leaderName"),
        3246: ("security", "num", "currencyCode"),
    }
    module_names = {
        3104: "Qot_RequestHistoryKLQuota_pb2",
        3202: "Qot_GetStaticInfo_pb2",
        3227: "Qot_GetFinancialsStatements_pb2",
        3228: "Qot_GetFinancialsRevenueBreakdown_pb2",
        3229: "Qot_GetResearchAnalystConsensus_pb2",
        3230: "Qot_GetResearchRatingSummary_pb2",
        3232: "Qot_GetValuationDetail_pb2",
        3234: "Qot_GetCorporateActionsDividends_pb2",
        3236: "Qot_GetCorporateActionsStockSplits_pb2",
        3243: "Qot_GetCompanyProfile_pb2",
        3244: "Qot_GetCompanyExecutives_pb2",
        3245: "Qot_GetCompanyExecutiveBackground_pb2",
        3246: "Qot_GetCompanyOperationalEfficiency_pb2",
    }
    parsed_by_protocol = {}
    try:
        for protocol_id, parameters in calls:
            result = adapter.fetch(
                protocol_id=protocol_id,
                code="US.AAPL",
                parameters=parameters,
                page_key=None,
            )
            assert result.parsed.ret_type == 0
            assert result.parsed.err_code == 0
            assert result.parsed.observations
            parsed_by_protocol[protocol_id] = result.parsed
            module = importlib.import_module(f"futu.common.pb.{module_names[protocol_id]}")
            request = module.Request()
            request.ParseFromString(fake.request_bodies[protocol_id][-1])
            assert (
                tuple(field.name for field, _ in request.c2s.ListFields())
                == (expected_request_fields[protocol_id])
            )
            if protocol_id == 3104:
                assert request.c2s.bGetDetail is True
                assert int(request.c2s.header.securityFirm) == 0
                continue
            if protocol_id == 3202:
                security = request.c2s.securityList[0]
            else:
                security = request.c2s.security
            assert int(security.market) == 11
            assert str(security.code) == "AAPL"

        financial_descriptor = parsed_by_protocol[3227].observations[0]
        assert financial_descriptor["field_id"] == "financial_structure:5001"
        assert financial_descriptor["value"] == "Total Revenue"
        assert financial_descriptor["qualifiers"] == {
            "financial_field_id": "5001",
            "futu_api_version": "10.10.7008",
            "normalized_display_name": "total revenue",
            "statement_type": "income",
        }
        financial = parsed_by_protocol[3227].observations[1]
        assert financial["field_id"] == "5001"
        assert financial["unit"] == "currency_units"
        assert financial["currency"] == "USD"
        assert financial["qualifiers"] == {
            "accounting_standard": "US_GAAP",
            "auditor_report": "UNQUALIFIED",
            "financial_type": 7,
            "fiscal_year": 2025,
            "period_kind": "flow",
            "statement_type": "income",
            "vendor_period": "2025/FY",
        }
        quota = parsed_by_protocol[3104].observations
        assert [item["field_id"] for item in quota] == [
            "history_quota_used",
            "history_quota_remaining",
            "history_quota_detail",
        ]
        assert quota[2]["value"] == "US.AAPL"
        assert quota[2]["qualifiers"] == {
            "last_request_at": "2026-08-14T18:17:17Z",
            "raw_market_code": 11,
            "raw_security_code": "AAPL",
            "source_request_time": "2026-08-14 14:17:17",
            "source_request_timestamp": 1_786_731_437,
            "vendor_security_code": "US.AAPL",
        }
        split = parsed_by_protocol[3236].observations
        assert len(split) == 2
        assert split[0]["field_id"] == "current_common_shares"
        assert split[0]["qualifiers"]["verification_status"] == (
            "vendor_not_supported"
        )
        assert split[1]["field_id"] == "stock_split_event"
        assert split[1]["value"] == "4/1"
        assert split[1]["qualifiers"]["event_type"] == "stock_split_completed"

        for protocol_id, parameters in calls:
            if protocol_id not in {3227, 3230, 3236, 3246}:
                continue
            result = adapter.fetch(
                protocol_id=protocol_id,
                code="US.AAPL",
                parameters=parameters,
                page_key="next-page",
            )
            assert result.parsed.terminal
            module = importlib.import_module(f"futu.common.pb.{module_names[protocol_id]}")
            request = module.Request()
            request.ParseFromString(fake.request_bodies[protocol_id][-1])
            assert request.c2s.HasField("nextKey")
            assert request.c2s.nextKey == "next-page"
        assert not guard.quarantined
    finally:
        adapter.close()
        fake.close()


@pytest.mark.parametrize(
    ("trade_logined", "trade_on_global_state_call"),
    [(False, None), (True, None), (False, 2)],
)
def test_fake_opend_guard_to_signed_uds_fetch(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    trade_logined: bool,
    trade_on_global_state_call: int | None,
) -> None:
    fake = FakeOpenD(
        trade_logined=trade_logined,
        trade_on_global_state_call=trade_on_global_state_call,
    )
    fake.start()
    guard = FrameGuardProxy(upstream_host="127.0.0.1", upstream_port=fake.port)
    guard.start()
    private_home = tmp_path / "sdk-home"
    private_home.mkdir(mode=0o700)
    adapter = OfficialFutuAdapter(guard=guard, private_home=private_home)

    cas_root = tmp_path / "cas"
    cas_root.mkdir(mode=0o700)
    cas = EncryptedCas(root=cas_root, key=b"\x02" * 32, key_id="test-key-1")
    seed = b"\x01" * 32
    identity = Ed25519Attestor.from_private_bytes(seed, signer_key_id="test-sidecar-key")
    seed_read, seed_write = os.pipe()
    os.write(seed_write, seed)
    os.close(seed_write)
    supervisor_socket, client_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    supervisor_failures: list[BaseException] = []
    repeated_protocol_plan = request_plan()
    repeated_protocol_plan.append(
        {
            **repeated_protocol_plan[1],
            "plan_index": len(repeated_protocol_plan),
            "security_code": "US.MSFT",
        }
    )
    daily_close_parameters = {
        "start": "2026-08-14",
        "end": "2026-08-14",
        "ktype": "K_DAY",
        "autype": "NONE",
        "fields": ["CLOSE", "VOLUME"],
        "max_count": 1,
        "extended_time": False,
        "session": "RTH",
    }
    for security_code, protocol_id, parameters in (
        ("US.AAPL", 3103, daily_close_parameters),
        ("US.MSFT", 3103, daily_close_parameters),
        ("US.AAPL", 3202, {}),
        ("US.MSFT", 3202, {}),
    ):
        repeated_protocol_plan.append(
            {
                "plan_index": len(repeated_protocol_plan),
                "security_code": security_code,
                "protocol_id": protocol_id,
                "parameters_sha256": canonical_sha256(parameters),
                "pagination_mode": "none",
                "maximum_pages": 1,
                "activation_condition": "always",
            }
        )
    repeated_protocol_plan.append(
        {
            "plan_index": len(repeated_protocol_plan),
            "security_code": "US.AAPL",
            "protocol_id": 3229,
            "parameters_sha256": canonical_sha256({}),
            "pagination_mode": "none",
            "maximum_pages": 1,
            "activation_condition": "eligible_conclusion_only",
        }
    )
    authorization, keyring = signed_runtime_authority(
        run_id="run:test-futu-sidecar",
        sidecar_signer_key_id="test-sidecar-key",
        plan=repeated_protocol_plan,
    )
    authorization_fd, keyring_fd = authority_fds(authorization, keyring)

    def supervise() -> None:
        try:
            serve_attestor(
                signer_socket=supervisor_socket,
                seed_fd=seed_read,
                authorization_fd=authorization_fd,
                authorization_keyring_fd=keyring_fd,
                signer_key_id="test-sidecar-key",
            )
        except BaseException as exc:  # test thread must propagate
            supervisor_failures.append(exc)

    supervisor_thread = threading.Thread(target=supervise, daemon=True)
    supervisor_thread.start()
    attestor = SupervisorAttestorClient(
        signer_socket=client_socket,
        expected_signer_key_id="test-sidecar-key",
        expected_public_key_hex=identity.public_key_hex,
    )
    controller = SessionController(
        attestor=attestor,
        supply_attestation=_supply(),
        runtime_claims=runtime_claims(authorization=authorization),
    )
    service = FutuSidecarService(adapter=adapter, cas=cas, controller=controller)
    socket_root = Path(
        tempfile.mkdtemp(prefix="oer-futu-", dir=Path(tempfile.gettempdir()).resolve())
    )
    os.chmod(socket_root, 0o700)
    socket_path = socket_root / "futu.sock"
    server = FutuSidecarServer(
        socket_path=socket_path,
        service=service,
        expected_peer_uid=os.getuid(),
    )
    server.start()
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        open_response = _exchange(
            socket_path,
            {
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "command": "open_quote_only_session",
                "run_id": "run:test-futu-sidecar",
                "challenge_nonce": "challenge-nonce-0123456789abcdef",
                "expected_supply_attestation": _supply(),
                "expected_signer_key_id": "test-sidecar-key",
                **open_expectations(authorization),
            },
        )
        boot = open_response["boot_attestation"]
        assert isinstance(boot, dict)
        Ed25519Attestor.verify(boot, public_key_hex=identity.public_key_hex)
        session_id = open_response["session_id"]
        request_fingerprint = "f" * 64

        def global_fingerprint(phase: str) -> str:
            return canonical_sha256(
                {
                    "schema_version": WIRE_SCHEMA_VERSION,
                    "operation": "GetGlobalState",
                    "protocol_id": 1002,
                    "run_id": "run:test-futu-sidecar",
                    "bound_data_request_fingerprint": request_fingerprint,
                    "phase": phase,
                }
            )

        fetch_response = _exchange(
            socket_path,
            {
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "command": "fetch_quote_data_with_global_state_guards",
                "run_id": "run:test-futu-sidecar",
                "request_id": "futu-request:test-history-quota",
                "request_fingerprint": request_fingerprint,
                "protocol": {"id": 3104, "name": "Qot_RequestHistoryKLQuota"},
                "security": {
                    "market": "US",
                    "code": "US.AAPL",
                    "security_id": "security:aapl-common",
                },
                "parameters": {"get_detail": True},
                "page_index": 0,
                "page_key": None,
                "expected_supply_attestation": _supply(),
                "global_state_guards": {
                    "protocol_id": 1002,
                    "required_pre_request_fingerprint": global_fingerprint("pre"),
                    "required_post_request_fingerprint": global_fingerprint("post"),
                    "qot_logined": True,
                },
                "session_id": session_id,
                "sequence": 1,
                "boot_receipt_id": boot["receipt_id"],
            },
        )
        Ed25519Attestor.verify(fetch_response, public_key_hex=identity.public_key_hex)
        assert fetch_response["sequence"] == 1
        assert fetch_response["session_id"] == session_id
        assert fetch_response["pre_global_state"]["trd_logined"] is (
            trade_logined or trade_on_global_state_call == 2
        )
        assert fetch_response["post_global_state"]["trd_logined"] is trade_logined
        observations = fetch_response["data_response"]["observations"]
        assert [item["field_id"] for item in observations] == [
            "history_quota_used",
            "history_quota_remaining",
            "history_quota_detail",
        ]
        assert observations[2]["value"] == "US.AAPL"

        second_request_fingerprint = "0" * 64

        def second_global_fingerprint(phase: str) -> str:
            return canonical_sha256(
                {
                    "schema_version": WIRE_SCHEMA_VERSION,
                    "operation": "GetGlobalState",
                    "protocol_id": 1002,
                    "run_id": "run:test-futu-sidecar",
                    "bound_data_request_fingerprint": second_request_fingerprint,
                    "phase": phase,
                }
            )

        second_fetch = _exchange(
            socket_path,
            {
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "command": "fetch_quote_data_with_global_state_guards",
                "run_id": "run:test-futu-sidecar",
                "request_id": "futu-request:test-profile",
                "request_fingerprint": second_request_fingerprint,
                "protocol": {"id": 3243, "name": "Qot_GetCompanyProfile"},
                "security": {
                    "market": "US",
                    "code": "US.AAPL",
                    "security_id": "security:aapl-common",
                },
                "parameters": {},
                "page_index": 0,
                "page_key": None,
                "expected_supply_attestation": _supply(),
                "global_state_guards": {
                    "protocol_id": 1002,
                    "required_pre_request_fingerprint": second_global_fingerprint("pre"),
                    "required_post_request_fingerprint": second_global_fingerprint("post"),
                    "qot_logined": True,
                },
                "session_id": session_id,
                "sequence": 2,
                "boot_receipt_id": boot["receipt_id"],
            },
        )
        Ed25519Attestor.verify(second_fetch, public_key_hex=identity.public_key_hex)
        assert second_fetch["sequence"] == 2
        assert second_fetch["data_response"]["observations"][0]["field_id"] == (
            "business_summary"
        )

        high_risk_specs = (
            ("US.MSFT", 3243, "Qot_GetCompanyProfile", {}),
            ("US.AAPL", 3103, "Qot_RequestHistoryKL", daily_close_parameters),
            ("US.MSFT", 3103, "Qot_RequestHistoryKL", daily_close_parameters),
            ("US.AAPL", 3202, "Qot_GetStaticInfo", {}),
            ("US.MSFT", 3202, "Qot_GetStaticInfo", {}),
        )
        for sequence, (code, protocol_id, protocol_name, parameters) in enumerate(
            high_risk_specs, start=3
        ):
            high_risk_fingerprint = f"{sequence:x}" * 64

            def high_risk_global_fingerprint(phase: str, bound: str = high_risk_fingerprint) -> str:
                return canonical_sha256(
                    {
                        "schema_version": WIRE_SCHEMA_VERSION,
                        "operation": "GetGlobalState",
                        "protocol_id": 1002,
                        "run_id": "run:test-futu-sidecar",
                        "bound_data_request_fingerprint": bound,
                        "phase": phase,
                    }
                )

            high_risk_response = _exchange(
                socket_path,
                {
                    "wire_schema_version": WIRE_SCHEMA_VERSION,
                    "command": "fetch_quote_data_with_global_state_guards",
                    "run_id": "run:test-futu-sidecar",
                    "request_id": f"futu-request:{protocol_id}:{code}",
                    "request_fingerprint": high_risk_fingerprint,
                    "protocol": {"id": protocol_id, "name": protocol_name},
                    "security": {
                        "market": "US",
                        "code": code,
                        "security_id": f"security:{code.lower()}",
                    },
                    "parameters": parameters,
                    "page_index": 0,
                    "page_key": None,
                    "expected_supply_attestation": _supply(),
                    "global_state_guards": {
                        "protocol_id": 1002,
                        "required_pre_request_fingerprint": (high_risk_global_fingerprint("pre")),
                        "required_post_request_fingerprint": (high_risk_global_fingerprint("post")),
                        "qot_logined": True,
                    },
                    "session_id": session_id,
                    "sequence": sequence,
                    "boot_receipt_id": boot["receipt_id"],
                },
            )
            Ed25519Attestor.verify(high_risk_response, public_key_hex=identity.public_key_hex)
            high_risk_observations = high_risk_response["data_response"]["observations"]
            if protocol_id == 3243:
                assert high_risk_observations[0]["field_id"] == "business_summary"
            elif protocol_id == 3103:
                assert [item["field_id"] for item in high_risk_observations] == [
                    "close",
                    "volume",
                ]
                assert all(
                    item["qualifiers"]
                    == {
                        "autype": "NONE",
                        "ktype": "K_DAY",
                        "price_basis": ("vendor_unadjusted_daily_close_rth_requested"),
                        "rth_semantics_attested": False,
                        "session": "RTH",
                    }
                    for item in high_risk_observations
                )
            else:
                assert [item["field_id"] for item in high_risk_observations] == [
                    "vendor_security_market",
                    "vendor_security_code",
                    "security_type",
                    "listing_mic",
                    "listing_date",
                    "delisting",
                    "vendor_security_id",
                    "lot_size",
                    "security_name",
                ]
                assert high_risk_observations[1]["value"] == code
                assert high_risk_observations[3]["value"] == "XNAS"

        conditional_fingerprint = "7" * 64

        def conditional_global_fingerprint(phase: str) -> str:
            return canonical_sha256(
                {
                    "schema_version": WIRE_SCHEMA_VERSION,
                    "operation": "GetGlobalState",
                    "protocol_id": 1002,
                    "run_id": "run:test-futu-sidecar",
                    "bound_data_request_fingerprint": conditional_fingerprint,
                    "phase": phase,
                }
            )

        conditional_fetch = _exchange(
            socket_path,
            {
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "command": "fetch_quote_data_with_global_state_guards",
                "run_id": "run:test-futu-sidecar",
                "request_id": "futu-request:test-consensus",
                "request_fingerprint": conditional_fingerprint,
                "protocol": {
                    "id": 3229,
                    "name": "Qot_GetResearchAnalystConsensus",
                },
                "security": {
                    "market": "US",
                    "code": "US.AAPL",
                    "security_id": "security:aapl-common",
                },
                "parameters": {},
                "page_index": 0,
                "page_key": None,
                "expected_supply_attestation": _supply(),
                "global_state_guards": {
                    "protocol_id": 1002,
                    "required_pre_request_fingerprint": conditional_global_fingerprint("pre"),
                    "required_post_request_fingerprint": conditional_global_fingerprint("post"),
                    "qot_logined": True,
                },
                "session_id": session_id,
                "sequence": 8,
                "boot_receipt_id": boot["receipt_id"],
            },
        )
        Ed25519Attestor.verify(conditional_fetch, public_key_hex=identity.public_key_hex)
        assert (
            conditional_fetch["data_response"]["observations"][0]["field_id"]
            == "average_target_price"
        )

        finalize_response = _exchange(
            socket_path,
            {
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "command": "finalize_quote_only_session",
                "run_id": "run:test-futu-sidecar",
                "session_id": session_id,
                "boot_receipt_id": boot["receipt_id"],
                "sequence": 9,
                "conditional_plan_disposition": completed_disposition(),
            },
        )
        for receipt_name in (
            "runtime_isolation_receipt",
            "execution_attestation_receipt",
        ):
            Ed25519Attestor.verify(
                finalize_response[receipt_name], public_key_hex=attestor.public_key_hex
            )
        assert adapter.connect_attempts == 1
        assert fake.connection_count == 1
        assert fake.init_recv_notify is False
        assert fake.global_state_user_ids == [42] * 18
        assert fake.quota_request_shapes == [
            {"get_detail": True, "security_firm": 0}
        ]
        assert fake.history_request_shapes == [
            {
                "rehab_type": 0,
                "kl_type": 2,
                "market": 11,
                "code": code,
                "begin_time": "2026-08-14 00:00:00",
                "end_time": "2026-08-14 23:59:59",
                "maximum_rows": 1,
                "field_mask": 40,
                "next_key": b"",
                "extended_time": False,
                "session": 1,
            }
            for code in ("AAPL", "MSFT")
        ]
        assert fake.static_info_request_shapes == [
            {
                # The pinned SDK deliberately encodes these filters as Unknown
                # when an explicit code list is present. The list is the wire
                # authority for the requested US identity.
                "market": 0,
                "security_type": 0,
                "codes": [{"market": 11, "code": code}],
            }
            for code in ("AAPL", "MSFT")
        ]
        assert guard.dropped_pushes()[0].protocol_id == 1003
        assert not guard.quarantined
        assert not any(2000 <= protocol < 3000 for protocol in fake.protocols)
        assert len(controller.executions) == 8
        assert controller.checkpoints[0]["trd_logined"] is trade_logined
        assert controller.checkpoints[-1]["trd_logined"] is trade_logined
        for execution in controller.executions:
            assert cas.load(execution.cas_receipt) == execution.frame_exchange.response.raw
    finally:
        server.close()
        adapter.close()
        attestor.close()
        supervisor_thread.join(timeout=5)
        fake.close()
        server_thread.join(timeout=5)
        shutil.rmtree(socket_root, ignore_errors=True)
    assert supervisor_failures == []
    log_directory = private_home / ".com.futunn.FutuOpenD" / "Log"
    assert not log_directory.exists() or not tuple(log_directory.iterdir())
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_quote_login_loss_closes_adapter_and_allows_idempotent_signed_abort(
    tmp_path: Path,
) -> None:
    fake = FakeOpenD(quote_lost_on_global_state_call=2)
    fake.start()
    guard = FrameGuardProxy(upstream_host="127.0.0.1", upstream_port=fake.port)
    guard.start()
    private_home = tmp_path / "quarantine-sdk-home"
    private_home.mkdir(mode=0o700)
    adapter = OfficialFutuAdapter(guard=guard, private_home=private_home)
    cas_root = tmp_path / "quarantine-cas"
    cas_root.mkdir(mode=0o700)
    attestor = Ed25519Attestor.from_private_bytes(b"\x03" * 32, signer_key_id="test-sidecar-key")
    authorization, _ = signed_runtime_authority(
        run_id="run:test-quarantine",
        sidecar_signer_key_id="test-sidecar-key",
    )
    controller = SessionController(
        attestor=attestor,
        supply_attestation=_supply(),
        runtime_claims=runtime_claims(authorization=authorization),
    )
    service = FutuSidecarService(
        adapter=adapter,
        cas=EncryptedCas(root=cas_root, key=b"\x04" * 32, key_id="test-key-2"),
        controller=controller,
    )
    try:
        opened = service.handle(
            {
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "command": "open_quote_only_session",
                "run_id": "run:test-quarantine",
                "challenge_nonce": "challenge-nonce-abcdef0123456789",
                "expected_supply_attestation": _supply(),
                "expected_signer_key_id": "test-sidecar-key",
                **open_expectations(authorization),
            }
        )
        boot = opened["boot_attestation"]
        request_fingerprint = "9" * 64

        def global_fingerprint(phase: str) -> str:
            return canonical_sha256(
                {
                    "schema_version": WIRE_SCHEMA_VERSION,
                    "operation": "GetGlobalState",
                    "protocol_id": 1002,
                    "run_id": "run:test-quarantine",
                    "bound_data_request_fingerprint": request_fingerprint,
                    "phase": phase,
                }
            )

        failed_fetch = {
            "wire_schema_version": WIRE_SCHEMA_VERSION,
            "command": "fetch_quote_data_with_global_state_guards",
            "run_id": "run:test-quarantine",
            "request_id": "futu-request:quarantined-quota",
            "request_fingerprint": request_fingerprint,
            "protocol": {"id": 3104, "name": "Qot_RequestHistoryKLQuota"},
            "security": {
                "market": "US",
                "code": "US.AAPL",
                "security_id": "security:aapl-common",
            },
            "parameters": {"get_detail": True},
            "page_index": 0,
            "page_key": None,
            "expected_supply_attestation": _supply(),
            "global_state_guards": {
                "protocol_id": 1002,
                "required_pre_request_fingerprint": global_fingerprint("pre"),
                "required_post_request_fingerprint": global_fingerprint("post"),
                "qot_logined": True,
            },
            "session_id": opened["session_id"],
            "sequence": 1,
            "boot_receipt_id": boot["receipt_id"],
        }
        with pytest.raises(FutuSidecarServerError, match="not quote-only"):
            service.handle(failed_fetch)
        assert guard.quarantined is False
        assert adapter._closed  # noqa: SLF001 - exact cleanup assertion

        abort_request = {
            "wire_schema_version": WIRE_SCHEMA_VERSION,
            "command": "abort_quote_only_session",
            "run_id": "run:test-quarantine",
            "session_id": opened["session_id"],
            "boot_receipt_id": boot["receipt_id"],
            "sequence": 1,
            "reason_code": "quote_login_lost",
        }
        aborted = service.handle(abort_request)
        assert set(aborted) == {
            "wire_schema_version",
            "command",
            "run_id",
            "session_id",
            "sequence",
            "abort_attestation",
        }
        Ed25519Attestor.verify(aborted["abort_attestation"], public_key_hex=attestor.public_key_hex)
        assert service.handle(abort_request) == aborted
        with pytest.raises((AttestationError, FutuSidecarServerError)):
            service.handle(failed_fetch)
    finally:
        adapter.close()
        fake.close()


def test_startup_actual_opend_identity_drift_quarantines(tmp_path: Path) -> None:
    fake = FakeOpenD(
        global_state_server_identity_overrides={1: (101007009, 2)}
    )
    fake.start()
    guard = FrameGuardProxy(upstream_host="127.0.0.1", upstream_port=fake.port)
    guard.start()
    private_home = tmp_path / "identity-drift-sdk-home"
    private_home.mkdir(mode=0o700)
    adapter = OfficialFutuAdapter(guard=guard, private_home=private_home)
    cas_root = tmp_path / "identity-drift-cas"
    cas_root.mkdir(mode=0o700)
    attestor = Ed25519Attestor.from_private_bytes(
        b"\x07" * 32, signer_key_id="identity-drift-sidecar-key"
    )
    authorization, _ = signed_runtime_authority(
        run_id="run:test-identity-drift",
        sidecar_signer_key_id="identity-drift-sidecar-key",
    )
    controller = SessionController(
        attestor=attestor,
        supply_attestation=_supply(),
        runtime_claims=runtime_claims(authorization=authorization),
    )
    service = FutuSidecarService(
        adapter=adapter,
        cas=EncryptedCas(root=cas_root, key=b"\x08" * 32, key_id="identity-drift-key"),
        controller=controller,
    )
    try:
        with pytest.raises(
            AttestationError,
            match="startup OpenD server identity differs from pinned supply",
        ):
            service.handle(
                {
                    "wire_schema_version": WIRE_SCHEMA_VERSION,
                    "command": "open_quote_only_session",
                    "run_id": "run:test-identity-drift",
                    "challenge_nonce": "challenge-nonce-identity-drift-0123456789",
                    "expected_supply_attestation": _supply(),
                    "expected_signer_key_id": "identity-drift-sidecar-key",
                    **open_expectations(authorization),
                }
            )
        assert fake.global_state_calls == 1
        assert controller.status is SessionStatus.QUARANTINED
        assert controller._quarantine_reason == "supply_attestation_mismatch"  # noqa: SLF001
        assert controller.checkpoints == []
        assert not guard.quarantined
    finally:
        adapter.close()
        fake.close()


def test_fetch_timestamps_are_sampled_after_responses_and_propagated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeOpenD()
    fake.start()
    guard = FrameGuardProxy(upstream_host="127.0.0.1", upstream_port=fake.port)
    guard.start()
    private_home = tmp_path / "completion-time-sdk-home"
    private_home.mkdir(mode=0o700)
    adapter = OfficialFutuAdapter(guard=guard, private_home=private_home)
    cas_root = tmp_path / "completion-time-cas"
    cas_root.mkdir(mode=0o700)
    attestor = Ed25519Attestor.from_private_bytes(
        b"\x09" * 32, signer_key_id="completion-time-sidecar-key"
    )
    run_id = "run:test-response-completion-time"
    authorization, _ = signed_runtime_authority(
        run_id=run_id,
        sidecar_signer_key_id="completion-time-sidecar-key",
    )
    controller = SessionController(
        attestor=attestor,
        supply_attestation=_supply(),
        runtime_claims=runtime_claims(authorization=authorization),
    )
    service = FutuSidecarService(
        adapter=adapter,
        cas=EncryptedCas(root=cas_root, key=b"\x0a" * 32, key_id="completion-time-key"),
        controller=controller,
    )
    try:
        opened = service.handle(
            {
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "command": "open_quote_only_session",
                "run_id": run_id,
                "challenge_nonce": "challenge-nonce-completion-time-0123456789",
                "expected_supply_attestation": _supply(),
                "expected_signer_key_id": "completion-time-sidecar-key",
                **open_expectations(authorization),
            }
        )
        boot = opened["boot_attestation"]

        base = datetime.now(UTC)
        sampled_times = {
            phase: (base + timedelta(microseconds=offset))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
            for phase, offset in (("pre", 1), ("data", 2), ("post", 3))
        }
        events: list[tuple[str, str]] = []
        clock_phases = iter(("pre", "data", "post"))

        def controlled_utc_now() -> str:
            phase = next(clock_phases)
            events.append(("clock", phase))
            return sampled_times[phase]

        global_phases = iter(("pre", "post"))
        original_global_state = adapter.global_state

        def completed_global_state() -> object:
            result = original_global_state()
            events.append(("response", next(global_phases)))
            return result

        original_fetch = adapter.fetch

        def completed_fetch(
            *,
            protocol_id: int,
            code: str,
            parameters: dict[str, object],
            page_key: str | None,
        ) -> object:
            result = original_fetch(
                protocol_id=protocol_id,
                code=code,
                parameters=parameters,
                page_key=page_key,
            )
            events.append(("response", "data"))
            return result

        monkeypatch.setattr(sidecar_server, "utc_now", controlled_utc_now)
        monkeypatch.setattr(adapter, "global_state", completed_global_state)
        monkeypatch.setattr(adapter, "fetch", completed_fetch)

        request_fingerprint = "8" * 64

        def global_fingerprint(phase: str) -> str:
            return canonical_sha256(
                {
                    "schema_version": WIRE_SCHEMA_VERSION,
                    "operation": "GetGlobalState",
                    "protocol_id": 1002,
                    "run_id": run_id,
                    "bound_data_request_fingerprint": request_fingerprint,
                    "phase": phase,
                }
            )

        fetch_response = service.handle(
            {
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "command": "fetch_quote_data_with_global_state_guards",
                "run_id": run_id,
                "request_id": "futu-request:completion-time-quota",
                "request_fingerprint": request_fingerprint,
                "protocol": {"id": 3104, "name": "Qot_RequestHistoryKLQuota"},
                "security": {
                    "market": "US",
                    "code": "US.AAPL",
                    "security_id": "security:aapl-common",
                },
                "parameters": {"get_detail": True},
                "page_index": 0,
                "page_key": None,
                "expected_supply_attestation": _supply(),
                "global_state_guards": {
                    "protocol_id": 1002,
                    "required_pre_request_fingerprint": global_fingerprint("pre"),
                    "required_post_request_fingerprint": global_fingerprint("post"),
                    "qot_logined": True,
                },
                "session_id": opened["session_id"],
                "sequence": 1,
                "boot_receipt_id": boot["receipt_id"],
            }
        )

        assert events == [
            ("response", "pre"),
            ("clock", "pre"),
            ("response", "data"),
            ("clock", "data"),
            ("response", "post"),
            ("clock", "post"),
        ]
        assert fetch_response["pre_global_state"]["retrieved_at"] == sampled_times["pre"]
        assert fetch_response["data_response"]["retrieved_at"] == sampled_times["data"]
        assert fetch_response["post_global_state"]["retrieved_at"] == sampled_times["post"]
        assert [checkpoint["observed_at"] for checkpoint in controller.checkpoints[-2:]] == [
            sampled_times["pre"],
            sampled_times["post"],
        ]
        Ed25519Attestor.verify(fetch_response, public_key_hex=attestor.public_key_hex)
    finally:
        adapter.close()
        fake.close()


def test_signed_uds_can_skip_only_the_complete_conditional_suffix(
    tmp_path: Path,
) -> None:
    fake = FakeOpenD(push_notify_before_profile=False)
    fake.start()
    guard = FrameGuardProxy(upstream_host="127.0.0.1", upstream_port=fake.port)
    guard.start()
    private_home = tmp_path / "skip-sdk-home"
    private_home.mkdir(mode=0o700)
    adapter = OfficialFutuAdapter(guard=guard, private_home=private_home)
    cas_root = tmp_path / "skip-cas"
    cas_root.mkdir(mode=0o700)
    cas = EncryptedCas(root=cas_root, key=b"\x06" * 32, key_id="skip-key")
    sidecar_seed = b"\x05" * 32
    identity = Ed25519Attestor.from_private_bytes(sidecar_seed, signer_key_id="skip-sidecar-key")
    plan = request_plan(protocol_id=3104)
    plan.append(
        {
            "plan_index": 1,
            "security_code": "US.AAPL",
            "protocol_id": 3229,
            "parameters_sha256": canonical_sha256({}),
            "pagination_mode": "none",
            "maximum_pages": 1,
            "activation_condition": "eligible_conclusion_only",
        }
    )
    authorization, keyring = signed_runtime_authority(
        run_id="run:test-conditional-skip",
        sidecar_signer_key_id="skip-sidecar-key",
        plan=plan,
    )
    authorization_fd, keyring_fd = authority_fds(authorization, keyring)
    seed_read, seed_write = os.pipe()
    os.write(seed_write, sidecar_seed)
    os.close(seed_write)
    supervisor_socket, client_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    supervisor_failures: list[BaseException] = []

    def supervise() -> None:
        try:
            serve_attestor(
                signer_socket=supervisor_socket,
                seed_fd=seed_read,
                authorization_fd=authorization_fd,
                authorization_keyring_fd=keyring_fd,
                signer_key_id="skip-sidecar-key",
            )
        except BaseException as exc:
            supervisor_failures.append(exc)

    supervisor_thread = threading.Thread(target=supervise, daemon=True)
    supervisor_thread.start()
    attestor = SupervisorAttestorClient(
        signer_socket=client_socket,
        expected_signer_key_id="skip-sidecar-key",
        expected_public_key_hex=identity.public_key_hex,
    )
    controller = SessionController(
        attestor=attestor,
        supply_attestation=_supply(),
        runtime_claims=runtime_claims(authorization=authorization),
    )
    service = FutuSidecarService(adapter=adapter, cas=cas, controller=controller)
    socket_root = Path(
        tempfile.mkdtemp(prefix="oer-futu-skip-", dir=Path(tempfile.gettempdir()).resolve())
    )
    os.chmod(socket_root, 0o700)
    socket_path = socket_root / "futu.sock"
    server = FutuSidecarServer(
        socket_path=socket_path,
        service=service,
        expected_peer_uid=os.getuid(),
    )
    server.start()
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        opened = _exchange(
            socket_path,
            {
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "command": "open_quote_only_session",
                "run_id": "run:test-conditional-skip",
                "challenge_nonce": "conditional-skip-0123456789abcdef",
                "expected_supply_attestation": _supply(),
                "expected_signer_key_id": "skip-sidecar-key",
                **open_expectations(authorization),
            },
        )
        boot = opened["boot_attestation"]
        request_fingerprint = "8" * 64

        def global_fingerprint(phase: str) -> str:
            return canonical_sha256(
                {
                    "schema_version": WIRE_SCHEMA_VERSION,
                    "operation": "GetGlobalState",
                    "protocol_id": 1002,
                    "run_id": "run:test-conditional-skip",
                    "bound_data_request_fingerprint": request_fingerprint,
                    "phase": phase,
                }
            )

        _exchange(
            socket_path,
            {
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "command": "fetch_quote_data_with_global_state_guards",
                "run_id": "run:test-conditional-skip",
                "request_id": "futu-request:mandatory-history-quota",
                "request_fingerprint": request_fingerprint,
                "protocol": {"id": 3104, "name": "Qot_RequestHistoryKLQuota"},
                "security": {
                    "market": "US",
                    "code": "US.AAPL",
                    "security_id": "security:aapl-common",
                },
                "parameters": {"get_detail": True},
                "page_index": 0,
                "page_key": None,
                "expected_supply_attestation": _supply(),
                "global_state_guards": {
                    "protocol_id": 1002,
                    "required_pre_request_fingerprint": global_fingerprint("pre"),
                    "required_post_request_fingerprint": global_fingerprint("post"),
                    "qot_logined": True,
                },
                "session_id": opened["session_id"],
                "sequence": 1,
                "boot_receipt_id": boot["receipt_id"],
            },
        )
        disposition = {
            "status": "skipped",
            "skipped_plan_indices": [1],
            "reason_code": "partial_or_contested_conclusion",
            "conclusion_receipt_id": "futu-frozen-conclusion:test-skip",
            "conclusion_fingerprint": "5" * 64,
        }
        finalized = _exchange(
            socket_path,
            {
                "wire_schema_version": WIRE_SCHEMA_VERSION,
                "command": "finalize_quote_only_session",
                "run_id": "run:test-conditional-skip",
                "session_id": opened["session_id"],
                "boot_receipt_id": boot["receipt_id"],
                "sequence": 2,
                "conditional_plan_disposition": disposition,
            },
        )
        assert (
            finalized["execution_attestation_receipt"]["conditional_plan_disposition"]
            == disposition
        )
        assert (
            finalized["runtime_isolation_receipt"]["request_plan_fingerprint"]
            == authorization["request_plan_fingerprint"]
        )
        assert 3229 not in fake.protocols
    finally:
        server.close()
        adapter.close()
        attestor.close()
        supervisor_thread.join(timeout=5)
        fake.close()
        server_thread.join(timeout=5)
        shutil.rmtree(socket_root, ignore_errors=True)
    assert supervisor_failures == []
