from __future__ import annotations

import importlib
import os
import shutil
import socket
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, cast

import pytest

import owner_research_futu_sidecar.cas as cas_module
import owner_research_futu_sidecar.operation_registry as operation_registry_module
from owner_research_futu_sidecar.attestation import (
    AttestationError,
    Ed25519Attestor,
)
from owner_research_futu_sidecar.canonical import SidecarContractError, canonical_bytes
from owner_research_futu_sidecar.cas import CasError, EncryptedCas
from owner_research_futu_sidecar.frame_guard import (
    DEFAULT_US_QUOTE_PROTOCOL_IDS,
    FUTU_HEADER_SIZE,
    FrameExchange,
    FrameGuardError,
    FrameGuardProxy,
    pack_futu_frame,
    parse_futu_frame,
    receive_futu_frame,
)
from owner_research_futu_sidecar.opend_adapter import (
    OfficialFutuAdapter,
    OfficialFutuAdapterError,
    _decode_page_key,
    _validate_fetch,
)
from owner_research_futu_sidecar.operation_registry import (
    PINNED_SDK_SDIST_SHA256,
    PINNED_SDK_VERSION,
    PROTOBUF_DESCRIPTOR_SET_SHA256,
    SDK_ADAPTER_REGISTRY_SHA256,
    verify_installed_sdk,
)
from owner_research_futu_sidecar.protobuf_parser import (
    ProtobufParserError,
    parse_data_response,
)
from owner_research_futu_sidecar.runtime_authorization import (
    RuntimeAuthorizationError,
    verify_runtime_authorization,
)
from owner_research_futu_sidecar.sdk_logging import (
    FutuSdkLogBoundary,
    FutuSdkLogError,
)
from owner_research_futu_sidecar.server import (
    FutuSidecarServer,
    FutuSidecarServerError,
)
from owner_research_futu_sidecar.supply_identity import (
    SIDECAR_PROVIDER_ID,
    SIDECAR_PROVIDER_VERSION,
    SupplyIdentityError,
    verify_local_supply_attestation,
    verify_local_supply_identity,
)

from .auth_helpers import request_plan, runtime_claims, signed_runtime_authority


def _wait_for(predicate: object, *, timeout: float = 3) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():  # type: ignore[operator]
        if time.monotonic() >= deadline:
            raise AssertionError("timed out waiting for test condition")
        time.sleep(0.01)


def _exchange_for_parser(
    protocol_id: int, request: Any, response: Any, *, serial_number: int
) -> FrameExchange:
    request_raw = pack_futu_frame(protocol_id, serial_number, request.SerializeToString())
    response_raw = pack_futu_frame(protocol_id, serial_number, response.SerializeToString())
    return FrameExchange(
        sequence=1,
        protocol_id=protocol_id,
        serial_number=serial_number,
        request=parse_futu_frame(request_raw[:FUTU_HEADER_SIZE], request_raw[FUTU_HEADER_SIZE:]),
        response=parse_futu_frame(response_raw[:FUTU_HEADER_SIZE], response_raw[FUTU_HEADER_SIZE:]),
        completed_monotonic=time.monotonic(),
    )


def test_pinned_sdk_introspection_is_real() -> None:
    verified = verify_installed_sdk()
    assert verified["operation_count"] == 16
    assert verified["futu_api_version"] == "10.10.7008"
    assert len(verified["operations"]) == 16


def test_runtime_replays_local_source_and_supply_identity() -> None:
    local = verify_local_supply_identity()
    attestation = {
        "supply_receipt_fingerprint": "a" * 64,
        "provider_id": SIDECAR_PROVIDER_ID,
        "provider_version": SIDECAR_PROVIDER_VERSION,
        "opend_version": PINNED_SDK_VERSION,
        "opend_server_version": 101007008,
        "opend_server_build_no": 1,
        "futu_api_version": PINNED_SDK_VERSION,
        "futu_api_distribution_sha256": PINNED_SDK_SDIST_SHA256,
        "sdk_operation_registry_sha256": SDK_ADAPTER_REGISTRY_SHA256,
        "protobuf_descriptor_set_sha256": PROTOBUF_DESCRIPTOR_SET_SHA256,
        "protocol_descriptor_sha256": local.protocol_descriptor_sha256,
        "facade_sha256": local.facade_sha256,
        "adapter_sha256": local.adapter_sha256,
        "parser_sha256": local.parser_sha256,
    }
    assert verify_local_supply_attestation(attestation) == attestation
    rebound = {**attestation, "adapter_sha256": "f" * 64}
    with pytest.raises(SupplyIdentityError, match="installed sidecar source bytes"):
        verify_local_supply_attestation(rebound)


def test_sdk_runtime_tree_rejects_noncovered_module_tamper(tmp_path: Path) -> None:
    installed = Path(
        operation_registry_module.metadata.distribution("futu-api").locate_file("futu")
    )
    copied = tmp_path / "futu"
    shutil.copytree(installed, copied, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    quote_query = copied / "quote" / "quote_query.py"
    quote_query.write_bytes(quote_query.read_bytes() + b"\n# tampered request packer\n")

    class FakeDistribution:
        version = "10.10.7008"

        @staticmethod
        def locate_file(name: str) -> Path:
            assert name == "futu"
            return copied

    with pytest.raises(SidecarContractError, match="quote/quote_query.py"):
        operation_registry_module._verify_runtime_tree(  # noqa: SLF001
            FakeDistribution(),
            budget=operation_registry_module.ReadBudget(
                operation_registry_module.MAXIMUM_SDK_CUMULATIVE_BYTES
            ),
        )


def test_sdk_runtime_tree_rejects_injected_bytecode_cache(tmp_path: Path) -> None:
    installed = Path(
        operation_registry_module.metadata.distribution("futu-api").locate_file("futu")
    )
    copied = tmp_path / "futu"
    shutil.copytree(installed, copied, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    injected = copied / "quote" / "__pycache__"
    injected.mkdir()
    (injected / f"quote_query.{sys.implementation.cache_tag}.pyc").write_bytes(
        b"malicious bytecode"
    )

    class FakeDistribution:
        version = "10.10.7008"

        @staticmethod
        def locate_file(name: str) -> Path:
            assert name == "futu"
            return copied

    with pytest.raises(SidecarContractError, match="bytecode cache"):
        operation_registry_module._verify_runtime_tree(  # noqa: SLF001
            FakeDistribution(),
            budget=operation_registry_module.ReadBudget(
                operation_registry_module.MAXIMUM_SDK_CUMULATIVE_BYTES
            ),
        )


def test_attestation_detects_payload_signature_and_key_rebinding() -> None:
    signer = Ed25519Attestor.from_private_bytes(b"\x11" * 32, signer_key_id="key-a")
    signed = signer.sign({"kind": "test", "counter": 1})
    signer.verify(signed, public_key_hex=signer.public_key_hex)

    changed = dict(signed)
    changed["counter"] = 2
    with pytest.raises(AttestationError):
        signer.verify(changed, public_key_hex=signer.public_key_hex)
    changed = dict(signed)
    changed["signature_hex"] = "00" * 64
    with pytest.raises(AttestationError):
        signer.verify(changed, public_key_hex=signer.public_key_hex)
    other = Ed25519Attestor.from_private_bytes(b"\x12" * 32, signer_key_id="key-b")
    with pytest.raises(AttestationError):
        signer.verify(signed, public_key_hex=other.public_key_hex)


def test_adapter_maps_every_governed_enum_family_to_pinned_sdk_constants() -> None:
    from futu.common.constant import (
        KL_FIELD,
        AuType,
        Currency,
        F10Type,
        KLType,
        Market,
        ResearchRatingDimensionType,
        SecurityType,
        Session,
    )

    class RecordingContext:
        def __init__(self) -> None:
            self.calls: list[tuple[str, tuple[Any, ...]]] = []

        def __getattr__(self, name: str) -> Any:
            def record(*args: Any) -> tuple[int, object]:
                self.calls.append((name, args))
                return 0, object()

            return record

        def get_history_kl_quota(self, *, get_detail: bool) -> tuple[int, object]:
            self.calls.append(("get_history_kl_quota", (get_detail,)))
            return 0, object()

    context = RecordingContext()
    adapter = object.__new__(OfficialFutuAdapter)
    adapter._context = context  # noqa: SLF001 - pinned invocation-shape conformance
    history = {
        "start": "2026-08-14",
        "end": "2026-08-14",
        "ktype": "K_DAY",
        "autype": "NONE",
        "fields": ["CLOSE", "VOLUME"],
        "max_count": 1,
        "extended_time": False,
        "session": "RTH",
    }
    adapter._invoke(  # noqa: SLF001 - pinned invocation-shape conformance
        protocol_id=3103, code="US.AAPL", parameters=history, page_key=None
    )
    assert context.calls.pop() == (
        "request_history_kline",
        (
            "US.AAPL",
            "2026-08-14",
            "2026-08-14",
            KLType.K_DAY,
            AuType.NONE,
            [KL_FIELD.CLOSE, KL_FIELD.TRADE_VOL],
            1,
            None,
            False,
            Session.RTH,
        ),
    )
    adapter._invoke(  # noqa: SLF001 - pinned invocation-shape conformance
        protocol_id=3104,
        code="US.AAPL",
        parameters={"get_detail": True},
        page_key=None,
    )
    assert context.calls.pop() == ("get_history_kl_quota", (True,))
    adapter._invoke(  # noqa: SLF001 - pinned invocation-shape conformance
        protocol_id=3202, code="US.AAPL", parameters={}, page_key=None
    )
    assert context.calls.pop() == (
        "get_stock_basicinfo",
        (Market.US, SecurityType.STOCK, ["US.AAPL"]),
    )
    adapter._invoke(  # noqa: SLF001 - pinned invocation-shape conformance
        protocol_id=3227,
        code="US.AAPL",
        parameters={
            "statement_type": 1,
            "financial_type": 7,
            "currency_code": "USD",
            "num": 50,
        },
        page_key=None,
    )
    assert context.calls.pop() == (
        "get_financials_statements",
        ("US.AAPL", 1, F10Type.ANNUAL, Currency.USD, None, 50),
    )
    adapter._invoke(  # noqa: SLF001 - pinned invocation-shape conformance
        protocol_id=3228,
        code="US.AAPL",
        parameters={"date": 0, "financial_type": 7, "currency_code": "USD"},
        page_key=None,
    )
    assert context.calls.pop() == (
        "get_financials_revenue_breakdown",
        ("US.AAPL", 0, F10Type.ANNUAL, Currency.USD),
    )
    adapter._invoke(  # noqa: SLF001 - pinned invocation-shape conformance
        protocol_id=3230,
        code="US.AAPL",
        parameters={"rating_dimension_type": 1, "uid": None, "num": 20},
        page_key=None,
    )
    assert context.calls.pop() == (
        "get_research_rating_summary",
        ("US.AAPL", ResearchRatingDimensionType.INSTITUTION, None, 20, None),
    )
    adapter._invoke(  # noqa: SLF001 - pinned invocation-shape conformance
        protocol_id=3232, code="US.AAPL", parameters={}, page_key=None
    )
    assert context.calls.pop() == (
        "get_valuation_detail",
        ("US.AAPL", None, None),
    )
    adapter._invoke(  # noqa: SLF001 - pinned invocation-shape conformance
        protocol_id=3246,
        code="US.AAPL",
        parameters={"num": 50, "currency_code": "USD"},
        page_key=None,
    )
    assert context.calls.pop() == (
        "get_company_operational_efficiency",
        ("US.AAPL", 50, None, Currency.USD),
    )


@pytest.mark.parametrize(
    ("protocol_id", "parameters"),
    [
        (3104, {"get_detail": False}),
        (3104, {"get_detail": 1}),
        (
            3103,
            {
                "start": "2026-08-14",
                "end": "2026-08-14",
                "ktype": "K_DAY",
                "autype": "NONE",
                "fields": ["CLOSE", "VOLUME"],
                "max_count": True,
                "extended_time": False,
                "session": "RTH",
            },
        ),
        (
            3103,
            {
                "start": "2026-08-14",
                "end": "2026-08-14",
                "ktype": "K_DAY",
                "autype": "NONE",
                "fields": ["CLOSE", "VOLUME"],
                "max_count": 1,
                "extended_time": 0,
                "session": "RTH",
            },
        ),
        (
            3227,
            {
                "statement_type": True,
                "financial_type": 7,
                "currency_code": "USD",
                "num": 50,
            },
        ),
        (
            3228,
            {"date": False, "financial_type": 7, "currency_code": "USD"},
        ),
        (
            3230,
            {"rating_dimension_type": True, "uid": None, "num": 20},
        ),
        (3246, {"num": True, "currency_code": "USD"}),
    ],
)
def test_adapter_rejects_boolean_aliases_for_integer_and_boolean_fields(
    protocol_id: int, parameters: dict[str, Any]
) -> None:
    with pytest.raises(OfficialFutuAdapterError):
        _validate_fetch(protocol_id, "US.AAPL", parameters, None)


@pytest.mark.parametrize("protocol_id", [True, 3103.0, "3103"])
def test_adapter_rejects_protocol_identifier_type_aliases(protocol_id: Any) -> None:
    with pytest.raises(OfficialFutuAdapterError, match="exact integer"):
        _validate_fetch(protocol_id, "US.AAPL", {}, None)


def test_history_date_and_binary_page_key_have_one_canonical_encoding() -> None:
    invalid_date = {
        "start": "xxxxxxxxxx",
        "end": "xxxxxxxxxx",
        "ktype": "K_DAY",
        "autype": "NONE",
        "fields": ["CLOSE", "VOLUME"],
        "max_count": 1,
        "extended_time": False,
        "session": "RTH",
    }
    with pytest.raises(OfficialFutuAdapterError, match="date"):
        _validate_fetch(3103, "US.AAPL", invalid_date, None)
    assert _decode_page_key("b64:YWJj") == b"abc"
    for alias in ("b64:YWJj!!!!", "b64:YWI", "b64:YWI=="):
        with pytest.raises(OfficialFutuAdapterError, match="malformed"):
            _decode_page_key(alias)
    with pytest.raises(OfficialFutuAdapterError, match="non-paginated"):
        _validate_fetch(3103, "US.AAPL", invalid_date, "b64:YWJj")
    with pytest.raises(OfficialFutuAdapterError, match="terminal pagination"):
        _validate_fetch(
            3227,
            "US.AAPL",
            {
                "statement_type": 1,
                "financial_type": 7,
                "currency_code": "USD",
                "num": 10,
            },
            "-1",
        )


def test_runtime_claims_reject_unknown_protocol_and_expiry() -> None:
    values, _ = signed_runtime_authority(
        run_id="run:test-runtime-claims", sidecar_signer_key_id="sidecar-key"
    )
    values["allowed_protocol_ids"] = [1001, 1002, 1004, 9999]
    with pytest.raises(AttestationError):
        runtime_claims(authorization=values)
    values, _ = signed_runtime_authority(
        run_id="run:test-runtime-claims", sidecar_signer_key_id="sidecar-key"
    )
    values["expires_at"] = "2020-01-01T00:00:00Z"
    with pytest.raises(AttestationError):
        runtime_claims(authorization=values)


def test_runtime_authority_requires_exactly_one_leading_detailed_quota_request() -> None:
    valid = request_plan()
    invalid_plans = (
        [dict(item, plan_index=index) for index, item in enumerate(valid[1:])],
        [
            dict(item, plan_index=index)
            for index, item in enumerate((valid[1], valid[0]))
        ],
        [*valid, {**valid[0], "plan_index": len(valid)}],
    )
    for plan in invalid_plans:
        authorization, keyring = signed_runtime_authority(
            run_id="run:test-quota-plan",
            sidecar_signer_key_id="sidecar-key",
            plan=plan,
        )
        with pytest.raises(RuntimeAuthorizationError, match="request-plan identity"):
            verify_runtime_authorization(
                authorization_raw=canonical_bytes(authorization),
                keyring_raw=canonical_bytes(keyring),
                expected_sidecar_attestor_key_id="sidecar-key",
            )


def test_cas_authenticated_reload_and_truncated_envelope(tmp_path: Path) -> None:
    root = tmp_path / "cas"
    root.mkdir(mode=0o700)
    cas = EncryptedCas(root=root, key=b"\x22" * 32, key_id="test-cas")
    receipt = cas.store(b"exact raw protobuf frame")
    assert cas.load(receipt) == b"exact raw protobuf frame"
    member = root / receipt.encrypted_object_sha256[:2] / receipt.encrypted_object_sha256
    os.chmod(member, 0o600)
    member.write_bytes(b"short")
    os.chmod(member, 0o400)
    with pytest.raises(CasError):
        cas.load(receipt)


def test_cas_rejects_hardlink_and_destination_injection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "cas-hardlink"
    root.mkdir(mode=0o700)
    cas = EncryptedCas(root=root, key=b"\x23" * 32, key_id="test-cas")
    receipt = cas.store(b"licensed private raw data")
    member = root / receipt.encrypted_object_sha256[:2] / receipt.encrypted_object_sha256
    leaked = tmp_path / "leaked-object"
    os.link(member, leaked)
    with pytest.raises(CasError, match="singly linked"):
        cas.load(receipt)
    leaked.unlink()
    assert cas.load(receipt) == b"licensed private raw data"

    real_link = cas_module.os.link
    injected_path: Path | None = None

    def inject_destination(
        source: os.PathLike[str],
        destination: os.PathLike[str],
        *,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal injected_path
        del source, follow_symlinks
        injected_path = Path(destination)
        injected_path.write_bytes(b"attacker-controlled")
        os.chmod(injected_path, 0o400)
        raise FileExistsError

    monkeypatch.setattr(cas_module.os, "link", inject_destination)
    with pytest.raises(CasError, match="collision"):
        cas.store(b"another private raw object")
    assert injected_path is not None
    assert injected_path.read_bytes() == b"attacker-controlled"
    monkeypatch.setattr(cas_module.os, "link", real_link)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin fixed root alias")
def test_sidecar_runtime_paths_accept_logical_tmp_fixed_root_alias() -> None:
    test_root = Path(tempfile.mkdtemp(prefix="oer-sidecar-paths-", dir="/tmp"))
    server = FutuSidecarServer(
        socket_path=test_root / "sidecar.sock",
        service=cast(Any, object()),
        expected_peer_uid=os.getuid(),
    )
    try:
        assert test_root.parent == Path("/tmp")
        assert test_root.resolve(strict=True) != test_root

        server.start()
        assert stat.S_ISSOCK((test_root / "sidecar.sock").lstat().st_mode)

        cas_root = test_root / "cas"
        cas_root.mkdir(mode=0o700)
        cas = EncryptedCas(root=cas_root, key=b"\x24" * 32, key_id="darwin-test-cas")
        receipt = cas.store(b"logical tmp encrypted payload")
        assert cas.load(receipt) == b"logical tmp encrypted payload"

        private_home = test_root / "private-home"
        private_home.mkdir(mode=0o700)
        boundary = FutuSdkLogBoundary(private_home=private_home)
        boundary.log_directory.mkdir(mode=0o700, parents=True)
        transient_log = boundary.log_directory / "futu-sdk.log"
        transient_log.write_bytes(b"transient vendor log")
        boundary._remove_transient_files()  # noqa: SLF001 - path-boundary regression
        assert tuple(boundary.log_directory.iterdir()) == ()
    finally:
        server.close()
        shutil.rmtree(test_root)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin fixed root alias")
def test_sidecar_runtime_paths_still_reject_nested_user_symlink() -> None:
    test_root = Path(tempfile.mkdtemp(prefix="oer-sidecar-symlink-", dir="/tmp"))
    real_directory = test_root / "real"
    alias_directory = test_root / "alias"
    try:
        real_directory.mkdir(mode=0o700)
        alias_directory.symlink_to(real_directory, target_is_directory=True)

        with pytest.raises(CasError, match="symbolic link"):
            EncryptedCas(
                root=alias_directory,
                key=b"\x25" * 32,
                key_id="nested-symlink-cas",
            )
        with pytest.raises(FutuSdkLogError, match="exact owner-only directory"):
            FutuSdkLogBoundary(private_home=alias_directory)

        server = FutuSidecarServer(
            socket_path=alias_directory / "sidecar.sock",
            service=cast(Any, object()),
            expected_peer_uid=os.getuid(),
        )
        with pytest.raises(FutuSidecarServerError, match="private and owner-controlled"):
            server.start()
    finally:
        shutil.rmtree(test_root)


def test_receive_frame_rejects_half_header() -> None:
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b"FT\x00")
        left.close()
        with pytest.raises(FrameGuardError, match="closed during"):
            receive_futu_frame(right)


def test_frame_guard_normal_eof_is_not_quarantine() -> None:
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)

    def serve() -> None:
        connection, _ = upstream.accept()
        with connection:
            request = receive_futu_frame(connection)
            assert request is not None
            connection.sendall(pack_futu_frame(1002, request.serial_number, b"ok"))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    guard = FrameGuardProxy(upstream_host="127.0.0.1", upstream_port=upstream.getsockname()[1])
    guard.start()
    client = socket.create_connection((guard.host, guard.port))
    with client:
        client.sendall(pack_futu_frame(1002, 1, b"request"))
        assert receive_futu_frame(client) is not None
    thread.join(timeout=3)
    _wait_for(lambda: not guard._connections)  # noqa: SLF001 - lifecycle conformance
    assert not guard.quarantined
    guard.close()
    upstream.close()


def test_frame_guard_pending_eof_and_c2s_notify_quarantine() -> None:
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    received = threading.Event()

    def serve() -> None:
        connection, _ = upstream.accept()
        with connection:
            assert receive_futu_frame(connection) is not None
            received.set()
            time.sleep(1)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    guard = FrameGuardProxy(upstream_host="127.0.0.1", upstream_port=upstream.getsockname()[1])
    guard.start()
    client = socket.create_connection((guard.host, guard.port))
    client.sendall(pack_futu_frame(1002, 10, b"request"))
    assert received.wait(timeout=2)
    client.close()
    _wait_for(lambda: guard.quarantined)
    assert "pending_request" in (guard.quarantine_reason or "")
    guard.close()
    upstream.close()
    thread.join(timeout=2)

    second_upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    second_upstream.bind(("127.0.0.1", 0))
    second_upstream.listen(1)
    second_guard = FrameGuardProxy(
        upstream_host="127.0.0.1", upstream_port=second_upstream.getsockname()[1]
    )
    second_guard.start()
    second_client = socket.create_connection((second_guard.host, second_guard.port))
    with second_client:
        second_client.sendall(pack_futu_frame(1003, 11, b"forbidden"))
        _wait_for(lambda: second_guard.quarantined)
    assert "1003" in (second_guard.quarantine_reason or "")
    second_guard.close()
    second_upstream.close()


def test_guard_allowlist_rejects_unknown_protocol() -> None:
    with pytest.raises(FrameGuardError):
        FrameGuardProxy(
            upstream_host="127.0.0.1",
            upstream_port=11111,
            allowed_quote_protocol_ids=DEFAULT_US_QUOTE_PROTOCOL_IDS | {9999},
        )


def test_daily_close_parser_never_self_attests_rth_semantics() -> None:
    from futu.common.pb import Qot_RequestHistoryKL_pb2

    request = Qot_RequestHistoryKL_pb2.Request()
    request.c2s.rehabType = 0
    request.c2s.klType = 2
    request.c2s.security.market = 11
    request.c2s.security.code = "AAPL"
    request.c2s.beginTime = "2026-08-14 00:00:00"
    request.c2s.endTime = "2026-08-14 23:59:59"
    request.c2s.maxAckKLNum = 1
    request.c2s.needKLFieldsFlag = 40
    request.c2s.session = 1
    request.c2s.header.securityFirm = 0
    response = Qot_RequestHistoryKL_pb2.Response(retType=0, errCode=0)
    response.s2c.security.market = 11
    response.s2c.security.code = "AAPL"
    row = response.s2c.klList.add()
    row.time = "2026-08-14 00:00:00"
    row.isBlank = False
    row.closePrice = 220.25
    row.volume = 123456
    request_raw = pack_futu_frame(3103, 50, request.SerializeToString())
    response_raw = pack_futu_frame(3103, 50, response.SerializeToString())
    request_frame = parse_futu_frame(request_raw[:FUTU_HEADER_SIZE], request_raw[FUTU_HEADER_SIZE:])
    response_frame = parse_futu_frame(
        response_raw[:FUTU_HEADER_SIZE], response_raw[FUTU_HEADER_SIZE:]
    )
    parsed = parse_data_response(
        FrameExchange(
            sequence=1,
            protocol_id=3103,
            serial_number=50,
            request=request_frame,
            response=response_frame,
            completed_monotonic=time.monotonic(),
        )
    )
    for observation in parsed.observations:
        assert observation["qualifiers"]["price_basis"] == (
            "vendor_unadjusted_daily_close_rth_requested"
        )
        assert observation["qualifiers"]["rth_semantics_attested"] is False
        assert observation["qualifiers"]["session"] == "RTH"


def test_daily_close_parser_rejects_request_and_response_rebinding() -> None:
    from futu.common.pb import Qot_RequestHistoryKL_pb2

    def request() -> Any:
        value = Qot_RequestHistoryKL_pb2.Request()
        value.c2s.rehabType = 0
        value.c2s.klType = 2
        value.c2s.security.market = 11
        value.c2s.security.code = "AAPL"
        value.c2s.beginTime = "2026-08-14 00:00:00"
        value.c2s.endTime = "2026-08-14 23:59:59"
        value.c2s.maxAckKLNum = 1
        value.c2s.needKLFieldsFlag = 40
        value.c2s.session = 1
        value.c2s.header.securityFirm = 0
        return value

    def response() -> Any:
        value = Qot_RequestHistoryKL_pb2.Response(retType=0, errCode=0)
        value.s2c.security.market = 11
        value.s2c.security.code = "AAPL"
        row = value.s2c.klList.add()
        row.time = "2026-08-14 00:00:00"
        row.isBlank = False
        row.closePrice = 220.25
        row.volume = 123456
        return value

    invalid_pairs: list[tuple[Any, Any]] = []
    wrong_session = request()
    wrong_session.c2s.session = 0
    invalid_pairs.append((wrong_session, response()))
    wrong_fields = request()
    wrong_fields.c2s.needKLFieldsFlag = 8
    invalid_pairs.append((wrong_fields, response()))
    explicit_default = request()
    explicit_default.c2s.extendedTime = False
    invalid_pairs.append((explicit_default, response()))
    wrong_code = response()
    wrong_code.s2c.security.code = "MSFT"
    invalid_pairs.append((request(), wrong_code))
    wrong_date = response()
    wrong_date.s2c.klList[0].time = "2026-08-13 00:00:00"
    invalid_pairs.append((request(), wrong_date))
    paginated = response()
    paginated.s2c.nextReqKey = b"unexpected"
    invalid_pairs.append((request(), paginated))
    for index, (bound_request, bound_response) in enumerate(invalid_pairs, start=70):
        with pytest.raises(ProtobufParserError):
            parse_data_response(
                _exchange_for_parser(
                    3103,
                    bound_request,
                    bound_response,
                    serial_number=index,
                )
            )


def test_history_quota_parser_preserves_typed_detail_without_vendor_names() -> None:
    from futu.common.pb import Qot_RequestHistoryKLQuota_pb2

    request = Qot_RequestHistoryKLQuota_pb2.Request()
    request.c2s.bGetDetail = True
    request.c2s.header.securityFirm = 0
    response = Qot_RequestHistoryKLQuota_pb2.Response(retType=0, errCode=0)
    response.s2c.usedQuota = 2
    response.s2c.remainQuota = 298
    us = response.s2c.detailList.add()
    us.security.market = 11
    us.security.code = "AAPL"
    us.name = "must not escape normalized observations"
    us.requestTime = "2026-08-14 14:17:17"
    us.requestTimeStamp = 1_786_731_437
    hk = response.s2c.detailList.add()
    hk.security.market = 1
    hk.security.code = "00700"
    hk.requestTime = "2021-09-10 14:17:17"
    hk.requestTimeStamp = 1_631_254_637

    parsed = parse_data_response(
        _exchange_for_parser(3104, request, response, serial_number=90)
    )
    assert [item["field_id"] for item in parsed.observations] == [
        "history_quota_used",
        "history_quota_remaining",
        "history_quota_detail",
        "history_quota_detail",
    ]
    assert parsed.observations[0]["value"] == "2"
    assert parsed.observations[0]["unit"] == "distinct_securities"
    assert parsed.observations[0]["qualifiers"] == {
        "get_detail": True,
        "quota_kind": "historical_candlestick_distinct_security_7d",
        "quota_window_days": 7,
    }
    assert parsed.observations[2]["value"] == "US.AAPL"
    assert parsed.observations[2]["qualifiers"]["last_request_at"] == (
        "2026-08-14T18:17:17Z"
    )
    assert parsed.observations[3]["value"] == "1:00700"
    assert parsed.observations[3]["qualifiers"]["last_request_at"] == (
        "2021-09-10T06:17:17Z"
    )
    assert "must not escape" not in repr(parsed.observations)


def test_history_quota_parser_derives_missing_timestamp_and_rejects_drift() -> None:
    from futu.common.pb import Qot_RequestHistoryKLQuota_pb2

    def request(*, get_detail: bool = True) -> Any:
        value = Qot_RequestHistoryKLQuota_pb2.Request()
        value.c2s.bGetDetail = get_detail
        value.c2s.header.securityFirm = 0
        return value

    def response() -> Any:
        value = Qot_RequestHistoryKLQuota_pb2.Response(retType=0, errCode=0)
        value.s2c.usedQuota = 1
        value.s2c.remainQuota = 299
        detail = value.s2c.detailList.add()
        detail.security.market = 11
        detail.security.code = "AAPL"
        detail.requestTime = "2026-08-14 14:17:17"
        return value

    valid = parse_data_response(
        _exchange_for_parser(3104, request(), response(), serial_number=91)
    )
    assert valid.observations[2]["qualifiers"]["source_request_timestamp"] is None
    assert valid.observations[2]["qualifiers"]["last_request_at"] == (
        "2026-08-14T18:17:17Z"
    )

    mismatched = response()
    mismatched.s2c.detailList[0].requestTimeStamp = 1_786_731_438
    with pytest.raises(ProtobufParserError, match="disagree"):
        parse_data_response(
            _exchange_for_parser(3104, request(), mismatched, serial_number=92)
        )
    with pytest.raises(ProtobufParserError, match="get-detail"):
        parse_data_response(
            _exchange_for_parser(3104, request(get_detail=False), response(), serial_number=93)
        )
    incomplete = response()
    incomplete.s2c.usedQuota = 2
    with pytest.raises(ProtobufParserError, match="impossible counts"):
        parse_data_response(
            _exchange_for_parser(3104, request(), incomplete, serial_number=94)
        )


def test_financial_parser_binds_structure_and_only_derives_consecutive_flow_start() -> None:
    from futu.common.pb import Qot_GetFinancialsStatements_pb2

    request = Qot_GetFinancialsStatements_pb2.Request()
    request.c2s.security.market = 11
    request.c2s.security.code = "AAPL"
    request.c2s.statementType = 1
    request.c2s.financialType = 7
    request.c2s.currencyCode = "USD"
    request.c2s.num = 10
    response = Qot_GetFinancialsStatements_pb2.Response(retType=0, errCode=0)
    structure = response.s2c.structureList.add()
    structure.fieldId = 5001
    structure.displayName = "Total Revenue"
    for period_end, fiscal_year, value in (
        ("2025-09-27", 2025, 391_035_000_000.0),
        ("2024-09-28", 2024, 383_285_000_000.0),
    ):
        report = response.s2c.reportList.add()
        report.dateTimeStr = period_end
        report.fiscalYear = fiscal_year
        report.financialType = 7
        report.periodText = f"{fiscal_year}/FY"
        report.currencyCode = "USD"
        report.accountingStandards = "US_GAAP"
        report.auditorReport = "UNQUALIFIED"
        item = report.itemList.add()
        item.fieldId = 5001
        item.data = value
    response.s2c.nextKey = "-1"

    parsed = parse_data_response(
        _exchange_for_parser(3227, request, response, serial_number=95)
    )
    descriptor, current, oldest = parsed.observations
    assert descriptor == {
        "field_id": "financial_structure:5001",
        "period": {"start": None, "end": None},
        "qualifiers": {
            "financial_field_id": "5001",
            "futu_api_version": "10.10.7008",
            "normalized_display_name": "total revenue",
            "statement_type": "income",
        },
        "value_type": "text",
        "value": "Total Revenue",
        "unit": None,
        "currency": None,
        "binary64_hex": None,
        "exact_binary64_decimal": None,
    }
    assert current["period"] == {"start": "2024-09-29", "end": "2025-09-27"}
    assert oldest["period"] == {"start": None, "end": "2024-09-28"}
    assert current["qualifiers"]["statement_type"] == "income"

    missing_descriptor = Qot_GetFinancialsStatements_pb2.Response()
    missing_descriptor.CopyFrom(response)
    missing_descriptor.s2c.structureList[0].fieldId = 5034
    with pytest.raises(ProtobufParserError, match="bound numeric value"):
        parse_data_response(
            _exchange_for_parser(3227, request, missing_descriptor, serial_number=96)
        )


def test_revenue_breakdown_parser_preserves_dimension_segment_period_currency_and_ratio() -> None:
    from futu.common.pb import Qot_GetFinancialsRevenueBreakdown_pb2

    request = Qot_GetFinancialsRevenueBreakdown_pb2.Request()
    request.c2s.security.market = 11
    request.c2s.security.code = "AAPL"
    request.c2s.date = 0
    request.c2s.financialType = 7
    request.c2s.currencyCode = "USD"
    response = Qot_GetFinancialsRevenueBreakdown_pb2.Response(retType=0, errCode=0)
    response.s2c.period = "2025/FY"
    response.s2c.currencyCode = "USD"
    group = response.s2c.breakdownList.add()
    group.type = 1
    segment = group.itemList.add()
    segment.name = "Products"
    segment.mainOperIncome = 250_000_000_000.0
    segment.ratio = 62.5
    services = group.itemList.add()
    services.name = "Services"
    services.mainOperIncome = 150_000_000_000.0
    services.ratio = 37.5

    parsed = parse_data_response(
        _exchange_for_parser(3228, request, response, serial_number=961)
    )
    income, ratio, services_income, services_ratio = parsed.observations
    assert income["field_id"] == "revenue_breakdown_main_operating_income"
    assert income["value"] == "250000000000.0"
    assert income["currency"] == "USD"
    assert income["unit"] == "currency_units"
    assert income["period"] == {"start": None, "end": None}
    assert income["qualifiers"]["dimension_type"] == 1
    assert income["qualifiers"]["segment_name"] == "Products"
    assert income["qualifiers"]["vendor_period"] == "2025/FY"
    assert len(income["qualifiers"]["segment_identity"]) == 64
    assert ratio["field_id"] == "revenue_breakdown_ratio"
    assert ratio["value"] == "62.5"
    assert ratio["unit"] == "percent"
    assert ratio["currency"] is None
    assert ratio["qualifiers"]["segment_identity"] == (
        income["qualifiers"]["segment_identity"]
    )
    assert ratio["qualifiers"]["ratio_basis"] == "main_operating_income"
    assert income["qualifiers"]["normalized_segment_name"] == "products"
    assert services_income["qualifiers"]["normalized_segment_name"] == "services"
    assert services_ratio["value"] == "37.5"

    empty = Qot_GetFinancialsRevenueBreakdown_pb2.Response(retType=0, errCode=0)
    empty.s2c.SetInParent()
    empty_result = parse_data_response(
        _exchange_for_parser(3228, request, empty, serial_number=968)
    )
    assert empty_result.observations[0]["field_id"] == (
        "revenue_breakdown_segment_set"
    )
    assert empty_result.observations[0]["qualifiers"] == {
        "reason_code": "official_no_data",
        "segment_set_status": "empty",
    }


def test_revenue_breakdown_duplicate_or_sum_mismatch_blocks() -> None:
    from futu.common.pb import Qot_GetFinancialsRevenueBreakdown_pb2

    request = Qot_GetFinancialsRevenueBreakdown_pb2.Request()
    request.c2s.security.market = 11
    request.c2s.security.code = "AAPL"
    request.c2s.date = 0
    request.c2s.financialType = 7
    request.c2s.currencyCode = "USD"

    def response() -> Any:
        value = Qot_GetFinancialsRevenueBreakdown_pb2.Response(retType=0, errCode=0)
        value.s2c.period = "2025/FY"
        value.s2c.currencyCode = "USD"
        group = value.s2c.breakdownList.add()
        group.type = 1
        products = group.itemList.add()
        products.name = "Products"
        products.mainOperIncome = 60.0
        products.ratio = 60.0
        services = group.itemList.add()
        services.name = "Services"
        services.mainOperIncome = 40.0
        services.ratio = 40.0
        return value

    duplicate = response()
    duplicate.s2c.breakdownList[0].itemList[1].name = " products "
    with pytest.raises(ProtobufParserError, match="segment is incomplete"):
        parse_data_response(
            _exchange_for_parser(3228, request, duplicate, serial_number=965)
        )

    sum_mismatch = response()
    sum_mismatch.s2c.breakdownList[0].itemList[1].ratio = 30.0
    with pytest.raises(ProtobufParserError, match="reconcile to its total"):
        parse_data_response(
            _exchange_for_parser(3228, request, sum_mismatch, serial_number=966)
        )

    value_mismatch = response()
    value_mismatch.s2c.breakdownList[0].itemList[0].mainOperIncome = 90.0
    with pytest.raises(ProtobufParserError, match="ratio does not reconcile"):
        parse_data_response(
            _exchange_for_parser(3228, request, value_mismatch, serial_number=967)
        )


def test_dividend_parser_preserves_one_event_identity() -> None:
    from futu.common.pb import Qot_GetCorporateActionsDividends_pb2

    request = Qot_GetCorporateActionsDividends_pb2.Request()
    request.c2s.security.market = 11
    request.c2s.security.code = "AAPL"
    response = Qot_GetCorporateActionsDividends_pb2.Response(retType=0, errCode=0)
    event = response.s2c.dividendList.add()
    event.pubDate = "2026/07/31"
    event.statement = "USD 0.25 cash dividend"
    event.recordDate = "2026/08/10"
    event.exDate = "2026/08/09"
    event.dividendPayableDate = "2026/08/15"

    parsed = parse_data_response(
        _exchange_for_parser(3234, request, response, serial_number=962)
    )
    assert len(parsed.observations) == 1
    dividend = parsed.observations[0]
    assert dividend["field_id"] == "dividend_event"
    assert dividend["value"] == "USD 0.25 cash dividend"
    assert dividend["period"] == {"start": None, "end": "2026-08-09"}
    assert dividend["qualifiers"] == {
        "event_identity": dividend["qualifiers"]["event_identity"],
        "ex_date": "2026-08-09",
        "fiscal_year": None,
        "payable_date": "2026-08-15",
        "process": None,
        "publication_date": "2026-07-31",
        "record_date": "2026-08-10",
    }
    assert len(dividend["qualifiers"]["event_identity"]) == 64

    empty = Qot_GetCorporateActionsDividends_pb2.Response(retType=0, errCode=0)
    empty.s2c.SetInParent()
    empty_result = parse_data_response(
        _exchange_for_parser(3234, request, empty, serial_number=968)
    )
    assert empty_result.observations[0]["field_id"] == "dividend_event_set"
    assert empty_result.observations[0]["qualifiers"] == {
        "event_set_status": "empty",
        "reason_code": "official_no_data",
    }


def test_dividend_date_statement_and_us_field_drift_blocks() -> None:
    from futu.common.pb import Qot_GetCorporateActionsDividends_pb2

    request = Qot_GetCorporateActionsDividends_pb2.Request()
    request.c2s.security.market = 11
    request.c2s.security.code = "AAPL"

    def response() -> Any:
        value = Qot_GetCorporateActionsDividends_pb2.Response(retType=0, errCode=0)
        event = value.s2c.dividendList.add()
        event.pubDate = "2026/07/31"
        event.statement = "USD 0.25 cash dividend"
        event.recordDate = "2026/08/10"
        return value

    invalid_date = response()
    invalid_date.s2c.dividendList[0].recordDate = "2026/02/30"
    with pytest.raises(ProtobufParserError, match="canonical calendar date"):
        parse_data_response(
            _exchange_for_parser(3234, request, invalid_date, serial_number=969)
        )

    blank_statement = response()
    blank_statement.s2c.dividendList[0].statement = " "
    with pytest.raises(ProtobufParserError, match="publication date or statement"):
        parse_data_response(
            _exchange_for_parser(3234, request, blank_statement, serial_number=970)
        )

    hk_only = response()
    hk_only.s2c.dividendList[0].process = "implemented"
    with pytest.raises(ProtobufParserError, match="market- or fund-specific"):
        parse_data_response(
            _exchange_for_parser(3234, request, hk_only, serial_number=971)
        )


def test_stock_split_parser_emits_ratio_event_and_no_numeric_current_shares() -> None:
    from futu.common.pb import Qot_GetCorporateActionsStockSplits_pb2

    request = Qot_GetCorporateActionsStockSplits_pb2.Request()
    request.c2s.security.market = 11
    request.c2s.security.code = "AAPL"
    response = Qot_GetCorporateActionsStockSplits_pb2.Response(retType=0, errCode=0)
    item = response.s2c.splitItemList.add()
    item.dirDeciPubDateStr = "2020-07-30"
    item.reformType = "Split"
    item.rate = "2.5->10"
    response.s2c.nextKey = "-1"

    parsed = parse_data_response(
        _exchange_for_parser(3236, request, response, serial_number=97)
    )
    assert parsed.observations == (
        {
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
        },
        {
            "field_id": "stock_split_event",
            "period": {"start": None, "end": "2020-07-30"},
            "qualifiers": {
                "announcement_date": "2020-07-30",
                "current_shares_status": "vendor_not_supported",
                "effective_date": None,
                "event_type": "stock_split_completed",
                "rate_denominator": "1",
                "rate_numerator": "4",
                "rate_raw": "2.5->10",
                "reform_type": "Split",
            },
            "value_type": "text",
            "value": "4/1",
            "unit": "split_ratio",
            "currency": None,
            "binary64_hex": None,
            "exact_binary64_decimal": None,
        },
    )
    empty = Qot_GetCorporateActionsStockSplits_pb2.Response(retType=0, errCode=0)
    empty.s2c.nextKey = "-1"
    empty_result = parse_data_response(
        _exchange_for_parser(3236, request, empty, serial_number=98)
    )
    assert tuple(item["field_id"] for item in empty_result.observations) == (
        "current_common_shares",
        "stock_split_event_set",
    )
    assert empty_result.observations[1]["qualifiers"] == {
        "event_set_status": "empty",
        "reason_code": "official_no_data",
    }

    invalid_rate = Qot_GetCorporateActionsStockSplits_pb2.Response()
    invalid_rate.CopyFrom(response)
    invalid_rate.s2c.splitItemList[0].rate = "4:1"
    with pytest.raises(ProtobufParserError, match="before-to-after"):
        parse_data_response(
            _exchange_for_parser(3236, request, invalid_rate, serial_number=99)
        )

    hk_only = Qot_GetCorporateActionsStockSplits_pb2.Response()
    hk_only.CopyFrom(response)
    hk_only.s2c.splitItemList[0].exDateStr = "2020-08-31"
    with pytest.raises(ProtobufParserError, match="Hong Kong-only"):
        parse_data_response(
            _exchange_for_parser(3236, request, hk_only, serial_number=991)
        )

    shares_after_effect = Qot_GetCorporateActionsStockSplits_pb2.Response()
    shares_after_effect.CopyFrom(response)
    shares_after_effect.s2c.splitItemList[0].sharesAfterEffect = 17_528_214_000.0
    with pytest.raises(ProtobufParserError, match="Hong Kong-only"):
        parse_data_response(
            _exchange_for_parser(3236, request, shares_after_effect, serial_number=992)
        )


def test_multi_page_us_split_history_has_one_current_share_disposition() -> None:
    from futu.common.pb import Qot_GetCorporateActionsStockSplits_pb2

    first_request = Qot_GetCorporateActionsStockSplits_pb2.Request()
    first_request.c2s.security.market = 11
    first_request.c2s.security.code = "AAPL"
    first_response = Qot_GetCorporateActionsStockSplits_pb2.Response(
        retType=0,
        errCode=0,
    )
    first_response.s2c.nextKey = "page-2"
    first = parse_data_response(
        _exchange_for_parser(3236, first_request, first_response, serial_number=963)
    )

    second_request = Qot_GetCorporateActionsStockSplits_pb2.Request()
    second_request.c2s.security.market = 11
    second_request.c2s.security.code = "AAPL"
    second_request.c2s.nextKey = "page-2"
    second_response = Qot_GetCorporateActionsStockSplits_pb2.Response(
        retType=0,
        errCode=0,
    )
    split = second_response.s2c.splitItemList.add()
    split.dirDeciPubDateStr = "2020-07-30"
    split.reformType = "Split"
    split.rate = "1->4"
    second_response.s2c.nextKey = "-1"
    second = parse_data_response(
        _exchange_for_parser(3236, second_request, second_response, serial_number=964)
    )

    combined = (*first.observations, *second.observations)
    assert sum(item["field_id"] == "current_common_shares" for item in combined) == 1
    assert sum(item["field_id"] == "stock_split_event" for item in combined) == 1


def test_static_info_parser_rejects_wrong_identity_type_and_listing() -> None:
    from futu.common.pb import Qot_GetStaticInfo_pb2

    def request() -> Any:
        value = Qot_GetStaticInfo_pb2.Request()
        value.c2s.market = 0
        value.c2s.secType = 0
        security = value.c2s.securityList.add()
        security.market = 11
        security.code = "AAPL"
        value.c2s.header.securityFirm = 0
        return value

    def response() -> Any:
        value = Qot_GetStaticInfo_pb2.Response(retType=0, errCode=0)
        basic = value.s2c.staticInfoList.add().basic
        basic.security.market = 11
        basic.security.code = "AAPL"
        basic.id = 1
        basic.lotSize = 1
        basic.secType = 3
        basic.name = "Apple Inc."
        basic.listTime = "1980-12-12"
        basic.delisting = False
        basic.exchType = 5
        return value

    valid = parse_data_response(_exchange_for_parser(3202, request(), response(), serial_number=80))
    assert [item["field_id"] for item in valid.observations] == [
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
    missing_explicit_filter = request()
    missing_explicit_filter.c2s.ClearField("market")
    with pytest.raises(ProtobufParserError):
        parse_data_response(
            _exchange_for_parser(
                3202,
                missing_explicit_filter,
                response(),
                serial_number=79,
            )
        )
    invalid_responses = []
    wrong_code = response()
    wrong_code.s2c.staticInfoList[0].basic.security.code = "MSFT"
    invalid_responses.append(wrong_code)
    wrong_type = response()
    wrong_type.s2c.staticInfoList[0].basic.secType = 5
    invalid_responses.append(wrong_type)
    delisted = response()
    delisted.s2c.staticInfoList[0].basic.delisting = True
    invalid_responses.append(delisted)
    unsupported_exchange = response()
    unsupported_exchange.s2c.staticInfoList[0].basic.exchType = 7
    invalid_responses.append(unsupported_exchange)
    multiple = response()
    multiple.s2c.staticInfoList.add().CopyFrom(multiple.s2c.staticInfoList[0])
    invalid_responses.append(multiple)
    for index, invalid in enumerate(invalid_responses, start=81):
        with pytest.raises(ProtobufParserError):
            parse_data_response(_exchange_for_parser(3202, request(), invalid, serial_number=index))


@pytest.mark.parametrize(
    ("protocol_id", "module_name"),
    [
        (3229, "Qot_GetResearchAnalystConsensus_pb2"),
        (3230, "Qot_GetResearchRatingSummary_pb2"),
        (3232, "Qot_GetValuationDetail_pb2"),
        (3244, "Qot_GetCompanyExecutives_pb2"),
        (3245, "Qot_GetCompanyExecutiveBackground_pb2"),
        (3246, "Qot_GetCompanyOperationalEfficiency_pb2"),
    ],
)
def test_optional_official_empty_payload_has_closed_unavailable_observation(
    protocol_id: int, module_name: str
) -> None:
    module = importlib.import_module(f"futu.common.pb.{module_name}")
    request = module.Request()
    request.c2s.security.market = 11
    request.c2s.security.code = "AAPL"
    if protocol_id == 3228:
        request.c2s.date = 0
        request.c2s.financialType = 7
        request.c2s.currencyCode = "USD"
    if protocol_id == 3230:
        request.c2s.ratingDimensionType = 1
        request.c2s.num = 20
    if protocol_id == 3245:
        request.c2s.leaderName = "Tim Cook"
    if protocol_id == 3246:
        request.c2s.num = 50
        request.c2s.currencyCode = "USD"
    response = module.Response(retType=0, errCode=0)
    response.s2c.SetInParent()
    request_raw = pack_futu_frame(protocol_id, 60, request.SerializeToString(deterministic=True))
    response_raw = pack_futu_frame(protocol_id, 60, response.SerializeToString())
    parsed = parse_data_response(
        FrameExchange(
            sequence=1,
            protocol_id=protocol_id,
            serial_number=60,
            request=parse_futu_frame(
                request_raw[:FUTU_HEADER_SIZE], request_raw[FUTU_HEADER_SIZE:]
            ),
            response=parse_futu_frame(
                response_raw[:FUTU_HEADER_SIZE], response_raw[FUTU_HEADER_SIZE:]
            ),
            completed_monotonic=time.monotonic(),
        )
    )
    assert parsed.observations == (
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
        },
    )


def test_required_company_profile_empty_payload_is_rejected() -> None:
    from futu.common.pb import Qot_GetCompanyProfile_pb2

    request = Qot_GetCompanyProfile_pb2.Request()
    request.c2s.security.market = 11
    request.c2s.security.code = "AAPL"
    response = Qot_GetCompanyProfile_pb2.Response(retType=0, errCode=0)
    response.s2c.SetInParent()
    with pytest.raises(ProtobufParserError, match="company-profile response is empty"):
        parse_data_response(
            _exchange_for_parser(3243, request, response, serial_number=61)
        )


def test_buyback_protocol_never_materializes_a_futu_data_response() -> None:
    raw = pack_futu_frame(3235, 61, b"not-called")
    frame = parse_futu_frame(raw[:FUTU_HEADER_SIZE], raw[FUTU_HEADER_SIZE:])
    with pytest.raises(ProtobufParserError, match="not an eligible US data response"):
        parse_data_response(
            FrameExchange(
                sequence=1,
                protocol_id=3235,
                serial_number=61,
                request=frame,
                response=frame,
                completed_monotonic=time.monotonic(),
            )
        )


def test_uds_endpoint_requires_exact_modes_and_detects_replacement(tmp_path: Path) -> None:
    socket_parent = Path(
        tempfile.mkdtemp(prefix="oer-futu-uds-", dir=Path(tempfile.gettempdir()).resolve())
    )
    os.chmod(socket_parent, 0o700)
    socket_path = socket_parent / "sidecar.sock"
    server = FutuSidecarServer(
        socket_path=socket_path,
        service=cast(Any, object()),
        expected_peer_uid=os.getuid(),
    )
    replacement: socket.socket | None = None
    try:
        server.start()
        assert stat.S_ISSOCK(socket_path.lstat().st_mode)
        assert socket_path.stat().st_mode & 0o777 == 0o600
        os.chmod(socket_path, 0o644)
        with pytest.raises(FutuSidecarServerError, match="mode drifted"):
            server._verify_endpoint()  # noqa: SLF001 - endpoint conformance
        os.chmod(socket_path, 0o600)
        server._verify_endpoint()  # noqa: SLF001 - endpoint conformance

        socket_path.unlink()
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement.bind(os.fspath(socket_path))
        os.chmod(socket_path, 0o600)
        with pytest.raises(FutuSidecarServerError, match="replaced"):
            server._verify_endpoint()  # noqa: SLF001 - replacement adversary
        server.close()
        assert socket_path.exists()
    finally:
        server.close()
        if replacement is not None:
            replacement.close()
        try:
            socket_path.unlink()
        except OSError:
            pass
        socket_parent.rmdir()


def test_uds_parent_mode_must_be_exact_0700(tmp_path: Path) -> None:
    socket_parent = tmp_path / "wrong-mode"
    socket_parent.mkdir(mode=0o500)
    server = FutuSidecarServer(
        socket_path=socket_parent / "sidecar.sock",
        service=cast(Any, object()),
        expected_peer_uid=os.getuid(),
    )
    with pytest.raises(FutuSidecarServerError, match="private and owner-controlled"):
        server.start()
