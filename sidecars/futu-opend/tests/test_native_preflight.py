from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from owner_research_futu_sidecar import native_preflight, runtime_authorization
from owner_research_futu_sidecar.canonical import SidecarContractError


@pytest.fixture
def native_probe(monkeypatch):
    monkeypatch.setattr(runtime_authorization.sys, "platform", "darwin")
    monkeypatch.setattr(native_preflight.os, "geteuid", lambda: 501)
    calls = []
    state = SimpleNamespace(
        qot_logined=True,
        trd_logined=True,
        server_version=1010,
        server_build_no=7008,
        exchange=SimpleNamespace(
            request=SimpleNamespace(sha256="a" * 64),
            response=SimpleNamespace(sha256="b" * 64),
        ),
    )
    guard = SimpleNamespace(
        quarantined=False,
        sequence=2,
        start=lambda: calls.append("start"),
        close=lambda: calls.append("guard_close"),
    )
    adapter = SimpleNamespace(
        connect_attempts=1,
        global_state=lambda: state,
        close=lambda: calls.append("adapter_close"),
    )

    def make_guard(**kwargs):
        assert kwargs == {"upstream_host": "127.0.0.1", "upstream_port": 11111}
        calls.append("guard")
        return guard

    def make_adapter(**kwargs):
        assert kwargs["guard"] is guard
        assert kwargs["private_home"].stat().st_mode & 0o777 == 0o700
        os.environ["HOME"] = str(kwargs["private_home"])
        calls.append("adapter")
        return adapter

    monkeypatch.setattr(native_preflight, "FrameGuardProxy", make_guard)
    monkeypatch.setattr(native_preflight, "OfficialFutuAdapter", make_adapter)
    return guard, adapter, state, calls


@pytest.mark.parametrize("trade_login", [True, False])
def test_native_probe_is_status_only_and_restores_home(native_probe, trade_login):
    _, _, state, calls = native_probe
    original_home = os.environ.get("HOME")
    state.trd_logined = trade_login
    result = native_preflight.probe_native_opend()
    assert result["status"] == "connected"
    assert result["protocol_ids"] == [1001, 1002]
    assert result["trd_logined"] is trade_login
    assert result["opend_server_version"] == 1010
    assert result["opend_server_build_no"] == 7008
    assert result["research_data_fetched"] is False
    assert result["canary_completed"] is False
    assert result["release_authority"] is False
    assert not {"user_id", "account_id", "raw_response", "price"} & set(result)
    assert calls == ["guard", "start", "adapter", "adapter_close"]
    assert os.environ.get("HOME") == original_home


def test_native_probe_retains_missing_quote_login(native_probe):
    native_probe[2].qot_logined = False
    assert native_preflight.probe_native_opend()["status"] == "quote_login_required"


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("quarantined", True),
        ("sequence", 3),
        ("connect_attempts", 2),
    ],
)
def test_native_probe_rejects_unexpected_session(native_probe, attribute, value):
    guard, adapter, _, calls = native_probe
    setattr(adapter if attribute == "connect_attempts" else guard, attribute, value)
    original_home = os.environ.get("HOME")
    with pytest.raises(SidecarContractError, match="one init and one status"):
        native_preflight.probe_native_opend()
    assert calls[-1] == "adapter_close"
    assert os.environ.get("HOME") == original_home


@pytest.mark.parametrize("platform,uid", [("linux", 501), ("darwin", 0)])
def test_native_probe_rejects_wrong_platform_or_root_before_connection(
    native_probe,
    monkeypatch,
    platform,
    uid,
):
    monkeypatch.setattr(runtime_authorization.sys, "platform", platform)
    monkeypatch.setattr(native_preflight.os, "geteuid", lambda: uid)
    with pytest.raises(SidecarContractError):
        native_preflight.probe_native_opend()
    assert native_probe[3] == []


@pytest.mark.parametrize(
    "host,port",
    [
        ("localhost", 11111),
        ("::1", 11111),
        ("192.0.2.1", 11111),
        ("127.0.0.1", 11112),
        ("127.0.0.1", "11111"),
    ],
)
def test_native_endpoint_is_fixed_loopback(monkeypatch, host, port):
    monkeypatch.setattr(runtime_authorization.sys, "platform", "darwin")
    runtime_authorization.require_runtime_endpoint("2.0.0", "127.0.0.1", 11111)
    with pytest.raises(SidecarContractError, match="127.0.0.1:11111"):
        runtime_authorization.require_runtime_endpoint("2.0.0", host, port)


def test_linux_authority_validation_does_not_require_native_platform(monkeypatch):
    monkeypatch.setattr(runtime_authorization.sys, "platform", "linux")
    runtime_authorization.require_runtime_platform("1.0.0")
    with pytest.raises(SidecarContractError, match="requires Darwin"):
        runtime_authorization.require_runtime_platform("2.0.0")
    with pytest.raises(SidecarContractError, match="unsupported runtime profile"):
        runtime_authorization.require_runtime_platform("3.0.0")
