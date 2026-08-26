from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import date, datetime
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

import owner_research.owner_equity_runtime as runtime_module
import owner_research.valuation_synthesis as synthesis
import owner_research.valuation_synthesis_types as replay_types
from owner_research.fingerprints import canonical_sha256, freeze, to_json_value
from owner_research.validation import ContractGraph
from owner_research.valuation_synthesis_types import (
    ExtensionAuthorityError,
    ExtensionContract,
    replay_retained_completed_run_once,
    retained_authority_replay_scope,
    retained_authority_replay_session,
)


@dataclass(frozen=True, slots=True)
class _ProbeAuthority:
    fingerprint: str
    state: str = "trusted"


@dataclass(frozen=True, slots=True)
class _ReplayProbe(ExtensionContract):
    SCHEMA_NAME = "valuation-basis-receipt"

    receipt_id: str
    value: str
    _authority: _ProbeAuthority = field(
        repr=False,
        metadata={"serialize": False},
    )


@dataclass(frozen=True, slots=True)
class _NestedReplayProbe(ExtensionContract):
    SCHEMA_NAME = "valuation-basis-receipt"

    receipt_id: str
    value: str
    _child: _ReplayProbe = field(
        repr=False,
        metadata={"serialize": False},
    )


@dataclass(frozen=True, slots=True)
class _CompletedRunProbe:
    fingerprint: str
    status: str = "completed"
    authority: object | None = None


@dataclass(frozen=True, slots=True)
class _NormalizingAuthority:
    fingerprint: str
    payloads: tuple[object, ...]
    members: frozenset[str]


class _OpaqueAuthority:
    __slots__ = ()


class _PrivateSlotAuthority:
    __slots__ = ("__state",)

    def __init__(self, state: str) -> None:
        self.__state = state

    def mutate(self, state: str) -> None:
        self.__state = state


class _BaseSlotAuthority:
    __slots__ = ("_state",)


class _DerivedSlotAuthority(_BaseSlotAuthority):
    __slots__ = ("_state",)

    def __init__(self, base_state: str, derived_state: str) -> None:
        _BaseSlotAuthority._state.__set__(self, base_state)
        _DerivedSlotAuthority._state.__set__(self, derived_state)


@dataclass(frozen=True, slots=True)
class _PublicPayloadProbe(ExtensionContract):
    SCHEMA_NAME = "valuation-basis-receipt"

    receipt_id: str
    payload: object
    _authority: object = field(
        repr=False,
        metadata={"serialize": False},
    )


def _probe(authority: _ProbeAuthority) -> _ReplayProbe:
    payload = {"value": "stable"}
    return _ReplayProbe(
        receipt_id=f"replay-probe:{canonical_sha256(payload)[:24]}",
        value="stable",
        _authority=authority,
    )


def _nested_probe(child: _ReplayProbe) -> _NestedReplayProbe:
    payload = {"value": "nested"}
    return _NestedReplayProbe(
        receipt_id=f"nested-replay-probe:{canonical_sha256(payload)[:24]}",
        value="nested",
        _child=child,
    )


def _public_payload_probe(
    authority: object,
    payload_value: object | None = None,
) -> _PublicPayloadProbe:
    payload = freeze({"1": "stable"} if payload_value is None else payload_value)
    identity = {"payload": to_json_value(payload)}
    return _PublicPayloadProbe(
        receipt_id=f"public-payload-probe:{canonical_sha256(identity)[:24]}",
        payload=payload,
        _authority=authority,
    )


def test_extension_replay_is_deduplicated_only_inside_one_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    monkeypatch.setattr(replay_types, "validate_extension_payload", lambda *_: None)

    def replay(contract: ExtensionContract) -> None:
        nonlocal calls
        calls += 1
        if contract._authority.state != "trusted":  # type: ignore[attr-defined]
            raise ExtensionAuthorityError("probe private authority changed")

    monkeypatch.setattr(synthesis, "_replay_extension_contract", replay)
    authority = _ProbeAuthority(fingerprint="trusted")
    with retained_authority_replay_session():
        probe = _probe(authority)
        probe.__post_init__()
        assert calls == 1

        object.__setattr__(
            probe,
            "_authority",
            _ProbeAuthority(fingerprint="trusted", state="trusted"),
        )
        with pytest.raises(
            ExtensionAuthorityError,
            match="cached retained extension authority changed",
        ):
            probe.__post_init__()

    clean_probe = _probe(authority)
    clean_probe.__post_init__()
    assert calls == 3


def test_completed_run_cache_rematerializes_bytes_and_never_crosses_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    run = _CompletedRunProbe(fingerprint="run-fingerprint")
    archive = object()

    monkeypatch.setattr(
        replay_types,
        "_completed_run_witness",
        lambda value: replay_types._authority_witness((value,)),
    )

    def replay(
        value: object,
    ) -> tuple[object, dict[str, Any], dict[str, Any]]:
        nonlocal calls
        assert value is run
        calls += 1
        return archive, {"nested": {"value": 1}}, {"result": [1, 2, 3]}

    with retained_authority_replay_session():
        first = replay_retained_completed_run_once(run, replay)
        first[1]["nested"]["value"] = 99
        second = replay_retained_completed_run_once(run, replay)
        assert calls == 1
        assert second[0] is archive
        assert second[1] == {"nested": {"value": 1}}
        assert second[1] is not first[1]

    replay_retained_completed_run_once(run, replay)
    replay_retained_completed_run_once(run, replay)
    assert calls == 3


def test_same_object_live_private_mutation_cannot_hit_the_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(replay_types, "validate_extension_payload", lambda *_: None)

    def replay(contract: ExtensionContract) -> None:
        if contract._authority.state != "trusted":  # type: ignore[attr-defined]
            raise ExtensionAuthorityError("same-object authority mutation detected")

    monkeypatch.setattr(synthesis, "_replay_extension_contract", replay)
    authority = _ProbeAuthority(fingerprint="trusted")
    with retained_authority_replay_session():
        probe = _probe(authority)
        probe.__post_init__()
        object.__setattr__(authority, "state", "mutated")
        with pytest.raises(
            ExtensionAuthorityError,
            match="cached retained extension authority changed",
        ):
            probe.__post_init__()

def test_nested_extension_private_rebind_cannot_hit_the_outer_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(replay_types, "validate_extension_payload", lambda *_: None)

    def replay(contract: ExtensionContract) -> None:
        if isinstance(contract, _ReplayProbe):
            authority = contract._authority
        else:
            authority = contract._child._authority  # type: ignore[attr-defined]
        if authority.state != "trusted":
            raise ExtensionAuthorityError("nested private authority rebind detected")

    monkeypatch.setattr(synthesis, "_replay_extension_contract", replay)
    with retained_authority_replay_session():
        child = _probe(_ProbeAuthority(fingerprint="trusted"))
        outer = _nested_probe(child)
        outer.__post_init__()
        object.__setattr__(
            child,
            "_authority",
            _ProbeAuthority(fingerprint="trusted", state="trusted"),
        )
        with pytest.raises(
            ExtensionAuthorityError,
            match="cached retained extension authority changed",
        ):
            outer.__post_init__()


def test_legal_canonical_refreeze_and_alias_breaking_are_stable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    monkeypatch.setattr(replay_types, "validate_extension_payload", lambda *_: None)

    def replay(contract: ExtensionContract) -> None:
        nonlocal calls
        calls += 1
        authority = contract._authority  # type: ignore[attr-defined]
        normalized = tuple(
            freeze(to_json_value(item)) for item in authority.payloads
        )
        assert normalized[0] is not normalized[1]
        object.__setattr__(authority, "payloads", normalized)
        object.__setattr__(authority, "members", frozenset(list(authority.members)))

    monkeypatch.setattr(synthesis, "_replay_extension_contract", replay)
    shared = freeze({"key": "value"})
    authority = _NormalizingAuthority(
        fingerprint="normalizing",
        payloads=(shared, shared),
        members=frozenset(("alpha", "beta")),
    )
    with retained_authority_replay_session():
        probe = _probe(authority)  # type: ignore[arg-type]
        probe.__post_init__()
    assert calls == 1


def test_equal_nested_authority_replacement_during_replay_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(replay_types, "validate_extension_payload", lambda *_: None)

    def replay(contract: ExtensionContract) -> None:
        if isinstance(contract, _NestedReplayProbe):
            object.__setattr__(
                contract._child,
                "_authority",
                _ProbeAuthority(fingerprint="trusted", state="trusted"),
            )

    monkeypatch.setattr(synthesis, "_replay_extension_contract", replay)
    child = _probe(_ProbeAuthority(fingerprint="trusted"))
    with pytest.raises(ExtensionAuthorityError, match="changed during replay"):
        _nested_probe(child)


def test_opaque_private_authority_identity_cannot_be_rebound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(replay_types, "validate_extension_payload", lambda *_: None)
    monkeypatch.setattr(synthesis, "_replay_extension_contract", lambda *_: None)
    with retained_authority_replay_session():
        probe = _probe(_OpaqueAuthority())  # type: ignore[arg-type]
        probe.__post_init__()
        object.__setattr__(probe, "_authority", _OpaqueAuthority())
        with pytest.raises(
            ExtensionAuthorityError,
            match="cached retained extension authority changed",
        ):
            probe.__post_init__()


def test_mapping_key_type_bytearray_and_public_key_drift_are_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mapping: dict[object, object] = {"1": "stable"}
    before_mapping = replay_types._authority_witness((mapping,))
    del mapping["1"]
    mapping[1] = "stable"
    after_mapping = replay_types._authority_witness((mapping,))
    assert not before_mapping.stable_after_replay(after_mapping)

    mutable_bytes = bytearray(b"before")
    before_bytes = replay_types._authority_witness((mutable_bytes,))
    mutable_bytes[:] = b"after!"
    after_bytes = replay_types._authority_witness((mutable_bytes,))
    assert not before_bytes.stable_after_replay(after_bytes)

    half_rebound = freeze({"key": "value"})
    object.__setattr__(half_rebound, "_items", (("key", "changed"),))
    with pytest.raises(ExtensionAuthorityError, match="FrozenMap storage"):
        replay_types._authority_witness((half_rebound,))

    rebound_index = freeze({"key": "value"})
    object.__setattr__(rebound_index, "_index", {"key": "value"})
    with pytest.raises(ExtensionAuthorityError, match="FrozenMap storage"):
        replay_types._authority_witness((rebound_index,))

    item_value = "".join(("same", "-value"))
    index_value = "".join(("same-", "value"))
    assert item_value == index_value and item_value is not index_value
    split_identity = freeze({"key": item_value})
    object.__setattr__(
        split_identity,
        "_index",
        MappingProxyType({"key": index_value}),
    )
    with pytest.raises(ExtensionAuthorityError, match="FrozenMap storage"):
        replay_types._authority_witness((split_identity,))

    monkeypatch.setattr(replay_types, "validate_extension_payload", lambda *_: None)
    monkeypatch.setattr(synthesis, "_replay_extension_contract", lambda *_: None)
    with retained_authority_replay_session():
        probe = _public_payload_probe(_ProbeAuthority(fingerprint="trusted"))
        probe.__post_init__()
        payload = probe.payload
        object.__setattr__(payload, "_items", ((1, "stable"),))
        object.__setattr__(payload, "_index", MappingProxyType({1: "stable"}))
        with pytest.raises(
            ExtensionAuthorityError,
            match="FrozenMap storage",
        ):
            probe.__post_init__()

    with retained_authority_replay_session():
        probe = _public_payload_probe(_ProbeAuthority(fingerprint="trusted"))
        probe.__post_init__()
        payload = probe.payload
        object.__setattr__(payload, "_items", (("1", "changed"),))
        with pytest.raises(ExtensionAuthorityError, match="FrozenMap storage"):
            probe.__post_init__()

    with retained_authority_replay_session():
        probe = _public_payload_probe(
            _ProbeAuthority(fingerprint="trusted"),
            {"1": ("stable",)},
        )
        probe.__post_init__()
        payload = probe.payload
        key = payload._items[0][0]
        changed_value = ["stable"]
        object.__setattr__(payload, "_items", ((key, changed_value),))
        object.__setattr__(
            payload,
            "_index",
            MappingProxyType({key: changed_value}),
        )
        with pytest.raises(
            ExtensionAuthorityError,
            match="cached retained extension authority changed",
        ):
            probe.__post_init__()


def test_date_datetime_and_exact_slot_state_are_live_witnessed() -> None:
    for before_value, after_value in (
        (date(2020, 1, 1), date(2030, 1, 1)),
        (
            datetime(2020, 1, 1, 0, 0, 0),
            datetime(2030, 1, 1, 0, 0, 0),
        ),
    ):
        before = replay_types._authority_witness((before_value,))
        after = replay_types._authority_witness((after_value,))
        assert not before.stable_after_replay(after)

    private = _PrivateSlotAuthority("before")
    private_before = replay_types._authority_witness((private,))
    private.mutate("after")
    private_after = replay_types._authority_witness((private,))
    assert not private_before.stable_after_replay(private_after)

    shadowed = _DerivedSlotAuthority("base-before", "derived-stable")
    shadowed_before = replay_types._authority_witness((shadowed,))
    _BaseSlotAuthority._state.__set__(shadowed, "base-after")
    shadowed_after = replay_types._authority_witness((shadowed,))
    assert not shadowed_before.stable_after_replay(shadowed_after)


def test_internal_witness_hash_matches_canonical_json_for_json_values() -> None:
    for value in (
        {"mapping": {"b": 2, "a": 1}},
        ("tuple", 1, None, True),
        "scalar",
        {"unicode": "所有者研究"},
    ):
        assert replay_types._witness_sha256(value) == canonical_sha256(value)


@pytest.mark.parametrize(
    ("payload", "replacement"),
    (
        ({"1": "stable"}, {"1": "stable"}),
        (["stable"], ["stable"]),
    ),
)
def test_nested_extension_public_exact_type_drift_is_detected(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
    replacement: object,
) -> None:
    monkeypatch.setattr(replay_types, "validate_extension_payload", lambda *_: None)
    monkeypatch.setattr(synthesis, "_replay_extension_contract", lambda *_: None)
    with retained_authority_replay_session():
        child = _public_payload_probe(
            _ProbeAuthority(fingerprint="trusted"),
            payload,
        )
        outer = _nested_probe(child)  # type: ignore[arg-type]
        outer.__post_init__()
        object.__setattr__(child, "payload", replacement)
        with pytest.raises(
            ExtensionAuthorityError,
            match="cached retained extension authority changed",
        ):
            outer.__post_init__()


def test_cache_hit_still_validates_normalizes_and_checks_deterministic_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema_calls = 0
    replay_calls = 0

    def validate(*_args: object) -> None:
        nonlocal schema_calls
        schema_calls += 1

    def replay(*_args: object) -> None:
        nonlocal replay_calls
        replay_calls += 1

    monkeypatch.setattr(replay_types, "validate_extension_payload", validate)
    monkeypatch.setattr(synthesis, "_replay_extension_contract", replay)
    with retained_authority_replay_session():
        probe = _public_payload_probe(
            _ProbeAuthority(fingerprint="trusted"),
            {"nested": ["stable"]},
        )
        assert schema_calls == 1
        assert replay_calls == 1

        object.__setattr__(probe, "payload", {"nested": ["stable"]})
        probe.__post_init__()
        assert schema_calls == 2
        assert replay_calls == 1
        assert type(probe.payload).__name__ == "FrozenMap"
        assert type(probe.payload["nested"]) is tuple

        object.__setattr__(probe, "receipt_id", "not-deterministic")
        with pytest.raises(ValueError, match="object ID is not deterministic"):
            probe.__post_init__()
        assert schema_calls == 3
        assert replay_calls == 1


def test_completed_run_equal_authority_replacement_is_not_rebaselined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    authority = _ProbeAuthority(fingerprint="trusted")
    run = _CompletedRunProbe(fingerprint="completed", authority=authority)
    monkeypatch.setattr(
        replay_types,
        "_completed_run_witness",
        lambda value: replay_types._authority_witness((value,)),
    )

    def replay(_value: object) -> tuple[object, dict[str, Any], dict[str, Any]]:
        nonlocal calls
        calls += 1
        return object(), {}, {}

    with retained_authority_replay_session():
        replay_retained_completed_run_once(run, replay)
        object.__setattr__(
            run,
            "authority",
            _ProbeAuthority(fingerprint="trusted", state="trusted"),
        )
        with pytest.raises(
            ExtensionAuthorityError,
            match="cached completed valuation run authority changed",
        ):
            replay_retained_completed_run_once(run, replay)
    assert calls == 1


def test_visiting_cycle_raises_and_exception_resets_the_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(replay_types, "validate_extension_payload", lambda *_: None)

    def cycle(contract: ExtensionContract) -> None:
        contract.__post_init__()

    monkeypatch.setattr(synthesis, "_replay_extension_contract", cycle)
    with pytest.raises(ExtensionAuthorityError, match="cycle detected"):
        _probe(_ProbeAuthority(fingerprint="trusted"))

    calls = 0

    def valid(_contract: ExtensionContract) -> None:
        nonlocal calls
        calls += 1

    monkeypatch.setattr(synthesis, "_replay_extension_contract", valid)
    probe = _probe(_ProbeAuthority(fingerprint="trusted"))
    probe.__post_init__()
    assert calls == 2


def test_contract_graph_component_lock_content_is_part_of_the_live_witness(
    tmp_path,
) -> None:
    component_lock = tmp_path / "component-lock.json"
    component_lock.write_text('{"version":1}\n', encoding="utf-8")
    graph = ContractGraph(component_lock_path=component_lock)
    first = replay_types._authority_witness((graph,))

    component_lock.write_text('{"version":2}\n', encoding="utf-8")
    second = replay_types._authority_witness((graph,))

    assert not first.matches(second)

    ordinary_path = tmp_path / "archive-locator"
    ordinary_path.write_text("v1", encoding="utf-8")
    ordinary_first = replay_types._authority_witness((ordinary_path,))
    replacement = tmp_path / "archive-locator-replacement"
    replacement.write_text("v2", encoding="utf-8")
    replacement.replace(ordinary_path)
    ordinary_second = replay_types._authority_witness((ordinary_path,))
    assert ordinary_first.matches(ordinary_second)


def test_real_completed_run_archive_mutation_cannot_hit_the_session_cache(
    sample_payloads,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    from test_phase5_v1_valuation_synthesis import _completed_run

    from owner_research.valuation_run import _replay_retained_completed_run

    run_result, *_ = _completed_run(sample_payloads, monkeypatch, tmp_path)
    calls = 0

    def replay(value: object) -> tuple[object, dict[str, Any], dict[str, Any]]:
        nonlocal calls
        calls += 1
        return _replay_retained_completed_run(value)  # type: ignore[arg-type]

    with retained_authority_replay_session():
        replay_retained_completed_run_once(run_result, replay)
        assert calls == 1
        archive = run_result.archive
        assert archive is not None
        retained_payload = archive.request_payload
        request = to_json_value(retained_payload)
        request["company"]["name"] = "Coordinated Rebind"
        changed_payload = freeze(request)
        object.__setattr__(retained_payload, "_items", changed_payload._items)
        object.__setattr__(retained_payload, "_index", changed_payload._index)
        assert archive.request_payload is retained_payload
        with pytest.raises(
            ExtensionAuthorityError,
            match="cached completed valuation run authority changed",
        ):
            replay_retained_completed_run_once(run_result, replay)
        assert calls == 1


def test_delayed_copied_context_child_gets_a_fresh_session() -> None:
    observed = []

    @retained_authority_replay_scope
    def observe_session():
        session = replay_types._RETAINED_REPLAY_SESSION.get()
        assert session is not None and session.active
        session.extensions[-1] = None  # type: ignore[assignment]
        session.completed_runs[-1] = None  # type: ignore[assignment]
        session.visiting.add(("test-child", -1))
        observed.append(session)
        return session

    async def exercise():
        child_started = asyncio.Event()
        release_child = asyncio.Event()

        async def delayed_child():
            child_session = observe_session()
            child_started.set()
            await release_child.wait()
            return child_session

        with retained_authority_replay_session():
            parent = replay_types._RETAINED_REPLAY_SESSION.get()
            assert parent is not None and parent.active
            parent.extensions[-1] = None  # type: ignore[assignment]
            parent.completed_runs[-1] = None  # type: ignore[assignment]
            parent.visiting.add(("test-parent", -1))
            child = asyncio.create_task(delayed_child())
            await child_started.wait()
            assert parent.active is True
            assert len(observed) == 1
            child_session = observed[0]
            assert child_session is not parent
            assert child_session.active is False
            release_child.set()
            assert await child is child_session
        assert parent.active is False
        assert not parent.extensions
        assert not parent.completed_runs
        assert not parent.visiting
        return parent, child_session

    parent, child = asyncio.run(exercise())
    assert child is not parent
    assert observed == [child]
    assert child.active is False
    assert not child.extensions
    assert not child.completed_runs
    assert not child.visiting


def test_live_runtime_synthesis_shares_one_completed_run_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _CompletedRunProbe(fingerprint="runtime-run")
    archive = object()
    replay_calls = 0

    monkeypatch.setattr(
        replay_types,
        "_completed_run_witness",
        lambda value: replay_types._authority_witness((value,)),
    )

    def replay(value: object) -> tuple[object, dict[str, Any], dict[str, Any]]:
        nonlocal replay_calls
        assert value is run
        replay_calls += 1
        return archive, {"request": "stable"}, {"result": "stable"}

    def touch(value: object) -> None:
        observed_archive, _, _ = replay_retained_completed_run_once(value, replay)
        assert observed_archive is archive

    basis = object()
    forward = object()
    peer_authority = object()
    comparable = object()
    composite = object()

    def build_basis(value: object, **_kwargs: object) -> object:
        touch(value)
        return basis

    def build_forward(value: object, **_kwargs: object) -> object:
        touch(value)
        return forward

    def build_peer(*, run_result: object, **_kwargs: object) -> object:
        touch(run_result)
        return peer_authority

    def build_comparable(value: object, **_kwargs: object) -> object:
        touch(value)
        return comparable

    def build_composite(value: object, **_kwargs: object) -> object:
        touch(value)
        return composite

    monkeypatch.setattr(runtime_module, "build_valuation_basis_receipt", build_basis)
    monkeypatch.setattr(runtime_module, "build_forward_reoi_valuation", build_forward)
    monkeypatch.setattr(runtime_module, "build_reviewed_peer_set_authority", build_peer)
    monkeypatch.setattr(runtime_module, "build_comparable_valuation", build_comparable)
    monkeypatch.setattr(runtime_module, "build_composite_valuation", build_composite)

    state = runtime_module._LiveRuntimeState(runtime=SimpleNamespace())
    state.run_result = run  # type: ignore[assignment]
    state.basis_review = object()  # type: ignore[assignment]
    state.forward_review = object()  # type: ignore[assignment]
    state.selection_review = object()  # type: ignore[assignment]
    state.forecast_review = object()  # type: ignore[assignment]
    state.peer_plan = SimpleNamespace(peer_graph_contexts=())  # type: ignore[assignment]
    state.keyring = object()  # type: ignore[assignment]
    state.peer_evidence_set = object()  # type: ignore[assignment]

    assert state.run_synthesis(object()) is composite  # type: ignore[arg-type]
    assert replay_calls == 1
