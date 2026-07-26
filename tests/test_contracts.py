from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from jsonschema import ValidationError

from owner_research.contracts import CONTRACT_TYPES, Fact, contract_from_dict
from owner_research.fingerprints import FrozenMap, canonical_sha256


def test_every_schema_has_an_immutable_python_type(sample_payloads: dict[str, dict]) -> None:
    assert set(CONTRACT_TYPES) == set(sample_payloads)
    for name, payload in sample_payloads.items():
        contract = contract_from_dict(name, payload)
        assert contract.to_dict() == payload
        with pytest.raises((FrozenInstanceError, AttributeError)):
            contract.schema_version = "changed"  # type: ignore[misc]


def test_nested_collections_are_immutable(sample_payloads: dict[str, dict]) -> None:
    fact = contract_from_dict("fact", sample_payloads["fact"])
    assert isinstance(fact, Fact)
    assert isinstance(fact.parent_fact_ids, tuple)
    with pytest.raises(AttributeError):
        fact.parent_fact_ids.append("fact:other")  # type: ignore[attr-defined]
    assert isinstance(fact.period, FrozenMap)
    with pytest.raises(TypeError):
        fact.period._index["end"] = "2099-12-31"  # type: ignore[index]


def test_direct_constructor_validates_and_deep_freezes(sample_payloads: dict[str, dict]) -> None:
    payload = sample_payloads["fact"]
    fact = Fact(**payload)
    payload["period"]["end"] = "2099-12-31"
    payload["parent_fact_ids"].append("fact:external-alias")
    assert fact.period["end"] == "2025-12-31"
    assert fact.parent_fact_ids == ()

    invalid = fact.to_dict()
    invalid["confidence"] = "invented"
    with pytest.raises(ValidationError):
        Fact(**invalid)


def test_fingerprint_is_stable_across_mapping_order(sample_payloads: dict[str, dict]) -> None:
    payload = sample_payloads["source-document"]
    reversed_payload = dict(reversed(list(payload.items())))
    assert canonical_sha256(payload) == canonical_sha256(reversed_payload)
    assert contract_from_dict("source-document", payload).fingerprint == canonical_sha256(payload)
