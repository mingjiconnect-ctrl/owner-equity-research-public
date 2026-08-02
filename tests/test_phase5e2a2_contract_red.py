from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

from owner_research.schema_store import validate_payload
from owner_research.valuation_market_execution_policies import (
    PINNED_KERNEL_COMMIT,
    PINNED_KERNEL_PACKAGE_VERSION,
    PINNED_KERNEL_PLUGIN_VERSION,
    PINNED_KERNEL_TAG,
    SHARE_BASIS_EVIDENCE_KINDS,
    SUPPORTED_SHARE_BASIS,
)

ROOT = Path(__file__).parents[1]


def test_phase5e2a2_pins_rc2_and_closes_current_share_policy() -> None:
    assert PINNED_KERNEL_TAG == "v2.0.0-rc.2"
    assert PINNED_KERNEL_COMMIT == "be9b0773d5a78f5f8a33ba982494512668df85fe"
    assert PINNED_KERNEL_PACKAGE_VERSION == "2.0.0rc2"
    assert PINNED_KERNEL_PLUGIN_VERSION == "2.0.0-rc.2"
    assert SUPPORTED_SHARE_BASIS == "current_common_shares_outstanding"
    assert SHARE_BASIS_EVIDENCE_KINDS == (
        "direct_point_in_time",
        "issued_less_treasury",
        "completed_event_rollforward",
    )


def test_market_reference_snapshot_v4_rejects_v3_and_fully_diluted_fields(
    sample_payloads,
) -> None:
    payload = sample_payloads["market-reference-snapshot"]
    assert payload["schema_version"] == "4.0.0"
    validate_payload("market-reference-snapshot", payload)

    legacy = dict(payload)
    legacy["schema_version"] = "3.0.0"
    with pytest.raises(ValidationError):
        validate_payload("market-reference-snapshot", legacy)

    legacy_share = json.loads(json.dumps(payload["share_basis"]))
    legacy_share["diluted_share_fact_id"] = legacy_share.pop("shares_outstanding_fact_id")
    legacy_share["point_in_time_diluted_shares_decimal"] = legacy_share.pop(
        "current_common_shares_outstanding_decimal"
    )
    forged = dict(payload)
    forged["share_basis"] = legacy_share
    with pytest.raises(ValidationError):
        validate_payload("market-reference-snapshot", forged)


def test_phase5e2a2_adversarial_manifest_covers_required_fail_closed_paths() -> None:
    payload = json.loads(
        (ROOT / "tests/fixtures/phase5e2a/adversarial-cases.json").read_text(encoding="utf-8")
    )
    cases = {item["case_id"] for item in payload["cases"]}
    assert {
        "rc1-kernel-pin",
        "snapshot-v2-runtime-payload",
        "legacy-fully-diluted-fields",
        "weighted-average-eps-shares",
        "potential-authorized-or-reserved-shares",
        "direct-current-share-fact-with-parents",
        "issued-less-treasury-arithmetic-error",
        "rollforward-unregistered-or-incomplete-event",
        "included-claim-standard-path",
        "blocked-claim-snapshot",
        "claim-root-numeric-parent",
        "market-equity-uses-diluted-shares",
        "request-v2-witness-uses-diluted-shares-fact-id",
        "phase5e2b-premature-authorization",
    }.issubset(cases)
