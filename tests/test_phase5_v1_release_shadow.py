from __future__ import annotations

import json
import runpy
from pathlib import Path

from owner_research.fingerprints import canonical_json, canonical_sha256

ROOT = Path(__file__).parents[1]
SHADOW = runpy.run_path(str(ROOT / "scripts" / "phase5_v1_release_shadow.py"))
COMMITTED = (
    ROOT
    / "evals"
    / "shadow"
    / "2026-07-11"
    / "phase5-v1-code-complete-preview.json"
)


def test_release_shadow_runs_unp_then_salesforce_and_stops_before_market(
    tmp_path: Path,
) -> None:
    payload = SHADOW["build_release_shadow"]()
    attempts = payload["attempts"]

    assert [item["issuer_id"] for item in attempts] == [
        "issuer:union-pacific",
        "issuer:salesforce",
    ]
    assert payload["fallback_reason"] == (
        "union_pacific_evidence_insufficient_for_price_blind_freeze"
    )
    assert payload["overall_status"] == "blocked"
    assert payload["release_qualifying"] is False
    assert payload["rc_tag_permitted"] is False
    assert payload["real_futu_opend_canary_completed"] is False
    assert all(item["stopped_before"] == "market_reference" for item in attempts)
    assert all(item["market_provider_invoked"] is False for item in attempts)
    assert all(item["kernel_invoked"] is False for item in attempts)
    assert all(item["archive_written"] is False for item in attempts)
    assert payload["contains_market_price"] is False
    assert payload["contains_valuation_request"] is False
    assert payload["contains_valuation_result"] is False
    fingerprint = payload.pop("shadow_fingerprint")
    assert fingerprint == canonical_sha256(payload)

    generated = tmp_path / "shadow.json"
    SHADOW["write_release_shadow"](generated)
    assert json.loads(generated.read_bytes())["shadow_fingerprint"] == fingerprint


def test_committed_release_shadow_is_the_exact_deterministic_projection() -> None:
    expected = SHADOW["build_release_shadow"]()
    assert COMMITTED.read_bytes() == (canonical_json(expected) + "\n").encode("utf-8")
