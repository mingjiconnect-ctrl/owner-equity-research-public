from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCK_PATH = ROOT / "docs" / "phase5-v1-stable-release-block.json"
POLICY_PATH = ROOT / "scripts" / "phase5e-futu-market-authority-policy-v2.json"
TRUST_PATH = ROOT / "scripts" / "phase5e2b12a-acceptance-trust.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_stable_release_is_blocked_by_all_three_unsigned_external_gates() -> None:
    block = json.loads(BLOCK_PATH.read_text(encoding="utf-8"))
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    trust = json.loads(TRUST_PATH.read_text(encoding="utf-8"))[
        "external_feasibility_receipt_authority"
    ]

    assert set(block) == {
        "decision",
        "evaluated_on",
        "fallbacks",
        "gates",
        "governing_policy",
        "official_reference_observations",
        "receipt_authority",
        "release",
        "release_canary",
        "schema_version",
    }
    assert block["schema_version"] == "2.0.0"
    assert block["decision"] == "release_candidate_and_stable_release_blocked"
    assert block["governing_policy"] == {
        "path": "scripts/phase5e-futu-market-authority-policy-v2.json",
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "sha256": _sha256(POLICY_PATH),
        "status": "current_comprehensive_skill_policy",
    }
    assert block["receipt_authority"] == {
        "path": "scripts/phase5e2b12a-acceptance-trust.json",
        "required_order": trust["required_order"],
        "sha256": _sha256(TRUST_PATH),
        "signer_keys_installed": False,
        "status": "bootstrap_pending",
    }
    assert trust["status"] == "bootstrap_pending"
    assert all(
        signer == {"key_id": None, "public_key_hex": None}
        for signer in trust["signers"].values()
    )

    assert set(block["gates"]) == {"account", "legal", "protocol"}
    for gate_name, gate in block["gates"].items():
        assert gate["status"] == "blocked", gate_name
        assert gate["external_signed_receipt_supplied"] is False
        assert set(gate["required_conditions"]).issuperset(
            trust["condition_coverage"][gate_name]
        )
        assert gate["blockers"]

    assert block["release"]["release_candidate_status"] == "blocked"
    assert block["release"]["release_candidate_tag_created"] is False
    assert block["release"]["stable_tag_created"] is False
    assert block["release"]["target_release_candidate_tag"] == "v1.0.0-rc.1"
    assert block["release"]["target_stable_tag"] == "v1.0.0"
    assert block["release"]["development_version_required"] is True
    assert block["release_canary"]["status"] == "blocked"
    assert block["release_canary"]["bound_commit"] is None
    assert block["release_canary"]["bound_tree"] is None
    assert block["fallbacks"]["reviewed_file"] == (
        "development_and_replay_only_not_release_canary"
    )
    assert set(block["fallbacks"]) - {"reviewed_file"} == {
        "free_api",
        "manual_price",
        "simulated_price",
        "trading_account_data",
        "web_scraping",
    }
    assert all(
        block["fallbacks"][name] == "forbidden"
        for name in block["fallbacks"]
        if name != "reviewed_file"
    )


def test_official_references_are_nonsecret_technical_observations_only() -> None:
    block = json.loads(BLOCK_PATH.read_text(encoding="utf-8"))
    observations = block["official_reference_observations"]

    assert set(observations) == {"authorities_and_quota", "global_state", "history_kline"}
    for observation in observations.values():
        assert observation["url"].startswith("https://openapi.futunn.com/")
        assert observation["retrieved_on"] <= block["evaluated_on"]
        assert len(observation["html_sha256"]) == 64
        assert observation["gate_effect"].endswith(
            ("receipt", "attestation", "proof")
        )
        serialized = json.dumps(observation, sort_keys=True).lower()
        assert not any(
            secret_name in serialized
            for secret_name in ("password", "private_key", "access_token", "cookie")
        )
