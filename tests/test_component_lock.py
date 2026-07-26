from __future__ import annotations

import json
import os
from pathlib import Path

from owner_research import __version__
from owner_research.component_lock import (
    load_component_lock,
    verify_component_lock,
    verify_future_mapping_contract,
    verify_research_schema_lock,
)

ROOT = Path(__file__).parents[1]


def test_component_lock_has_exact_pinned_identity() -> None:
    lock = load_component_lock(ROOT / "component-lock.json")
    assert lock["lock_version"] == "1.2.0"
    assert lock["owner_equity_research"]["plugin_version"] == "0.5.0-dev.11"
    assert __version__ == "0.5.0.dev11"
    kernel = lock["valuation_kernel"]
    assert kernel["repository"] == "mingjiconnect-ctrl/owner-valuation-kernel"
    assert kernel["tag"] == "v2.0.0-rc.2"
    assert kernel["annotated_tag_object"] == "4e19ce6a59bc4321ebcd368e807ed764f4e8abde"
    assert kernel["commit"] == "be9b0773d5a78f5f8a33ba982494512668df85fe"
    assert kernel["package_version"] == "2.0.0rc2"
    assert kernel["plugin_version"] == "2.0.0-rc.2"
    assert kernel["release_evidence"]["tag_ci_run_id"] == 29388946546
    authority = lock["market_access_authority"]
    assert authority["authority_version"] == "1.0.0"
    assert set(authority) == {
        "authority_version",
        "provider_registry",
        "calendar_registry",
        "security_identity_policy",
        "secret_policy",
        "adapter_code",
        "parser_code",
    }


def test_component_lock_matches_pinned_local_checkout() -> None:
    default_repo = ROOT.parent / "owner-valuation-kernel"
    kernel_repo = Path(os.environ.get("OWNER_VALUATION_REPO", default_repo))
    result = verify_component_lock(
        ROOT / "component-lock.json",
        source_repo=kernel_repo,
        require_clean=True,
        require_pinned_head=True,
    )
    assert result.ok, "\n".join(result.errors)


def test_component_lock_matches_research_schema_files() -> None:
    result = verify_research_schema_lock(ROOT / "component-lock.json", ROOT)
    assert result.ok, "\n".join(result.errors)


def test_compatibility_fixture_uses_only_future_mappable_numeric_fields() -> None:
    fixture = json.loads(
        (ROOT / "evals" / "future-valuation-mapping.json").read_text(encoding="utf-8")
    )
    assert fixture["mapping_status"] == "IMPLEMENTED_PHASE_5B"
    assert fixture["eligible_fact"]["value_type"] == "number"
    assert fixture["target_schema"] == "fact-ledger.schema.json"
    default_repo = ROOT.parent / "owner-valuation-kernel"
    kernel_repo = Path(os.environ.get("OWNER_VALUATION_REPO", default_repo))
    result = verify_future_mapping_contract(
        ROOT / "evals" / "future-valuation-mapping.json",
        source_repo=kernel_repo,
    )
    assert result.ok, "\n".join(result.errors)
