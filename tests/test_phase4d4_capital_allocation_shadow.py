from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "capital_allocation_shadow_run.py"


def _module():
    spec = importlib.util.spec_from_file_location("capital_allocation_shadow_run", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("issuer", ["amazon", "salesforce", "union-pacific"])
def test_capital_allocation_shadow_is_fixed_cutoff_metadata_only(
    tmp_path: Path,
    issuer: str,
) -> None:
    module = _module()
    output = tmp_path / f"{issuer}.json"
    payload = module.run_shadow(issuer, "2026-07-11", output)
    assert payload == json.loads(output.read_text(encoding="utf-8"))
    assert payload["review_status"] == "blocked"
    assert payload["formal_object_ids"]["event_ids"] == []
    assert payload["network_access_performed"] is False
    for field in (
        "contains_raw_source_content",
        "contains_facts",
        "contains_claims",
        "contains_scores",
        "contains_market_price",
        "contains_valuation",
        "contains_target_price",
        "contains_recommendation",
        "contains_report",
        "contains_pdf",
        "contains_publisher",
    ):
        assert payload[field] is False
    text = output.read_text(encoding="utf-8").lower()
    assert "target price" not in text
    assert "investment recommendation" not in text


def test_capital_allocation_shadow_rejects_cutoff_drift(tmp_path: Path) -> None:
    module = _module()
    with pytest.raises(SystemExit, match="must remain fixed"):
        module.run_shadow("amazon", "2026-07-12", tmp_path / "bad.json")
