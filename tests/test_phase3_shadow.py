from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_fixed_date_shadow_manifests_are_metadata_only() -> None:
    shadow_root = ROOT / "evals" / "shadow" / "2026-07-11"
    manifests = [
        manifest
        for path in sorted(shadow_root.glob("*.json"))
        if (manifest := json.loads(path.read_text()))["shadow_type"]
        == "sec_filing_accounting_quality"
    ]
    assert {item["issuer_id"] for item in manifests} == {"issuer:amazon", "issuer:salesforce"}
    for manifest in manifests:
        assert manifest["data_cutoff_date"] == "2026-07-11"
        assert manifest["contains_raw_filing_content"] is False
        assert manifest["contains_facts"] is False
        assert manifest["contains_claims"] is False
        assert manifest["contains_scores"] is False
        assert manifest["contains_valuation"] is False
        assert manifest["contains_report"] is False
        assert manifest["validation_status"] in {"partial", "blocked"}
        assert manifest["blocked_items"]
        for filing in manifest["filings"]:
            assert filing["form"] in {"10-K", "10-Q"}
            assert "accession" in filing
            assert "raw_sha256" in filing
            assert "normalized_sha256" in filing
