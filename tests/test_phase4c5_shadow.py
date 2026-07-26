from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from owner_research.fingerprints import canonical_sha256

SCRIPT = Path(__file__).parents[1] / "scripts" / "business_quality_shadow_run.py"
SPEC = importlib.util.spec_from_file_location("business_quality_shadow_run", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SHADOW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHADOW)


@pytest.mark.parametrize("issuer", ("amazon", "salesforce", "union-pacific"))
def test_shadow_is_metadata_only_and_hashes_are_scoped(tmp_path: Path, issuer: str) -> None:
    output = tmp_path / f"{issuer}.json"
    payload = SHADOW.run_shadow(issuer, SHADOW.CUTOFF, output)
    assert json.loads(output.read_text(encoding="utf-8")) == payload
    assert payload["review_status"] == "blocked"
    assert payload["formal_object_ids"] == {
        "business_model_snapshot_ids": [],
        "business_quality_review_ids": [],
        "competitive_context_snapshot_ids": [],
        "hypothesis_ids": [],
    }
    assert len(payload["official_filings"]) == 2
    for filing in payload["official_filings"]:
        source = {
            key: filing[key]
            for key in (
                "accession",
                "form",
                "filing_date",
                "report_period",
                "primary_document",
                "index_url",
            )
        }
        assert filing["source_metadata_sha256"] == canonical_sha256(source)
        assert filing["hash_scope"] == "official_metadata_tuple"
        assert filing["verification_mode"] == "official_sec_web_index"
        assert filing["index_url"].startswith("https://www.sec.gov/Archives/")
    for flag in (
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
        assert payload[flag] is False
    manifest = payload["run_manifest"]
    assert manifest["data_cutoff_date"] == SHADOW.CUTOFF
    assert manifest["component_versions"]["owner-equity-research"] == "0.4.0-dev.12"
    assert set(manifest["input_document_hashes"]) == {
        item["source_identifier"] for item in payload["official_filings"]
    }
    assert manifest["missing_evidence"] == payload["blocked_items"]


def test_shadow_scope_and_fail_closed_expectations(tmp_path: Path) -> None:
    amazon = SHADOW.run_shadow("amazon", SHADOW.CUTOFF, tmp_path / "amazon.json")
    assert amazon["scope_expectations"]["scope_mode"] == "segment_specific"
    assert amazon["scope_expectations"]["material_scope_labels"] == [
        "North America",
        "International",
        "AWS",
    ]
    assert amazon["scope_expectations"]["issuer_wide_generalization_allowed"] is False

    salesforce = SHADOW.run_shadow(
        "salesforce", SHADOW.CUTOFF, tmp_path / "salesforce.json"
    )
    assert "retention_kpi_definition_and_population_not_fully_comparable" in salesforce[
        "blocked_items"
    ]
    assert "switching_cost" in salesforce["mechanism_topics"]

    union_pacific = SHADOW.run_shadow(
        "union-pacific", SHADOW.CUTOFF, tmp_path / "union-pacific.json"
    )
    assert "regulatory_license" in union_pacific["mechanism_topics"]
    assert "capital_intensity" in union_pacific["mechanism_topics"]
    assert union_pacific["review_status"] == "blocked"


def test_shadow_rejects_cutoff_drift(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="cutoff must remain fixed"):
        SHADOW.run_shadow("amazon", "2026-07-12", tmp_path / "bad.json")


@pytest.mark.parametrize("issuer", ("amazon", "salesforce", "union-pacific"))
def test_committed_acceptance_shadow_matches_deterministic_runner(
    tmp_path: Path, issuer: str
) -> None:
    generated = SHADOW.run_shadow(issuer, SHADOW.CUTOFF, tmp_path / f"{issuer}.json")
    committed_path = (
        Path(__file__).parents[1]
        / "evals"
        / "shadow"
        / SHADOW.CUTOFF
        / f"business-quality-{issuer}.json"
    )
    assert json.loads(committed_path.read_text(encoding="utf-8")) == generated
