from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from owner_research.contracts import RunManifest
from owner_research.fingerprints import canonical_sha256

ROOT = Path(__file__).parents[1]
SHADOW_ROOT = ROOT / "evals" / "shadow" / "2026-07-11"


def _manifests() -> dict[str, dict]:
    return {
        issuer: json.loads((SHADOW_ROOT / f"management-{issuer}.json").read_text())
        for issuer in ("amazon", "salesforce")
    }


def test_fixed_date_management_shadows_are_metadata_only() -> None:
    manifests = _manifests()
    assert manifests["salesforce"]["review_status"] == "complete"
    assert manifests["amazon"]["review_status"] == "partial"
    assert manifests["salesforce"]["coverage"]["superseded_count"] == 1
    assert manifests["salesforce"]["coverage"]["not_due_count"] == 2
    assert manifests["amazon"]["coverage"]["due_count"] == 1
    assert manifests["amazon"]["coverage"]["unverifiable_count"] == 1

    forbidden_fields = {
        "statement_text",
        "fact_id",
        "claim_id",
        "score",
        "valuation",
        "target_price",
        "recommendation",
        "report",
    }
    for manifest in manifests.values():
        assert manifest["data_cutoff_date"] == "2026-07-11"
        assert manifest["shadow_type"] == "phase4b_management_ledger"
        assert all(
            manifest[key] is False
            for key in (
                "contains_raw_source_content",
                "contains_facts",
                "contains_claims",
                "contains_scores",
                "contains_valuation",
                "contains_target_price",
                "contains_recommendation",
                "contains_report",
            )
        )
        serialized = json.dumps(manifest, sort_keys=True)
        assert forbidden_fields.isdisjoint(_all_keys(manifest))
        assert "investment advice" not in serialized.lower()


def test_shadow_sources_have_official_ids_hashes_and_verified_anchors() -> None:
    allowed_hosts = {
        "issuer:amazon": {"ir.aboutamazon.com"},
        "issuer:salesforce": {"investor.salesforce.com"},
    }
    for manifest in _manifests().values():
        assert len(manifest["sec_accessions"]) == 2
        assert manifest["sources"]
        for source in manifest["sources"]:
            assert urlparse(source["source_url"]).hostname in allowed_hosts[manifest["issuer_id"]]
            assert len(source["evidence_sha256"]) == 64
            assert len(source["anchor_sha256"]) == 64
            assert source["anchor_verified"] is True
            assert source["hash_scope"] in {
                "full_response_bytes",
                "normalized_official_excerpt",
            }
            assert source["retrieval_mode"] in {
                "live_official_page",
                "verified_official_web_snapshot",
            }


def test_shadow_run_manifest_and_summary_fingerprints_reconcile() -> None:
    for manifest in _manifests().values():
        run_manifest = RunManifest(**manifest["run_manifest"])
        assert run_manifest.data_cutoff_date == "2026-07-11"
        assert run_manifest.component_lock_sha256 == (
            "0e4b21615b21a6f08decf09301eb0c9efbc11ee7085286e3a3932203421aec46"
        )
        assert run_manifest.component_versions["owner-equity-research"] == "0.4.0-dev.6"
        assert dict(run_manifest.input_document_hashes) == {
            item["document_id"]: item["evidence_sha256"] for item in manifest["sources"]
        }
        core = {
            key: manifest[key]
            for key in (
                "issuer_id",
                "cik",
                "data_cutoff_date",
                "sec_accessions",
                "sources",
                "object_ids",
                "coverage",
                "review_status",
                "blocked_items",
            )
        }
        assert run_manifest.output_artifact_hashes["management-shadow-summary"] == (
            canonical_sha256(core)
        )


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_all_keys(item) for item in value.values()), set())
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value), set())
    return set()
