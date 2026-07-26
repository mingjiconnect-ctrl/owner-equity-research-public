#!/usr/bin/env python3
"""Write the fixed-cutoff, metadata-only Phase 4C business-quality shadows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from owner_research.contracts import RunManifest
from owner_research.fingerprints import canonical_sha256

CUTOFF = "2026-07-11"
COMPONENT_VERSION = "0.4.0-dev.12"
COMPONENT_LOCK_SHA256 = "e640e0c99d68faac9695068f1151994ec8113f02fbabc6ea41e0f63d098e0fdd"
RECORDED_AT = "2026-07-12T00:00:00Z"


SHADOWS = {
    "amazon": {
        "issuer_id": "issuer:amazon",
        "cik": "0001018724",
        "filings": (
            {
                "accession": "0001018724-26-000004",
                "form": "10-K",
                "filing_date": "2026-02-06",
                "report_period": "2025-12-31",
                "primary_document": "amzn-20251231.htm",
                "index_url": "https://www.sec.gov/Archives/edgar/data/1018724/000101872426000004/0001018724-26-000004-index.htm",
            },
            {
                "accession": "0001018724-26-000014",
                "form": "10-Q",
                "filing_date": "2026-04-30",
                "report_period": "2026-03-31",
                "primary_document": "amzn-20260331.htm",
                "index_url": "https://www.sec.gov/Archives/edgar/data/1018724/000101872426000014/0001018724-26-000014-index.htm",
            },
        ),
        "scope_expectations": {
            "scope_mode": "segment_specific",
            "material_scope_labels": ("North America", "International", "AWS"),
            "issuer_wide_generalization_allowed": False,
        },
        "mechanism_topics": ("network_effect", "scale_cost_advantage"),
        "missing_evidence": (
            "formal_segment_scoped_business_model_not_promoted",
            "independent_context_observations_not_promoted",
            "reviewed_mechanism_claims_not_available",
        ),
    },
    "salesforce": {
        "issuer_id": "issuer:salesforce",
        "cik": "0001108524",
        "filings": (
            {
                "accession": "0001108524-26-000060",
                "form": "10-K",
                "filing_date": "2026-03-02",
                "report_period": "2026-01-31",
                "primary_document": "crm-20260131.htm",
                "index_url": "https://www.sec.gov/Archives/edgar/data/1108524/000110852426000060/0001108524-26-000060-index.htm",
            },
            {
                "accession": "0001108524-26-000127",
                "form": "10-Q",
                "filing_date": "2026-05-28",
                "report_period": "2026-04-30",
                "primary_document": "crm-20260430.htm",
                "index_url": "https://www.sec.gov/Archives/edgar/data/1108524/000110852426000127/0001108524-26-000127-index.htm",
            },
        ),
        "scope_expectations": {
            "scope_mode": "issuer_wide",
            "material_scope_labels": ("Salesforce",),
            "issuer_wide_generalization_allowed": True,
        },
        "mechanism_topics": ("switching_cost", "retention", "remaining_performance_obligation"),
        "missing_evidence": (
            "retention_kpi_definition_and_population_not_fully_comparable",
            "independent_switching_cost_counterevidence_not_promoted",
            "reviewed_mechanism_claims_not_available",
        ),
    },
    "union-pacific": {
        "issuer_id": "issuer:union-pacific",
        "cik": "0000100885",
        "filings": (
            {
                "accession": "0000100885-26-000037",
                "form": "10-K",
                "filing_date": "2026-02-06",
                "report_period": "2025-12-31",
                "primary_document": "unp-20251231.htm",
                "index_url": "https://www.sec.gov/Archives/edgar/data/100885/000010088526000037/0000100885-26-000037-index.htm",
            },
            {
                "accession": "0000100885-26-000155",
                "form": "10-Q",
                "filing_date": "2026-04-23",
                "report_period": "2026-03-31",
                "primary_document": "unp-20260331.htm",
                "index_url": "https://www.sec.gov/Archives/edgar/data/100885/000010088526000155/0000100885-26-000155-index.htm",
            },
        ),
        "scope_expectations": {
            "scope_mode": "issuer_wide",
            "material_scope_labels": ("Union Pacific Railroad",),
            "issuer_wide_generalization_allowed": True,
        },
        "mechanism_topics": (
            "efficient_scale",
            "regulatory_license",
            "process_execution",
            "capital_intensity",
        ),
        "missing_evidence": (
            "entrant_economics_and_capacity_context_not_promoted",
            "comparable_process_and_capital_intensity_diagnostics_not_available",
            "reviewed_mechanism_claims_not_available",
        ),
    },
}


def _filing_metadata(row: dict[str, str]) -> dict[str, str]:
    metadata = dict(row)
    metadata["source_identifier"] = f"sec:{row['accession']}"
    metadata["hash_scope"] = "official_metadata_tuple"
    metadata["verification_mode"] = "official_sec_web_index"
    metadata["source_metadata_sha256"] = canonical_sha256(row)
    return metadata


def run_shadow(issuer: str, cutoff: str, output: Path) -> dict[str, object]:
    if cutoff != CUTOFF:
        raise SystemExit(f"business-quality shadow cutoff must remain fixed at {CUTOFF}")
    try:
        config = SHADOWS[issuer]
    except KeyError as exc:
        raise SystemExit(f"unsupported business-quality shadow issuer: {issuer}") from exc

    filings = tuple(_filing_metadata(dict(item)) for item in config["filings"])
    object_ids = {
        "competitive_context_snapshot_ids": [],
        "business_model_snapshot_ids": [],
        "hypothesis_ids": [],
        "business_quality_review_ids": [],
    }
    status_counts = {
        "proposed_hypothesis_count": 0,
        "supported_hypothesis_count": 0,
        "contested_hypothesis_count": 0,
        "falsified_hypothesis_count": 0,
        "blocked_hypothesis_count": 0,
        "unresolved_mechanism_topic_count": len(config["mechanism_topics"]),
    }
    core = {
        "issuer_id": config["issuer_id"],
        "cik": config["cik"],
        "data_cutoff_date": cutoff,
        "official_filings": filings,
        "scope_expectations": config["scope_expectations"],
        "mechanism_topics": config["mechanism_topics"],
        "formal_object_ids": object_ids,
        "status_counts": status_counts,
        "review_status": "blocked",
        "blocked_items": config["missing_evidence"],
    }
    manifest = RunManifest(
        schema_version="1.0.0",
        run_id=f"business-quality-shadow:{config['issuer_id']}:{cutoff}",
        issuer_id=config["issuer_id"],
        data_cutoff_date=cutoff,
        started_at=RECORDED_AT,
        completed_at=RECORDED_AT,
        component_lock_sha256=COMPONENT_LOCK_SHA256,
        component_versions={"owner-equity-research": COMPONENT_VERSION},
        input_document_hashes={
            item["source_identifier"]: item["source_metadata_sha256"] for item in filings
        },
        output_artifact_hashes={"business-quality-shadow-summary": canonical_sha256(core)},
        missing_evidence=config["missing_evidence"],
        anti_anchoring={
            "state": "pre_conclusion",
            "conclusion_frozen_at": None,
            "current_conclusion_sha256": None,
            "prior_materials_accessed": [],
        },
    )
    payload = {
        "manifest_version": "1.0.0",
        "shadow_type": "phase4c_business_quality",
        **core,
        "run_manifest": manifest.to_dict(),
        "network_is_explicit": True,
        "network_access_performed": False,
        "source_verification_mode": "official_sec_web_index",
        "contains_raw_source_content": False,
        "contains_facts": False,
        "contains_claims": False,
        "contains_scores": False,
        "contains_market_price": False,
        "contains_valuation": False,
        "contains_target_price": False,
        "contains_recommendation": False,
        "contains_report": False,
        "contains_pdf": False,
        "contains_publisher": False,
    }
    serialized = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialized, encoding="utf-8")
    return json.loads(serialized)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer", choices=sorted(SHADOWS), required=True)
    parser.add_argument("--cutoff", default=CUTOFF)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run_shadow(args.issuer, args.cutoff, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
