#!/usr/bin/env python3
"""Write fixed-cutoff, metadata-only Phase 4D capital-allocation shadows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from owner_research.contracts import RunManifest
from owner_research.fingerprints import canonical_sha256

CUTOFF = "2026-07-11"
COMPONENT_VERSION = "0.4.0-dev.18"
COMPONENT_LOCK_SHA256 = "cff4971d2d1f55dd710d354f38179511d2fc3f01a0f08def224834d46d5c6c93"
RECORDED_AT = "2026-07-13T01:00:00Z"

SHADOWS = {
    "amazon": {
        "issuer_id": "issuer:amazon",
        "cik": "0001018724",
        "accessions": ("0001018724-26-000004", "0001018724-26-000014"),
        "event_types": ("organic_capex", "acquisition", "equity_issuance", "cash_accumulation"),
    },
    "salesforce": {
        "issuer_id": "issuer:salesforce",
        "cik": "0001108524",
        "accessions": ("0001108524-26-000060", "0001108524-26-000127"),
        "event_types": ("acquisition", "buyback", "stock_based_compensation", "debt_issuance"),
    },
    "union-pacific": {
        "issuer_id": "issuer:union-pacific",
        "cik": "0000100885",
        "accessions": ("0000100885-26-000037", "0000100885-26-000155"),
        "event_types": ("organic_capex", "buyback", "dividend", "debt_repayment"),
    },
}


def run_shadow(issuer: str, cutoff: str, output: Path) -> dict[str, object]:
    if cutoff != CUTOFF:
        raise SystemExit(f"capital-allocation shadow cutoff must remain fixed at {CUTOFF}")
    try:
        config = SHADOWS[issuer]
    except KeyError as exc:
        raise SystemExit(f"unsupported capital-allocation shadow issuer: {issuer}") from exc
    sources = tuple(
        {
            "source_identifier": f"sec:{accession}",
            "accession": accession,
            "hash_scope": "official_metadata_tuple",
            "source_metadata_sha256": canonical_sha256(
                {"cik": config["cik"], "accession": accession, "cutoff": cutoff}
            ),
        }
        for accession in config["accessions"]
    )
    missing = (
        "capital_allocation_candidates_not_promoted",
        "human_event_review_decisions_not_available",
        "outcome_role_evidence_not_promoted",
        "capital_allocation_review_not_buildable",
    )
    core = {
        "issuer_id": config["issuer_id"],
        "cik": config["cik"],
        "data_cutoff_date": cutoff,
        "official_source_metadata": sources,
        "event_types_examined": config["event_types"],
        "formal_object_ids": {
            "event_candidate_ids": [],
            "event_ids": [],
            "bridge_calculation_ids": [],
            "outcome_ids": [],
            "review_ids": [],
        },
        "status_counts": {
            "logical_event_count": 0,
            "observed_outcome_count": 0,
            "partial_outcome_count": 0,
            "unverifiable_outcome_count": 0,
            "blocked_outcome_count": 0,
        },
        "review_status": "blocked",
        "blocked_items": missing,
    }
    manifest = RunManifest(
        schema_version="1.0.0",
        run_id=f"capital-allocation-shadow:{config['issuer_id']}:{cutoff}",
        issuer_id=config["issuer_id"],
        data_cutoff_date=cutoff,
        started_at=RECORDED_AT,
        completed_at=RECORDED_AT,
        component_lock_sha256=COMPONENT_LOCK_SHA256,
        component_versions={"owner-equity-research": COMPONENT_VERSION},
        input_document_hashes={
            item["source_identifier"]: item["source_metadata_sha256"] for item in sources
        },
        output_artifact_hashes={"capital-allocation-shadow-summary": canonical_sha256(core)},
        missing_evidence=missing,
        anti_anchoring={
            "state": "pre_conclusion",
            "conclusion_frozen_at": None,
            "current_conclusion_sha256": None,
            "prior_materials_accessed": [],
        },
    )
    payload = {
        "manifest_version": "1.0.0",
        "shadow_type": "phase4d_capital_allocation",
        **core,
        "run_manifest": manifest.to_dict(),
        "network_access_performed": False,
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
