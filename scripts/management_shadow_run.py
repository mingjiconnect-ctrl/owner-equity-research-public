#!/usr/bin/env python3
"""Run the explicit, metadata-only Phase 4B management shadow."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

from owner_research.component_lock import file_sha256
from owner_research.contracts import RunManifest
from owner_research.fingerprints import canonical_sha256
from owner_research.management_sources import (
    OfficialSourceClient,
    OfficialSourceError,
    validate_official_url,
)
from owner_research.management_statements import normalized_source_text

CUTOFF = "2026-07-11"
COMPONENT_VERSION = "0.4.0-dev.6"

SHADOWS = {
    "salesforce": {
        "issuer_id": "issuer:salesforce",
        "cik": "1108524",
        "allowed_hosts": frozenset({"salesforce.com"}),
        "sec_accessions": ("0001108524-26-000060", "0001108524-26-000127"),
        "sources": (
            {
                "document_id": "doc:issuer:salesforce:fy30-target-2025",
                "published_date": "2025-10-15",
                "url": "https://investor.salesforce.com/news/news-details/2025/Salesforce-Announces-New-FY30-Revenue-Target-of-60B-10-Organic-FY26-FY30-CAGR/default.aspx",
                "anchor": "new long-term revenue target of $60b+ by fiscal year (fy) 2030",
            },
            {
                "document_id": "doc:issuer:salesforce:q4-fy26-results",
                "published_date": "2026-02-25",
                "url": "https://investor.salesforce.com/news/news-details/2026/Salesforce-Delivers-Record-Fourth-Quarter-Fiscal-2026-Results/default.aspx",
                "anchor": "full year fy30 revenue target to $63 billion including informatica",
            },
            {
                "document_id": "doc:issuer:salesforce:q1-fy27-results",
                "published_date": "2026-05-27",
                "url": "https://investor.salesforce.com/news/news-details/2026/Salesforce-Delivers-Record-First-Quarter-Fiscal-2027-Results/default.aspx",
                "anchor": "full year fy27 revenue of $45.9 billion to $46.2 billion",
            },
        ),
        "object_ids": {
            "statement_ids": (
                "management-statement:issuer:salesforce:fy30-60b",
                "management-statement:issuer:salesforce:fy30-63b",
                "management-statement:issuer:salesforce:fy27-revenue-range",
            ),
            "commitment_ids": (
                "management-commitment:issuer:salesforce:fy30-60b",
                "management-commitment:issuer:salesforce:fy30-63b",
                "management-commitment:issuer:salesforce:fy27-revenue-range",
            ),
            "outcome_ids": (
                "management-outcome:issuer:salesforce:fy30-60b:superseded",
                "management-outcome:issuer:salesforce:fy30-63b:pending",
                "management-outcome:issuer:salesforce:fy27-revenue-range:pending",
            ),
            "review_id": "management-review:issuer:salesforce:2026-07-11",
        },
        "coverage": {
            "statement_count": 3,
            "confirmed_count": 3,
            "open_count": 2,
            "not_due_count": 2,
            "due_count": 0,
            "evaluated_due_count": 0,
            "pending_count": 2,
            "met_count": 0,
            "partially_met_count": 0,
            "missed_count": 0,
            "unverifiable_count": 0,
            "blocked_count": 0,
            "withdrawn_count": 0,
            "superseded_count": 1,
        },
        "review_status": "complete",
        "missing_evidence": (),
    },
    "amazon": {
        "issuer_id": "issuer:amazon",
        "cik": "1018724",
        "allowed_hosts": frozenset({"aboutamazon.com"}),
        "sec_accessions": ("0001018724-26-000004", "0001018724-26-000014"),
        "sources": (
            {
                "document_id": "doc:issuer:amazon:q1-2026-results",
                "published_date": "2026-04-29",
                "url": "https://ir.aboutamazon.com/news-release/news-release-details/2026/Amazon-com-Announces-First-Quarter-Results/",
                "anchor": "net sales are expected to be between $194.0 billion and $199.0 billion",
            },
        ),
        "object_ids": {
            "statement_ids": ("management-statement:issuer:amazon:q2-2026-sales-range",),
            "commitment_ids": ("management-commitment:issuer:amazon:q2-2026-sales-range",),
            "outcome_ids": (
                "management-outcome:issuer:amazon:q2-2026-sales-range:unverifiable",
            ),
            "review_id": "management-review:issuer:amazon:2026-07-11",
        },
        "coverage": {
            "statement_count": 1,
            "confirmed_count": 1,
            "open_count": 1,
            "not_due_count": 0,
            "due_count": 1,
            "evaluated_due_count": 1,
            "pending_count": 0,
            "met_count": 0,
            "partially_met_count": 0,
            "missed_count": 0,
            "unverifiable_count": 1,
            "blocked_count": 0,
            "withdrawn_count": 0,
            "superseded_count": 0,
        },
        "review_status": "partial",
        "missing_evidence": (
            "official_q2_2026_result_not_disclosed_at_cutoff",
            "multi_year_quantitative_target_not_disclosed",
        ),
    },
}


def run_shadow(
    issuer: str,
    cutoff: str,
    output: Path,
    *,
    verified_snapshot: Path | None = None,
) -> dict:
    if cutoff != CUTOFF:
        raise SystemExit(f"management shadow cutoff must remain fixed at {CUTOFF}")
    try:
        config = SHADOWS[issuer]
    except KeyError as exc:
        raise SystemExit(f"unsupported management shadow issuer: {issuer}") from exc
    started_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    source_rows = []
    blocked = []
    snapshots = (
        json.loads(verified_snapshot.read_text(encoding="utf-8"))
        if verified_snapshot is not None
        else {}
    )
    with OfficialSourceClient(allowed_hosts=config["allowed_hosts"]) as client:
        for source in config["sources"]:
            validate_official_url(source["url"], config["allowed_hosts"])
            retrieval_mode = "live_official_page"
            hash_scope = "full_response_bytes"
            try:
                raw = client.get_bytes(source["url"])
                text = normalized_source_text(raw).lower()
                evidence_sha256 = hashlib.sha256(raw).hexdigest()
            except (httpx.HTTPError, OfficialSourceError):
                snapshot = snapshots.get(source["document_id"])
                if not isinstance(snapshot, dict) or not isinstance(
                    snapshot.get("normalized_excerpt"), str
                ):
                    raise
                if snapshot.get("source_url") != source["url"]:
                    raise SystemExit("verified snapshot source URL mismatch") from None
                text = " ".join(snapshot["normalized_excerpt"].split()).lower()
                evidence_sha256 = hashlib.sha256(text.encode()).hexdigest()
                retrieval_mode = "verified_official_web_snapshot"
                hash_scope = "normalized_official_excerpt"
            anchor_verified = source["anchor"] in text
            if not anchor_verified:
                blocked.append(f"anchor_not_verified:{source['document_id']}")
            source_rows.append(
                {
                    "document_id": source["document_id"],
                    "published_date": source["published_date"],
                    "source_url": source["url"],
                    "evidence_sha256": evidence_sha256,
                    "hash_scope": hash_scope,
                    "retrieval_mode": retrieval_mode,
                    "anchor_sha256": hashlib.sha256(source["anchor"].encode()).hexdigest(),
                    "anchor_verified": anchor_verified,
                }
            )
    completed_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    missing = tuple(sorted({*config["missing_evidence"], *blocked}))
    review_status = "blocked" if blocked else config["review_status"]
    core = {
        "issuer_id": config["issuer_id"],
        "cik": config["cik"],
        "data_cutoff_date": cutoff,
        "sec_accessions": list(config["sec_accessions"]),
        "sources": source_rows,
        "object_ids": config["object_ids"],
        "coverage": config["coverage"],
        "review_status": review_status,
        "blocked_items": list(missing),
    }
    component_lock = Path(__file__).parents[1] / "component-lock.json"
    run_manifest = RunManifest(
        schema_version="1.0.0",
        run_id=f"management-shadow:{config['issuer_id']}:{cutoff}",
        issuer_id=config["issuer_id"],
        data_cutoff_date=cutoff,
        started_at=started_at,
        completed_at=completed_at,
        component_lock_sha256=file_sha256(component_lock),
        component_versions={"owner-equity-research": COMPONENT_VERSION},
        input_document_hashes={
            item["document_id"]: item["evidence_sha256"] for item in source_rows
        },
        output_artifact_hashes={"management-shadow-summary": canonical_sha256(core)},
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
        "shadow_type": "phase4b_management_ledger",
        **core,
        "run_manifest": run_manifest.to_dict(),
        "network_is_explicit": True,
        "contains_raw_source_content": False,
        "contains_facts": False,
        "contains_claims": False,
        "contains_scores": False,
        "contains_valuation": False,
        "contains_target_price": False,
        "contains_recommendation": False,
        "contains_report": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer", choices=sorted(SHADOWS), required=True)
    parser.add_argument("--cutoff", default=CUTOFF)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verified-snapshot", type=Path)
    args = parser.parse_args()
    run_shadow(
        args.issuer,
        args.cutoff,
        args.output,
        verified_snapshot=args.verified_snapshot,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
