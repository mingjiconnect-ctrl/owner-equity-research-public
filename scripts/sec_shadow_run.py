#!/usr/bin/env python3
"""Run an explicit, metadata-only SEC shadow acceptance.

This command is intentionally not called by CI.  It downloads the latest qualifying
10-K and 10-Q at a fixed cutoff, writes only hashes/accessions/coverage, and never
serializes filing HTML, Facts, recommendations, valuation, or a company report.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import httpx

from owner_research.contracts import SourceDocument
from owner_research.extraction import extract_ixbrl_candidates
from owner_research.footnotes import REQUIRED_TOPICS, discover_note_headings, discover_topic_codes
from owner_research.sec import (
    PARSER_VERSION,
    SecClient,
    SecIntakeError,
    build_filing_artifact,
    select_latest_filings,
)

ISSUERS = {
    "amazon": {"issuer_id": "issuer:amazon", "cik": "1018724"},
    "salesforce": {"issuer_id": "issuer:salesforce", "cik": "1108524"},
}


def _document(issuer_id: str, selection, raw: bytes, retrieved_at: str) -> SourceDocument:
    import hashlib

    return SourceDocument(
        schema_version="1.0.0",
        document_id=f"doc:{issuer_id}:{selection.accession}",
        issuer_id=issuer_id,
        document_type=selection.form,
        period={"start": None, "end": selection.report_period},
        published_date=selection.filing_date,
        retrieved_at=retrieved_at,
        source_url=selection.source_url,
        authority_level="primary_regulatory",
        content_sha256=hashlib.sha256(raw).hexdigest(),
    )


def run_shadow(issuer: str, cutoff: str, output: Path) -> dict:
    try:
        identity = ISSUERS[issuer.lower()]
    except KeyError as exc:
        raise SystemExit(f"unsupported shadow issuer: {issuer}") from exc
    user_agent = os.environ.get("OWNER_RESEARCH_SEC_USER_AGENT", "").strip()
    if not user_agent:
        raise SystemExit("OWNER_RESEARCH_SEC_USER_AGENT is required for a live shadow run")

    retrieved_at = (
        datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    filings = []
    blocked_items: list[str] = []
    with SecClient(user_agent=user_agent) as client:
        try:
            selections = select_latest_filings(
                client.submissions(identity["cik"]), cik=identity["cik"], cutoff_date=cutoff
            )
        except (httpx.HTTPError, SecIntakeError) as exc:
            selections = {}
            blocked_items.append(f"submissions_unavailable:{type(exc).__name__}")
        for form in ("10-K", "10-Q"):
            selection = selections.get(form)
            if selection is None:
                continue
            try:
                raw = client.get_bytes(selection.source_url)
            except httpx.HTTPError as exc:
                blocked_items.append(f"{form}_unavailable:{type(exc).__name__}")
                filings.append(
                    {
                        "form": form,
                        "accession": selection.accession,
                        "filing_date": selection.filing_date,
                        "report_period": selection.report_period,
                        "blocked_items": [f"sec_fetch_error:{type(exc).__name__}"],
                    }
                )
                continue
            document = _document(identity["issuer_id"], selection, raw, retrieved_at)
            artifact = build_filing_artifact(
                issuer_id=identity["issuer_id"],
                source_document_id=document.document_id,
                selection=selection,
                raw=raw,
                retrieved_at=retrieved_at,
            )
            topics = set(discover_topic_codes(raw))
            candidates = extract_ixbrl_candidates(raw, artifact=artifact, source_document=document)
            filings.append(
                {
                    "form": form,
                    "accession": selection.accession,
                    "filing_date": selection.filing_date,
                    "report_period": selection.report_period,
                    "raw_sha256": artifact.raw_sha256,
                    "normalized_sha256": artifact.normalized_sha256,
                    "parser_version": PARSER_VERSION,
                    "note_heading_count": len(discover_note_headings(raw)),
                    "ixbrl_candidate_count": len(candidates),
                    "footnote_coverage": sorted(topics),
                    "blocked_items": [
                        f"missing_mandatory_topic:{topic}"
                        for topic in REQUIRED_TOPICS
                        if topic not in topics
                    ]
                    + (
                        ["note_heading_discovery_unresolved"]
                        if not discover_note_headings(raw)
                        else []
                    ),
                }
            )

    for filing in filings:
        blocked_items.extend(
            f"{filing['form']}:{item}" for item in filing.get("blocked_items", [])
        )

    manifest = {
        "manifest_version": "1.0.0",
        "shadow_type": "sec_filing_accounting_quality",
        "issuer_id": identity["issuer_id"],
        "cik": identity["cik"],
        "data_cutoff_date": cutoff,
        "retrieved_at": retrieved_at,
        "parser_version": PARSER_VERSION,
        "validation_status": (
            "blocked"
            if blocked_items and not filings
            else ("partial" if blocked_items else "complete")
        ),
        "filings": filings,
        "blocked_items": blocked_items,
        "network_is_explicit": True,
        "contains_raw_filing_content": False,
        "contains_facts": False,
        "contains_claims": False,
        "contains_scores": False,
        "contains_valuation": False,
        "contains_report": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer", choices=sorted(ISSUERS), required=True)
    parser.add_argument("--cutoff", default="2026-07-11")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run_shadow(args.issuer, args.cutoff, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
