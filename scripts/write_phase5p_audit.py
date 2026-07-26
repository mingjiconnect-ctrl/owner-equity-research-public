#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

AUDIT_TOOL = "owner-research-phase5p-readonly"
AUDIT_VERSION = "1.8.0"


def _canonical_sha256(payload: object) -> str:
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reviewed-commit", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--ci-run-id", action="append", default=[])
    parser.add_argument("--findings-file", type=Path, required=True)
    args = parser.parse_args()

    evidence = json.loads(args.findings_file.read_text(encoding="utf-8"))
    if evidence.get("audit_tool") != AUDIT_TOOL or evidence.get("audit_version") != AUDIT_VERSION:
        parser.error("findings file audit identity mismatch")
    if evidence.get("reviewed_commit") != args.reviewed_commit:
        parser.error("findings file reviewed commit mismatch")
    findings = evidence.get("findings")
    if not isinstance(findings, list):
        parser.error("findings file lacks a findings list")
    counts = {priority: 0 for priority in ("P0", "P1", "P2", "P3")}
    for finding in findings:
        priority = finding.get("priority") if isinstance(finding, dict) else None
        if priority not in counts:
            parser.error("findings file contains an invalid priority")
        counts[priority] += 1
    test_counts = evidence.get("test_counts")
    if not isinstance(test_counts, dict) or set(test_counts) != {
        "collected_tests",
        "passed_tests",
        "skipped_tests",
        "failed_tests",
    }:
        parser.error("findings file lacks machine-readable test counts")
    document_hashes = evidence.get("planning_document_sha256")
    if not isinstance(document_hashes, dict) or len(document_hashes) != 6:
        parser.error("findings file lacks the six planning-document hashes")
    report = {
        "reviewed_commit": args.reviewed_commit,
        "research_baseline_commit": evidence.get("research_baseline_commit"),
        "valuation_kernel_commit": evidence.get("valuation_kernel_commit"),
        "audit_tool": AUDIT_TOOL,
        "audit_version": AUDIT_VERSION,
        "started_at": args.started_at,
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "finding_counts": counts,
        "test_counts": test_counts,
        "planning_document_sha256": document_hashes,
        "audit_evidence_sha256": hashlib.sha256(args.findings_file.read_bytes()).hexdigest(),
        "check_count": len(evidence.get("checks", [])),
        "ci_run_ids": sorted(set(args.ci_run_id)),
    }
    report["report_sha256"] = _canonical_sha256(report)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
