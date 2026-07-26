#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from owner_research.fingerprints import canonical_sha256

AUDIT_TOOL = "owner-research-phase4a-readonly"
AUDIT_VERSION = "1.1.0"


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
    finding_counts = {priority: 0 for priority in ("P0", "P1", "P2", "P3")}
    for finding in findings:
        priority = finding.get("priority") if isinstance(finding, dict) else None
        if priority not in finding_counts:
            parser.error("findings file contains an invalid priority")
        finding_counts[priority] += 1

    report = {
        "reviewed_commit": args.reviewed_commit,
        "audit_tool": AUDIT_TOOL,
        "audit_version": AUDIT_VERSION,
        "started_at": args.started_at,
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "finding_counts": finding_counts,
        "audit_evidence_sha256": hashlib.sha256(args.findings_file.read_bytes()).hexdigest(),
        "check_count": len(evidence.get("checks", [])),
        "ci_run_ids": sorted(set(args.ci_run_id)),
    }
    report["report_sha256"] = canonical_sha256(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    full_sha256 = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(f"phase4a audit report: {args.output}")
    print(f"canonical report sha256: {report['report_sha256']}")
    print(f"artifact sha256: {full_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
