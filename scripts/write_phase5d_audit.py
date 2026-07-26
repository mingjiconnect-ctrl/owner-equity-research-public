#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

AUDIT_TOOL = "owner-research-phase5d-readonly"
AUDIT_VERSION = "2.2.6"


def _sha(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reviewed-commit", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--ci-run-id", action="append", default=[])
    parser.add_argument("--findings-file", type=Path, required=True)
    args = parser.parse_args()
    evidence = json.loads(args.findings_file.read_text())
    if (
        evidence.get("audit_tool") != AUDIT_TOOL
        or evidence.get("audit_version") != AUDIT_VERSION
        or evidence.get("reviewed_commit") != args.reviewed_commit
    ):
        parser.error("findings file audit identity mismatch")
    counts = {priority: 0 for priority in ("P0", "P1", "P2", "P3")}
    for finding in evidence.get("findings", []):
        priority = finding.get("priority")
        if priority not in counts:
            parser.error("findings file contains an invalid priority")
        counts[priority] += 1
    report = {
        "reviewed_commit": args.reviewed_commit,
        "phase5c_baseline_commit": evidence.get("phase5c_baseline_commit"),
        "valuation_kernel_commit": evidence.get("valuation_kernel_commit"),
        "audit_tool": AUDIT_TOOL,
        "audit_version": AUDIT_VERSION,
        "started_at": args.started_at,
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "finding_counts": counts,
        "test_counts": evidence.get("test_counts"),
        "audited_file_sha256": evidence.get("audited_file_sha256"),
        "audit_evidence_sha256": hashlib.sha256(args.findings_file.read_bytes()).hexdigest(),
        "check_count": len(evidence.get("checks", [])),
        "ci_run_ids": sorted(set(args.ci_run_id)),
    }
    report["report_sha256"] = _sha(report)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0 if not any(counts.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
