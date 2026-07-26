#!/usr/bin/env python3
"""Verify that the accepted Phase 5B implementation and audit remain byte-frozen."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5B_MERGE = "17afbdc9464af2310f2bf5be72df87f3da9fbbc2"
IMMUTABLE_PATHS = (
    "docs/adr/0025-phase5b-fact-mapping-boundary.md",
    "docs/phase5b-mapping-policy.md",
    "evals/future-valuation-mapping.json",
    "scripts/run_phase5b_audit.py",
    "scripts/verify_phase5b_mapping.py",
    "scripts/write_phase5b_audit.py",
    "src/owner_research/research_bundle_validation.py",
    "src/owner_research/valuation_fact_mapping.py",
    "src/owner_research/valuation_fact_mapping_policies.py",
    "src/owner_research/valuation_fact_mapping_types.py",
    "src/owner_research/valuation_readiness.py",
    "tests/fixtures/phase5b/adversarial-cases.json",
    "tests/fixtures/phase5b/golden-readiness-cases.json",
    "tests/test_phase5b0_mapping_policies.py",
    "tests/test_phase5b1_raw_fact_compiler.py",
    "tests/test_phase5b2_derived_lineage.py",
    "tests/test_phase5b3_readiness_routing.py",
    "tests/test_phase5b4_replay_closeout.py",
)


def _git(*args: str, text: bool = True) -> str | bytes:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args],
        text=text,
        stderr=subprocess.STDOUT,
    )


def main() -> int:
    ancestry = subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", PHASE5B_MERGE, "HEAD"]
    )
    if ancestry.returncode:
        raise SystemExit("HEAD is not descended from the accepted Phase 5B merge")
    for relative in IMMUTABLE_PATHS:
        baseline = _git("show", f"{PHASE5B_MERGE}:{relative}", text=False)
        current = (ROOT / relative).read_bytes()
        if current != baseline:
            raise SystemExit(f"Accepted Phase 5B artifact was rewritten: {relative}")

    baseline_lock = json.loads(
        _git("show", f"{PHASE5B_MERGE}:component-lock.json", text=True)
    )
    current_lock = json.loads((ROOT / "component-lock.json").read_text(encoding="utf-8"))
    current_schemas = current_lock["owner_equity_research"]["public_schema_sha256"]
    baseline_schemas = baseline_lock["owner_equity_research"]["public_schema_sha256"]
    if set(current_schemas) != set(baseline_schemas) or len(current_schemas) != 43:
        raise SystemExit("Phase 5B public Schema registry membership was rewritten")
    later_phase_contracts = {
        "schemas/market-reference-snapshot.schema.json",
        "schemas/valuation-assumption-candidate.schema.json",
        "schemas/valuation-handoff.schema.json",
    }
    for relative, expected in baseline_schemas.items():
        if relative not in later_phase_contracts and current_schemas[relative] != expected:
            raise SystemExit(f"Phase 5B-owned public Schema hash was rewritten: {relative}")
    if current_lock["valuation_kernel"] != baseline_lock["valuation_kernel"]:
        raise SystemExit("Pinned valuation-kernel identity or Schema hashes drifted")
    for relative, expected in current_schemas.items():
        actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"Public research Schema bytes drifted: {relative}")
    print("Canonical Phase 5B mapping and readiness baseline is unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
