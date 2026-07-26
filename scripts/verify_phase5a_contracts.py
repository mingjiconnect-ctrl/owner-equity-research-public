#!/usr/bin/env python3
"""Verify the closed, validation-only Phase 5A surface."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5A_SCHEMAS = {
    "market-reference-snapshot",
    "valuation-assumption-candidate",
    "valuation-assumption-review-decision",
    "valuation-handoff",
}
FORBIDDEN_PUBLIC_NAMES = {
    "build_valuation_handoff",
    "compile_fact_ledger",
    "compile_assumption_ledger",
    "fetch_market_reference",
    "run_valuation_kernel",
    "write_valuation_artifacts",
}


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.schema_store import SCHEMA_NAMES

    if len(SCHEMA_NAMES) != 43 or not PHASE5A_SCHEMAS.issubset(SCHEMA_NAMES):
        raise SystemExit("Phase 5A must expose exactly four new schemas and 43 total schemas")
    if any(hasattr(owner_research, name) for name in FORBIDDEN_PUBLIC_NAMES):
        raise SystemExit("Phase 5A exposed a forbidden production API")
    lock = json.loads((ROOT / "component-lock.json").read_text())
    if len(lock["owner_equity_research"]["public_schema_sha256"]) != 43:
        raise SystemExit("component lock does not contain 43 research schema hashes")
    if lock["valuation_kernel"]["commit"] != ("a7dd1528c34f09702686b32ffbb8a397439665f0"):
        raise SystemExit("valuation-kernel commit drifted")
    subprocess.run([sys.executable, "scripts/verify_phase5p_baseline.py"], cwd=ROOT, check=True)
    print("Phase 5A validation-only contract surface passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
