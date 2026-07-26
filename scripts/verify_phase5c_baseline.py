#!/usr/bin/env python3
"""Verify that accepted Phase 5C implementation artifacts remain byte-frozen."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5C_BASELINE = "d3028bc7a601c63aebf9faf136ce133e4097b9d2"
IMMUTABLE_PATHS = (
    "docs/adr/0026-phase5c-accounting-equity-bridge-boundary.md",
    "docs/phase5c-accounting-equity-bridge-policy.md",
    "docs/phase5c-failure-mode-matrix.json",
    "scripts/run_phase5c_audit.py",
    "scripts/verify_phase5c_policies.py",
    "scripts/write_phase5c_audit.py",
    "src/owner_research/valuation_accounting_policies.py",
    "src/owner_research/valuation_accounting_quality.py",
    "src/owner_research/valuation_accounting_reconciliation.py",
    "src/owner_research/valuation_accounting_types.py",
    "src/owner_research/valuation_equity_bridge.py",
    "src/owner_research/valuation_method_views.py",
    "src/owner_research/valuation_phase5c_readiness.py",
    "tests/fixtures/phase5c/adversarial-cases.json",
    "tests/test_phase5c0_accounting_bridge_policies.py",
    "tests/test_phase5c1_accounting_reconciliation.py",
    "tests/test_phase5c2_accounting_quality_adjustments.py",
    "tests/test_phase5c3_method_views.py",
    "tests/test_phase5c4_equity_bridge.py",
    "tests/test_phase5c5_readiness_closeout.py",
)


def _git(*args: str, text: bool = True) -> str | bytes:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=text, stderr=subprocess.STDOUT
    )


def main() -> int:
    ancestry = subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", PHASE5C_BASELINE, "HEAD"]
    )
    if ancestry.returncode:
        raise SystemExit("HEAD is not descended from the accepted Phase 5C baseline")
    for relative in IMMUTABLE_PATHS:
        baseline = _git("show", f"{PHASE5C_BASELINE}:{relative}", text=False)
        if (ROOT / relative).read_bytes() != baseline:
            raise SystemExit(f"Accepted Phase 5C artifact was rewritten: {relative}")
    print("Canonical Phase 5C implementation baseline is unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
