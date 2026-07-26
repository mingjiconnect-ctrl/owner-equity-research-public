#!/usr/bin/env python3
"""Verify the canonical Phase 5D-2 review and AssumptionLedger baseline."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D2_CLOSEOUT_MERGE = "78eea32199702c3bc4bd55a0c8c70b5b6caab770"
FROZEN_FILES = (
    "src/owner_research/valuation_assumption_types.py",
    "src/owner_research/valuation_assumption_ledger.py",
    "tests/test_phase5d2_assumption_ledger.py",
    "scripts/verify_phase5d2_assumption_ledger.py",
)


def _git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def main() -> int:
    ancestry = subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "merge-base",
            "--is-ancestor",
            PHASE5D2_CLOSEOUT_MERGE,
            "HEAD",
        ]
    )
    if ancestry.returncode:
        raise SystemExit("HEAD is not descended from the accepted Phase 5D-2 closeout")
    for relative in FROZEN_FILES:
        expected = _git("show", f"{PHASE5D2_CLOSEOUT_MERGE}:{relative}")
        current = (ROOT / relative).read_bytes()
        if hashlib.sha256(current).digest() != hashlib.sha256(expected).digest():
            raise SystemExit(f"Canonical Phase 5D-2 file changed: {relative}")
    print("Canonical Phase 5D-2 AssumptionLedger compiler baseline is unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
