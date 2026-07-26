#!/usr/bin/env python3
"""Verify the canonical accepted Phase 5D-5 freeze baseline."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D5_CLOSEOUT_MERGE = "087146b212067d6e3fcae651256fa1478cb967d4"
FROZEN_FILES = (
    "docs/adr/0028-phase5d5-price-blind-freeze.md",
    "src/owner_research/valuation_price_blind_freeze.py",
    "tests/test_phase5d5_price_blind_freeze.py",
    "scripts/verify_phase5d5_price_blind_freeze.py",
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
            PHASE5D5_CLOSEOUT_MERGE,
            "HEAD",
        ]
    )
    if ancestry.returncode:
        raise SystemExit("HEAD is not descended from the accepted Phase 5D-5 closeout")
    for relative in FROZEN_FILES:
        expected = _git("show", f"{PHASE5D5_CLOSEOUT_MERGE}:{relative}")
        current = (ROOT / relative).read_bytes()
        if hashlib.sha256(current).digest() != hashlib.sha256(expected).digest():
            raise SystemExit(f"Canonical Phase 5D-5 file changed: {relative}")
    print("Canonical Phase 5D-5 price-blind freeze baseline is unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
