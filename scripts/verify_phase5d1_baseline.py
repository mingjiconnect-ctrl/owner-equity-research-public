#!/usr/bin/env python3
"""Verify the canonical Phase 5D-1 Candidate compiler implementation baseline."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D1_CLOSEOUT_MERGE = "6e5ad16ecf4aa05f47c7375bf1555c8eadb7bb4b"
FROZEN_FILES = (
    "src/owner_research/valuation_assumption_candidates.py",
    "tests/test_phase5d1_assumption_candidates.py",
    "scripts/verify_phase5d1_candidates.py",
)


def _git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def main() -> int:
    for relative in FROZEN_FILES:
        expected = _git("show", f"{PHASE5D1_CLOSEOUT_MERGE}:{relative}")
        current = (ROOT / relative).read_bytes()
        if hashlib.sha256(current).digest() != hashlib.sha256(expected).digest():
            raise SystemExit(f"Canonical Phase 5D-1 file changed: {relative}")
    print("Canonical Phase 5D-1 Candidate compiler baseline is unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
