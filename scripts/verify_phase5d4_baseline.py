#!/usr/bin/env python3
"""Verify the canonical accepted Phase 5D-4 baseline."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D4_CLOSEOUT_MERGE = "217a364742beb4fc61342126cc76ae5833a01d22"
FROZEN_FILES = (
    "src/owner_research/valuation_penman_inputs.py",
    "tests/test_phase5d4_penman_inputs.py",
    "scripts/verify_phase5d4_penman_inputs.py",
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
            PHASE5D4_CLOSEOUT_MERGE,
            "HEAD",
        ]
    )
    if ancestry.returncode:
        raise SystemExit("HEAD is not descended from the accepted Phase 5D-4 closeout")
    for relative in FROZEN_FILES:
        expected = _git("show", f"{PHASE5D4_CLOSEOUT_MERGE}:{relative}")
        current = (ROOT / relative).read_bytes()
        if hashlib.sha256(current).digest() != hashlib.sha256(expected).digest():
            raise SystemExit(f"Canonical Phase 5D-4 file changed: {relative}")
    print("Canonical Phase 5D-4 Penman input baseline is unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
