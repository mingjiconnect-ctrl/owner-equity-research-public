#!/usr/bin/env python3
"""Verify the canonical accepted Phase 5D-6 closeout baseline."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D6_CLOSEOUT_MERGE = "bdac6e4a23e821c73a2545167f478cfc0348316f"
FROZEN_FILES = (
    "docs/phase5d-closeout.md",
    "scripts/verify_phase5d6_replay_closeout.py",
    "tests/test_phase5d6_replay_closeout.py",
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
            PHASE5D6_CLOSEOUT_MERGE,
            "HEAD",
        ],
        check=False,
    )
    if ancestry.returncode:
        raise SystemExit("HEAD is not descended from the accepted Phase 5D baseline")
    for relative in FROZEN_FILES:
        expected = _git("show", f"{PHASE5D6_CLOSEOUT_MERGE}:{relative}")
        current = (ROOT / relative).read_bytes()
        if hashlib.sha256(current).digest() != hashlib.sha256(expected).digest():
            raise SystemExit(f"Canonical Phase 5D-6 file changed: {relative}")
    print("Canonical Phase 5D-6 replay and closeout baseline is unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
