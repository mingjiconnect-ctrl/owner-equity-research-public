#!/usr/bin/env python3
"""Verify that the accepted Phase 5P planning baseline was not rewritten."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5P_MERGE = "ba1ac50a7ae5f3f3af637015369599abd24c9b73"
IMMUTABLE_PATHS = (
    "docs/phase5-plan.md",
    "docs/phase5-methodology.md",
    "docs/phase5-interface-matrix.json",
    "docs/phase5-failure-mode-matrix.json",
    "docs/adr/0023-research-to-valuation-boundary.md",
    "docs/phase5-acceptance.md",
    "scripts/run_phase5p_audit.py",
    "scripts/verify_phase5p_plan.py",
    "scripts/write_phase5p_audit.py",
)


def _git(*args: str, text: bool = True) -> str | bytes:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args],
        text=text,
        stderr=subprocess.STDOUT,
    )


def main() -> int:
    ancestry = subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", PHASE5P_MERGE, "HEAD"]
    )
    if ancestry.returncode:
        raise SystemExit("HEAD is not descended from the accepted Phase 5P merge")
    for relative in IMMUTABLE_PATHS:
        baseline = _git("show", f"{PHASE5P_MERGE}:{relative}", text=False)
        current = (ROOT / relative).read_bytes()
        if current != baseline:
            raise SystemExit(f"Accepted Phase 5P artifact was rewritten: {relative}")
    print("Canonical Phase 5P planning baseline is unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
