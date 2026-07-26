#!/usr/bin/env python3
"""Verify that the accepted Phase 5P planning baseline was not rewritten."""

from __future__ import annotations

import subprocess
from pathlib import Path

try:
    from scripts.public_bootstrap import commit_exists, verify_public_bootstrap_snapshot
except ModuleNotFoundError:  # Direct ``python -I scripts/...`` execution.
    from public_bootstrap import commit_exists, verify_public_bootstrap_snapshot

ROOT = Path(__file__).resolve().parents[1]
PHASE5P_MERGE = "ba1ac50a7ae5f3f3af637015369599abd24c9b73"
PUBLIC_CANONICAL_MERGE = "184e5097e1da982b63ae818aad2b82a472eab007"
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
    baseline = PHASE5P_MERGE
    if not commit_exists(PHASE5P_MERGE, ROOT):
        verify_public_bootstrap_snapshot(ROOT)
        if not commit_exists(PUBLIC_CANONICAL_MERGE, ROOT):
            raise SystemExit("Canonical public Phase 5P baseline is unavailable")
        baseline = PUBLIC_CANONICAL_MERGE
    ancestry = subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", baseline, "HEAD"]
    )
    if ancestry.returncode:
        raise SystemExit("HEAD is not descended from the accepted Phase 5P merge")
    for relative in IMMUTABLE_PATHS:
        baseline_bytes = _git("show", f"{baseline}:{relative}", text=False)
        current = (ROOT / relative).read_bytes()
        if current != baseline_bytes:
            raise SystemExit(f"Accepted Phase 5P artifact was rewritten: {relative}")
    print("Canonical Phase 5P planning baseline is unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
