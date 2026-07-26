#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "3fbd39f9d16af467a73bff670600b692ff0f3756"
FROZEN_FILES = (
    "component-lock.json",
    "pyproject.toml",
    "plugins/owner-equity-research/.codex-plugin/plugin.json",
    "src/owner_research/__init__.py",
    "src/owner_research/valuation_current_share_compiler.py",
    "src/owner_research/valuation_current_share_evidence.py",
    "src/owner_research/valuation_share_event_identity.py",
    "docs/adr/0036-phase5e2b1-cross-source-share-event-identity.md",
    "docs/phase5e2b1-share-event-identity-policy.md",
    "tests/fixtures/phase5e2b1/adversarial-cases.json",
    "tests/test_phase5e2b1_share_event_identity_policy.py",
    "scripts/verify_phase5e2b1_cross_source_red.py",
    "scripts/verify_phase5e2b_acceptance_closeout.py",
)
FROZEN_TREES = ("schemas", "src/owner_research/resources/market_access")


def _git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def main() -> int:
    subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", BASELINE, "HEAD"],
        check=True,
    )
    for relative in FROZEN_FILES:
        expected = _git("show", f"{BASELINE}:{relative}")
        actual = (ROOT / relative).read_bytes()
        if actual != expected:
            raise SystemExit(f"Phase 5E-2B.1-0 frozen file drifted: {relative}")
    for relative in FROZEN_TREES:
        expected = _git("rev-parse", f"{BASELINE}:{relative}").strip()
        actual = _git("rev-parse", f"HEAD:{relative}").strip()
        if actual != expected:
            raise SystemExit(f"Phase 5E-2B.1-0 frozen tree drifted: {relative}")
    print("Phase 5E-2B.1-0 frozen policy and historical governance verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
