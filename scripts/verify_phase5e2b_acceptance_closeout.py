#!/usr/bin/env python3
"""Verify the governance-only Phase 5E-2B acceptance closeout."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_MERGE = "8e9d1f5e233c3d73cbcb97952c915d7f784e8970"
IMPLEMENTATION_HEAD = "2b9618f39eef99820cc03690b0d21e44d00dddac"
IMPLEMENTATION_TREE = "ff650c4503789eb1c434f34d5859b818c333f639"
GOVERNANCE_BASELINE = "1449e544d9907297c43c8d930d33170c45a60abb"
ALLOWED_FILES = {
    "AGENTS.md",
    "README.md",
    "docs/phase-status.json",
    "docs/phase5e2b-acceptance-closeout.md",
    "docs/phase5e2b-current-share-compilation.md",
    "docs/roadmap.md",
    "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md",
    "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md",
    "scripts/run_phase5e_audit.py",
    "scripts/verify_all.py",
    "scripts/verify_phase5e2b_acceptance_closeout.py",
    "scripts/verify_phase_state.py",
    "tests/test_phase4d5_phase_state.py",
    "tests/test_phase5e_audit.py",
}
FROZEN_FILES = {
    "component-lock.json",
    "pyproject.toml",
    "schemas/market-reference-snapshot.schema.json",
    "src/owner_research/__init__.py",
    "src/owner_research/valuation_current_share_compiler.py",
    "src/owner_research/valuation_handoff_validation.py",
    "src/owner_research/valuation_market_reference_types.py",
}


def _git(*args: str, text: bool = True) -> str | bytes:
    value = subprocess.check_output(
        ["git", "-C", str(ROOT), *args],
        text=text,
        stderr=subprocess.STDOUT,
    )
    return value.strip() if text else value


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    if subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", IMPLEMENTATION_MERGE, "HEAD"]
    ).returncode:
        raise SystemExit("acceptance closeout is not based on the implementation merge")
    changed = set(
        _git("diff", "--name-only", IMPLEMENTATION_MERGE, GOVERNANCE_BASELINE).splitlines()
    )
    if changed != ALLOWED_FILES:
        raise SystemExit(f"acceptance closeout changed an invalid file set: {sorted(changed)}")
    for relative in FROZEN_FILES:
        baseline = _git("show", f"{IMPLEMENTATION_MERGE}:{relative}", text=False)
        assert isinstance(baseline, bytes)
        current_baseline = _git("show", f"{GOVERNANCE_BASELINE}:{relative}", text=False)
        assert isinstance(current_baseline, bytes)
        if _sha(current_baseline) != _sha(baseline) or _sha(
            (ROOT / relative).read_bytes()
        ) != _sha(current_baseline):
            raise SystemExit(f"acceptance closeout changed frozen semantics: {relative}")
    state = json.loads((ROOT / "docs/phase-status.json").read_text(encoding="utf-8"))
    closeout = state["closeout"]["historical_phase5e2b_closeout"]
    if (
        state["current_phase"] != "Phase 5E-2B.1"
        or state["status"] != "semantic_closeout_required"
        or state["authorized_next"]
        != ["Phase 5E-2B.1-1 cross-source share-event grouping implementation"]
        or "Phase 5E-2C" not in state["prohibited"]
        or "Phase 5E-2D" not in state["prohibited"]
        or state["release_tag"] is not None
        or closeout["substantive_head_commit"] != IMPLEMENTATION_HEAD
        or closeout["substantive_merge_commit"] != IMPLEMENTATION_MERGE
        or closeout["substantive_tree_sha"] != IMPLEMENTATION_TREE
        or any(closeout["audit"]["finding_counts"].values())
    ):
        raise SystemExit("historical Phase 5E-2B evidence or corrective boundary drifted")
    if _git("rev-parse", f"{IMPLEMENTATION_HEAD}^{{tree}}") != IMPLEMENTATION_TREE or _git(
        "rev-parse", f"{IMPLEMENTATION_MERGE}^{{tree}}"
    ) != IMPLEMENTATION_TREE:
        raise SystemExit("implementation head and merge do not share the recorded tree")
    print("Historical Phase 5E-2B closeout preserved behind corrective boundary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
