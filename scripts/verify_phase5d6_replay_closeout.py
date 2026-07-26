#!/usr/bin/env python3
"""Verify the non-production Phase 5D-6 replay and closeout boundary."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D5_CLOSEOUT_MERGE = "087146b212067d6e3fcae651256fa1478cb967d4"
ALLOWED_TOP_LEVEL_CHANGES = {
    "AGENTS.md",
    "README.md",
    "docs",
    "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md",
    "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md",
    "scripts",
    "tests",
}


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def _allowed(relative: str) -> bool:
    return any(
        relative == prefix or relative.startswith(f"{prefix}/")
        for prefix in ALLOWED_TOP_LEVEL_CHANGES
    )


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research

    changes_set = {
        item
        for item in _git(
            "diff",
            "--name-only",
            "--no-renames",
            PHASE5D5_CLOSEOUT_MERGE,
            "HEAD",
        ).splitlines()
        if item
    }
    changes_set.update(
        item
        for item in _git("diff", "--name-only", "--no-renames").splitlines()
        if item
    )
    changes_set.update(
        item
        for item in _git("ls-files", "--others", "--exclude-standard").splitlines()
        if item and not item.startswith("_deps/")
    )
    changes = tuple(sorted(changes_set))
    forbidden = tuple(item for item in changes if not _allowed(item))
    if forbidden:
        raise SystemExit(f"Phase 5D-6 changed a forbidden path: {forbidden}")
    source_changes = tuple(item for item in changes if item.startswith("src/"))
    schema_changes = tuple(item for item in changes if item.startswith("schemas/"))
    if source_changes or schema_changes:
        raise SystemExit("Phase 5D-6 may not change production source or public schemas")
    for frozen in ("pyproject.toml", "component-lock.json"):
        if (ROOT / frozen).read_bytes() != subprocess.check_output(
            ["git", "-C", str(ROOT), "show", f"{PHASE5D5_CLOSEOUT_MERGE}:{frozen}"]
        ):
            raise SystemExit(f"Phase 5D-6 changed frozen metadata: {frozen}")
    if owner_research.__version__ != "0.5.0.dev4":
        raise SystemExit("Phase 5D-6 changed the fixed Phase 5D package version")
    if len(tuple((ROOT / "schemas").glob("*.schema.json"))) != 43:
        raise SystemExit("Phase 5D-6 changed the 43-schema public contract surface")
    plugin = json.loads(
        (ROOT / "plugins/owner-equity-research/.codex-plugin/plugin.json").read_text()
    )
    lock = json.loads((ROOT / "component-lock.json").read_text())
    if (
        plugin["version"] != "0.5.0-dev.4"
        or lock["owner_equity_research"]["plugin_version"] != "0.5.0-dev.4"
    ):
        raise SystemExit("Phase 5D-6 changed the fixed Plugin version")
    if _git("tag", "--list", "v0.5.0-alpha.1"):
        raise SystemExit("Phase 5D-6 must not create the Phase 5 release tag")
    required = {
        "tests/test_phase5d6_replay_closeout.py",
        "scripts/verify_phase5d5_baseline.py",
        "scripts/verify_phase5d6_replay_closeout.py",
    }
    if not required.issubset(set(changes)):
        raise SystemExit("Phase 5D-6 replay or baseline proof is missing")
    print("Phase 5D-6 deterministic replay and closeout boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
