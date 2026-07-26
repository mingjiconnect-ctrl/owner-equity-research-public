#!/usr/bin/env python3
"""Verify the internal, price-blind Phase 5D-1 Candidate compiler boundary."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D0_MERGE = "4814029d9c5a690e2779dcb4e5e800798c663053"
ALLOWED_SOURCE_CHANGES = {
    ("M", "src/owner_research/valuation_assumption_types.py"),
    ("A", "src/owner_research/valuation_assumption_candidates.py"),
}
FORBIDDEN_IMPORTS = {"httpx", "requests", "urllib", "owner_valuation"}
FORBIDDEN_NAMES = {
    "compile_assumption_ledger",
    "review_valuation_assumption_candidates",
    "write_price_blind_input",
    "fetch_market_reference",
    "run_valuation_kernel",
}


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.valuation_assumption_candidates import (
        compile_valuation_assumption_candidates,
    )

    changes = set()
    output = _git(
        "diff",
        "--name-status",
        "--no-renames",
        PHASE5D0_MERGE,
        "--",
        "src/owner_research",
    )
    for line in output.splitlines():
        status, path = line.split("\t", 1)
        changes.add((status, path))
    untracked = _git("ls-files", "--others", "--exclude-standard", "src/owner_research")
    changes.update(("A", path) for path in untracked.splitlines() if path)
    inherited = {
        ("M", "src/owner_research/__init__.py"),
        ("M", "src/owner_research/contracts.py"),
        ("M", "src/owner_research/validation.py"),
        ("M", "src/owner_research/valuation_handoff_policies.py"),
        ("M", "src/owner_research/valuation_handoff_validation.py"),
    }
    if changes - inherited != ALLOWED_SOURCE_CHANGES:
        raise SystemExit(f"Phase 5D-1 source boundary drifted: {changes}")
    if hasattr(owner_research, "compile_valuation_assumption_candidates"):
        raise SystemExit("Phase 5D-1 compiler escaped the package-root boundary")
    if compile_valuation_assumption_candidates.__module__ != (
        "owner_research.valuation_assumption_candidates"
    ):
        raise SystemExit("Phase 5D-1 compiler identity drifted")
    for _, relative in ALLOWED_SOURCE_CHANGES:
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        imports: set[str] = set()
        definitions: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                definitions.add(node.name)
        if imports & FORBIDDEN_IMPORTS:
            raise SystemExit(f"Phase 5D-1 added a forbidden import in {relative}")
        if definitions & FORBIDDEN_NAMES:
            raise SystemExit(f"Phase 5D-1 added a later-phase surface in {relative}")
    if owner_research.__version__ != "0.5.0.dev4":
        raise SystemExit("Phase 5D-1 changed the fixed Phase 5D package version")
    print("Phase 5D-1 internal Candidate compiler boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
