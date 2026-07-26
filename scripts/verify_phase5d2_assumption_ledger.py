#!/usr/bin/env python3
"""Verify the internal Phase 5D-2 human-review and AssumptionLedger boundary."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D1_CLOSEOUT_MERGE = "6e5ad16ecf4aa05f47c7375bf1555c8eadb7bb4b"
ALLOWED_SOURCE_CHANGES = {
    ("M", "src/owner_research/valuation_assumption_types.py"),
    ("A", "src/owner_research/valuation_assumption_ledger.py"),
}
FORBIDDEN_IMPORTS = {"httpx", "requests", "urllib"}
FORBIDDEN_NAMES = {
    "compile_mckinsey_scenarios",
    "compile_penman_inputs",
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
    from owner_research.valuation_assumption_ledger import (
        KERNEL_ASSUMPTION_SCHEMA_SHA256,
        compile_reviewed_assumption_ledger,
    )

    changes: set[tuple[str, str]] = set()
    output = _git(
        "diff",
        "--name-status",
        "--no-renames",
        PHASE5D1_CLOSEOUT_MERGE,
        "--",
        "src/owner_research",
    )
    for line in output.splitlines():
        status, path = line.split("\t", 1)
        changes.add((status, path))
    untracked = _git("ls-files", "--others", "--exclude-standard", "src/owner_research")
    changes.update(("A", path) for path in untracked.splitlines() if path)
    if changes != ALLOWED_SOURCE_CHANGES:
        raise SystemExit(f"Phase 5D-2 source boundary drifted: {changes}")
    if hasattr(owner_research, "compile_reviewed_assumption_ledger"):
        raise SystemExit("Phase 5D-2 compiler escaped the package-root boundary")
    if compile_reviewed_assumption_ledger.__module__ != (
        "owner_research.valuation_assumption_ledger"
    ):
        raise SystemExit("Phase 5D-2 compiler identity drifted")
    if KERNEL_ASSUMPTION_SCHEMA_SHA256 != (
        "2232642332dc6444c784e21746cbd16bf8d4cd74fc483a0a345d95f98fc97a7a"
    ):
        raise SystemExit("Pinned AssumptionLedger Schema identity drifted")
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
            raise SystemExit(f"Phase 5D-2 added a forbidden import in {relative}")
        if definitions & FORBIDDEN_NAMES:
            raise SystemExit(f"Phase 5D-2 added a later-phase surface in {relative}")
    if owner_research.__version__ != "0.5.0.dev4":
        raise SystemExit("Phase 5D-2 changed the fixed Phase 5D package version")
    print("Phase 5D-2 human-review and AssumptionLedger boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
