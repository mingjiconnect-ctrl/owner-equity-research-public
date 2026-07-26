#!/usr/bin/env python3
"""Verify the internal Phase 5D-3 McKinsey input boundary."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D2_CLOSEOUT_MERGE = "78eea32199702c3bc4bd55a0c8c70b5b6caab770"
ALLOWED_SOURCE_CHANGES = {
    ("A", "src/owner_research/valuation_mckinsey_inputs.py"),
}
FORBIDDEN_IMPORTS = {"httpx", "requests", "urllib"}
FORBIDDEN_NAMES = {
    "compile_penman_inputs",
    "write_price_blind_input",
    "fetch_market_reference",
    "compile_valuation_request",
    "run_valuation_kernel",
    "calculate_enterprise_dcf",
    "calculate_economic_profit",
}


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.valuation_mckinsey_inputs import (
        KERNEL_MCKINSEY_MODULE_SHA256,
        compile_mckinsey_scenario_inputs,
    )

    changes: set[tuple[str, str]] = set()
    output = _git(
        "diff",
        "--name-status",
        "--no-renames",
        PHASE5D2_CLOSEOUT_MERGE,
        "--",
        "src/owner_research",
    )
    for line in output.splitlines():
        status, path = line.split("\t", 1)
        changes.add((status, path))
    untracked = _git("ls-files", "--others", "--exclude-standard", "src/owner_research")
    changes.update(("A", path) for path in untracked.splitlines() if path)
    if changes != ALLOWED_SOURCE_CHANGES:
        raise SystemExit(f"Phase 5D-3 source boundary drifted: {changes}")
    if hasattr(owner_research, "compile_mckinsey_scenario_inputs"):
        raise SystemExit("Phase 5D-3 compiler escaped the package-root boundary")
    if compile_mckinsey_scenario_inputs.__module__ != (
        "owner_research.valuation_mckinsey_inputs"
    ):
        raise SystemExit("Phase 5D-3 compiler identity drifted")
    if KERNEL_MCKINSEY_MODULE_SHA256 != (
        "011ea8bdbcc8f7cfa4a87c44f3bd059397d93da8d46101816ad5c1dc641ec1e6"
    ):
        raise SystemExit("Pinned McKinsey module identity drifted")
    relative = "src/owner_research/valuation_mckinsey_inputs.py"
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
        raise SystemExit("Phase 5D-3 added a forbidden network import")
    if definitions & FORBIDDEN_NAMES:
        raise SystemExit("Phase 5D-3 added a later-phase or valuation surface")
    if owner_research.__version__ != "0.5.0.dev4":
        raise SystemExit("Phase 5D-3 changed the fixed Phase 5D package version")
    print("Phase 5D-3 McKinsey four-scenario input boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
