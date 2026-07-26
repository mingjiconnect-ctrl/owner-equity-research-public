#!/usr/bin/env python3
"""Verify the internal Phase 5D-4 price-blind Penman input boundary."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D3_CLOSEOUT_MERGE = "0eea5f1107ec8e3dc9a211febf1fa52f4c99911f"
ALLOWED_SOURCE_CHANGES = {
    ("A", "src/owner_research/valuation_penman_inputs.py"),
}
FORBIDDEN_IMPORTS = {"httpx", "requests", "urllib"}
FORBIDDEN_NAMES = {
    "write_price_blind_input",
    "fetch_market_reference",
    "compile_valuation_request",
    "run_valuation_kernel",
    "no_growth_anchor",
    "reverse_implied_growth",
    "reverse_implied_fade_weight",
    "reverse_implied_cap",
    "growth_return_profile",
    "hurdle_rate_comparisons",
}


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.valuation_penman_inputs import (
        KERNEL_PENMAN_MODULE_SHA256,
        compile_penman_price_blind_inputs,
    )

    changes: set[tuple[str, str]] = set()
    output = _git(
        "diff",
        "--name-status",
        "--no-renames",
        PHASE5D3_CLOSEOUT_MERGE,
        "--",
        "src/owner_research",
    )
    for line in output.splitlines():
        status, path = line.split("\t", 1)
        changes.add((status, path))
    untracked = _git("ls-files", "--others", "--exclude-standard", "src/owner_research")
    changes.update(("A", path) for path in untracked.splitlines() if path)
    if changes != ALLOWED_SOURCE_CHANGES:
        raise SystemExit(f"Phase 5D-4 source boundary drifted: {changes}")
    if hasattr(owner_research, "compile_penman_price_blind_inputs"):
        raise SystemExit("Phase 5D-4 compiler escaped the package-root boundary")
    if compile_penman_price_blind_inputs.__module__ != (
        "owner_research.valuation_penman_inputs"
    ):
        raise SystemExit("Phase 5D-4 compiler identity drifted")
    if KERNEL_PENMAN_MODULE_SHA256 != (
        "a540ea5f09dfb6008a09d4544f24737ca7674f11d15c48cb8d7c1e56ed4ef885"
    ):
        raise SystemExit("Pinned Penman module identity drifted")
    relative = "src/owner_research/valuation_penman_inputs.py"
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
        raise SystemExit("Phase 5D-4 added a forbidden network import")
    if definitions & FORBIDDEN_NAMES:
        raise SystemExit("Phase 5D-4 added market, persistence, or valuation mathematics")
    source = (ROOT / relative).read_text(encoding="utf-8")
    if "market_equity_value_fact_id" not in source or "include_cap_diagnostic" not in source:
        raise SystemExit("Phase 5D-4 omits explicit anti-anchoring guards")
    if owner_research.__version__ != "0.5.0.dev4":
        raise SystemExit("Phase 5D-4 changed the fixed Phase 5D package version")
    print("Phase 5D-4 price-blind Penman input boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
