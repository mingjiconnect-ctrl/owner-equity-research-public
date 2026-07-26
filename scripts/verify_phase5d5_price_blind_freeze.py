#!/usr/bin/env python3
"""Verify the internal Phase 5D-5 canonical price-blind freeze boundary."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D4_CLOSEOUT_MERGE = "217a364742beb4fc61342126cc76ae5833a01d22"
ALLOWED_SOURCE_CHANGES = {
    ("A", "src/owner_research/valuation_price_blind_freeze.py"),
}
FORBIDDEN_IMPORTS = {"httpx", "requests", "urllib"}
FORBIDDEN_NAMES = {
    "fetch_market_reference",
    "compile_valuation_request",
    "run_valuation_kernel",
    "write_valuation_result",
    "build_market_reference_snapshot",
}


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.valuation_price_blind_freeze import (
        PRICE_BLIND_INPUT_FILENAME,
        compile_price_blind_input_freeze,
        load_price_blind_input_artifact,
        write_price_blind_input_artifact,
    )

    changes: set[tuple[str, str]] = set()
    output = _git(
        "diff",
        "--name-status",
        "--no-renames",
        PHASE5D4_CLOSEOUT_MERGE,
        "--",
        "src/owner_research",
    )
    for line in output.splitlines():
        status, path = line.split("\t", 1)
        changes.add((status, path))
    untracked = _git("ls-files", "--others", "--exclude-standard", "src/owner_research")
    changes.update(("A", path) for path in untracked.splitlines() if path)
    if changes != ALLOWED_SOURCE_CHANGES:
        raise SystemExit(f"Phase 5D-5 source boundary drifted: {changes}")
    for name in (
        "compile_price_blind_input_freeze",
        "write_price_blind_input_artifact",
        "load_price_blind_input_artifact",
    ):
        if hasattr(owner_research, name):
            raise SystemExit(f"Phase 5D-5 internal API escaped package root: {name}")
    if PRICE_BLIND_INPUT_FILENAME != "price-blind-input.json":
        raise SystemExit("Phase 5D-5 canonical artifact filename drifted")
    if compile_price_blind_input_freeze.__module__ != (
        "owner_research.valuation_price_blind_freeze"
    ) or write_price_blind_input_artifact.__module__ != (
        "owner_research.valuation_price_blind_freeze"
    ) or load_price_blind_input_artifact.__module__ != (
        "owner_research.valuation_price_blind_freeze"
    ):
        raise SystemExit("Phase 5D-5 internal compiler or artifact API identity drifted")
    relative = "src/owner_research/valuation_price_blind_freeze.py"
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
        raise SystemExit("Phase 5D-5 added a forbidden network import")
    if definitions & FORBIDDEN_NAMES:
        raise SystemExit("Phase 5D-5 added market, request/result, or valuation execution")
    source = (ROOT / relative).read_text(encoding="utf-8")
    required = {
        "price_blind_input_fingerprint",
        "protected_mckinsey_sha256",
        "protected_penman_assumptions_sha256",
        "price_blind_input_frozen",
        "market_reference_allowed",
        "market_equity_value_fact_id",
    }
    missing = sorted(token for token in required if token not in source)
    if missing:
        raise SystemExit(f"Phase 5D-5 anti-anchoring guards are missing: {missing}")
    if owner_research.__version__ != "0.5.0.dev4":
        raise SystemExit("Phase 5D-5 changed the fixed Phase 5D package version")
    print("Phase 5D-5 canonical price-blind freeze boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
