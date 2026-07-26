#!/usr/bin/env python3
"""Verify the validation-only Phase 5D-0 assumption-governance boundary."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5C_BASELINE = "d3028bc7a601c63aebf9faf136ce133e4097b9d2"
ALLOWED_SOURCE_CHANGES = {
    ("M", "src/owner_research/__init__.py"),
    ("M", "src/owner_research/contracts.py"),
    ("M", "src/owner_research/validation.py"),
    ("A", "src/owner_research/valuation_assumption_types.py"),
    ("M", "src/owner_research/valuation_handoff_policies.py"),
    ("M", "src/owner_research/valuation_handoff_validation.py"),
}
FORBIDDEN_ROOT_NAMES = {
    "PriceBlindReferenceClosure",
    "build_valuation_assumption_candidate",
    "compile_assumption_ledger",
    "fetch_market_reference",
    "run_valuation_kernel",
    "write_price_blind_input",
}
FORBIDDEN_DEFINITION_PREFIXES = ("build_", "compile_", "fetch_", "run_", "write_")
FORBIDDEN_IMPORTS = {"httpx", "requests", "urllib", "owner_valuation"}


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def _source_changes() -> set[tuple[str, str]]:
    output = _git(
        "diff",
        "--name-status",
        "--no-renames",
        PHASE5C_BASELINE,
        "--",
        "src/owner_research",
    )
    rows: set[tuple[str, str]] = set()
    for line in output.splitlines():
        status, path = line.split("\t", 1)
        rows.add((status, path))
    return rows


def _definitions_and_imports(path: Path) -> tuple[set[str], set[str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    definitions = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    return definitions, imports


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.schema_store import SCHEMA_NAMES, load_schema
    from owner_research.valuation_handoff_policies import (
        ASSUMPTION_CANDIDATE_POLICY_VERSION,
        HANDOFF_POLICY_VERSION,
        assumption_evidence_policy_sha256,
        assumption_slot_policy_sha256,
        empty_supplemental_reference_closure_sha256,
        price_blind_freeze_policy_sha256,
    )

    if owner_research.__version__ != "0.5.0.dev4":
        raise SystemExit("Python package version is not 0.5.0.dev4")
    if len(SCHEMA_NAMES) != 43:
        raise SystemExit("Phase 5D-0 must keep exactly 43 public Schemas")
    if load_schema("valuation-assumption-candidate")["properties"]["schema_version"] != {
        "const": "2.0.0"
    }:
        raise SystemExit("ValuationAssumptionCandidate is not v2")
    if load_schema("valuation-handoff")["properties"]["schema_version"] != {
        "const": "2.0.0"
    }:
        raise SystemExit("ValuationHandoff is not v2")
    if (ASSUMPTION_CANDIDATE_POLICY_VERSION, HANDOFF_POLICY_VERSION) != (
        "2.0.0",
        "2.0.0",
    ):
        raise SystemExit("Phase 5D-0 public policy version mismatch")
    hashes = {
        assumption_slot_policy_sha256(),
        assumption_evidence_policy_sha256(),
        price_blind_freeze_policy_sha256(),
        empty_supplemental_reference_closure_sha256(),
    }
    if len(hashes) != 4 or any(len(value) != 64 for value in hashes):
        raise SystemExit("Phase 5D-0 policy hashes are invalid")
    if any(hasattr(owner_research, name) for name in FORBIDDEN_ROOT_NAMES):
        raise SystemExit("Phase 5D-0 exposed an internal or later-phase API")
    changes = _source_changes()
    if changes != ALLOWED_SOURCE_CHANGES:
        raise SystemExit(f"Phase 5D-0 source changes exceed the authorized boundary: {changes}")
    for _, relative in changes:
        definitions, imports = _definitions_and_imports(ROOT / relative)
        if relative.endswith(("valuation_assumption_types.py", "valuation_handoff_policies.py")):
            forbidden = {
                name for name in definitions if name.startswith(FORBIDDEN_DEFINITION_PREFIXES)
            }
            if forbidden:
                raise SystemExit(f"Phase 5D-0 added a production definition: {sorted(forbidden)}")
        if imports & FORBIDDEN_IMPORTS:
            raise SystemExit(f"Phase 5D-0 added a forbidden import in {relative}")
    lock = json.loads((ROOT / "component-lock.json").read_text(encoding="utf-8"))
    if lock["owner_equity_research"]["plugin_version"] != "0.5.0-dev.4":
        raise SystemExit("Phase 5D-0 component-lock version mismatch")
    if lock["valuation_kernel"]["commit"] != (
        "a7dd1528c34f09702686b32ffbb8a397439665f0"
    ):
        raise SystemExit("Pinned valuation-kernel identity drifted")
    fixture = json.loads(
        (ROOT / "tests/fixtures/phase5d0/adversarial-cases.json").read_text(encoding="utf-8")
    )
    if len(fixture["cases"]) < 36 or len(fixture["cases"]) != len(set(fixture["cases"])):
        raise SystemExit("Phase 5D-0 adversarial fixture is incomplete")
    print("Phase 5D-0 validation-only assumption-governance boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
