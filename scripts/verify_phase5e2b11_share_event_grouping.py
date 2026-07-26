#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "3fbd39f9d16af467a73bff670600b692ff0f3756"
MODULE = ROOT / "src/owner_research/valuation_share_event_grouping.py"
TEST = ROOT / "tests/test_phase5e2b11_share_event_grouping.py"
COMPONENT_LOCK_SHA256 = "957c43bf4b9cca4f2168e816b5ea89b9ca7d86bdad5d967cc8de76e38bfdf1c7"
FROZEN = (
    "src/owner_research/__init__.py",
    "src/owner_research/valuation_current_share_compiler.py",
    "src/owner_research/valuation_current_share_evidence.py",
    "src/owner_research/valuation_share_event_identity.py",
)


def _git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def main() -> int:
    if hashlib.sha256((ROOT / "component-lock.json").read_bytes()).hexdigest() != (
        COMPONENT_LOCK_SHA256
    ):
        raise SystemExit("component lock drifted during Phase 5E-2B.1-1")
    if len(tuple((ROOT / "schemas").glob("*.schema.json"))) != 43:
        raise SystemExit("public Schema count changed during internal grouping work")
    for relative in FROZEN:
        if (ROOT / relative).read_bytes() != _git("show", f"{BASELINE}:{relative}"):
            raise SystemExit(f"frozen current-share boundary drifted: {relative}")

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    functions = {
        item.name: item for item in ast.walk(tree) if isinstance(item, ast.FunctionDef)
    }
    entry = functions.get("group_governed_completed_share_events")
    if entry is None:
        raise SystemExit("production grouping entry point is missing")
    if entry.args.args or entry.args.vararg or entry.args.kwarg:
        raise SystemExit("grouping entry point accepts positional or free-form caller input")
    expected = {
        "graph",
        "issuer_id",
        "security_compilation_result",
        "opening_date",
        "quote_date",
        "data_cutoff_date",
    }
    if {item.arg for item in entry.args.kwonlyargs} != expected:
        raise SystemExit("grouping entry point boundary drifted")
    calls = {
        item.func.id
        for item in ast.walk(tree)
        if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
    }
    forbidden_calls = {
        "Fact",
        "SourceDocument",
        "CalculationResult",
        "MarketReferenceSnapshot",
        "compile_quote_date_current_common_shares",
        "run_dual_panel",
    }
    if calls.intersection(forbidden_calls):
        raise SystemExit("grouping module creates or invokes a prohibited downstream object")
    module_text = MODULE.read_text(encoding="utf-8")
    if "__all__: tuple[str, ...] = ()" not in module_text:
        raise SystemExit("grouping module is not explicitly internal")
    for relative in (
        "src/owner_research/__init__.py",
        "src/owner_research/valuation_current_share_compiler.py",
        "src/owner_research/valuation_current_share_evidence.py",
    ):
        if "valuation_share_event_grouping" in (ROOT / relative).read_text(encoding="utf-8"):
            raise SystemExit(f"grouping leaked into a frozen runtime surface: {relative}")
    test_text = TEST.read_text(encoding="utf-8")
    for token in (
        "8-K",
        "10-Q",
        "company_primary",
        "blocked_share_event_conflict",
        "blocked_share_event_cumulative_amount",
        "canonical_event_fact_id",
        "input_order",
    ):
        if token not in test_text:
            raise SystemExit(f"production grouping adversarial coverage is missing: {token}")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            str(TEST),
        ],
        cwd=ROOT,
        check=True,
    )
    print("Phase 5E-2B.1-1 production share-event grouping verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
