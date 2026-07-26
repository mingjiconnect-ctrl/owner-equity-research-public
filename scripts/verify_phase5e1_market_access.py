#!/usr/bin/env python3
"""Verify the internal-only Phase 5E-1.1 market-authority boundary."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5E0_BASELINE = "ac70357624c95f78b5567bc8eb8544c13fa375dd"
MODULES = (
    ROOT / "src/owner_research/valuation_market_access.py",
    ROOT / "src/owner_research/valuation_market_adapters.py",
    ROOT / "src/owner_research/valuation_market_authority.py",
    ROOT / "src/owner_research/valuation_market_authority_types.py",
    ROOT / "src/owner_research/valuation_market_calendar.py",
    ROOT / "src/owner_research/valuation_market_parsers.py",
    ROOT / "src/owner_research/valuation_market_runtime.py",
    ROOT / "src/owner_research/valuation_security_identity.py",
)
FORBIDDEN_IMPORTS = {"httpx", "requests", "socket", "owner_valuation"}
FORBIDDEN_NAMES = {
    "build_market_reference_snapshot",
    "compile_final_valuation_request",
    "run_pinned_valuation_kernel",
    "write_valuation_artifacts",
}


def _git(*args: str, text: bool = True) -> str | bytes:
    output = subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=text, stderr=subprocess.STDOUT
    )
    return output.strip() if text else output


def _schema_hashes(revision: str | None = None) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted((ROOT / "schemas").glob("*.json")):
        relative = path.relative_to(ROOT).as_posix()
        payload = path.read_bytes() if revision is None else _git(
            "show", f"{revision}:{relative}", text=False
        )
        result[relative] = hashlib.sha256(payload).hexdigest()
    return result


def _assert_import_boundary() -> None:
    imports: set[str] = set()
    for module in MODULES:
        if not module.is_file():
            raise SystemExit(f"Phase 5E-1.1 module is missing: {module.name}")
        source = module.read_text(encoding="utf-8")
        if any(name in source for name in FORBIDDEN_NAMES):
            raise SystemExit(f"{module.name} contains a later-phase production surface")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
    if imports & FORBIDDEN_IMPORTS:
        raise SystemExit(f"Phase 5E-1.1 imports network or kernel code: {imports}")


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.schema_store import SCHEMA_NAMES
    from owner_research.valuation_market_access import (
        GovernedMarketQuoteReceipt,
        MarketAccessResult,
        MarketQuoteProvider,
        acquire_governed_market_quote,
    )
    from owner_research.valuation_market_authority import load_market_access_authority
    from owner_research.valuation_market_authority_types import RawMarketResponse
    from owner_research.valuation_security_identity import (
        SecurityAccessProposal,
        SecurityIdentityCompilationResult,
        compile_security_identity,
    )

    if owner_research.__version__ != "0.5.0.dev7":
        raise SystemExit("Python package version is not 0.5.0.dev7")
    current_schemas = _schema_hashes()
    baseline_schemas = _schema_hashes(PHASE5E0_BASELINE)
    changed = {
        path for path in current_schemas if current_schemas[path] != baseline_schemas[path]
    }
    if len(SCHEMA_NAMES) != 43 or changed != {
        "schemas/market-reference-snapshot.schema.json"
    }:
        raise SystemExit("Phase 5E-2A must change exactly the Snapshot public Schema")
    signature = inspect.signature(acquire_governed_market_quote)
    if tuple(signature.parameters) != (
        "price_blind_artifact_directory",
        "graph",
        "expected_freeze",
        "expected_security",
        "provider",
    ) or any(
        parameter.kind is not inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    ):
        raise SystemExit("Phase 5E-1.1 entrypoint signature drifted")
    security_signature = inspect.signature(compile_security_identity)
    if tuple(security_signature.parameters) != ("graph", "expected_freeze", "proposal"):
        raise SystemExit("security compiler signature drifted")
    internal = (
        GovernedMarketQuoteReceipt,
        MarketAccessResult,
        MarketQuoteProvider,
        RawMarketResponse,
        SecurityAccessProposal,
        SecurityIdentityCompilationResult,
        acquire_governed_market_quote,
        compile_security_identity,
    )
    if any(hasattr(owner_research, item.__name__) for item in internal):
        raise SystemExit("Phase 5E-1.1 exposed an internal type or entrypoint at package root")
    _assert_import_boundary()
    authority = load_market_access_authority()
    if authority.lock_version != "1.1.0" or len(authority.calendar_registry.datasets) != 2:
        raise SystemExit("component-locked market authority is incomplete")
    if {item.mic for item in authority.calendar_registry.datasets} != {"XNAS", "XNYS"}:
        raise SystemExit("calendar authority MIC coverage drifted")
    if any(len(item.sessions) != 251 for item in authority.calendar_registry.datasets):
        raise SystemExit("2026 calendar authority session coverage drifted")
    if any(
        item.adapter_kind not in {"recorded", "loopback"}
        for item in authority.provider_registry.registrations
    ):
        raise SystemExit("a non-offline Provider entered Phase 5E-1.1")
    state = json.loads((ROOT / "docs/phase-status.json").read_text(encoding="utf-8"))
    if (
        state["current_phase"] != "Phase 5E-2A.1"
        or state["status"] != "accepted_closed"
        or state["authorized_next"]
        != ["Phase 5E-2B governed point-in-time share-basis work"]
        or "Phase 5E-2B" in state["prohibited"]
        or "Phase 5E-2C" not in state["prohibited"]
        or state["release_tag"] is not None
    ):
        raise SystemExit("Phase 5E-1.1 machine state or successor boundary drifted")
    print("Phase 5E-1.1 governed market-authority boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
