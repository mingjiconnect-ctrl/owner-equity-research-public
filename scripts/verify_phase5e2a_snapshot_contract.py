#!/usr/bin/env python3
"""Verify the validation-only MarketReferenceSnapshot 2.0.0 boundary."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5E11_BASELINE = "640ce470cb986d356ec54fc6018f48b6ad02ae36"
SNAPSHOT_SCHEMA = "schemas/market-reference-snapshot.schema.json"
AUTHORITY_PATHS = (
    "src/owner_research/resources/market_access/provider-registry.json",
    "src/owner_research/resources/market_access/calendar-registry.json",
    "src/owner_research/resources/market_access/calendar_sources/XNAS-2026.json",
    "src/owner_research/resources/market_access/calendar_sources/XNYS-2026.json",
    "src/owner_research/resources/market_access/calendars/XNAS-2026.json",
    "src/owner_research/resources/market_access/calendars/XNYS-2026.json",
    "src/owner_research/resources/market_access/secret-policy.json",
    "src/owner_research/resources/market_access/security-identity-policy.json",
    "src/owner_research/valuation_market_access.py",
    "src/owner_research/valuation_market_adapters.py",
    "src/owner_research/valuation_market_authority.py",
    "src/owner_research/valuation_market_calendar.py",
    "src/owner_research/valuation_market_parsers.py",
    "src/owner_research/valuation_market_runtime.py",
    "src/owner_research/valuation_security_identity.py",
)
FORBIDDEN_PUBLIC_NAMES = {
    "build_market_reference_snapshot",
    "compile_market_reference_snapshot",
    "compile_share_basis",
    "generate_market_evidence",
    "compile_final_request",
    "run_valuation_kernel",
    "write_valuation_artifacts",
}


def _git(*args: str, text: bool = True) -> str | bytes:
    output = subprocess.check_output(
        ["git", "-C", str(ROOT), *args],
        text=text,
        stderr=subprocess.STDOUT,
    )
    return output.strip() if text else output


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _schema_hashes(revision: str | None = None) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted((ROOT / "schemas").glob("*.json")):
        relative = path.relative_to(ROOT).as_posix()
        payload = (
            path.read_bytes()
            if revision is None
            else _git("show", f"{revision}:{relative}", text=False)
        )
        result[relative] = _sha(payload)
    return result


def _assert_no_production_surface() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.valuation_market_reference_types import (
        MarketReferenceValidationContext,
    )

    if any(hasattr(owner_research, name) for name in FORBIDDEN_PUBLIC_NAMES):
        raise SystemExit("Phase 5E-2A exposed a later-phase package-root surface")
    if hasattr(owner_research, "MarketReferenceValidationContext"):
        raise SystemExit("Phase 5E-2A exported its internal validation context")
    if MarketReferenceValidationContext.__module__ != (
        "owner_research.valuation_market_reference_types"
    ):
        raise SystemExit("MarketReferenceValidationContext module identity drifted")
    for relative in (
        "src/owner_research/valuation_market_reference_types.py",
        "src/owner_research/valuation_handoff_validation.py",
    ):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        if names & FORBIDDEN_PUBLIC_NAMES:
            raise SystemExit(f"{relative} defines a prohibited production surface")


def main() -> int:
    if subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", PHASE5E11_BASELINE, "HEAD"]
    ).returncode:
        raise SystemExit("HEAD is not descended from the Phase 5E-1.1 baseline")
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.schema_store import SCHEMA_NAMES, load_schema

    if owner_research.__version__ != "0.5.0.dev7":
        raise SystemExit("Python package version is not 0.5.0.dev7")
    if len(SCHEMA_NAMES) != 43:
        raise SystemExit("Phase 5E-2A must retain exactly 43 public Schemas")
    baseline = _schema_hashes(PHASE5E11_BASELINE)
    current = _schema_hashes()
    changed = {path for path in current if current[path] != baseline[path]}
    if changed != {SNAPSHOT_SCHEMA}:
        raise SystemExit(f"Phase 5E-2A changed the wrong public Schemas: {sorted(changed)}")
    schema = load_schema("market-reference-snapshot")
    if (
        schema.get("additionalProperties") is not False
        or schema["properties"]["schema_version"] != {"const": "2.0.0"}
        or schema["properties"]["status"] != {"const": "validated"}
    ):
        raise SystemExit("MarketReferenceSnapshot 2.0.0 Schema is not closed")
    lock = json.loads((ROOT / "component-lock.json").read_text(encoding="utf-8"))
    baseline_lock = json.loads(_git("show", f"{PHASE5E11_BASELINE}:component-lock.json"))
    if lock["lock_version"] != "1.1.0":
        raise SystemExit("component-lock format drifted")
    if lock["market_access_authority"] != baseline_lock["market_access_authority"]:
        raise SystemExit("Phase 5E-1.1 market-access authority changed")
    if lock["valuation_kernel"] != baseline_lock["valuation_kernel"]:
        raise SystemExit("pinned valuation-kernel identity changed")
    owner = lock["owner_equity_research"]
    if owner["plugin_version"] != "0.5.0-dev.7":
        raise SystemExit("component-lock Plugin version is not dev.7")
    if owner["public_schema_sha256"] != current:
        raise SystemExit("component-lock public Schema hashes do not match repository bytes")
    for relative in AUTHORITY_PATHS:
        if _sha((ROOT / relative).read_bytes()) != _sha(
            _git("show", f"{PHASE5E11_BASELINE}:{relative}", text=False)
        ):
            raise SystemExit(f"Phase 5E-1.1 authority file drifted: {relative}")
    migration = json.loads(
        (ROOT / "docs/phase5e2a-migration-manifest.json").read_text(encoding="utf-8")
    )
    if (
        migration["migration_strategy"] != "preproduction_hard_break"
        or migration["automatic_migration"] is not False
        or migration["changed_public_schemas"] != [SNAPSHOT_SCHEMA]
    ):
        raise SystemExit("Snapshot v1-to-v2 hard-break manifest drifted")
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
        raise SystemExit("Phase 5E-2A.1 machine state or successor boundary drifted")
    _assert_no_production_surface()
    print("Phase 5E-2A.1 MarketReferenceSnapshot v2 contract boundary accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
