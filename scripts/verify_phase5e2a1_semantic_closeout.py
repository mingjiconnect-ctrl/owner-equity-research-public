#!/usr/bin/env python3
"""Independent Phase 5E-2A.1 dilution-authority and public-domain oracle."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5E2A_BASELINE = "e7111ebf51439267602ebed6353347018659537d"
PHASE5E11_BASELINE = "640ce470cb986d356ec54fc6018f48b6ad02ae36"
SNAPSHOT_SCHEMA = "schemas/market-reference-snapshot.schema.json"
FROZEN_AUTHORITY_PATHS = (
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
FORBIDDEN_NAMES = {
    "build_market_reference_snapshot",
    "compile_market_reference_snapshot",
    "compile_share_basis",
    "generate_market_evidence",
    "compile_final_request",
    "run_valuation_kernel",
    "write_valuation_artifacts",
}


def _git(*args: str, text: bool = True) -> str | bytes:
    value = subprocess.check_output(
        ["git", "-C", str(ROOT), *args],
        text=text,
        stderr=subprocess.STDOUT,
    )
    return value.strip() if text else value


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _schema_hashes(revision: str | None = None) -> dict[str, str]:
    result = {}
    for path in sorted((ROOT / "schemas").glob("*.json")):
        relative = path.relative_to(ROOT).as_posix()
        value = path.read_bytes() if revision is None else _git(
            "show", f"{revision}:{relative}", text=False
        )
        result[relative] = _sha(value)
    return result


def _assert_internal_types() -> None:
    tree = ast.parse(
        (ROOT / "src/owner_research/valuation_market_reference_types.py").read_text(
            encoding="utf-8"
        )
    )
    classes = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    if (
        "Phase5CDilutionRootAuthority" not in classes
        or "MarketReferenceValidationContext" not in classes
    ):
        raise SystemExit("Phase 5E-2A.1 internal authority types are missing")
    context = classes["MarketReferenceValidationContext"]
    caller_fields = {
        child.target.id
        for child in context.body
        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name)
    }
    if caller_fields.intersection(
        {"share_basis_root_fact_ids", "equity_bridge_dilution_root_fact_ids"}
    ):
        raise SystemExit("validation context still accepts caller-owned final dilution roots")
    names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    if names.intersection(FORBIDDEN_NAMES):
        raise SystemExit("Phase 5E-2A.1 introduced a prohibited production surface")


def main() -> int:
    if subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", PHASE5E2A_BASELINE, "HEAD"]
    ).returncode:
        raise SystemExit("HEAD is not descended from the accepted Phase 5E-2A merge")
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research

    if owner_research.__version__ != "0.5.0.dev7":
        raise SystemExit("Phase 5E-2A.1 Python version is not dev7")
    current = _schema_hashes()
    phase5e11 = _schema_hashes(PHASE5E11_BASELINE)
    if len(current) != 43 or {
        path for path in current if current[path] != phase5e11[path]
    } != {SNAPSHOT_SCHEMA}:
        raise SystemExit("Phase 5E-2A.1 did not retain the one-Schema v2 boundary")
    lock = json.loads((ROOT / "component-lock.json").read_text(encoding="utf-8"))
    baseline_lock = json.loads(_git("show", f"{PHASE5E2A_BASELINE}:component-lock.json"))
    if (
        lock["owner_equity_research"]["plugin_version"] != "0.5.0-dev.7"
        or lock["owner_equity_research"]["public_schema_sha256"] != current
        or lock["market_access_authority"] != baseline_lock["market_access_authority"]
        or lock["valuation_kernel"] != baseline_lock["valuation_kernel"]
    ):
        raise SystemExit("Phase 5E-2A.1 component lock drifted outside its allowed surface")
    for relative in FROZEN_AUTHORITY_PATHS:
        if (ROOT / relative).read_bytes() != _git(
            "show", f"{PHASE5E2A_BASELINE}:{relative}", text=False
        ):
            raise SystemExit(f"frozen market authority drifted: {relative}")

    schema = json.loads((ROOT / SNAPSHOT_SCHEMA).read_text(encoding="utf-8"))
    pattern = schema["$defs"]["positiveDecimal"]["pattern"]
    if any(re.fullmatch(pattern, value) for value in ("0", "0.0", "0.000")):
        raise SystemExit("public positiveDecimal still accepts zero")
    if any(not re.fullmatch(pattern, value) for value in ("0.001", "1", "1.0", "100.25")):
        raise SystemExit("public positiveDecimal rejects a canonical positive value")
    _assert_internal_types()

    source = (ROOT / "src/owner_research/valuation_market_reference_types.py").read_text(
        encoding="utf-8"
    )
    required_tokens = {
        "economic_claim_bindings",
        "consumption_records",
        "included_option_root_fact_ids",
        "excluded_option_root_fact_ids",
        "blocked_option_root_fact_ids",
        "phase5c_diluted_share_root_fact_ids",
    }
    if not required_tokens.issubset(set(re.findall(r"[A-Za-z0-9_]+", source))):
        raise SystemExit("dilution authority does not cover the required Phase 5C semantics")
    state = json.loads((ROOT / "docs/phase-status.json").read_text(encoding="utf-8"))
    if not (
        state["current_phase"] == "Phase 5E-2A.1"
        and state["status"] == "accepted_closed"
        and state["authorized_next"]
        == ["Phase 5E-2B governed point-in-time share-basis work"]
        and "Phase 5E-2B" not in state["prohibited"]
        and "Phase 5E-2C" in state["prohibited"]
        and state["release_tag"] is None
    ):
        raise SystemExit("Phase 5E-2A.1 acceptance state or successor boundary drifted")
    print("Phase 5E-2A.1 dilution authority and public-contract parity passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
