#!/usr/bin/env python3
"""Verify that accepted Phase 5E-0 code and public contracts remain frozen."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5E0_BASELINE = "ac70357624c95f78b5567bc8eb8544c13fa375dd"
FROZEN_FILES = (
    "docs/adr/0029-phase5e-market-execution-policy.md",
    "docs/phase5e0-market-execution-policy.md",
    "src/owner_research/valuation_market_execution_policies.py",
    "src/owner_research/valuation_market_execution_types.py",
    "tests/fixtures/phase5e0/adversarial-cases.json",
    "tests/test_phase5e0_market_execution_policies.py",
)


def _git(*args: str, text: bool = True) -> str | bytes:
    output = subprocess.check_output(
        ["git", "-C", str(ROOT), *args],
        text=text,
        stderr=subprocess.STDOUT,
    )
    return output.strip() if text else output


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    if (
        subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "merge-base",
                "--is-ancestor",
                PHASE5E0_BASELINE,
                "HEAD",
            ]
        ).returncode
        != 0
    ):
        raise SystemExit("HEAD is not descended from the accepted Phase 5E-0 baseline")
    schemas = tuple(
        path.relative_to(ROOT).as_posix()
        for path in sorted((ROOT / "schemas").glob("*.json"))
    )
    frozen = (
        *FROZEN_FILES,
        *(item for item in schemas if item != "schemas/market-reference-snapshot.schema.json"),
    )
    drift: list[str] = []
    for relative in frozen:
        path = ROOT / relative
        if not path.is_file():
            drift.append(f"missing:{relative}")
            continue
        baseline = _git("show", f"{PHASE5E0_BASELINE}:{relative}", text=False)
        current = path.read_bytes()
        if _digest(baseline) != _digest(current):
            drift.append(relative)
    if drift:
        raise SystemExit(f"Accepted Phase 5E-0 baseline drifted: {drift}")
    baseline_lock = json.loads(_git("show", f"{PHASE5E0_BASELINE}:component-lock.json"))
    current_lock = json.loads((ROOT / "component-lock.json").read_text(encoding="utf-8"))
    if current_lock.get("lock_version") != "1.1.0":
        raise SystemExit("Phase 5E-1.1 component-lock extension is missing")
    if current_lock.get("valuation_kernel") != baseline_lock.get("valuation_kernel"):
        raise SystemExit("Accepted Phase 5E-0 valuation-kernel lock subtree drifted")
    baseline_owner = baseline_lock["owner_equity_research"]
    current_owner = current_lock["owner_equity_research"]
    if current_owner.get("plugin_version") != "0.5.0-dev.7":
        raise SystemExit("Phase 5E-2A.1 Plugin version is not dev.7")
    baseline_schemas = baseline_owner["public_schema_sha256"]
    current_schemas = current_owner["public_schema_sha256"]
    unchanged = set(baseline_schemas) - {"schemas/market-reference-snapshot.schema.json"}
    if any(current_schemas.get(key) != baseline_schemas[key] for key in unchanged):
        raise SystemExit("A public Schema outside MarketReferenceSnapshot drifted")
    snapshot_path = ROOT / "schemas/market-reference-snapshot.schema.json"
    if current_schemas.get(snapshot_path.relative_to(ROOT).as_posix()) != _digest(
        snapshot_path.read_bytes()
    ):
        raise SystemExit("MarketReferenceSnapshot component-lock hash mismatch")
    if set(current_lock) != {
        "lock_version",
        "generated_date",
        "owner_equity_research",
        "market_access_authority",
        "valuation_kernel",
    }:
        raise SystemExit("Component lock contains an unauthorized Phase 5E-1.1 extension")
    baseline_project = _git("show", f"{PHASE5E0_BASELINE}:pyproject.toml")
    current_project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if (
        'version = "0.5.0.dev5"' not in baseline_project
        or 'version = "0.5.0.dev7"' not in current_project
        or '"component-lock.json" = "owner_research/component-lock.json"'
        not in baseline_project
        or '"component-lock.json" = "owner_research/component-lock.json"'
        not in current_project
    ):
        raise SystemExit("Accepted Phase 5E-0 project identity drifted")
    print("Canonical Phase 5E-0 policy and contract baseline is unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
