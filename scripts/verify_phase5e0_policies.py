#!/usr/bin/env python3
"""Verify the policy-only Phase 5E-0 boundary."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D_BASELINE = "bdac6e4a23e821c73a2545167f478cfc0348316f"
NEW_POLICY_MODULES = (
    "src/owner_research/valuation_market_execution_policies.py",
    "src/owner_research/valuation_market_execution_types.py",
)
FORBIDDEN_IMPORTS = {"httpx", "requests", "urllib", "socket", "owner_valuation"}
FORBIDDEN_PREFIXES = ("acquire_", "build_", "compile_", "fetch_", "run_", "write_")
FORBIDDEN_ROOT_NAMES = {
    "MarketQuoteRequest",
    "MarketQuoteReceipt",
    "SecurityIdentityDecision",
    "ShareBasisDecision",
    "FinalRequestCompilationReceipt",
    "KernelExecutionReceipt",
    "acquire_governed_market_quote",
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
    paths = sorted((ROOT / "schemas").glob("*.json"))
    result: dict[str, str] = {}
    for path in paths:
        relative = path.relative_to(ROOT).as_posix()
        payload = (
            path.read_bytes()
            if revision is None
            else _git("show", f"{revision}:{relative}", text=False)
        )
        result[relative] = hashlib.sha256(payload).hexdigest()
    return result


def main() -> int:
    if (
        subprocess.run(
            ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", PHASE5D_BASELINE, "HEAD"]
        ).returncode
        != 0
    ):
        raise SystemExit("HEAD is not descended from the accepted Phase 5D baseline")
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.schema_store import SCHEMA_NAMES
    from owner_research.valuation_market_execution_policies import (
        PHASE5E_POLICIES,
        PINNED_KERNEL_COMMIT,
        PINNED_KERNEL_SCHEMA_SHA256,
        phase5e_policy_sha256,
    )

    if owner_research.__version__ != "0.5.0.dev7":
        raise SystemExit("Python package version is not 0.5.0.dev7")
    current_schemas = _schema_hashes()
    baseline_schemas = _schema_hashes(PHASE5D_BASELINE)
    changed = {
        path for path in current_schemas if current_schemas[path] != baseline_schemas[path]
    }
    if len(SCHEMA_NAMES) != 43 or changed != {
        "schemas/market-reference-snapshot.schema.json"
    }:
        raise SystemExit("Phase 5E-2A must change exactly the Snapshot public Schema")
    if set(PHASE5E_POLICIES) != {
        "market_quote",
        "security_identity",
        "share_basis",
        "final_request",
        "kernel_execution",
    }:
        raise SystemExit("Phase 5E-0 policy registry is not closed")
    if len(phase5e_policy_sha256()) != 64:
        raise SystemExit("Phase 5E-0 policy hash is invalid")
    if PINNED_KERNEL_COMMIT != "a7dd1528c34f09702686b32ffbb8a397439665f0":
        raise SystemExit("Pinned kernel commit drifted")
    if len(PINNED_KERNEL_SCHEMA_SHA256) != 8:
        raise SystemExit("Pinned kernel Schema registry must contain eight hashes")
    if any(hasattr(owner_research, name) for name in FORBIDDEN_ROOT_NAMES):
        raise SystemExit("Phase 5E-0 exposed an internal or later-phase API")

    for relative in NEW_POLICY_MODULES:
        path = ROOT / relative
        if not path.is_file():
            raise SystemExit(f"Missing Phase 5E-0 module: {relative}")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        definitions = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        forbidden_definitions = sorted(
            name for name in definitions if name.startswith(FORBIDDEN_PREFIXES)
        )
        if forbidden_definitions:
            raise SystemExit(f"Phase 5E-0 added production definitions: {forbidden_definitions}")
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        if imports & FORBIDDEN_IMPORTS:
            raise SystemExit(f"Phase 5E-0 added forbidden imports: {sorted(imports)}")

    lock = json.loads((ROOT / "component-lock.json").read_text(encoding="utf-8"))
    if lock["owner_equity_research"]["plugin_version"] != "0.5.0-dev.7":
        raise SystemExit("Phase 5E-0 component-lock version mismatch")
    if lock["owner_equity_research"]["public_schema_sha256"] != _schema_hashes():
        raise SystemExit("component-lock public Schema hashes drifted")
    if lock["valuation_kernel"]["public_schema_sha256"] != PINNED_KERNEL_SCHEMA_SHA256:
        raise SystemExit("component-lock kernel Schema hashes drifted")
    fixture = json.loads(
        (ROOT / "tests/fixtures/phase5e0/adversarial-cases.json").read_text(encoding="utf-8")
    )
    if len(fixture["cases"]) < 60 or len(fixture["cases"]) != len(set(fixture["cases"])):
        raise SystemExit("Phase 5E-0 adversarial fixture is incomplete")
    interface = json.loads(
        (ROOT / "docs/phase5e-interface-matrix.json").read_text(encoding="utf-8")
    )
    failure = json.loads(
        (ROOT / "docs/phase5e-failure-mode-matrix.json").read_text(encoding="utf-8")
    )
    strategy_ids = [item["strategy_id"] for item in interface["strategies"]]
    failure_ids = [item["failure_id"] for item in failure["failures"]]
    referenced_failures = {
        failure_id for item in interface["mappings"] for failure_id in item["failure_ids"]
    }
    if len(strategy_ids) != len(set(strategy_ids)):
        raise SystemExit("Phase 5E interface strategies are not unique")
    if len(failure_ids) != len(set(failure_ids)) or not referenced_failures <= set(failure_ids):
        raise SystemExit("Phase 5E failure overlay is not referentially closed")
    for relative in (
        "docs/adr/0029-phase5e-market-execution-policy.md",
        "docs/phase5e0-market-execution-policy.md",
        "docs/phase5e-interface-matrix.json",
        "docs/phase5e-failure-mode-matrix.json",
        "docs/phase5e-acceptance-matrix.json",
        "docs/phase5e-golden-matrix.json",
    ):
        if not (ROOT / relative).is_file():
            raise SystemExit(f"Missing Phase 5E-0 governance artifact: {relative}")
    print("Phase 5E-0 policy-only market/request/kernel boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
