#!/usr/bin/env python3
"""Verify the closed Phase 5B mapping boundary without running valuation code."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERNEL_COMMIT = "a7dd1528c34f09702686b32ffbb8a397439665f0"
FACT_LEDGER_SHA256 = "55be5aadad21629db1cdbe7fce386656eb930b52af8644d1314ba7404e384706"
FORBIDDEN_NAMES = {
    "compile_assumption_ledger",
    "fetch_market_reference",
    "run_valuation_kernel",
    "write_valuation_artifacts",
    "build_valuation_request",
}


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.schema_store import SCHEMA_NAMES
    from owner_research.valuation_fact_mapping import compile_price_blind_fact_ledger
    from owner_research.valuation_fact_mapping_policies import (
        CLASSIFICATION_POLICY_ID,
        CLASSIFICATION_POLICY_VERSION,
        MAPPING_POLICY_ID,
        MAPPING_POLICY_VERSION,
        PINNED_FACT_LEDGER_SCHEMA_SHA256,
        READINESS_POLICY_ID,
        READINESS_POLICY_VERSION,
        mapping_policy_sha256,
        readiness_policy_sha256,
    )
    from owner_research.valuation_readiness import assess_method_readiness

    if len(SCHEMA_NAMES) != 43:
        raise SystemExit("Phase 5B must keep exactly 43 public research Schemas")
    if owner_research.__version__ != "0.5.0.dev2":
        raise SystemExit("Python package version is not 0.5.0.dev2")
    if any(hasattr(owner_research, name) for name in FORBIDDEN_NAMES):
        raise SystemExit("Phase 5B exposed a forbidden later-phase API")
    if (MAPPING_POLICY_ID, MAPPING_POLICY_VERSION) != (
        "research-to-kernel-fact-mapping",
        "1.0.0",
    ):
        raise SystemExit("Phase 5B mapping-policy identity drifted")
    if len(mapping_policy_sha256()) != 64:
        raise SystemExit("Phase 5B mapping-policy fingerprint is invalid")
    if (
        CLASSIFICATION_POLICY_ID,
        CLASSIFICATION_POLICY_VERSION,
        READINESS_POLICY_ID,
        READINESS_POLICY_VERSION,
    ) != (
        "valuation-company-classification",
        "1.0.0",
        "valuation-method-readiness",
        "1.0.0",
    ) or len(readiness_policy_sha256()) != 64:
        raise SystemExit("Phase 5B readiness-policy identity drifted")
    if PINNED_FACT_LEDGER_SCHEMA_SHA256 != FACT_LEDGER_SHA256:
        raise SystemExit("Phase 5B FactLedger Schema identity drifted")

    plugin = json.loads(
        (ROOT / "plugins/owner-equity-research/.codex-plugin/plugin.json").read_text()
    )
    lock = json.loads((ROOT / "component-lock.json").read_text())
    if plugin["version"] != "0.5.0-dev.2":
        raise SystemExit("Plugin version is not 0.5.0-dev.2")
    if lock["owner_equity_research"]["plugin_version"] != "0.5.0-dev.2":
        raise SystemExit("component lock version is not 0.5.0-dev.2")
    if len(lock["owner_equity_research"]["public_schema_sha256"]) != 43:
        raise SystemExit("component lock does not contain 43 research Schema hashes")
    if lock["valuation_kernel"]["commit"] != KERNEL_COMMIT:
        raise SystemExit("valuation-kernel commit drifted")
    if tuple(inspect.signature(compile_price_blind_fact_ledger).parameters) != (
        "bundle_artifact_directory",
        "graph",
        "kernel_repository",
    ):
        raise SystemExit("raw Fact compiler accepts caller-controlled mapping fields")
    if tuple(inspect.signature(assess_method_readiness).parameters) != (
        "graph",
        "mapping_result",
    ):
        raise SystemExit("readiness accepts caller-controlled classification or status")
    if hasattr(owner_research, "assess_method_readiness"):
        raise SystemExit("Phase 5B readiness must remain an internal entrypoint")
    mapping = json.loads((ROOT / "evals/future-valuation-mapping.json").read_text())
    if mapping["mapping_status"] != "IMPLEMENTED_PHASE_5B":
        raise SystemExit("Phase 5B mapping implementation state is stale")

    kernel = Path(
        os.environ.get("OWNER_VALUATION_REPO", str(ROOT.parent / "owner-valuation-kernel"))
    )
    schema = kernel / "schemas/fact-ledger.schema.json"
    schema_matches = (
        schema.is_file()
        and hashlib.sha256(schema.read_bytes()).hexdigest() == FACT_LEDGER_SHA256
    )
    if not schema_matches:
        raise SystemExit("pinned FactLedger Schema is unavailable or changed")
    for path in (
        ROOT / "src/owner_research/valuation_fact_mapping_policies.py",
        ROOT / "src/owner_research/valuation_fact_mapping_types.py",
        ROOT / "src/owner_research/valuation_fact_mapping.py",
        ROOT / "src/owner_research/valuation_readiness.py",
    ):
        text = path.read_text(encoding="utf-8")
        if "httpx" in text or "owner_valuation" in text:
            raise SystemExit("Phase 5B mapping boundary imports network or kernel code")
    print("Phase 5B mapping boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
