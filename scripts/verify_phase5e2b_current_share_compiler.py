#!/usr/bin/env python3
"""Independent structural oracle for the internal Phase 5E-2B compiler."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "045e13bd08eadab942b2e1695d6818e6d0b71ede"
EXPECTED_VERSION = "0.5.0.dev10"
EXPECTED_PLUGIN_VERSION = "0.5.0-dev.10"
REQUIRED_PATHS = {
    "direct_point_in_time",
    "issued_less_treasury",
    "completed_event_rollforward",
}
FORBIDDEN_PARAMETERS = {
    "issuer_id",
    "data_cutoff_date",
    "quote_date",
    "share_fact_id",
    "evidence_kind",
    "status",
    "share_basis_decision",
}
FORBIDDEN_PUBLIC_NAMES = {
    "compile_quote_date_current_common_shares",
    "CurrentShareCompilationResult",
    "CurrentSharePathDecision",
}


def _git(*args: str, text: bool = True) -> str | bytes:
    payload = subprocess.check_output(
        ["git", "-C", str(ROOT), *args],
        text=text,
        stderr=subprocess.STDOUT,
    )
    return payload.strip() if text else payload


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _schema_hashes(revision: str | None = None) -> dict[str, str]:
    result = {}
    for path in sorted((ROOT / "schemas").glob("*.json")):
        relative = path.relative_to(ROOT).as_posix()
        payload = path.read_bytes() if revision is None else _git(
            "show", f"{revision}:{relative}", text=False
        )
        assert isinstance(payload, bytes)
        result[relative] = _sha(payload)
    return result


def _literal_strings(tree: ast.AST, name: str) -> set[str]:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        value = node.value
        if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
            return {
                item.value
                for item in value.elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            }
    raise SystemExit(f"missing literal registry {name}")


def main() -> int:
    if subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", BASELINE, "HEAD"]
    ).returncode:
        raise SystemExit("HEAD is not descended from accepted Phase 5E-2A.2.1")
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.valuation_current_share_compiler import (
        CurrentShareCompilationResult,
        CurrentSharePathDecision,
        compile_quote_date_current_common_shares,
    )
    from owner_research.valuation_market_reference_types import (
        MarketReferenceValidationContext,
    )

    if owner_research.__version__ != EXPECTED_VERSION:
        raise SystemExit("Phase 5E-2B package version mismatch")
    plugin = json.loads(
        (ROOT / "plugins/owner-equity-research/.codex-plugin/plugin.json").read_text()
    )
    lock = json.loads((ROOT / "component-lock.json").read_text())
    if (
        plugin["version"] != EXPECTED_PLUGIN_VERSION
        or lock["owner_equity_research"]["plugin_version"] != EXPECTED_PLUGIN_VERSION
    ):
        raise SystemExit("Phase 5E-2B Plugin/component-lock version mismatch")
    if len(_schema_hashes()) != 43 or _schema_hashes() != _schema_hashes(BASELINE):
        raise SystemExit("Phase 5E-2B changed the 43 public Schemas")
    baseline_lock = json.loads(_git("show", f"{BASELINE}:component-lock.json"))
    for key in ("valuation_kernel", "market_access_authority"):
        if lock[key] != baseline_lock[key]:
            raise SystemExit(f"Phase 5E-2B changed the frozen {key} subtree")

    module_path = ROOT / "src/owner_research/valuation_current_share_compiler.py"
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    if _literal_strings(tree, "CURRENT_SHARE_PATH_KINDS") != REQUIRED_PATHS:
        raise SystemExit("Phase 5E-2B compiler path registry is not closed")
    signature = inspect.signature(compile_quote_date_current_common_shares)
    if set(signature.parameters) != {
        "price_blind_artifact_directory",
        "graph",
        "expected_freeze",
        "expected_security",
        "expected_market_access",
    } or any(
        item.kind is not inspect.Parameter.KEYWORD_ONLY
        for item in signature.parameters.values()
    ):
        raise SystemExit("Phase 5E-2B compiler signature permits caller-owned selection")
    if set(signature.parameters).intersection(FORBIDDEN_PARAMETERS):
        raise SystemExit("Phase 5E-2B compiler accepts a forbidden caller-owned field")
    if any(hasattr(owner_research, name) for name in FORBIDDEN_PUBLIC_NAMES):
        raise SystemExit("Phase 5E-2B compiler leaked through the package root")
    context = inspect.signature(MarketReferenceValidationContext).parameters
    if "share_basis_decision" in context or "current_share_compilation_result" not in context:
        raise SystemExit("Snapshot validation still accepts a caller-owned ShareBasisDecision")
    if CurrentShareCompilationResult.__module__ != (
        "owner_research.valuation_current_share_compiler"
    ) or CurrentSharePathDecision.__module__ != (
        "owner_research.valuation_current_share_compiler"
    ):
        raise SystemExit("Phase 5E-2B immutable types moved or leaked")

    tests = (ROOT / "tests/test_phase5e2b_current_share_compiler.py").read_text()
    required_fragments = {
        "direct_quote_date_current_common_shares",
        "issued_less_treasury",
        "completed_event_rollforward",
        "conflicting_quote_date_paths",
        "conflicting_duplicate_direct_facts",
        "rollforward_split_window_routes_specialist",
        "phase5c_claim_authority_controls_compiler_route",
        "artifact_identity_are_replayed",
        "internal_only",
    }
    if not all(fragment in tests for fragment in required_fragments):
        raise SystemExit("Phase 5E-2B adversarial test matrix is incomplete")
    if "__all__ = ()" not in module_path.read_text(encoding="utf-8"):
        raise SystemExit("Phase 5E-2B module does not close its export surface")
    print("Phase 5E-2B independent current-share compiler verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
