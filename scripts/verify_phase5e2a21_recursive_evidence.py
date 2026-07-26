#!/usr/bin/env python3
"""Independent Phase 5E-2A.2.1 recursive current-share authority oracle."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "01c6f8fae58ac7971c5449612f7684184ac5700e"
EXPECTED_VERSION = "0.5.0.dev10"
EXPECTED_PLUGIN_VERSION = "0.5.0-dev.10"
REQUIRED_EVENT_CONCEPTS = {
    "common_shares_issued_completed",
    "common_shares_repurchased_completed",
    "common_shares_retired_or_cancelled_completed",
    "option_shares_exercised_completed",
    "rsu_shares_settled_completed",
    "convertible_shares_converted_completed",
    "warrant_shares_exercised_completed",
    "acquisition_consideration_shares_issued_completed",
}
REQUIRED_COVERAGE_CATEGORIES = {
    "issuance",
    "repurchase",
    "retirement_or_cancellation",
    "option_exercise",
    "rsu_settlement",
    "convertible_conversion",
    "warrant_exercise",
    "acquisition_consideration",
    "employee_plan_issuance",
    "stock_dividend",
    "split_or_reverse_split",
    "treasury_stock_movement",
}
FORBIDDEN_PRODUCTION_NAMES = {
    "compile_governed_quote_date_current_shares",
    "compile_share_basis",
    "build_market_reference_snapshot",
    "compile_market_reference_snapshot",
    "generate_market_evidence",
    "compile_final_request",
    "run_valuation_kernel",
}


def _git(*args: str, text: bool = True) -> str | bytes:
    result = subprocess.check_output(
        ["git", "-C", str(ROOT), *args],
        text=text,
        stderr=subprocess.STDOUT,
    )
    return result.strip() if text else result


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _schema_hashes(revision: str | None = None) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted((ROOT / "schemas").glob("*.json")):
        relative = path.relative_to(ROOT).as_posix()
        payload = (
            path.read_bytes()
            if revision is None
            else _git("show", f"{revision}:{relative}", text=False)
        )
        hashes[relative] = _sha(payload)
    return hashes


def _literal_set(tree: ast.AST, name: str) -> set[str]:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        value = node.value
        if isinstance(value, ast.Dict):
            return {
                item.value
                for item in value.keys
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            }
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
        raise SystemExit("HEAD is not descended from accepted Phase 5E-2A.2")

    sys.path.insert(0, str(ROOT / "src"))
    import owner_research

    if owner_research.__version__ != EXPECTED_VERSION:
        raise SystemExit("Phase 5E-2A.2.1 Python version drifted")
    current_schemas = _schema_hashes()
    if len(current_schemas) != 43 or current_schemas != _schema_hashes(BASELINE):
        raise SystemExit("Phase 5E-2A.2.1 changed a public Schema")

    lock = json.loads((ROOT / "component-lock.json").read_text(encoding="utf-8"))
    baseline_lock = json.loads(_git("show", f"{BASELINE}:component-lock.json"))
    if (
        lock["lock_version"] != "1.2.0"
        or lock["owner_equity_research"]["plugin_version"] != EXPECTED_PLUGIN_VERSION
        or lock["owner_equity_research"]["public_schema_sha256"] != current_schemas
        or lock["market_access_authority"] != baseline_lock["market_access_authority"]
        or lock["valuation_kernel"] != baseline_lock["valuation_kernel"]
    ):
        raise SystemExit("component lock changed outside the research package version")

    module_path = ROOT / "src/owner_research/valuation_current_share_evidence.py"
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    definitions = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
    }
    required = {
        "CurrentShareEvidenceClosure",
        "CorporateActionCoverageLedger",
        "CompletedClaimTransitionReconciliation",
        "derive_current_share_evidence_closure",
    }
    if not required.issubset(definitions):
        raise SystemExit("recursive current-share closure surface is incomplete")
    if definitions.intersection(FORBIDDEN_PRODUCTION_NAMES):
        raise SystemExit("Phase 5E-2A.2.1 exposes a prohibited production surface")

    event_concepts = _literal_set(tree, "COMPLETED_SHARE_EVENT_SIGNS")
    if not REQUIRED_EVENT_CONCEPTS.issubset(event_concepts):
        raise SystemExit("completed share-event registry is incomplete")
    if "common_shares_repurched_completed" in event_concepts:
        raise SystemExit("legacy misspelled repurchase concept remains registered")
    coverage = _literal_set(tree, "CORPORATE_ACTION_COVERAGE_CATEGORIES")
    if coverage != REQUIRED_COVERAGE_CATEGORIES:
        raise SystemExit("corporate-action coverage registry drifted")

    package_root = (ROOT / "src/owner_research/__init__.py").read_text(encoding="utf-8")
    if "valuation_current_share_evidence" in package_root:
        raise SystemExit("current-share validation internals leaked from the package root")

    tests = (ROOT / "tests/test_phase5e2a21_recursive_evidence.py").read_text(encoding="utf-8")
    required_test_tokens = {
        "authorized_shares",
        "potential_conversion_shares",
        "test_rollforward_rejects_derived_event_and_invalid_opening",
        'published_date="2026-07-15"',
        'confidence="low"',
        "SourceSearchReceipt",
        "search silence as zero",
        "common_shares_repurchased_completed",
        "common_shares_repurched_completed",
        "extinguished claim remains",
    }
    if any(token not in tests for token in required_test_tokens):
        raise SystemExit("Phase 5E-2A.2.1 adversarial coverage is incomplete")

    state = json.loads((ROOT / "docs/phase-status.json").read_text(encoding="utf-8"))
    if state["release_tag"] is not None:
        raise SystemExit("Phase 5E-2A.2.1 successor created an unauthorized release tag")
    closeouts = [*state.get("prior_closeouts", ()), state.get("closeout", {})]
    accepted = next(
        (item for item in closeouts if item.get("phase") == "Phase 5E-2A.2.1"),
        None,
    )
    if (
        accepted is None
        or accepted.get("substantive_merge_commit")
        != "973a98a8e8b03ba1f8efa681b8c528c064467a2c"
        or accepted.get("audit", {}).get("version") != "2.3.2.2.1"
        or any(accepted.get("audit", {}).get("finding_counts", {}).values())
    ):
        raise SystemExit("accepted Phase 5E-2A.2.1 closeout identity drifted")

    print("Phase 5E-2A.2.1 recursive current-share evidence boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
