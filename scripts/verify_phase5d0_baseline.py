#!/usr/bin/env python3
"""Verify that accepted Phase 5D-0 contract and policy artifacts remain byte-frozen."""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE5D0_MERGE = "4814029d9c5a690e2779dcb4e5e800798c663053"
IMMUTABLE_PATHS = (
    "docs/adr/0027-phase5d0-assumption-governance.md",
    "docs/phase5d0-assumption-policy.md",
    "schemas/valuation-assumption-candidate.schema.json",
    "schemas/valuation-handoff.schema.json",
    "tests/fixtures/phase5d0/adversarial-cases.json",
    "tests/test_phase5d0_assumption_policies.py",
)
SHARED_PHASE5D_DEFINITIONS = {
    "src/owner_research/contracts.py": {
        "ValuationAssumptionCandidate",
        "ValuationAssumptionReviewDecision",
        "ValuationHandoff",
    },
    "src/owner_research/valuation_handoff_validation.py": {
        "candidate_evidence_graph_sha256",
        "_validate_candidate",
        "_validate_decisions",
        "_validate_handoffs",
    },
}


def _git(*args: str, text: bool = True) -> str | bytes:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=text, stderr=subprocess.STDOUT
    )


def _definition_dumps(payload: str, names: set[str]) -> dict[str, str]:
    tree = ast.parse(payload)
    definitions = {
        node.name: ast.dump(node, include_attributes=False)
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in names
    }
    if set(definitions) != names:
        missing = sorted(names - set(definitions))
        raise SystemExit(f"Phase 5D-0 shared definitions are missing: {missing}")
    return definitions


def main() -> int:
    ancestry = subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", PHASE5D0_MERGE, "HEAD"]
    )
    if ancestry.returncode:
        raise SystemExit("HEAD is not descended from the accepted Phase 5D-0 merge")
    for relative in IMMUTABLE_PATHS:
        baseline = _git("show", f"{PHASE5D0_MERGE}:{relative}", text=False)
        if (ROOT / relative).read_bytes() != baseline:
            raise SystemExit(f"Accepted Phase 5D-0 artifact was rewritten: {relative}")
    for relative, names in SHARED_PHASE5D_DEFINITIONS.items():
        baseline = _definition_dumps(
            _git("show", f"{PHASE5D0_MERGE}:{relative}", text=True), names
        )
        current = _definition_dumps((ROOT / relative).read_text(encoding="utf-8"), names)
        if current != baseline:
            raise SystemExit(f"Accepted Phase 5D-0 shared semantics were rewritten: {relative}")
    policy_path = "src/owner_research/valuation_handoff_policies.py"
    baseline_policy = _git("show", f"{PHASE5D0_MERGE}:{policy_path}", text=True)
    expected_policy = baseline_policy.replace(
        'MARKET_REFERENCE_POLICY_VERSION = "1.0.0"',
        'MARKET_REFERENCE_POLICY_VERSION = "2.0.0"',
    )
    if (ROOT / policy_path).read_text(encoding="utf-8") != expected_policy:
        raise SystemExit("Phase 5D-0 policy changed beyond the Snapshot v2 version slot")
    print("Canonical Phase 5D-0 contracts and policies are unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
