#!/usr/bin/env python3
"""Independent Phase 5E-2B.1-0 policy and baseline-vulnerability oracle."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "1449e544d9907297c43c8d930d33170c45a60abb"
AUDIT_VERSION = "2.3.2.3.1"


def _legacy_duplicate_key_fields() -> set[str]:
    tree = ast.parse(
        (ROOT / "src/owner_research/valuation_current_share_compiler.py").read_text(
            encoding="utf-8"
        )
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "duplicate_event_keys"
            for target in node.targets
        ):
            return {
                item.attr
                for child in ast.walk(node.value)
                if isinstance(child, ast.Tuple)
                for item in child.elts
                if isinstance(item, ast.Attribute)
            }
    raise SystemExit("baseline completed-event duplicate key is missing")


def main() -> int:
    fixture_path = ROOT / "tests/fixtures/phase5e2b1/adversarial-cases.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    if fixture.get("baseline_commit") != BASELINE:
        raise SystemExit("share-event red fixture baseline drifted")
    cases = {item["case_id"]: item for item in fixture["cases"]}
    required = {
        "same-repurchase-8k-10q",
        "same-issuance-8k-10q-ir",
        "same-legal-id-magnitude-conflict",
        "same-legal-id-date-conflict",
        "different-fact-ids-same-event",
        "same-date-amount-no-distinct-legal-id",
        "same-date-amount-distinct-legal-ids",
        "duplicate-option-exercise-transition",
        "input-order-reversal",
        "corroboration-closure-only-change",
        "ineligible-member-evidence",
        "cumulative-period-total",
    }
    if set(cases) != required:
        raise SystemExit("share-event adversarial matrix is incomplete")

    baseline_case = cases["same-repurchase-8k-10q"]
    legacy_keys = {
        (
            "common_shares_repurchased_completed",
            event_date,
            f"source:{source}",
            f"locator:{source}",
        )
        for source, event_date in zip(
            baseline_case["member_sources"], baseline_case["dates"], strict=True
        )
    }
    legacy_result = int(fixture["opening_shares"]) - sum(
        int(value) for value in baseline_case["magnitudes"]
    )
    if len(legacy_keys) != 2 or legacy_result != 90_000_000:
        raise SystemExit("baseline vulnerability no longer reproduces as recorded")
    if int(baseline_case["expected_current_shares"]) != 95_000_000:
        raise SystemExit("canonical exactly-once result drifted")
    fields = _legacy_duplicate_key_fields()
    if not {"source_document_id", "source_locator"}.issubset(fields):
        raise SystemExit("baseline source-identity vulnerability is no longer observable")

    policy_source = (
        ROOT / "src/owner_research/valuation_share_event_identity.py"
    ).read_text(encoding="utf-8")
    policy_tree = ast.parse(policy_source)
    classes = {node.name for node in policy_tree.body if isinstance(node, ast.ClassDef)}
    expected_classes = {
        "ShareEventIdentity",
        "ShareEventEvidenceMember",
        "ShareEventEvidenceGroup",
        "ShareEventGroupingResult",
        "ShareEventConflict",
    }
    if not expected_classes.issubset(classes):
        raise SystemExit("Phase 5E-2B.1 internal type boundary is incomplete")
    forbidden_functions = {
        "group_share_events",
        "compile_share_event_groups",
        "compile_governed_market_evidence",
    }
    if forbidden_functions.intersection(
        node.name for node in policy_tree.body if isinstance(node, ast.FunctionDef)
    ):
        raise SystemExit("Phase 5E-2B.1-0 contains an unauthorized production entry point")

    state = json.loads((ROOT / "docs/phase-status.json").read_text(encoding="utf-8"))
    if (
        state.get("current_phase") != "Phase 5E-2B.1"
        or state.get("status") != "semantic_closeout_required"
        or state.get("authorized_next")
        != ["Phase 5E-2B.1-1 cross-source share-event grouping implementation"]
        or "Phase 5E-2C" not in state.get("prohibited", [])
    ):
        raise SystemExit("Phase 5E-2C is not closed behind the corrective boundary")

    evidence = {
        "audit_version": AUDIT_VERSION,
        "baseline_commit": BASELINE,
        "fixture_sha256": hashlib.sha256(fixture_path.read_bytes()).hexdigest(),
        "legacy_duplicate_key_fields": sorted(fields),
        "legacy_result": str(legacy_result),
        "canonical_result": baseline_case["expected_current_shares"],
        "production_grouping_present": False,
    }
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
