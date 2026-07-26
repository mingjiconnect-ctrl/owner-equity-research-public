#!/usr/bin/env python3
# ruff: noqa: E501
"""Executable independent oracle for Phase 5E-2B.1-2A.

Expected values and hashes are recalculated here with the standard library.  The oracle also
constructs the production contracts through a test-only valid-baseline factory and executes every
registered adversarial test.  Static source checks remain boundary scans, not semantic evidence.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import hashlib
import importlib
import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

try:
    from scripts.public_bootstrap import (
        commit_exists,
        public_root_commit,
        verify_public_bootstrap_snapshot,
    )
except ModuleNotFoundError:  # direct script execution
    from public_bootstrap import (  # type: ignore[no-redef]
        commit_exists,
        public_root_commit,
        verify_public_bootstrap_snapshot,
    )

CONTROL_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("PHASE5E_CANDIDATE_REPOSITORY", CONTROL_ROOT)).resolve()
TYPE_MODULE = ROOT / "src/owner_research/valuation_share_event_integration_types.py"
POLICY = ROOT / "src/owner_research/resources/current_share/canonical-event-integration-policy.json"
TEST = ROOT / "tests/test_phase5e2b12a_integration_contracts.py"
INTEGRATION_ORACLE = ROOT / "scripts/verify_phase5e2b12a_integration_contracts.py"
AUDIT_RUNNER = ROOT / "scripts/run_phase5e_audit.py"

REQUIRED_TESTS = {
    "test_hidden_governed_event_cannot_be_closed_as_zero_activity",
    "test_security_identity_is_replayed_after_synchronized_caller_forgery",
    "test_counterevidence_is_inside_the_recursive_extension_closure",
    "test_source_content_change_invalidates_the_recursive_source_closure",
    "test_observed_event_source_must_be_returned_by_governed_receipt",
    "test_search_endpoint_tool_and_receipt_identity_are_closed",
    "test_claim_transition_rejects_common_shares_and_missing_canonical_parent",
    "test_claim_transition_review_chain_is_exact_and_economic_key_is_authorized",
    "test_phase5c_dilution_authority_cannot_be_caller_rewritten",
    "test_synchronized_artifact_and_handoffs_cannot_authorize_outside_graph_root",
    "test_graph_owned_root_without_exact_human_review_chain_is_rejected",
    "test_synchronized_resign_cannot_hide_duplicate_phase5c_review_identity",
    "test_synchronized_resign_cannot_reuse_phase5c_review_chain_across_bindings",
    "test_synchronized_resign_cannot_add_unreviewed_blocked_phase5c_binding",
    "test_synchronized_resign_cannot_hide_reviewed_blocked_binding",
    "test_synchronized_resign_cannot_hide_positive_option_root_by_treatment_or_identity",
    "test_distinct_confirmed_excluded_bindings_close_with_unique_review_chains",
    "test_each_phase5c_review_reference_is_one_to_one",
    "test_phase5c_root_fact_cannot_be_bound_twice",
    "test_confirmed_phase5c_binding_requires_each_review_reference",
    "test_phase5c_identity_kind_matrix_matches_frozen_accounting_policy",
    "test_synchronized_resign_cannot_duplicate_phase5c_consumption_record",
    "test_synchronized_resign_cannot_duplicate_phase5c_option_role_root",
    "test_synchronized_resign_cannot_add_unique_phase5c_consumption_record",
    "test_synchronized_resign_cannot_add_unbound_phase5c_consumption_root",
    "test_claim_authority_rejects_a_superseded_freeze_run",
    "test_claim_authority_rejects_two_active_freeze_runs",
    "test_freeze_handoff_chain_must_be_exactly_owned_by_current_graph",
    "test_component_lock_drift_invalidates_graph_owned_claim_authority",
    "test_claim_authority_ignores_unrelated_graph_history_but_rejects_missing_review_object",
    "test_claim_authority_cannot_be_transplanted_into_bundle_from_another_graph",
    "test_bundle_closure_is_independent_of_unrelated_graph_history",
    "test_same_graph_claim_sensitive_authority_closes_bundle_and_outer_evidence",
    "test_artifact_only_dilution_authority_constructor_is_removed",
    "test_primary_source_selection_is_order_independent",
    "test_coverage_rejects_a_duplicate_registered_category",
    "test_not_applicable_review_chain_is_category_and_security_specific",
    "test_not_applicable_review_requires_exact_scope_named_human_and_hashes",
    "test_not_applicable_candidate_and_claim_must_be_period_safe",
    "test_not_applicable_chain_ids_cannot_be_reused_across_categories",
    "test_each_not_applicable_review_identity_is_unique_per_category",
    "test_distinct_not_applicable_chains_may_share_one_supporting_fact",
    "test_not_applicable_claim_is_an_exact_candidate_projection",
    "test_not_applicable_review_and_support_must_replay_governed_time_and_sources",
    "test_not_applicable_review_cannot_postdate_the_data_cutoff",
    "test_not_applicable_support_cannot_postdate_the_candidate",
    "test_not_applicable_counterevidence_cannot_postdate_the_candidate",
    "test_not_applicable_candidate_cannot_predate_the_covered_period_end",
    "test_not_applicable_candidate_bindings_must_be_direct_fact_only",
    "test_not_applicable_binding_ids_are_unique_across_evidence_polarities",
    "test_bundle_rejects_duplicate_typed_source_documents",
    "test_bundle_replay_rejects_duplicate_security_closure_identities",
    "test_recursive_closure_byte_binds_all_typed_coverage_evidence",
    "test_standard_option_transition_replays_one_reviewed_phase5c_dilution_root",
    "test_claim_transition_review_chain_cannot_cross_the_data_cutoff",
    "test_claim_transition_evidence_fact_cannot_cross_the_candidate_or_cutoff",
    "test_claim_transition_evidence_source_cannot_postdate_the_candidate",
    "test_not_applicable_candidate_may_follow_period_end_through_cutoff",
    "test_recursive_fact_parent_edges_are_the_exact_deterministic_lineage",
    "test_typed_extension_event_and_decision_roots_replay_complete_event_evidence",
    "test_typed_extension_rejects_wrong_type_or_dangling_fact_reference",
    "test_typed_extension_candidate_reaches_each_exclusive_evidence_domain",
    "test_typed_extension_calculation_reaches_all_four_input_domains",
    "test_management_commitment_scope_is_typed_only_for_segment_scope",
    "test_convertible_and_warrant_transitions_require_specialist_authority",
    "test_current_share_closure_cannot_bypass_specialist_claim_authority",
}

REQUIRED_SOURCE_MARKERS = {
    "group_governed_completed_share_events",
    "GroupBoundDilutionClaimAuthority",
    "Phase5CDilutionClaimAuthority",
    "PriceBlindFreezeCompilationResult",
    "PriceBlindInputArtifact",
    "from_price_blind_freeze",
    "price-blind Handoff chain is not current and graph-owned",
    "group-bound dilution authority changed the current freeze or lock",
    "Candidate-to-human-Decision-to-Claim",
    "Phase 5C review binding references are duplicated",
    "research-bundle-current-share-extension",
    "current-share-source-search-authority",
    "owner-research-source-search/1.0.0",
    "_candidate_evidence_object_ids",
    "observed share-event source is absent from its governed receipt",
    "claim-transition economic claim key does not replay",
    "current-share grouping does not replay the current governed graph",
    "group-bound coverage requires exactly one entry per registered category",
    "coverage N/A Candidate review chain is reused across categories",
    "current-share extension SourceDocuments are duplicated",
    "current-share security evidence contains duplicate typed identities",
    "coverage typed evidence is not byte-bound to the graph-owned Bundle closure",
    "claim-transition typed evidence is not byte-bound",
    "claim-transition review chain crosses the data cutoff",
    "must contain direct Fact-only evidence",
    "_typed_extension_dependency_closure",
    "GRAPH_OBJECT_ID_ATTRIBUTE",
    "claim-transition event requires specialist authority outside frozen Phase 5C",
}

EXPECTED_COVERAGE_CATEGORIES = (
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
)

EXPECTED_SOURCE_FAMILIES = (
    "10-K",
    "10-Q",
    "8-K",
    "DEF14A",
    "registration_or_prospectus",
    "tender_or_merger_material",
    "credit_or_indentures",
    "official_ir",
)
EXPECTED_POLICY_SHA256 = "3c0b97cd2145efaf35b92fb28c65ba7bf0ab76a2a097ad59dd103b01c3014da4"
EXPECTED_POLICY_RAW_SHA256 = (
    "78538fe7b76ac12eeadbd9298fcf46d67b87e4a86718694233fd445de152ddb5"
)
EXPECTED_TYPE_MODULE_SHA256 = (
    "401b283f18ffd5e5f990a7a756e89804c9803cbdfc711cf19d5f877792b56865"
)
EXPECTED_TYPE_AST_SHA256 = {
    (3, 11): "0b298e1d5bba64e7a03218f001dc7f34daa68909bccb0f45d8133b3fd002b086",
    (3, 12): "cca66107f6d33ac1398850816f7ebd799fc542385df7ded79aaeca0624996c40",
    (3, 13): "a88f78bec3e0c076388b366c647deae23da0cc9fe2bd51fac35ecd7aba83e659",
    (3, 14): "a88f78bec3e0c076388b366c647deae23da0cc9fe2bd51fac35ecd7aba83e659",
}
ACCEPTANCE_CLOSEOUT = "docs/phase5e2b12a-acceptance-closeout.json"

ADVERSARIAL_FIXTURE = ROOT / "tests/fixtures/phase5e2b12a/adversarial-cases.json"
EXPECTED_ADVERSARIAL_CASE_IDS = frozenset(
    {
        "official-occurrence-split-across-legal-groups",
        "bundle-rejects-split-official-occurrence",
        "reserved-canonical-id-existing-fact",
        "reserved-output-id-existing-fact",
        "reserved-canonical-id-cross-domain",
        "reserved-output-id-cross-domain",
        "reserved-canonical-id-exact-reuse-only",
        "caller-rewrites-generated-reservations",
        "two-corroborating-members-consumed-once",
        "one-vs-two-corroborating-members",
        "member-fact-bytes-forged",
        "bundle-dangling-member-fact",
        "grouping-magnitude-or-future-date-self-attested",
        "coverage-receipt-or-zero-evidence-forged",
        "receipt-and-bundle-cik-forgery",
        "wrong-output-with-rehashed-closure",
        "sequential-option-chain-and-branch-guard",
        "blank-reviewer-or-inverted-stock-period",
        "caller-rewrites-phase5c-authority",
        "primary-source-input-order-reversal",
        "multi-item-collection-permutations",
        "extra-recursive-parent-edge",
        "fully-closed-zero-event-rollforward",
        "root-parent-tmp-spaces-and-symlink-replay",
        "extra-import-function-class-method-or-body",
        "duplicate-numeric-or-nonfinite-policy-json",
        "convertible-forced-through-option-authority",
        "warrant-forced-through-option-authority",
    }
)

def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _reject_duplicate_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json(path: Path) -> object:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_json_pairs,
        parse_int=lambda value: (_ for _ in ()).throw(
            SystemExit(f"numeric JSON value is forbidden: {value}")
        ),
        parse_float=lambda value: (_ for _ in ()).throw(
            SystemExit(f"numeric JSON value is forbidden: {value}")
        ),
        parse_constant=lambda value: (_ for _ in ()).throw(
            SystemExit(f"non-finite JSON constant: {value}")
        ),
    )


def _ast_sha256(source: str) -> str:
    tree = ast.parse(source, type_comments=True)
    payload = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def _function_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _literal_assignment(path: Path, name: str) -> object:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ):
            return ast.literal_eval(node.value)
    raise SystemExit(f"{name} is missing from {path.name}")


def _independent_json(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {
            field.name: _independent_json(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, Mapping):
        return {str(key): _independent_json(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_independent_json(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_independent_json(item) for item in value)
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    return value


def _independent_object_sha(value: Any, hash_field: str) -> str:
    payload = _independent_json(value)
    if not isinstance(payload, dict):
        raise SystemExit(f"{type(value).__name__} is not an object payload")
    payload.pop(hash_field)
    return _canonical_sha256(payload)


def _test_functions(path: Path) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        node.name: node
        for node in ast.parse(path.read_text(encoding="utf-8")).body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _execute_production_contract_oracle() -> None:
    tests_path = CONTROL_ROOT / "tests"
    prior_path = list(sys.path)
    sys.path.append(str(tests_path))
    sys.path.append(str(ROOT / "src"))
    try:
        conftest = importlib.import_module("conftest")
        support = importlib.import_module("test_phase5e2b12a_integration_contracts")
    finally:
        sys.path[:] = prior_path

    sample_payloads = conftest.sample_payloads.__wrapped__()
    closure, _ = support._accepted_context(
        sample_payloads=sample_payloads,
        corroborating_count=2,
    )
    materialization = closure.materializations[0]
    if len(materialization.members) != 2 or len(closure.numeric_consumptions) != 1:
        raise SystemExit("production baseline does not preserve exactly-once corroboration")
    magnitude_by_group = {
        item.group_id: int(item.canonical_share_magnitude) for item in closure.materializations
    }
    expected_output = int(closure.opening_share_fact.value) + sum(
        int(Decimal(item.sign) * magnitude_by_group[item.group_id])
        for item in closure.numeric_consumptions
    )
    if expected_output != 95_000_000 or int(closure.output_share_fact.value) != expected_output:
        raise SystemExit("production baseline fails independent exactly-once arithmetic")
    expected_parent_ids = tuple(sorted(item.fact_id for item in materialization.members))
    if tuple(materialization.canonical_event_fact.parent_fact_ids) != expected_parent_ids:
        raise SystemExit("canonical event Fact does not preserve all corroborating parents")
    module_sha = hashlib.sha256(TYPE_MODULE.read_bytes()).hexdigest()
    if materialization.materialization_code_sha256 != module_sha:
        raise SystemExit("materialization code SHA does not bind exact module bytes")
    if materialization.materialization_fingerprint != _independent_object_sha(
        materialization,
        "materialization_fingerprint",
    ):
        raise SystemExit("materialization fingerprint fails independent replay")
    if closure.coverage_ledger.ledger_sha256 != _independent_object_sha(
        closure.coverage_ledger,
        "ledger_sha256",
    ):
        raise SystemExit("coverage ledger SHA fails independent replay")
    if closure.claim_transition_reconciliation.reconciliation_sha256 != (
        _independent_object_sha(
            closure.claim_transition_reconciliation,
            "reconciliation_sha256",
        )
    ):
        raise SystemExit("Claim-transition SHA fails independent replay")
    if closure.bundle_evidence_closure.closure_sha256 != _independent_object_sha(
        closure.bundle_evidence_closure,
        "closure_sha256",
    ):
        raise SystemExit("Bundle evidence closure SHA fails independent replay")
    if closure.closure_sha256 != _independent_object_sha(closure, "closure_sha256"):
        raise SystemExit("current-share closure SHA fails independent replay")

    material_payload = _independent_json(materialization)
    material_payload["materialization_code_sha256"] = "0" * 64
    material_payload.pop("materialization_fingerprint")
    try:
        dataclasses.replace(
            materialization,
            materialization_code_sha256="0" * 64,
            materialization_fingerprint=_canonical_sha256(material_payload),
        )
    except ValueError as error:
        if "code SHA" not in str(error):
            raise SystemExit(
                "production code-SHA gate rejected through the wrong boundary"
            ) from error
    else:
        raise SystemExit("production code-SHA gate accepted a byte-unbound materialization")

    entries = closure.coverage_ledger.entries
    duplicated_entries = (*entries[:-1], entries[0])
    coverage_payload = _independent_json(closure.coverage_ledger)
    coverage_payload["entries"] = _independent_json(duplicated_entries)
    coverage_payload.pop("ledger_sha256")
    try:
        dataclasses.replace(
            closure.coverage_ledger,
            entries=duplicated_entries,
            ledger_sha256=_canonical_sha256(coverage_payload),
        )
    except ValueError as error:
        if "exactly one entry" not in str(error):
            raise SystemExit("production cardinality attack hit the wrong boundary") from error
    else:
        raise SystemExit("production coverage gate accepted a duplicated category")

    # These functions are loaded from the immutable protected-base oracle tree, while every
    # contract class they exercise is imported from the candidate production package.  They are
    # intentionally invoked directly rather than discovered from candidate-owned pytest files.
    support.test_generated_fact_parent_order_is_canonical_not_set_equivalent(sample_payloads)
    support.test_recursive_closure_id_is_deterministic(sample_payloads)
    support.test_zero_event_closure_binds_integration_contract_policy_and_code(sample_payloads)
    support.test_bundle_closure_rejects_binary_float_opening_share_root(sample_payloads)
    for updates, message in (
        ({"value": 5_000_000.0}, "exact JSON integer"),
        ({"confidence": "medium"}, "canonical group evidence"),
        (
            {"period": {"start": "2026-03-31", "end": "2026-06-15"}},
            "canonical group evidence",
        ),
    ):
        support.test_observed_coverage_entry_rejects_noncanonical_numeric_evidence(
            sample_payloads,
            updates,
            message,
        )
    for event_date in ("2026-03-31", "2026-07-01"):
        support.test_observed_coverage_ledger_rejects_event_outside_closed_window(
            sample_payloads,
            event_date,
        )
    support.test_claim_transition_remaining_fact_identity_is_replay_deterministic()


def _execute_registered_adversarial_tests(nodeids: Sequence[str]) -> None:
    """Execute every case named by the closed adversarial registry.

    The registry is useful only if its node IDs are executable.  This protected-base oracle
    therefore runs the exact closed set in addition to the independent arithmetic and object-hash
    checks above.  Pytest remains candidate code and is not the sole oracle; the manually replayed
    invariants in this module are the independent control surface.
    """

    completed = subprocess.run(
        (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "--disable-warnings",
            "--maxfail=1",
            *tuple(sorted(nodeids)),
        ),
        cwd=ROOT,
        env=dict(os.environ),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=600,
        check=False,
    )
    if completed.returncode != 0:
        evidence = completed.stdout[-8_000:]
        raise SystemExit(f"registered adversarial tests failed:\n{evidence}")



def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frozen-contract-replay", action="store_true")
    args = parser.parse_args()
    integration_paths = set(
        _literal_assignment(INTEGRATION_ORACLE, "PHASE5E2B12A_ALLOWED_CHANGED_PATHS")
    )
    audit_paths = set(_literal_assignment(AUDIT_RUNNER, "PHASE5E2B12A_ALLOWED_CHANGED_PATHS"))
    private_baseline = "4fd643df73108b1fa3ab3ce1eb258ae3c3ce8a6d"
    public_mode = not commit_exists(private_baseline, ROOT)
    if public_mode:
        verify_public_bootstrap_snapshot(ROOT)
        comparison_commit = public_root_commit(ROOT)
        expected_paths = set(
            _literal_assignment(
                INTEGRATION_ORACLE,
                "PUBLIC_CANONICAL_MIGRATION_CHANGED_PATHS",
            )
        )
    else:
        comparison_commit = private_baseline
        expected_paths = set(integration_paths)
    actual_paths = set(
        subprocess.check_output(
            [
                "git",
                "-C",
                str(ROOT),
                "diff",
                "--name-only",
                "--no-renames",
                comparison_commit,
            ],
            text=True,
        ).splitlines()
    ) | set(
        subprocess.check_output(
            ["git", "-C", str(ROOT), "ls-files", "--others", "--exclude-standard"],
            text=True,
        ).splitlines()
    )
    phase_status = json.loads((ROOT / "docs/phase-status.json").read_text(encoding="utf-8"))
    accepted = (
        phase_status.get("current_phase") == "Phase 5E-2B.1-2A"
        and phase_status.get("status") == "accepted_closed"
        and (ROOT / ACCEPTANCE_CLOSEOUT).is_file()
    )
    if accepted and not public_mode:
        expected_paths.add(ACCEPTANCE_CLOSEOUT)
    required_boundary_paths = {
        ".github/workflows/ci.yml",
        ".github/workflows/phase5e2b12a-acceptance-gate.yml",
        "pyproject.toml",
        "plugins/owner-equity-research/.codex-plugin/plugin.json",
        "scripts/run_phase5e_audit.py",
        "scripts/pytest_phase5e_nodeids.py",
        "scripts/verify_phase5e2b12a_acceptance_gate.py",
        "scripts/verify_phase5e2b12a_integration_contracts.py",
        "src/owner_research/__init__.py",
        "src/owner_research/valuation_share_event_integration_types.py",
    }
    if not args.frozen_contract_replay and (
        integration_paths != audit_paths
        or expected_paths != actual_paths
        or not required_boundary_paths.issubset(integration_paths)
    ):
        raise SystemExit("repository-wide Phase 5E-2B.1-2A changed-path boundary is open")
    policy = _strict_json(POLICY)
    if not isinstance(policy, dict):
        raise SystemExit("closed current-share integration policy is not an object")
    if (
        hashlib.sha256(POLICY.read_bytes()).hexdigest() != EXPECTED_POLICY_RAW_SHA256
        or _canonical_sha256(policy) != EXPECTED_POLICY_SHA256
    ):
        raise SystemExit("closed current-share integration policy drifted")
    if tuple(policy["coverage"]["required_categories"]) != EXPECTED_COVERAGE_CATEGORIES:
        raise SystemExit("closed coverage category registry drifted")
    if tuple(policy["coverage"]["required_source_families"]) != EXPECTED_SOURCE_FAMILIES:
        raise SystemExit("closed source-family registry drifted")
    if tuple(policy["claim_transition"]["standard_event_concepts"]) != (
        "option_shares_exercised_completed",
    ):
        raise SystemExit("standard Claim-transition registry drifted")
    if tuple(policy["claim_transition"]["specialist_required_event_concepts"]) != (
        "convertible_shares_converted_completed",
        "warrant_shares_exercised_completed",
    ):
        raise SystemExit("specialist Claim-transition registry drifted")
    fixture = _strict_json(ADVERSARIAL_FIXTURE)
    if not isinstance(fixture, dict) or not isinstance(fixture.get("cases"), list):
        raise SystemExit("adversarial case registry is not a closed object")
    cases = fixture["cases"]
    required_case_keys = {
        "case_id",
        "case_kind",
        "boundary",
        "mutation",
        "expected",
        "test_nodeid",
    }
    case_ids = [item.get("case_id") for item in cases]
    nodeids = [item.get("test_nodeid") for item in cases]
    if (
        fixture.get("schema_version") != "2.0.0"
        or fixture.get("phase") != "Phase 5E-2B.1-2A"
        or any(not isinstance(item, dict) or set(item) != required_case_keys for item in cases)
        or set(case_ids) != EXPECTED_ADVERSARIAL_CASE_IDS
        or len(case_ids) != len(set(case_ids))
        or len(nodeids) != len(set(nodeids))
        or any(
            not isinstance(nodeid, str)
            or not nodeid.startswith(
                "tests/test_phase5e2b12a_integration_contracts.py::test_"
            )
            for nodeid in nodeids
        )
    ):
        raise SystemExit("case-specific executable adversarial registry drifted")
    if policy["research_bundle_extension"] != {
        "policy_id": "research-bundle-current-share-extension",
        "policy_version": "1.0.0",
        "base": "immutable_public_research_bundle_dependency_closure",
        "extension": "exact_transitive_post_bundle_current_share_dependency_closure",
        "extension_roots": "graph_owned_reviewed_current_share_evidence_only",
        "graph_fingerprint": "exact_scoped_dependency_objects_plus_component_lock",
        "issuer_cik_authority": (
            "one_cutoff_safe_graph_owned_filing_artifact_cik_bound_to_all_"
            "source_search_receipts"
        ),
        "unrelated_history": "excluded_from_fingerprint_and_closure",
    }:
        raise SystemExit("current-share extension authority is not closed")
    if (
        policy["coverage"]["search_authority"] != "current-share-source-search-authority/1.0.0"
        or policy["claim_transition"]["authority"]
        != "full_price_blind_freeze_and_current_contract_graph_replayed_phase5c_claim_authority"
        or policy["claim_transition"]["authority_policy"]
        != "phase5c-reviewed-dilution-claim-authority/2.0.0"
        or policy["claim_transition"]["freeze"] != "exact_price_blind_freeze_compilation_result"
        or policy["claim_transition"]["handoff"]
        != "graph_owned_adjacent_v1_v4_unique_current_unsuperseded_run_and_current_component_lock"
        or policy["claim_transition"]["artifact_self_hash"] != "insufficient_authority"
        or policy["claim_transition"]["typed_review_payload"]
        != "unique_ids_exact_binding_cardinality_and_graph_byte_equality"
        or policy["claim_transition"]["outer_bundle_replay"]
        != "same_contract_graph_as_current_share_bundle_evidence_closure"
        or policy["claim_transition"]["consumption_records"]
        != "closed_unique_records_and_only_the_exact_option_bridge_deduction_per_excluded_root"
        or policy["claim_transition"]["counterevidence"]
        != "included_in_recursive_extension_closure"
        or policy["coverage"]["cardinality"]
        != (
            "exactly_one_entry_per_registered_category_and_"
            "exactly_one_category_binding_per_canonical_group"
        )
        or policy["coverage"]["not_applicable_review_chain"]
        != "one_unique_category_specific_candidate_one_named_human_decision_one_claim"
        or policy["coverage"]["not_applicable_temporal_policy"]
        != (
            "support_and_counterevidence_fact_and_source_not_after_candidate_candidate_not_"
            "before_coverage_period_end_and_not_after_data_cutoff_candidate_equals_claim_"
            "review_not_before_candidate_and_not_after_data_cutoff"
        )
        or policy["coverage"]["not_applicable_evidence_binding"]
        != "direct_fact_only_globally_unique_binding_ids_and_exact_candidate_claim_projection"
        or policy["coverage"]["typed_graph_binding"]
        != (
            "all_result_sources_receipts_zero_observed_not_applicable_support_and_"
            "counterevidence_facts_candidates_decisions_and_claims_match_graph_owned_"
            "bundle_object_id_and_fingerprint"
        )
        or policy["recursive_closure"]["extension_dependency_policy"]
        != "closed_contract_type_specific_reference_edges_never_arbitrary_string_matching"
        or policy["recursive_closure"]["fact_parent_edge_policy"]
        != (
            "exact_output_to_opening_and_canonical_edges_plus_canonical_to_all_raw_member_"
            "edges_only"
        )
        or policy["claim_transition"]["temporal_policy"]
        != (
            "transition_evidence_fact_period_and_source_publication_not_after_candidate_"
            "candidate_equals_claim_review_not_before_candidate_and_all_not_after_data_cutoff"
        )
        or policy["claim_transition"]["typed_graph_binding"]
        != (
            "affected_remaining_and_transition_evidence_facts_sources_claims_candidates_"
            "and_decisions_match_graph_owned_bundle_object_id_and_fingerprint"
        )
        or policy["claim_transition"]["standard_event_concepts"]
        != ["option_shares_exercised_completed"]
        or set(policy["claim_transition"]["specialist_required_event_concepts"])
        != {
            "convertible_shares_converted_completed",
            "warrant_shares_exercised_completed",
        }
    ):
        raise SystemExit("coverage or Claim-transition trust authority is incomplete")

    source = TYPE_MODULE.read_text(encoding="utf-8")
    if (
        hashlib.sha256(TYPE_MODULE.read_bytes()).hexdigest() != EXPECTED_TYPE_MODULE_SHA256
        or _ast_sha256(source) != EXPECTED_TYPE_AST_SHA256.get(sys.version_info[:2])
    ):
        raise SystemExit("exact current-share integration type surface drifted")
    missing_markers = sorted(marker for marker in REQUIRED_SOURCE_MARKERS if marker not in source)
    if missing_markers:
        raise SystemExit(f"semantic validation markers are missing: {missing_markers}")
    top_level = ast.parse(source).body
    unauthorized = {
        node.name
        for node in top_level
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith(
            (
                "build_",
                "compile_",
                "fetch_",
                "run_",
                "write_",
                "persist_",
                "publish_",
                "score_",
                "value_",
            )
        )
    }
    if unauthorized:
        raise SystemExit(f"unauthorized production surface exists: {sorted(unauthorized)}")
    forbidden_imports = {"httpx", "requests", "socket", "urllib"}
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        str(node.module).split(".", 1)[0]
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module
    }
    if imported_roots & forbidden_imports:
        raise SystemExit("unauthorized network capability exists")
    forbidden_io_methods = {
        "write_bytes",
        "write_text",
        "touch",
        "mkdir",
        "rename",
        "unlink",
        "rmdir",
    }
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in forbidden_io_methods
        for node in ast.walk(ast.parse(source))
    ):
        raise SystemExit("unauthorized writer capability exists")
    integration_class = next(
        (
            node
            for node in top_level
            if isinstance(node, ast.ClassDef) and node.name == "GroupBoundDilutionClaimAuthority"
        ),
        None,
    )
    if integration_class is None:
        raise SystemExit("GroupBoundDilutionClaimAuthority is missing")
    authority_methods = {
        node.name
        for node in integration_class.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if "from_price_blind_freeze" not in authority_methods:
        raise SystemExit("full-freeze authority constructor is missing")
    if "from_price_blind_artifact" in authority_methods:
        raise SystemExit("artifact-only authority constructor remains exposed")

    missing_tests = sorted(REQUIRED_TESTS.difference(_function_names(TEST)))
    if missing_tests:
        raise SystemExit(f"semantic attack tests are missing: {missing_tests}")

    # Independent manual oracle: three disclosures are one reviewed legal event.
    disclosures = (
        ("primary_regulatory", "2026-06-15", "doc:8-k", "fact:8-k", "8-k:item"),
        ("primary_regulatory", "2026-06-30", "doc:10-q", "fact:10-q", "10-q:table"),
        ("company_primary", "2026-06-15", "doc:ir", "fact:ir", "ir:release"),
    )
    authority_rank = {"primary_regulatory": 0, "company_primary": 1}
    document_rank = {"8-K": 0, "10-Q": 1, "10-K": 2, "official_ir": 5}
    disclosures = (
        (*disclosures[0], "8-K"),
        (*disclosures[1], "10-Q"),
        (*disclosures[2], "official_ir"),
    )

    def primary(items: tuple[tuple[str, str, str, str, str, str], ...]) -> str:
        return min(
            items,
            key=lambda item: (
                authority_rank[item[0]],
                document_rank[item[5]],
                item[1],
                item[2],
                item[3],
                item[4],
            ),
        )[2]

    if primary(disclosures) != primary(tuple(reversed(disclosures))):
        raise SystemExit("independent primary-source order oracle failed")
    opening = 100_000_000
    canonical_groups = {
        "legal-event:repurchase-program-2026-06-15": {
            "magnitude": 5_000_000,
            "members": disclosures,
        }
    }
    result = opening - sum(item["magnitude"] for item in canonical_groups.values())
    if result != 95_000_000:
        raise SystemExit("independent exactly-once arithmetic oracle failed")
    before = _canonical_sha256(canonical_groups)
    canonical_groups["legal-event:repurchase-program-2026-06-15"]["members"] += (
        (
            "primary_regulatory",
            "2026-07-01",
            "doc:10-k",
            "fact:10-k",
            "10-k:note",
            "10-K",
        ),
    )
    after = _canonical_sha256(canonical_groups)
    if before == after or result != 95_000_000:
        raise SystemExit("corroborating-evidence metamorphic oracle failed")

    # Independent coverage oracle: set equality is insufficient when one category is duplicated.
    required_categories = tuple(policy["coverage"]["required_categories"])
    if required_categories != EXPECTED_COVERAGE_CATEGORIES:
        raise SystemExit("closed coverage category registry drifted")
    duplicated_categories = (*required_categories, required_categories[0])
    if (
        len(required_categories) != 12
        or set(duplicated_categories) != set(required_categories)
        or len(duplicated_categories) == len(required_categories)
    ):
        raise SystemExit("independent coverage-cardinality attack oracle failed")

    security_id = "security:issuer:acme:XNYS:ACME:common"
    statements = {
        category: (
            f"Share activity category {category} is not applicable to security {security_id}."
        )
        for category in required_categories
    }
    if len(set(statements.values())) != len(required_categories):
        raise SystemExit("independent category-specific N/A statement oracle failed")
    reused_chain_ids = ("candidate:generic", "decision:generic", "claim:generic")
    chains = {
        required_categories[0]: reused_chain_ids,
        required_categories[1]: reused_chain_ids,
    }
    if len(chains) == len(set(chains.values())):
        raise SystemExit("independent N/A chain-reuse attack oracle failed")

    # Independent temporal/typed-evidence oracle. These expectations are deliberately hard-coded
    # here rather than derived from the mutable production policy or validator.
    candidate_date = "2026-06-25"
    cutoff_date = "2026-06-30"
    invalid_temporal_cases = (
        {"support_end": "2026-06-26", "source_published": "2026-06-20", "review": cutoff_date},
        {"support_end": candidate_date, "source_published": "2026-06-26", "review": cutoff_date},
        {"support_end": candidate_date, "source_published": "2026-06-20", "review": "2026-07-01"},
    )
    if any(
        case["support_end"] <= candidate_date
        and case["source_published"] <= candidate_date
        and candidate_date <= case["review"] <= cutoff_date
        for case in invalid_temporal_cases
    ):
        raise SystemExit("independent N/A temporal attack oracle failed")
    support_binding_ids = {"binding:shared"}
    counter_binding_ids = {"binding:shared"}
    if support_binding_ids.isdisjoint(counter_binding_ids):
        raise SystemExit("independent cross-polarity binding-identity attack oracle failed")
    graph_binding = ("Fact", "fact:same-id", "a" * 64)
    caller_binding = ("Fact", "fact:same-id", "b" * 64)
    if graph_binding == caller_binding or caller_binding in {graph_binding}:
        raise SystemExit("independent typed-object substitution oracle failed")
    if not ("2026-06-30" < "2027-01-02"):
        raise SystemExit("independent Claim-transition cutoff oracle failed")

    _execute_production_contract_oracle()
    _execute_registered_adversarial_tests(tuple(nodeids))

    print("Phase 5E-2B.1-2A independent semantic trust-boundary oracle passed")
    return 0


def _fail_closed_main() -> int:
    try:
        return main()
    except BaseException as exc:  # Candidate imports must never turn SystemExit(0) into success.
        print(
            f"Phase 5E-2B.1-2A semantic oracle failed closed: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(_fail_closed_main())
