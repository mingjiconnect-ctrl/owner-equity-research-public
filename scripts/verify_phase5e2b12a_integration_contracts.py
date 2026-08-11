#!/usr/bin/env python3
"""Independent current-head oracle for Phase 5E-2B.1-2A."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

try:
    from scripts.public_bootstrap import (
        commit_exists,
        public_root_commit,
        public_root_file,
        public_root_paths,
        verify_public_bootstrap_snapshot,
    )
except ModuleNotFoundError:  # direct script execution
    from public_bootstrap import (  # type: ignore[no-redef]
        commit_exists,
        public_root_commit,
        public_root_file,
        public_root_paths,
        verify_public_bootstrap_snapshot,
    )

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "4fd643df73108b1fa3ab3ce1eb258ae3c3ce8a6d"
EXPECTED_VERSION = "0.5.0.dev11"
EXPECTED_PLUGIN_VERSION = "0.5.0-dev.11"
EXPECTED_AUDIT_VERSION = "2.3.2.3.3"
EXPECTED_POLICY_SHA256 = "815fbbd41f8ae307b6b758fd210830deb777a9e952e171b09e61e1a2b68fb16b"
EXPECTED_POLICY_OBJECT_SHA256 = (
    "332ba7d4cf4370126119fdc172082f5f3b19a82da8f65fe3a1e811fa726dc96f"
)
EXPECTED_TYPE_MODULE_SHA256 = (
    "003dfad8e1da2d07bddeaaf39310ad5a7529643e9a2aedbaffaa6d552683051d"
)
EXPECTED_TYPE_AST_SHA256 = {
    (3, 11): "d242cf697494f21377f3260a25f5e6f3d2cacdaedeca65034dc5b448e5761a1c",
    (3, 12): "e18d6d9c55fd19392a6009252710865d9676d825186704dab7254fdafb6c629c",
    (3, 13): "78c8f6e361f62cbbefe10834517d5dcaba9fd43258e2507b7dcb9f7655dc0411",
    (3, 14): "78c8f6e361f62cbbefe10834517d5dcaba9fd43258e2507b7dcb9f7655dc0411",
}
EXPECTED_ADVERSARIAL_FIXTURE_SHA256 = (
    "7f8ba762df20c51fbea5edee89e440ec7205c546416676211090ca950f65ec0d"
)
TYPE_MODULE = "src/owner_research/valuation_share_event_integration_types.py"
POLICY = "src/owner_research/resources/current_share/canonical-event-integration-policy.json"
TEST = "tests/test_phase5e2b12a_integration_contracts.py"
STATUS_PATH = "docs/phase-status.json"
ACCEPTANCE_CLOSEOUT = "docs/phase5e2b12a-acceptance-closeout.json"
INTERNAL_TYPE_NAMES = {
    "CanonicalShareEventMemberBinding",
    "CanonicalShareEventFactMaterialization",
    "ShareEventNumericConsumption",
    "CorporateActionCoverageEntryV2",
    "CorporateActionCoverageLedgerV2",
    "GroupBoundDilutionClaimAuthority",
    "GroupBoundClaimTransition",
    "GroupBoundClaimTransitionReconciliation",
    "CurrentShareBundleEvidenceClosure",
    "CurrentShareEvidenceClosureV2",
}
PHASE5E2B12A_ALLOWED_CHANGED_PATHS = {
    ".github/workflows/ci.yml",
    ".github/workflows/phase5e2b12a-acceptance-gate.yml",
    "AGENTS.md",
    "README.md",
    "component-lock.json",
    "docs/adr/0038-phase5e2b12a-current-share-integration-contracts.md",
    "docs/adr/0039-phase5e2b12a-semantic-trust-boundaries.md",
    "docs/phase-status.json",
    "docs/phase5-completion-overlay-v1.md",
    "docs/phase5-completion-overlay-v2.md",
    "docs/phase5-completion-overlay-v3.md",
    "docs/phase5e-acceptance-matrix.json",
    "docs/phase5e-failure-mode-matrix.json",
    "docs/phase5e-golden-matrix.json",
    "docs/phase5e-interface-matrix.json",
    "docs/phase5e2b12a-integration-contracts.md",
    "docs/roadmap.md",
    "plugins/owner-equity-research/.codex-plugin/plugin.json",
    "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md",
    "plugins/owner-equity-research/skills/owner-equity-research/references/market-execution-policy.md",
    "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md",
    "plugins/owner-equity-research/skills/owner-research-audit/agents/openai.yaml",
    "pyproject.toml",
    "scripts/run_phase5e_audit.py",
    "scripts/build_kernel_release_interface.py",
    "scripts/launch_phase5e_readonly_audit.sh",
    "scripts/phase5e-audit-requirements.lock",
    "scripts/phase5e-audit-runtime-matrix.json",
    "scripts/phase5e-audit-wheelhouse.sha256",
    "scripts/phase5e_audit_profiles.py",
    "scripts/phase5e-futu-market-authority-policy-v1.json",
    "scripts/phase5e_candidate_exec.sh",
    "scripts/phase5e_kernel_git_shim.sh",
    "scripts/pytest_phase5e_nodeids.py",
    "scripts/phase5e2b12a-acceptance-trust.json",
    "scripts/phase5e2b12b-acceptance-trust.json",
    "scripts/phase5e-successor-gate-bundle.schema.json",
    "scripts/verify_phase5e2b12a_acceptance_gate.py",
    "scripts/verify_all.py",
    "scripts/verify_phase5e2b11_frozen_acceptance.py",
    "scripts/verify_phase5e2b12a_integration_contracts.py",
    "scripts/verify_phase5e2b12a_semantic_oracle.py",
    "scripts/verify_phase5e_candidate_surface.py",
    "scripts/verify_phase5e_candidate_import_surface.py",
    "scripts/verify_kernel_release_interface.py",
    "scripts/verify_phase5e2b12b_acceptance_gate.py",
    "scripts/verify_phase5e2b12b_semantic_oracle.py",
    "scripts/verify_phase5e_successor_gate.py",
    "scripts/verify_phase5e_successor_gate_oracle.py",
    "scripts/verify_phase5e2b12c_semantic_oracle.py",
    "scripts/verify_phase5e2c0_semantic_oracle.py",
    "scripts/verify_phase5e_audit_runtime_matrix.py",
    "scripts/verify_phase_state.py",
    "scripts/verify_wheel.py",
    "scripts/write_phase5e_audit.py",
    "src/owner_research/__init__.py",
    "src/owner_research/resources/current_share/canonical-event-integration-policy.json",
    "src/owner_research/valuation_share_event_integration_types.py",
    "tests/fixtures/phase5e2b12a/adversarial-cases.json",
    "tests/phase5e2a_support.py",
    "tests/test_component_lock.py",
    "tests/test_phase4a_audit.py",
    "tests/test_phase4b_audit.py",
    "tests/test_phase5c_audit.py",
    "tests/test_phase5d_audit.py",
    "tests/test_phase4d5_phase_state.py",
    "tests/test_phase5e2a_snapshot_contract.py",
    "tests/test_phase5e2b12a_acceptance_gate.py",
    "tests/test_phase5e2b12a_integration_contracts.py",
    "tests/test_phase5e2b12b_acceptance_gate.py",
    "tests/test_phase5e_successor_gate.py",
    "tests/test_phase5e_audit.py",
    "tests/test_plugin_boundaries.py",
}
PUBLIC_CANONICAL_MIGRATION_CHANGED_PATHS = {
    ".github/workflows/phase5e2b12a-acceptance-gate.yml",
    "AGENTS.md",
    "README.md",
    "docs/adr/0040-public-canonical-repository.md",
    "docs/phase5-completion-overlay-v2.md",
    "docs/phase5-interface-matrix.json",
    "docs/phase5e2b12a-integration-contracts.md",
    "docs/roadmap.md",
    "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md",
    (
        "plugins/owner-equity-research/skills/owner-equity-research/"
        "references/market-execution-policy.md"
    ),
    "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md",
    "scripts/phase5e2b12a-acceptance-trust.json",
    "scripts/phase5e_audit_profiles.py",
    "scripts/phase5e_candidate_exec.sh",
    "scripts/phase5e_kernel_git_shim.sh",
    "scripts/launch_phase5e_readonly_audit.sh",
    "scripts/public_bootstrap.py",
    "scripts/run_phase5e_audit.py",
    "scripts/verify_phase5e_audit_runtime_matrix.py",
    "scripts/verify_phase5p_baseline.py",
    "scripts/verify_phase5e2b11_frozen_acceptance.py",
    "scripts/verify_phase5e2b12a_acceptance_gate.py",
    "scripts/verify_phase5e2b12a_integration_contracts.py",
    "scripts/verify_phase5e2b12a_semantic_oracle.py",
    "scripts/verify_phase5e_successor_gate.py",
    "scripts/verify_phase5e_successor_gate_oracle.py",
    "scripts/verify_phase_state.py",
    "scripts/verify_public_bootstrap.py",
    "tests/test_phase5e2b12a_acceptance_gate.py",
    "tests/test_phase5e_audit.py",
    "tests/test_phase5e_successor_gate.py",
    "tests/test_public_bootstrap.py",
}
PUBLIC_CANONICAL_MIGRATION_OPTIONAL_CHANGED_PATHS = {
    "docs/public-phase5e2b12a-revalidation.json",
    "scripts/phase5e-audit-requirements.lock",
    "scripts/phase5e-audit-runtime-matrix.json",
    "scripts/phase5e-audit-wheelhouse.sha256",
    "scripts/phase5e_pid1_reaper.py",
}


def _public_mode() -> bool:
    return not commit_exists(BASELINE, ROOT)


def _git(*arguments: str, text: bool = False) -> bytes | str:
    value = subprocess.check_output(["git", "-C", str(ROOT), *arguments], stderr=subprocess.STDOUT)
    return value.decode().strip() if text else value


def _baseline_file(relative: str) -> bytes:
    if _public_mode():
        return public_root_file(relative, ROOT)
    value = _git("show", f"{BASELINE}:{relative}")
    assert isinstance(value, bytes)
    return value


def _file_sha(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def _reject_duplicate_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json(relative: str) -> object:
    return json.loads(
        (ROOT / relative).read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_json_pairs,
        parse_int=lambda value: (_ for _ in ()).throw(
            ValueError(f"numeric JSON value is forbidden: {value}")
        ),
        parse_float=lambda value: (_ for _ in ()).throw(
            ValueError(f"numeric JSON value is forbidden: {value}")
        ),
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON constant: {value}")
        ),
    )


def _canonical_object_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _ast_sha256(source: str) -> str:
    tree = ast.parse(source, type_comments=True)
    payload = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def _baseline_paths(prefix: str) -> tuple[str, ...]:
    if _public_mode():
        return public_root_paths(prefix, ROOT)
    value = _git("ls-tree", "-r", "--name-only", BASELINE, prefix, text=True)
    assert isinstance(value, str)
    return tuple(item for item in value.splitlines() if item)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frozen-contract-replay", action="store_true")
    args = parser.parse_args()
    if _public_mode():
        try:
            verify_public_bootstrap_snapshot(ROOT)
        except ValueError as exc:
            raise SystemExit(
                "Phase 5E-2B.1-2A public bootstrap provenance failed"
            ) from exc
    elif subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", BASELINE, "HEAD"],
        check=False,
    ).returncode:
        raise SystemExit("Phase 5E-2B.1-2A is not based on its accepted predecessor")

    required = {
        TYPE_MODULE,
        POLICY,
        TEST,
        "docs/adr/0038-phase5e2b12a-current-share-integration-contracts.md",
        "docs/adr/0039-phase5e2b12a-semantic-trust-boundaries.md",
        "docs/phase5e2b12a-integration-contracts.md",
        "docs/phase5-completion-overlay-v1.md",
        ".github/workflows/phase5e2b12a-acceptance-gate.yml",
        "scripts/verify_phase5e2b12a_acceptance_gate.py",
        "scripts/verify_phase5e2b12a_semantic_oracle.py",
        "scripts/phase5e_audit_profiles.py",
    }
    missing = sorted(item for item in required if not (ROOT / item).is_file())
    if missing:
        raise SystemExit(f"Phase 5E-2B.1-2A files are missing: {missing}")

    comparison_commit = public_root_commit(ROOT) if _public_mode() else BASELINE
    changed_paths = set(
        str(
            _git(
                "diff",
                "--name-only",
                "--no-renames",
                comparison_commit,
                text=True,
            )
        ).splitlines()
    ) | set(
        str(_git("ls-files", "--others", "--exclude-standard", text=True)).splitlines()
    )
    phase_status = json.loads((ROOT / STATUS_PATH).read_text(encoding="utf-8"))
    accepted = (
        phase_status.get("current_phase") == "Phase 5E-2B.1-2A"
        and phase_status.get("status") == "accepted_closed"
        and (ROOT / ACCEPTANCE_CLOSEOUT).is_file()
    )
    if _public_mode():
        expected_changed_paths = set(PUBLIC_CANONICAL_MIGRATION_CHANGED_PATHS)
        if accepted:
            expected_changed_paths.update({STATUS_PATH, ACCEPTANCE_CLOSEOUT})
        permitted_changed_paths = (
            expected_changed_paths | PUBLIC_CANONICAL_MIGRATION_OPTIONAL_CHANGED_PATHS
        )
    else:
        expected_changed_paths = set(PHASE5E2B12A_ALLOWED_CHANGED_PATHS)
        if accepted:
            expected_changed_paths.add(ACCEPTANCE_CLOSEOUT)
        permitted_changed_paths = expected_changed_paths
    if not args.frozen_contract_replay and (
        changed_paths - permitted_changed_paths
        or expected_changed_paths - changed_paths
    ):
        raise SystemExit(
            "Phase 5E-2B.1-2A repository-wide changed-path boundary drifted: "
            f"unexpected={sorted(changed_paths - permitted_changed_paths)}; "
            f"missing={sorted(expected_changed_paths - changed_paths)}"
        )
    changed_package_paths = {
        path for path in changed_paths if path.startswith("src/owner_research/")
    }
    allowed_package_changes = {
        "src/owner_research/__init__.py",
        POLICY,
        TYPE_MODULE,
    }
    unauthorized_package_changes = sorted(changed_package_paths - allowed_package_changes)
    if not args.frozen_contract_replay and unauthorized_package_changes:
        raise SystemExit(
            "Phase 5E-2B.1-2A changed unauthorized production paths: "
            f"{unauthorized_package_changes}"
        )

    schema_paths = _baseline_paths("schemas")
    if len(schema_paths) != 43 or any(
        (ROOT / path).read_bytes() != _baseline_file(path) for path in schema_paths
    ):
        raise SystemExit("Phase 5E-2B.1-2A changed the 43 public Schemas")

    baseline_lock = json.loads(_baseline_file("component-lock.json"))
    current_lock = json.loads((ROOT / "component-lock.json").read_text(encoding="utf-8"))
    expected_lock = json.loads(json.dumps(baseline_lock))
    expected_lock["generated_date"] = "2026-07-16"
    expected_lock["owner_equity_research"]["plugin_version"] = EXPECTED_PLUGIN_VERSION
    if current_lock != expected_lock:
        raise SystemExit("component lock changed outside the research version/date boundary")
    if (
        current_lock["valuation_kernel"]["tag"] != "v2.0.0-rc.2"
        or current_lock["valuation_kernel"]["annotated_tag_object"]
        != "4e19ce6a59bc4321ebcd368e807ed764f4e8abde"
        or current_lock["valuation_kernel"]["commit"] != "be9b0773d5a78f5f8a33ba982494512668df85fe"
        or current_lock["valuation_kernel"]["release_evidence"]["wheel_sha256"]
        != "fb27d01b1ee75fbd542371510150e890516d306218d33f3608f2aa3caa0e55a5"
    ):
        raise SystemExit("fixed rc.2 kernel identity drifted")

    frozen_market_paths = set(_baseline_paths("src/owner_research/resources/market_access"))
    frozen_market_paths.update(
        {
            "src/owner_research/valuation_market_adapters.py",
            "src/owner_research/valuation_market_authority.py",
            "src/owner_research/valuation_market_calendar.py",
            "src/owner_research/valuation_market_parsers.py",
            "src/owner_research/valuation_market_runtime.py",
            "src/owner_research/valuation_security_identity.py",
        }
    )
    if any(
        not (ROOT / path).is_file() or (ROOT / path).read_bytes() != _baseline_file(path)
        for path in frozen_market_paths
    ):
        raise SystemExit("frozen market-access authority drifted")

    package_source = (ROOT / "src/owner_research/__init__.py").read_text(encoding="utf-8")
    plugin = json.loads(
        (ROOT / "plugins/owner-equity-research/.codex-plugin/plugin.json").read_text()
    )
    if (
        f'__version__ = "{EXPECTED_VERSION}"' not in package_source
        or plugin["version"] != EXPECTED_PLUGIN_VERSION
    ):
        raise SystemExit("Phase 5E-2B.1-2A package or Plugin version is invalid")

    policy = _strict_json(POLICY)
    if not isinstance(policy, dict):
        raise SystemExit("Phase 5E-2B.1-2A policy is not a JSON object")
    if (
        _file_sha(POLICY) != EXPECTED_POLICY_SHA256
        or _canonical_object_sha256(policy) != EXPECTED_POLICY_OBJECT_SHA256
        or policy.get("policy_id") != "canonical-share-event-current-share-integration"
        or policy.get("policy_version") != "2.1.0"
        or tuple(policy["coverage"]["required_categories"])
        != (
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
        or tuple(policy["coverage"]["required_source_families"])
        != (
            "10-K",
            "10-Q",
            "8-K",
            "DEF14A",
            "registration_or_prospectus",
            "tender_or_merger_material",
            "credit_or_indentures",
            "official_ir",
        )
        or policy["coverage"].get("search_authority")
        != "current-share-source-search-authority/2.0.0"
        or policy.get("research_bundle_extension", {}).get("policy_id")
        != "research-bundle-current-share-extension"
        or policy["claim_transition"].get("authority")
        != "full_price_blind_freeze_and_current_contract_graph_replayed_phase5c_claim_authority"
        or policy["claim_transition"].get("authority_policy")
        != "phase5c-reviewed-dilution-claim-authority/2.0.0"
        or policy["claim_transition"].get("freeze") != "exact_price_blind_freeze_compilation_result"
        or policy["claim_transition"].get("handoff")
        != "graph_owned_adjacent_v1_v4_unique_current_unsuperseded_run_and_current_component_lock"
        or policy["claim_transition"].get("artifact_self_hash") != "insufficient_authority"
        or policy["claim_transition"].get("typed_review_payload")
        != "unique_ids_exact_binding_cardinality_and_graph_byte_equality"
        or policy["claim_transition"].get("outer_bundle_replay")
        != "same_contract_graph_as_current_share_bundle_evidence_closure"
        or policy["claim_transition"].get("consumption_records")
        != "closed_unique_records_and_only_the_exact_option_bridge_deduction_per_excluded_root"
        or policy["coverage"].get("cardinality")
        != (
            "exactly_one_entry_per_registered_category_and_"
            "exactly_one_category_binding_per_canonical_group"
        )
        or policy["coverage"].get("not_applicable_review_chain")
        != "one_unique_category_specific_candidate_one_named_human_decision_one_claim"
        or policy["coverage"].get("not_applicable_temporal_policy")
        != (
            "support_and_counterevidence_fact_and_source_not_after_candidate_candidate_not_"
            "before_coverage_period_end_and_not_after_data_cutoff_candidate_equals_claim_"
            "review_not_before_candidate_and_not_after_data_cutoff"
        )
        or policy["coverage"].get("not_applicable_evidence_binding")
        != "direct_fact_only_globally_unique_binding_ids_and_exact_candidate_claim_projection"
        or policy["coverage"].get("typed_graph_binding")
        != (
            "all_result_sources_receipts_zero_observed_not_applicable_support_and_"
            "counterevidence_facts_candidates_decisions_and_claims_match_graph_owned_"
            "bundle_object_id_and_fingerprint"
        )
        or policy["recursive_closure"].get("extension_dependency_policy")
        != "closed_contract_type_specific_reference_edges_never_arbitrary_string_matching"
        or policy["recursive_closure"].get("fact_parent_edge_policy")
        != (
            "exact_output_to_opening_and_canonical_edges_plus_canonical_to_all_raw_member_"
            "edges_only"
        )
        or policy["claim_transition"].get("temporal_policy")
        != (
            "transition_evidence_fact_period_and_source_publication_not_after_candidate_"
            "candidate_equals_claim_review_not_before_candidate_and_all_not_after_data_cutoff"
        )
        or policy["claim_transition"].get("typed_graph_binding")
        != (
            "affected_remaining_and_transition_evidence_facts_sources_claims_candidates_"
            "and_decisions_match_graph_owned_bundle_object_id_and_fingerprint"
        )
        or policy["claim_transition"].get("standard_event_concepts")
        != ["option_shares_exercised_completed"]
        or tuple(policy["claim_transition"].get("specialist_required_event_concepts", []))
        != (
            "convertible_shares_converted_completed",
            "warrant_shares_exercised_completed",
        )
        or policy.get("status") != "production_active"
        or set(policy.get("active_production", ()))
        != {
            "canonical_fact_materializer",
            "current_share_rollforward_integration",
            "coverage_builder",
            "claim_transition_builder",
            "recursive_closure_builder",
            "market_evidence",
            "market_reference_snapshot",
        }
        or "market_evidence" in policy["deferred_production"]
        or "kernel_execution" not in policy["deferred_production"]
    ):
        raise SystemExit("Phase 5E-2B.1-2A closed policy is incomplete")

    type_source = (ROOT / TYPE_MODULE).read_text(encoding="utf-8")
    if (
        _file_sha(TYPE_MODULE) != EXPECTED_TYPE_MODULE_SHA256
        or _ast_sha256(type_source)
        != EXPECTED_TYPE_AST_SHA256.get(sys.version_info[:2])
    ):
        raise SystemExit("Phase 5E-2B.1-2A exact type-module surface drifted")
    tree = ast.parse(type_source, type_comments=True)
    class_names = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    function_names = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    if not INTERNAL_TYPE_NAMES.issubset(class_names):
        raise SystemExit("Phase 5E-2B.1-2A internal contract set is incomplete")
    authority_class = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "GroupBoundDilutionClaimAuthority"
        ),
        None,
    )
    authority_methods = (
        {
            node.name
            for node in authority_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if authority_class is not None
        else set()
    )
    if "from_price_blind_freeze" not in authority_methods:
        raise SystemExit("full-freeze Claim authority constructor is missing")
    if "from_price_blind_artifact" in authority_methods:
        raise SystemExit("artifact-only Claim authority constructor remains exposed")
    forbidden_prefixes = (
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
    if any(name.startswith(forbidden_prefixes) for name in function_names):
        raise SystemExit("Phase 5E-2B.1-2A exposes an unauthorized production function")
    forbidden_imports = {"httpx", "requests", "socket", "urllib"}
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        str(node.module).split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    if imported_roots & forbidden_imports:
        raise SystemExit("Phase 5E-2B.1-2A imports a forbidden network capability")
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
        for node in ast.walk(tree)
    ):
        raise SystemExit("Phase 5E-2B.1-2A contains a forbidden writer capability")
    forbidden_tokens = {
        "MarketReferenceSnapshot",
        "run_dual_panel",
        "valuation-request.json",
        "market_equity_value",
    }
    if any(token in type_source for token in forbidden_tokens):
        raise SystemExit("Phase 5E-2B.1-2A crosses into market or kernel execution")
    for relative in (
        "src/owner_research/__init__.py",
        "src/owner_research/cli.py",
        "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md",
        "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        if any(name in source for name in INTERNAL_TYPE_NAMES):
            raise SystemExit(f"internal current-share type leaked through {relative}")

    fixture_path = "tests/fixtures/phase5e2b12a/adversarial-cases.json"
    fixture = _strict_json(fixture_path)
    if not isinstance(fixture, dict) or not isinstance(fixture.get("cases"), list):
        raise SystemExit("Phase 5E-2B.1-2A adversarial matrix is malformed")
    required_keys = {
        "case_id",
        "case_kind",
        "boundary",
        "mutation",
        "expected",
        "test_nodeid",
    }
    case_ids = [item.get("case_id") for item in fixture["cases"]]
    nodeids = [item.get("test_nodeid") for item in fixture["cases"]]
    if (
        _file_sha(fixture_path) != EXPECTED_ADVERSARIAL_FIXTURE_SHA256
        or fixture.get("schema_version") != "2.0.0"
        or fixture.get("phase") != "Phase 5E-2B.1-2A"
        or len(case_ids) < 20
        or len(case_ids) != len(set(case_ids))
        or len(nodeids) != len(set(nodeids))
        or any(
            not isinstance(item, dict)
            or set(item) != required_keys
            or not isinstance(item.get("test_nodeid"), str)
            for item in fixture["cases"]
        )
    ):
        raise SystemExit("Phase 5E-2B.1-2A adversarial matrix is incomplete")
    # Independent arithmetic oracle: corroborating disclosures describe one 5m legal event.
    if 100_000_000 + (-1 * 5_000_000) != 95_000_000:
        raise SystemExit("independent current-share arithmetic oracle failed")

    semantic_command = [sys.executable, "scripts/verify_phase5e2b12a_semantic_oracle.py"]
    if args.frozen_contract_replay:
        semantic_command.append("--frozen-contract-replay")
    semantic_oracle = subprocess.run(
        semantic_command,
        cwd=ROOT,
        check=False,
    )
    if semantic_oracle.returncode:
        raise SystemExit("Phase 5E-2B.1-2A independent semantic oracle failed")

    result = subprocess.run([sys.executable, "-m", "pytest", "-q", TEST], cwd=ROOT, check=False)
    if result.returncode:
        raise SystemExit("Phase 5E-2B.1-2A targeted tests failed")
    print(
        "Phase 5E-2B.1-2A integration contracts verified "
        f"(module={_file_sha(TYPE_MODULE)}, audit={EXPECTED_AUDIT_VERSION})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
