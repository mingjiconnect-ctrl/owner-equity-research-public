#!/usr/bin/env python3
"""Verify frozen Phase 5C policies and authorized 5C-1 through 5C-5 compilers."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import fields
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERNEL_COMMIT = "a7dd1528c34f09702686b32ffbb8a397439665f0"
KERNEL_TAG = "v2.0.0-rc.1"
FACT_LEDGER_SHA256 = "55be5aadad21629db1cdbe7fce386656eb930b52af8644d1314ba7404e384706"
PHASE5B_BASELINE_COMMIT = "17afbdc9464af2310f2bf5be72df87f3da9fbbc2"
ALLOWED_PHASE5C_SOURCE_CHANGES = {
    ("M", "src/owner_research/__init__.py"),
    ("A", "src/owner_research/valuation_accounting_policies.py"),
    ("A", "src/owner_research/valuation_accounting_quality.py"),
    ("A", "src/owner_research/valuation_accounting_reconciliation.py"),
    ("A", "src/owner_research/valuation_method_views.py"),
    ("A", "src/owner_research/valuation_equity_bridge.py"),
    ("A", "src/owner_research/valuation_phase5c_readiness.py"),
    ("A", "src/owner_research/valuation_accounting_types.py"),
}
FORBIDDEN_ROOT_NAMES = {
    "AccountClassificationDecision",
    "AccountingReconciliationResult",
    "AccountingQualityCompilationResult",
    "MethodViewCompilationResult",
    "EquityBridgeCompilationResult",
    "Phase5CReadinessResult",
    "assess_phase5c_readiness",
    "build_valuation_request",
    "compile_accounting_reformulation",
    "compile_accounting_quality_adjustments",
    "compile_equity_bridge",
    "compile_method_views",
    "fetch_market_reference",
    "run_valuation_kernel",
    "write_valuation_artifacts",
}
FORBIDDEN_SOURCE_TOKENS = (
    "AssumptionLedger",
    "MarketReferenceSnapshot",
    "build_valuation_request",
    "fetch_market_reference",
    "run_dual_panel",
    "run_equity_bridge",
    "run_valuation_kernel",
    "valuation-result.json",
    "valuation-request.json",
    "write_valuation_artifacts",
)


def _definitions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        item.name
        for item in ast.walk(tree)
        if isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args],
        text=True,
        stderr=subprocess.STDOUT,
    ).strip()


def _parse_name_status(value: str) -> set[tuple[str, str]]:
    rows: set[tuple[str, str]] = set()
    for raw_line in value.splitlines():
        if not raw_line.strip():
            continue
        parts = raw_line.split("\t")
        if len(parts) != 2 or parts[0] not in {"A", "M", "D", "T", "U", "X", "B"}:
            raise ValueError("Phase 5C source diff contains an unsupported status row")
        rows.add((parts[0], parts[1]))
    return rows


def _validate_source_change_set(rows: set[tuple[str, str]]) -> None:
    if rows != ALLOWED_PHASE5C_SOURCE_CHANGES:
        raise ValueError("Phase 5C source changes exceed the authorized compiler boundary")


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for item in ast.walk(tree):
        if isinstance(item, ast.Import):
            modules.update(alias.name for alias in item.names)
        elif isinstance(item, ast.ImportFrom) and item.module:
            modules.add(item.module)
    return modules


def _embedded_kernel_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for item in ast.walk(tree):
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            continue
        if "owner_valuation" not in item.value:
            continue
        embedded = ast.parse(item.value)
        for node in ast.walk(embedded):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module == "owner_valuation" or node.module.startswith(
                    "owner_valuation."
                ):
                    imports.update(f"{node.module}.{alias.name}" for alias in node.names)
            elif isinstance(node, ast.Import):
                imports.update(
                    alias.name
                    for alias in node.names
                    if alias.name == "owner_valuation"
                    or alias.name.startswith("owner_valuation.")
                )
    return imports


def _expected_phase5c_init(baseline_text: str) -> str:
    marker = '__version__ = "0.5.0.dev2"'
    if baseline_text.count(marker) != 1:
        raise ValueError("Phase 5B package version marker is not uniquely reproducible")
    return baseline_text.replace(marker, '__version__ = "0.5.0.dev3"')


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research
    from owner_research.schema_store import SCHEMA_NAMES
    from owner_research.valuation_accounting_policies import (
        ACCOUNT_CONCEPT_POLICIES,
        BRIDGE_ROLE_POLICIES,
        BRIDGE_ROLES,
        CROSS_CHANNEL_POLICIES,
        FORMULA_POLICIES,
        FORMULA_TERM_INCLUSION_STATUSES,
        KERNEL_FORBIDDEN_SURFACES,
        KERNEL_METHOD_VIEW_TARGET_ALLOWLIST,
        KERNEL_VALIDATION_ALLOWLIST,
        METHOD_ADJUSTMENT_CALCULATOR_POLICY,
        METHOD_SUCCESSOR_REQUIRED_ROLES,
        METHOD_TARGET_POLICIES,
        OWNER_TRANSACTION_POLICIES,
        PERIOD_ALIGNMENT_POLICIES,
        PHASE5C_POLICY_ID,
        PHASE5C_POLICY_VERSION,
        PHASE5C_REASON_CODES,
        QUALITY_MAPPING_POLICIES,
        phase5c_policy_sha256,
    )
    from owner_research.valuation_accounting_types import (
        AccountingQualityCompilationResult,
        Phase5CReadinessResult,
    )

    if len(SCHEMA_NAMES) != 43:
        raise SystemExit("Phase 5C must keep exactly 43 public research Schemas")
    if owner_research.__version__ != "0.5.0.dev3":
        raise SystemExit("Python package version is not 0.5.0.dev3")
    if any(hasattr(owner_research, name) for name in FORBIDDEN_ROOT_NAMES):
        raise SystemExit("Phase 5C exposed an internal or later-phase package-root API")
    if (PHASE5C_POLICY_ID, PHASE5C_POLICY_VERSION) != (
        "phase5c-accounting-equity-bridge",
        "1.0.0",
    ) or len(phase5c_policy_sha256()) != 64:
        raise SystemExit("Phase 5C policy identity or fingerprint is invalid")
    if len(BRIDGE_ROLES) != 9 or len(set(BRIDGE_ROLES)) != 9:
        raise SystemExit("Phase 5C equity-bridge registry is not exactly nine roles")
    if "total_liabilities" not in ACCOUNT_CONCEPT_POLICIES or (
        "reported_liabilities" in ACCOUNT_CONCEPT_POLICIES
    ):
        raise SystemExit("Phase 5C does not consume the exact Phase 5B liability concept")
    if ACCOUNT_CONCEPT_POLICIES["total_equity"].account_role != "unresolved":
        raise SystemExit("reported total equity was prematurely classified as common equity")
    if (
        "adjusted_total_liabilities" not in ACCOUNT_CONCEPT_POLICIES
        or FORMULA_POLICIES["adjusted_total_liabilities"].output_concept
        != "adjusted_total_liabilities"
    ):
        raise SystemExit("adjusted-liability formula output is not a distinct registered concept")
    clean_surplus = PERIOD_ALIGNMENT_POLICIES["clean_surplus"]
    if clean_surplus.same_measurement_end or clean_surplus.date_relationship != (
        "beginning_plus_one_day_equals_flow_start_and_ending_equals_flow_end"
    ):
        raise SystemExit("clean-surplus stock/flow date policy is invalid")
    if len(OWNER_TRANSACTION_POLICIES) != 6:
        raise SystemExit("owner-distribution component coverage is incomplete")
    expected_formula_inclusion = {
        "not_required",
        "included_in_total_equity",
        "outside_reported_liabilities",
        "not_in_reported_liabilities",
        "none_identified_after_review",
        "unresolved",
    }
    if set(FORMULA_TERM_INCLUSION_STATUSES) != expected_formula_inclusion:
        raise SystemExit("formula-term inclusion-proof states are not closed")
    if (
        FORMULA_POLICIES["common_equity"].terms[1].required_inclusion_status
        != "included_in_total_equity"
        or FORMULA_POLICIES["adjusted_total_liabilities"].terms[
            1
        ].required_inclusion_status
        != "outside_reported_liabilities"
        or FORMULA_POLICIES["net_financial_obligations"].terms[
            1
        ].required_inclusion_status
        != "not_in_reported_liabilities"
    ):
        raise SystemExit("non-common formula terms lack explicit inclusion semantics")
    calculator = METHOD_ADJUSTMENT_CALCULATOR_POLICY
    if (
        calculator.operation != "signed_sum"
        or not calculator.requires_reporting_currency_millions
        or not calculator.requires_same_period
        or not calculator.requires_single_source
        or not calculator.requires_zero_assumptions
        or len(calculator.calculator_code_sha256) != 64
    ):
        raise SystemExit("method-adjustment calculator policy is not deterministic and closed")
    if (
        QUALITY_MAPPING_POLICIES["watch"].resolved is not False
        or QUALITY_MAPPING_POLICIES["informational"].resolved is not False
        or QUALITY_MAPPING_POLICIES["cleared"].material_source != "reviewed_final_severity"
    ):
        raise SystemExit("accounting-quality resolution semantics drifted")
    if set(METHOD_SUCCESSOR_REQUIRED_ROLES) != {"mckinsey", "penman"}:
        raise SystemExit("successor readiness method-role registry is incomplete")
    if (
        METHOD_TARGET_POLICIES["mckinsey"].allowed_concepts != ("invested_capital",)
        or METHOD_TARGET_POLICIES["mckinsey"].allows_modeled_bridge_facts
        or METHOD_TARGET_POLICIES["mckinsey"].allowed_bridge_roles
        or KERNEL_METHOD_VIEW_TARGET_ALLOWLIST["mckinsey"]
        != ("invested_capital", *BRIDGE_ROLES)
        or KERNEL_METHOD_VIEW_TARGET_ALLOWLIST["penman"]
        != ("net_financial_obligations", "net_operating_assets")
    ):
        raise SystemExit("MethodView base and later bridge target boundaries drifted")
    required_quality_fields = {
        "kernel_gate_scope",
        "kernel_route_effect_by_method",
        "kernel_execution_compatibility_by_method",
        "kernel_incompatibility_reason_codes",
    }
    if not required_quality_fields.issubset(
        {item.name for item in fields(AccountingQualityCompilationResult)}
    ) or not {
        "pinned_kernel_global_gate_overblocks_penman",
        "pinned_kernel_quality_gate_underblocks_mckinsey",
    }.issubset(PHASE5C_REASON_CODES):
        raise SystemExit("pinned-kernel accounting-quality incompatibility is not explicit")
    required_stable_capital_fields = {
        "stable_capital_footnote_review",
        "stable_capital_allocation_review",
        "stable_capital_claim",
        "stable_capital_claim_candidate",
        "stable_capital_claim_review_decision",
    }
    if not required_stable_capital_fields.issubset(
        {item.name for item in fields(Phase5CReadinessResult)}
    ):
        raise SystemExit("stable-capital readiness lacks typed evidence bindings")
    for role in BRIDGE_ROLES:
        cross_policy = CROSS_CHANNEL_POLICIES[role]
        bridge_policy = BRIDGE_ROLE_POLICIES[role]
        if (
            not cross_policy.permits_cross_method_base_sharing
            or cross_policy.consumption_limit_scope != "per_method"
            or not bridge_policy.requires_diluted_share_root_separation
        ):
            raise SystemExit("bridge root-conservation policy is inconsistent")

    plugin = json.loads(
        (ROOT / "plugins/owner-equity-research/.codex-plugin/plugin.json").read_text()
    )
    lock = json.loads((ROOT / "component-lock.json").read_text())
    if plugin["version"] != "0.5.0-dev.3":
        raise SystemExit("Plugin version is not 0.5.0-dev.3")
    if lock["owner_equity_research"]["plugin_version"] != "0.5.0-dev.3":
        raise SystemExit("component lock version is not 0.5.0-dev.3")
    if len(lock["owner_equity_research"]["public_schema_sha256"]) != 43:
        raise SystemExit("component lock does not contain 43 research Schema hashes")
    if lock["valuation_kernel"]["commit"] != KERNEL_COMMIT:
        raise SystemExit("valuation-kernel commit drifted")

    fixture = json.loads(
        (ROOT / "tests/fixtures/phase5c/adversarial-cases.json").read_text(encoding="utf-8")
    )
    matrix = json.loads(
        (ROOT / "docs/phase5c-failure-mode-matrix.json").read_text(encoding="utf-8")
    )
    required_adversarial_cases = {
        "aggregate_component_double_count",
        "audit_control_hash_omitted",
        "blocked_economic_claim_binding_marked_pass",
        "blocked_role_contaminates_confirmed_sibling",
        "bridge_not_applicable_ghost_review",
        "duplicate_economic_claim_key",
        "late_bridge_raw_evidence",
        "economic_claim_alias_across_fact_ids",
        "economic_claim_semantic_drift",
        "included_option_retained_in_penman_nfo",
        "invalid_52_53_week_chain_accepted",
        "market_reference_in_phase5c_graph",
        "phase5b_graph_fact_tamper",
        "phase5b_derived_fact_semantic_tamper",
        "phase5b_mapping_decision_set_tamper",
        "phase5b_readiness_semantic_tamper",
        "phase5c_source_tree_tamper",
        "pinned_kernel_quality_route_mismatch",
        "phase5c_acceptance_evidence_mismatch",
        "stable_capital_placeholder_evidence",
    }
    if len(fixture["cases"]) < 94 or not required_adversarial_cases.issubset(
        {item["case_id"] for item in fixture["cases"]}
    ):
        raise SystemExit("Phase 5C adversarial fixture is incomplete")
    if [item["case_id"] for item in fixture["cases"]] != [
        item["case_id"] for item in matrix["failure_modes"]
    ]:
        raise SystemExit("Phase 5C failure matrix and fixture differ")

    policy_paths = (
        ROOT / "src/owner_research/valuation_accounting_policies.py",
        ROOT / "src/owner_research/valuation_accounting_types.py",
    )
    reconciliation_path = ROOT / "src/owner_research/valuation_accounting_reconciliation.py"
    quality_path = ROOT / "src/owner_research/valuation_accounting_quality.py"
    method_view_path = ROOT / "src/owner_research/valuation_method_views.py"
    equity_bridge_path = ROOT / "src/owner_research/valuation_equity_bridge.py"
    readiness_path = ROOT / "src/owner_research/valuation_phase5c_readiness.py"
    try:
        source_changes = _parse_name_status(
            _git(
                ROOT,
                "diff",
                "--name-status",
                "--no-renames",
                PHASE5B_BASELINE_COMMIT,
                "--",
                "src/owner_research",
            )
        )
        _validate_source_change_set(source_changes)
        baseline_init = _git(
            ROOT,
            "show",
            f"{PHASE5B_BASELINE_COMMIT}:src/owner_research/__init__.py",
        )
        current_init = (ROOT / "src/owner_research/__init__.py").read_text(
            encoding="utf-8"
        ).rstrip("\n")
        if current_init != _expected_phase5c_init(baseline_init):
            raise ValueError(
                "Phase 5C package root differs from Phase 5B beyond the version bump"
            )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    for path in policy_paths:
        text = path.read_text(encoding="utf-8")
        if "owner_valuation" in text and path.name != "valuation_accounting_policies.py":
            raise SystemExit("Phase 5C-0 internal types import valuation-kernel code")
        if "import owner_valuation" in text or "from owner_valuation" in text or "httpx" in text:
            raise SystemExit("Phase 5C-0 policy boundary imports kernel or network code")
        if path.name == "valuation_accounting_types.py" and any(
            token in text for token in FORBIDDEN_SOURCE_TOKENS
        ):
            raise SystemExit(f"Phase 5C-0 contains a forbidden later-phase surface: {path.name}")
    definitions = set().union(*(_definitions(path) for path in policy_paths))
    early_api_prefixes = ("build_", "compile_", "fetch_", "run_", "write_")
    if any(name.startswith(early_api_prefixes) for name in definitions):
        raise SystemExit("Phase 5C-0 production compiler or writer was implemented early")
    compiler_boundaries = {
        reconciliation_path: (
            {"compile_accounting_reformulation"},
            {
                "owner_valuation.FactLedger",
                "owner_valuation.validation.validate_balance_sheet",
                "owner_valuation.validation.validate_clean_surplus",
            },
        ),
        quality_path: (
            {"compile_accounting_quality_adjustments"},
            {
                "owner_valuation.validation.AccountingQualityIssue",
                "owner_valuation.validation.accounting_quality_gate",
            },
        ),
        method_view_path: (
            {"compile_method_views"},
            {
                "owner_valuation.FactLedger",
                "owner_valuation.MethodAdjustment",
                "owner_valuation.MethodView",
                "owner_valuation.facts.AdjustmentCategory",
                "owner_valuation.facts.ViewName",
            },
        ),
        equity_bridge_path: (
            {"compile_equity_bridge"},
            {"owner_valuation.FactLedger"},
        ),
        readiness_path: (
            {"assess_phase5c_readiness"},
            set(),
        ),
    }
    for compiler_path, (expected_surfaces, expected_embedded_imports) in (
        compiler_boundaries.items()
    ):
        compiler_modules = _imported_modules(compiler_path)
        if any(
            module == "owner_valuation"
            or module.startswith("owner_valuation.")
            or module == "httpx"
            or module.startswith("httpx.")
            for module in compiler_modules
        ):
            raise SystemExit(
                "Phase 5C compiler directly imports valuation-kernel or network code"
            )
        compiler_definitions = _definitions(compiler_path)
        exposed_compiler_surfaces = {
            name
            for name in compiler_definitions
            if not name.startswith("_")
            and name.startswith(
                ("assess_", "build_", "compile_", "fetch_", "run_", "write_")
            )
        }
        if exposed_compiler_surfaces != expected_surfaces:
            raise SystemExit("Phase 5C production compiler surface drifted")
        if _embedded_kernel_imports(compiler_path) != expected_embedded_imports:
            raise SystemExit("Phase 5C embedded kernel compatibility interface drifted")
        compiler_text = compiler_path.read_text(encoding="utf-8")
        if any(token in compiler_text for token in FORBIDDEN_SOURCE_TOKENS):
            raise SystemExit("Phase 5C compiler contains a forbidden later-phase surface")

    kernel = Path(
        os.environ.get("OWNER_VALUATION_REPO", str(ROOT.parent / "owner-valuation-kernel"))
    ).resolve()
    if _git(kernel, "rev-parse", "HEAD") != KERNEL_COMMIT or _git(
        kernel, "rev-parse", f"{KERNEL_TAG}^{{}}"
    ) != KERNEL_COMMIT:
        raise SystemExit("fixed valuation-kernel checkout or tag drifted")
    schema = kernel / "schemas/fact-ledger.schema.json"
    if hashlib.sha256(schema.read_bytes()).hexdigest() != FACT_LEDGER_SHA256:
        raise SystemExit("pinned FactLedger Schema drifted")
    root_definitions = _definitions(kernel / "src/owner_valuation/facts.py")
    validation_definitions = _definitions(kernel / "src/owner_valuation/validation.py")
    required_fact_interfaces = {
        "FactLedger",
        "MethodAdjustment",
        "MethodView",
    }
    if not required_fact_interfaces.issubset(root_definitions):
        raise SystemExit("pinned kernel Fact/MethodView interface drifted")
    if not {
        "accounting_quality_gate",
        "validate_balance_sheet",
        "validate_clean_surplus",
    }.issubset(validation_definitions):
        raise SystemExit("pinned kernel validation interface drifted")
    expected_allowlist = {
        "owner_valuation.FactLedger",
        "owner_valuation.MethodAdjustment",
        "owner_valuation.MethodView",
        "owner_valuation.validation.accounting_quality_gate",
        "owner_valuation.validation.validate_balance_sheet",
        "owner_valuation.validation.validate_clean_surplus",
    }
    if set(KERNEL_VALIDATION_ALLOWLIST) != expected_allowlist:
        raise SystemExit("Phase 5C kernel validation allowlist drifted")
    if not {
        "owner_valuation.AssumptionLedger",
        "owner_valuation.run_dual_panel",
        "owner_valuation.run_equity_bridge",
    }.issubset(KERNEL_FORBIDDEN_SURFACES):
        raise SystemExit("Phase 5C forbidden kernel surfaces are incomplete")
    print("Phase 5C-5 deterministic successor-readiness boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
