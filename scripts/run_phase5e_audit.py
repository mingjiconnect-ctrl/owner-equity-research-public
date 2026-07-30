#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from phase5e_audit_profiles import (  # noqa: E402
    AUDIT_TOOL,
    PHASE5E2B12A_AUDIT_PROFILE,
    AuditProfile,
    audit_profile,
    audit_profile_context_sha256,
    audit_profile_policy_sha256,
    resolve_controller_audit_profile,
    resolve_controller_gate_position,
)
from public_bootstrap import (  # noqa: E402
    commit_exists,
    public_root_commit,
    verify_public_bootstrap_snapshot,
)
from verify_phase5e2b12a_integration_contracts import (  # noqa: E402
    PUBLIC_CANONICAL_MIGRATION_CHANGED_PATHS,
    PUBLIC_CANONICAL_MIGRATION_OPTIONAL_CHANGED_PATHS,
)

# Compatibility alias for the frozen 2A tests and trust snapshot.  Runtime selection is always
# derived from the protected controller profile below.
EXPECTED_AUDIT_CHECK_IDS = audit_profile(
    PHASE5E2B12A_AUDIT_PROFILE
).expected_check_ids
PHASE5D_BASELINE = "bdac6e4a23e821c73a2545167f478cfc0348316f"
PHASE5E0_BASELINE = "ac70357624c95f78b5567bc8eb8544c13fa375dd"
PHASE5E11_BASELINE = "640ce470cb986d356ec54fc6018f48b6ad02ae36"
PHASE5E2A_BASELINE = "d7197942f447a011590a503c69da065fdbdc07c0"
PHASE5E2B10_BASELINE = "3fbd39f9d16af467a73bff670600b692ff0f3756"
PHASE5E2B11_BASELINE = "4fd643df73108b1fa3ab3ce1eb258ae3c3ce8a6d"
KERNEL_BASELINE = "be9b0773d5a78f5f8a33ba982494512668df85fe"
_EXTERNAL_FEASIBILITY_PHASE = "Phase 5E-2C-P"
_EXTERNAL_CONTROLLER_DIFF = {
    "docs/phase-status.json": "M",
    "governance/phase5e-external/phase5e2cp-controller-handoff.json": "A",
    "governance/phase5e-gates/phase5e2c0/adversarial-cases.json": "A",
    "governance/phase5e-gates/phase5e2c0/bundle.json": "A",
    "governance/phase5e-gates/phase5e2c0/semantic-oracle.py.txt": "A",
}
CONTROL_ORACLE_FIXED_PATHS = frozenset(
    {
        "component-lock.json",
        "docs/phase5-completion-overlay-v3.md",
        "scripts/phase5e-successor-gate-bundle.schema.json",
        "scripts/phase5e-futu-market-authority-policy-v1.json",
        "scripts/phase5e2b12a-acceptance-trust.json",
        "scripts/phase5e2b12b-acceptance-trust.json",
        "scripts/phase5e_audit_profiles.py",
        "scripts/phase5e_kernel_git_shim.sh",
        "scripts/phase5e_pid1_reaper.py",
        "scripts/public_bootstrap.py",
        "scripts/verify_phase5e2b12a_semantic_oracle.py",
        "scripts/verify_phase5e2b12b_semantic_oracle.py",
        "scripts/verify_phase5e2b12c_semantic_oracle.py",
        "scripts/verify_phase5e2c0_semantic_oracle.py",
        "scripts/verify_phase5e_successor_gate.py",
        "scripts/verify_phase5e_successor_gate_oracle.py",
    }
)
EXPECTED_PHASE5E2B12A_TEST_COUNT = 1374
EXPECTED_PHASE5E2B12A_NODEID_SHA256 = (
    "eab85a4981f3fdcfe841c5e730af10f3e2b50ce41c617f3f9204b17a7ba4a79b"
)
_PROFILE_RESOLUTION_FAILURE_CHECK_ID = "phase5e-audit-profile-resolution"
_PROFILE_RESOLUTION_FAILURE_PROFILE = AuditProfile(
    profile_id="phase5e-audit-profile-resolution-failed",
    phase="Phase 5E audit profile resolution failure",
    audit_version="2.3.2-emergency.1",
    expected_check_ids=frozenset({_PROFILE_RESOLUTION_FAILURE_CHECK_ID}),
    semantic_oracle_path="scripts/run_phase5e_audit.py",
    expected_test_count=0,
    predecessor_test_count=0,
    predecessor_nodeid_sha256=hashlib.sha256(b"").hexdigest(),
    expected_added_test_nodeids=(),
    profile_kind="emergency_profile_resolution_failure",
)
_JUNIT_FAILURE_TAGS = frozenset({"failure", "error", "skipped"})
_NONNEGATIVE_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
PHASE5E2B12A_ACCEPTANCE_CLOSEOUT_PATH = "docs/phase5e2b12a-acceptance-closeout.json"
PHASE_STATUS_PATH = "docs/phase-status.json"
PHASE5E2B12A_OPTIONAL_CHANGED_PATHS = {
    "docs/public-phase5e2b12a-revalidation.json",
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
    "scripts/phase5e-successor-gate-bundle.schema.json",
    "scripts/phase5e_audit_profiles.py",
    "scripts/phase5e_candidate_exec.sh",
    "scripts/phase5e_kernel_git_shim.sh",
    "scripts/pytest_phase5e_nodeids.py",
    "scripts/phase5e2b12a-acceptance-trust.json",
    "scripts/phase5e2b12b-acceptance-trust.json",
    "scripts/phase5e-futu-market-authority-policy-v1.json",
    "scripts/verify_phase5e2b12a_acceptance_gate.py",
    "scripts/verify_all.py",
    "scripts/verify_phase5e2b11_frozen_acceptance.py",
    "scripts/verify_phase5e2b12a_integration_contracts.py",
    "scripts/verify_phase5e2b12a_semantic_oracle.py",
    "scripts/verify_phase5e_candidate_surface.py",
    "scripts/verify_phase5e_candidate_import_surface.py",
    "scripts/verify_phase5e_successor_gate.py",
    "scripts/verify_phase5e_successor_gate_oracle.py",
    "scripts/verify_phase5e2b12c_semantic_oracle.py",
    "scripts/verify_phase5e2c0_semantic_oracle.py",
    "scripts/verify_kernel_release_interface.py",
    "scripts/verify_phase5e2b12b_acceptance_gate.py",
    "scripts/verify_phase5e2b12b_semantic_oracle.py",
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
    "tests/test_phase5e_audit.py",
    "tests/test_phase5e_successor_gate.py",
    "tests/test_plugin_boundaries.py",
}
STATIC_CONTROL_FILES = {
    ".github/workflows/ci.yml",
    ".github/workflows/phase5e2b12a-acceptance-gate.yml",
    "AGENTS.md",
    "README.md",
    "component-lock.json",
    "docs/adr/0029-phase5e-market-execution-policy.md",
    "docs/adr/0030-phase5e11-market-authority-trust-root.md",
    "docs/adr/0031-phase5e2a-market-reference-snapshot-v2.md",
    "docs/adr/0032-phase5e2a1-dilution-authority-contract-parity.md",
    "docs/adr/0033-phase5e2a2-rc2-current-share-contract.md",
    "docs/adr/0034-phase5e2a21-recursive-current-share-evidence.md",
    "docs/adr/0035-phase5e2b-current-share-compiler.md",
    "docs/adr/0036-phase5e2b1-cross-source-share-event-identity.md",
    "docs/adr/0037-phase5e2b11-production-share-event-grouping.md",
    "docs/adr/0038-phase5e2b12a-current-share-integration-contracts.md",
    "docs/adr/0039-phase5e2b12a-semantic-trust-boundaries.md",
    "docs/adr/0040-public-canonical-repository.md",
    "docs/phase-status.json",
    "docs/phase5-acceptance.md",
    "docs/phase5-failure-mode-matrix.json",
    "docs/phase5-interface-matrix.json",
    "docs/phase5-methodology.md",
    "docs/phase5-plan.md",
    "docs/phase5-completion-overlay-v1.md",
    "docs/phase5-completion-overlay-v2.md",
    "docs/phase5-completion-overlay-v3.md",
    "docs/phase5e-acceptance-matrix.json",
    "docs/phase5e-failure-mode-matrix.json",
    "docs/phase5e-golden-matrix.json",
    "docs/phase5e-interface-matrix.json",
    "docs/phase5e0-market-execution-policy.md",
    "docs/phase5e2a-migration-manifest.json",
    "docs/phase5e2a-snapshot-contract.md",
    "docs/phase5e2a1-semantic-closeout.md",
    "docs/phase5e2a2-migration-manifest.json",
    "docs/phase5e2a21-implementation.md",
    "docs/phase5e2b-acceptance-closeout.md",
    "docs/phase5e2b-current-share-compilation.md",
    "docs/phase5e2b1-share-event-identity-policy.md",
    "docs/phase5e2b11-acceptance-closeout.md",
    "docs/phase5e2b11-production-grouping.md",
    "docs/phase5e2b12a-integration-contracts.md",
    "docs/public-bootstrap-provenance.json",
    "docs/roadmap.md",
    "plugins/owner-equity-research/.codex-plugin/plugin.json",
    "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md",
    "plugins/owner-equity-research/skills/owner-equity-research/references/market-execution-policy.md",
    "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md",
    "plugins/owner-equity-research/skills/owner-research-audit/agents/openai.yaml",
    "scripts/run_phase5e_audit.py",
    "scripts/build_kernel_release_interface.py",
    "scripts/launch_phase5e_readonly_audit.sh",
    "scripts/phase5e-audit-requirements.lock",
    "scripts/phase5e-audit-runtime-matrix.json",
    "scripts/phase5e-audit-wheelhouse.sha256",
    "scripts/phase5e-successor-gate-bundle.schema.json",
    "scripts/phase5e_audit_profiles.py",
    "scripts/phase5e_candidate_exec.sh",
    "scripts/phase5e_kernel_git_shim.sh",
    "scripts/pytest_phase5e_nodeids.py",
    "scripts/phase5e2b12a-acceptance-trust.json",
    "scripts/phase5e2b12b-acceptance-trust.json",
    "scripts/phase5e-futu-market-authority-policy-v1.json",
    "scripts/public_bootstrap.py",
    "scripts/verify_phase5e2b12a_acceptance_gate.py",
    "scripts/verify_phase5e2b12b_acceptance_gate.py",
    "scripts/verify_phase5e2b12b_semantic_oracle.py",
    "scripts/verify_public_bootstrap.py",
    "scripts/verify_phase5e_audit_runtime_matrix.py",
    "scripts/verify_phase5e_successor_gate.py",
    "scripts/verify_phase5e_successor_gate_oracle.py",
    "scripts/verify_phase5e2b12c_semantic_oracle.py",
    "scripts/verify_phase5e2c0_semantic_oracle.py",
    "scripts/verify_market_access_authority.py",
    "scripts/verify_kernel_release_interface.py",
    "scripts/verify_all.py",
    "scripts/verify_phase5d6_baseline.py",
    "scripts/verify_phase5e0_baseline.py",
    "scripts/verify_phase5e0_policies.py",
    "scripts/verify_phase5e1_market_access.py",
    "scripts/verify_phase5e2a_snapshot_contract.py",
    "scripts/verify_phase5e2a1_semantic_closeout.py",
    "scripts/verify_phase5e2a2_rc2_current_share.py",
    "scripts/verify_phase5e2a21_recursive_evidence.py",
    "scripts/verify_phase5e2b_current_share_compiler.py",
    "scripts/verify_phase5e2b_acceptance_closeout.py",
    "scripts/verify_phase5e2b1_cross_source_red.py",
    "scripts/verify_phase5e2b10_frozen.py",
    "scripts/verify_phase5e2b11_acceptance_closeout.py",
    "scripts/verify_phase5e2b11_frozen_acceptance.py",
    "scripts/verify_phase5e2b11_share_event_grouping.py",
    "scripts/verify_phase5e2b12a_integration_contracts.py",
    "scripts/verify_phase5e2b12a_semantic_oracle.py",
    "scripts/verify_phase5e_candidate_surface.py",
    "scripts/verify_phase5e_candidate_import_surface.py",
    "scripts/verify_phase_state.py",
    "scripts/write_phase5e_audit.py",
    "src/owner_research/valuation_market_execution_policies.py",
    "src/owner_research/valuation_market_execution_types.py",
    "src/owner_research/valuation_market_access.py",
    "src/owner_research/valuation_market_adapters.py",
    "src/owner_research/valuation_market_authority.py",
    "src/owner_research/valuation_market_authority_types.py",
    "src/owner_research/valuation_market_calendar.py",
    "src/owner_research/valuation_market_parsers.py",
    "src/owner_research/valuation_market_runtime.py",
    "src/owner_research/valuation_security_identity.py",
    "src/owner_research/valuation_market_reference_types.py",
    "src/owner_research/valuation_handoff_validation.py",
    "src/owner_research/valuation_current_share_evidence.py",
    "src/owner_research/valuation_current_share_compiler.py",
    "src/owner_research/valuation_share_event_identity.py",
    "src/owner_research/valuation_share_event_grouping.py",
    "src/owner_research/valuation_share_event_integration_types.py",
    "src/owner_research/resources/current_share/canonical-event-integration-policy.json",
    "schemas/market-reference-snapshot.schema.json",
    "src/owner_research/resources/market_access/calendar-registry.json",
    "src/owner_research/resources/market_access/calendar_sources/XNAS-2026.json",
    "src/owner_research/resources/market_access/calendar_sources/XNYS-2026.json",
    "src/owner_research/resources/market_access/calendars/XNAS-2026.json",
    "src/owner_research/resources/market_access/calendars/XNYS-2026.json",
    "src/owner_research/resources/market_access/provider-registry.json",
    "src/owner_research/resources/market_access/secret-policy.json",
    "src/owner_research/resources/market_access/security-identity-policy.json",
    "tests/fixtures/phase5e0/adversarial-cases.json",
    "tests/test_phase5e0_market_execution_policies.py",
    "tests/fixtures/phase5e1/recorded-quote.json",
    "tests/fixtures/phase5e1/trading-sessions.json",
    "tests/test_phase5e1_market_access.py",
    "tests/test_phase5e11_authority_red.py",
    "tests/test_phase5e11_market_calendar.py",
    "tests/test_phase5e11_raw_runtime.py",
    "tests/fixtures/phase5e2a/adversarial-cases.json",
    "tests/fixtures/phase5e2a/recorded-official-close.json",
    "tests/phase5e2a_support.py",
    "tests/test_phase5e2a_snapshot_contract.py",
    "tests/test_phase5e2a21_recursive_evidence.py",
    "tests/phase5e2b_support.py",
    "tests/test_phase5e2b_current_share_compiler.py",
    "tests/fixtures/phase5e2b1/adversarial-cases.json",
    "tests/test_phase5e2b1_share_event_identity_policy.py",
    "tests/test_phase5e2b11_share_event_grouping.py",
    "tests/fixtures/phase5e2b12a/adversarial-cases.json",
    "tests/test_phase5e2b12a_integration_contracts.py",
    "tests/test_phase5e2b12a_acceptance_gate.py",
    "tests/test_phase5e2b12b_acceptance_gate.py",
    "tests/test_phase5e_audit.py",
    "tests/test_phase5e_successor_gate.py",
}


def _strict_junit_tree(root: ET.Element) -> bool:
    def canonical_nonnegative_integer(value: object) -> bool:
        return (
            isinstance(value, str)
            and value.isascii()
            and value.isdigit()
            and str(int(value)) == value
        )

    def canonical_nonnegative_decimal(value: object) -> bool:
        return isinstance(value, str) and _NONNEGATIVE_DECIMAL.fullmatch(value) is not None

    if root.tag != "testsuites" or root.attrib != {"name": "pytest tests"}:
        return False
    suites = tuple(root)
    if len(suites) != 1:
        return False
    suite = suites[0]
    if (
        suite.tag != "testsuite"
        or set(suite.attrib)
        != {
            "name",
            "errors",
            "failures",
            "skipped",
            "tests",
            "time",
            "timestamp",
            "hostname",
        }
        or suite.attrib["name"] != "pytest"
        or any(suite.attrib[key] != "0" for key in ("errors", "failures", "skipped"))
        or not canonical_nonnegative_integer(suite.attrib["tests"])
        or not canonical_nonnegative_decimal(suite.attrib["time"])
        or not suite.attrib["timestamp"]
        or not suite.attrib["hostname"]
    ):
        return False
    testcases = tuple(suite)
    if len(testcases) != int(suite.attrib["tests"]):
        return False
    for testcase in testcases:
        if (
            testcase.tag != "testcase"
            or set(testcase.attrib) != {"classname", "name", "time"}
            or not testcase.attrib["classname"]
            or not testcase.attrib["name"]
            or not canonical_nonnegative_decimal(testcase.attrib["time"])
        ):
            return False
        children = tuple(testcase)
        if len(children) != 1 or children[0].tag != "properties" or children[0].attrib:
            return False
        properties = tuple(children[0])
        if len(properties) != 1:
            return False
        property_element = properties[0]
        if (
            property_element.tag != "property"
            or set(property_element.attrib) != {"name", "value"}
            or property_element.attrib["name"] != "phase5e_nodeid"
            or not property_element.attrib["value"]
            or len(property_element) != 0
        ):
            return False
    return True


AUDIT_TRUST_KEYS = frozenset(
    {
        "controller_commit",
        "controller_tree",
        "candidate_tree",
        "workflow_sha256",
        "audit_controller_sha256",
        "launcher_sha256",
        "candidate_executor_sha256",
        "semantic_oracle_sha256",
        "audit_profile_context_sha256",
        "audit_profile_policy_sha256",
        "audit_profile_registry_sha256",
        "requirements_lock_sha256",
        "runtime_matrix_sha256",
        "runtime_matrix_oracle_sha256",
        "audit_wheelhouse_manifest_sha256",
        "kernel_interface_sha256",
        "control_oracle_tree_sha256",
        "sandbox_profile",
    }
)

RUNTIME_IDENTITY_KEYS = frozenset(
    {
        "runtime_id",
        "python_version",
        "implementation",
        "abi",
        "operating_system",
        "architecture",
        "threading",
    }
)


def _runtime_identity(runtime_id: str) -> dict[str, str]:
    cache_tag = sys.implementation.cache_tag
    if not isinstance(cache_tag, str) or not cache_tag.startswith("cpython-"):
        abi = "unknown"
    else:
        abi = "cp" + cache_tag.removeprefix("cpython-").replace("-", "")
    gil_probe = getattr(sys, "_is_gil_enabled", None)
    gil_enabled = True if gil_probe is None else bool(gil_probe())
    identity = {
        "runtime_id": runtime_id,
        "python_version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "abi": abi,
        "operating_system": platform.system(),
        "architecture": platform.machine(),
        "threading": "gil" if gil_enabled else "free-threaded",
    }
    if set(identity) != RUNTIME_IDENTITY_KEYS:
        raise RuntimeError("runtime identity shape drifted")
    return identity


def _validate_protected_runtime(
    controller_root: Path, runtime_id: str, identity: dict[str, str]
) -> None:
    matrix = json.loads(
        (controller_root / "scripts/phase5e-audit-runtime-matrix.json").read_text(
            encoding="utf-8"
        )
    )
    expected = {
        item["runtime_id"]: {
            "runtime_id": item["runtime_id"],
            "python_version": item["python_version"],
            "implementation": matrix["platform"]["implementation"],
            "abi": item["abi"],
            "operating_system": matrix["platform"]["operating_system"],
            "architecture": matrix["platform"]["architecture"],
            "threading": matrix["platform"]["threading"],
        }
        for item in matrix["runtimes"]
    }
    if runtime_id not in expected or identity != expected[runtime_id]:
        raise RuntimeError("protected runtime differs from the fixed runtime matrix")


def audit_check_ids_sha256(check_ids: tuple[str, ...] | list[str] | set[str]) -> str:
    normalized = tuple(sorted(check_ids))
    return hashlib.sha256(("\n".join(normalized) + "\n").encode()).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json_exclusive(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def _write_bytes_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def _audit_started_at() -> str:
    value = os.environ.get("PHASE5E_AUDIT_STARTED_AT")
    if value is None:
        return datetime.now(UTC).isoformat().replace("+00:00", "Z")
    if not value.endswith("Z"):
        raise ValueError("controller audit start timestamp is not canonical UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC:
        raise ValueError("controller audit start timestamp is not UTC")
    return value


def _write_emergency_failure(argv: list[str], error: BaseException) -> None:
    try:
        output_index = argv.index("--output") + 1
        output = Path(argv[output_index])
    except (ValueError, IndexError):
        return
    reviewed_commit = "0" * 40
    runtime_id = "unknown"
    try:
        reviewed_commit = argv[argv.index("--reviewed-commit") + 1]
    except (ValueError, IndexError):
        pass
    try:
        runtime_id = argv[argv.index("--runtime-id") + 1]
    except (ValueError, IndexError):
        pass
    evidence = f"{type(error).__name__}:{error}".encode("utf-8", errors="replace")
    digest = hashlib.sha256(evidence).hexdigest()
    try:
        controller_root = Path(__file__).resolve().parents[1]
        json.loads((controller_root / "docs/phase-status.json").read_text(encoding="utf-8"))
        profile = resolve_controller_audit_profile(
            controller_root,
            "HEAD",
            has_2a_closeout=(
                controller_root / PHASE5E2B12A_ACCEPTANCE_CLOSEOUT_PATH
            ).is_file(),
        )
    except BaseException:
        # A damaged recursive state must never be mislabeled as a historical
        # Phase 5E-2B.1-2A audit.  This identity is deliberately stage-agnostic:
        # the resolver failed, so guessing a recursive owner would itself be
        # untrusted evidence.
        profile = _PROFILE_RESOLUTION_FAILURE_PROFILE
    check_ids = tuple(sorted(profile.expected_check_ids))
    checks = [
        {
            "check_id": check_id,
            "status": "failed",
            "evidence_sha256": digest,
            "evidence_size": len(evidence),
        }
        for check_id in check_ids
    ]
    findings = [
        {
            "finding_id": f"P0:{check_id}",
            "priority": "P0",
            "check_id": check_id,
            "summary": "Audit controller terminated before it could establish this check.",
            "evidence_sha256": digest,
        }
        for check_id in check_ids
    ]
    try:
        now = _audit_started_at()
    except ValueError:
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    payload = {
        "audit_tool": AUDIT_TOOL,
        "audit_profile": profile.profile_id,
        "audit_version": profile.audit_version,
        "reviewed_commit": reviewed_commit,
        "phase5d_baseline_commit": PHASE5D_BASELINE,
        "phase5e0_baseline_commit": PHASE5E0_BASELINE,
        "phase5e11_baseline_commit": PHASE5E11_BASELINE,
        "phase5e2a_baseline_commit": PHASE5E2A_BASELINE,
        "phase5e2b10_baseline_commit": PHASE5E2B10_BASELINE,
        "phase5e2b11_baseline_commit": PHASE5E2B11_BASELINE,
        "valuation_kernel_commit": KERNEL_BASELINE,
        "runtime_identity": _runtime_identity(runtime_id),
        "audit_trust": {
            "controller_commit": "0" * 40,
            "controller_tree": "0" * 40,
            "candidate_tree": "0" * 40,
            "workflow_sha256": "0" * 64,
            "audit_controller_sha256": _file_sha256(Path(__file__)),
            "launcher_sha256": "0" * 64,
            "candidate_executor_sha256": "0" * 64,
            "semantic_oracle_sha256": "0" * 64,
            "audit_profile_context_sha256": audit_profile_context_sha256(profile),
            "audit_profile_policy_sha256": audit_profile_policy_sha256(profile),
            "audit_profile_registry_sha256": _file_sha256(
                Path(__file__).with_name("phase5e_audit_profiles.py")
            ),
            "requirements_lock_sha256": "0" * 64,
            "runtime_matrix_sha256": "0" * 64,
            "runtime_matrix_oracle_sha256": "0" * 64,
            "audit_wheelhouse_manifest_sha256": "0" * 64,
            "kernel_interface_sha256": "0" * 64,
            "control_oracle_tree_sha256": "0" * 64,
            "sandbox_profile": "audit-controller-emergency-failure",
        },
        "started_at": now,
        "finished_at": now,
        "audited_file_sha256": {"audit-controller-error": digest},
        "test_counts": {
            "collected_tests": 0,
            "passed_tests": 0,
            "skipped_tests": 0,
            "failed_tests": 0,
            "nodeid_sha256": hashlib.sha256(b"").hexdigest(),
            "junit_sha256": hashlib.sha256(b"").hexdigest(),
        },
        "check_ids": check_ids,
        "check_ids_sha256": audit_check_ids_sha256(check_ids),
        "checks": checks,
        "findings": findings,
    }
    if not output.exists():
        _write_json_exclusive(output, payload)


def _emergency_failure(argv: list[str], error: BaseException) -> None:
    """Best-effort failure artifact that can never mask the original exception."""

    try:
        _write_emergency_failure(argv, error)
    except BaseException:
        return

COMMAND_TIMEOUT_SECONDS = 900
COMMAND_OUTPUT_LIMIT_BYTES = 8 * 1024 * 1024
TEST_MANIFEST_LIMIT_BYTES = 64 * 1024
JUNIT_LIMIT_BYTES = 16 * 1024 * 1024


def _has_blocking_findings(findings: tuple[dict[str, str], ...] | list[dict[str, str]]) -> bool:
    return any(item.get("priority") in {"P0", "P1", "P2", "P3"} for item in findings)


def _read_locked_candidate_output(path: Path, *, maximum_bytes: int) -> bytes:
    """Read one pre-created root-owned candidate output without following path objects."""

    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or before.st_gid != 65534
            or stat.S_IMODE(before.st_mode) != 0o660
            or before.st_size < 1
            or before.st_size > maximum_bytes
        ):
            raise ValueError("candidate output is not the exact bounded controller-owned file")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            len(raw) != before.st_size
            or len(raw) > maximum_bytes
            or identity_before != identity_after
        ):
            raise ValueError("candidate output changed during bounded descriptor replay")
        return raw
    finally:
        os.close(descriptor)


def _load_candidate_test_manifest(raw: bytes) -> dict[str, int]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError(f"duplicate test-manifest key: {key}")
            value[key] = child
        return value

    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite test-manifest value: {token}")
        ),
    )
    expected_keys = {
        "collected_tests",
        "passed_tests",
        "skipped_tests",
        "failed_tests",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or any(type(value[key]) is not int or value[key] < 0 for key in expected_keys)
        or value["collected_tests"]
        != value["passed_tests"] + value["skipped_tests"] + value["failed_tests"]
        or raw
        != (json.dumps(value, allow_nan=False, sort_keys=True) + "\n").encode("utf-8")
    ):
        raise ValueError("candidate test manifest is not the exact canonical count object")
    return {key: int(value[key]) for key in expected_keys}


def _phase5e2b12a_changed_path_violations(
    changed_paths: set[str],
    *,
    accepted: bool = False,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    expected_paths = set(PHASE5E2B12A_ALLOWED_CHANGED_PATHS)
    permitted_paths = expected_paths | PHASE5E2B12A_OPTIONAL_CHANGED_PATHS
    if accepted:
        expected_paths.add(PHASE5E2B12A_ACCEPTANCE_CLOSEOUT_PATH)
        permitted_paths.add(PHASE5E2B12A_ACCEPTANCE_CLOSEOUT_PATH)
    return (
        tuple(sorted(changed_paths - permitted_paths)),
        tuple(sorted(expected_paths - changed_paths)),
    )


def _phase5e2b12a_public_changed_path_violations(
    changed_paths: set[str],
    *,
    accepted: bool = False,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    expected_paths = set(PUBLIC_CANONICAL_MIGRATION_CHANGED_PATHS)
    permitted_paths = expected_paths | PUBLIC_CANONICAL_MIGRATION_OPTIONAL_CHANGED_PATHS
    if accepted:
        acceptance_paths = {
            PHASE_STATUS_PATH,
            PHASE5E2B12A_ACCEPTANCE_CLOSEOUT_PATH,
        }
        expected_paths.update(acceptance_paths)
        permitted_paths.update(acceptance_paths)
    return (
        tuple(sorted(changed_paths - permitted_paths)),
        tuple(sorted(expected_paths - changed_paths)),
    )


def _phase5e2b12b_changed_path_violations(
    *, controller_root: Path, candidate_root: Path, candidate_status: dict[str, Any]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    trust = json.loads(
        (controller_root / "scripts/phase5e2b12b-acceptance-trust.json").read_text(
            encoding="utf-8"
        )
    )
    states = trust.get("states", {})
    actual_markers = {
        "phase5e2b12a_closeout": bool(
            _git(
                candidate_root,
                "ls-tree",
                "HEAD",
                "--",
                PHASE5E2B12A_ACCEPTANCE_CLOSEOUT_PATH,
            )
        ),
        "phase5e2b12b_closeout": bool(
            _git(
                candidate_root,
                "ls-tree",
                "HEAD",
                "--",
                "docs/phase5e2b12b-acceptance-closeout.json",
            )
        ),
        "phase5e2b12b_test": bool(
            _git(
                candidate_root,
                "ls-tree",
                "HEAD",
                "--",
                "tests/test_phase5e2b12b_canonical_event_consumption.py",
            )
        ),
    }
    target_state: str | None = None
    for state_name in ("s2", "s3"):
        state = states.get(state_name)
        if (
            isinstance(state, dict)
            and actual_markers == state.get("markers")
            and isinstance(state.get("status_patch"), dict)
            and all(
                candidate_status.get(key) == value
                for key, value in state["status_patch"].items()
            )
        ):
            target_state = state_name
            break
    if target_state == "s2":
        expected = trust.get("implementation_diff")
    elif target_state == "s3":
        expected = trust.get("acceptance_diff")
    else:
        return (("invalid-successor-state",), ())
    if not isinstance(expected, dict) or any(
        not isinstance(path, str) or status not in {"A", "M"}
        for path, status in expected.items()
    ):
        return (("invalid-successor-trust",), ())
    output = _git(
        candidate_root,
        "diff",
        "--name-status",
        "--no-renames",
        _git(controller_root, "rev-parse", "HEAD"),
        _git(candidate_root, "rev-parse", "HEAD"),
        "--",
    )
    actual: dict[str, str] = {}
    for line in output.splitlines():
        status, path = line.split("\t", 1)
        if path in actual:
            return (("duplicate-successor-diff-path",), ())
        actual[path] = status
    unexpected = {
        f"{actual[path]}:{path}" for path in actual.keys() - expected.keys()
    } | {
        f"{actual[path]}:{path}"
        for path, status in expected.items()
        if path in actual and actual[path] != status
    }
    missing = {
        f"{status}:{path}"
        for path, status in expected.items()
        if path not in actual
    }
    return tuple(sorted(unexpected)), tuple(sorted(missing))


def _phase5e_successor_changed_path_violations(
    *,
    controller_root: Path,
    candidate_root: Path,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    controller_ref = _git(controller_root, "rev-parse", "HEAD")
    candidate_ref = _git(candidate_root, "rev-parse", "HEAD")
    position = resolve_controller_gate_position(controller_root, controller_ref)
    state = position["stage"]
    authority = position["authority"]
    bundle = position["bundle"]
    sealed_controller_boundary = (
        state == "g5"
        and int(position.get("depth", -1)) == 1
        and position.get("gate_id") == "phase5e2c0"
        and isinstance(authority, dict)
        and authority.get("owner_phase") == "Phase 5E-2C-0"
        and authority.get("next_owner_phase") == "Phase 5E-2C-1"
        and authority.get("next_gate_authority_sha256") is None
        and isinstance(bundle, dict)
        and bundle.get("next_gate_seed") is None
        and isinstance(bundle.get("post_successor_closeout"), dict)
        and isinstance(bundle["post_successor_closeout"].get("accepted_state"), dict)
        and bundle["post_successor_closeout"]["accepted_state"].get("status")
        == "accepted_closed"
        and bundle["post_successor_closeout"]["accepted_state"].get(
            "authorized_next"
        )
        == []
    )
    if state == "s3":
        expected = authority["gate_bootstrap_diff"]
    elif state == "g1":
        expected = authority["gate_acceptance_diff"]
    elif state == "g2":
        expected = authority["successor_implementation_diff"]
    elif state == "g3":
        expected = authority["successor_acceptance_diff"]
    elif state == "g4" and isinstance(bundle, dict):
        expected = bundle["post_successor_closeout"]["diff"]
    elif state == "g5" and isinstance(bundle, dict):
        seed = bundle.get("next_gate_seed")
        if sealed_controller_boundary:
            expected = {}
        elif isinstance(seed, dict):
            expected = seed.get("gate_bootstrap_diff")
        elif authority.get("next_owner_phase") == _EXTERNAL_FEASIBILITY_PHASE:
            expected = _EXTERNAL_CONTROLLER_DIFF
        else:
            expected = None
    else:
        expected = None
    if expected is None:
        return ((f"invalid-successor-controller-state:{state}",), ())
    if sealed_controller_boundary and candidate_ref != controller_ref:
        return (("sealed-controller-reauthorization-requires-exact-controller-head",), ())
    raw = subprocess.check_output(
        [
            "git",
            "-C",
            str(candidate_root),
            "diff",
            "--name-status",
            "--no-renames",
            "-z",
            controller_ref,
            candidate_ref,
        ]
    )
    fields = raw.split(b"\0")
    if fields[-1:] != [b""] or len(fields[:-1]) % 2:
        return (("malformed-successor-diff",), ())
    actual: dict[str, str] = {}
    for index in range(0, len(fields) - 1, 2):
        try:
            disposition = fields[index].decode("ascii")
            path = fields[index + 1].decode("utf-8")
        except UnicodeDecodeError:
            return (("malformed-successor-diff-path",), ())
        if disposition not in {"A", "M"} or path in actual:
            return ((f"invalid-successor-diff-entry:{disposition}:{path}",), ())
        actual[path] = disposition
    unexpected = {
        f"{actual[path]}:{path}" for path in actual.keys() - expected.keys()
    } | {
        f"{actual[path]}:{path}"
        for path, disposition in expected.items()
        if path in actual and actual[path] != disposition
    }
    missing = {
        f"{disposition}:{path}"
        for path, disposition in expected.items()
        if path not in actual
    }
    return tuple(sorted(unexpected)), tuple(sorted(missing))


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def _record(
    checks: list[dict[str, str]],
    findings: list[dict[str, str]],
    *,
    check_id: str,
    passed: bool,
    summary: str,
    evidence: str,
    priority: str = "P1",
) -> None:
    raw = evidence.encode("utf-8", errors="replace")
    digest = hashlib.sha256(raw).hexdigest()
    checks.append(
        {
            "check_id": check_id,
            "status": "passed" if passed else "failed",
            "evidence_sha256": digest,
            "evidence_size": len(raw),
        }
    )
    if not passed:
        findings.append(
            {
                "finding_id": f"{priority}:{check_id}",
                "priority": priority,
                "check_id": check_id,
                "summary": summary,
                "evidence_sha256": digest,
            }
        )


def _run_direct(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    capture_text: bool = False,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        timed_out = False
        try:
            returncode = process.wait(timeout=COMMAND_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                returncode = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                returncode = process.wait(timeout=10)
        finally:
            # The direct child may exit while descendants remain in its process group.  Kill the
            # complete group before any controller-owned evidence is read.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        output.seek(0, os.SEEK_END)
        size = output.tell()
        output.seek(0)
        digest = hashlib.sha256()
        captured = bytearray()
        while chunk := output.read(1024 * 1024):
            digest.update(chunk)
            if capture_text and len(captured) <= COMMAND_OUTPUT_LIMIT_BYTES:
                captured.extend(chunk)
        summary = json.dumps(
            {
                "command": tuple(command),
                "output_bytes": size,
                "output_sha256": digest.hexdigest(),
                "output_within_limit": size <= COMMAND_OUTPUT_LIMIT_BYTES,
                "timed_out": timed_out,
            },
            sort_keys=True,
        )
        if size > COMMAND_OUTPUT_LIMIT_BYTES and returncode == 0:
            returncode = 125
        stdout = (
            captured.decode("utf-8", errors="strict")
            if capture_text and size <= COMMAND_OUTPUT_LIMIT_BYTES
            else summary
        )
        return subprocess.CompletedProcess(command, returncode, stdout, None)


def _sandbox_path(path: str, *, repository: Path, scratch: Path) -> str:
    candidate = repository.resolve()
    candidate_scratch = scratch.resolve()
    try:
        relative = Path(path).resolve().relative_to(candidate)
    except (OSError, ValueError):
        pass
    else:
        return str(Path("/work") / relative)
    try:
        relative = Path(path).resolve().relative_to(candidate_scratch)
    except (OSError, ValueError):
        return path
    return str(Path("/scratch") / relative)


def _run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    capture_text: bool = False,
) -> subprocess.CompletedProcess[str]:
    helper = environment.get("PHASE5E_CANDIDATE_EXEC")
    if helper is None:
        return _run_direct(
            command,
            cwd=cwd,
            environment=environment,
            capture_text=capture_text,
        )
    repository = Path(environment["PHASE5E_CANDIDATE_REPOSITORY"]).resolve()
    interface = Path(environment["PHASE5E_KERNEL_INTERFACE"]).resolve()
    venv = Path(environment["PHASE5E_AUDIT_VENV"]).resolve()
    scratch = Path(environment["PHASE5E_CANDIDATE_SCRATCH"]).resolve()
    oracle = Path(environment["PHASE5E_CONTROL_ORACLE"]).resolve()
    mapped: list[str] = []
    for index, value in enumerate(command):
        if index == 0 and Path(value).resolve() == Path(sys.executable).resolve():
            mapped.extend(("/venv/bin/python", "-P"))
        else:
            mapped.append(_sandbox_path(value, repository=repository, scratch=scratch))
    candidate_cwd = _sandbox_path(str(cwd), repository=repository, scratch=scratch)
    return _run_direct(
        [
            "/bin/bash",
            helper,
            str(repository),
            str(interface),
            str(venv),
            str(scratch),
            str(oracle),
            candidate_cwd,
            *mapped,
        ],
        cwd=repository,
        environment={
            "HOME": "/root",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        },
        capture_text=capture_text,
    )


def _run_dynamic_successor_oracles(
    *,
    repository: Path,
    controller_root: Path,
    controller_ref: str,
    candidate_ref: str,
    profile: Any,
    environment: dict[str, str],
    protected_mode: bool,
    controller_integrity_passed: bool,
) -> tuple[
    subprocess.CompletedProcess[str],
    subprocess.CompletedProcess[str] | None,
]:
    """Run candidate behavior only after the protected structural oracle succeeds."""

    structural = _run_direct(
        [
            sys.executable,
            "-I",
            str(controller_root / "scripts/verify_phase5e_successor_gate_oracle.py"),
            "--repository",
            str(repository),
            "--controller-root",
            str(controller_root),
            "--controller-ref",
            controller_ref,
            "--candidate-ref",
            candidate_ref,
        ],
        cwd=repository,
        environment=environment,
    )
    if not controller_integrity_passed or structural.returncode != 0:
        return structural, None
    behavior_path = (
        f"/oracle/{profile.semantic_oracle_path}"
        if protected_mode
        else str(controller_root / profile.semantic_oracle_path)
    )
    behavior = _run(
        [
            sys.executable,
            "-I",
            behavior_path,
            "--repository",
            str(repository),
        ],
        cwd=repository,
        environment=environment,
    )
    return structural, behavior


def _regular_tracked_file(repository: Path, relative: str) -> bool:
    path = repository / relative
    try:
        mode = path.lstat().st_mode
        resolved = path.resolve(strict=True)
        resolved.relative_to(repository.resolve())
    except (FileNotFoundError, RuntimeError, ValueError):
        return False
    if not stat.S_ISREG(mode):
        return False
    tree_entry = _git(repository, "ls-tree", "HEAD", "--", relative)
    return bool(tree_entry) and tree_entry.split()[0] in {"100644", "100755"}


def _tracked_manifest(repository: Path) -> dict[str, Any]:
    paths = subprocess.check_output(
        ["git", "-C", str(repository), "ls-files", "-z"],
    ).split(b"\0")
    entries: list[tuple[str, str, str]] = []
    for raw in paths:
        if not raw:
            continue
        relative = raw.decode("utf-8")
        path = repository / relative
        raw_mode = path.lstat().st_mode
        mode = stat.S_IMODE(raw_mode)
        if stat.S_ISREG(raw_mode):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        elif stat.S_ISLNK(raw_mode):
            digest = hashlib.sha256(os.readlink(path).encode()).hexdigest()
        else:
            digest = hashlib.sha256(f"non-regular:{raw_mode}".encode()).hexdigest()
        entries.append((relative, f"{mode:04o}", digest))
    return {
        "head": _git(repository, "rev-parse", "HEAD"),
        "tree": _git(repository, "rev-parse", "HEAD^{tree}"),
        "remotes": tuple(_git(repository, "remote").splitlines()),
        "refs": tuple(_git(repository, "for-each-ref", "--format=%(refname)").splitlines()),
        "status": _git(repository, "status", "--porcelain=v1"),
        "tracked_sha256": hashlib.sha256(
            json.dumps(entries, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest(),
        "tracked_count": len(entries),
    }


def _file_tree_manifest(root: Path) -> dict[str, Any]:
    entries: list[tuple[str, str, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        raw_mode = path.lstat().st_mode
        if not stat.S_ISREG(raw_mode) or path.is_symlink():
            digest = hashlib.sha256(f"non-regular:{raw_mode}".encode()).hexdigest()
        else:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append((relative, f"{stat.S_IMODE(raw_mode):04o}", digest))
    return {
        "tree_sha256": hashlib.sha256(
            json.dumps(entries, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest(),
        "file_count": len(entries),
    }


def _verify_control_oracle_file_manifest(
    *,
    oracle_root: Path,
    controller_root: Path,
) -> dict[str, str]:
    """Bind every file exposed at ``/oracle`` to one protected-controller Git blob."""

    fixed = set(CONTROL_ORACLE_FIXED_PATHS)
    successor_literal = "governance/phase5e-gates/phase5e2b12c/semantic-oracle.py.txt"
    if (controller_root / successor_literal).is_file():
        fixed.add(successor_literal)
    tracked_tests = {
        line
        for line in str(_git(controller_root, "ls-files", "--", "tests")).splitlines()
        if line
    }
    expected_paths = fixed | tracked_tests
    manifest_path = oracle_root / "oracle-manifest.json"
    raw = manifest_path.read_bytes()

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise RuntimeError(f"duplicate oracle manifest key: {key}")
            value[key] = child
        return value

    manifest = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda token: (_ for _ in ()).throw(
            RuntimeError(f"non-finite oracle manifest constant: {token}")
        ),
    )
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "files"}
        or manifest.get("schema_version") != "1.0.0"
        or not isinstance(manifest.get("files"), list)
        or raw
        != (json.dumps(manifest, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    ):
        raise RuntimeError("control oracle per-file manifest is malformed")
    entries: dict[str, str] = {}
    prior_path = ""
    for item in manifest["files"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not isinstance(item.get("path"), str)
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", item["path"])
            or item["path"].startswith("/")
            or ".." in Path(item["path"]).parts
            or item["path"] <= prior_path
            or not isinstance(item.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
            or item["path"] in entries
        ):
            raise RuntimeError("control oracle per-file manifest has an open entry")
        entries[item["path"]] = item["sha256"]
        prior_path = item["path"]
    if set(entries) != expected_paths:
        raise RuntimeError("control oracle surface differs from its protected file inventory")
    controller_head = str(_git(controller_root, "rev-parse", "HEAD"))
    for relative, digest in entries.items():
        exposed = oracle_root / relative
        tree_entry = str(_git(controller_root, "ls-tree", controller_head, "--", relative))
        fields = tree_entry.split(None, 3)
        if (
            exposed.is_symlink()
            or not exposed.is_file()
            or len(fields) != 4
            or fields[0] != "100644"
            or fields[3].split("\t", 1)[-1] != relative
        ):
            raise RuntimeError(f"control oracle file is not one regular protected blob: {relative}")
        protected_raw = subprocess.check_output(
            ["git", "-C", str(controller_root), "show", f"{controller_head}:{relative}"],
        )
        if (
            not isinstance(protected_raw, bytes)
            or hashlib.sha256(protected_raw).hexdigest() != digest
            or hashlib.sha256(exposed.read_bytes()).hexdigest() != digest
        ):
            raise RuntimeError(f"control oracle file hash drifted: {relative}")
    return entries


def _verify_profile_semantic_oracle_binding(
    *,
    controller_root: Path,
    controller_ref: str,
    profile: Any,
    oracle_root: Path | None,
    oracle_manifest: dict[str, str],
) -> str:
    """Bind one behavior oracle to its protected Git blob before it can execute."""

    relative = profile.semantic_oracle_path
    if (
        not isinstance(relative, str)
        or not relative
        or relative.startswith("/")
        or Path(relative).as_posix() != relative
        or ".." in Path(relative).parts
    ):
        raise RuntimeError("audit profile semantic oracle path is unsafe")
    tree_raw = subprocess.check_output(
        [
            "git",
            "-C",
            str(controller_root),
            "ls-tree",
            "-z",
            controller_ref,
            "--",
            relative,
        ]
    )
    records = tree_raw.rstrip(b"\0").split(b"\0") if tree_raw else []
    if len(records) != 1:
        raise RuntimeError("audit profile semantic oracle is not one protected Git blob")
    try:
        metadata, tracked_path = records[0].split(b"\t", 1)
        mode, object_type, _object_id = metadata.decode("ascii").split(" ", 2)
        decoded_path = tracked_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError("audit profile semantic oracle Git identity is malformed") from exc
    if mode != "100644" or object_type != "blob" or decoded_path != relative:
        raise RuntimeError("audit profile semantic oracle is not a non-executable regular blob")
    protected_raw = subprocess.check_output(
        ["git", "-C", str(controller_root), "show", f"{controller_ref}:{relative}"]
    )
    digest = hashlib.sha256(protected_raw).hexdigest()
    declared = profile.semantic_oracle_sha256
    if declared and digest != declared:
        raise RuntimeError("audit profile semantic oracle differs from its declared digest")
    worktree_file = controller_root / relative
    if (
        worktree_file.is_symlink()
        or not worktree_file.is_file()
        or hashlib.sha256(worktree_file.read_bytes()).hexdigest() != digest
    ):
        raise RuntimeError("controller worktree semantic oracle differs from its protected blob")
    if oracle_root is not None:
        exposed = oracle_root / relative
        if (
            oracle_manifest.get(relative) != digest
            or exposed.is_symlink()
            or not exposed.is_file()
            or hashlib.sha256(exposed.read_bytes()).hexdigest() != digest
        ):
            raise RuntimeError("sandbox semantic oracle differs from its protected blob")
    return digest


def _linux_sandbox_evidence(repository: Path, kernel_interface: Path) -> tuple[bool, str]:
    status_text = Path("/proc/self/status").read_text(encoding="utf-8")
    status_fields = {
        line.split(":", 1)[0]: line.split(":", 1)[1].strip()
        for line in status_text.splitlines()
        if ":" in line
    }
    # /sys may retain the parent namespace's interface view when it was mounted
    # before unshare(2).  Query the active network namespace through libc
    # instead; this is the same namespace socket operations would use.
    interfaces = tuple(sorted(name for _index, name in socket.if_nameindex()))
    evidence = {
        "audit_marker": os.environ.get("AUDIT_OS_SANDBOX"),
        "effective_uid": os.geteuid(),
        "effective_gid": os.getegid(),
        "no_new_privs": status_fields.get("NoNewPrivs"),
        "cap_eff": status_fields.get("CapEff"),
        "network_interfaces": interfaces,
        "research_readonly": bool(os.statvfs(repository).f_flag & os.ST_RDONLY),
        "kernel_interface_readonly": bool(
            os.statvfs(kernel_interface).f_flag & os.ST_RDONLY
        ),
        "candidate_executor": os.environ.get("PHASE5E_CANDIDATE_EXEC"),
        "network_namespace": os.readlink("/proc/self/ns/net"),
        "mount_namespace": os.readlink("/proc/self/ns/mnt"),
        "pid_namespace": os.readlink("/proc/self/ns/pid"),
    }
    passed = (
        evidence["audit_marker"] == "linux-root-controller-net-pid-v2"
        and evidence["effective_uid"] == 0
        and evidence["effective_gid"] == 0
        and evidence["no_new_privs"] == "1"
        and interfaces == ("lo",)
        and evidence["research_readonly"]
        and evidence["kernel_interface_readonly"]
        and isinstance(evidence["candidate_executor"], str)
        and bool(evidence["candidate_executor"])
    )
    return passed, json.dumps(evidence, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    kernel_group = parser.add_mutually_exclusive_group(required=True)
    kernel_group.add_argument("--valuation-repo", type=Path)
    kernel_group.add_argument("--kernel-interface", type=Path)
    parser.add_argument("--reviewed-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-id")
    parser.add_argument("--require-os-sandbox", action="store_true")
    args = parser.parse_args()
    repository = args.repository.resolve()
    controller_root = Path(__file__).resolve().parents[1]
    profile = resolve_controller_audit_profile(
        controller_root,
        "HEAD",
        has_2a_closeout=(
            controller_root / PHASE5E2B12A_ACCEPTANCE_CLOSEOUT_PATH
        ).is_file(),
    )
    interface = args.kernel_interface.resolve() if args.kernel_interface is not None else None
    kernel = (
        interface / "kernel"
        if interface is not None
        else args.valuation_repo.resolve()
        if args.valuation_repo is not None
        else None
    )
    if kernel is None:
        raise RuntimeError("kernel identity input is missing")
    protected_mode = args.require_os_sandbox
    if protected_mode and (
        interface is None
        or not os.environ.get("PHASE5E_CANDIDATE_EXEC")
        or not os.environ.get("PHASE5E_CANDIDATE_SCRATCH")
    ):
        raise RuntimeError("protected audit requires the bounded interface and candidate executor")
    runtime_id = args.runtime_id or "local"
    runtime_identity = _runtime_identity(runtime_id)
    if protected_mode:
        if args.runtime_id is None:
            raise RuntimeError("protected audit requires a fixed runtime identity")
        _validate_protected_runtime(controller_root, runtime_id, runtime_identity)
    checks: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    started_at = _audit_started_at()

    research_before = _tracked_manifest(repository)
    controller_before = _tracked_manifest(controller_root)
    kernel_before = (
        _file_tree_manifest(interface)
        if interface is not None
        else _tracked_manifest(kernel)
    )
    if interface is not None:
        interface_manifest = json.loads(
            (interface / "kernel-release-interface.json").read_text(encoding="utf-8")
        )
        kernel_interface_sha256 = str(interface_manifest.get("interface_sha256", ""))
    else:
        kernel_interface_sha256 = hashlib.sha256(
            json.dumps(kernel_before, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    control_oracle_root = os.environ.get("PHASE5E_CONTROL_ORACLE")
    control_oracle_manifest: dict[str, str] = {}
    if control_oracle_root:
        control_oracle_manifest = _verify_control_oracle_file_manifest(
            oracle_root=Path(control_oracle_root),
            controller_root=controller_root,
        )
    control_oracle_tree_sha256 = (
        _file_tree_manifest(Path(control_oracle_root))["tree_sha256"]
        if control_oracle_root
        else _file_tree_manifest(controller_root / "tests")["tree_sha256"]
    )
    semantic_oracle_sha256 = _verify_profile_semantic_oracle_binding(
        controller_root=controller_root,
        controller_ref=controller_before["head"],
        profile=profile,
        oracle_root=Path(control_oracle_root) if control_oracle_root else None,
        oracle_manifest=control_oracle_manifest,
    )
    audit_trust = {
        "controller_commit": controller_before["head"],
        "controller_tree": controller_before["tree"],
        "candidate_tree": research_before["tree"],
        "workflow_sha256": _file_sha256(
            controller_root / ".github/workflows/phase5e2b12a-acceptance-gate.yml"
        ),
        "audit_controller_sha256": _file_sha256(Path(__file__)),
        "launcher_sha256": _file_sha256(
            controller_root / "scripts/launch_phase5e_readonly_audit.sh"
        ),
        "candidate_executor_sha256": _file_sha256(
            controller_root / "scripts/phase5e_candidate_exec.sh"
        ),
        "semantic_oracle_sha256": semantic_oracle_sha256,
        "audit_profile_context_sha256": audit_profile_context_sha256(profile),
        "audit_profile_policy_sha256": audit_profile_policy_sha256(profile),
        "audit_profile_registry_sha256": _file_sha256(
            controller_root / "scripts/phase5e_audit_profiles.py"
        ),
        "requirements_lock_sha256": _file_sha256(
            controller_root / "scripts/phase5e-audit-requirements.lock"
        ),
        "runtime_matrix_sha256": _file_sha256(
            controller_root / "scripts/phase5e-audit-runtime-matrix.json"
        ),
        "runtime_matrix_oracle_sha256": _file_sha256(
            controller_root / "scripts/verify_phase5e_audit_runtime_matrix.py"
        ),
        "audit_wheelhouse_manifest_sha256": _file_sha256(
            controller_root / "scripts/phase5e-audit-wheelhouse.sha256"
        ),
        "kernel_interface_sha256": kernel_interface_sha256,
        "control_oracle_tree_sha256": control_oracle_tree_sha256,
        "sandbox_profile": (
            "linux-root-controller-net-pid-v2"
            if protected_mode
            else "local-unprotected"
        ),
    }
    if set(audit_trust) != AUDIT_TRUST_KEYS:
        raise RuntimeError("audit trust context shape drifted")

    controller_integrity_passed = (
        not protected_mode
        or (
            os.geteuid() == 0
            and interface is not None
            and Path(os.environ["PHASE5E_CANDIDATE_EXEC"]).is_file()
            and not controller_before["remotes"]
            and not controller_before["refs"]
            and not research_before["refs"]
            and not controller_before["status"]
            and _file_sha256(Path(os.environ["PHASE5E_CANDIDATE_EXEC"]))
            == audit_trust["candidate_executor_sha256"]
            and _file_sha256(
                Path(os.environ["PHASE5E_CONTROL_ORACLE"])
                / profile.semantic_oracle_path
            )
            == audit_trust["semantic_oracle_sha256"]
            and _file_sha256(controller_root / "scripts/phase5e_audit_profiles.py")
            == audit_trust["audit_profile_registry_sha256"]
        )
    )
    _record(
        checks,
        findings,
        check_id="audit-controller-integrity",
        passed=controller_integrity_passed,
        summary="Trusted root controller or candidate-execution boundary is missing.",
        evidence=json.dumps(
            {
                "protected_mode": protected_mode,
                "effective_uid": os.geteuid(),
                "candidate_executor": os.environ.get("PHASE5E_CANDIDATE_EXEC"),
                "kernel_interface": str(interface) if interface is not None else None,
                "audit_trust": audit_trust,
            },
            sort_keys=True,
        ),
        priority="P0",
    )

    head = _git(repository, "rev-parse", "HEAD")
    remotes = _git(repository, "remote")
    _record(
        checks,
        findings,
        check_id="exact-head-no-remote",
        passed=head == args.reviewed_commit and not remotes,
        summary="Audit checkout is not exact-head or retains a remote.",
        evidence=f"expected={args.reviewed_commit}\nhead={head}\nremotes={remotes}",
        priority="P0",
    )
    if interface is not None:
        interface_verification = _run_direct(
            [
                sys.executable,
                str(Path(__file__).with_name("verify_kernel_release_interface.py")),
                "--interface",
                str(interface),
            ],
            cwd=Path(__file__).resolve().parents[1],
            environment={
                "HOME": os.environ.get("HOME", "/tmp"),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            },
            capture_text=True,
        )
        kernel_identity_passed = interface_verification.returncode == 0
        kernel_identity_evidence = interface_verification.stdout
    else:
        kernel_head = _git(kernel, "rev-parse", "HEAD")
        kernel_remotes = _git(kernel, "remote")
        kernel_identity_passed = (
            kernel_head == KERNEL_BASELINE
            and not kernel_remotes
            and not kernel_before["status"]
        )
        kernel_identity_evidence = json.dumps(kernel_before, sort_keys=True)
    _record(
        checks,
        findings,
        check_id="kernel-exact-head-no-remote",
        passed=kernel_identity_passed,
        summary="Kernel release interface or local checkout identity is not exact.",
        evidence=kernel_identity_evidence,
        priority="P0",
    )
    if args.require_os_sandbox:
        if interface is None:
            raise RuntimeError("protected audit cannot expose a full kernel checkout")
        sandbox_passed, sandbox_evidence = _linux_sandbox_evidence(repository, interface)
    else:
        sandbox_passed = os.environ.get("AUDIT_OS_SANDBOX") is None
        sandbox_evidence = json.dumps({"required": False, "local_mode": True}, sort_keys=True)
    _record(
        checks,
        findings,
        check_id="os-sandbox-boundary",
        passed=sandbox_passed,
        summary=(
            "Audit process is not inside the required unprivileged read-only "
            "no-network sandbox."
        ),
        evidence=sandbox_evidence,
        priority="P0",
    )
    public_mode = not commit_exists(PHASE5D_BASELINE, repository)
    if public_mode:
        verify_public_bootstrap_snapshot(repository)
        research_comparison_commit = public_root_commit(repository)
    else:
        research_comparison_commit = PHASE5D_BASELINE
    changed_files = set(
        _git(
            repository,
            "diff",
            "--name-only",
            "--no-renames",
            research_comparison_commit,
            "HEAD",
        ).splitlines()
    )
    phase_status = json.loads((repository / "docs/phase-status.json").read_text())
    if profile.profile_kind == "legacy_2a_recovery":
        if (
            repository
            / "scripts/phase5e-phase-state-performance-recovery-seal-v1.json"
        ).is_file():
            topology_option = "--verify-phase-state-performance-topology-only"
        elif (
            repository
            / "scripts/phase5e-base-finalization-topology-recovery-seal-v1.json"
        ).is_file():
            topology_option = "--verify-base-finalization-topology-only"
        else:
            topology_option = "--verify-inventory-parity-topology-only"
        parity_topology = _run_direct(
            [
                sys.executable,
                str(
                    controller_root
                    / "scripts/verify_phase5e2b12a_acceptance_gate.py"
                ),
                "--repository",
                str(repository),
                "--base",
                research_before["head"],
                topology_option,
            ],
            cwd=repository,
            environment={"PATH": os.environ.get("PATH", "")},
        )
        unexpected_phase_paths = (
            [] if parity_topology.returncode == 0 else ["inventory-parity-topology"]
        )
        missing_phase_paths: list[str] = []
        changed_path_check_id = "phase5e2b12a-repository-wide-changed-path-boundary"
        changed_path_summary = (
            "Current protected 2A control differs from its sealed inventory-parity boundary."
        )
    elif profile.profile_kind == "legacy_2a":
        phase_comparison_commit = (
            research_comparison_commit if public_mode else PHASE5E2B11_BASELINE
        )
        phase_changed_files = set(
            _git(
                repository,
                "diff",
                "--name-only",
                "--no-renames",
                phase_comparison_commit,
                "HEAD",
            ).splitlines()
        )
        phase_accepted = (
            phase_status.get("current_phase") == "Phase 5E-2B.1-2A"
            and phase_status.get("status") == "accepted_closed"
            and (repository / PHASE5E2B12A_ACCEPTANCE_CLOSEOUT_PATH).is_file()
        )
        if public_mode:
            unexpected_phase_paths, missing_phase_paths = (
                _phase5e2b12a_public_changed_path_violations(
                    phase_changed_files,
                    accepted=phase_accepted,
                )
            )
        else:
            unexpected_phase_paths, missing_phase_paths = (
                _phase5e2b12a_changed_path_violations(
                    phase_changed_files,
                    accepted=phase_accepted,
                )
            )
        changed_path_check_id = "phase5e2b12a-repository-wide-changed-path-boundary"
        changed_path_summary = (
            "Phase 5E-2B.1-2A changed paths escaped the closed repository-wide boundary."
        )
    elif profile.profile_kind == "legacy_2b":
        unexpected_phase_paths, missing_phase_paths = (
            _phase5e2b12b_changed_path_violations(
                controller_root=controller_root,
                candidate_root=repository,
                candidate_status=phase_status,
            )
        )
        changed_path_check_id = "phase5e2b12b-repository-wide-changed-path-boundary"
        changed_path_summary = (
            "Phase 5E-2B.1-2B candidate differs from its protected controller boundary."
        )
    elif profile.profile_kind in {
        "sealed_controller_reauthorization",
        "external_feasibility",
        "successor_bootstrap",
        "successor_dynamic",
        "successor_transition",
    }:
        unexpected_phase_paths, missing_phase_paths = (
            _phase5e_successor_changed_path_violations(
                controller_root=controller_root,
                candidate_root=repository,
            )
        )
        changed_path_check_id = "phase5e-successor-repository-wide-changed-path-boundary"
        changed_path_summary = (
            "Phase 5E successor candidate differs from its protected gate bundle."
        )
    else:  # pragma: no cover - AuditProfile rejects unknown kinds before this point.
        raise RuntimeError(f"unsupported Phase 5E audit profile kind: {profile.profile_kind}")
    _record(
        checks,
        findings,
        check_id=changed_path_check_id,
        passed=not unexpected_phase_paths and not missing_phase_paths,
        summary=changed_path_summary,
        evidence=json.dumps(
            {
                "unexpected": unexpected_phase_paths,
                "missing": missing_phase_paths,
            },
            sort_keys=True,
        ),
        priority="P1",
    )
    audited_files = tuple(sorted(changed_files | STATIC_CONTROL_FILES))
    missing = [
        relative
        for relative in audited_files
        if not _regular_tracked_file(repository, relative)
    ]
    _record(
        checks,
        findings,
        check_id="audited-files-present",
        passed=not missing,
        summary="Required Phase 5E-2B.1 audit files are missing.",
        evidence=json.dumps(missing, sort_keys=True),
        priority="P0",
    )
    existing = [
        relative
        for relative in audited_files
        if _regular_tracked_file(repository, relative)
    ]
    writable = [
        item
        for item in (".", *existing)
        if (repository / item).stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    ]
    kernel_identity_label = (
        "release-interface"
        if interface is not None
        else _git(kernel, "rev-parse", "HEAD")
    )
    _record(
        checks,
        findings,
        check_id="read-only-checkout",
        passed=not writable,
        summary="Audit checkout or Phase 5E files remain writable.",
        evidence=json.dumps(writable, sort_keys=True),
        priority="P0",
    )
    research_ok = (
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "merge-base",
                "--is-ancestor",
                research_comparison_commit,
                "HEAD",
            ]
        ).returncode
        == 0
    )
    kernel_ok = kernel_identity_passed
    _record(
        checks,
        findings,
        check_id="fixed-baselines",
        passed=research_ok and kernel_ok,
        summary="Phase 5D or valuation-kernel baseline drifted.",
        evidence=f"research={PHASE5D_BASELINE}\nkernel={kernel_identity_label}",
        priority="P0",
    )

    environment = {
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "OWNER_VALUATION_REPO": "/interface/kernel" if protected_mode else str(kernel),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONSAFEPATH": "1",
        "PYTEST_ADDOPTS": "--import-mode=importlib -p no:cacheprovider",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONPATH": f"{repository / 'src'}:{repository}",
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    for key in (
        "PHASE5E_CANDIDATE_EXEC",
        "PHASE5E_CANDIDATE_REPOSITORY",
        "PHASE5E_KERNEL_INTERFACE",
        "PHASE5E_AUDIT_VENV",
        "PHASE5E_CANDIDATE_SCRATCH",
        "PHASE5E_CONTROL_ORACLE",
    ):
        if value := os.environ.get(key):
            environment[key] = value
    runtime_context = (
        nullcontext(os.environ["PHASE5E_CANDIDATE_SCRATCH"])
        if protected_mode
        else tempfile.TemporaryDirectory(prefix="phase5e-audit-runtime-")
    )
    with runtime_context as runtime:
        runtime_path = Path(runtime)
        environment["PYTHONPYCACHEPREFIX"] = str(runtime_path / "pycache")
        environment["RUFF_CACHE_DIR"] = str(runtime_path / "ruff-cache")
        controller_output_root = (
            runtime_path / "controller-outputs" if protected_mode else runtime_path
        )
        test_manifest = controller_output_root / "phase5e-test-counts.json"
        verification = _run(
            [
                sys.executable,
                str(repository / "scripts/verify_all.py"),
                "--test-manifest",
                str(test_manifest),
            ],
            cwd=repository,
            environment=environment,
        )
        _record(
            checks,
            findings,
            check_id="full-verification",
            passed=verification.returncode == 0,
            summary="Full Phase 1-5E-2B.1 verification failed.",
            evidence=verification.stdout,
            priority="P0",
        )
        try:
            reported_manifest_raw = (
                _read_locked_candidate_output(
                    test_manifest,
                    maximum_bytes=TEST_MANIFEST_LIMIT_BYTES,
                )
                if protected_mode
                else test_manifest.read_bytes()
            )
            reported_counts = _load_candidate_test_manifest(reported_manifest_raw)
        except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
            reported_counts = None
        collection = _run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q"],
            cwd=repository,
            environment=environment,
            capture_text=True,
        )
        collected_nodeids = tuple(
            sorted(
                line.strip()
                for line in collection.stdout.splitlines()
                if "::" in line and not line.startswith(("=", " "))
            )
        )
        nodeid_bytes = ("\n".join(collected_nodeids) + "\n").encode()
        independent_junit = controller_output_root / "phase5e-independent.xml"
        independent_tests = _run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-p",
                "scripts.pytest_phase5e_nodeids",
                "--junitxml",
                str(independent_junit),
            ],
            cwd=repository,
            environment=environment,
        )
        try:
            independent_junit_raw = (
                _read_locked_candidate_output(
                    independent_junit,
                    maximum_bytes=JUNIT_LIMIT_BYTES,
                )
                if protected_mode
                else independent_junit.read_bytes()
            )
            junit_root = ET.fromstring(independent_junit_raw)
        except (OSError, ValueError, ET.ParseError):
            independent_junit_raw = b""
            junit_root = None
        independent_suites = (
            [junit_root]
            if junit_root is not None and junit_root.tag == "testsuite"
            else list(junit_root.findall("testsuite"))
            if junit_root is not None
            else []
        )
        independent_collected = sum(int(item.attrib.get("tests", 0)) for item in independent_suites)
        independent_failed = sum(
            int(item.attrib.get("failures", 0)) + int(item.attrib.get("errors", 0))
            for item in independent_suites
        )
        independent_skipped = sum(int(item.attrib.get("skipped", 0)) for item in independent_suites)
        independent_testcases = tuple(
            testcase for suite in independent_suites for testcase in suite.findall("testcase")
        )
        testcase_nodeids = tuple(
            tuple(
                property_element.attrib.get("value")
                for properties in testcase.findall("properties")
                for property_element in properties.findall("property")
                if property_element.attrib.get("name") == "phase5e_nodeid"
            )
            for testcase in independent_testcases
        )
        executed_nodeids = tuple(
            sorted(
                values[0]
                for values in testcase_nodeids
                if len(values) == 1 and isinstance(values[0], str)
            )
        )
        junit_shape_valid = (
            junit_root is not None
            and _strict_junit_tree(junit_root)
            and len(independent_testcases) == independent_collected
            and len(testcase_nodeids) == independent_collected
            and all(len(values) == 1 and isinstance(values[0], str) for values in testcase_nodeids)
            and len(set(executed_nodeids)) == len(executed_nodeids)
            and all(
                all(
                    descendant.tag not in _JUNIT_FAILURE_TAGS
                    for descendant in testcase.iter()
                    if descendant is not testcase
                )
                for testcase in independent_testcases
            )
        )
        independent_counts = {
            "collected_tests": independent_collected,
            "passed_tests": independent_collected - independent_failed - independent_skipped,
            "skipped_tests": independent_skipped,
            "failed_tests": independent_failed,
            "nodeid_sha256": hashlib.sha256(nodeid_bytes).hexdigest(),
            "junit_sha256": (
                hashlib.sha256(independent_junit_raw).hexdigest()
                if independent_junit_raw
                else None
            ),
        }
        expected_added_nodeids = frozenset(profile.expected_added_test_nodeids)
        collected_nodeid_set = frozenset(collected_nodeids)
        predecessor_nodeids = tuple(
            nodeid for nodeid in collected_nodeids if nodeid not in expected_added_nodeids
        )
        predecessor_nodeid_bytes = ("\n".join(predecessor_nodeids) + "\n").encode()
        inventory_identity_passed = (
            len(collected_nodeids) == profile.expected_test_count
            and expected_added_nodeids.issubset(collected_nodeid_set)
            and len(predecessor_nodeids) == profile.predecessor_test_count
            and hashlib.sha256(predecessor_nodeid_bytes).hexdigest()
            == profile.predecessor_nodeid_sha256
        )
        count_gate_passed = (
            collection.returncode == 0
            and independent_tests.returncode == 0
            and inventory_identity_passed
            and independent_collected == len(collected_nodeids)
            and junit_shape_valid
            and executed_nodeids == collected_nodeids
            and independent_counts["passed_tests"] == independent_collected
            and independent_failed == 0
            and independent_skipped == 0
            and reported_counts is not None
            and all(
                reported_counts.get(key) == independent_counts[key]
                for key in (
                    "collected_tests",
                    "passed_tests",
                    "skipped_tests",
                    "failed_tests",
                )
            )
        )
        _record(
            checks,
            findings,
            check_id="independent-test-manifest-replay",
            passed=count_gate_passed,
            summary="Reported test counts do not replay from independent collection and JUnit.",
            evidence=json.dumps(
                {
                    "reported": reported_counts,
                    "independent": independent_counts,
                    "nodeid_count": len(collected_nodeids),
                    "expected_added_nodeids": sorted(expected_added_nodeids),
                    "predecessor_nodeid_sha256": hashlib.sha256(
                        predecessor_nodeid_bytes
                    ).hexdigest(),
                    "junit_shape_valid": junit_shape_valid,
                    "executed_nodeids_match": executed_nodeids == collected_nodeids,
                },
                sort_keys=True,
            ),
            priority="P0",
        )
        frozen_predecessor = _run(
            [
                sys.executable,
                str(repository / "scripts/verify_phase5e2b11_frozen_acceptance.py"),
            ],
            cwd=repository,
            environment=environment,
        )
        _record(
            checks,
            findings,
            check_id="phase5e2b11-frozen-acceptance",
            passed=frozen_predecessor.returncode == 0,
            summary="Frozen Phase 5E-2B.1-1 acceptance snapshot failed replay.",
            evidence=frozen_predecessor.stdout,
            priority="P0",
        )
        if profile.profile_kind in {"legacy_2a", "legacy_2a_recovery"}:
            frozen_replay = profile.profile_kind == "legacy_2a_recovery"
            integration_contracts = _run(
                [
                    sys.executable,
                    str(
                        repository
                        / "scripts/verify_phase5e2b12a_integration_contracts.py"
                    ),
                    *(["--frozen-contract-replay"] if frozen_replay else []),
                ],
                cwd=repository,
                environment=environment,
            )
            _record(
                checks,
                findings,
                check_id="phase5e2b12a-integration-contracts",
                passed=integration_contracts.returncode == 0,
                summary=(
                    "Phase 5E-2B.1-2A current-head integration contract oracle failed."
                ),
                evidence=integration_contracts.stdout,
                priority="P0",
            )
            semantic_oracle = _run(
                [
                    sys.executable,
                    "-I",
                    (
                        "/oracle/scripts/verify_phase5e2b12a_semantic_oracle.py"
                        if protected_mode
                        else str(
                            repository
                            / "scripts/verify_phase5e2b12a_semantic_oracle.py"
                        )
                    ),
                    *(["--frozen-contract-replay"] if frozen_replay else []),
                ],
                cwd=repository,
                environment=environment,
            )
            _record(
                checks,
                findings,
                check_id="phase5e2b12a-independent-semantic-oracle",
                passed=semantic_oracle.returncode == 0,
                summary="Phase 5E-2B.1-2A independent trust-boundary oracle failed.",
                evidence=semantic_oracle.stdout,
                priority="P0",
            )
        elif profile.profile_kind == "legacy_2b":
            frozen_contract_replay = _run(
                [
                    sys.executable,
                    str(
                        repository
                        / "scripts/verify_phase5e2b12a_integration_contracts.py"
                    ),
                    "--frozen-contract-replay",
                ],
                cwd=repository,
                environment=environment,
            )
            _record(
                checks,
                findings,
                check_id="phase5e2b12a-frozen-contract-replay",
                passed=frozen_contract_replay.returncode == 0,
                summary="Frozen Phase 5E-2B.1-2A contract replay failed under 2B.",
                evidence=frozen_contract_replay.stdout,
                priority="P0",
            )
            successor_semantic_oracle = _run(
                [
                    sys.executable,
                    "-I",
                    (
                        f"/oracle/{profile.semantic_oracle_path}"
                        if protected_mode
                        else str(controller_root / profile.semantic_oracle_path)
                    ),
                    "--repository",
                    str(repository),
                ],
                cwd=repository,
                environment=environment,
            )
            _record(
                checks,
                findings,
                check_id="phase5e2b12b-independent-semantic-oracle",
                passed=successor_semantic_oracle.returncode == 0,
                summary=(
                    "Phase 5E-2B.1-2B control-owned production-behavior oracle failed."
                ),
                evidence=successor_semantic_oracle.stdout,
                priority="P0",
            )
        elif profile.profile_kind == "successor_bootstrap":
            successor_bundle = _run_direct(
                [
                    sys.executable,
                    "-I",
                    str(controller_root / "scripts/verify_phase5e_successor_gate.py"),
                    "--repository",
                    str(repository),
                    "--validate-bundle-ref",
                    "HEAD",
                ],
                cwd=repository,
                environment=environment,
            )
            _record(
                checks,
                findings,
                check_id="phase5e-successor-gate-bundle-validation",
                passed=successor_bundle.returncode == 0,
                summary="Protected successor-gate bundle validation failed.",
                evidence=successor_bundle.stdout,
                priority="P0",
            )
            successor_oracle = _run_direct(
                [
                    sys.executable,
                    "-I",
                    str(
                        controller_root
                        / "scripts/verify_phase5e_successor_gate_oracle.py"
                    ),
                    "--repository",
                    str(repository),
                    "--controller-root",
                    str(controller_root),
                    "--controller-ref",
                    str(controller_before["head"]),
                    "--candidate-ref",
                    str(research_before["head"]),
                ],
                cwd=repository,
                environment=environment,
            )
            _record(
                checks,
                findings,
                check_id="phase5e-successor-gate-independent-structural-oracle",
                passed=successor_oracle.returncode == 0,
                summary="Independent successor-gate structural oracle failed.",
                evidence=successor_oracle.stdout,
                priority="P0",
            )
        elif profile.profile_kind in {"successor_dynamic", "successor_transition"}:
            successor_structural_oracle, successor_behavior_oracle = (
                _run_dynamic_successor_oracles(
                    repository=repository,
                    controller_root=controller_root,
                    controller_ref=str(controller_before["head"]),
                    candidate_ref=str(research_before["head"]),
                    profile=profile,
                    environment=environment,
                    protected_mode=protected_mode,
                    controller_integrity_passed=controller_integrity_passed,
                )
            )
            behavior_passed = (
                successor_behavior_oracle is not None
                and successor_behavior_oracle.returncode == 0
            )
            behavior_evidence = (
                successor_behavior_oracle.stdout
                if successor_behavior_oracle is not None
                else "not-started: controller integrity or structural oracle failed"
            )
            _record(
                checks,
                findings,
                check_id="phase5e-successor-independent-semantic-oracle",
                passed=(
                    controller_integrity_passed
                    and profile.semantic_oracle_sha256
                    == audit_trust["semantic_oracle_sha256"]
                    and successor_structural_oracle.returncode == 0
                    and behavior_passed
                ),
                summary=(
                    "Protected independent successor structural or production-behavior "
                    "replay failed."
                ),
                evidence=(
                    "structural oracle:\n"
                    + successor_structural_oracle.stdout
                    + "\nbehavior oracle:\n"
                    + behavior_evidence
                ),
                priority="P0",
            )
        elif profile.profile_kind == "sealed_controller_reauthorization":
            exact_controller_head = (
                controller_before["head"]
                == research_before["head"]
                == args.reviewed_commit
            )
            sealed_oracle: subprocess.CompletedProcess[str] | None = None
            if controller_integrity_passed and exact_controller_head:
                oracle_path = (
                    "/oracle/scripts/verify_phase5e_successor_gate_oracle.py"
                    if protected_mode
                    else str(
                        controller_root
                        / "scripts/verify_phase5e_successor_gate_oracle.py"
                    )
                )
                controller_argument = repository if protected_mode else controller_root
                sealed_oracle = _run(
                    [
                        sys.executable,
                        "-I",
                        oracle_path,
                        "--repository",
                        str(repository),
                        "--controller-root",
                        str(controller_argument),
                        "--controller-ref",
                        research_before["head"],
                        "--candidate-ref",
                        research_before["head"],
                        "--verify-sealed-controller-ref",
                    ],
                    cwd=repository,
                    environment=environment,
                )
            _record(
                checks,
                findings,
                check_id="phase5e-successor-controller-reauthorization-boundary",
                passed=(
                    controller_integrity_passed
                    and exact_controller_head
                    and sealed_oracle is not None
                    and sealed_oracle.returncode == 0
                ),
                summary=(
                    "The sealed 2C-0 Controller boundary is not one exact, "
                    "independently replayed protected head."
                ),
                evidence=(
                    sealed_oracle.stdout
                    if sealed_oracle is not None
                    else "not-started: controller integrity or exact-head identity failed"
                ),
                priority="P0",
            )
        elif profile.profile_kind == "external_feasibility":
            external_boundary = _run_direct(
                [
                    sys.executable,
                    "-I",
                    str(
                        controller_root
                        / "scripts/verify_phase5e_successor_gate_oracle.py"
                    ),
                    "--repository",
                    str(repository),
                    "--controller-root",
                    str(controller_root),
                    "--controller-ref",
                    str(controller_before["head"]),
                    "--candidate-ref",
                    str(research_before["head"]),
                ],
                cwd=repository,
                environment=environment,
            )
            _record(
                checks,
                findings,
                check_id="phase5e-successor-independent-semantic-oracle",
                passed=external_boundary.returncode == 0,
                summary=(
                    "External Futu feasibility handoff did not advance exactly from "
                    "the protected G5 boundary to 2C-0 G1."
                ),
                evidence=external_boundary.stdout,
                priority="P0",
            )
        else:  # pragma: no cover - closed AuditProfile kind.
            raise RuntimeError(f"unsupported Phase 5E profile: {profile.profile_kind}")
        synchronized_resign_oracle = (
            _run(
                [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_synchronized_artifact_and_handoffs_cannot_authorize_outside_graph_root",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_graph_owned_root_without_exact_human_review_chain_is_rejected",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_synchronized_resign_cannot_hide_duplicate_phase5c_review_identity",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_synchronized_resign_cannot_reuse_phase5c_review_chain_across_bindings",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_synchronized_resign_cannot_add_unreviewed_blocked_phase5c_binding",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_synchronized_resign_cannot_hide_reviewed_blocked_binding",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + (
                    "::test_synchronized_resign_cannot_hide_positive_option_root_"
                    "by_treatment_or_identity"
                ),
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_distinct_confirmed_excluded_bindings_close_with_unique_review_chains",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_each_phase5c_review_reference_is_one_to_one",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_phase5c_root_fact_cannot_be_bound_twice",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_confirmed_phase5c_binding_requires_each_review_reference",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_phase5c_identity_kind_matrix_matches_frozen_accounting_policy",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_synchronized_resign_cannot_duplicate_phase5c_consumption_record",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_synchronized_resign_cannot_duplicate_phase5c_option_role_root",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_synchronized_resign_cannot_add_unique_phase5c_consumption_record",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_synchronized_resign_cannot_add_unbound_phase5c_consumption_root",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_claim_authority_rejects_a_superseded_freeze_run",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_claim_authority_rejects_two_active_freeze_runs",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_freeze_handoff_chain_must_be_exactly_owned_by_current_graph",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_component_lock_drift_invalidates_graph_owned_claim_authority",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_claim_authority_ignores_unrelated_graph_history_"
                "but_rejects_missing_review_object",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_claim_authority_cannot_be_transplanted_into_bundle_from_another_graph",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_bundle_closure_is_independent_of_unrelated_graph_history",
                str(repository / "tests/test_phase5e2b12a_integration_contracts.py")
                + "::test_same_graph_claim_sensitive_authority_closes_bundle_and_outer_evidence",
            ],
                cwd=repository,
                environment=environment,
            )
            if profile.profile_kind in {"legacy_2a", "legacy_2a_recovery"}
            else subprocess.CompletedProcess([], 0, "", None)
        )
        if profile.profile_kind in {"legacy_2a", "legacy_2a_recovery"}:
            _record(
                checks,
                findings,
                check_id="phase5e2b12a-synchronized-resign-attack-oracle",
                passed=synchronized_resign_oracle.returncode == 0,
                summary=(
                    "Synchronized artifact/Handoff resign escaped the graph-owned authority gate."
                ),
                evidence=synchronized_resign_oracle.stdout,
                priority="P0",
            )
        authority_oracle = _run(
            [sys.executable, str(repository / "scripts/verify_market_access_authority.py")],
            cwd=repository,
            environment=environment,
        )
        _record(
            checks,
            findings,
            check_id="independent-market-authority-oracle",
            passed=authority_oracle.returncode == 0,
            summary="Independent market-authority hash and calendar oracle failed.",
            evidence=authority_oracle.stdout,
            priority="P0",
        )
        test_counts = independent_counts

    research_after = _tracked_manifest(repository)
    kernel_after = (
        _file_tree_manifest(interface)
        if interface is not None
        else _tracked_manifest(kernel)
    )
    immutable = research_after == research_before and kernel_after == kernel_before
    _record(
        checks,
        findings,
        check_id="tracked-bytes-immutable",
        passed=immutable,
        summary=(
            "Audit execution changed research or kernel tracked bytes, refs, "
            "remotes, or status."
        ),
        evidence=json.dumps(
            {
                "research_before": research_before,
                "research_after": research_after,
                "kernel_before": kernel_before,
                "kernel_after": kernel_after,
            },
            sort_keys=True,
        ),
        priority="P0",
    )
    after = research_after["status"]
    _record(
        checks,
        findings,
        check_id="clean-after",
        passed=not after,
        summary="Verification modified the audit checkout.",
        evidence=after or "clean",
        priority="P0",
    )
    check_ids = tuple(sorted(item["check_id"] for item in checks))
    if (
        len(check_ids) != len(set(check_ids))
        or set(check_ids) != profile.expected_check_ids
    ):
        raise RuntimeError("Phase 5E audit check identity set drifted")
    payload: dict[str, Any] = {
        "audit_tool": AUDIT_TOOL,
        "audit_profile": profile.profile_id,
        "audit_version": profile.audit_version,
        "reviewed_commit": args.reviewed_commit,
        "phase5d_baseline_commit": PHASE5D_BASELINE,
        "phase5e0_baseline_commit": PHASE5E0_BASELINE,
        "phase5e11_baseline_commit": PHASE5E11_BASELINE,
        "phase5e2a_baseline_commit": PHASE5E2A_BASELINE,
        "phase5e2b10_baseline_commit": PHASE5E2B10_BASELINE,
        "phase5e2b11_baseline_commit": PHASE5E2B11_BASELINE,
        "valuation_kernel_commit": KERNEL_BASELINE,
        "runtime_identity": runtime_identity,
        "audit_trust": audit_trust,
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "audited_file_sha256": {
            relative: hashlib.sha256((repository / relative).read_bytes()).hexdigest()
            for relative in existing
        },
        "test_counts": test_counts,
        "check_ids": check_ids,
        "check_ids_sha256": audit_check_ids_sha256(check_ids),
        "checks": checks,
        "findings": findings,
    }
    _write_bytes_exclusive(args.output.with_name("phase5e-independent.xml"), independent_junit_raw)
    _write_bytes_exclusive(args.output.with_name("phase5e-nodeids.txt"), nodeid_bytes)
    _write_json_exclusive(args.output, payload)
    return 1 if _has_blocking_findings(findings) else 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except BaseException as audit_error:
        _emergency_failure(sys.argv[1:], audit_error)
        raise
    raise SystemExit(exit_code)
