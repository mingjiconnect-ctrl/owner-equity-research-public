#!/usr/bin/env python3
"""Base-owned structural and remote-evidence gate for the 2A acceptance-only PR.

The pull-request-target workflow executes this file from the protected base commit.  It reads the
candidate head through Git object plumbing and never imports or executes candidate-head code.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent


def _load_public_bootstrap_module() -> Any:
    """Load the sibling bootstrap verifier without trusting import search paths."""

    path = _SCRIPT_DIR / "public_bootstrap.py"
    if path.is_symlink() or not path.is_file() or path.parent != _SCRIPT_DIR:
        raise RuntimeError("public bootstrap verifier is not a regular local file")
    name = "_phase5e_public_bootstrap"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("public bootstrap verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    prior = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if prior is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = prior
        raise
    return module


_PUBLIC_BOOTSTRAP_MODULE = _load_public_bootstrap_module()
commit_exists = _PUBLIC_BOOTSTRAP_MODULE.commit_exists
public_root_commit = _PUBLIC_BOOTSTRAP_MODULE.public_root_commit
verify_public_bootstrap_snapshot = _PUBLIC_BOOTSTRAP_MODULE.verify_public_bootstrap_snapshot


def _load_absolute_control_module(path: Path, name: str) -> Any:
    """Load one protected controller module without trusting ``sys.modules`` or ``PYTHONPATH``."""

    if path.is_symlink() or not path.is_file() or path.parent != _SCRIPT_DIR:
        raise RuntimeError(f"protected control module is not a regular local file: {path.name}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"protected control module cannot be loaded: {path.name}")
    module = importlib.util.module_from_spec(spec)
    prior = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if prior is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = prior
        raise
    return module


_AUDIT_PROFILES_MODULE = _load_absolute_control_module(
    _SCRIPT_DIR / "phase5e_audit_profiles.py",
    "_phase5e_protected_audit_profiles",
)
AUDIT_TOOL = _AUDIT_PROFILES_MODULE.AUDIT_TOOL
AuditProfile = _AUDIT_PROFILES_MODULE.AuditProfile
PHASE5E2B12A_AUDIT_PROFILE = _AUDIT_PROFILES_MODULE.PHASE5E2B12A_AUDIT_PROFILE
PHASE5E2B12B_AUDIT_PROFILE = _AUDIT_PROFILES_MODULE.PHASE5E2B12B_AUDIT_PROFILE
audit_profile = _AUDIT_PROFILES_MODULE.audit_profile
audit_profile_context_sha256 = _AUDIT_PROFILES_MODULE.audit_profile_context_sha256
audit_profile_policy_sha256 = _AUDIT_PROFILES_MODULE.audit_profile_policy_sha256
resolve_controller_audit_profile = _AUDIT_PROFILES_MODULE.resolve_controller_audit_profile
resolve_controller_gate_position = _AUDIT_PROFILES_MODULE.resolve_controller_gate_position

_CURRENT_AUDIT_PROFILE = audit_profile(PHASE5E2B12A_AUDIT_PROFILE)

TRUST_SNAPSHOT_PATH = Path(__file__).with_name("phase5e2b12a-acceptance-trust.json")
_TRUST_SNAPSHOT_KEYS = frozenset(
    {
        "schema_version",
        "controller_authority",
        "expected_audit_check_ids",
        "external_gate_authority",
        "external_feasibility_receipt_authority",
        "futu_market_authority_policy",
        "kernel_baseline",
        "kernel_reader_authority",
        "phase5d_baseline",
        "phase5e0_baseline",
        "phase5e11_baseline",
        "phase5e2a_baseline",
        "phase5e2b10_baseline",
        "phase5e2b11_baseline",
        "static_control_files",
        "successor_gate_files",
    }
)
_trust_raw = TRUST_SNAPSHOT_PATH.read_bytes()
_TRUST = json.loads(_trust_raw)
if (
    not isinstance(_TRUST, dict)
    or set(_TRUST) != _TRUST_SNAPSHOT_KEYS
    or _TRUST.get("schema_version") != "4.0.0"
    or _trust_raw
    != (json.dumps(_TRUST, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
):
    raise RuntimeError("Phase 5E-2B.1-2A acceptance trust snapshot is malformed")
_controller_authority = _TRUST["controller_authority"]
_CONTROLLER_AUTHORITY_KEYS = {
    "status",
    "app_id",
    "app_slug",
    "installation_id",
    "controller_environment",
    "app_id_variable",
    "private_key_secret",
    "account_id",
    "account_login",
    "account_type",
    "repository_id",
    "repository",
    "repository_selection",
    "permissions",
    "events",
}
if (
    not isinstance(_controller_authority, dict)
    or set(_controller_authority) != _CONTROLLER_AUTHORITY_KEYS
    or _controller_authority.get("status") not in {"bootstrap_pending", "pinned"}
    or _controller_authority.get("controller_environment")
    != "phase5e-controller-main-only"
    or _controller_authority.get("app_id_variable") != "PHASE5E_CONTROLLER_APP_ID"
    or _controller_authority.get("private_key_secret")
    != "PHASE5E_CONTROLLER_PRIVATE_KEY"
    or _controller_authority.get("account_id") != 263841576
    or _controller_authority.get("account_login") != "mingjiconnect-ctrl"
    or _controller_authority.get("account_type") != "User"
    or _controller_authority.get("repository_id") != 1312436919
    or _controller_authority.get("repository")
    != "mingjiconnect-ctrl/owner-equity-research-public"
    or _controller_authority.get("repository_selection") != "selected"
    or _controller_authority.get("permissions")
    != {
        "actions": "read",
        "actions_variables": "read",
        "administration": "read",
        "contents": "read",
        "environments": "read",
        "metadata": "read",
        "pull_requests": "read",
        "secrets": "read",
        "statuses": "write",
    }
    or _controller_authority.get("events") != []
):
    raise RuntimeError("Phase 5E controller authority trust is malformed")
CONTROLLER_AUTHORITY_STATUS = str(_controller_authority["status"])
PINNED_CONTROLLER_APP_ID = _controller_authority["app_id"]
PINNED_CONTROLLER_APP_SLUG = _controller_authority["app_slug"]
PINNED_CONTROLLER_INSTALLATION_ID = _controller_authority["installation_id"]
CONTROLLER_ACCOUNT_ID = int(_controller_authority["account_id"])
CONTROLLER_ACCOUNT_LOGIN = str(_controller_authority["account_login"])
CONTROLLER_ACCOUNT_TYPE = str(_controller_authority["account_type"])
CONTROLLER_REPOSITORY_ID = int(_controller_authority["repository_id"])
CONTROLLER_REPOSITORY = str(_controller_authority["repository"])
CONTROLLER_REPOSITORY_SELECTION = str(_controller_authority["repository_selection"])
CONTROLLER_PERMISSIONS = dict(_controller_authority["permissions"])
CONTROLLER_EVENTS = list(_controller_authority["events"])
if CONTROLLER_AUTHORITY_STATUS == "pinned":
    if (
        type(PINNED_CONTROLLER_APP_ID) is not int
        or PINNED_CONTROLLER_APP_ID <= 0
        or not isinstance(PINNED_CONTROLLER_APP_SLUG, str)
        or not PINNED_CONTROLLER_APP_SLUG
        or type(PINNED_CONTROLLER_INSTALLATION_ID) is not int
        or PINNED_CONTROLLER_INSTALLATION_ID <= 0
    ):
        raise RuntimeError("pinned Phase 5E controller authority is incomplete")
elif any(
    value is not None
    for value in (
        PINNED_CONTROLLER_APP_ID,
        PINNED_CONTROLLER_APP_SLUG,
        PINNED_CONTROLLER_INSTALLATION_ID,
    )
):
    raise RuntimeError("pending Phase 5E controller authority must not self-assign an identity")

_external_gate_authority = _TRUST["external_gate_authority"]
_EXTERNAL_GATE_AUTHORITY_KEYS = {
    "status",
    "app_id",
    "app_slug",
    "installation_id",
    "account_id",
    "account_login",
    "account_type",
    "repository_id",
    "repository",
    "repository_selection",
    "permissions",
    "events",
    "environment",
    "app_id_variable",
    "private_key_secret",
    "reserved_branch",
}
if (
    not isinstance(_external_gate_authority, dict)
    or set(_external_gate_authority) != _EXTERNAL_GATE_AUTHORITY_KEYS
    or _external_gate_authority.get("status") not in {"bootstrap_pending", "pinned"}
    or _external_gate_authority.get("account_id") != 263841576
    or _external_gate_authority.get("account_login") != "mingjiconnect-ctrl"
    or _external_gate_authority.get("account_type") != "User"
    or _external_gate_authority.get("repository_id") != 1312436919
    or _external_gate_authority.get("repository")
    != "mingjiconnect-ctrl/owner-equity-research-public"
    or _external_gate_authority.get("repository_selection") != "selected"
    or _external_gate_authority.get("permissions")
    != {"contents": "write", "metadata": "read", "pull_requests": "write"}
    or _external_gate_authority.get("events") != []
    or _external_gate_authority.get("environment")
    != "phase5e-external-gate-author"
    or _external_gate_authority.get("app_id_variable")
    != "PHASE5E_EXTERNAL_GATE_AUTHOR_APP_ID"
    or _external_gate_authority.get("private_key_secret")
    != "PHASE5E_EXTERNAL_GATE_AUTHOR_PRIVATE_KEY"
    or _external_gate_authority.get("reserved_branch")
    != "feature/phase5e2c0-controller-gate-bootstrap"
):
    raise RuntimeError("Phase 5E external gate-author authority trust is malformed")
EXTERNAL_GATE_AUTHORITY_STATUS = str(_external_gate_authority["status"])
PINNED_EXTERNAL_GATE_AUTHOR_APP_ID = _external_gate_authority["app_id"]
PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG = _external_gate_authority["app_slug"]
PINNED_EXTERNAL_GATE_AUTHOR_INSTALLATION_ID = _external_gate_authority[
    "installation_id"
]
EXTERNAL_GATE_AUTHOR_ENVIRONMENT = str(_external_gate_authority["environment"])
EXTERNAL_GATE_AUTHOR_APP_ID_VARIABLE = str(_external_gate_authority["app_id_variable"])
EXTERNAL_GATE_AUTHOR_PRIVATE_KEY_SECRET = str(
    _external_gate_authority["private_key_secret"]
)
if EXTERNAL_GATE_AUTHORITY_STATUS == "pinned":
    if (
        type(PINNED_EXTERNAL_GATE_AUTHOR_APP_ID) is not int
        or PINNED_EXTERNAL_GATE_AUTHOR_APP_ID <= 0
        or not isinstance(PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG, str)
        or not PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG
        or type(PINNED_EXTERNAL_GATE_AUTHOR_INSTALLATION_ID) is not int
        or PINNED_EXTERNAL_GATE_AUTHOR_INSTALLATION_ID <= 0
    ):
        raise RuntimeError("pinned Phase 5E external gate-author authority is incomplete")
elif any(
    value is not None
    for value in (
        PINNED_EXTERNAL_GATE_AUTHOR_APP_ID,
        PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG,
        PINNED_EXTERNAL_GATE_AUTHOR_INSTALLATION_ID,
    )
):
    raise RuntimeError("pending external gate-author authority must not self-assign identity")

_receipt_authority = _TRUST["external_feasibility_receipt_authority"]
_RECEIPT_AUTHORITY_KEYS = {
    "status",
    "algorithm",
    "condition_coverage",
    "domain",
    "max_validity_seconds",
    "required_order",
    "signers",
}
_RECEIPT_SIGNER_KEYS = {"key_id", "public_key_hex"}
if (
    not isinstance(_receipt_authority, dict)
    or set(_receipt_authority) != _RECEIPT_AUTHORITY_KEYS
    or _receipt_authority.get("status") not in {"bootstrap_pending", "pinned"}
    or _receipt_authority.get("algorithm") != "ed25519"
    or _receipt_authority.get("domain")
    != "owner-equity-research/phase5e2cp/receipt/v1"
    or _receipt_authority.get("condition_coverage")
    != {
        "legal": [
            "account_agreement_permits_internal_valuation_use",
            "data_rights_permit_private_encrypted_cas_retention_and_independent_audit_replay",
        ],
        "account": ["qot_login_true_while_trade_login_false_is_enforceable"],
        "protocol": ["raw_protobuf_s2c_bytes_are_stably_capturable"],
    }
    or _receipt_authority.get("max_validity_seconds") != 86400
    or _receipt_authority.get("required_order") != ["legal", "account", "protocol"]
    or not isinstance(_receipt_authority.get("signers"), dict)
    or set(_receipt_authority["signers"]) != {"legal", "account", "protocol"}
    or any(
        not isinstance(value, dict) or set(value) != _RECEIPT_SIGNER_KEYS
        for value in _receipt_authority["signers"].values()
    )
):
    raise RuntimeError("Phase 5E external feasibility receipt authority is malformed")
EXTERNAL_RECEIPT_AUTHORITY_STATUS = str(_receipt_authority["status"])
EXTERNAL_RECEIPT_DOMAIN = str(_receipt_authority["domain"])
EXTERNAL_RECEIPT_MAX_VALIDITY_SECONDS = int(
    _receipt_authority["max_validity_seconds"]
)
EXTERNAL_RECEIPT_SIGNERS = {
    str(kind): dict(value) for kind, value in _receipt_authority["signers"].items()
}
if EXTERNAL_RECEIPT_AUTHORITY_STATUS == "pinned":
    key_ids: set[str] = set()
    public_keys: set[str] = set()
    for signer in EXTERNAL_RECEIPT_SIGNERS.values():
        key_id = signer.get("key_id")
        public_key = signer.get("public_key_hex")
        if (
            not isinstance(key_id, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", key_id)
            or not isinstance(public_key, str)
            or re.fullmatch(r"[0-9a-f]{64}", public_key) is None
            or key_id in key_ids
            or public_key in public_keys
        ):
            raise RuntimeError("pinned feasibility receipt signer authority is incomplete")
        key_ids.add(key_id)
        public_keys.add(public_key)
elif any(
    signer.get("key_id") is not None or signer.get("public_key_hex") is not None
    for signer in EXTERNAL_RECEIPT_SIGNERS.values()
):
    raise RuntimeError("pending feasibility receipt authority must not self-assign keys")

_futu_policy = _TRUST["futu_market_authority_policy"]
if (
    not isinstance(_futu_policy, dict)
    or set(_futu_policy) != {"path", "sha256", "overlay_path", "overlay_sha256"}
    or _futu_policy.get("path")
    != "scripts/phase5e-futu-market-authority-policy-v1.json"
    or _futu_policy.get("overlay_path") != "docs/phase5-completion-overlay-v3.md"
    or not isinstance(_futu_policy.get("sha256"), str)
    or not isinstance(_futu_policy.get("overlay_sha256"), str)
):
    raise RuntimeError("Phase 5E Futu market-authority policy trust is malformed")
FUTU_MARKET_POLICY_PATH = str(_futu_policy["path"])
FUTU_MARKET_POLICY_SHA256 = str(_futu_policy["sha256"])
FUTU_MARKET_OVERLAY_PATH = str(_futu_policy["overlay_path"])
FUTU_MARKET_OVERLAY_SHA256 = str(_futu_policy["overlay_sha256"])
for relative, digest in (
    (FUTU_MARKET_POLICY_PATH, FUTU_MARKET_POLICY_SHA256),
    (FUTU_MARKET_OVERLAY_PATH, FUTU_MARKET_OVERLAY_SHA256),
):
    target = Path(__file__).resolve().parents[1] / relative
    if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        raise RuntimeError("Phase 5E Futu market-authority policy bytes drifted")

_kernel_reader_authority = _TRUST["kernel_reader_authority"]
_KERNEL_READER_AUTHORITY_KEYS = {
    "status",
    "environment",
    "app_id_variable",
    "private_key_secret",
    "app_id",
    "app_slug",
    "installation_id",
    "account_id",
    "account_login",
    "account_type",
    "repository_id",
    "repository",
    "repository_selection",
    "permissions",
    "events",
}
if (
    not isinstance(_kernel_reader_authority, dict)
    or set(_kernel_reader_authority) != _KERNEL_READER_AUTHORITY_KEYS
    or _kernel_reader_authority.get("status") not in {"bootstrap_pending", "pinned"}
    or _kernel_reader_authority.get("environment")
    != "phase5e-private-kernel-readonly"
    or _kernel_reader_authority.get("app_id_variable")
    != "PHASE5E_KERNEL_READER_APP_ID"
    or _kernel_reader_authority.get("private_key_secret")
    != "PHASE5E_KERNEL_READER_PRIVATE_KEY"
    or _kernel_reader_authority.get("account_id") != 263841576
    or _kernel_reader_authority.get("account_login") != "mingjiconnect-ctrl"
    or _kernel_reader_authority.get("account_type") != "User"
    or _kernel_reader_authority.get("repository_id") != 1296284659
    or _kernel_reader_authority.get("repository")
    != "mingjiconnect-ctrl/owner-valuation-kernel"
    or _kernel_reader_authority.get("repository_selection") != "selected"
    or _kernel_reader_authority.get("permissions")
    != {"contents": "read", "metadata": "read"}
    or _kernel_reader_authority.get("events") != []
):
    raise RuntimeError("Phase 5E kernel-reader authority trust is malformed")
KERNEL_READER_AUTHORITY_STATUS = str(_kernel_reader_authority["status"])
PINNED_KERNEL_READER_APP_ID = _kernel_reader_authority["app_id"]
PINNED_KERNEL_READER_APP_SLUG = _kernel_reader_authority["app_slug"]
PINNED_KERNEL_READER_INSTALLATION_ID = _kernel_reader_authority["installation_id"]
KERNEL_READER_ACCOUNT_ID = int(_kernel_reader_authority["account_id"])
KERNEL_READER_ACCOUNT_LOGIN = str(_kernel_reader_authority["account_login"])
KERNEL_READER_ACCOUNT_TYPE = str(_kernel_reader_authority["account_type"])
KERNEL_READER_REPOSITORY_ID = int(_kernel_reader_authority["repository_id"])
KERNEL_READER_REPOSITORY = str(_kernel_reader_authority["repository"])
KERNEL_READER_REPOSITORY_SELECTION = str(
    _kernel_reader_authority["repository_selection"]
)
KERNEL_READER_PERMISSIONS = dict(_kernel_reader_authority["permissions"])
KERNEL_READER_EVENTS = list(_kernel_reader_authority["events"])
if KERNEL_READER_AUTHORITY_STATUS == "pinned":
    if (
        type(PINNED_KERNEL_READER_APP_ID) is not int
        or PINNED_KERNEL_READER_APP_ID <= 0
        or not isinstance(PINNED_KERNEL_READER_APP_SLUG, str)
        or not PINNED_KERNEL_READER_APP_SLUG
        or type(PINNED_KERNEL_READER_INSTALLATION_ID) is not int
        or PINNED_KERNEL_READER_INSTALLATION_ID <= 0
    ):
        raise RuntimeError("pinned Phase 5E kernel-reader authority is incomplete")
elif any(
    value is not None
    for value in (
        PINNED_KERNEL_READER_APP_ID,
        PINNED_KERNEL_READER_APP_SLUG,
        PINNED_KERNEL_READER_INSTALLATION_ID,
    )
):
    raise RuntimeError("pending Phase 5E kernel-reader authority must not self-assign an identity")
if {
    CONTROLLER_AUTHORITY_STATUS,
    EXTERNAL_GATE_AUTHORITY_STATUS,
    KERNEL_READER_AUTHORITY_STATUS,
} == {"pinned"}:
    for label, identities in (
        (
            "App ID",
            (
                PINNED_CONTROLLER_APP_ID,
                PINNED_EXTERNAL_GATE_AUTHOR_APP_ID,
                PINNED_KERNEL_READER_APP_ID,
            ),
        ),
        (
            "App slug",
            (
                PINNED_CONTROLLER_APP_SLUG,
                PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG,
                PINNED_KERNEL_READER_APP_SLUG,
            ),
        ),
        (
            "installation ID",
            (
                PINNED_CONTROLLER_INSTALLATION_ID,
                PINNED_EXTERNAL_GATE_AUTHOR_INSTALLATION_ID,
                PINNED_KERNEL_READER_INSTALLATION_ID,
            ),
        ),
    ):
        if len(set(identities)) != 3:
            raise RuntimeError(f"Phase 5E authority reuses a privileged {label}")
EXPECTED_AUDIT_CHECK_IDS = frozenset(_TRUST["expected_audit_check_ids"])
if EXPECTED_AUDIT_CHECK_IDS != _CURRENT_AUDIT_PROFILE.expected_check_ids:
    raise RuntimeError("2A trust snapshot and protected audit profile disagree")
KERNEL_BASELINE = str(_TRUST["kernel_baseline"])
PHASE5D_BASELINE = str(_TRUST["phase5d_baseline"])
PHASE5E0_BASELINE = str(_TRUST["phase5e0_baseline"])
PHASE5E11_BASELINE = str(_TRUST["phase5e11_baseline"])
PHASE5E2A_BASELINE = str(_TRUST["phase5e2a_baseline"])
PHASE5E2B10_BASELINE = str(_TRUST["phase5e2b10_baseline"])
PHASE5E2B11_BASELINE = str(_TRUST["phase5e2b11_baseline"])
STATIC_CONTROL_FILES = frozenset(_TRUST["static_control_files"])
SUCCESSOR_GATE_FILES = {
    str(path): str(digest) for path, digest in _TRUST["successor_gate_files"].items()
}


def _trusted_successor_surface_path(control_root: Path, relative: str) -> Path:
    """Resolve the bounded control surface inside the candidate pivot root."""

    if control_root == Path("/oracle") and relative.startswith("tests/"):
        return Path("/work") / relative
    return control_root / relative


_SUCCESSOR_CONTROL_ROOT = Path(__file__).resolve().parents[1]
if (
    not SUCCESSOR_GATE_FILES
    or any(
        not _trusted_successor_surface_path(_SUCCESSOR_CONTROL_ROOT, relative).is_file()
        or hashlib.sha256(
            _trusted_successor_surface_path(_SUCCESSOR_CONTROL_ROOT, relative).read_bytes()
        ).hexdigest()
        != digest
        for relative, digest in SUCCESSOR_GATE_FILES.items()
    )
):
    raise RuntimeError("preinstalled Phase 5E-2B.1-2B gate bytes drifted")

AUDIT_VERSION = _CURRENT_AUDIT_PROFILE.audit_version
EXPECTED_TEST_COUNT = 1374
EXPECTED_NODEID_SHA256 = "eab85a4981f3fdcfe841c5e730af10f3e2b50ce41c617f3f9204b17a7ba4a79b"
REQUIRED_AUDITED_PATHS = frozenset(
    {
        ".github/workflows/phase5e2b12a-acceptance-gate.yml",
        "component-lock.json",
        "scripts/phase5e-audit-requirements.lock",
        "scripts/phase5e-audit-runtime-matrix.json",
        "scripts/phase5e-audit-wheelhouse.sha256",
        "scripts/phase5e_audit_profiles.py",
        "scripts/launch_phase5e_readonly_audit.sh",
        "scripts/phase5e_candidate_exec.sh",
        "scripts/run_phase5e_audit.py",
        "scripts/pytest_phase5e_nodeids.py",
        "scripts/phase5e2b12a-acceptance-trust.json",
        "docs/phase5-completion-overlay-v3.md",
        "scripts/phase5e-futu-market-authority-policy-v1.json",
        "scripts/verify_phase5e2b12a_acceptance_gate.py",
        "scripts/verify_phase5e2b12a_integration_contracts.py",
        "scripts/verify_phase5e2b12a_semantic_oracle.py",
        "scripts/phase5e2b12b-acceptance-trust.json",
        "scripts/phase5e-successor-gate-bundle.schema.json",
        "scripts/verify_phase5e2b12b_acceptance_gate.py",
        "scripts/verify_phase5e2b12b_semantic_oracle.py",
        "scripts/verify_phase5e_candidate_import_surface.py",
        "scripts/verify_phase5e_successor_gate.py",
        "scripts/verify_phase5e_successor_gate_oracle.py",
        "scripts/verify_phase5e2b12c_semantic_oracle.py",
        "scripts/verify_phase5e2c0_semantic_oracle.py",
        "scripts/verify_phase5e_audit_runtime_matrix.py",
        "src/owner_research/resources/current_share/canonical-event-integration-policy.json",
        "src/owner_research/valuation_share_event_integration_types.py",
        "tests/test_phase5e2b12a_integration_contracts.py",
        "tests/test_phase5e2b12b_acceptance_gate.py",
        "tests/test_phase5e_successor_gate.py",
    }
)
CLOSEOUT_PATH = "docs/phase5e2b12a-acceptance-closeout.json"
STATUS_PATH = "docs/phase-status.json"
PUBLIC_REVALIDATION_PATH = "docs/public-phase5e2b12a-revalidation.json"
PUBLIC_REVALIDATION_BRANCH = "fix/phase5e2b12a-r2-coverage-claim-parity"
PUBLIC_REVALIDATION_ORIGINAL_PAYLOAD = {
    "kind": "public_canonical_audit_revalidation",
    "phase": "Phase 5E-2B.1-2A",
    "public_repository": "mingjiconnect-ctrl/owner-equity-research-public",
    "reason_code": "public-controller-bootstrap-revalidation",
    "release_tag": None,
    "schema_version": "1.0.0",
}
PUBLIC_REVALIDATION_GENERATION2_PAYLOAD = {
    **PUBLIC_REVALIDATION_ORIGINAL_PAYLOAD,
    "generation": 2,
    "prior_reason_code": "public-controller-bootstrap-revalidation",
    "reason_code": "pull-request-target-run-metadata-revalidation",
}
PUBLIC_REVALIDATION_GENERATION3_PAYLOAD = {
    **PUBLIC_REVALIDATION_GENERATION2_PAYLOAD,
    "generation": 3,
    "prior_reason_code": "pull-request-target-run-metadata-revalidation",
    "reason_code": "acceptance-first-parent-topology-revalidation",
}
PUBLIC_REVALIDATION_GENERATION4_PAYLOAD = {
    **PUBLIC_REVALIDATION_GENERATION3_PAYLOAD,
    "generation": 4,
    "prior_reason_code": "acceptance-first-parent-topology-revalidation",
    "reason_code": "public-acceptance-path-registration-revalidation",
}
PUBLIC_REVALIDATION_LEGACY_PAYLOAD = {
    **PUBLIC_REVALIDATION_GENERATION4_PAYLOAD,
    "generation": 5,
    "prior_reason_code": "public-acceptance-path-registration-revalidation",
    "reason_code": "public-acceptance-status-registration-revalidation",
}
PUBLIC_REVALIDATION_GENERATION6_PAYLOAD = {
    **PUBLIC_REVALIDATION_LEGACY_PAYLOAD,
    "generation": 6,
    "prior_reason_code": "public-acceptance-status-registration-revalidation",
    "reason_code": "public-commit-status-url-identity-revalidation",
}
PUBLIC_REVALIDATION_GENERATION7_PAYLOAD = {
    **PUBLIC_REVALIDATION_GENERATION6_PAYLOAD,
    "generation": 7,
    "prior_reason_code": "public-commit-status-url-identity-revalidation",
    "reason_code": "public-audit-inventory-trust-root-revalidation",
}
PUBLIC_REVALIDATION_PAYLOAD = {
    **PUBLIC_REVALIDATION_GENERATION7_PAYLOAD,
    "generation": 8,
    "prior_reason_code": "public-audit-inventory-trust-root-revalidation",
    "reason_code": "public-acceptance-audit-inventory-parity-revalidation",
}
POST_IMPLEMENTATION_CONTROL_REVALIDATION_PATHS = frozenset(
    {
        PUBLIC_REVALIDATION_PATH,
        "scripts/phase5e2b12a-acceptance-trust.json",
        "scripts/verify_phase5e2b12a_acceptance_gate.py",
        "tests/test_phase5e2b12a_acceptance_gate.py",
    }
)
MUTABLE_GOVERNANCE_PATHS = frozenset(
    {
        STATUS_PATH,
        CLOSEOUT_PATH,
    }
)
PENDING_ACCEPTANCE_TRUST_ROOT = frozenset(
    {
        ".github/workflows/ci.yml",
        ".github/workflows/phase5e2b12a-acceptance-gate.yml",
        STATUS_PATH,
        CLOSEOUT_PATH,
        "scripts/pytest_phase5e_nodeids.py",
        "scripts/phase5e2b12a-acceptance-trust.json",
        "docs/phase5-completion-overlay-v3.md",
        "scripts/phase5e-futu-market-authority-policy-v1.json",
        "scripts/phase5e-audit-requirements.lock",
        "scripts/phase5e-audit-runtime-matrix.json",
        "scripts/phase5e-audit-wheelhouse.sha256",
        "scripts/phase5e_audit_profiles.py",
        "scripts/launch_phase5e_readonly_audit.sh",
        "scripts/phase5e_candidate_exec.sh",
        "scripts/run_phase5e_audit.py",
        "scripts/verify_phase5e2b12a_acceptance_gate.py",
        "scripts/write_phase5e_audit.py",
        "scripts/phase5e2b12b-acceptance-trust.json",
        "scripts/phase5e-successor-gate-bundle.schema.json",
        "scripts/verify_phase5e2b12b_acceptance_gate.py",
        "scripts/verify_phase5e2b12b_semantic_oracle.py",
        "scripts/verify_phase5e_candidate_import_surface.py",
        "scripts/verify_phase5e_successor_gate.py",
        "scripts/verify_phase5e_successor_gate_oracle.py",
        "scripts/verify_phase5e2b12c_semantic_oracle.py",
        "scripts/verify_phase5e2c0_semantic_oracle.py",
        "scripts/verify_phase5e_audit_runtime_matrix.py",
        "tests/test_phase5e2b12b_acceptance_gate.py",
        "tests/test_phase5e_successor_gate.py",
    }
)
# Once the acceptance-only PR has created its immutable closeout, later phases must be able to
# advance the generic phase state, CI matrix, and shared audit runner.  The base-owned gate itself,
# its verifier, and the historical evidence record remain permanently immutable; successor phases
# install their own base-owned gates instead of rewriting this one.
PERMANENT_ACCEPTED_TRUST_ROOT = frozenset(
    {
        ".github/workflows/phase5e2b12a-acceptance-gate.yml",
        CLOSEOUT_PATH,
        "scripts/phase5e-audit-requirements.lock",
        "scripts/phase5e-audit-runtime-matrix.json",
        "scripts/phase5e-audit-wheelhouse.sha256",
        "scripts/phase5e_audit_profiles.py",
        "scripts/launch_phase5e_readonly_audit.sh",
        "scripts/phase5e_candidate_exec.sh",
        "scripts/phase5e2b12a-acceptance-trust.json",
        "docs/phase5-completion-overlay-v3.md",
        "scripts/phase5e-futu-market-authority-policy-v1.json",
        "scripts/verify_phase5e2b12a_acceptance_gate.py",
        "scripts/phase5e2b12b-acceptance-trust.json",
        "scripts/phase5e-successor-gate-bundle.schema.json",
        "scripts/verify_phase5e2b12b_acceptance_gate.py",
        "scripts/verify_phase5e2b12b_semantic_oracle.py",
        "scripts/verify_phase5e_candidate_import_surface.py",
        "scripts/verify_phase5e_successor_gate.py",
        "scripts/verify_phase5e_successor_gate_oracle.py",
        "scripts/verify_phase5e2b12c_semantic_oracle.py",
        "scripts/verify_phase5e2c0_semantic_oracle.py",
        "scripts/verify_phase5e_audit_runtime_matrix.py",
        "tests/test_phase5e2b12b_acceptance_gate.py",
        "tests/test_phase5e_successor_gate.py",
    }
)
# Compatibility alias for existing callers that mean the pre-acceptance trust root.
FROZEN_ACCEPTANCE_TRUST_ROOT = PENDING_ACCEPTANCE_TRUST_ROOT
MANDATORY_CHANGED_PATHS = MUTABLE_GOVERNANCE_PATHS
EXPECTED_CLOSEOUT_KEYS = frozenset(
    {
        "schema_version",
        "phase",
        "implementation_pull_request",
        "implementation_head_commit",
        "implementation_merge_commit",
        "implementation_tree_sha",
        "acceptance_pull_request",
        "pr_ci_run_id",
        "main_ci_run_id",
        "audit_workflow_id",
        "audit_tool",
        "audit_profile",
        "audit_version",
        "audit_report_sha256",
        "audit_artifact_sha256",
        "test_inventory_sha256",
        "runtime_matrix_sha256",
        "audit_wheelhouse_manifest_sha256",
        "controller_app_id",
        "controller_app_slug",
        "controller_installation_id",
        "test_count",
    }
)
PENDING_PROHIBITED = (
    "Phase 5E-2B.1-2B",
    "Phase 5E-2B.1-2C",
    "Phase 5E-2B.1-3",
    "Phase 5E-2C",
    "Phase 5E-2D",
    "Phase 5E-2E",
    "Phase 5E-2F",
    "Phase 5E-3",
    "Phase 5E-4",
    "Phase 5E-5",
    "Phase 5E-6",
    "Phase 5F",
    "Phase 6",
    "Phase 7",
    "Phase 8",
    "Phase 9",
)
ACCEPTED_PROHIBITED = tuple(
    item for item in PENDING_PROHIBITED if item != "Phase 5E-2B.1-2B"
)
# Compatibility alias for pending-acceptance callers.
EXPECTED_PROHIBITED = PENDING_PROHIBITED
PENDING_AUTHORIZED_NEXT = ("Phase 5E-2B.1-2A acceptance closeout",)
ACCEPTED_AUTHORIZED_NEXT = (
    "Phase 5E-2B.1-2B canonical-event roll-forward implementation",
)
EXPECTED_FINDINGS_KEYS = frozenset(
    {
        "audit_tool",
        "audit_profile",
        "audit_version",
        "reviewed_commit",
        "phase5d_baseline_commit",
        "phase5e0_baseline_commit",
        "phase5e11_baseline_commit",
        "phase5e2a_baseline_commit",
        "phase5e2b10_baseline_commit",
        "phase5e2b11_baseline_commit",
        "valuation_kernel_commit",
        "runtime_identity",
        "audit_trust",
        "started_at",
        "finished_at",
        "audited_file_sha256",
        "test_counts",
        "check_ids",
        "check_ids_sha256",
        "checks",
        "findings",
    }
)
EXPECTED_REPORT_KEYS = frozenset(
    {
        "reviewed_commit",
        "phase5d_baseline_commit",
        "phase5e0_baseline_commit",
        "phase5e11_baseline_commit",
        "phase5e2a_baseline_commit",
        "phase5e2b10_baseline_commit",
        "phase5e2b11_baseline_commit",
        "valuation_kernel_commit",
        "audit_trust",
        "audit_tool",
        "audit_profile",
        "audit_version",
        "started_at",
        "finished_at",
        "finding_counts",
        "test_counts",
        "audited_file_sha256",
        "test_inventory_sha256",
        "runtime_matrix_sha256",
        "audit_wheelhouse_manifest_sha256",
        "runtime_results",
        "check_ids",
        "check_ids_sha256",
        "check_count",
        "ci_run_ids",
        "report_sha256",
    }
)


def _check_ids_sha256(check_ids: tuple[str, ...]) -> str:
    return hashlib.sha256(("\n".join(check_ids) + "\n").encode()).hexdigest()


EXPECTED_TEST_COUNT_KEYS = frozenset(
    {
        "collected_tests",
        "passed_tests",
        "skipped_tests",
        "failed_tests",
    }
)
EXPECTED_BASELINE_FIELDS = {
    "phase5d_baseline_commit": PHASE5D_BASELINE,
    "phase5e0_baseline_commit": PHASE5E0_BASELINE,
    "phase5e11_baseline_commit": PHASE5E11_BASELINE,
    "phase5e2a_baseline_commit": PHASE5E2A_BASELINE,
    "phase5e2b10_baseline_commit": PHASE5E2B10_BASELINE,
    "phase5e2b11_baseline_commit": PHASE5E2B11_BASELINE,
    "valuation_kernel_commit": KERNEL_BASELINE,
}

EXPECTED_AUDIT_TRUST_KEYS = frozenset(
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

_JUNIT_FAILURE_TAGS = frozenset({"failure", "error", "skipped"})
_NONNEGATIVE_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
GITHUB_ACTIONS_APP_ID = 15368
CONTROLLER_APP_ID_VARIABLE = "PHASE5E_CONTROLLER_APP_ID"
CONTROLLER_ENVIRONMENT_NAME = "phase5e-controller-main-only"
KERNEL_ENVIRONMENT_NAME = "phase5e-private-kernel-readonly"
CONTROLLER_PRIVATE_KEY_SECRET = "PHASE5E_CONTROLLER_PRIVATE_KEY"
CONTROLLER_APP_JWT_ENV = "PHASE5E_CONTROLLER_APP_JWT"
KERNEL_READER_APP_ID_VARIABLE = "PHASE5E_KERNEL_READER_APP_ID"
KERNEL_READER_PRIVATE_KEY_SECRET = "PHASE5E_KERNEL_READER_PRIVATE_KEY"
KERNEL_READER_APP_JWT_ENV = "PHASE5E_KERNEL_READER_APP_JWT"
EXTERNAL_GATE_AUTHOR_APP_JWT_ENV = "PHASE5E_EXTERNAL_GATE_AUTHOR_APP_JWT"
EXTERNAL_CONTROLLER_BRANCH = "feature/phase5e2c0-controller-gate-bootstrap"
EXTERNAL_HANDOFF_PATH = (
    "governance/phase5e-external/phase5e2cp-controller-handoff.json"
)
GITHUB_ACTIONS_CHECKS = frozenset(
    {
        "phase5e/actions-status-token-revoked",
        "verify (3.11)",
        "verify (3.12)",
        "verify (3.13)",
    }
)
CONTROLLER_APP_CHECKS = frozenset(
    {
        "phase5e/controller-readonly-audit",
        "phase5e/controller-structure",
    }
)
REQUIRED_PROTECTION_CHECKS = GITHUB_ACTIONS_CHECKS | CONTROLLER_APP_CHECKS
CONTROLLER_APP_INSTALLATION_PERMISSIONS = {
    "actions": "read",
    "actions_variables": "read",
    "administration": "read",
    "contents": "read",
    "environments": "read",
    "metadata": "read",
    "pull_requests": "read",
    "secrets": "read",
    "statuses": "write",
}


def _canonical_nonnegative_integer(value: object) -> bool:
    return (
        isinstance(value, str) and value.isascii() and value.isdigit() and str(int(value)) == value
    )


def _canonical_nonnegative_decimal(value: object) -> bool:
    return isinstance(value, str) and _NONNEGATIVE_DECIMAL.fullmatch(value) is not None


def _nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _sha256(value: object) -> bool:
    return isinstance(value, str) and _LOWER_SHA256.fullmatch(value) is not None


def _git_oid(value: object) -> bool:
    return isinstance(value, str) and _LOWER_GIT_OID.fullmatch(value) is not None


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _strict_junit_tree(root: ET.Element) -> bool:
    if root.tag != "testsuites" or root.attrib != {"name": "pytest tests"}:
        return False
    suites = tuple(root)
    if len(suites) != 1:
        return False
    suite = suites[0]
    expected_suite_attributes = {
        "name",
        "errors",
        "failures",
        "skipped",
        "tests",
        "time",
        "timestamp",
        "hostname",
    }
    if (
        suite.tag != "testsuite"
        or set(suite.attrib) != expected_suite_attributes
        or suite.attrib["name"] != "pytest"
        or any(suite.attrib[key] != "0" for key in ("errors", "failures", "skipped"))
        or not _canonical_nonnegative_integer(suite.attrib["tests"])
        or not _canonical_nonnegative_decimal(suite.attrib["time"])
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
            or not _canonical_nonnegative_decimal(testcase.attrib["time"])
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


def _git(repository: Path, *args: str, text: bool = True) -> str | bytes:
    output = subprocess.check_output(
        ["git", "-C", str(repository), *args],
        text=text,
    )
    return output.strip() if text else output


def _run_protected_structural_gate(
    *,
    relative_script: str,
    repository: Path,
    base: str,
    head: str,
    event: dict[str, Any],
    repository_slug: str,
) -> None:
    """Run a hash-bound successor gate in a fresh isolated interpreter.

    The acceptance controller never imports successor code into its own interpreter.  This avoids
    candidate-controlled ``sys.modules`` state, package shadowing, or mutated module globals from
    becoming part of the trust boundary.
    """

    expected_sha = SUCCESSOR_GATE_FILES.get(relative_script)
    script = Path(__file__).resolve().parents[1] / relative_script
    if (
        expected_sha is None
        or script.is_symlink()
        or not script.is_file()
        or hashlib.sha256(script.read_bytes()).hexdigest() != expected_sha
        or not _git_oid(base)
        or not _git_oid(head)
    ):
        raise SystemExit("protected successor gate identity is invalid")
    canonical_event = (
        json.dumps(event, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    with tempfile.TemporaryDirectory(prefix="phase5e-controller-event-") as directory:
        event_path = Path(directory) / "event.json"
        event_path.write_bytes(canonical_event)
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(script),
                "--repository",
                str(repository.resolve()),
                "--base",
                base,
                "--head",
                head,
                "--event-json",
                str(event_path),
                "--repository-slug",
                repository_slug,
                "--structural-only",
            ],
            cwd="/",
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            capture_output=True,
            check=False,
            timeout=120,
        )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SystemExit(f"protected successor structural gate failed: {message}")
    if completed.stdout not in {b"", b"\n"}:
        raise SystemExit("protected successor structural gate emitted unexpected output")


def _read_hash_bound_control_json(relative_path: str) -> dict[str, Any]:
    expected_sha = SUCCESSOR_GATE_FILES.get(relative_path)
    path = Path(__file__).resolve().parents[1] / relative_path
    if (
        expected_sha is None
        or path.is_symlink()
        or not path.is_file()
        or hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha
    ):
        raise SystemExit("protected controller JSON identity is invalid")
    raw = path.read_bytes()

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = child
        return value

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit("protected controller JSON is not strict UTF-8 JSON") from exc
    if (
        not isinstance(value, dict)
        or raw
        != (json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    ):
        raise SystemExit("protected controller JSON is not canonical")
    return value


def _resolve_legacy_successor_state(repository: Path, ref: str) -> str:
    relative_script = "scripts/verify_phase5e2b12b_acceptance_gate.py"
    expected_sha = SUCCESSOR_GATE_FILES.get(relative_script)
    script = Path(__file__).resolve().parents[1] / relative_script
    if (
        expected_sha is None
        or script.is_symlink()
        or not script.is_file()
        or hashlib.sha256(script.read_bytes()).hexdigest() != expected_sha
        or not _git_oid(ref)
    ):
        raise SystemExit("protected legacy successor gate identity is invalid")
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(script),
            "--repository",
            str(repository.resolve()),
            "--describe-state-ref",
            ref,
        ],
        cwd="/",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        capture_output=True,
        check=False,
        timeout=120,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SystemExit(f"protected legacy successor state resolution failed: {message}")
    value = completed.stdout.decode("ascii", errors="strict").strip()
    if value not in {"s0", "s1", "s2", "s3", "invalid"}:
        raise SystemExit("protected legacy successor state output is malformed")
    return value


def _commit_parents(repository: Path, commit: str) -> tuple[str, ...]:
    parts = str(_git(repository, "show", "-s", "--format=%P", commit)).split()
    return tuple(parts)


def _tree(repository: Path, commit: str) -> str:
    return str(_git(repository, "rev-parse", f"{commit}^{{tree}}"))


def _read_json(repository: Path, commit: str, path: str) -> dict[str, Any]:
    raw = subprocess.check_output(["git", "-C", str(repository), "show", f"{commit}:{path}"])

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise SystemExit(f"{path} contains a duplicate JSON key: {key}")
            value[key] = child
        return value

    def reject_nonfinite_constant(token: str) -> None:
        raise SystemExit(f"{path} contains a non-finite JSON constant: {token}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{path} is not canonical UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} is not a JSON object")
    try:
        canonical = (json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    except ValueError as exc:
        raise SystemExit(f"{path} contains a non-finite JSON number") from exc
    if raw != canonical:
        raise SystemExit(f"{path} is not canonically serialized")
    return value


def _path_exists(repository: Path, commit: str, path: str) -> bool:
    return bool(str(_git(repository, "ls-tree", commit, "--", path)))


def protected_controller_audit_profile(repository: Path, base: str) -> AuditProfile:
    """Derive the audit subject from the protected controller commit only."""

    return resolve_controller_audit_profile(
        repository,
        base,
        has_2a_closeout=_path_exists(repository, base, CLOSEOUT_PATH),
    )


def _governance_state_matches(
    status: dict[str, Any],
    *,
    current_phase: str,
    state: str,
    authorized_next: tuple[str, ...],
    prohibited: tuple[str, ...],
) -> bool:
    return (
        status.get("current_phase") == current_phase
        and status.get("status") == state
        and status.get("authorized_next") == list(authorized_next)
        and status.get("prohibited") == list(prohibited)
        and status.get("release_tag") is None
        and not (set(authorized_next) & set(prohibited))
    )


def _accepted_closeout_has_closed_shape(closeout: dict[str, Any]) -> bool:
    return (
        set(closeout) == EXPECTED_CLOSEOUT_KEYS
        and closeout.get("schema_version") == "1.0.0"
        and closeout.get("phase") == "Phase 5E-2B.1-2A"
        and closeout.get("audit_tool") == AUDIT_TOOL
        and closeout.get("audit_profile") == PHASE5E2B12A_AUDIT_PROFILE
        and closeout.get("audit_version") == AUDIT_VERSION
        and type(closeout.get("implementation_pull_request")) is int
        and closeout["implementation_pull_request"] > 0
        and type(closeout.get("acceptance_pull_request")) is int
        and closeout["acceptance_pull_request"] > 0
        and type(closeout.get("test_count")) is int
        and closeout["test_count"] > 0
        and all(
            _git_oid(closeout.get(field))
            for field in (
                "implementation_head_commit",
                "implementation_merge_commit",
                "implementation_tree_sha",
            )
        )
        and all(
            _sha256(closeout.get(field))
            for field in (
                "audit_report_sha256",
                "audit_artifact_sha256",
                "test_inventory_sha256",
                "runtime_matrix_sha256",
                "audit_wheelhouse_manifest_sha256",
            )
        )
        and all(
            isinstance(closeout.get(field), str) and closeout[field].isdigit()
            for field in ("pr_ci_run_id", "main_ci_run_id")
        )
        and type(closeout.get("audit_workflow_id")) is int
        and closeout["audit_workflow_id"] > 0
        and type(closeout.get("controller_app_id")) is int
        and closeout["controller_app_id"] > 0
        and isinstance(closeout.get("controller_app_slug"), str)
        and re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?",
            closeout["controller_app_slug"],
        )
        is not None
        and type(closeout.get("controller_installation_id")) is int
        and closeout["controller_installation_id"] > 0
    )


def _load_canonical_evidence_json(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise SystemExit(f"{label} contains a duplicate JSON key: {key}")
            value[key] = child
        return value

    def reject_nonfinite_constant(token: str) -> None:
        raise SystemExit(f"{label} contains a non-finite JSON constant: {token}")

    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{label} is not canonical UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{label} is not a JSON object")
    try:
        canonical = (json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    except ValueError as exc:
        raise SystemExit(f"{label} contains a non-finite JSON number") from exc
    if raw != canonical:
        raise SystemExit(f"{label} is not canonically serialized")
    return value


def _diff_entries(repository: Path, base: str, head: str) -> tuple[tuple[str, str], ...]:
    output = str(
        _git(
            repository,
            "diff",
            "--name-status",
            "--no-renames",
            base,
            head,
            "--",
        )
    )
    entries: list[tuple[str, str]] = []
    for line in output.splitlines():
        status, path = line.split("\t", 1)
        entries.append((status, path))
    return tuple(entries)


def _mode(repository: Path, commit: str, path: str) -> str:
    output = str(_git(repository, "ls-tree", commit, "--", path))
    if not output:
        raise SystemExit(f"missing acceptance path: {path}")
    return output.split()[0]


def _api_json(url: str, token: str) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.github.com"
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.fragment)
        or not parsed.path.startswith("/")
    ):
        raise SystemExit("authenticated GitHub API URL escaped its fixed authority")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "owner-research-phase5e2b12a-acceptance-gate",
        },
    )
    try:
        with urllib.request.build_opener(_NoCredentialRedirect()).open(
            request,
            timeout=30,
        ) as response:
            value = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code in {301, 302, 303, 307, 308}:
            raise SystemExit("authenticated GitHub API response attempted a redirect") from exc
        raise
    if not isinstance(value, dict):
        raise SystemExit("GitHub API response is not an object")
    return value


def _api_graphql_repository_merge_settings(
    repository_slug: str,
    token: str,
) -> tuple[bool, bool, bool]:
    """Read the three repository merge-mode booleans through GitHub GraphQL."""

    if repository_slug.count("/") != 1:
        raise SystemExit("repository slug is not canonical")
    owner, name = repository_slug.split("/", 1)
    if not owner or not name:
        raise SystemExit("repository slug is not canonical")
    payload = json.dumps(
        {
            "query": (
                "query($owner:String!,$name:String!){"
                "repository(owner:$owner,name:$name){"
                "mergeCommitAllowed squashMergeAllowed rebaseMergeAllowed"
                "}}"
            ),
            "variables": {"name": name, "owner": owner},
        },
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    request = urllib.request.Request(
        "https://api.github.com/graphql",
        data=payload,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "owner-research-phase5e2b12a-acceptance-gate",
        },
        method="POST",
    )
    try:
        with urllib.request.build_opener(_NoCredentialRedirect()).open(
            request,
            timeout=30,
        ) as response:
            value = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code in {301, 302, 303, 307, 308}:
            raise SystemExit("authenticated GitHub GraphQL response redirected") from exc
        raise
    if (
        not isinstance(value, dict)
        or set(value) != {"data"}
        or not isinstance(value.get("data"), dict)
        or set(value["data"]) != {"repository"}
        or not isinstance(value["data"].get("repository"), dict)
    ):
        raise SystemExit("GitHub GraphQL merge-policy response is malformed")
    repository = value["data"]["repository"]
    expected = {
        "mergeCommitAllowed",
        "squashMergeAllowed",
        "rebaseMergeAllowed",
    }
    if set(repository) != expected or any(
        type(repository[field]) is not bool for field in expected
    ):
        raise SystemExit("GitHub GraphQL merge-policy response is malformed")
    return (
        repository["mergeCommitAllowed"],
        repository["squashMergeAllowed"],
        repository["rebaseMergeAllowed"],
    )


def _api_paginated_items(
    url: str,
    *,
    key: str,
    token: str,
) -> tuple[dict[str, Any], ...]:
    items: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    expected_total: int | None = None
    separator = "&" if "?" in url else "?"
    for page in range(1, 101):
        response = _api_json(
            f"{url}{separator}per_page=100&page={page}",
            token,
        )
        total = response.get("total_count")
        batch = response.get(key)
        if (
            not isinstance(total, int)
            or isinstance(total, bool)
            or total < 0
            or not isinstance(batch, list)
            or len(batch) > 100
        ):
            raise SystemExit(f"GitHub {key} pagination response is malformed")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise SystemExit(f"GitHub {key} pagination total changed during replay")
        for item in batch:
            item_id = item.get("id") if isinstance(item, dict) else None
            if not isinstance(item_id, int) or isinstance(item_id, bool) or item_id in seen_ids:
                raise SystemExit(f"GitHub {key} pagination identity is ambiguous")
            seen_ids.add(item_id)
            items.append(item)
        if len(items) > expected_total:
            raise SystemExit(f"GitHub {key} pagination exceeds declared total")
        if len(items) == expected_total:
            return tuple(items)
        if len(batch) < 100:
            raise SystemExit(f"GitHub {key} pagination is incomplete")
    raise SystemExit(f"GitHub {key} pagination exceeds audit limit")


class _NoCredentialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


_INSTALLATION_TOKEN_REVOCATION_PROBE_DELAYS_SECONDS = (0.0, 1.0, 1.0, 2.0, 4.0, 4.0)


def _hard_revoke_installation_token(token: str) -> None:
    """Revoke one App installation token and prove the same token becomes unusable."""

    endpoint = "https://api.github.com/installation/token"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "owner-research-phase5e2b12a-acceptance-gate",
    }
    opener = urllib.request.build_opener(_NoCredentialRedirect())
    delete = urllib.request.Request(endpoint, headers=headers, method="DELETE")
    try:
        with opener.open(delete, timeout=30) as response:
            if response.status != 204:
                raise SystemExit("installation token revocation did not return HTTP 204")
    except urllib.error.HTTPError as exc:
        raise SystemExit("installation token revocation did not return HTTP 204") from exc

    probe = urllib.request.Request(
        "https://api.github.com/installation/repositories",
        headers=headers,
        method="GET",
    )
    for delay_seconds in _INSTALLATION_TOKEN_REVOCATION_PROBE_DELAYS_SECONDS:
        if delay_seconds:
            time.sleep(delay_seconds)
        try:
            with opener.open(probe, timeout=30) as response:
                if response.status != 200:
                    raise SystemExit(
                        "revoked installation token probe returned an unexpected success status"
                    )
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                return
            raise SystemExit("revoked installation token did not fail with HTTP 401") from exc
    raise SystemExit("revoked installation token remained usable after bounded propagation probes")


def _api_bytes(url: str, token: str) -> bytes:
    parsed_api = urllib.parse.urlsplit(url)
    if parsed_api.scheme != "https" or parsed_api.hostname != "api.github.com":
        raise SystemExit("artifact metadata URL is outside the GitHub API authority")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "owner-research-phase5e2b12a-acceptance-gate",
        },
    )
    opener = urllib.request.build_opener(_NoCredentialRedirect())
    try:
        opener.open(request, timeout=30)
    except urllib.error.HTTPError as exc:
        if exc.code not in {301, 302, 303, 307, 308}:
            raise
        location = exc.headers.get("Location")
    else:
        raise SystemExit("artifact API did not return its expected signed redirect")
    parsed_download = urllib.parse.urlsplit(location or "")
    hostname = parsed_download.hostname or ""
    if (
        parsed_download.scheme != "https"
        or parsed_download.username is not None
        or parsed_download.password is not None
        or not (
            hostname.endswith(".blob.core.windows.net")
            or hostname.endswith(".actions.githubusercontent.com")
            or hostname.endswith(".githubusercontent.com")
        )
    ):
        raise SystemExit("artifact redirect escaped the bounded GitHub storage authority")
    download = urllib.request.Request(
        location,
        headers={
            "User-Agent": "owner-research-phase5e2b12a-acceptance-gate",
        },
    )
    try:
        with urllib.request.build_opener(_NoCredentialRedirect()).open(
            download,
            timeout=30,
        ) as response:
            if response.geturl() != location:
                raise SystemExit("artifact storage response changed its signed authority")
            payload = response.read(10 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in {301, 302, 303, 307, 308}:
            raise SystemExit("artifact storage response attempted a second redirect") from exc
        raise
    if len(payload) > 10 * 1024 * 1024:
        raise SystemExit("audit artifact archive exceeds its fixed size bound")
    return payload


def _api_list(url: str, token: str) -> list[dict[str, Any]]:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.github.com"
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.fragment)
        or not parsed.path.startswith("/")
    ):
        raise SystemExit("authenticated GitHub API URL escaped its fixed authority")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "owner-research-phase5e2b12a-acceptance-gate",
        },
    )
    try:
        with urllib.request.build_opener(_NoCredentialRedirect()).open(
            request,
            timeout=30,
        ) as response:
            value = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code in {301, 302, 303, 307, 308}:
            raise SystemExit("authenticated GitHub API response attempted a redirect") from exc
        raise
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise SystemExit("GitHub API response is not an object list")
    return value


def _api_paginated_list(url: str, token: str) -> list[dict[str, Any]]:
    """Load a bounded GitHub list endpoint without trusting the first page."""

    items: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    separator = "&" if "?" in url else "?"
    for page in range(1, 101):
        batch = _api_list(f"{url}{separator}per_page=100&page={page}", token)
        for item in batch:
            item_id = item.get("id")
            if type(item_id) is not int or item_id <= 0 or item_id in seen_ids:
                raise SystemExit("GitHub list pagination identity is ambiguous")
            seen_ids.add(item_id)
            items.append(item)
        if len(batch) < 100:
            return items
    raise SystemExit("GitHub list pagination exceeds the fixed page bound")


def _verify_scoped_controller_token_identity(
    repository_slug: str,
    token: str,
    *,
    controller_app_id: int,
) -> tuple[int, str]:
    repositories = _api_json("https://api.github.com/installation/repositories", token)
    scoped_repositories = repositories.get("repositories")
    if (
        controller_app_id != PINNED_CONTROLLER_APP_ID
        or type(repositories.get("total_count")) is not int
        or repositories.get("total_count") != 1
        or not isinstance(scoped_repositories, list)
        or len(scoped_repositories) != 1
        or scoped_repositories[0].get("full_name") != repository_slug
    ):
        raise SystemExit("controller App token authority or repository scope is invalid")
    return PINNED_CONTROLLER_INSTALLATION_ID, PINNED_CONTROLLER_APP_SLUG


def _api_paginated_collection(
    url: str,
    token: str,
    *,
    collection_key: str,
    per_page: int,
    identity_key: str | None = None,
    expected_metadata: dict[str, object] | None = None,
) -> tuple[dict[str, Any], ...]:
    items: list[dict[str, Any]] = []
    seen_identities: set[int] = set()
    expected_total: int | None = None
    metadata = expected_metadata or {}
    expected_keys = {"total_count", collection_key, *metadata}
    separator = "&" if "?" in url else "?"
    for page in range(1, 101):
        payload = _api_json(f"{url}{separator}per_page={per_page}&page={page}", token)
        if (
            not isinstance(payload, dict)
            or set(payload) != expected_keys
            or any(payload.get(key) != value for key, value in metadata.items())
        ):
            raise SystemExit(f"GitHub {collection_key} page has an open or malformed shape")
        total_count = payload.get("total_count")
        batch = payload.get(collection_key)
        if (
            type(total_count) is not int
            or total_count < 0
            or not isinstance(batch, list)
            or len(batch) > per_page
            or any(not isinstance(item, dict) for item in batch)
        ):
            raise SystemExit(f"GitHub {collection_key} pagination metadata is malformed")
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            raise SystemExit(f"GitHub {collection_key} total count drifted across pages")
        for item in batch:
            if identity_key is not None:
                identity = item.get(identity_key)
                if (
                    type(identity) is not int
                    or identity <= 0
                    or identity in seen_identities
                ):
                    raise SystemExit(
                        f"GitHub {collection_key} pagination identity is ambiguous"
                    )
                seen_identities.add(identity)
            items.append(dict(item))
        if len(items) > expected_total:
            raise SystemExit(f"GitHub {collection_key} pages exceed their declared total")
        if len(items) == expected_total:
            return tuple(items)
        if not batch or len(batch) < per_page:
            raise SystemExit(f"GitHub {collection_key} pagination ended before its declared total")
    raise SystemExit(f"GitHub {collection_key} pagination exceeds the fixed page bound")


def _secret_inventory(url: str, token: str) -> frozenset[str]:
    resources = _api_paginated_collection(
        url,
        token,
        collection_key="secrets",
        per_page=100,
    )
    if any(
        set(item) != {"name", "created_at", "updated_at"}
        or not _nonempty_string(item.get("name"))
        or not _nonempty_string(item.get("created_at"))
        or not _nonempty_string(item.get("updated_at"))
        for item in resources
    ):
        raise SystemExit("GitHub secret inventory has an open or malformed item")
    names = [str(item["name"]) for item in resources]
    if len(names) != len(set(names)):
        raise SystemExit("GitHub secret inventory contains duplicate names")
    return frozenset(names)


def _variable_inventory(url: str, token: str) -> dict[str, str]:
    resources = _api_paginated_collection(
        url,
        token,
        collection_key="variables",
        per_page=30,
    )
    if any(
        set(item) != {"name", "value", "created_at", "updated_at"}
        or not _nonempty_string(item.get("name"))
        or not isinstance(item.get("value"), str)
        or not _nonempty_string(item.get("created_at"))
        or not _nonempty_string(item.get("updated_at"))
        for item in resources
    ):
        raise SystemExit("GitHub variable inventory has an open or malformed item")
    values = {str(item["name"]): str(item["value"]) for item in resources}
    if len(values) != len(resources):
        raise SystemExit("GitHub variable inventory contains duplicate names")
    return values


def _verify_single_repository_app_authority(
    token: str,
    *,
    app_jwt: str,
    app_id: int,
    app_slug: str,
    installation_id: int,
    expected_account_id: int,
    expected_account_login: str,
    expected_account_type: str,
    expected_repository_id: int,
    expected_repository: str,
    expected_repository_selection: str,
    expected_private: bool,
    expected_permissions: dict[str, str],
    expected_events: list[object],
    label: str,
) -> None:
    """Prove App-global, installation-global, and exact one-repository authority."""

    app = _api_json("https://api.github.com/app", app_jwt)
    app_owner = app.get("owner")
    if (
        app.get("id") != app_id
        or app.get("slug") != app_slug
        or app.get("permissions") != expected_permissions
        or app.get("events") != expected_events
        or not isinstance(app_owner, dict)
        or app_owner.get("id") != expected_account_id
        or app_owner.get("login") != expected_account_login
        or app_owner.get("type") != expected_account_type
    ):
        raise SystemExit(f"{label} App-global authority is invalid")
    app_installations = _api_paginated_list(
        "https://api.github.com/app/installations",
        app_jwt,
    )
    if len(app_installations) != 1:
        raise SystemExit(f"{label} App must have exactly one global installation")
    global_installation = app_installations[0]
    global_account = global_installation.get("account")
    if (
        global_installation.get("id") != installation_id
        or global_installation.get("app_id") != app_id
        or global_installation.get("app_slug") != app_slug
        or global_installation.get("repository_selection")
        != expected_repository_selection
        or global_installation.get("permissions") != expected_permissions
        or global_installation.get("events") != expected_events
        or global_installation.get("suspended_at") is not None
        or global_installation.get("suspended_by") is not None
        or global_installation.get("target_type") != expected_account_type
        or not isinstance(global_account, dict)
        or global_account.get("id") != expected_account_id
        or global_account.get("login") != expected_account_login
        or global_account.get("type") != expected_account_type
    ):
        raise SystemExit(f"{label} global installation authority is invalid")

    repositories = _api_paginated_collection(
        "https://api.github.com/installation/repositories",
        token,
        collection_key="repositories",
        per_page=100,
        identity_key="id",
        expected_metadata={
            "repository_selection": expected_repository_selection,
        },
    )
    if len(repositories) != 1:
        raise SystemExit(f"{label} App must be installed on exactly one repository")
    repository = repositories[0]
    owner = repository.get("owner")
    if (
        repository.get("id") != expected_repository_id
        or repository.get("full_name") != expected_repository
        or repository.get("private") is not expected_private
        or repository.get("fork") is not False
        or repository.get("archived") is not False
        or repository.get("disabled") is not False
        or repository.get("default_branch") != "main"
        or not isinstance(owner, dict)
        or owner.get("id") != expected_account_id
        or owner.get("login") != expected_account_login
        or owner.get("type") != expected_account_type
    ):
        raise SystemExit(f"{label} repository scope or identity is invalid")
    direct_repository = _api_json(
        f"https://api.github.com/repos/{expected_repository}",
        token,
    )
    if any(
        direct_repository.get(key) != repository.get(key)
        for key in (
            "id",
            "full_name",
            "private",
            "fork",
            "archived",
            "disabled",
            "default_branch",
        )
    ):
        raise SystemExit(f"{label} direct repository identity does not replay")


def _verify_controller_token_authority(
    token: str,
    *,
    app_jwt: str,
    app_id: int,
    app_slug: str,
    installation_id: int,
) -> None:
    if CONTROLLER_AUTHORITY_STATUS != "pinned":
        raise SystemExit("dedicated Phase 5E controller authority bootstrap is still pending")
    if (
        type(app_id) is not int
        or app_id != PINNED_CONTROLLER_APP_ID
        or app_id in {GITHUB_ACTIONS_APP_ID, PINNED_KERNEL_READER_APP_ID,
                      PINNED_EXTERNAL_GATE_AUTHOR_APP_ID}
        or app_slug != PINNED_CONTROLLER_APP_SLUG
        or installation_id != PINNED_CONTROLLER_INSTALLATION_ID
    ):
        raise SystemExit("controller action outputs do not match the pinned authority")
    _verify_single_repository_app_authority(
        token,
        app_jwt=app_jwt,
        app_id=app_id,
        app_slug=app_slug,
        installation_id=installation_id,
        expected_account_id=CONTROLLER_ACCOUNT_ID,
        expected_account_login=CONTROLLER_ACCOUNT_LOGIN,
        expected_account_type=CONTROLLER_ACCOUNT_TYPE,
        expected_repository_id=CONTROLLER_REPOSITORY_ID,
        expected_repository=CONTROLLER_REPOSITORY,
        expected_repository_selection=CONTROLLER_REPOSITORY_SELECTION,
        expected_private=False,
        expected_permissions=CONTROLLER_PERMISSIONS,
        expected_events=CONTROLLER_EVENTS,
        label="controller",
    )


def _verify_external_gate_author_token_authority(
    token: str,
    *,
    app_jwt: str,
    app_id: int,
    app_slug: str,
    installation_id: int,
) -> None:
    if EXTERNAL_GATE_AUTHORITY_STATUS != "pinned":
        raise SystemExit("external gate-author App authority bootstrap is still pending")
    if (
        type(app_id) is not int
        or app_id != PINNED_EXTERNAL_GATE_AUTHOR_APP_ID
        or app_id in {GITHUB_ACTIONS_APP_ID, PINNED_CONTROLLER_APP_ID,
                      PINNED_KERNEL_READER_APP_ID}
        or app_slug != PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG
        or installation_id != PINNED_EXTERNAL_GATE_AUTHOR_INSTALLATION_ID
    ):
        raise SystemExit("external gate-author action outputs do not match pinned authority")
    _verify_single_repository_app_authority(
        token,
        app_jwt=app_jwt,
        app_id=app_id,
        app_slug=app_slug,
        installation_id=installation_id,
        expected_account_id=int(_external_gate_authority["account_id"]),
        expected_account_login=str(_external_gate_authority["account_login"]),
        expected_account_type=str(_external_gate_authority["account_type"]),
        expected_repository_id=int(_external_gate_authority["repository_id"]),
        expected_repository=str(_external_gate_authority["repository"]),
        expected_repository_selection=str(
            _external_gate_authority["repository_selection"]
        ),
        expected_private=False,
        expected_permissions=dict(_external_gate_authority["permissions"]),
        expected_events=list(_external_gate_authority["events"]),
        label="external gate-author",
    )


def _verify_kernel_reader_token_authority(
    token: str,
    *,
    app_jwt: str,
    app_id: int,
    app_slug: str,
    installation_id: int,
) -> None:
    """Verify the App-global and full-installation scope before private-kernel checkout."""

    if KERNEL_READER_AUTHORITY_STATUS != "pinned":
        raise SystemExit("dedicated Phase 5E kernel-reader authority bootstrap is still pending")
    if (
        type(app_id) is not int
        or app_id <= 0
        or app_id == GITHUB_ACTIONS_APP_ID
        or app_id == PINNED_CONTROLLER_APP_ID
        or app_id == PINNED_EXTERNAL_GATE_AUTHOR_APP_ID
        or app_id != PINNED_KERNEL_READER_APP_ID
        or not isinstance(app_slug, str)
        or app_slug != PINNED_KERNEL_READER_APP_SLUG
        or type(installation_id) is not int
        or installation_id <= 0
        or installation_id != PINNED_KERNEL_READER_INSTALLATION_ID
    ):
        raise SystemExit("kernel-reader action outputs do not match the pinned authority")

    _verify_single_repository_app_authority(
        token,
        app_jwt=app_jwt,
        app_id=app_id,
        app_slug=app_slug,
        installation_id=installation_id,
        expected_account_id=KERNEL_READER_ACCOUNT_ID,
        expected_account_login=KERNEL_READER_ACCOUNT_LOGIN,
        expected_account_type=KERNEL_READER_ACCOUNT_TYPE,
        expected_repository_id=KERNEL_READER_REPOSITORY_ID,
        expected_repository=KERNEL_READER_REPOSITORY,
        expected_repository_selection=KERNEL_READER_REPOSITORY_SELECTION,
        expected_private=True,
        expected_permissions=KERNEL_READER_PERMISSIONS,
        expected_events=KERNEL_READER_EVENTS,
        label="kernel-reader",
    )


def _verify_environment(
    repository_slug: str,
    token: str,
    *,
    environment_name: str,
    expected_secret_names: frozenset[str],
    expected_variables: dict[str, str],
) -> None:
    encoded_name = urllib.parse.quote(environment_name, safe="")
    base = f"https://api.github.com/repos/{repository_slug}/environments/{encoded_name}"
    environment = _api_json(base, token)
    if (
        set(environment)
        - {
            "id",
            "node_id",
            "name",
            "url",
            "html_url",
            "created_at",
            "updated_at",
            "can_admins_bypass",
            "protection_rules",
            "deployment_branch_policy",
        }
        or environment.get("name") != environment_name
        or environment.get("can_admins_bypass") is not False
        or not isinstance(environment.get("protection_rules"), list)
        or len(environment["protection_rules"]) != 1
        or not isinstance(environment["protection_rules"][0], dict)
        or environment["protection_rules"][0].get("type") != "branch_policy"
        or set(environment["protection_rules"][0]) - {"id", "node_id", "type"}
        or type(environment["protection_rules"][0].get("id")) is not int
        or environment["protection_rules"][0]["id"] <= 0
        or environment.get("deployment_branch_policy")
        != {"protected_branches": False, "custom_branch_policies": True}
    ):
        raise SystemExit(f"environment {environment_name} is not a main-only trust boundary")

    policies = _api_paginated_collection(
        f"{base}/deployment-branch-policies",
        token,
        collection_key="branch_policies",
        per_page=100,
        identity_key="id",
    )
    if (
        len(policies) != 1
        or set(policies[0]) - {"id", "node_id", "name", "type"}
        or type(policies[0].get("id")) is not int
        or policies[0]["id"] <= 0
        or policies[0].get("name") != "main"
        or policies[0].get("type") != "branch"
    ):
        raise SystemExit(f"environment {environment_name} lacks the exact main branch policy")

    secret_names = _secret_inventory(f"{base}/secrets", token)
    variables = _variable_inventory(f"{base}/variables", token)
    if (
        secret_names != expected_secret_names
        or set(variables) != set(expected_variables)
        or any(variables[name] != value for name, value in expected_variables.items())
    ):
        raise SystemExit(f"environment {environment_name} secret or variable placement is invalid")


def _verify_environment_and_secret_authority(
    repository_slug: str,
    token: str,
    *,
    controller_app_id: int,
) -> None:
    if (
        KERNEL_READER_AUTHORITY_STATUS != "pinned"
        or type(PINNED_KERNEL_READER_APP_ID) is not int
        or PINNED_KERNEL_READER_APP_ID <= 0
    ):
        raise SystemExit("dedicated Phase 5E kernel-reader authority bootstrap is still pending")
    raw_environments = _api_paginated_collection(
        f"https://api.github.com/repos/{repository_slug}/environments",
        token,
        collection_key="environments",
        per_page=100,
        identity_key="id",
    )
    expected_environments = {CONTROLLER_ENVIRONMENT_NAME, KERNEL_ENVIRONMENT_NAME}
    if EXTERNAL_GATE_AUTHORITY_STATUS == "pinned":
        expected_environments.add(EXTERNAL_GATE_AUTHOR_ENVIRONMENT)
    if (
        len(raw_environments) != len(expected_environments)
        or {
            item.get("name")
            for item in raw_environments
            if isinstance(item, dict)
        }
        != expected_environments
    ):
        raise SystemExit("repository environment inventory is not the exact Phase 5E set")

    repository_secret_names = _secret_inventory(
        f"https://api.github.com/repos/{repository_slug}/actions/secrets",
        token,
    )
    repository_variable_names = frozenset(
        _variable_inventory(
            f"https://api.github.com/repos/{repository_slug}/actions/variables",
            token,
        )
    )
    if repository_secret_names or repository_variable_names:
        raise SystemExit(
            "repository-scoped Actions secrets and variables must be empty; "
            "Phase 5E credentials belong only to protected main environments"
        )

    _verify_environment(
        repository_slug,
        token,
        environment_name=CONTROLLER_ENVIRONMENT_NAME,
        expected_secret_names=frozenset({CONTROLLER_PRIVATE_KEY_SECRET}),
        expected_variables={CONTROLLER_APP_ID_VARIABLE: str(controller_app_id)},
    )
    _verify_environment(
        repository_slug,
        token,
        environment_name=KERNEL_ENVIRONMENT_NAME,
        expected_secret_names=frozenset({KERNEL_READER_PRIVATE_KEY_SECRET}),
        expected_variables={
            KERNEL_READER_APP_ID_VARIABLE: str(PINNED_KERNEL_READER_APP_ID)
        },
    )
    if EXTERNAL_GATE_AUTHORITY_STATUS == "pinned":
        _verify_environment(
            repository_slug,
            token,
            environment_name=EXTERNAL_GATE_AUTHOR_ENVIRONMENT,
            expected_secret_names=frozenset(
                {EXTERNAL_GATE_AUTHOR_PRIVATE_KEY_SECRET}
            ),
            expected_variables={
                EXTERNAL_GATE_AUTHOR_APP_ID_VARIABLE: str(
                    PINNED_EXTERNAL_GATE_AUTHOR_APP_ID
                )
            },
        )


def _verify_public_artifact_policy(
    repository_slug: str,
    token: str,
    repository: dict[str, Any],
) -> None:
    """Allow only explicitly sanitized artifacts in the public repository."""

    owner = repository.get("owner")
    expected_login = repository_slug.split("/", 1)[0]
    if (
        repository.get("private") is not False
        or not isinstance(owner, dict)
        or type(owner.get("id")) is not int
        or owner["id"] <= 0
        or owner.get("login") != expected_login
        or owner.get("type") != "User"
    ):
        raise SystemExit("public research repository identity is invalid")
    artifacts = _api_paginated_collection(
        f"https://api.github.com/repos/{repository_slug}/actions/artifacts",
        token,
        collection_key="artifacts",
        per_page=100,
        identity_key="id",
    )
    allowed = (
        re.compile(r"phase5e-audit-wheelhouse-[1-9][0-9]*\Z"),
        re.compile(r"phase5e-audit-[0-9a-f]{40}\Z"),
    )
    for artifact in artifacts:
        name = artifact.get("name")
        if (
            not isinstance(name, str)
            or not any(pattern.fullmatch(name) for pattern in allowed)
        ):
            raise SystemExit("public repository contains an unapproved Actions artifact")


def _verify_remote_repository_governance(
    repository_slug: str,
    token: str,
    *,
    controller_app_id: int,
) -> tuple[int, str]:
    if CONTROLLER_AUTHORITY_STATUS != "pinned":
        raise SystemExit("dedicated Phase 5E controller authority bootstrap is still pending")
    if controller_app_id <= 0 or controller_app_id == GITHUB_ACTIONS_APP_ID:
        raise SystemExit("dedicated Phase 5E controller App identity is invalid")
    if controller_app_id != PINNED_CONTROLLER_APP_ID:
        raise SystemExit("dedicated Phase 5E controller App identity is not the pinned authority")
    installation_id, app_slug = _verify_scoped_controller_token_identity(
        repository_slug,
        token,
        controller_app_id=controller_app_id,
    )
    if (
        installation_id != PINNED_CONTROLLER_INSTALLATION_ID
        or app_slug != PINNED_CONTROLLER_APP_SLUG
    ):
        raise SystemExit("dedicated Phase 5E controller installation identity drifted")
    repository = _api_json(
        f"https://api.github.com/repos/{repository_slug}",
        token,
    )
    rest_merge_settings = (
        repository.get("allow_merge_commit"),
        repository.get("allow_squash_merge"),
        repository.get("allow_rebase_merge"),
    )
    if rest_merge_settings == (None, None, None):
        merge_settings = _api_graphql_repository_merge_settings(
            repository_slug,
            token,
        )
    elif all(type(value) is bool for value in rest_merge_settings):
        merge_settings = rest_merge_settings
    else:
        merge_settings = (None, None, None)
    _verify_public_artifact_policy(repository_slug, token, repository)
    protection = _api_json(
        f"https://api.github.com/repos/{repository_slug}/branches/main/protection",
        token,
    )
    status_checks = protection.get("required_status_checks")
    pinned_checks: dict[str, int] = {}
    raw_contexts: object = None
    if isinstance(status_checks, dict):
        raw_contexts = status_checks.get("contexts")
        raw_checks = status_checks.get("checks", [])
        if isinstance(raw_checks, list):
            for item in raw_checks:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("context"), str)
                    or type(item.get("app_id")) is not int
                    or item["context"] in pinned_checks
                ):
                    raise SystemExit("main protection contains an unpinned or duplicate check")
                pinned_checks[item["context"]] = item["app_id"]
    reviews = protection.get("required_pull_request_reviews")
    bypass = reviews.get("bypass_pull_request_allowances") if isinstance(reviews, dict) else None
    no_bypass = bypass is None or (
        isinstance(bypass, dict)
        and set(bypass) == {"users", "teams", "apps"}
        and all(bypass[key] == [] for key in ("users", "teams", "apps"))
    )
    rulesets = _api_list(
        f"https://api.github.com/repos/{repository_slug}/rulesets?includes_parents=true",
        token,
    )
    legacy_contexts_valid = raw_contexts is None or (
        isinstance(raw_contexts, list)
        and len(raw_contexts) == len(REQUIRED_PROTECTION_CHECKS)
        and set(raw_contexts) == REQUIRED_PROTECTION_CHECKS
    )
    governance_gates = {
        "repository-full-name": repository.get("full_name") == repository_slug,
        "repository-owner": (
            repository.get("owner", {}).get("login")
            == repository_slug.split("/", 1)[0]
            and repository.get("owner", {}).get("type") == "User"
        ),
        "repository-origin": repository.get("fork") is False,
        "repository-default-branch": repository.get("default_branch") == "main",
        "repository-public": repository.get("private") is False,
        "merge-commit-only": merge_settings == (True, False, False),
        "status-check-shape": isinstance(status_checks, dict),
        "status-check-strict": (
            isinstance(status_checks, dict) and status_checks.get("strict") is True
        ),
        "legacy-context-mirror": legacy_contexts_valid,
        "pinned-check-set": set(pinned_checks) == REQUIRED_PROTECTION_CHECKS,
        "actions-check-authority": all(
            pinned_checks.get(context) == GITHUB_ACTIONS_APP_ID
            for context in GITHUB_ACTIONS_CHECKS
        ),
        "controller-check-authority": all(
            pinned_checks.get(context) == controller_app_id
            for context in CONTROLLER_APP_CHECKS
        ),
        "review-shape": isinstance(reviews, dict),
        "review-count": (
            isinstance(reviews, dict)
            and reviews.get("required_approving_review_count") == 0
        ),
        "dismiss-stale-reviews": (
            isinstance(reviews, dict) and reviews.get("dismiss_stale_reviews") is False
        ),
        "last-push-approval": (
            isinstance(reviews, dict)
            and reviews.get("require_last_push_approval") is False
        ),
        "review-bypass": no_bypass,
        "admin-enforcement": (
            protection.get("enforce_admins", {}).get("enabled") is True
        ),
        "force-push-disabled": (
            protection.get("allow_force_pushes", {}).get("enabled") is False
        ),
        "deletion-disabled": (
            protection.get("allow_deletions", {}).get("enabled") is False
        ),
        "conversation-resolution": (
            protection.get("required_conversation_resolution", {}).get("enabled")
            is True
        ),
        "ruleset-absence": rulesets == [],
    }
    failed_gates = sorted(
        gate for gate, accepted in governance_gates.items() if not accepted
    )
    if failed_gates:
        raise SystemExit(
            "public main branch lacks the required non-bypass acceptance protections: "
            + ",".join(failed_gates)
        )
    _verify_environment_and_secret_authority(
        repository_slug,
        token,
        controller_app_id=controller_app_id,
    )
    return installation_id, app_slug


def _github_utc_timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise SystemExit(f"{label} is not a UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise SystemExit(f"{label} is not a canonical UTC timestamp") from exc
    return parsed


def _github_bot_identity(
    value: object,
    *,
    login: str,
    bot_id: int | None = None,
) -> bool:
    return (
        isinstance(value, dict)
        and value.get("login") == login
        and value.get("type") == "Bot"
        and type(value.get("id")) is int
        and value["id"] > 0
        and value.get("site_admin") is False
        and (bot_id is None or value["id"] == bot_id)
    )


def _verify_external_controller_handoff_remote(
    *,
    repository: Path,
    repository_slug: str,
    token: str,
    base: str,
    head: str,
    event: dict[str, Any],
    controller_app_id: int,
    controller_app_slug: str,
    controller_installation_id: int,
) -> None:
    """Bind one external handoff to a separate least-privilege author App PR."""

    if (
        EXTERNAL_GATE_AUTHORITY_STATUS != "pinned"
        or type(PINNED_EXTERNAL_GATE_AUTHOR_APP_ID) is not int
        or type(PINNED_EXTERNAL_GATE_AUTHOR_INSTALLATION_ID) is not int
        or not isinstance(PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG, str)
    ):
        raise SystemExit("external gate-author App authority bootstrap is still pending")
    if PINNED_EXTERNAL_GATE_AUTHOR_APP_ID in {
        controller_app_id,
        GITHUB_ACTIONS_APP_ID,
    }:
        raise SystemExit("external gate-author App is not privilege-separated")
    author_app = _api_json(
        f"https://api.github.com/apps/{PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG}",
        token,
    )
    author_owner = author_app.get("owner")
    if (
        author_app.get("id") != PINNED_EXTERNAL_GATE_AUTHOR_APP_ID
        or author_app.get("slug") != PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG
        or author_app.get("permissions")
        != {"contents": "write", "metadata": "read", "pull_requests": "write"}
        or author_app.get("events") != []
        or not isinstance(author_owner, dict)
        or author_owner.get("id") != 263841576
        or author_owner.get("login") != "mingjiconnect-ctrl"
        or author_owner.get("type") != "User"
    ):
        raise SystemExit("external gate-author App metadata or permissions drifted")
    number = event.get("number")
    if type(number) is not int or number <= 0:
        raise SystemExit("external Controller handoff has no canonical PR number")
    handoff = _read_json(repository, head, EXTERNAL_HANDOFF_PATH)
    if (
        handoff.get("controller_app_id") != controller_app_id
        or handoff.get("controller_app_slug") != controller_app_slug
        or handoff.get("controller_installation_id") != controller_installation_id
        or handoff.get("author_app_id") != PINNED_EXTERNAL_GATE_AUTHOR_APP_ID
        or handoff.get("author_app_slug") != PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG
        or handoff.get("author_installation_id")
        != PINNED_EXTERNAL_GATE_AUTHOR_INSTALLATION_ID
    ):
        raise SystemExit("external handoff App authority binding drifted")
    pull = _api_json(
        f"https://api.github.com/repos/{repository_slug}/pulls/{number}",
        token,
    )
    author_login = f"{PINNED_EXTERNAL_GATE_AUTHOR_APP_SLUG}[bot]"
    pull_user = pull.get("user")
    pull_head = pull.get("head")
    pull_base = pull.get("base")
    if (
        pull.get("number") != number
        or pull.get("state") != "open"
        or pull.get("draft") is not False
        or pull.get("merged") is not False
        or pull.get("closed_at") is not None
        or pull.get("merged_at") is not None
        or type(pull.get("commits")) is not int
        or pull["commits"] != 1
        or not _github_bot_identity(pull_user, login=author_login)
        or not isinstance(pull_head, dict)
        or pull_head.get("sha") != head
        or pull_head.get("ref") != EXTERNAL_CONTROLLER_BRANCH
        or pull_head.get("repo", {}).get("full_name") != repository_slug
        or not isinstance(pull_base, dict)
        or pull_base.get("sha") != base
        or pull_base.get("ref") != "main"
        or pull_base.get("repo", {}).get("full_name") != repository_slug
    ):
        raise SystemExit("external handoff PR is not the exact author-App transition")
    pull_commits = _api_list(
        f"https://api.github.com/repos/{repository_slug}/pulls/{number}/commits"
        "?per_page=2&page=1",
        token,
    )
    if len(pull_commits) != 1 or pull_commits[0].get("sha") != head:
        raise SystemExit("external handoff PR commit inventory is not singular")
    commit = _api_json(
        f"https://api.github.com/repos/{repository_slug}/commits/{head}",
        token,
    )
    commit_payload = commit.get("commit")
    verification = (
        commit_payload.get("verification") if isinstance(commit_payload, dict) else None
    )
    bot_id = pull_user["id"]
    remote_parents = commit.get("parents")
    if (
        commit.get("sha") != head
        or not _github_bot_identity(commit.get("author"), login=author_login, bot_id=bot_id)
        or not _github_bot_identity(
            commit.get("committer"),
            login=author_login,
            bot_id=bot_id,
        )
        or not isinstance(remote_parents, list)
        or len(remote_parents) != 1
        or remote_parents[0].get("sha") != base
        or _commit_parents(repository, head) != (base,)
        or not isinstance(commit_payload, dict)
        or commit_payload.get("tree", {}).get("sha") != _tree(repository, head)
        or not isinstance(verification, dict)
        or verification.get("verified") is not True
        or verification.get("reason") != "valid"
        or any(
            not isinstance(verification.get(field), str) or not verification[field]
            for field in ("signature", "payload", "verified_at")
        )
    ):
        raise SystemExit("external handoff commit is not a verified author-App commit")
    approved_at = _github_utc_timestamp(handoff.get("approved_at"), label="approved_at")
    receipt_bindings = handoff.get("receipt_bindings")
    if not isinstance(receipt_bindings, list) or len(receipt_bindings) != 3:
        raise SystemExit("external handoff lacks its signed receipt time bounds")
    receipt_expiries = [
        _github_utc_timestamp(
            item.get("payload", {}).get("expires_at")
            if isinstance(item, dict)
            else None,
            label="receipt expires_at",
        )
        for item in receipt_bindings
    ]
    receipt_expiry = min(receipt_expiries)
    commit_at = _github_utc_timestamp(
        commit_payload.get("committer", {}).get("date"),
        label="commit committer date",
    )
    pull_created_at = _github_utc_timestamp(
        pull.get("created_at"),
        label="pull request created_at",
    )
    verified_at = _github_utc_timestamp(
        verification.get("verified_at"),
        label="verification verified_at",
    )
    now = datetime.now(UTC)
    if not (
        approved_at <= commit_at <= pull_created_at <= receipt_expiry
        and pull_created_at <= now
        and commit_at <= verified_at <= now
    ):
        raise SystemExit("external handoff approval or verification chronology is invalid")


def _pull_request_association_matches(
    pull_requests: Any,
    *,
    repository_slug: str,
    number: int,
    head_sha: str,
    head_ref: str,
    base_sha: str,
) -> bool:
    return (
        isinstance(pull_requests, list)
        and len(pull_requests) == 1
        and pull_requests[0].get("number") == number
        and pull_requests[0].get("head", {}).get("sha") == head_sha
        and pull_requests[0].get("head", {}).get("ref") == head_ref
        and pull_requests[0].get("head", {}).get("repo", {}).get("full_name")
        == repository_slug
        and pull_requests[0].get("base", {}).get("sha") == base_sha
        and pull_requests[0].get("base", {}).get("ref") == "main"
        and pull_requests[0].get("base", {}).get("repo", {}).get("full_name")
        == repository_slug
    )


def _verify_external_handoff_merge_window(
    *,
    handoff: dict[str, Any],
    pull_request: dict[str, Any],
) -> None:
    """Bind the authoritative merge timestamp to every signed feasibility TTL."""

    receipt_bindings = handoff.get("receipt_bindings")
    if not isinstance(receipt_bindings, list) or len(receipt_bindings) != 3:
        raise SystemExit("external handoff lacks its signed receipt time bounds")
    expiries = [
        _github_utc_timestamp(
            item.get("payload", {}).get("expires_at")
            if isinstance(item, dict)
            else None,
            label="receipt expires_at",
        )
        for item in receipt_bindings
    ]
    approved_at = _github_utc_timestamp(handoff.get("approved_at"), label="approved_at")
    created_at = _github_utc_timestamp(
        pull_request.get("created_at"),
        label="pull request created_at",
    )
    merged_at = _github_utc_timestamp(
        pull_request.get("merged_at"),
        label="pull request merged_at",
    )
    if not approved_at <= created_at <= merged_at <= min(expiries):
        raise SystemExit("external handoff merged outside its signed receipt validity window")


def _pull_request_identity_matches(
    pull_request: Any,
    *,
    number: int,
    head_sha: str,
    head_ref: str,
    base_sha: str,
) -> bool:
    return (
        isinstance(pull_request, dict)
        and pull_request.get("number") == number
        and pull_request.get("head", {}).get("sha") == head_sha
        and pull_request.get("head", {}).get("ref") == head_ref
        and pull_request.get("base", {}).get("sha") == base_sha
        and pull_request.get("base", {}).get("ref") == "main"
    )


def _verify_run(
    *,
    repository_slug: str,
    token: str,
    run_id: str,
    expected_head: str,
    expected_event: str,
    expected_head_branch: str,
    expected_pull_request_number: int | None = None,
    expected_pull_request_head: str | None = None,
    expected_pull_request_head_ref: str | None = None,
    expected_pull_request_base: str | None = None,
    expected_workflow_name: str = "owner-research-ci",
    expected_workflow_file: str = ".github/workflows/ci.yml",
) -> dict[str, Any]:
    run = _api_json(
        f"https://api.github.com/repos/{repository_slug}/actions/runs/{run_id}",
        token,
    )
    pull_request_identity_matches = True
    if expected_pull_request_number is not None:
        if expected_pull_request_base is None:
            raise SystemExit("CI pull-request association lacks an expected base")
        pull_request_identity_matches = _pull_request_identity_matches(
            _api_json(
                (
                    f"https://api.github.com/repos/{repository_slug}/pulls/"
                    f"{expected_pull_request_number}"
                ),
                token,
            ),
            number=expected_pull_request_number,
            head_sha=expected_pull_request_head or expected_head,
            head_ref=expected_pull_request_head_ref or expected_head_branch,
            base_sha=expected_pull_request_base,
        )
    run_pull_requests = run.get("pull_requests")
    if expected_pull_request_number is None:
        run_association_matches = run_pull_requests in (None, [])
    elif expected_event == "pull_request_target" and run_pull_requests in (None, []):
        # GitHub's pull_request_target run payload can omit pull_requests even though the
        # triggering pull request remains available through the Pull Request API.  In that
        # documented runtime shape, the exact PR API identity above is the association proof.
        run_association_matches = pull_request_identity_matches
    else:
        run_association_matches = (
            expected_pull_request_base is not None
            and _pull_request_association_matches(
                run_pull_requests,
                repository_slug=repository_slug,
                number=expected_pull_request_number,
                head_sha=expected_pull_request_head or expected_head,
                head_ref=expected_pull_request_head_ref or expected_head_branch,
                base_sha=expected_pull_request_base,
            )
        )
    mismatches = tuple(
        name
        for name, invalid in (
            ("run_id", str(run.get("id")) != run_id),
            ("head_sha", run.get("head_sha") != expected_head),
            ("event", run.get("event") != expected_event),
            ("conclusion", run.get("conclusion") != "success"),
            ("workflow_name", run.get("name") != expected_workflow_name),
            ("head_branch", run.get("head_branch") != expected_head_branch),
            ("workflow_path", run.get("path") != expected_workflow_file),
            (
                "repository",
                run.get("repository", {}).get("full_name") != repository_slug,
            ),
            (
                "head_repository",
                run.get("head_repository", {}).get("full_name") != repository_slug,
            ),
            ("workflow_id", type(run.get("workflow_id")) is not int),
            ("pull_request", not pull_request_identity_matches),
            ("run_association", not run_association_matches),
        )
        if invalid
    )
    if mismatches:
        raise SystemExit(
            f"CI run {run_id} does not prove the expected successful head: "
            + ", ".join(mismatches)
        )
    workflow = _api_json(
        (f"https://api.github.com/repos/{repository_slug}/actions/workflows/{run['workflow_id']}"),
        token,
    )
    if (
        workflow.get("id") != run["workflow_id"]
        or workflow.get("path") != expected_workflow_file
        or workflow.get("name") != expected_workflow_name
        or workflow.get("state") != "active"
    ):
        raise SystemExit(f"CI run {run_id} does not use the exact expected workflow identity")
    return run


def _verify_controller_statuses(
    *,
    repository_slug: str,
    token: str,
    head_sha: str,
    workflow_run_id: str,
    app_slug: str,
) -> None:
    statuses = _api_paginated_list(
        f"https://api.github.com/repos/{repository_slug}/commits/{head_sha}/statuses",
        token,
    )
    expected_status_url = (
        f"https://api.github.com/repos/{repository_slug}/statuses/{head_sha}"
    )
    status_ids = [item.get("id") for item in statuses]
    if (
        any(type(item_id) is not int or item_id <= 0 for item_id in status_ids)
        or len(status_ids) != len(set(status_ids))
    ):
        raise SystemExit("protected status inventory has an ambiguous identity")
    expected_target = (
        f"https://github.com/{repository_slug}/actions/runs/{workflow_run_id}"
    )
    for context in CONTROLLER_APP_CHECKS:
        matching = [item for item in statuses if item.get("context") == context]
        if not matching:
            raise SystemExit(f"protected controller status is missing: {context}")
        latest = max(matching, key=lambda item: item["id"])
        if (
            latest.get("url") != expected_status_url
            or latest.get("state") != "success"
            or latest.get("target_url") != expected_target
            or latest.get("creator", {}).get("login") != f"{app_slug}[bot]"
            or latest.get("creator", {}).get("type") != "Bot"
        ):
            raise SystemExit(f"protected controller status identity drifted: {context}")
    revocation_context = "phase5e/actions-status-token-revoked"
    revocations = [
        item for item in statuses if item.get("context") == revocation_context
    ]
    if not revocations:
        raise SystemExit("Actions-owned controller-token revocation status is missing")
    latest_revocation = max(revocations, key=lambda item: item["id"])
    if (
        latest_revocation.get("url") != expected_status_url
        or latest_revocation.get("state") != "success"
        or latest_revocation.get("target_url") != expected_target
        or latest_revocation.get("creator", {}).get("login")
        != "github-actions[bot]"
        or latest_revocation.get("creator", {}).get("type") != "Bot"
    ):
        raise SystemExit("Actions-owned controller-token revocation status drifted")


def _verify_implementation_pull_request(
    *,
    repository_slug: str,
    token: str,
    pull_request_number: int,
    implementation_merge: str,
    implementation_head: str,
    implementation_base: str,
    expected_head_ref: str,
) -> dict[str, Any]:
    pull_request = _api_json(
        f"https://api.github.com/repos/{repository_slug}/pulls/{pull_request_number}",
        token,
    )
    if (
        pull_request.get("state") != "closed"
        or pull_request.get("merged") is not True
        or pull_request.get("merged_at") is None
        or pull_request.get("merge_commit_sha") != implementation_merge
        or pull_request.get("base", {}).get("sha") != implementation_base
        or pull_request.get("base", {}).get("ref") != "main"
        or pull_request.get("base", {}).get("repo", {}).get("full_name") != repository_slug
        or pull_request.get("head", {}).get("sha") != implementation_head
        or pull_request.get("head", {}).get("ref") != expected_head_ref
        or pull_request.get("head", {}).get("repo", {}).get("full_name") != repository_slug
    ):
        raise SystemExit("implementation pull request identity does not replay")
    return pull_request


def _verify_acceptance_pull_request(
    *,
    repository_slug: str,
    token: str,
    pull_request_number: int,
    acceptance_base: str,
    acceptance_head: str,
    acceptance_merge: str,
    expected_head_ref: str,
) -> dict[str, Any]:
    pull_request = _api_json(
        f"https://api.github.com/repos/{repository_slug}/pulls/{pull_request_number}",
        token,
    )
    if (
        pull_request.get("state") != "closed"
        or pull_request.get("merged") is not True
        or pull_request.get("merged_at") is None
        or pull_request.get("merge_commit_sha") != acceptance_merge
        or pull_request.get("base", {}).get("sha") != acceptance_base
        or pull_request.get("base", {}).get("ref") != "main"
        or pull_request.get("base", {}).get("repo", {}).get("full_name") != repository_slug
        or pull_request.get("head", {}).get("sha") != acceptance_head
        or pull_request.get("head", {}).get("ref") != expected_head_ref
        or pull_request.get("head", {}).get("repo", {}).get("full_name") != repository_slug
    ):
        raise SystemExit("acceptance pull request identity does not replay after merge")
    return pull_request


def _verify_merged_main_2a_acceptance(
    *,
    repository: Path,
    merged_main: str,
    repository_slug: str,
    token: str,
    triggering_ci_run_id: str,
    controller_app_id: int,
) -> bool:
    parents = _commit_parents(repository, merged_main)
    if len(parents) != 2:
        raise SystemExit("accepted merged main is not a two-parent pull-request merge")
    acceptance_base, acceptance_head = parents
    if _tree(repository, merged_main) != _tree(repository, acceptance_head):
        raise SystemExit("accepted merged main tree differs from the acceptance pull-request head")
    status = _read_json(repository, merged_main, STATUS_PATH)
    if not (
        status.get("current_phase") == "Phase 5E-2B.1-2A"
        and status.get("status") == "accepted_closed"
    ):
        return False
    closeout = _read_json(repository, merged_main, CLOSEOUT_PATH)
    implementation_merge = closeout.get("implementation_merge_commit")
    if not _git_oid(implementation_merge):
        raise SystemExit("accepted closeout lacks a valid implementation merge")
    _verify_acceptance_pull_request(
        repository_slug=repository_slug,
        token=token,
        pull_request_number=int(closeout["acceptance_pull_request"]),
        acceptance_base=acceptance_base,
        acceptance_head=acceptance_head,
        acceptance_merge=merged_main,
        expected_head_ref="feature/phase5e2b12a-acceptance-closeout",
    )
    verify_acceptance(
        repository=repository,
        base=acceptance_base,
        head=acceptance_head,
        event=None,
        repository_slug=repository_slug,
        token=token,
        require_remote=True,
        controller_app_id=controller_app_id,
    )
    _verify_run(
        repository_slug=repository_slug,
        token=token,
        run_id=triggering_ci_run_id,
        expected_head=merged_main,
        expected_event="push",
        expected_head_branch="main",
    )
    runs = _api_paginated_items(
        (
            f"https://api.github.com/repos/{repository_slug}/actions/workflows/"
            "phase5e2b12a-acceptance-gate.yml/runs"
            "?event=pull_request_target&status=completed"
            f"&head_sha={acceptance_head}"
        ),
        key="workflow_runs",
        token=token,
    )
    acceptance_number = int(closeout["acceptance_pull_request"])
    matching = [
        run
        for run in runs
        if run.get("head_sha") == acceptance_head
        and run.get("name") == "phase5e2b12a-base-owned-acceptance-gate"
        and run.get("path") == ".github/workflows/phase5e2b12a-acceptance-gate.yml"
    ]
    if len(matching) != 1:
        raise SystemExit("current base-owned acceptance workflow run is missing or ambiguous")
    if matching[0].get("conclusion") != "success":
        raise SystemExit("current base-owned acceptance workflow run did not succeed")
    _verify_run(
        repository_slug=repository_slug,
        token=token,
        run_id=str(matching[0]["id"]),
        expected_head=acceptance_head,
        expected_event="pull_request_target",
        expected_head_branch="feature/phase5e2b12a-acceptance-closeout",
        expected_pull_request_number=acceptance_number,
        expected_pull_request_head=acceptance_head,
        expected_pull_request_head_ref="feature/phase5e2b12a-acceptance-closeout",
        expected_pull_request_base=acceptance_base,
        expected_workflow_name="phase5e2b12a-base-owned-acceptance-gate",
        expected_workflow_file=".github/workflows/phase5e2b12a-acceptance-gate.yml",
    )
    _verify_controller_statuses(
        repository_slug=repository_slug,
        token=token,
        head_sha=acceptance_head,
        workflow_run_id=str(matching[0]["id"]),
        app_slug=str(closeout["controller_app_slug"]),
    )
    return True


def _verify_merged_main_2b_acceptance(
    *,
    repository: Path,
    merged_main: str,
    repository_slug: str,
    token: str,
    triggering_ci_run_id: str,
    controller_app_id: int,
) -> bool:
    successor_trust = _read_hash_bound_control_json(
        "scripts/phase5e2b12b-acceptance-trust.json"
    )
    acceptance_branch = str(successor_trust["acceptance_branch"])
    successor_closeout_path = "docs/phase5e2b12b-acceptance-closeout.json"
    parents = _commit_parents(repository, merged_main)
    if len(parents) != 2:
        raise SystemExit("accepted 2B merged main is not a two-parent pull-request merge")
    implementation_merge, acceptance_head = parents
    if _tree(repository, merged_main) != _tree(repository, acceptance_head):
        raise SystemExit("accepted 2B merged-main tree differs from its acceptance head")
    closeout = _read_json(repository, merged_main, successor_closeout_path)
    acceptance_number = int(closeout["acceptance_pull_request"])
    _verify_acceptance_pull_request(
        repository_slug=repository_slug,
        token=token,
        pull_request_number=acceptance_number,
        acceptance_base=implementation_merge,
        acceptance_head=acceptance_head,
        acceptance_merge=merged_main,
        expected_head_ref=acceptance_branch,
    )
    structural_event = {
        "number": acceptance_number,
        "repository": {"full_name": repository_slug},
        "pull_request": {
            "base": {
                "ref": "main",
                "repo": {"full_name": repository_slug},
                "sha": implementation_merge,
            },
            "head": {
                "ref": acceptance_branch,
                "repo": {"full_name": repository_slug},
                "sha": acceptance_head,
            },
        },
    }
    _run_protected_structural_gate(
        relative_script="scripts/verify_phase5e2b12b_acceptance_gate.py",
        repository=repository,
        base=implementation_merge,
        head=acceptance_head,
        event=structural_event,
        repository_slug=repository_slug,
    )
    implementation_parents = _commit_parents(repository, implementation_merge)
    if len(implementation_parents) != 2:
        raise SystemExit("accepted 2B implementation is not a two-parent merge")
    implementation_base, implementation_head = implementation_parents
    _verify_phase5e2b12b_remote_evidence(
        repository=repository,
        repository_slug=repository_slug,
        token=token,
        implementation_base=implementation_base,
        implementation_merge=implementation_merge,
        implementation_head=implementation_head,
        closeout=closeout,
        controller_app_id=controller_app_id,
    )
    _verify_run(
        repository_slug=repository_slug,
        token=token,
        run_id=triggering_ci_run_id,
        expected_head=merged_main,
        expected_event="push",
        expected_head_branch="main",
    )
    runs = _api_paginated_items(
        (
            f"https://api.github.com/repos/{repository_slug}/actions/workflows/"
            "phase5e2b12a-acceptance-gate.yml/runs"
            "?event=pull_request_target&status=completed"
            f"&head_sha={acceptance_head}"
        ),
        key="workflow_runs",
        token=token,
    )
    matching = [
        run
        for run in runs
        if run.get("head_sha") == acceptance_head
        and run.get("name") == "phase5e2b12a-base-owned-acceptance-gate"
        and run.get("path") == ".github/workflows/phase5e2b12a-acceptance-gate.yml"
    ]
    if len(matching) != 1 or matching[0].get("conclusion") != "success":
        raise SystemExit("accepted 2B base-owned acceptance run is missing or failed")
    _verify_run(
        repository_slug=repository_slug,
        token=token,
        run_id=str(matching[0]["id"]),
        expected_head=acceptance_head,
        expected_event="pull_request_target",
        expected_head_branch=acceptance_branch,
        expected_pull_request_number=acceptance_number,
        expected_pull_request_head=acceptance_head,
        expected_pull_request_head_ref=acceptance_branch,
        expected_pull_request_base=implementation_merge,
        expected_workflow_name="phase5e2b12a-base-owned-acceptance-gate",
        expected_workflow_file=".github/workflows/phase5e2b12a-acceptance-gate.yml",
    )
    _verify_controller_statuses(
        repository_slug=repository_slug,
        token=token,
        head_sha=acceptance_head,
        workflow_run_id=str(matching[0]["id"]),
        app_slug=str(closeout["controller_app_slug"]),
    )
    return True


def _verify_merged_main_generic_acceptance(
    *,
    repository: Path,
    merged_main: str,
    repository_slug: str,
    token: str,
    triggering_ci_run_id: str,
    controller_app_id: int,
) -> bool:
    position = resolve_controller_gate_position(repository, merged_main)
    merged_state = position["stage"]
    if merged_state not in {"g2", "g4", "g5"}:
        return False
    authority = position["authority"]
    if not isinstance(authority, dict):
        raise SystemExit("generic successor authority is malformed")
    paths = {
        "closeout": str(authority["closeout_path"]),
        "successor_closeout": str(authority["successor_closeout_path"]),
    }
    if merged_state == "g2":
        closeout_path = paths["closeout"]
        acceptance_branch = str(authority["acceptance_branch"])
    elif merged_state == "g4":
        closeout_path = paths["successor_closeout"]
        acceptance_branch = str(authority["successor_acceptance_branch"])
    else:
        if position["bundle"] is None:
            raise SystemExit("generic post-successor acceptance lacks its frozen bundle")
        post = position["bundle"]["post_successor_closeout"]
        closeout_path = str(post["closeout_path"])
        acceptance_branch = str(post["branch"])
    parents = _commit_parents(repository, merged_main)
    if len(parents) != 2:
        raise SystemExit("accepted generic successor main is not a two-parent merge")
    implementation_merge, acceptance_head = parents
    if _tree(repository, merged_main) != _tree(repository, acceptance_head):
        raise SystemExit("accepted generic successor tree differs from its acceptance head")
    closeout = _read_json(repository, merged_main, closeout_path)
    pull_request = _verify_acceptance_pull_request(
        repository_slug=repository_slug,
        token=token,
        pull_request_number=int(closeout["acceptance_pull_request"]),
        acceptance_base=implementation_merge,
        acceptance_head=acceptance_head,
        acceptance_merge=merged_main,
        expected_head_ref=acceptance_branch,
    )
    event = {
        "number": int(closeout["acceptance_pull_request"]),
        "repository": {"full_name": repository_slug},
        "pull_request": pull_request,
    }

    _run_protected_structural_gate(
        relative_script="scripts/verify_phase5e_successor_gate.py",
        repository=repository,
        base=implementation_merge,
        head=acceptance_head,
        event=event,
        repository_slug=repository_slug,
    )
    implementation_parents = _commit_parents(repository, implementation_merge)
    if len(implementation_parents) != 2 or not isinstance(position["bundle"], dict):
        raise SystemExit("generic successor implementation ancestry or bundle is malformed")
    transition = {
        "g2": "gate_acceptance",
        "g4": "successor_acceptance",
        "g5": "post_successor_closeout",
    }[merged_state]
    _verify_phase5e_successor_remote_evidence(
        transition=transition,
        repository=repository,
        repository_slug=repository_slug,
        token=token,
        implementation_base=implementation_parents[0],
        implementation_merge=implementation_merge,
        implementation_head=implementation_parents[1],
        closeout=closeout,
        bundle=position["bundle"],
        controller_app_id=controller_app_id,
    )
    _verify_run(
        repository_slug=repository_slug,
        token=token,
        run_id=triggering_ci_run_id,
        expected_head=merged_main,
        expected_event="push",
        expected_head_branch="main",
    )
    runs = _api_paginated_items(
        (
            f"https://api.github.com/repos/{repository_slug}/actions/workflows/"
            "phase5e2b12a-acceptance-gate.yml/runs"
            "?event=pull_request_target&status=completed"
            f"&head_sha={acceptance_head}"
        ),
        key="workflow_runs",
        token=token,
    )
    matching = [
        run
        for run in runs
        if run.get("head_sha") == acceptance_head
        and run.get("name") == "phase5e2b12a-base-owned-acceptance-gate"
        and run.get("path") == ".github/workflows/phase5e2b12a-acceptance-gate.yml"
        and run.get("conclusion") == "success"
        and type(run.get("id")) is int
        and run["id"] > 0
    ]
    if len(matching) != 1:
        raise SystemExit("generic successor acceptance controller run is missing or ambiguous")
    _verify_run(
        repository_slug=repository_slug,
        token=token,
        run_id=str(matching[0]["id"]),
        expected_head=acceptance_head,
        expected_event="pull_request_target",
        expected_head_branch=acceptance_branch,
        expected_pull_request_number=int(closeout["acceptance_pull_request"]),
        expected_pull_request_head=acceptance_head,
        expected_pull_request_head_ref=acceptance_branch,
        expected_pull_request_base=implementation_merge,
        expected_workflow_name="phase5e2b12a-base-owned-acceptance-gate",
        expected_workflow_file=".github/workflows/phase5e2b12a-acceptance-gate.yml",
    )
    _verify_controller_statuses(
        repository_slug=repository_slug,
        token=token,
        head_sha=acceptance_head,
        workflow_run_id=str(matching[0]["id"]),
        app_slug=str(closeout["controller_app_slug"]),
    )
    return True


def verify_merged_main_acceptance(
    *,
    repository: Path,
    merged_main: str,
    repository_slug: str,
    token: str,
    triggering_ci_run_id: str,
    controller_app_id: int,
) -> bool:
    _verify_remote_repository_governance(
        repository_slug,
        token,
        controller_app_id=controller_app_id,
    )
    status = _read_json(repository, merged_main, STATUS_PATH)
    if (
        status.get("current_phase") == "Phase 5E-2B.1-2A"
        and status.get("status") == "accepted_closed"
    ):
        return _verify_merged_main_2a_acceptance(
            repository=repository,
            merged_main=merged_main,
            repository_slug=repository_slug,
            token=token,
            triggering_ci_run_id=triggering_ci_run_id,
            controller_app_id=controller_app_id,
        )
    if (
        status.get("current_phase") == "Phase 5E-2B.1-2B"
        and status.get("status") == "accepted_closed"
    ):
        return _verify_merged_main_2b_acceptance(
            repository=repository,
            merged_main=merged_main,
            repository_slug=repository_slug,
            token=token,
            triggering_ci_run_id=triggering_ci_run_id,
            controller_app_id=controller_app_id,
        )
    return _verify_merged_main_generic_acceptance(
        repository=repository,
        merged_main=merged_main,
        repository_slug=repository_slug,
        token=token,
        triggering_ci_run_id=triggering_ci_run_id,
        controller_app_id=controller_app_id,
    )


def _verify_base_merged_main_finalized(
    *,
    repository: Path,
    base: str,
    repository_slug: str,
    token: str,
    controller_app_id: int,
) -> None:
    """Prove the accepted base completed its non-cancellable merged-main audit."""

    gate_runs = _api_paginated_items(
        (
            f"https://api.github.com/repos/{repository_slug}/actions/workflows/"
            "phase5e2b12a-acceptance-gate.yml/runs"
            f"?event=workflow_run&status=completed&head_sha={base}"
        ),
        key="workflow_runs",
        token=token,
    )
    matching_gate_runs = [
        run
        for run in gate_runs
        if run.get("head_sha") == base
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_run"
        and run.get("conclusion") == "success"
        and run.get("name") == "phase5e2b12a-base-owned-acceptance-gate"
        and run.get("path") == ".github/workflows/phase5e2b12a-acceptance-gate.yml"
        and type(run.get("id")) is int
        and run["id"] > 0
    ]
    if len(matching_gate_runs) != 1:
        raise SystemExit("accepted base lacks one completed merged-main controller audit")
    gate_run_id = str(matching_gate_runs[0]["id"])
    _verify_run(
        repository_slug=repository_slug,
        token=token,
        run_id=gate_run_id,
        expected_head=base,
        expected_event="workflow_run",
        expected_head_branch="main",
        expected_workflow_name="phase5e2b12a-base-owned-acceptance-gate",
        expected_workflow_file=".github/workflows/phase5e2b12a-acceptance-gate.yml",
    )

    ci_runs = _api_paginated_items(
        (
            f"https://api.github.com/repos/{repository_slug}/actions/workflows/ci.yml/runs"
            f"?event=push&status=completed&head_sha={base}"
        ),
        key="workflow_runs",
        token=token,
    )
    matching_ci_runs = [
        run
        for run in ci_runs
        if run.get("head_sha") == base
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("conclusion") == "success"
        and run.get("name") == "owner-research-ci"
        and run.get("path") == ".github/workflows/ci.yml"
        and type(run.get("id")) is int
        and run["id"] > 0
    ]
    if len(matching_ci_runs) != 1:
        raise SystemExit("accepted base lacks one successful main CI trigger")
    triggering_ci_run_id = str(matching_ci_runs[0]["id"])
    if not verify_merged_main_acceptance(
        repository=repository,
        merged_main=base,
        repository_slug=repository_slug,
        token=token,
        triggering_ci_run_id=triggering_ci_run_id,
        controller_app_id=controller_app_id,
    ):
        raise SystemExit("accepted base is not a finalized Phase 5E transition")

    parents = _commit_parents(repository, base)
    if len(parents) != 2:
        raise SystemExit("accepted base is not a two-parent merge")
    profile = protected_controller_audit_profile(repository, parents[0])
    _download_single_report(
        repository=repository,
        repository_slug=repository_slug,
        token=token,
        run_id=gate_run_id,
        reviewed_commit=base,
        controller_commit=parents[0],
        expected_profile=profile,
    )


def _validate_audit_report_contract(
    *,
    report: dict[str, Any],
    reviewed_commit: str,
    audit_run_id: str,
    repository: Path | None = None,
    controller_commit: str | None = None,
    audit_profile_id: str = PHASE5E2B12A_AUDIT_PROFILE,
    expected_profile: AuditProfile | None = None,
) -> None:
    expected_profile = expected_profile or audit_profile(audit_profile_id)
    if set(report) != EXPECTED_REPORT_KEYS:
        raise SystemExit("audit report uses an unknown or missing field")
    if (
        report.get("audit_tool") != AUDIT_TOOL
        or report.get("audit_profile") != expected_profile.profile_id
        or report.get("audit_version") != expected_profile.audit_version
        or report.get("reviewed_commit") != reviewed_commit
        or any(report.get(key) != value for key, value in EXPECTED_BASELINE_FIELDS.items())
        or not _nonempty_string(report.get("started_at"))
        or not _nonempty_string(report.get("finished_at"))
    ):
        raise SystemExit("audit report identity is not exact")
    trust = report.get("audit_trust")
    if (
        not isinstance(trust, dict)
        or set(trust) != EXPECTED_AUDIT_TRUST_KEYS
        or any(
            not _git_oid(trust.get(field))
            for field in ("controller_commit", "controller_tree", "candidate_tree")
        )
        or any(
            not _sha256(trust.get(field))
            for field in EXPECTED_AUDIT_TRUST_KEYS
            - {
                "controller_commit",
                "controller_tree",
                "candidate_tree",
                "sandbox_profile",
            }
        )
        or trust.get("sandbox_profile") != "linux-root-controller-net-pid-v2"
        or trust.get("audit_profile_context_sha256")
        != audit_profile_context_sha256(expected_profile)
        or trust.get("audit_profile_policy_sha256")
        != audit_profile_policy_sha256(expected_profile)
    ):
        raise SystemExit("audit report trust context is malformed")
    if repository is not None and controller_commit is not None:
        expected_hash_paths = {
            "workflow_sha256": ".github/workflows/phase5e2b12a-acceptance-gate.yml",
            "audit_controller_sha256": "scripts/run_phase5e_audit.py",
            "launcher_sha256": "scripts/launch_phase5e_readonly_audit.sh",
            "candidate_executor_sha256": "scripts/phase5e_candidate_exec.sh",
            "semantic_oracle_sha256": expected_profile.semantic_oracle_path,
            "audit_profile_registry_sha256": "scripts/phase5e_audit_profiles.py",
            "requirements_lock_sha256": "scripts/phase5e-audit-requirements.lock",
            "runtime_matrix_sha256": "scripts/phase5e-audit-runtime-matrix.json",
            "runtime_matrix_oracle_sha256": (
                "scripts/verify_phase5e_audit_runtime_matrix.py"
            ),
            "audit_wheelhouse_manifest_sha256": (
                "scripts/phase5e-audit-wheelhouse.sha256"
            ),
        }
        if (
            trust["controller_commit"] != controller_commit
            or trust["controller_tree"] != _tree(repository, controller_commit)
            or trust["candidate_tree"] != _tree(repository, reviewed_commit)
        ):
            raise SystemExit("audit report controller or candidate tree identity drifted")
        for field, path in expected_hash_paths.items():
            raw = _git(repository, "show", f"{controller_commit}:{path}", text=False)
            if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != trust[field]:
                raise SystemExit(f"audit report protected controller hash drifted: {path}")
    audited_hashes = report.get("audited_file_sha256")
    if (
        not isinstance(audited_hashes, dict)
        or not audited_hashes
        or any(
            not _nonempty_string(path) or not _sha256(expected_sha)
            for path, expected_sha in audited_hashes.items()
        )
    ):
        raise SystemExit("audit report file hashes are malformed")
    finding_counts = report.get("finding_counts")
    if (
        not isinstance(finding_counts, dict)
        or set(finding_counts) != {"P0", "P1", "P2", "P3"}
        or any(not _nonnegative_integer(value) for value in finding_counts.values())
    ):
        raise SystemExit("audit report finding counts are not closed nonnegative integers")
    test_counts = report.get("test_counts")
    if (
        not isinstance(test_counts, dict)
        or set(test_counts) != EXPECTED_TEST_COUNT_KEYS
        or any(
            not _nonnegative_integer(test_counts[key])
            for key in ("collected_tests", "passed_tests", "skipped_tests", "failed_tests")
        )
        or test_counts["collected_tests"]
        != test_counts["passed_tests"] + test_counts["skipped_tests"] + test_counts["failed_tests"]
    ):
        raise SystemExit("audit test counts are not closed typed evidence")
    runtime_results = report.get("runtime_results")
    expected_runtime_identities = (
        ("cp311", "3.11.15"),
        ("cp312", "3.12.13"),
        ("cp313", "3.13.13"),
    )
    if not isinstance(runtime_results, list) or len(runtime_results) != 3:
        raise SystemExit("audit report does not contain exactly three runtime results")
    for runtime, (runtime_id, python_version) in zip(
        runtime_results, expected_runtime_identities, strict=True
    ):
        if (
            not isinstance(runtime, dict)
            or set(runtime)
            != {
                "runtime_id",
                "python_version",
                "implementation",
                "abi",
                "operating_system",
                "architecture",
                "threading",
                "test_counts",
                "finding_counts",
                "check_ids_sha256",
            }
            or runtime.get("runtime_id") != runtime_id
            or runtime.get("python_version") != python_version
            or runtime.get("implementation") != "CPython"
            or runtime.get("abi") != runtime_id
            or runtime.get("operating_system") != "Linux"
            or runtime.get("architecture") != "x86_64"
            or runtime.get("threading") != "gil"
            or runtime.get("test_counts") != test_counts
            or runtime.get("finding_counts") != finding_counts
            or runtime.get("check_ids_sha256")
            != _check_ids_sha256(tuple(sorted(expected_profile.expected_check_ids)))
        ):
            raise SystemExit("audit runtime result differs from the protected matrix")
    ci_run_ids = report.get("ci_run_ids")
    check_ids = report.get("check_ids")
    expected_check_ids = tuple(sorted(expected_profile.expected_check_ids))
    if (
        not isinstance(ci_run_ids, list)
        or any(
            not isinstance(item, str) or not item.isascii() or not item.isdigit()
            for item in ci_run_ids
        )
        or ci_run_ids != sorted(set(ci_run_ids))
        or ci_run_ids != [audit_run_id]
    ):
        raise SystemExit("audit report CI run identities are malformed")
    if (
        not isinstance(check_ids, list)
        or tuple(check_ids) != expected_check_ids
        or report.get("check_ids_sha256") != _check_ids_sha256(expected_check_ids)
        or not _nonnegative_integer(report.get("check_count"))
        or report.get("check_count") != len(expected_profile.expected_check_ids)
        or not _sha256(report.get("test_inventory_sha256"))
        or not _sha256(report.get("runtime_matrix_sha256"))
        or not _sha256(report.get("audit_wheelhouse_manifest_sha256"))
        or report.get("runtime_matrix_sha256") != trust.get("runtime_matrix_sha256")
        or report.get("audit_wheelhouse_manifest_sha256")
        != trust.get("audit_wheelhouse_manifest_sha256")
        or not _sha256(report.get("report_sha256"))
        or test_counts.get("collected_tests") != expected_profile.expected_test_count
        or test_counts.get("passed_tests") != expected_profile.expected_test_count
        or test_counts.get("skipped_tests") != 0
        or test_counts.get("failed_tests") != 0
        or (
            not expected_profile.expected_added_test_nodeids
            and report.get("test_inventory_sha256")
            != expected_profile.predecessor_nodeid_sha256
        )
    ):
        raise SystemExit("audit report bounded evidence is malformed")


def _download_single_report(
    *,
    repository: Path,
    repository_slug: str,
    token: str,
    run_id: str,
    reviewed_commit: str,
    controller_commit: str,
    audit_profile_id: str = PHASE5E2B12A_AUDIT_PROFILE,
    expected_profile: AuditProfile | None = None,
) -> tuple[bytes, dict[str, Any]]:
    artifacts = _api_paginated_items(
        f"https://api.github.com/repos/{repository_slug}/actions/runs/{run_id}/artifacts",
        key="artifacts",
        token=token,
    )
    expected_name = f"phase5e-audit-{reviewed_commit}"
    matching = [item for item in artifacts if item.get("name") == expected_name]
    if len(matching) != 1 or matching[0].get("expired"):
        raise SystemExit("canonical protected-base audit artifact is missing or ambiguous")
    archive = _api_bytes(str(matching[0]["archive_download_url"]), token)
    if len(archive) > 10 * 1024 * 1024:
        raise SystemExit("audit artifact archive exceeds its fixed size bound")
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        infos = bundle.infolist()
        if (
            len(infos) != 1
            or infos[0].filename != "phase5e-audit.json"
            or infos[0].file_size > 4 * 1024 * 1024
            or infos[0].compress_size > 4 * 1024 * 1024
            or infos[0].is_dir()
            or infos[0].external_attr >> 16 & 0o170000 not in {0, 0o100000}
        ):
            raise SystemExit("audit artifact is not the exact bounded one-report bundle")
        report_bytes = bundle.read(infos[0])
    report = _load_canonical_evidence_json(report_bytes, "audit report")
    _validate_audit_report_contract(
        report=report,
        reviewed_commit=reviewed_commit,
        audit_run_id=run_id,
        repository=repository,
        controller_commit=controller_commit,
        audit_profile_id=audit_profile_id,
        expected_profile=expected_profile,
    )
    return report_bytes, report


def _verify_remote_evidence(
    *,
    repository: Path,
    repository_slug: str,
    token: str,
    implementation_merge: str,
    implementation_head: str,
    closeout: dict[str, Any],
    audit_profile_id: str = PHASE5E2B12A_AUDIT_PROFILE,
    expected_profile: AuditProfile | None = None,
    controller_app_id: int,
    implementation_branch: str = "fix/phase5e2b12a-r2-coverage-claim-parity",
    require_legacy_closeout_fields: bool = True,
) -> None:
    profile = expected_profile or audit_profile(audit_profile_id)
    installation_id, app_slug = _verify_remote_repository_governance(
        repository_slug,
        token,
        controller_app_id=controller_app_id,
    )
    if (
        closeout.get("controller_app_id") != controller_app_id
        or closeout.get("controller_installation_id") != installation_id
        or closeout.get("controller_app_slug") != app_slug
    ):
        raise SystemExit("acceptance closeout does not bind controller App authority")
    implementation_base = _commit_parents(repository, implementation_merge)[0]
    pull_request = _verify_implementation_pull_request(
        repository_slug=repository_slug,
        token=token,
        pull_request_number=int(closeout["implementation_pull_request"]),
        implementation_merge=implementation_merge,
        implementation_head=implementation_head,
        implementation_base=implementation_base,
        expected_head_ref=implementation_branch,
    )
    pr_run = _verify_run(
        repository_slug=repository_slug,
        token=token,
        run_id=str(closeout["pr_ci_run_id"]),
        expected_head=implementation_head,
        expected_event="pull_request_target",
        expected_head_branch=str(pull_request["head"]["ref"]),
        expected_pull_request_number=int(closeout["implementation_pull_request"]),
        expected_pull_request_head=implementation_head,
        expected_pull_request_head_ref=str(pull_request["head"]["ref"]),
        expected_pull_request_base=implementation_base,
        expected_workflow_name="phase5e2b12a-base-owned-acceptance-gate",
        expected_workflow_file=".github/workflows/phase5e2b12a-acceptance-gate.yml",
    )
    main_run = _verify_run(
        repository_slug=repository_slug,
        token=token,
        run_id=str(closeout["main_ci_run_id"]),
        expected_head=implementation_merge,
        expected_event="workflow_run",
        expected_head_branch="main",
        expected_workflow_name="phase5e2b12a-base-owned-acceptance-gate",
        expected_workflow_file=".github/workflows/phase5e2b12a-acceptance-gate.yml",
    )
    if pr_run["workflow_id"] != main_run["workflow_id"]:
        raise SystemExit("PR and main CI do not use one workflow identity")
    if (
        require_legacy_closeout_fields
        and closeout.get("audit_workflow_id") != pr_run["workflow_id"]
    ):
        raise SystemExit("acceptance evidence does not bind the audit workflow identity")
    _verify_controller_statuses(
        repository_slug=repository_slug,
        token=token,
        head_sha=implementation_head,
        workflow_run_id=str(closeout["pr_ci_run_id"]),
        app_slug=app_slug,
    )
    _, pr_report = _download_single_report(
        repository=repository,
        repository_slug=repository_slug,
        token=token,
        run_id=str(closeout["pr_ci_run_id"]),
        reviewed_commit=implementation_head,
        controller_commit=implementation_base,
        audit_profile_id=audit_profile_id,
        expected_profile=profile,
    )
    report_bytes, report = _download_single_report(
        repository=repository,
        repository_slug=repository_slug,
        token=token,
        run_id=str(closeout["main_ci_run_id"]),
        reviewed_commit=implementation_merge,
        controller_commit=implementation_base,
        audit_profile_id=audit_profile_id,
        expected_profile=profile,
    )
    if hashlib.sha256(report_bytes).hexdigest() != closeout["audit_artifact_sha256"]:
        raise SystemExit("audit artifact report bytes do not match the recorded SHA")
    report_without_sha = dict(report)
    reported_sha = report_without_sha.pop("report_sha256", None)
    recomputed_report_sha = hashlib.sha256(
        json.dumps(report_without_sha, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    counts = report.get("finding_counts", {})
    tests = report.get("test_counts", {})
    if (
        report.get("audit_tool") != AUDIT_TOOL
        or report.get("audit_profile") != profile.profile_id
        or report.get("audit_version") != profile.audit_version
        or report.get("reviewed_commit") != implementation_merge
        or reported_sha != recomputed_report_sha
        or reported_sha != closeout["audit_report_sha256"]
        or report.get("ci_run_ids") != [str(closeout["main_ci_run_id"])]
        or pr_report.get("ci_run_ids") != [str(closeout["pr_ci_run_id"])]
        or any(counts.get(priority) != 0 for priority in ("P0", "P1", "P2", "P3"))
        or tests.get("collected_tests") != profile.expected_test_count
        or tests.get("passed_tests") != profile.expected_test_count
        or tests.get("skipped_tests") != 0
        or tests.get("failed_tests") != 0
        or (
            require_legacy_closeout_fields
            and closeout.get("test_count") != profile.expected_test_count
        )
        or closeout.get("finding_counts", {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
        != {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
        or closeout.get("test_inventory_sha256")
        != report.get("test_inventory_sha256")
        or closeout.get("runtime_matrix_sha256")
        != report.get("runtime_matrix_sha256")
        or closeout.get("audit_wheelhouse_manifest_sha256")
        != report.get("audit_wheelhouse_manifest_sha256")
        or tuple(report.get("check_ids", ()))
        != tuple(sorted(profile.expected_check_ids))
        or report.get("check_ids_sha256")
        != _check_ids_sha256(tuple(sorted(profile.expected_check_ids)))
        or report.get("check_count") != len(profile.expected_check_ids)
        or pr_report.get("test_counts") != tests
        or pr_report.get("audit_trust") != report.get("audit_trust")
        or any(
            pr_report.get("finding_counts", {}).get(priority) != 0
            for priority in ("P0", "P1", "P2", "P3")
        )
    ):
        raise SystemExit("canonical merged-main audit report is not acceptance-grade")
    audited_hashes = report.get("audited_file_sha256", {})
    if commit_exists(PHASE5D_BASELINE, repository):
        audit_comparison_commit = PHASE5D_BASELINE
    else:
        verify_public_bootstrap_snapshot(repository)
        audit_comparison_commit = public_root_commit(repository)
    expected_audited_paths = set(STATIC_CONTROL_FILES) | set(
        str(
            _git(
                repository,
                "diff",
                "--name-only",
                "--no-renames",
                audit_comparison_commit,
                implementation_merge,
            )
        ).splitlines()
    )
    if (
        not isinstance(audited_hashes, dict)
        or set(audited_hashes) != expected_audited_paths
        or not REQUIRED_AUDITED_PATHS.issubset(audited_hashes)
    ):
        raise SystemExit("canonical audit report omits acceptance trust-root files")
    for path, expected_sha in audited_hashes.items():
        raw = _git(repository, "show", f"{implementation_merge}:{path}", text=False)
        if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != expected_sha:
            raise SystemExit(f"audit file hash does not match implementation tree: {path}")


def _verify_phase5e2b12b_remote_evidence(
    *,
    repository: Path,
    repository_slug: str,
    token: str,
    implementation_base: str,
    implementation_merge: str,
    implementation_head: str,
    closeout: dict[str, Any],
    controller_app_id: int,
) -> None:
    successor_trust = _read_hash_bound_control_json(
        "scripts/phase5e2b12b-acceptance-trust.json"
    )
    implementation_branch = str(successor_trust["implementation_branch"])

    parents = _commit_parents(repository, implementation_merge)
    if len(parents) != 2 or parents[0] != implementation_base:
        raise SystemExit("2B remote replay implementation ancestry drifted")
    _verify_remote_evidence(
        repository=repository,
        repository_slug=repository_slug,
        token=token,
        implementation_merge=implementation_merge,
        implementation_head=implementation_head,
        closeout=closeout,
        audit_profile_id=PHASE5E2B12B_AUDIT_PROFILE,
        controller_app_id=controller_app_id,
        implementation_branch=implementation_branch,
    )
def _verify_phase5e_successor_remote_evidence(
    *,
    transition: str,
    repository: Path,
    repository_slug: str,
    token: str,
    implementation_base: str,
    implementation_merge: str,
    implementation_head: str,
    closeout: dict[str, Any],
    bundle: dict[str, Any],
    controller_app_id: int,
) -> None:
    """Replay one generic gate/successor acceptance from protected controller code."""

    # Reports were produced by the protected controller commit (the first parent of the
    # implementation merge), so resolve their exact recursive profile from that commit.  The
    # profile object, including its gate/policy hashes, is passed through rather than reduced to a
    # candidate-supplied string identifier.
    profile = protected_controller_audit_profile(repository, implementation_base)
    position = resolve_controller_gate_position(repository, implementation_merge)
    authority = position["authority"]
    if not isinstance(authority, dict):
        raise SystemExit("generic successor remote authority is malformed")
    if transition == "gate_acceptance":
        implementation_branch = str(authority["bootstrap_branch"])
    elif transition == "successor_acceptance":
        implementation_branch = str(authority["successor_implementation_branch"])
    elif transition == "post_successor_closeout":
        implementation_branch = str(authority["successor_acceptance_branch"])
    else:
        raise SystemExit("unknown generic successor acceptance transition")
    parents = _commit_parents(repository, implementation_merge)
    if len(parents) != 2 or parents[0] != implementation_base:
        raise SystemExit("generic successor implementation ancestry drifted")
    _verify_remote_evidence(
        repository=repository,
        repository_slug=repository_slug,
        token=token,
        implementation_merge=implementation_merge,
        implementation_head=implementation_head,
        closeout=closeout,
        expected_profile=profile,
        controller_app_id=controller_app_id,
        implementation_branch=implementation_branch,
    )
    if transition == "gate_acceptance" and implementation_branch == EXTERNAL_CONTROLLER_BRANCH:
        pull_request = _api_json(
            (
                f"https://api.github.com/repos/{repository_slug}/pulls/"
                f"{int(closeout['implementation_pull_request'])}"
            ),
            token,
        )
        _verify_external_handoff_merge_window(
            handoff=_read_json(repository, implementation_head, EXTERNAL_HANDOFF_PATH),
            pull_request=pull_request,
        )


def _verify_post_implementation_control_revalidation(
    *,
    repository: Path,
    implementation_merge: str,
    acceptance_base: str,
) -> None:
    """Allow only the audited control-plane merges needed to unblock acceptance."""

    if implementation_merge == acceptance_base:
        return
    ancestor = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            implementation_merge,
            acceptance_base,
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if ancestor.returncode != 0:
        raise SystemExit("acceptance base does not descend from the recorded implementation")
    changed_paths = {
        path
        for _, path in _diff_entries(repository, implementation_merge, acceptance_base)
    }
    if not changed_paths or not changed_paths.issubset(
        POST_IMPLEMENTATION_CONTROL_REVALIDATION_PATHS
    ):
        unexpected = sorted(
            changed_paths - POST_IMPLEMENTATION_CONTROL_REVALIDATION_PATHS
        )
        raise SystemExit(
            "post-implementation history changes non-control paths: "
            f"{unexpected or sorted(changed_paths)}"
        )
    if _read_json(repository, implementation_merge, STATUS_PATH) != _read_json(
        repository, acceptance_base, STATUS_PATH
    ):
        raise SystemExit("post-implementation control history changed phase authority")
    if _path_exists(repository, acceptance_base, CLOSEOUT_PATH):
        raise SystemExit("acceptance closeout already exists on the acceptance base")
    if (
        not _path_exists(repository, acceptance_base, PUBLIC_REVALIDATION_PATH)
        or _read_json(repository, acceptance_base, PUBLIC_REVALIDATION_PATH)
        != PUBLIC_REVALIDATION_PAYLOAD
    ):
        raise SystemExit("acceptance base lacks the current public revalidation marker")

    commits = str(
        _git(
            repository,
            "rev-list",
            "--first-parent",
            "--reverse",
            f"{implementation_merge}..{acceptance_base}",
        )
    ).splitlines()
    if not commits or commits[-1] != acceptance_base:
        raise SystemExit("post-implementation first-parent history is incomplete")
    previous = implementation_merge
    for commit in commits:
        parents = _commit_parents(repository, commit)
        if len(parents) != 2 or parents[0] != previous:
            raise SystemExit(
                "post-implementation control history contains a non-PR or nonlinear commit"
            )
        if _tree(repository, commit) != _tree(repository, parents[1]):
            raise SystemExit(
                "post-implementation control merge tree differs from its pull-request head"
            )
        entries = _diff_entries(repository, previous, commit)
        commit_paths = {path for _, path in entries}
        if not commit_paths or not commit_paths.issubset(
            POST_IMPLEMENTATION_CONTROL_REVALIDATION_PATHS
        ):
            unexpected = sorted(
                commit_paths - POST_IMPLEMENTATION_CONTROL_REVALIDATION_PATHS
            )
            raise SystemExit(
                "post-implementation merge changes non-control paths: "
                f"{unexpected or sorted(commit_paths)}"
            )
        for status, path in entries:
            if status not in {"A", "M"} or _mode(repository, commit, path) != "100644":
                raise SystemExit(
                    "post-implementation control history changes file lifecycle or mode: "
                    f"{status} {path}"
                )
        previous = commit


def verify_acceptance(
    *,
    repository: Path,
    base: str,
    head: str,
    event: dict[str, Any] | None,
    repository_slug: str | None,
    token: str | None,
    require_remote: bool,
    controller_app_id: int | None = None,
) -> None:
    if _path_exists(repository, base, CLOSEOUT_PATH):
        raise SystemExit("acceptance closeout already exists on the base commit")
    base_status = _read_json(repository, base, STATUS_PATH)
    if not _governance_state_matches(
        base_status,
        current_phase="Phase 5E-2B.1",
        state="implementation_complete_pending_acceptance",
        authorized_next=PENDING_AUTHORIZED_NEXT,
        prohibited=PENDING_PROHIBITED,
    ):
        raise SystemExit("acceptance base is not the exact pending 2A governance state")
    if str(_git(repository, "merge-base", base, head)) != base:
        raise SystemExit("acceptance head is not based directly on the acceptance base")
    if _commit_parents(repository, head) != (base,):
        raise SystemExit("acceptance head must be one direct non-merge commit over the base")
    closeout = _read_json(repository, head, CLOSEOUT_PATH)
    implementation_merge = closeout.get("implementation_merge_commit")
    if not _git_oid(implementation_merge):
        raise SystemExit("acceptance evidence lacks a valid implementation merge")
    parents = _commit_parents(repository, implementation_merge)
    if len(parents) != 2:
        raise SystemExit("recorded implementation is not a two-parent pull-request merge")
    implementation_head = parents[1]
    if _tree(repository, implementation_merge) != _tree(repository, implementation_head):
        raise SystemExit("implementation merge tree differs from its pull-request head")
    _verify_post_implementation_control_revalidation(
        repository=repository,
        implementation_merge=implementation_merge,
        acceptance_base=base,
    )
    entries = _diff_entries(repository, base, head)
    if {path: status for status, path in entries} != {
        STATUS_PATH: "M",
        CLOSEOUT_PATH: "A",
    }:
        raise SystemExit("acceptance PR must modify status and add one new closeout")
    changed_paths = {path for _, path in entries}
    if not MANDATORY_CHANGED_PATHS.issubset(changed_paths):
        raise SystemExit("acceptance PR omits mandatory status or evidence files")
    if not changed_paths.issubset(MUTABLE_GOVERNANCE_PATHS):
        unexpected = sorted(changed_paths - MUTABLE_GOVERNANCE_PATHS)
        raise SystemExit(f"acceptance PR changes frozen paths: {unexpected}")
    for status, path in entries:
        if status not in {"A", "M"} or _mode(repository, head, path) != "100644":
            raise SystemExit(
                f"acceptance PR changes file type, mode, or lifecycle: {status} {path}"
            )
    if _mode(repository, head, CLOSEOUT_PATH) != "100644":
        raise SystemExit("acceptance evidence is not a regular file")

    expected_tree = _tree(repository, implementation_merge)
    if (
        set(closeout) != EXPECTED_CLOSEOUT_KEYS
        or closeout.get("schema_version") != "1.0.0"
        or closeout.get("phase") != "Phase 5E-2B.1-2A"
        or closeout.get("implementation_merge_commit") != implementation_merge
        or closeout.get("implementation_head_commit") != implementation_head
        or closeout.get("implementation_tree_sha") != expected_tree
        or type(closeout.get("implementation_pull_request")) is not int
        or closeout["implementation_pull_request"] <= 0
        or type(closeout.get("acceptance_pull_request")) is not int
        or closeout["acceptance_pull_request"] <= 0
        or closeout.get("audit_tool") != AUDIT_TOOL
        or type(closeout.get("audit_workflow_id")) is not int
        or closeout["audit_workflow_id"] <= 0
        or type(closeout.get("controller_app_id")) is not int
        or closeout["controller_app_id"] <= 0
        or not isinstance(closeout.get("controller_app_slug"), str)
        or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?",
            closeout["controller_app_slug"],
        )
        or type(closeout.get("controller_installation_id")) is not int
        or closeout["controller_installation_id"] <= 0
        or closeout.get("audit_profile") != PHASE5E2B12A_AUDIT_PROFILE
        or closeout.get("audit_version") != AUDIT_VERSION
        or any(
            not isinstance(closeout.get(field), str) or not closeout[field]
            for field in (
                "pr_ci_run_id",
                "main_ci_run_id",
                "audit_report_sha256",
                "audit_artifact_sha256",
                "test_inventory_sha256",
                "runtime_matrix_sha256",
                "audit_wheelhouse_manifest_sha256",
            )
        )
        or type(closeout.get("test_count")) is not int
        or closeout.get("test_count") != EXPECTED_TEST_COUNT
    ):
        raise SystemExit("acceptance evidence does not bind the implementation merge")
    for field in (
        "audit_report_sha256",
        "audit_artifact_sha256",
        "test_inventory_sha256",
        "runtime_matrix_sha256",
        "audit_wheelhouse_manifest_sha256",
    ):
        value = closeout[field]
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise SystemExit(f"acceptance evidence contains an invalid {field}")
    for field in ("pr_ci_run_id", "main_ci_run_id"):
        if not closeout[field].isdigit():
            raise SystemExit(f"acceptance evidence contains an invalid {field}")

    expected_status = dict(base_status)
    expected_status.update(
        {
            "current_phase": "Phase 5E-2B.1-2A",
            "status": "accepted_closed",
            "authorized_next": list(ACCEPTED_AUTHORIZED_NEXT),
            "prohibited": list(ACCEPTED_PROHIBITED),
            "release_tag": None,
        }
    )
    status = _read_json(repository, head, STATUS_PATH)
    if status != expected_status:
        raise SystemExit("acceptance machine state does not authorize only Phase 5E-2B.1-2B")
    if event is not None:
        pull_request = event.get("pull_request", {})
        if (
            event.get("repository", {}).get("full_name") != repository_slug
            or pull_request.get("base", {}).get("ref") != "main"
            or pull_request.get("base", {}).get("repo", {}).get("full_name") != repository_slug
            or pull_request.get("head", {}).get("repo", {}).get("full_name") != repository_slug
            or pull_request.get("base", {}).get("sha") != base
            or pull_request.get("head", {}).get("sha") != head
            or pull_request.get("head", {}).get("ref") != "feature/phase5e2b12a-acceptance-closeout"
            or closeout.get("acceptance_pull_request") != event.get("number")
        ):
            raise SystemExit("GitHub event identity does not match the acceptance evidence")
    if require_remote:
        if not repository_slug or not token or controller_app_id is None:
            raise SystemExit(
                "remote evidence verification requires repository, token, and controller App"
            )
        _verify_remote_evidence(
            repository=repository,
            repository_slug=repository_slug,
            token=token,
            implementation_merge=implementation_merge,
            implementation_head=implementation_head,
            closeout=closeout,
            controller_app_id=controller_app_id,
        )


def verify_non_acceptance_pr(
    *,
    repository: Path,
    base: str,
    head: str,
    event: dict[str, Any] | None,
    repository_slug: str | None,
    token: str | None = None,
    require_remote: bool = False,
    controller_app_id: int | None = None,
) -> None:
    if event is None or not repository_slug:
        raise SystemExit("non-acceptance classification requires GitHub event identity")
    pull_request = event.get("pull_request", {})
    head_ref = pull_request.get("head", {}).get("ref")
    if (
        event.get("repository", {}).get("full_name") != repository_slug
        or pull_request.get("base", {}).get("ref") != "main"
        or pull_request.get("base", {}).get("repo", {}).get("full_name") != repository_slug
        or pull_request.get("head", {}).get("repo", {}).get("full_name") != repository_slug
        or pull_request.get("base", {}).get("sha") != base
        or pull_request.get("head", {}).get("sha") != head
        or not isinstance(head_ref, str)
        or not head_ref
        or head_ref == "feature/phase5e2b12a-acceptance-closeout"
    ):
        raise SystemExit("GitHub event identity does not match a non-acceptance pull request")
    merge_base = str(_git(repository, "merge-base", base, head))
    if merge_base != base:
        raise SystemExit("non-acceptance pull request is not based on current main")
    changed_paths = {path for _, path in _diff_entries(repository, merge_base, head)}
    accepted_closeout_exists = _path_exists(repository, base, CLOSEOUT_PATH)
    base_status = _read_json(repository, base, STATUS_PATH)
    if not accepted_closeout_exists:
        if not _governance_state_matches(
            base_status,
            current_phase="Phase 5E-2B.1",
            state="implementation_complete_pending_acceptance",
            authorized_next=PENDING_AUTHORIZED_NEXT,
            prohibited=PENDING_PROHIBITED,
        ):
            raise SystemExit("pending 2A base governance state is malformed")
        if head_ref == PUBLIC_REVALIDATION_BRANCH:
            base_marker = (
                _read_json(repository, base, PUBLIC_REVALIDATION_PATH)
                if _path_exists(repository, base, PUBLIC_REVALIDATION_PATH)
                else None
            )
            if base_marker is None:
                expected_marker_payloads = (PUBLIC_REVALIDATION_PAYLOAD,)
            elif base_marker == PUBLIC_REVALIDATION_LEGACY_PAYLOAD:
                expected_marker_payloads = (PUBLIC_REVALIDATION_GENERATION6_PAYLOAD,)
            elif base_marker == PUBLIC_REVALIDATION_GENERATION6_PAYLOAD:
                # The protected predecessor test surface historically resolves
                # PUBLIC_REVALIDATION_PAYLOAD from the candidate controller.  Preserve the
                # normal generation-7 hop while allowing that exact, remote-authorized,
                # one-file bootstrap test to target the current generation directly.
                expected_marker_payloads = (
                    PUBLIC_REVALIDATION_GENERATION7_PAYLOAD,
                    PUBLIC_REVALIDATION_PAYLOAD,
                )
            elif base_marker == PUBLIC_REVALIDATION_GENERATION7_PAYLOAD:
                expected_marker_payloads = (PUBLIC_REVALIDATION_PAYLOAD,)
            else:
                expected_marker_payloads = ()
            expected_marker_change = (
                (("A", PUBLIC_REVALIDATION_PATH),)
                if base_marker is None
                else (("M", PUBLIC_REVALIDATION_PATH),)
            )
            if (
                not require_remote
                or token is None
                or controller_app_id is None
                or not expected_marker_payloads
                or _commit_parents(repository, head) != (base,)
                or _diff_entries(repository, base, head) != expected_marker_change
                or _mode(repository, head, PUBLIC_REVALIDATION_PATH) != "100644"
                or _read_json(repository, head, PUBLIC_REVALIDATION_PATH)
                not in expected_marker_payloads
            ):
                raise SystemExit(
                    "public Controller revalidation is not the exact one-file audit marker"
                )
            _verify_remote_repository_governance(
                repository_slug,
                token,
                controller_app_id=controller_app_id,
            )
            return
        raise SystemExit("pending 2A permits only the reserved acceptance closeout PR")

    closeout = _read_json(repository, base, CLOSEOUT_PATH)
    if not _accepted_closeout_has_closed_shape(closeout):
        raise SystemExit("accepted 2A base evidence is malformed")
    if (
        not _path_exists(repository, base, PUBLIC_REVALIDATION_PATH)
        or _read_json(repository, base, PUBLIC_REVALIDATION_PATH)
        != PUBLIC_REVALIDATION_PAYLOAD
        or PUBLIC_REVALIDATION_PATH in changed_paths
    ):
        raise SystemExit("accepted public Controller revalidation marker drifted")
    violations = sorted(changed_paths & PERMANENT_ACCEPTED_TRUST_ROOT)
    if violations:
        raise SystemExit(
            f"non-acceptance pull request changes the frozen acceptance trust root: {violations}"
        )
    successor_state = _resolve_legacy_successor_state(repository, base)
    if not require_remote or token is None or controller_app_id is None:
        raise SystemExit("every successor transition requires protected remote authority")
    controller_installation_id, controller_app_slug = _verify_remote_repository_governance(
        repository_slug,
        token,
        controller_app_id=controller_app_id,
    )
    if successor_state == "s1":
        _verify_base_merged_main_finalized(
            repository=repository,
            base=base,
            repository_slug=repository_slug,
            token=token,
            controller_app_id=controller_app_id,
        )

    if successor_state in {"s1", "s2"}:
        acceptance_transition = successor_state == "s2"
        _run_protected_structural_gate(
            relative_script="scripts/verify_phase5e2b12b_acceptance_gate.py",
            repository=repository,
            base=base,
            head=head,
            event=event,
            repository_slug=repository_slug,
        )
        if acceptance_transition:
            implementation_parents = _commit_parents(repository, base)
            if len(implementation_parents) != 2:
                raise SystemExit("2B acceptance base is not a two-parent implementation merge")
            _verify_phase5e2b12b_remote_evidence(
                repository=repository,
                repository_slug=repository_slug,
                token=token,
                implementation_base=implementation_parents[0],
                implementation_merge=base,
                implementation_head=implementation_parents[1],
                closeout=_read_json(
                    repository,
                    head,
                    "docs/phase5e2b12b-acceptance-closeout.json",
                ),
                controller_app_id=controller_app_id,
            )
        return

    if successor_state != "s3":
        raise SystemExit("legacy successor state is invalid or no longer authorized")

    position = resolve_controller_gate_position(repository, base)
    generic_state = position["stage"]
    if generic_state in {"s3", "g2", "g5"}:
        _verify_base_merged_main_finalized(
            repository=repository,
            base=base,
            repository_slug=repository_slug,
            token=token,
            controller_app_id=controller_app_id,
        )

    _run_protected_structural_gate(
        relative_script="scripts/verify_phase5e_successor_gate.py",
        repository=repository,
        base=base,
        head=head,
        event=event,
        repository_slug=repository_slug,
    )
    external_controller_transition = (
        generic_state == "g5"
        and isinstance(position.get("bundle"), dict)
        and position["bundle"].get("next_gate_seed") is None
        and isinstance(position.get("authority"), dict)
        and position["authority"].get("next_owner_phase") == "Phase 5E-2C-P"
    )
    if external_controller_transition:
        _verify_external_controller_handoff_remote(
            repository=repository,
            repository_slug=repository_slug,
            token=token,
            base=base,
            head=head,
            event=event,
            controller_app_id=controller_app_id,
            controller_app_slug=controller_app_slug,
            controller_installation_id=controller_installation_id,
        )
    if generic_state in {"g1", "g3", "g4"}:
        authority = position["authority"]
        bundle = position["bundle"]
        if not isinstance(authority, dict) or not isinstance(bundle, dict):
            raise SystemExit("generic acceptance lacks a frozen authority bundle")
        if generic_state == "g1":
            closeout_path = str(authority["closeout_path"])
            transition = "gate_acceptance"
        elif generic_state == "g3":
            closeout_path = str(authority["successor_closeout_path"])
            transition = "successor_acceptance"
        else:
            closeout_path = str(bundle["post_successor_closeout"]["closeout_path"])
            transition = "post_successor_closeout"
        implementation_parents = _commit_parents(repository, base)
        if len(implementation_parents) != 2:
            raise SystemExit("generic acceptance base is not a two-parent implementation merge")
        _verify_phase5e_successor_remote_evidence(
            transition=transition,
            repository=repository,
            repository_slug=repository_slug,
            token=token,
            implementation_base=implementation_parents[0],
            implementation_merge=base,
            implementation_head=implementation_parents[1],
            closeout=_read_json(repository, head, closeout_path),
            bundle=bundle,
            controller_app_id=controller_app_id,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--event-json", type=Path)
    parser.add_argument("--repository-slug")
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument(
        "--controller-app-id",
        type=int,
        default=os.environ.get(CONTROLLER_APP_ID_VARIABLE),
    )
    parser.add_argument(
        "--kernel-reader-app-id",
        type=int,
        default=os.environ.get(KERNEL_READER_APP_ID_VARIABLE),
    )
    parser.add_argument("--kernel-reader-app-slug")
    parser.add_argument("--kernel-reader-installation-id", type=int)
    parser.add_argument("--controller-app-slug")
    parser.add_argument("--controller-installation-id", type=int)
    parser.add_argument(
        "--external-gate-author-app-id",
        type=int,
        default=os.environ.get(EXTERNAL_GATE_AUTHOR_APP_ID_VARIABLE),
    )
    parser.add_argument("--external-gate-author-app-slug")
    parser.add_argument("--external-gate-author-installation-id", type=int)
    parser.add_argument("--require-remote", action="store_true")
    parser.add_argument("--non-acceptance-pr", action="store_true")
    parser.add_argument("--print-audit-profile", action="store_true")
    parser.add_argument("--verify-remote-governance-only", action="store_true")
    parser.add_argument("--verify-kernel-reader-authority-only", action="store_true")
    parser.add_argument("--verify-controller-authority-only", action="store_true")
    parser.add_argument(
        "--verify-external-gate-author-authority-only",
        action="store_true",
    )
    parser.add_argument(
        "--verify-external-gate-author-handoff-only",
        action="store_true",
    )
    parser.add_argument(
        "--hard-revoke-current-installation-token",
        action="store_true",
    )
    parser.add_argument("--merged-main")
    parser.add_argument("--triggering-ci-run-id")
    args = parser.parse_args()
    event = json.loads(args.event_json.read_text()) if args.event_json else None
    if args.hard_revoke_current_installation_token:
        if not args.github_token:
            raise SystemExit("hard revocation requires the current installation token")
        _hard_revoke_installation_token(args.github_token)
        print("Phase 5E installation token hard revocation and 401 probe passed")
        return 0
    if args.verify_controller_authority_only:
        controller_app_jwt = os.environ.get(CONTROLLER_APP_JWT_ENV)
        if (
            not args.github_token
            or not controller_app_jwt
            or type(args.controller_app_id) is not int
            or not args.controller_app_slug
            or type(args.controller_installation_id) is not int
        ):
            raise SystemExit(
                "controller replay requires token and exact action authority outputs"
            )
        _verify_controller_token_authority(
            args.github_token,
            app_jwt=controller_app_jwt,
            app_id=args.controller_app_id,
            app_slug=args.controller_app_slug,
            installation_id=args.controller_installation_id,
        )
        print("Phase 5E controller authority replay passed")
        return 0
    if args.verify_external_gate_author_authority_only:
        author_app_jwt = os.environ.get(EXTERNAL_GATE_AUTHOR_APP_JWT_ENV)
        if (
            not args.github_token
            or not author_app_jwt
            or type(args.external_gate_author_app_id) is not int
            or not args.external_gate_author_app_slug
            or type(args.external_gate_author_installation_id) is not int
        ):
            raise SystemExit(
                "external gate-author replay requires token and exact action outputs"
            )
        _verify_external_gate_author_token_authority(
            args.github_token,
            app_jwt=author_app_jwt,
            app_id=args.external_gate_author_app_id,
            app_slug=args.external_gate_author_app_slug,
            installation_id=args.external_gate_author_installation_id,
        )
        print("Phase 5E external gate-author authority replay passed")
        return 0
    if args.verify_external_gate_author_handoff_only:
        if (
            not args.base
            or not args.head
            or not isinstance(event, dict)
            or not args.repository_slug
            or not args.github_token
            or type(PINNED_CONTROLLER_APP_ID) is not int
            or not isinstance(PINNED_CONTROLLER_APP_SLUG, str)
            or type(PINNED_CONTROLLER_INSTALLATION_ID) is not int
        ):
            raise SystemExit(
                "external gate-author provenance replay requires exact PR and authority inputs"
            )
        _verify_external_controller_handoff_remote(
            repository=args.repository.resolve(),
            repository_slug=args.repository_slug,
            token=args.github_token,
            base=args.base,
            head=args.head,
            event=event,
            controller_app_id=PINNED_CONTROLLER_APP_ID,
            controller_app_slug=PINNED_CONTROLLER_APP_SLUG,
            controller_installation_id=PINNED_CONTROLLER_INSTALLATION_ID,
        )
        print("Phase 5E external gate-author handoff provenance replay passed")
        return 0
    if args.verify_kernel_reader_authority_only:
        kernel_reader_app_jwt = os.environ.get(KERNEL_READER_APP_JWT_ENV)
        if (
            not args.github_token
            or not kernel_reader_app_jwt
            or type(args.kernel_reader_app_id) is not int
            or not args.kernel_reader_app_slug
            or type(args.kernel_reader_installation_id) is not int
        ):
            raise SystemExit(
                "kernel-reader replay requires token and exact action authority outputs"
            )
        _verify_kernel_reader_token_authority(
            args.github_token,
            app_jwt=kernel_reader_app_jwt,
            app_id=args.kernel_reader_app_id,
            app_slug=args.kernel_reader_app_slug,
            installation_id=args.kernel_reader_installation_id,
        )
        print("Phase 5E kernel-reader authority replay passed")
        return 0
    if args.verify_remote_governance_only:
        if (
            not args.repository_slug
            or not args.github_token
            or type(args.controller_app_id) is not int
        ):
            raise SystemExit(
                "remote-governance replay requires repository, token, and controller App"
            )
        _verify_remote_repository_governance(
            args.repository_slug,
            args.github_token,
            controller_app_id=args.controller_app_id,
        )
        print("Phase 5E remote governance authority replay passed")
        return 0
    if args.print_audit_profile:
        if not args.base:
            raise SystemExit("audit-profile classification requires --base")
        print(
            protected_controller_audit_profile(
                args.repository.resolve(), args.base
            ).profile_id
        )
        return 0
    if args.merged_main:
        if not args.repository_slug or not args.github_token or not args.triggering_ci_run_id:
            raise SystemExit("merged-main verification requires remote identity and CI run ID")
        verified = verify_merged_main_acceptance(
            repository=args.repository.resolve(),
            merged_main=args.merged_main,
            repository_slug=args.repository_slug,
            token=args.github_token,
            triggering_ci_run_id=args.triggering_ci_run_id,
            controller_app_id=args.controller_app_id,
        )
        print(
            "Phase 5E-2B.1-2A merged-main acceptance evidence passed"
            if verified
            else "No Phase 5E-2B.1-2A accepted state requires merged-main verification"
        )
        return 0
    if not args.base or not args.head:
        raise SystemExit("pull-request acceptance verification requires --base and --head")
    if args.non_acceptance_pr:
        verify_non_acceptance_pr(
            repository=args.repository.resolve(),
            base=args.base,
            head=args.head,
            event=event,
            repository_slug=args.repository_slug,
            token=args.github_token,
            require_remote=args.require_remote,
            controller_app_id=args.controller_app_id,
        )
        print("Non-acceptance pull request preserves the frozen acceptance trust root")
        return 0
    verify_acceptance(
        repository=args.repository.resolve(),
        base=args.base,
        head=args.head,
        event=event,
        repository_slug=args.repository_slug,
        token=args.github_token,
        require_remote=args.require_remote,
        controller_app_id=args.controller_app_id,
    )
    print("Phase 5E-2B.1-2A base-owned acceptance gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
