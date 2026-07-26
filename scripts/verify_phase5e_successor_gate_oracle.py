#!/usr/bin/env python3
"""Independent commit-bound oracle for recursive Phase 5E successor gates.

This verifier deliberately imports no production gate, audit, or ``owner_research`` module.  It
reads only full Git commit identities, independently recomputes the exact transition diff and file
modes, traverses every accepted gate seed, and treats the candidate ``semantic-oracle.py.txt`` as
an inert bounded literal manifest.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

TRUST_PATH = "scripts/phase5e2b12b-acceptance-trust.json"
BASE_TRUST_PATH = "scripts/phase5e2b12a-acceptance-trust.json"
STATUS_PATH = "docs/phase-status.json"
COMPONENT_LOCK_PATH = "component-lock.json"
_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_BRANCH = re.compile(r"(?:feature|fix)/[a-z0-9][a-z0-9._/-]*\Z")
_CHECK_ID = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_AUDIT_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){2,4}\Z")
_UTC_TIMESTAMP = re.compile(
    r"20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)
_EXTERNAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_BUNDLE_BYTES = 512 * 1024
_MAX_ORACLE_BYTES = 64 * 1024
_MAX_CASE_BYTES = 256 * 1024
_MAX_AST_NODES = 4096
_MAX_CHAIN_DEPTH = 64
_KERNEL = {
    "tag": "v2.0.0-rc.2",
    "tag_object": "4e19ce6a59bc4321ebcd368e807ed764f4e8abde",
    "commit": "be9b0773d5a78f5f8a33ba982494512668df85fe",
    "wheel_sha256": "fb27d01b1ee75fbd542371510150e890516d306218d33f3608f2aa3caa0e55a5",
}
_PHASE_SUCCESSOR = {
    "Phase 5E-2B.1-2C": "Phase 5E-2C-P",
    "Phase 5E-2C-P": "Phase 5E-2C-0",
    "Phase 5E-2C-0": "Phase 5E-2C-1",
    "Phase 5E-2C-1": "Phase 5E-2C-2",
    "Phase 5E-2C-2": "Phase 5E-2C-3",
    "Phase 5E-2C-3": "Phase 5E-2C-4",
    "Phase 5E-2C-4": "Phase 5E-2D-0",
    "Phase 5E-2D-0": "Phase 5E-2D-1",
    "Phase 5E-2D-1": "Phase 5E-2D-2",
    "Phase 5E-2D-2": "Phase 5E-2E",
    "Phase 5E-2E": "Phase 5E-2F",
    "Phase 5E-2F": "Phase 5E-3-0",
    "Phase 5E-3-0": "Phase 5E-3-1",
    "Phase 5E-3-1": "Phase 5E-3-2",
    "Phase 5E-3-2": "Phase 5E-3-3",
    "Phase 5E-3-3": "Phase 5E-3-4",
    "Phase 5E-3-4": "Phase 5E-4-0",
    "Phase 5E-4-0": "Phase 5E-4-1",
    "Phase 5E-4-1": "Phase 5E-4-2",
    "Phase 5E-4-2": "Phase 5E-4-3",
    "Phase 5E-4-3": "Phase 5E-5A",
    "Phase 5E-5A": "Phase 5E-5B",
    "Phase 5E-5B": "Phase 5E-5C",
    "Phase 5E-5C": "Phase 5E-6",
    "Phase 5E-6": "Phase 5F-0",
    "Phase 5F-0": "Phase 5F-1",
    "Phase 5F-1": "Phase 5F-2",
    "Phase 5F-2": "Phase 5F-3",
    "Phase 5F-3": "Phase 5F-4",
    "Phase 5F-4": None,
}
_TERMINAL_PHASE = "Phase 5F-4"
_EXTERNAL_FEASIBILITY_PHASE = "Phase 5E-2C-P"
_EXTERNAL_TARGET_PHASE = "Phase 5E-2C-0"
_CONTROLLER_REAUTHORIZATION_BOUNDARIES = frozenset({_EXTERNAL_TARGET_PHASE})
_EXTERNAL_CONTROLLER_BRANCH = "feature/phase5e2c0-controller-gate-bootstrap"
_EXTERNAL_HANDOFF_PATH = (
    "governance/phase5e-external/phase5e2cp-controller-handoff.json"
)
_EXTERNAL_GATE_DIRECTORY = "governance/phase5e-gates/phase5e2c0"
_EXTERNAL_PROTECTED_ORACLE_PATH = "scripts/verify_phase5e2c0_semantic_oracle.py"
_EXTERNAL_CONTROLLER_DIFF = {
    STATUS_PATH: "M",
    _EXTERNAL_HANDOFF_PATH: "A",
    f"{_EXTERNAL_GATE_DIRECTORY}/bundle.json": "A",
    f"{_EXTERNAL_GATE_DIRECTORY}/semantic-oracle.py.txt": "A",
    f"{_EXTERNAL_GATE_DIRECTORY}/adversarial-cases.json": "A",
}
_EXTERNAL_2C0_IMPLEMENTATION_DIFF = {
    COMPONENT_LOCK_PATH: "M",
    STATUS_PATH: "M",
    "plugins/owner-equity-research/.codex-plugin/plugin.json": "M",
    "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md": "M",
    "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md": "M",
    "pyproject.toml": "M",
    "schemas/market-reference-snapshot.schema.json": "M",
    "schemas/valuation-handoff.schema.json": "M",
    "src/owner_research/resources/market_access/vendor-market-contract-policy.json": "A",
    "src/owner_research/valuation_vendor_market_contract_types.py": "A",
    "tests/fixtures/phase5e2c0/adversarial-cases.json": "A",
    "tests/test_phase5e2c0_vendor_market_contract.py": "A",
}
_EXTERNAL_HANDOFF_KEYS = {
    "schema_version",
    "external_phase",
    "source_gate_id",
    "source_owner_phase",
    "target_owner_phase",
    "predecessor_commit",
    "predecessor_tree",
    "predecessor_state_fingerprint",
    "receipt_bindings",
    "receipt_set_sha256",
    "challenge_nonce",
    "policy_path",
    "policy_sha256",
    "policy_overlay_path",
    "policy_overlay_sha256",
    "authority_seed",
    "authority_seed_sha256",
    "author_app_id",
    "author_app_slug",
    "author_installation_id",
    "controller_app_id",
    "controller_app_slug",
    "controller_installation_id",
    "approved_at",
}
_EXTERNAL_RECEIPT_KEYS = {"payload", "signature_hex"}
_EXTERNAL_RECEIPT_PAYLOAD_KEYS = {
    "schema_version",
    "kind",
    "sequence",
    "receipt_id",
    "decision",
    "feasibility_conditions",
    "repository_id",
    "repository",
    "source_gate_id",
    "source_owner_phase",
    "target_owner_phase",
    "predecessor_commit",
    "predecessor_tree",
    "predecessor_state_fingerprint",
    "component_lock_sha256",
    "authority_seed_sha256",
    "policy_sha256",
    "challenge_nonce",
    "issued_at",
    "expires_at",
    "artifact_store",
    "artifact_object_id",
    "artifact_version",
    "artifact_sha256",
    "prior_receipt_sha256",
    "signer_key_id",
}
_EXTERNAL_RECEIPT_KINDS = ("legal", "account", "protocol")
_EXTERNAL_CONDITION_COVERAGE = {
    "legal": (
        "account_agreement_permits_internal_valuation_use",
        "data_rights_permit_private_encrypted_cas_retention_and_independent_audit_replay",
    ),
    "account": ("qot_login_true_while_trade_login_false_is_enforceable",),
    "protocol": ("raw_protobuf_s2c_bytes_are_stably_capturable",),
}
_EXTERNAL_RELEASABLE_FROZEN = frozenset(
    {
        COMPONENT_LOCK_PATH,
        "pyproject.toml",
        "schemas/market-reference-snapshot.schema.json",
        "schemas/valuation-handoff.schema.json",
    }
)
_EXTERNAL_RELEASABLE_PREFIXES = frozenset({"plugins", "schemas"})
_EXTERNAL_RELEASE_ALLOWLIST = frozenset(
    {
        COMPONENT_LOCK_PATH,
        "pyproject.toml",
        "plugins/owner-equity-research/.codex-plugin/plugin.json",
        "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md",
        "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md",
        "schemas/market-reference-snapshot.schema.json",
        "schemas/valuation-handoff.schema.json",
    }
)
_RECEIPT_DOMAIN = "owner-equity-research/phase5e2cp/receipt/v1"
_RECEIPT_MAX_VALIDITY_SECONDS = 86400
_PROTECTED_EXTERNAL_TRUST: dict[str, Any] | None = None
_MAX_EXTERNAL_HANDOFF_BYTES = 64 * 1024
_SHARED_MUTABLE_PATHS = frozenset({STATUS_PATH})
_GENERIC_CHECKS = frozenset(
    {
        "audit-controller-integrity",
        "audited-files-present",
        "clean-after",
        "exact-head-no-remote",
        "fixed-baselines",
        "full-verification",
        "independent-market-authority-oracle",
        "independent-test-manifest-replay",
        "kernel-exact-head-no-remote",
        "os-sandbox-boundary",
        "phase5e-successor-independent-semantic-oracle",
        "phase5e-successor-repository-wide-changed-path-boundary",
        "phase5e2b11-frozen-acceptance",
        "read-only-checkout",
        "tracked-bytes-immutable",
    }
)
_CONTROL_FROZEN = frozenset(
    {
        "tests/test_phase5e2b12a_acceptance_gate.py",
        "tests/test_phase5e2b12b_acceptance_gate.py",
        "tests/test_phase5e_audit.py",
        "tests/test_phase5e_successor_gate.py",
    }
)
_CONTROL_FORBIDDEN = frozenset({".github", "scripts"})
_STATE_KEYS = {"current_phase", "status", "authorized_next", "prohibited", "release_tag"}
_AUTHORITY_KEYS = {
    "gate_id",
    "owner_phase",
    "next_owner_phase",
    "next_gate_authority_sha256",
    "bootstrap_branch",
    "acceptance_branch",
    "bundle_directory",
    "closeout_path",
    "successor_closeout_path",
    "successor_implementation_branch",
    "successor_acceptance_branch",
    "gate_bootstrap_diff",
    "gate_acceptance_diff",
    "successor_implementation_diff",
    "successor_acceptance_diff",
    "pending_gate_state",
    "accepted_gate_state",
    "successor_pending_state",
    "successor_accepted_state",
    "frozen_paths",
    "forbidden_prefixes",
    "audit_policy",
}
_AUDIT_POLICY_KEYS = {
    "profile_id",
    "audit_version",
    "protected_oracle_path",
    "protected_oracle_sha256",
    "expected_added_test_nodeids",
    "mandatory_check_ids",
    "predecessor_test_count",
    "predecessor_nodeid_sha256",
}
_BUNDLE_KEYS = {
    "schema_version",
    "gate_id",
    "owner_phase",
    "predecessor_state_fingerprint",
    "gate_bootstrap_branch",
    "gate_acceptance_branch",
    "gate_bootstrap_diff",
    "gate_acceptance_diff",
    "successor_implementation_branch",
    "successor_acceptance_branch",
    "successor_implementation_diff",
    "successor_acceptance_diff",
    "pending_gate_state",
    "accepted_gate_state",
    "successor_pending_state",
    "successor_accepted_state",
    "post_successor_closeout",
    "next_gate_seed",
    "audit",
    "semantic_oracle",
    "adversarial_cases",
    "frozen_paths",
    "forbidden_prefixes",
    "component_lock_sha256",
    "public_schema_count",
    "public_schema_set_sha256",
    "kernel_release",
    "execution_mode",
    "successor_production_authorized_by_bundle",
}
_AUDIT_KEYS = {
    "profile_id",
    "audit_version",
    "protected_oracle_path",
    "protected_oracle_sha256",
    "predecessor_test_count",
    "predecessor_nodeid_sha256",
    "expected_added_test_nodeids",
    "expected_check_ids",
}
_POST_KEYS = {
    "branch",
    "closeout_path",
    "diff",
    "accepted_state",
    "implementation_audit_profile",
    "implementation_audit_version",
    "transition_audit_profile",
    "transition_audit_version",
    "transition_check_ids",
    "expected_test_count",
    "expected_nodeid_sha256",
}
_CLOSEOUT_KEYS = {
    "schema_version",
    "gate_id",
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
    "finding_counts",
    "test_count",
}
_MANIFEST_KEYS = (
    "SCHEMA_VERSION",
    "GATE_ID",
    "AUDIT_PROFILE",
    "ADVERSARIAL_CASE_IDS",
    "EXPECTED_TEST_NODEIDS",
)


@dataclass(frozen=True, slots=True)
class Position:
    authority: dict[str, Any]
    bundle: dict[str, Any] | None
    depth: int
    stage: str


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = child
    return value


def _strict_json(raw: bytes, *, label: str, canonical: bool) -> Any:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    expected = (json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    if canonical and raw != expected:
        raise SystemExit(f"{label} is not canonically serialized")
    return value


def _git(repository: Path, *args: str, text: bool = True) -> str | bytes:
    return subprocess.check_output(["git", "-C", str(repository), *args], text=text).strip()


def _commit(repository: Path, ref: str) -> str:
    if _GIT_OID.fullmatch(ref) is None:
        raise SystemExit("oracle requires a full 40-hex commit identity")
    if str(_git(repository, "cat-file", "-t", ref)) != "commit":
        raise SystemExit("oracle identity is not a commit")
    return ref


def _blob(repository: Path, ref: str, path: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repository), "show", f"{ref}:{path}"])


def _json_blob(
    repository: Path,
    ref: str,
    path: str,
    *,
    canonical: bool = True,
) -> Any:
    return _strict_json(_blob(repository, ref, path), label=path, canonical=canonical)


def _exists(repository: Path, ref: str, path: str) -> bool:
    return (
        subprocess.run(
            ["git", "-C", str(repository), "cat-file", "-e", f"{ref}:{path}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def _mode(repository: Path, ref: str, path: str) -> str:
    raw = str(_git(repository, "ls-tree", ref, "--", path))
    fields = raw.split(None, 3)
    if len(fields) != 4 or fields[3].split("\t", 1)[-1] != path:
        raise SystemExit(f"missing Git path: {path}")
    return fields[0]


def _tree(repository: Path, ref: str) -> str:
    value = str(_git(repository, "rev-parse", f"{ref}^{{tree}}"))
    if _GIT_OID.fullmatch(value) is None:
        raise SystemExit("oracle tree identity is malformed")
    return value


def _parents(repository: Path, ref: str) -> tuple[str, ...]:
    raw = str(_git(repository, "show", "-s", "--format=%P", ref))
    values = tuple(raw.split()) if raw else ()
    if any(_GIT_OID.fullmatch(value) is None for value in values):
        raise SystemExit("oracle parent identity is malformed")
    return values


def _tracked_paths(repository: Path, ref: str, prefix: str) -> frozenset[str]:
    raw = str(_git(repository, "ls-tree", "-r", "--name-only", ref, "--", prefix))
    values = frozenset(path for path in raw.splitlines() if path)
    if any(not _safe_path(path) for path in values):
        raise SystemExit("tracked protected path inventory is malformed")
    return values


def _safe_path(value: object) -> bool:
    if not isinstance(value, str) or not value or unicodedata.normalize("NFC", value) != value:
        return False
    if any(character in value for character in ("?", "#", "\\", "\x00")):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and str(path) == value


def _sha(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _canonical_payload_sha256(value: object) -> str:
    payload = (
        json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _utc_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC)


_ED_Q = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_Q - 2, _ED_Q)) % _ED_Q
_ED_I = pow(2, (_ED_Q - 1) // 4, _ED_Q)
_ED_IDENTITY = (0, 1)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_Q - 2, _ED_Q) % _ED_Q
    x = pow(xx, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - xx) % _ED_Q != 0:
        x = x * _ED_I % _ED_Q
    if (x * x - xx) % _ED_Q != 0:
        raise ValueError("invalid Ed25519 point")
    return x


_ED_BY = 4 * pow(5, _ED_Q - 2, _ED_Q) % _ED_Q
_ED_BX = _ed_xrecover(_ED_BY)
if _ED_BX & 1:
    _ED_BX = _ED_Q - _ED_BX
_ED_BASE = (_ED_BX, _ED_BY)


def _ed_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = _ED_D * x1 * x2 * y1 * y2 % _ED_Q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + product, _ED_Q - 2, _ED_Q) % _ED_Q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - product, _ED_Q - 2, _ED_Q) % _ED_Q
    return x3, y3


def _ed_scalarmult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = _ED_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        scalar >>= 1
    return result


def _ed_encode(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_decode(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("invalid Ed25519 point length")
    value = int.from_bytes(encoded, "little")
    y = value & ((1 << 255) - 1)
    if y >= _ED_Q:
        raise ValueError("non-canonical Ed25519 point")
    x = _ed_xrecover(y)
    sign = value >> 255
    if x == 0 and sign != 0:
        raise ValueError("non-canonical Ed25519 x sign")
    if (x & 1) != sign:
        x = _ED_Q - x
    point = (x, y)
    if (
        point == _ED_IDENTITY
        or _ed_encode(point) != encoded
        or _ed_scalarmult(point, _ED_L) != _ED_IDENTITY
    ):
        raise ValueError("non-canonical or non-subgroup Ed25519 point")
    return point


def _verify_ed25519(public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    try:
        public_key = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(signature_hex)
        if len(public_key) != 32 or len(signature) != 64:
            return False
        public_point = _ed_decode(public_key)
        r_encoded = signature[:32]
        r_point = _ed_decode(r_encoded)
        scalar = int.from_bytes(signature[32:], "little")
        if scalar >= _ED_L:
            return False
        challenge = int.from_bytes(
            hashlib.sha512(r_encoded + public_key + message).digest(),
            "little",
        ) % _ED_L
        return _ed_scalarmult(_ED_BASE, scalar) == _ed_add(
            r_point,
            _ed_scalarmult(public_point, challenge),
        )
    except (ValueError, OverflowError):
        return False


def _receipt_payload_bytes(payload: dict[str, Any]) -> bytes:
    canonical = (
        json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    return _RECEIPT_DOMAIN.encode() + b"\x00" + canonical


def _external_receipts(
    value: object,
    *,
    expected: dict[str, object],
    approved_at: str,
) -> tuple[dict[str, Any], ...]:
    trust = _PROTECTED_EXTERNAL_TRUST
    if not isinstance(trust, dict):
        raise SystemExit("protected external receipt authority was not initialized")
    receipt_authority = trust.get("external_feasibility_receipt_authority")
    if (
        not isinstance(receipt_authority, dict)
        or receipt_authority.get("status") != "pinned"
        or receipt_authority.get("algorithm") != "ed25519"
        or receipt_authority.get("domain") != _RECEIPT_DOMAIN
        or receipt_authority.get("required_order") != list(_EXTERNAL_RECEIPT_KINDS)
        or receipt_authority.get("condition_coverage")
        != {kind: list(values) for kind, values in _EXTERNAL_CONDITION_COVERAGE.items()}
        or receipt_authority.get("condition_coverage")
        != {kind: list(values) for kind, values in _EXTERNAL_CONDITION_COVERAGE.items()}
        or receipt_authority.get("max_validity_seconds")
        != _RECEIPT_MAX_VALIDITY_SECONDS
        or not isinstance(receipt_authority.get("signers"), dict)
        or set(receipt_authority["signers"]) != set(_EXTERNAL_RECEIPT_KINDS)
    ):
        raise SystemExit("external receipt signer authority is not pinned")
    signers = receipt_authority["signers"]
    key_ids = [signers[kind].get("key_id") for kind in _EXTERNAL_RECEIPT_KINDS]
    public_keys = [
        signers[kind].get("public_key_hex") for kind in _EXTERNAL_RECEIPT_KINDS
    ]
    if (
        len(set(key_ids)) != len(_EXTERNAL_RECEIPT_KINDS)
        or len(set(public_keys)) != len(_EXTERNAL_RECEIPT_KINDS)
        or any(
            not isinstance(key_id, str) or _EXTERNAL_ID.fullmatch(key_id) is None
            for key_id in key_ids
        )
        or any(
            not isinstance(public_key, str)
            or re.fullmatch(r"[0-9a-f]{64}", public_key) is None
            for public_key in public_keys
        )
    ):
        raise SystemExit("external receipt signer keys are not three distinct authorities")
    if not isinstance(value, list) or len(value) != len(_EXTERNAL_RECEIPT_KINDS):
        raise SystemExit("external handoff lacks exactly three signed receipt envelopes")
    approved_time = _utc_timestamp(approved_at)
    if approved_time is None:
        raise SystemExit("external handoff approval timestamp is malformed")
    receipts: list[dict[str, Any]] = []
    prior_sha: str | None = None
    prior_issued: datetime | None = None
    for sequence, (expected_kind, item) in enumerate(
        zip(_EXTERNAL_RECEIPT_KINDS, value, strict=True),
        start=1,
    ):
        payload = item.get("payload") if isinstance(item, dict) else None
        signature_hex = item.get("signature_hex") if isinstance(item, dict) else None
        signer = signers[expected_kind]
        if (
            not isinstance(item, dict)
            or set(item) != _EXTERNAL_RECEIPT_KEYS
            or not isinstance(payload, dict)
            or set(payload) != _EXTERNAL_RECEIPT_PAYLOAD_KEYS
            or payload.get("schema_version") != "1.0.0"
            or payload.get("kind") != expected_kind
            or payload.get("sequence") != sequence
            or payload.get("decision") != "passed"
            or payload.get("feasibility_conditions")
            != list(_EXTERNAL_CONDITION_COVERAGE[expected_kind])
            or type(payload.get("sequence")) is not int
            or type(payload.get("repository_id")) is not int
            or any(
                type(payload.get(key)) is not str
                for key in _EXTERNAL_RECEIPT_PAYLOAD_KEYS
                - {
                    "sequence",
                    "repository_id",
                    "feasibility_conditions",
                    "prior_receipt_sha256",
                }
            )
            or (
                payload.get("prior_receipt_sha256") is not None
                and type(payload.get("prior_receipt_sha256")) is not str
            )
            or not isinstance(payload.get("receipt_id"), str)
            or _EXTERNAL_ID.fullmatch(payload["receipt_id"]) is None
            or payload.get("signer_key_id") != signer.get("key_id")
            or not isinstance(signature_hex, str)
            or re.fullmatch(r"[0-9a-f]{128}", signature_hex) is None
            or payload.get("prior_receipt_sha256") != prior_sha
            or payload.get("artifact_store") != "private_worm_cas"
            or not _sha(payload.get("artifact_sha256"))
            or payload.get("artifact_object_id") != payload.get("artifact_sha256")
            or not isinstance(payload.get("artifact_version"), str)
            or _EXTERNAL_ID.fullmatch(payload["artifact_version"]) is None
            or any(
                payload.get(key) != expected_value
                for key, expected_value in expected.items()
            )
        ):
            raise SystemExit("external signed receipt payload is malformed")
        issued = _utc_timestamp(payload.get("issued_at"))
        expires = _utc_timestamp(payload.get("expires_at"))
        if (
            issued is None
            or expires is None
            or not issued < expires
            or int((expires - issued).total_seconds()) > _RECEIPT_MAX_VALIDITY_SECONDS
            or not issued <= approved_time <= expires
            or (prior_issued is not None and issued < prior_issued)
        ):
            raise SystemExit("external signed receipt time bound is invalid")
        public_key = signer.get("public_key_hex")
        if not isinstance(public_key, str) or not _verify_ed25519(
            public_key,
            signature_hex,
            _receipt_payload_bytes(payload),
        ):
            raise SystemExit("external receipt signature is invalid")
        envelope = {"payload": dict(payload), "signature_hex": signature_hex}
        prior_sha = _canonical_payload_sha256(envelope)
        prior_issued = issued
        receipts.append(envelope)
    if len({item["payload"]["receipt_id"] for item in receipts}) != len(receipts):
        raise SystemExit("external handoff receipt identities are not unique")
    return tuple(receipts)


def _state(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == _STATE_KEYS
        and isinstance(value.get("current_phase"), str)
        and bool(value["current_phase"])
        and value.get("status")
        in {"implementation_complete_pending_acceptance", "accepted_closed"}
        and isinstance(value.get("authorized_next"), list)
        and len(value["authorized_next"]) <= 1
        and all(isinstance(item, str) and item for item in value["authorized_next"])
        and isinstance(value.get("prohibited"), list)
        and bool(value["prohibited"])
        and value["prohibited"] == list(dict.fromkeys(value["prohibited"]))
        and all(isinstance(item, str) and item for item in value["prohibited"])
        and not (set(value["authorized_next"]) & set(value["prohibited"]))
        and value.get("release_tag") is None
    )


def _phase_is_prohibited(phase: str | None, prohibited: list[str]) -> bool:
    if phase is None:
        return False
    return any(phase == item or phase.startswith(item + "-") for item in prohibited)


def _authority_state_semantics(value: dict[str, Any]) -> bool:
    owner = value["owner_phase"]
    next_owner = value["next_owner_phase"]
    pending = value["pending_gate_state"]
    gate_accepted = value["accepted_gate_state"]
    successor_pending = value["successor_pending_state"]
    successor_accepted = value["successor_accepted_state"]
    states = (pending, gate_accepted, successor_pending, successor_accepted)
    terminal = owner == _TERMINAL_PHASE and next_owner is None
    later_phase_authorized = any(
        any(label in item for label in ("Phase 6", "Phase 7", "Phase 8", "Phase 9"))
        for state in states
        for item in state["authorized_next"]
    )
    later_phases_explicitly_prohibited = all(
        _phase_is_prohibited(later, state["prohibited"])
        for state in states
        for later in ("Phase 6", "Phase 7", "Phase 8", "Phase 9")
    )
    return (
        pending["current_phase"] == f"{owner}-gate"
        and pending["status"] == "implementation_complete_pending_acceptance"
        and pending["authorized_next"] == [f"{owner} successor-gate acceptance closeout"]
        and _phase_is_prohibited(owner, pending["prohibited"])
        and gate_accepted["current_phase"] == f"{owner}-gate"
        and gate_accepted["status"] == "accepted_closed"
        and len(gate_accepted["authorized_next"]) == 1
        and gate_accepted["authorized_next"][0].startswith(owner + " ")
        and gate_accepted["authorized_next"][0].endswith(" implementation")
        and not _phase_is_prohibited(owner, gate_accepted["prohibited"])
        and successor_pending["current_phase"] == owner
        and successor_pending["status"] == "implementation_complete_pending_acceptance"
        and successor_pending["authorized_next"] == [f"{owner} acceptance closeout"]
        and not _phase_is_prohibited(owner, successor_pending["prohibited"])
        and successor_accepted["current_phase"] == owner
        and successor_accepted["status"] == "accepted_closed"
        and len(successor_accepted["authorized_next"]) == 1
        and successor_accepted["authorized_next"][0].endswith(" closeout")
        and not _phase_is_prohibited(owner, successor_accepted["prohibited"])
        and (
            terminal
            or all(_phase_is_prohibited(next_owner, state["prohibited"]) for state in states)
        )
        and not later_phase_authorized
        and later_phases_explicitly_prohibited
    )


def _diff_policy(value: object) -> bool:
    return (
        isinstance(value, dict)
        and bool(value)
        and all(
            _safe_path(path) and disposition in {"A", "M"}
            for path, disposition in value.items()
        )
    )


def _paths(authority: dict[str, Any]) -> dict[str, str]:
    directory = authority["bundle_directory"]
    return {
        "bundle": f"{directory}/bundle.json",
        "oracle": f"{directory}/semantic-oracle.py.txt",
        "cases": f"{directory}/adversarial-cases.json",
        "closeout": authority["closeout_path"],
        "successor_closeout": authority["successor_closeout_path"],
    }


def _audit_policy(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == _AUDIT_POLICY_KEYS
        and isinstance(value.get("profile_id"), str)
        and _CHECK_ID.fullmatch(value["profile_id"]) is not None
        and isinstance(value.get("audit_version"), str)
        and _AUDIT_VERSION.fullmatch(value["audit_version"]) is not None
        and _safe_path(value.get("protected_oracle_path"))
        and str(value["protected_oracle_path"]).startswith("scripts/")
        and _sha(value.get("protected_oracle_sha256"))
        and value.get("mandatory_check_ids") == sorted(_GENERIC_CHECKS)
        and isinstance(value.get("expected_added_test_nodeids"), list)
        and bool(value["expected_added_test_nodeids"])
        and value["expected_added_test_nodeids"]
        == sorted(set(value["expected_added_test_nodeids"]))
        and all(isinstance(item, str) and item for item in value["expected_added_test_nodeids"])
        and type(value.get("predecessor_test_count")) is int
        and value["predecessor_test_count"] > 0
        and _sha(value.get("predecessor_nodeid_sha256"))
    )


def _authority(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _AUTHORITY_KEYS:
        raise SystemExit("successor authority has an open shape")
    audit = value.get("audit_policy")
    if (
        not isinstance(value.get("gate_id"), str)
        or not value["gate_id"]
        or not isinstance(value.get("owner_phase"), str)
        or value["owner_phase"] not in _PHASE_SUCCESSOR
        or value.get("next_owner_phase") != _PHASE_SUCCESSOR.get(value["owner_phase"])
        or not (
            value.get("next_gate_authority_sha256") is None
            or _sha(value.get("next_gate_authority_sha256"))
        )
        or any(
            _BRANCH.fullmatch(str(value.get(key))) is None
            for key in (
                "bootstrap_branch",
                "acceptance_branch",
                "successor_implementation_branch",
                "successor_acceptance_branch",
            )
        )
        or any(
            not _safe_path(value.get(key))
            for key in ("bundle_directory", "closeout_path", "successor_closeout_path")
        )
        or any(
            not _diff_policy(value.get(key))
            for key in (
                "gate_bootstrap_diff",
                "gate_acceptance_diff",
                "successor_implementation_diff",
                "successor_acceptance_diff",
            )
        )
        or any(
            not _state(value.get(key))
            for key in (
                "pending_gate_state",
                "accepted_gate_state",
                "successor_pending_state",
                "successor_accepted_state",
            )
        )
        or not isinstance(value.get("frozen_paths"), list)
        or value["frozen_paths"] != sorted(set(value["frozen_paths"]))
        or not _CONTROL_FROZEN.issubset(value["frozen_paths"])
        or not all(_safe_path(path) for path in value["frozen_paths"])
        or not isinstance(value.get("forbidden_prefixes"), list)
        or value["forbidden_prefixes"] != sorted(set(value["forbidden_prefixes"]))
        or not _CONTROL_FORBIDDEN.issubset(value["forbidden_prefixes"])
        or not all(_safe_path(path) for path in value["forbidden_prefixes"])
        or not _audit_policy(audit)
    ):
        raise SystemExit("successor authority violates the protected floor")
    if not _authority_state_semantics(value):
        raise SystemExit("successor authority machine-state semantics are malformed")
    paths = _paths(value)
    expected_bootstrap_diff = (
        _EXTERNAL_CONTROLLER_DIFF
        if value["gate_id"] == "phase5e2c0"
        and value["owner_phase"] == _EXTERNAL_TARGET_PHASE
        and value["bootstrap_branch"] == _EXTERNAL_CONTROLLER_BRANCH
        else {
            STATUS_PATH: "M",
            paths["bundle"]: "A",
            paths["oracle"]: "A",
            paths["cases"]: "A",
        }
    )
    if (
        value["gate_bootstrap_diff"] != expected_bootstrap_diff
        or value["gate_acceptance_diff"] != {STATUS_PATH: "M", paths["closeout"]: "A"}
        or value["successor_acceptance_diff"]
        != {STATUS_PATH: "M", paths["successor_closeout"]: "A"}
        or not any(
            disposition == "A" and path != STATUS_PATH
            for path, disposition in value["successor_implementation_diff"].items()
        )
    ):
        raise SystemExit("successor authority exact diffs are malformed")
    controlled = set(value["successor_implementation_diff"]) | set(
        value["successor_acceptance_diff"]
    )
    if controlled & set(value["frozen_paths"]) or any(
        path == prefix or path.startswith(prefix.rstrip("/") + "/")
        for path in controlled
        for prefix in value["forbidden_prefixes"]
    ):
        raise SystemExit("successor authority weakens its control plane")
    if len(set(_paths(value).values())) != 5 or len(
        {
            value["bootstrap_branch"],
            value["acceptance_branch"],
            value["successor_implementation_branch"],
            value["successor_acceptance_branch"],
        }
    ) != 4:
        raise SystemExit("successor authority reuses a path or branch")
    return value


def _authority_governed_paths(
    authority: dict[str, Any],
    *,
    post_successor_closeout: dict[str, Any] | None = None,
) -> frozenset[str]:
    paths = set(_paths(authority).values())
    for key in (
        "gate_bootstrap_diff",
        "gate_acceptance_diff",
        "successor_implementation_diff",
        "successor_acceptance_diff",
    ):
        paths.update(path for path in authority[key] if path not in _SHARED_MUTABLE_PATHS)
    if post_successor_closeout is not None:
        paths.update(
            path
            for path in post_successor_closeout["diff"]
            if path not in _SHARED_MUTABLE_PATHS
        )
    return frozenset(paths)


def _post(value: object, expected_test_count: int) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != _POST_KEYS
        or _BRANCH.fullmatch(str(value.get("branch"))) is None
        or not _safe_path(value.get("closeout_path"))
        or value.get("diff") != {STATUS_PATH: "M", value.get("closeout_path"): "A"}
        or not _state(value.get("accepted_state"))
        or any(
            not isinstance(value.get(key), str) or _CHECK_ID.fullmatch(value[key]) is None
            for key in ("implementation_audit_profile", "transition_audit_profile")
        )
        or any(
            not isinstance(value.get(key), str) or _AUDIT_VERSION.fullmatch(value[key]) is None
            for key in ("implementation_audit_version", "transition_audit_version")
        )
        or value.get("transition_check_ids") != sorted(_GENERIC_CHECKS)
        or value.get("expected_test_count") != expected_test_count
        or not _sha(value.get("expected_nodeid_sha256"))
    ):
        raise SystemExit("post-successor closeout authority is malformed")
    return value


def _closeout(
    value: object,
    *,
    gate_id: str,
    profile: str,
    version: str,
    test_count: int,
) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == _CLOSEOUT_KEYS
        and value.get("schema_version") == "1.0.0"
        and value.get("gate_id") == gate_id
        and all(
            type(value.get(key)) is int and value[key] > 0
            for key in (
                "implementation_pull_request",
                "acceptance_pull_request",
                "audit_workflow_id",
                "controller_app_id",
                "controller_installation_id",
            )
        )
        and all(
            isinstance(value.get(key), str) and _GIT_OID.fullmatch(value[key]) is not None
            for key in (
                "implementation_head_commit",
                "implementation_merge_commit",
                "implementation_tree_sha",
            )
        )
        and all(
            isinstance(value.get(key), str)
            and value[key].isdigit()
            and str(int(value[key])) == value[key]
            and value[key] != "0"
            for key in ("pr_ci_run_id", "main_ci_run_id")
        )
        and value.get("audit_tool") == "owner-research-phase5e-readonly"
        and value.get("audit_profile") == profile
        and value.get("audit_version") == version
        and all(
            _sha(value.get(key))
            for key in (
                "audit_report_sha256",
                "audit_artifact_sha256",
                "test_inventory_sha256",
                "runtime_matrix_sha256",
                "audit_wheelhouse_manifest_sha256",
            )
        )
        and isinstance(value.get("controller_app_slug"), str)
        and _CHECK_ID.fullmatch(value["controller_app_slug"]) is not None
        and value.get("finding_counts") == {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
        and value.get("test_count") == test_count
    )


def _schema_set(repository: Path, ref: str) -> tuple[int, str]:
    names = str(_git(repository, "ls-tree", "-r", "--name-only", ref, "--", "schemas"))
    paths = sorted(path for path in names.splitlines() if path.endswith(".schema.json"))
    payload = b"".join(
        path.encode()
        + b"\0"
        + hashlib.sha256(_blob(repository, ref, path)).hexdigest().encode()
        + b"\n"
        for path in paths
    )
    return len(paths), hashlib.sha256(payload).hexdigest()


def _manifest(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > _MAX_ORACLE_BYTES:
        raise SystemExit("candidate manifest exceeds its byte bound")
    try:
        tree = ast.parse(raw.decode("utf-8"), filename="semantic-oracle.py.txt")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise SystemExit("candidate manifest is not parseable") from exc
    if sum(1 for _ in ast.walk(tree)) > _MAX_AST_NODES:
        raise SystemExit("candidate manifest exceeds its AST bound")
    values: dict[str, Any] = {}
    for node in tree.body:
        if (
            not isinstance(node, ast.Assign)
            or len(node.targets) != 1
            or not isinstance(node.targets[0], ast.Name)
            or node.targets[0].id not in _MANIFEST_KEYS
            or node.targets[0].id in values
        ):
            raise SystemExit("candidate manifest exposes executable syntax")
        try:
            values[node.targets[0].id] = ast.literal_eval(node.value)
        except (ValueError, TypeError) as exc:
            raise SystemExit("candidate manifest contains a non-literal") from exc
    if tuple(values) != _MANIFEST_KEYS:
        raise SystemExit("candidate manifest key order or shape drifted")
    for key in ("ADVERSARIAL_CASE_IDS", "EXPECTED_TEST_NODEIDS"):
        sequence = values[key]
        if (
            not isinstance(sequence, tuple)
            or sequence != tuple(sorted(set(sequence)))
            or any(not isinstance(item, str) or not item for item in sequence)
        ):
            raise SystemExit("candidate manifest sequence is malformed")
    return values


def _cases(raw: bytes) -> tuple[str, ...]:
    if not raw or len(raw) > _MAX_CASE_BYTES:
        raise SystemExit("adversarial cases exceed their byte bound")
    value = _strict_json(raw, label="adversarial cases", canonical=True)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "cases"}
        or value.get("schema_version") != "1.0.0"
        or not isinstance(value.get("cases"), list)
        or not value["cases"]
    ):
        raise SystemExit("adversarial cases have an open shape")
    identifiers: list[str] = []
    for item in value["cases"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"case_id", "priority", "expectation"}
            or not isinstance(item.get("case_id"), str)
            or item.get("priority") not in {"P0", "P1", "P2", "P3"}
            or not isinstance(item.get("expectation"), str)
            or not item["expectation"]
        ):
            raise SystemExit("adversarial case has an open shape")
        identifiers.append(item["case_id"])
    if identifiers != sorted(set(identifiers)):
        raise SystemExit("adversarial case IDs are not canonical and unique")
    return tuple(identifiers)


def _baseline(repository: Path, ref: str, authority: dict[str, Any]) -> str:
    path = authority["closeout_path"]
    if not _exists(repository, ref, path):
        return ref
    closeout = _json_blob(repository, ref, path)
    baseline = closeout.get("implementation_merge_commit") if isinstance(closeout, dict) else None
    if not isinstance(baseline, str) or _GIT_OID.fullmatch(baseline) is None:
        raise SystemExit("accepted gate closeout has no bootstrap merge")
    _commit(repository, baseline)
    if str(_git(repository, "merge-base", baseline, ref)) != baseline:
        raise SystemExit("gate bootstrap merge is not an ancestor")
    return baseline


def _kernel_component(repository: Path, ref: str) -> dict[str, Any]:
    value = _json_blob(repository, ref, COMPONENT_LOCK_PATH, canonical=False)
    kernel = value.get("valuation_kernel") if isinstance(value, dict) else None
    if (
        not isinstance(kernel, dict)
        or kernel.get("tag") != _KERNEL["tag"]
        or kernel.get("annotated_tag_object") != _KERNEL["tag_object"]
        or kernel.get("commit") != _KERNEL["commit"]
        or kernel.get("release_evidence", {}).get("wheel_sha256") != _KERNEL["wheel_sha256"]
        or not isinstance(kernel.get("public_schema_sha256"), dict)
        or len(kernel["public_schema_sha256"]) != 8
        or not all(
            _safe_path(path) and _sha(digest)
            for path, digest in kernel["public_schema_sha256"].items()
        )
    ):
        raise SystemExit("component lock is not pinned to rc.2")
    return value


def _next_seed(
    value: object,
    *,
    authority: dict[str, Any],
    post: dict[str, Any],
) -> dict[str, Any] | None:
    state = post["accepted_state"]
    expected_sha = authority["next_gate_authority_sha256"]
    if value is None:
        terminal = authority["owner_phase"] == _TERMINAL_PHASE
        external = authority["next_owner_phase"] == _EXTERNAL_FEASIBILITY_PHASE
        controller_reauthorization = (
            authority["owner_phase"] in _CONTROLLER_REAUTHORIZATION_BOUNDARIES
        )
        if not (terminal or external or controller_reauthorization):
            raise SystemExit("nonterminal successor authority lacks a protected next seed")
        external_label = f"{_EXTERNAL_FEASIBILITY_PHASE} Futu feasibility gate"
        expected_authorization = (
            [external_label]
            if external
            else []
        )
        if expected_sha is not None or state["authorized_next"] != expected_authorization:
            raise SystemExit("post-closeout lacks its protected next authority")
        return None
    if expected_sha is None:
        raise SystemExit("candidate supplied an unpinned next-gate authority")
    seed = _authority(value)
    seed_payload = (
        json.dumps(seed, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if hashlib.sha256(seed_payload).hexdigest() != expected_sha:
        raise SystemExit("next seed differs from the protected authority hash")
    expected_label = f'{seed["owner_phase"]} successor-gate bootstrap'
    current_paths = _authority_governed_paths(
        authority,
        post_successor_closeout=post,
    )
    next_paths = _authority_governed_paths(seed)
    required_frozen = {*authority["frozen_paths"], *current_paths}
    refrozen_external_prefixes = True
    if authority["owner_phase"] == _EXTERNAL_TARGET_PHASE:
        released_paths = {
            path
            for path in authority["successor_implementation_diff"]
            if any(
                path == prefix or path.startswith(prefix.rstrip("/") + "/")
                for prefix in _EXTERNAL_RELEASABLE_PREFIXES
            )
        }
        refrozen_external_prefixes = (
            _EXTERNAL_RELEASABLE_PREFIXES.issubset(seed["forbidden_prefixes"])
            and released_paths.issubset(seed["frozen_paths"])
        )
    if (
        seed["gate_id"] == authority["gate_id"]
        or seed["owner_phase"] != authority["next_owner_phase"]
        or current_paths & next_paths
        or {
            seed["bootstrap_branch"],
            seed["acceptance_branch"],
            seed["successor_implementation_branch"],
            seed["successor_acceptance_branch"],
        }
        & {
            authority["bootstrap_branch"],
            authority["acceptance_branch"],
            authority["successor_implementation_branch"],
            authority["successor_acceptance_branch"],
            post["branch"],
        }
        or state["authorized_next"] != [expected_label]
        or expected_label in state["prohibited"]
        or seed["pending_gate_state"]["authorized_next"]
        != [f'{seed["owner_phase"]} successor-gate acceptance closeout']
        or seed["audit_policy"]["predecessor_test_count"] != post["expected_test_count"]
        or seed["audit_policy"]["predecessor_nodeid_sha256"] != post["expected_nodeid_sha256"]
        or not required_frozen.issubset(seed["frozen_paths"])
        or not set(authority["forbidden_prefixes"]).issubset(seed["forbidden_prefixes"])
        or not refrozen_external_prefixes
    ):
        raise SystemExit("next seed reuses authority or skips the protected phase chain")
    return seed


def _external_authority_seed(
    value: object,
    *,
    authority: dict[str, Any],
    post: dict[str, Any],
) -> dict[str, Any]:
    if (
        authority["next_owner_phase"] != _EXTERNAL_FEASIBILITY_PHASE
        or authority["next_gate_authority_sha256"] is not None
        or _PHASE_SUCCESSOR.get(_EXTERNAL_FEASIBILITY_PHASE) != _EXTERNAL_TARGET_PHASE
    ):
        raise SystemExit("external handoff is not at the protected boundary")
    seed = _authority(value)
    if (
        seed["gate_id"] != "phase5e2c0"
        or seed["owner_phase"] != _EXTERNAL_TARGET_PHASE
        or seed["next_owner_phase"] != _PHASE_SUCCESSOR[_EXTERNAL_TARGET_PHASE]
        or seed["next_gate_authority_sha256"] is not None
        or seed["bundle_directory"] != _EXTERNAL_GATE_DIRECTORY
        or seed["bootstrap_branch"] != _EXTERNAL_CONTROLLER_BRANCH
        or seed["audit_policy"]["protected_oracle_path"]
        != _EXTERNAL_PROTECTED_ORACLE_PATH
        or seed["successor_implementation_diff"]
        != _EXTERNAL_2C0_IMPLEMENTATION_DIFF
        or seed["audit_policy"]["predecessor_test_count"] != post["expected_test_count"]
        or seed["audit_policy"]["predecessor_nodeid_sha256"]
        != post["expected_nodeid_sha256"]
    ):
        raise SystemExit("external handoff does not install the exact 2C-0 authority")
    current_paths = _authority_governed_paths(
        authority,
        post_successor_closeout=post,
    )
    next_paths = _authority_governed_paths(seed)
    current_branches = {
        authority["bootstrap_branch"],
        authority["acceptance_branch"],
        authority["successor_implementation_branch"],
        authority["successor_acceptance_branch"],
        post["branch"],
    }
    next_branches = {
        seed["bootstrap_branch"],
        seed["acceptance_branch"],
        seed["successor_implementation_branch"],
        seed["successor_acceptance_branch"],
    }
    released_frozen = set(authority["frozen_paths"]) - set(seed["frozen_paths"])
    released_prefixes = set(authority["forbidden_prefixes"]) - set(
        seed["forbidden_prefixes"]
    )
    successor_paths = set(seed["successor_implementation_diff"])
    required_frozen = (
        set(authority["frozen_paths"])
        - _EXTERNAL_RELEASABLE_FROZEN
        | set(current_paths)
        | {_EXTERNAL_HANDOFF_PATH, _EXTERNAL_PROTECTED_ORACLE_PATH}
    )
    released_prefix_paths = {
        path
        for path in successor_paths
        if any(
            path == prefix or path.startswith(prefix.rstrip("/") + "/")
            for prefix in released_prefixes
        )
    }
    if (
        seed["gate_id"] == authority["gate_id"]
        or current_paths & next_paths
        or current_branches & (next_branches - {_EXTERNAL_CONTROLLER_BRANCH})
        or not required_frozen.issubset(seed["frozen_paths"])
        or not released_frozen.issubset(_EXTERNAL_RELEASABLE_FROZEN)
        or not released_frozen.issubset(successor_paths)
        or not released_prefixes.issubset(_EXTERNAL_RELEASABLE_PREFIXES)
        or (released_prefixes and not released_prefix_paths)
        or not released_prefix_paths.issubset(_EXTERNAL_RELEASE_ALLOWLIST)
        or not _CONTROL_FORBIDDEN.issubset(seed["forbidden_prefixes"])
    ):
        raise SystemExit("external 2C-0 seed releases or reuses unreviewed authority")
    return seed


def _external_handoff_seed(
    repository: Path,
    ref: str,
    *,
    authority: dict[str, Any],
    bundle: dict[str, Any],
) -> dict[str, Any] | None:
    if not (
        bundle.get("next_gate_seed") is None
        and authority["next_owner_phase"] == _EXTERNAL_FEASIBILITY_PHASE
    ):
        return None
    external_paths = tuple(
        path for path in _EXTERNAL_CONTROLLER_DIFF if path != STATUS_PATH
    )
    present = tuple(_exists(repository, ref, path) for path in external_paths)
    if any(present) and not all(present):
        raise SystemExit("external Controller handoff is only partially installed")
    if not any(present):
        return None
    raw = _blob(repository, ref, _EXTERNAL_HANDOFF_PATH)
    if not raw or len(raw) > _MAX_EXTERNAL_HANDOFF_BYTES:
        raise SystemExit("external Controller handoff exceeds its byte bound")
    handoff = _strict_json(raw, label=_EXTERNAL_HANDOFF_PATH, canonical=True)
    if not isinstance(handoff, dict) or set(handoff) != _EXTERNAL_HANDOFF_KEYS:
        raise SystemExit("external Controller handoff has an open shape")
    predecessor = handoff.get("predecessor_commit")
    predecessor_tree = handoff.get("predecessor_tree")
    predecessor_fingerprint = handoff.get("predecessor_state_fingerprint")
    approved_at = handoff.get("approved_at")
    protected_trust = _PROTECTED_EXTERNAL_TRUST
    futu_policy = (
        protected_trust.get("futu_market_authority_policy")
        if isinstance(protected_trust, dict)
        else None
    )
    if (
        handoff.get("schema_version") != "1.0.0"
        or handoff.get("external_phase") != _EXTERNAL_FEASIBILITY_PHASE
        or handoff.get("source_gate_id") != authority["gate_id"]
        or handoff.get("source_owner_phase") != authority["owner_phase"]
        or handoff.get("target_owner_phase") != _EXTERNAL_TARGET_PHASE
        or not isinstance(predecessor, str)
        or _GIT_OID.fullmatch(predecessor) is None
        or not isinstance(predecessor_tree, str)
        or _GIT_OID.fullmatch(predecessor_tree) is None
        or not _sha(predecessor_fingerprint)
        or _utc_timestamp(approved_at) is None
        or not _sha(handoff.get("challenge_nonce"))
        or not isinstance(futu_policy, dict)
        or set(futu_policy) != {"path", "sha256", "overlay_path", "overlay_sha256"}
        or handoff.get("policy_path") != futu_policy.get("path")
        or handoff.get("policy_sha256") != futu_policy.get("sha256")
        or handoff.get("policy_overlay_path") != futu_policy.get("overlay_path")
        or handoff.get("policy_overlay_sha256") != futu_policy.get("overlay_sha256")
        or type(handoff.get("controller_app_id")) is not int
        or handoff["controller_app_id"] <= 0
        or not isinstance(handoff.get("controller_app_slug"), str)
        or _CHECK_ID.fullmatch(handoff["controller_app_slug"]) is None
        or type(handoff.get("controller_installation_id")) is not int
        or handoff["controller_installation_id"] <= 0
        or type(handoff.get("author_app_id")) is not int
        or handoff["author_app_id"] <= 0
        or not isinstance(handoff.get("author_app_slug"), str)
        or _CHECK_ID.fullmatch(handoff["author_app_slug"]) is None
        or type(handoff.get("author_installation_id")) is not int
        or handoff["author_installation_id"] <= 0
    ):
        raise SystemExit("external Controller handoff identity is malformed")
    if (
        str(_git(repository, "cat-file", "-t", predecessor)) != "commit"
        or _tree(repository, predecessor) != predecessor_tree
        or str(_git(repository, "merge-base", predecessor, ref)) != predecessor
    ):
        raise SystemExit("external predecessor is not immutable ancestry")
    predecessor_status = _json_blob(
        repository,
        predecessor,
        STATUS_PATH,
        canonical=False,
    )
    if (
        _status_core(predecessor_status)
        != bundle["post_successor_closeout"]["accepted_state"]
        or _canonical_payload_sha256(predecessor_status) != predecessor_fingerprint
    ):
        raise SystemExit("external predecessor state fingerprint drifted")
    seed = _external_authority_seed(
        handoff.get("authority_seed"),
        authority=authority,
        post=bundle["post_successor_closeout"],
    )
    seed_sha256 = _canonical_payload_sha256(seed)
    if handoff.get("authority_seed_sha256") != seed_sha256:
        raise SystemExit("external authority seed hash drifted")
    component_lock_sha256 = hashlib.sha256(
        _blob(repository, predecessor, COMPONENT_LOCK_PATH)
    ).hexdigest()
    receipts = _external_receipts(
        handoff.get("receipt_bindings"),
        expected={
            "repository_id": 1312436919,
            "repository": "mingjiconnect-ctrl/owner-equity-research-public",
            "source_gate_id": authority["gate_id"],
            "source_owner_phase": authority["owner_phase"],
            "target_owner_phase": _EXTERNAL_TARGET_PHASE,
            "predecessor_commit": predecessor,
            "predecessor_tree": predecessor_tree,
            "predecessor_state_fingerprint": predecessor_fingerprint,
            "component_lock_sha256": component_lock_sha256,
            "authority_seed_sha256": seed_sha256,
            "policy_sha256": futu_policy["sha256"],
            "challenge_nonce": handoff["challenge_nonce"],
        },
        approved_at=approved_at,
    )
    if handoff.get("receipt_set_sha256") != _canonical_payload_sha256(list(receipts)):
        raise SystemExit("external signed receipt set hash drifted")
    for path_key, sha_key in (
        ("path", "sha256"),
        ("overlay_path", "overlay_sha256"),
    ):
        policy_path = futu_policy[path_key]
        if (
            _mode(repository, predecessor, policy_path) != "100644"
            or hashlib.sha256(_blob(repository, predecessor, policy_path)).hexdigest()
            != futu_policy[sha_key]
            or _blob(repository, ref, policy_path)
            != _blob(repository, predecessor, policy_path)
        ):
            raise SystemExit("protected Futu market-authority policy bytes drifted")
    released_prefixes = set(authority["forbidden_prefixes"]) - set(
        seed["forbidden_prefixes"]
    )
    successor_diff = seed["successor_implementation_diff"]
    for prefix in released_prefixes:
        tracked = _tracked_paths(repository, predecessor, prefix)
        mutable = {
            path
            for path in successor_diff
            if path == prefix or path.startswith(prefix.rstrip("/") + "/")
        }
        if (
            not (tracked - mutable).issubset(seed["frozen_paths"])
            or not mutable.issubset(_EXTERNAL_RELEASE_ALLOWLIST)
            or any(
                successor_diff[path] != ("M" if path in tracked else "A")
                for path in mutable
            )
        ):
            raise SystemExit("external seed does not freeze its released prefix")
    additions = str(
        _git(
            repository,
            "log",
            "--format=%H",
            "--diff-filter=A",
            f"{predecessor}..{ref}",
            "--",
            _EXTERNAL_HANDOFF_PATH,
        )
    ).splitlines()
    if len(additions) != 1:
        raise SystemExit("external handoff introduction is missing or ambiguous")
    introduction = additions[0]
    if (
        _parents(repository, introduction) != (predecessor,)
        or _exact_diff(repository, predecessor, introduction) != _EXTERNAL_CONTROLLER_DIFF
        or _status_core(_json_blob(repository, introduction, STATUS_PATH, canonical=False))
        != seed["pending_gate_state"]
    ):
        raise SystemExit("external handoff is not one exact direct transition")
    for path in _EXTERNAL_CONTROLLER_DIFF:
        if path == STATUS_PATH:
            continue
        if (
            _mode(repository, introduction, path) != "100644"
            or _blob(repository, introduction, path) != _blob(repository, ref, path)
        ):
            raise SystemExit("external handoff evidence drifted after introduction")
    protected_oracle_sha = hashlib.sha256(
        _blob(repository, predecessor, _EXTERNAL_PROTECTED_ORACLE_PATH)
    ).hexdigest()
    if (
        _mode(repository, predecessor, _EXTERNAL_PROTECTED_ORACLE_PATH) != "100644"
        or seed["audit_policy"]["protected_oracle_sha256"] != protected_oracle_sha
        or _blob(repository, ref, _EXTERNAL_PROTECTED_ORACLE_PATH)
        != _blob(repository, predecessor, _EXTERNAL_PROTECTED_ORACLE_PATH)
    ):
        raise SystemExit("protected-base 2C-0 oracle is missing, drifted, or candidate-installed")
    seed_bundle = _bundle(repository, ref, seed)
    if seed_bundle["predecessor_state_fingerprint"] != predecessor_fingerprint:
        raise SystemExit("external 2C-0 bundle is not bound to its predecessor")
    return seed


def _bundle(repository: Path, ref: str, authority: dict[str, Any]) -> dict[str, Any]:
    paths = _paths(authority)
    raw = _blob(repository, ref, paths["bundle"])
    if (
        not raw
        or len(raw) > _MAX_BUNDLE_BYTES
        or _mode(repository, ref, paths["bundle"]) != "100644"
    ):
        raise SystemExit("bundle exceeds bounds or is not a regular file")
    value = _strict_json(raw, label="successor bundle", canonical=True)
    if not isinstance(value, dict) or set(value) != _BUNDLE_KEYS:
        raise SystemExit("successor bundle has an open shape")
    if (
        value.get("schema_version") != "2.0.0"
        or value.get("gate_id") != authority["gate_id"]
        or value.get("owner_phase") != authority["owner_phase"]
        or not _sha(value.get("predecessor_state_fingerprint"))
        or value.get("gate_bootstrap_branch") != authority["bootstrap_branch"]
        or value.get("gate_acceptance_branch") != authority["acceptance_branch"]
        or value.get("successor_implementation_branch")
        != authority["successor_implementation_branch"]
        or value.get("successor_acceptance_branch") != authority["successor_acceptance_branch"]
        or any(
            value.get(key) != authority[key]
            for key in (
                "gate_bootstrap_diff",
                "gate_acceptance_diff",
                "successor_implementation_diff",
                "successor_acceptance_diff",
                "pending_gate_state",
                "accepted_gate_state",
                "successor_pending_state",
                "successor_accepted_state",
                "frozen_paths",
                "forbidden_prefixes",
            )
        )
        or value.get("execution_mode") != "protected_base_only_after_gate_acceptance"
        or value.get("successor_production_authorized_by_bundle") is not False
        or value.get("public_schema_count") != 43
        or not _sha(value.get("public_schema_set_sha256"))
        or not _sha(value.get("component_lock_sha256"))
    ):
        raise SystemExit("successor bundle violates protected authority")
    audit = value.get("audit")
    policy = authority["audit_policy"]
    implementation_tests = sorted(
        path
        for path, disposition in authority["successor_implementation_diff"].items()
        if disposition == "A" and path.startswith("tests/test_") and path.endswith(".py")
    )
    if (
        not isinstance(audit, dict)
        or set(audit) != _AUDIT_KEYS
        or audit.get("profile_id") != policy["profile_id"]
        or audit.get("audit_version") != policy["audit_version"]
        or audit.get("protected_oracle_path") != policy["protected_oracle_path"]
        or audit.get("protected_oracle_sha256") != policy["protected_oracle_sha256"]
        or audit.get("predecessor_test_count") != policy["predecessor_test_count"]
        or audit.get("predecessor_nodeid_sha256") != policy["predecessor_nodeid_sha256"]
        or audit.get("expected_added_test_nodeids") != policy["expected_added_test_nodeids"]
        or audit.get("expected_check_ids") != policy["mandatory_check_ids"]
        or not implementation_tests
        or not all(
            any(nodeid.startswith(path + "::") for path in implementation_tests)
            for nodeid in audit["expected_added_test_nodeids"]
        )
    ):
        raise SystemExit("successor bundle audit policy is malformed")
    expected_test_count = int(policy["predecessor_test_count"]) + len(
        policy["expected_added_test_nodeids"]
    )
    post = _post(value.get("post_successor_closeout"), expected_test_count)
    if (
        post["implementation_audit_profile"] != policy["profile_id"]
        or post["implementation_audit_version"] != policy["audit_version"]
        or post["transition_audit_profile"] == policy["profile_id"]
    ):
        raise SystemExit("successor transition audit is not independently identified")
    next_seed = _next_seed(value.get("next_gate_seed"), authority=authority, post=post)
    post_state = post["accepted_state"]
    expected_post_authorization = (
        [f"{_EXTERNAL_FEASIBILITY_PHASE} Futu feasibility gate"]
        if next_seed is None
        and authority["next_owner_phase"] == _EXTERNAL_FEASIBILITY_PHASE
        else []
        if next_seed is None
        else [f'{authority["next_owner_phase"]} successor-gate bootstrap']
    )
    if (
        post_state["current_phase"] != authority["owner_phase"]
        or post_state["status"] != "accepted_closed"
        or post_state["authorized_next"] != expected_post_authorization
        or (
            next_seed is not None
            and not _phase_is_prohibited(
                authority["next_owner_phase"], post_state["prohibited"]
            )
        )
        or any(
            any(label in item for label in ("Phase 6", "Phase 7", "Phase 8", "Phase 9"))
            for item in post_state["authorized_next"]
        )
        or not all(
            _phase_is_prohibited(later, post_state["prohibited"])
            for later in ("Phase 6", "Phase 7", "Phase 8", "Phase 9")
        )
    ):
        raise SystemExit("post-successor machine-state semantics are malformed")
    manifest: dict[str, Any] | None = None
    case_ids: tuple[str, ...] | None = None
    for field, path in (
        ("semantic_oracle", paths["oracle"]),
        ("adversarial_cases", paths["cases"]),
    ):
        binding = value.get(field)
        data = _blob(repository, ref, path)
        if (
            not isinstance(binding, dict)
            or set(binding) != {"path", "sha256"}
            or binding.get("path") != path
            or binding.get("sha256") != hashlib.sha256(data).hexdigest()
            or _mode(repository, ref, path) != "100644"
        ):
            raise SystemExit(f"{field} is not content-addressed regular evidence")
        if field == "semantic_oracle":
            manifest = _manifest(data)
        else:
            case_ids = _cases(data)
    if (
        manifest is None
        or case_ids is None
        or manifest.get("SCHEMA_VERSION") != "1.0.0"
        or manifest.get("GATE_ID") != authority["gate_id"]
        or manifest.get("AUDIT_PROFILE") != policy["profile_id"]
        or manifest.get("ADVERSARIAL_CASE_IDS") != case_ids
        or manifest.get("EXPECTED_TEST_NODEIDS") != tuple(policy["expected_added_test_nodeids"])
    ):
        raise SystemExit("candidate manifest is not bound to gate evidence")
    baseline = _baseline(repository, ref, authority)
    if baseline != ref:
        for path in (paths["bundle"], paths["oracle"], paths["cases"]):
            if (
                _mode(repository, baseline, path) != "100644"
                or _blob(repository, baseline, path) != _blob(repository, ref, path)
            ):
                raise SystemExit("accepted gate evidence drifted after bootstrap")
    component_raw = _blob(repository, baseline, COMPONENT_LOCK_PATH)
    component = _kernel_component(repository, baseline)
    current_component = _kernel_component(repository, ref)
    count, schema_sha = _schema_set(repository, baseline)
    current_count, _ = _schema_set(repository, ref)
    kernel = value.get("kernel_release")
    if (
        hashlib.sha256(component_raw).hexdigest() != value["component_lock_sha256"]
        or count != 43
        or current_count != 43
        or schema_sha != value["public_schema_set_sha256"]
        or not isinstance(kernel, dict)
        or set(kernel) != {*_KERNEL, "schema_sha256"}
        or any(kernel.get(key) != expected for key, expected in _KERNEL.items())
        or not isinstance(kernel.get("schema_sha256"), dict)
        or len(kernel["schema_sha256"]) != 8
        or component["valuation_kernel"].get("public_schema_sha256") != kernel["schema_sha256"]
        or current_component["valuation_kernel"].get("public_schema_sha256")
        != kernel["schema_sha256"]
    ):
        raise SystemExit("bundle dependency or rc.2 identity drifted")
    return value


def _status_core(value: dict[str, Any]) -> dict[str, Any]:
    return {key: value.get(key) for key in _STATE_KEYS}


def _stage(
    repository: Path,
    ref: str,
    authority: dict[str, Any],
    *,
    root_predecessor: dict[str, Any] | None,
) -> tuple[str, dict[str, Any] | None]:
    paths = _paths(authority)
    status = _json_blob(repository, ref, STATUS_PATH, canonical=False)
    has_bundle = _exists(repository, ref, paths["bundle"])
    has_closeout = _exists(repository, ref, paths["closeout"])
    has_successor = _exists(repository, ref, paths["successor_closeout"])
    markers = [
        path
        for path, disposition in authority["successor_implementation_diff"].items()
        if disposition == "A" and path != STATUS_PATH
    ]
    has_impl = bool(markers) and all(_exists(repository, ref, path) for path in markers)
    if any(_exists(repository, ref, path) for path in markers) != has_impl:
        return "invalid", None
    if not any((has_bundle, has_closeout, has_impl, has_successor)):
        return (
            "s3"
            if root_predecessor is not None and _status_core(status) == root_predecessor
            else "absent",
            None,
        )
    if not has_bundle:
        return "invalid", None
    bundle = _bundle(repository, ref, authority)
    post = bundle["post_successor_closeout"]
    has_post = _exists(repository, ref, post["closeout_path"])
    if not has_closeout:
        return (
            "g1"
            if not has_impl
            and not has_successor
            and not has_post
            and _status_core(status) == authority["pending_gate_state"]
            else "invalid",
            bundle,
        )
    bootstrap_profile = "phase5e-successor-gate-bootstrap"
    if has_closeout and not has_impl and not has_successor:
        valid = _closeout(
            _json_blob(repository, ref, paths["closeout"]),
            gate_id=authority["gate_id"],
            profile=bootstrap_profile,
            version="2.3.2.3.4.1",
            test_count=int(bundle["audit"]["predecessor_test_count"]),
        )
        return (
            (
                "g2"
                if valid
                and not has_post
                and _status_core(status) == authority["accepted_gate_state"]
                else "invalid"
            ),
            bundle,
        )
    if has_closeout and has_impl and not has_successor:
        return (
            (
                "g3"
                if not has_post
                and _status_core(status) == authority["successor_pending_state"]
                else "invalid"
            ),
            bundle,
        )
    if has_closeout and has_impl and has_successor:
        successor_ok = _closeout(
            _json_blob(repository, ref, paths["successor_closeout"]),
            gate_id=authority["gate_id"],
            profile=bundle["audit"]["profile_id"],
            version=bundle["audit"]["audit_version"],
            test_count=(
                int(bundle["audit"]["predecessor_test_count"])
                + len(bundle["audit"]["expected_added_test_nodeids"])
            ),
        )
        if not has_post:
            return (
                (
                    "g4"
                    if successor_ok
                    and _status_core(status) == authority["successor_accepted_state"]
                    else "invalid"
                ),
                bundle,
            )
        post_ok = _closeout(
            _json_blob(repository, ref, post["closeout_path"]),
            gate_id=authority["gate_id"],
            profile=post["implementation_audit_profile"],
            version=post["implementation_audit_version"],
            test_count=post["expected_test_count"],
        )
        seed = _next_seed(bundle.get("next_gate_seed"), authority=authority, post=post)
        external_seed = _external_handoff_seed(
            repository,
            ref,
            authority=authority,
            bundle=bundle,
        )
        next_authority = seed or external_seed
        next_exists = next_authority is not None and _exists(
            repository,
            ref,
            _paths(next_authority)["bundle"],
        )
        return (
            "g5"
            if successor_ok
            and post_ok
            and (_status_core(status) == post["accepted_state"] or next_exists)
            else "invalid",
            bundle,
        )
    return "invalid", bundle


def _position(
    repository: Path,
    ref: str,
    *,
    root: dict[str, Any],
    root_predecessor: dict[str, Any] | None,
) -> Position:
    authority = root
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    seen_branches: set[str] = set()
    for depth in range(_MAX_CHAIN_DEPTH):
        gate_paths = set(_authority_governed_paths(authority))
        gate_branches = {
            authority["bootstrap_branch"],
            authority["acceptance_branch"],
            authority["successor_implementation_branch"],
            authority["successor_acceptance_branch"],
        }
        if (
            authority["gate_id"] in seen_ids
            or seen_paths & gate_paths
            or seen_branches & gate_branches
        ):
            raise SystemExit("recursive gate chain reuses an identity, path, or branch")
        seen_ids.add(authority["gate_id"])
        seen_paths.update(gate_paths)
        seen_branches.update(gate_branches)
        stage, bundle = _stage(
            repository,
            ref,
            authority,
            root_predecessor=root_predecessor if depth == 0 else None,
        )
        if bundle is not None:
            post = bundle["post_successor_closeout"]
            if post["closeout_path"] in seen_paths or post["branch"] in seen_branches:
                raise SystemExit("post-closeout reuses gate authority")
            seen_paths.update(
                _authority_governed_paths(
                    authority,
                    post_successor_closeout=post,
                )
            )
            seen_branches.add(post["branch"])
        if stage != "g5" or bundle is None:
            if stage in {"invalid", "absent"}:
                raise SystemExit(f"recursive gate state is {stage}")
            return Position(authority=authority, bundle=bundle, depth=depth, stage=stage)
        seed = _next_seed(
            bundle.get("next_gate_seed"),
            authority=authority,
            post=bundle["post_successor_closeout"],
        )
        if seed is None:
            seed = _external_handoff_seed(
                repository,
                ref,
                authority=authority,
                bundle=bundle,
            )
        if seed is None or not _exists(repository, ref, _paths(seed)["bundle"]):
            return Position(authority=authority, bundle=bundle, depth=depth, stage="g5")
        authority = seed
    raise SystemExit("recursive gate chain exceeds its fixed depth")


def _exact_diff(repository: Path, base: str, head: str) -> dict[str, str]:
    raw = _git(
        repository,
        "diff",
        "--name-status",
        "--no-renames",
        "-z",
        base,
        head,
        text=False,
    )
    assert isinstance(raw, bytes)
    fields = raw.split(b"\0")
    if fields[-1:] != [b""] or len(fields[:-1]) % 2:
        raise SystemExit("Git diff is not an exact NUL-delimited pair sequence")
    result: dict[str, str] = {}
    for index in range(0, len(fields) - 1, 2):
        try:
            disposition = fields[index].decode("ascii")
            path = fields[index + 1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SystemExit("Git diff contains malformed path bytes") from exc
        if disposition not in {"A", "M"} or path in result or not _safe_path(path):
            raise SystemExit("Git diff contains a forbidden lifecycle or duplicate path")
        result[path] = disposition
    return result


def _expected_transition(position: Position) -> tuple[dict[str, str], str, int, str]:
    authority = position.authority
    if position.stage == "s3":
        return authority["gate_bootstrap_diff"], "g1", position.depth, authority["gate_id"]
    if position.stage == "g1":
        return authority["gate_acceptance_diff"], "g2", position.depth, authority["gate_id"]
    if position.stage == "g2":
        return (
            authority["successor_implementation_diff"],
            "g3",
            position.depth,
            authority["gate_id"],
        )
    if position.stage == "g3":
        return authority["successor_acceptance_diff"], "g4", position.depth, authority["gate_id"]
    if position.stage == "g4" and position.bundle is not None:
        return (
            position.bundle["post_successor_closeout"]["diff"],
            "g5",
            position.depth,
            authority["gate_id"],
        )
    if position.stage == "g5" and position.bundle is not None:
        seed = _next_seed(
            position.bundle.get("next_gate_seed"),
            authority=authority,
            post=position.bundle["post_successor_closeout"],
        )
        if seed is None:
            if authority["next_owner_phase"] != _EXTERNAL_FEASIBILITY_PHASE:
                raise SystemExit("terminal gate has no authorized next transition")
            return (
                dict(_EXTERNAL_CONTROLLER_DIFF),
                "g1",
                position.depth + 1,
                "phase5e2c0",
            )
        return seed["gate_bootstrap_diff"], "g1", position.depth + 1, seed["gate_id"]
    raise SystemExit("controller stage has no authorized transition")


def _sealed_controller_reauthorization(position: Position) -> bool:
    bundle = position.bundle
    if position.stage != "g5" or position.depth != 1 or not isinstance(bundle, dict):
        return False
    authority = position.authority
    post = bundle.get("post_successor_closeout")
    accepted = post.get("accepted_state") if isinstance(post, dict) else None
    prohibited = accepted.get("prohibited") if isinstance(accepted, dict) else None
    return (
        authority.get("gate_id") == "phase5e2c0"
        and authority.get("owner_phase") == _EXTERNAL_TARGET_PHASE
        and authority.get("next_owner_phase") == _PHASE_SUCCESSOR[_EXTERNAL_TARGET_PHASE]
        and authority.get("next_gate_authority_sha256") is None
        and bundle.get("next_gate_seed") is None
        and isinstance(accepted, dict)
        and accepted.get("status") == "accepted_closed"
        and accepted.get("authorized_next") == []
        and isinstance(prohibited, list)
        and {
            "Phase 5E-2C-1",
            "Phase 6",
            "Phase 7",
            "Phase 8",
            "Phase 9",
        }.issubset(prohibited)
    )


def _expected_status_patch(
    controller_position: Position,
    candidate_position: Position,
) -> dict[str, Any]:
    authority = controller_position.authority
    if controller_position.stage == "s3":
        return authority["pending_gate_state"]
    if controller_position.stage == "g1":
        return authority["accepted_gate_state"]
    if controller_position.stage == "g2":
        return authority["successor_pending_state"]
    if controller_position.stage == "g3":
        return authority["successor_accepted_state"]
    if controller_position.stage == "g4" and controller_position.bundle is not None:
        return controller_position.bundle["post_successor_closeout"]["accepted_state"]
    if controller_position.stage == "g5":
        return candidate_position.authority["pending_gate_state"]
    raise SystemExit("controller stage has no exact machine-state transition")


def main() -> int:
    global _PROTECTED_EXTERNAL_TRUST

    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--controller-root", type=Path, required=True)
    parser.add_argument("--controller-ref", required=True)
    parser.add_argument("--candidate-ref", required=True)
    parser.add_argument("--verify-sealed-controller-ref", action="store_true")
    args = parser.parse_args()
    repository = args.repository.resolve()
    controller = args.controller_root.resolve()
    controller_ref = _commit(controller, args.controller_ref)
    candidate_ref = _commit(repository, args.candidate_ref)
    if str(_git(repository, "merge-base", controller_ref, candidate_ref)) != controller_ref:
        raise SystemExit("candidate is not descended from the protected controller commit")
    trust_raw = _blob(controller, controller_ref, TRUST_PATH)
    if _mode(controller, controller_ref, TRUST_PATH) != "100644":
        raise SystemExit("protected trust root is not a regular file")
    trust = _strict_json(trust_raw, label=TRUST_PATH, canonical=True)
    if not isinstance(trust, dict) or not isinstance(trust.get("successor_gate_bootstrap"), dict):
        raise SystemExit("protected trust root has no recursive gate authority")
    root = _authority(trust["successor_gate_bootstrap"])
    external_trust_raw = _blob(controller, controller_ref, BASE_TRUST_PATH)
    if _mode(controller, controller_ref, BASE_TRUST_PATH) != "100644":
        raise SystemExit("protected external trust root is not a regular file")
    external_trust = _strict_json(
        external_trust_raw,
        label=BASE_TRUST_PATH,
        canonical=True,
    )
    receipt_authority = (
        external_trust.get("external_feasibility_receipt_authority")
        if isinstance(external_trust, dict)
        else None
    )
    futu_policy = (
        external_trust.get("futu_market_authority_policy")
        if isinstance(external_trust, dict)
        else None
    )
    if (
        not isinstance(receipt_authority, dict)
        or receipt_authority.get("algorithm") != "ed25519"
        or receipt_authority.get("domain") != _RECEIPT_DOMAIN
        or receipt_authority.get("required_order") != list(_EXTERNAL_RECEIPT_KINDS)
        or receipt_authority.get("max_validity_seconds")
        != _RECEIPT_MAX_VALIDITY_SECONDS
        or not isinstance(futu_policy, dict)
        or set(futu_policy) != {"path", "sha256", "overlay_path", "overlay_sha256"}
    ):
        raise SystemExit("protected external feasibility trust is malformed")
    for path_key, sha_key in (("path", "sha256"), ("overlay_path", "overlay_sha256")):
        path = futu_policy[path_key]
        if (
            not _safe_path(path)
            or not _sha(futu_policy[sha_key])
            or _mode(controller, controller_ref, path) != "100644"
            or hashlib.sha256(_blob(controller, controller_ref, path)).hexdigest()
            != futu_policy[sha_key]
        ):
            raise SystemExit("protected Futu market-authority policy binding drifted")
    policy_path = futu_policy["path"]
    policy_payload = _strict_json(
        _blob(controller, controller_ref, policy_path),
        label=policy_path,
        canonical=True,
    )
    policy_conditions = (
        policy_payload.get("feasibility_gate", {}).get("all_required")
        if isinstance(policy_payload, dict)
        else None
    )
    covered_conditions = [
        condition
        for kind in _EXTERNAL_RECEIPT_KINDS
        for condition in _EXTERNAL_CONDITION_COVERAGE[kind]
    ]
    if (
        not isinstance(policy_conditions, list)
        or any(type(item) is not str for item in policy_conditions)
        or len(policy_conditions) != len(set(policy_conditions))
        or set(policy_conditions) != set(covered_conditions)
        or len(covered_conditions) != len(set(covered_conditions))
    ):
        raise SystemExit("protected receipts do not cover every Futu feasibility condition")
    _PROTECTED_EXTERNAL_TRUST = external_trust
    protected_behavior_oracle = root["audit_policy"]["protected_oracle_path"]
    if (
        _mode(controller, controller_ref, protected_behavior_oracle) != "100644"
        or hashlib.sha256(
            _blob(controller, controller_ref, protected_behavior_oracle)
        ).hexdigest()
        != root["audit_policy"]["protected_oracle_sha256"]
    ):
        raise SystemExit("protected successor behavior oracle drifted")
    predecessor = trust.get("states", {}).get("s3", {}).get("status_patch")
    if not isinstance(predecessor, dict):
        raise SystemExit("protected trust root has no predecessor state")
    # The candidate may not replace the protected root even when it synchronously updates other
    # hashes.  Read both commits and compare exact blob bytes/modes.
    if (
        not _exists(repository, candidate_ref, TRUST_PATH)
        or _mode(repository, candidate_ref, TRUST_PATH) != "100644"
        or _blob(repository, candidate_ref, TRUST_PATH) != trust_raw
    ):
        raise SystemExit("candidate changed the protected recursive authority root")
    if (
        not _exists(repository, candidate_ref, BASE_TRUST_PATH)
        or _mode(repository, candidate_ref, BASE_TRUST_PATH) != "100644"
        or _blob(repository, candidate_ref, BASE_TRUST_PATH) != external_trust_raw
    ):
        raise SystemExit("candidate changed the protected external authority root")
    controller_position = _position(
        controller,
        controller_ref,
        root=root,
        root_predecessor=predecessor,
    )
    candidate_position = _position(
        repository,
        candidate_ref,
        root=root,
        root_predecessor=predecessor,
    )
    if args.verify_sealed_controller_ref:
        if (
            controller_ref != candidate_ref
            or _exact_diff(repository, controller_ref, candidate_ref)
            or not _sealed_controller_reauthorization(controller_position)
            or not _sealed_controller_reauthorization(candidate_position)
        ):
            raise SystemExit("sealed Controller reauthorization position is not exact-head")
        print("phase5e-successor-gate-independent-sealed-controller-oracle: passed")
        return 0
    expected_diff, expected_stage, expected_depth, expected_gate = _expected_transition(
        controller_position
    )
    actual_diff = _exact_diff(repository, controller_ref, candidate_ref)
    if actual_diff != expected_diff:
        raise SystemExit("candidate diff does not equal the protected transition")
    for path in actual_diff:
        if _mode(repository, candidate_ref, path) != "100644":
            raise SystemExit("candidate transition contains a symlink or executable file")
    if (
        candidate_position.stage != expected_stage
        or candidate_position.depth != expected_depth
        or candidate_position.authority["gate_id"] != expected_gate
    ):
        raise SystemExit("candidate did not advance exactly one protected gate transition")
    controller_status = _json_blob(
        controller,
        controller_ref,
        STATUS_PATH,
        canonical=False,
    )
    candidate_status = _json_blob(
        repository,
        candidate_ref,
        STATUS_PATH,
        canonical=False,
    )
    expected_status = dict(controller_status)
    expected_status.update(_expected_status_patch(controller_position, candidate_position))
    if candidate_status != expected_status:
        raise SystemExit("candidate changed machine-state history outside the exact transition")
    external_transition = (
        controller_position.stage == "g5"
        and controller_position.bundle is not None
        and controller_position.bundle.get("next_gate_seed") is None
        and controller_position.authority["next_owner_phase"]
        == _EXTERNAL_FEASIBILITY_PHASE
    )
    if external_transition:
        handoff = _json_blob(repository, candidate_ref, _EXTERNAL_HANDOFF_PATH)
        if (
            _parents(repository, candidate_ref) != (controller_ref,)
            or handoff.get("predecessor_commit") != controller_ref
        ):
            raise SystemExit("external handoff is not the unique direct controller transition")
    if controller_position.stage in {"s3", "g5"}:
        candidate_bundle = candidate_position.bundle
        if candidate_bundle is None:
            raise SystemExit("gate bootstrap produced no bundle")
        predecessor_sha = hashlib.sha256(
            (
                json.dumps(
                    _json_blob(controller, controller_ref, STATUS_PATH, canonical=False),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
        ).hexdigest()
        if candidate_bundle["predecessor_state_fingerprint"] != predecessor_sha:
            raise SystemExit("bundle predecessor-state fingerprint is not commit-bound")
    print("phase5e-successor-gate-independent-commit-oracle: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
