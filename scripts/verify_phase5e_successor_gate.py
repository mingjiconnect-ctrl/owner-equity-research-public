#!/usr/bin/env python3
"""Protected-base generic successor gate for the remaining Phase 5 sequence.

Candidate gate bundles are inert data until their own acceptance-only transition is complete.
Before acceptance this verifier hashes and parses the proposed oracle but never imports, compiles,
or executes it.  Accepted bundles may later be consumed only by the protected audit controller.
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import re
import subprocess
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TRUST_PATH = Path(__file__).with_name("phase5e2b12b-acceptance-trust.json")
BASE_TRUST_PATH = Path(__file__).with_name("phase5e2b12a-acceptance-trust.json")
SCHEMA_PATH = Path(__file__).with_name("phase5e-successor-gate-bundle.schema.json")
STATUS_PATH = "docs/phase-status.json"
COMPONENT_LOCK_PATH = "component-lock.json"
PUBLIC_SCHEMA_PREFIX = "schemas/"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
_BRANCH = re.compile(r"(?:feature|fix)/[a-z0-9][a-z0-9._/-]*\Z")
_CHECK_ID = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_AUDIT_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){2,4}\Z")
_UTC_TIMESTAMP = re.compile(
    r"20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)
_EXTERNAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_EXTERNAL_HANDOFF_BYTES = 64 * 1024
_KERNEL = {
    "tag": "v2.0.0-rc.2",
    "tag_object": "4e19ce6a59bc4321ebcd368e807ed764f4e8abde",
    "commit": "be9b0773d5a78f5f8a33ba982494512668df85fe",
    "wheel_sha256": "fb27d01b1ee75fbd542371510150e890516d306218d33f3608f2aa3caa0e55a5",
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
_STATE_KEYS = {"current_phase", "status", "authorized_next", "prohibited", "release_tag"}
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
_HASHED_PATH_KEYS = {"path", "sha256"}
_ORACLE_MANIFEST_KEYS = (
    "SCHEMA_VERSION",
    "GATE_ID",
    "AUDIT_PROFILE",
    "ADVERSARIAL_CASE_IDS",
    "EXPECTED_TEST_NODEIDS",
)
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
_POST_CLOSEOUT_KEYS = {
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

_GENERIC_SUCCESSOR_CHECK_IDS = frozenset(
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
_CONTROL_PLANE_FORBIDDEN_PREFIXES = frozenset({".github", "scripts"})
_CONTROL_PLANE_FROZEN_PATHS = frozenset(
    {
        "tests/test_phase5e2b12a_acceptance_gate.py",
        "tests/test_phase5e2b12b_acceptance_gate.py",
        "tests/test_phase5e_audit.py",
        "tests/test_phase5e_successor_gate.py",
    }
)

# This sequence is a protected-base capability chain.  A candidate bundle may describe only the
# immediate next owner phase; it cannot skip to a later production phase or manufacture a Phase 9
# authorization.  Corrective Phase 5R gates are installed only after a separately accepted final
# audit and are deliberately outside this pre-release sequence.
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
# The externally authorized 2C-0 contract gate is deliberately a new controller
# reauthorization boundary. Its feasibility handoff may not pre-authorize 2C-1
# implementation bytes, tests, or an executable oracle. A later protected-base
# change must install the next exact authority after 2C-0 itself is accepted.
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
# The external feasibility review may authorize the exact 2C-0 contract surface.  Only these
# current trust-root paths/prefixes may be released into that Controller-owned implementation
# diff; every other historical control remains frozen.
_EXTERNAL_RELEASABLE_FROZEN_PATHS = frozenset(
    {
        COMPONENT_LOCK_PATH,
        "pyproject.toml",
        "schemas/market-reference-snapshot.schema.json",
        "schemas/valuation-handoff.schema.json",
    }
)
_EXTERNAL_RELEASABLE_FORBIDDEN_PREFIXES = frozenset({"plugins", "schemas"})
_EXTERNAL_RELEASE_PATH_ALLOWLIST = frozenset(
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
_SHARED_MUTABLE_PATHS = frozenset({STATUS_PATH})
_MAX_BUNDLE_BYTES = 512 * 1024
_MAX_ORACLE_BYTES = 64 * 1024
_MAX_CASE_BYTES = 256 * 1024
_MAX_ORACLE_AST_NODES = 4096
RemoteEvidenceVerifier = Callable[..., None]

_BASE_TRUST_RAW = BASE_TRUST_PATH.read_bytes()
_BASE_TRUST = json.loads(_BASE_TRUST_RAW)
if _BASE_TRUST_RAW != (
    json.dumps(_BASE_TRUST, allow_nan=False, indent=2, sort_keys=True) + "\n"
).encode():
    raise RuntimeError("protected-base trust is not canonical JSON")
_RECEIPT_AUTHORITY = _BASE_TRUST.get("external_feasibility_receipt_authority")
_FUTU_POLICY_AUTHORITY = _BASE_TRUST.get("futu_market_authority_policy")
if (
    not isinstance(_RECEIPT_AUTHORITY, dict)
    or _RECEIPT_AUTHORITY.get("algorithm") != "ed25519"
    or _RECEIPT_AUTHORITY.get("domain")
    != "owner-equity-research/phase5e2cp/receipt/v1"
    or _RECEIPT_AUTHORITY.get("required_order") != list(_EXTERNAL_RECEIPT_KINDS)
    or _RECEIPT_AUTHORITY.get("condition_coverage")
    != {kind: list(values) for kind, values in _EXTERNAL_CONDITION_COVERAGE.items()}
    or _RECEIPT_AUTHORITY.get("max_validity_seconds") != 86400
    or not isinstance(_RECEIPT_AUTHORITY.get("signers"), dict)
    or set(_RECEIPT_AUTHORITY["signers"]) != set(_EXTERNAL_RECEIPT_KINDS)
    or not isinstance(_FUTU_POLICY_AUTHORITY, dict)
    or set(_FUTU_POLICY_AUTHORITY)
    != {"path", "sha256", "overlay_path", "overlay_sha256"}
):
    raise RuntimeError("protected external-feasibility trust is malformed")
_RECEIPT_AUTHORITY_STATUS = str(_RECEIPT_AUTHORITY.get("status"))
_RECEIPT_DOMAIN = str(_RECEIPT_AUTHORITY["domain"])
_RECEIPT_MAX_VALIDITY_SECONDS = int(_RECEIPT_AUTHORITY["max_validity_seconds"])
_RECEIPT_SIGNERS = {
    str(kind): dict(value) for kind, value in _RECEIPT_AUTHORITY["signers"].items()
}
_FUTU_POLICY_PATH = str(_FUTU_POLICY_AUTHORITY["path"])
_FUTU_POLICY_SHA256 = str(_FUTU_POLICY_AUTHORITY["sha256"])
_FUTU_OVERLAY_PATH = str(_FUTU_POLICY_AUTHORITY["overlay_path"])
_FUTU_OVERLAY_SHA256 = str(_FUTU_POLICY_AUTHORITY["overlay_sha256"])
for _relative, _expected_digest in (
    (_FUTU_POLICY_PATH, _FUTU_POLICY_SHA256),
    (_FUTU_OVERLAY_PATH, _FUTU_OVERLAY_SHA256),
):
    _target = ROOT / _relative
    if (
        not _target.is_file()
        or hashlib.sha256(_target.read_bytes()).hexdigest() != _expected_digest
    ):
        raise RuntimeError("protected Futu market-authority policy bytes drifted")
_EXTERNAL_PROTECTED_ORACLE_SHA256 = hashlib.sha256(
    (ROOT / _EXTERNAL_PROTECTED_ORACLE_PATH).read_bytes()
).hexdigest()

if _RECEIPT_AUTHORITY_STATUS == "pinned":
    _signer_key_ids = [value.get("key_id") for value in _RECEIPT_SIGNERS.values()]
    _signer_public_keys = [
        value.get("public_key_hex") for value in _RECEIPT_SIGNERS.values()
    ]
    if (
        len(set(_signer_key_ids)) != len(_EXTERNAL_RECEIPT_KINDS)
        or len(set(_signer_public_keys)) != len(_EXTERNAL_RECEIPT_KINDS)
        or any(
            not isinstance(key_id, str)
            or _EXTERNAL_ID.fullmatch(key_id) is None
            for key_id in _signer_key_ids
        )
        or any(
            not isinstance(public_key, str)
            or re.fullmatch(r"[0-9a-f]{64}", public_key) is None
            for public_key in _signer_public_keys
        )
    ):
        raise RuntimeError("pinned external receipt signers are not three distinct keys")


@dataclass(frozen=True, slots=True)
class GatePosition:
    authority: dict[str, Any]
    gate_id: str
    depth: int
    stage: str
    bundle: dict[str, Any] | None


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_json(raw: bytes, *, label: str, require_canonical: bool = True) -> Any:
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    canonical = (json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    if require_canonical and raw != canonical:
        raise SystemExit(f"{label} is not canonically serialized")
    return value


def _git(repository: Path, *args: str, text: bool = True) -> str | bytes:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args],
        text=text,
    ).strip()


def _git_bytes(repository: Path, ref: str, path: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repository), "show", f"{ref}:{path}"])


def _git_json(repository: Path, ref: str, path: str) -> Any:
    return _canonical_json(_git_bytes(repository, ref, path), label=path)


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


def _tracked_paths(repository: Path, ref: str, prefix: str) -> frozenset[str]:
    raw = str(_git(repository, "ls-tree", "-r", "--name-only", ref, "--", prefix))
    paths = frozenset(path for path in raw.splitlines() if path)
    if any(not _safe_path(path) for path in paths):
        raise SystemExit("tracked protected path inventory is malformed")
    return paths


def _safe_path(value: object) -> bool:
    if not isinstance(value, str) or not value or unicodedata.normalize("NFC", value) != value:
        return False
    if any(character in value for character in ("?", "#", "\\", "\x00")):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and str(path) == value


def _sha256(value: object) -> bool:
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
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


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
    if _RECEIPT_AUTHORITY_STATUS != "pinned":
        raise SystemExit("external feasibility receipt signer authority is still pending")
    policy = _canonical_json(
        (ROOT / _FUTU_POLICY_PATH).read_bytes(),
        label=_FUTU_POLICY_PATH,
        require_canonical=True,
    )
    required_conditions = (
        policy.get("feasibility_gate", {}).get("all_required")
        if isinstance(policy, dict)
        else None
    )
    covered_conditions = [
        condition
        for kind in _EXTERNAL_RECEIPT_KINDS
        for condition in _EXTERNAL_CONDITION_COVERAGE[kind]
    ]
    if (
        not isinstance(required_conditions, list)
        or any(type(item) is not str for item in required_conditions)
        or len(required_conditions) != len(set(required_conditions))
        or set(required_conditions) != set(covered_conditions)
        or len(covered_conditions) != len(set(covered_conditions))
    ):
        raise SystemExit("external feasibility receipts do not cover the closed policy gates")
    if not isinstance(value, list) or len(value) != len(_EXTERNAL_RECEIPT_KINDS):
        raise SystemExit("external feasibility handoff lacks its three signed receipts")
    approved_time = _utc_timestamp(approved_at)
    if approved_time is None:
        raise SystemExit("external feasibility approval time is malformed")
    receipts: list[dict[str, Any]] = []
    prior_sha: str | None = None
    prior_issued: datetime | None = None
    for sequence, (expected_kind, item) in enumerate(
        zip(_EXTERNAL_RECEIPT_KINDS, value, strict=True),
        start=1,
    ):
        if not isinstance(item, dict) or set(item) != _EXTERNAL_RECEIPT_KEYS:
            raise SystemExit("external feasibility signed receipt envelope is malformed")
        payload = item.get("payload")
        signature_hex = item.get("signature_hex")
        signer = _RECEIPT_SIGNERS[expected_kind]
        if (
            not isinstance(payload, dict)
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
            or not _sha256(payload.get("artifact_sha256"))
            or payload.get("artifact_object_id") != payload.get("artifact_sha256")
            or not isinstance(payload.get("artifact_version"), str)
            or _EXTERNAL_ID.fullmatch(payload["artifact_version"]) is None
            or any(payload.get(key) != expected_value for key, expected_value in expected.items())
        ):
            raise SystemExit("external feasibility signed receipt payload is malformed")
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
            raise SystemExit("external feasibility signed receipt time bound is invalid")
        public_key = signer.get("public_key_hex")
        if not isinstance(public_key, str) or not _verify_ed25519(
            public_key,
            signature_hex,
            _receipt_payload_bytes(payload),
        ):
            raise SystemExit("external feasibility receipt signature is invalid")
        envelope = {"payload": copy.deepcopy(payload), "signature_hex": signature_hex}
        prior_sha = _canonical_payload_sha256(envelope)
        prior_issued = issued
        receipts.append(envelope)
    if len({item["payload"]["receipt_id"] for item in receipts}) != len(receipts):
        raise SystemExit("external feasibility receipt identities are not unique")
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
        and len(value["prohibited"]) == len(set(value["prohibited"]))
        and all(isinstance(item, str) and item for item in value["prohibited"])
        and not (set(value["authorized_next"]) & set(value["prohibited"]))
        and value.get("release_tag") is None
    )


def _phase_is_prohibited(phase: str | None, prohibited: list[str]) -> bool:
    if phase is None:
        return False
    return any(phase == item or phase.startswith(item + "-") for item in prohibited)


def _validate_authority_state_semantics(authority: dict[str, Any]) -> bool:
    """Constrain the four machine states to the authority's immediate owner phase."""

    owner = authority["owner_phase"]
    next_owner = authority["next_owner_phase"]
    pending = authority["pending_gate_state"]
    accepted_gate = authority["accepted_gate_state"]
    successor_pending = authority["successor_pending_state"]
    successor_accepted = authority["successor_accepted_state"]
    forbidden_later_authority = any(
        any(label in item for label in ("Phase 6", "Phase 7", "Phase 8", "Phase 9"))
        for state in (pending, accepted_gate, successor_pending, successor_accepted)
        for item in state["authorized_next"]
    )
    later_phases_explicitly_prohibited = all(
        _phase_is_prohibited(later, state["prohibited"])
        for state in (pending, accepted_gate, successor_pending, successor_accepted)
        for later in ("Phase 6", "Phase 7", "Phase 8", "Phase 9")
    )
    terminal = owner == _TERMINAL_PHASE and next_owner is None
    return (
        pending["current_phase"] == f"{owner}-gate"
        and pending["status"] == "implementation_complete_pending_acceptance"
        and pending["authorized_next"] == [f"{owner} successor-gate acceptance closeout"]
        and _phase_is_prohibited(owner, pending["prohibited"])
        and accepted_gate["current_phase"] == f"{owner}-gate"
        and accepted_gate["status"] == "accepted_closed"
        and len(accepted_gate["authorized_next"]) == 1
        and accepted_gate["authorized_next"][0].startswith(owner + " ")
        and accepted_gate["authorized_next"][0].endswith(" implementation")
        and not _phase_is_prohibited(owner, accepted_gate["prohibited"])
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
            or all(
                _phase_is_prohibited(next_owner, state["prohibited"])
                for state in (pending, accepted_gate, successor_pending, successor_accepted)
            )
        )
        and not forbidden_later_authority
        and later_phases_explicitly_prohibited
    )


def _diff(value: object) -> bool:
    return (
        isinstance(value, dict)
        and bool(value)
        and all(
            _safe_path(path) and disposition in {"A", "M"}
            for path, disposition in value.items()
        )
    )


def _load_trust() -> dict[str, Any]:
    value = _canonical_json(TRUST_PATH.read_bytes(), label=str(TRUST_PATH.name))
    if not isinstance(value, dict) or not isinstance(value.get("successor_gate_bootstrap"), dict):
        raise RuntimeError("2B trust does not preinstall a successor-gate bootstrap")
    return value


def _valid_audit_policy(audit: object) -> bool:
    return (
        isinstance(audit, dict)
        and set(audit) == _AUDIT_POLICY_KEYS
        and isinstance(audit.get("profile_id"), str)
        and _CHECK_ID.fullmatch(audit["profile_id"]) is not None
        and isinstance(audit.get("audit_version"), str)
        and _AUDIT_VERSION.fullmatch(audit["audit_version"]) is not None
        and _safe_path(audit.get("protected_oracle_path"))
        and str(audit["protected_oracle_path"]).startswith("scripts/")
        and _sha256(audit.get("protected_oracle_sha256"))
        and isinstance(audit.get("mandatory_check_ids"), list)
        and audit["mandatory_check_ids"] == sorted(audit["mandatory_check_ids"])
        and set(audit["mandatory_check_ids"]) == _GENERIC_SUCCESSOR_CHECK_IDS
        and len(audit["mandatory_check_ids"]) == len(set(audit["mandatory_check_ids"]))
        and all(
            isinstance(item, str) and _CHECK_ID.fullmatch(item)
            for item in audit["mandatory_check_ids"]
        )
        and isinstance(audit.get("expected_added_test_nodeids"), list)
        and audit["expected_added_test_nodeids"]
        == sorted(audit["expected_added_test_nodeids"])
        and bool(audit["expected_added_test_nodeids"])
        and len(audit["expected_added_test_nodeids"])
        == len(set(audit["expected_added_test_nodeids"]))
        and all(
            isinstance(item, str) and item
            for item in audit["expected_added_test_nodeids"]
        )
        and type(audit.get("predecessor_test_count")) is int
        and audit["predecessor_test_count"] > 0
        and _sha256(audit.get("predecessor_nodeid_sha256"))
    )


def _valid_post_successor_closeout(value: object, *, expected_test_count: int) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == _POST_CLOSEOUT_KEYS
        and _BRANCH.fullmatch(str(value.get("branch"))) is not None
        and _safe_path(value.get("closeout_path"))
        and _diff(value.get("diff"))
        and value["diff"] == {STATUS_PATH: "M", value["closeout_path"]: "A"}
        and _state(value.get("accepted_state"))
        and isinstance(value.get("implementation_audit_profile"), str)
        and _CHECK_ID.fullmatch(value["implementation_audit_profile"]) is not None
        and isinstance(value.get("implementation_audit_version"), str)
        and _AUDIT_VERSION.fullmatch(value["implementation_audit_version"]) is not None
        and isinstance(value.get("transition_audit_profile"), str)
        and _CHECK_ID.fullmatch(value["transition_audit_profile"]) is not None
        and isinstance(value.get("transition_audit_version"), str)
        and _AUDIT_VERSION.fullmatch(value["transition_audit_version"]) is not None
        and value.get("transition_check_ids")
        == sorted(_GENERIC_SUCCESSOR_CHECK_IDS)
        and type(value.get("expected_test_count")) is int
        and value["expected_test_count"] == expected_test_count
        and _sha256(value.get("expected_nodeid_sha256"))
    )


def _validate_authority(authority: object) -> dict[str, Any]:
    if not isinstance(authority, dict):
        raise RuntimeError("successor-gate authority is not an object")
    audit = authority.get("audit_policy")
    if (
        set(authority) != _AUTHORITY_KEYS
        or not isinstance(authority.get("gate_id"), str)
        or not isinstance(authority.get("owner_phase"), str)
        or not authority["owner_phase"]
        or authority["owner_phase"] not in _PHASE_SUCCESSOR
        or authority.get("next_owner_phase") != _PHASE_SUCCESSOR.get(authority["owner_phase"])
        or not (
            authority.get("next_gate_authority_sha256") is None
            or _sha256(authority.get("next_gate_authority_sha256"))
        )
        or not _BRANCH.fullmatch(str(authority.get("bootstrap_branch")))
        or not _BRANCH.fullmatch(str(authority.get("acceptance_branch")))
        or not _BRANCH.fullmatch(str(authority.get("successor_implementation_branch")))
        or not _BRANCH.fullmatch(str(authority.get("successor_acceptance_branch")))
        or not _safe_path(authority.get("bundle_directory"))
        or not _safe_path(authority.get("closeout_path"))
        or not _safe_path(authority.get("successor_closeout_path"))
        or not all(
            _diff(authority.get(key))
            for key in (
                "gate_bootstrap_diff",
                "gate_acceptance_diff",
                "successor_implementation_diff",
                "successor_acceptance_diff",
            )
        )
        or not all(
            _state(authority.get(key))
            for key in (
                "pending_gate_state",
                "accepted_gate_state",
                "successor_pending_state",
                "successor_accepted_state",
            )
        )
        or not isinstance(authority.get("frozen_paths"), list)
        or authority["frozen_paths"] != sorted(authority["frozen_paths"])
        or not authority["frozen_paths"]
        or not all(_safe_path(path) for path in authority["frozen_paths"])
        or not _CONTROL_PLANE_FROZEN_PATHS.issubset(authority["frozen_paths"])
        or not isinstance(authority.get("forbidden_prefixes"), list)
        or authority["forbidden_prefixes"] != sorted(authority["forbidden_prefixes"])
        or not authority["forbidden_prefixes"]
        or not all(_safe_path(path) for path in authority["forbidden_prefixes"])
        or not _CONTROL_PLANE_FORBIDDEN_PREFIXES.issubset(authority["forbidden_prefixes"])
        or not _valid_audit_policy(audit)
    ):
        raise RuntimeError("successor-gate bootstrap authority is malformed")
    if not _validate_authority_state_semantics(authority):
        raise RuntimeError("successor-gate machine-state semantics are malformed")
    expected_bootstrap_diff = (
        _EXTERNAL_CONTROLLER_DIFF
        if authority["gate_id"] == "phase5e2c0"
        and authority["owner_phase"] == _EXTERNAL_TARGET_PHASE
        and authority["bootstrap_branch"] == _EXTERNAL_CONTROLLER_BRANCH
        else {
            STATUS_PATH: "M",
            f'{authority["bundle_directory"]}/bundle.json': "A",
            f'{authority["bundle_directory"]}/semantic-oracle.py.txt': "A",
            f'{authority["bundle_directory"]}/adversarial-cases.json': "A",
        }
    )
    if (
        authority["gate_bootstrap_diff"] != expected_bootstrap_diff
        or authority["gate_acceptance_diff"]
        != {STATUS_PATH: "M", authority["closeout_path"]: "A"}
        or authority["successor_acceptance_diff"]
        != {STATUS_PATH: "M", authority["successor_closeout_path"]: "A"}
        or not any(
            disposition == "A" and path != STATUS_PATH
            for path, disposition in authority["successor_implementation_diff"].items()
        )
        or any(
            path != STATUS_PATH
            and (
                path in _CONTROL_PLANE_FROZEN_PATHS
                or any(
                    path == prefix or path.startswith(prefix.rstrip("/") + "/")
                    for prefix in _CONTROL_PLANE_FORBIDDEN_PREFIXES
                )
            )
            for path in (
                *authority["successor_implementation_diff"],
                *authority["successor_acceptance_diff"],
            )
        )
    ):
        raise RuntimeError("successor-gate exact transition authority is malformed")
    controlled = set(authority["successor_implementation_diff"]) | set(
        authority["successor_acceptance_diff"]
    )
    if controlled & set(authority["frozen_paths"]) or any(
        path == prefix or path.startswith(prefix.rstrip("/") + "/")
        for path in controlled
        for prefix in authority["forbidden_prefixes"]
    ):
        raise RuntimeError("successor authority weakens its own control plane")
    paths = bundle_paths(authority)
    governed_paths = tuple(paths.values())
    branches = (
        authority["bootstrap_branch"],
        authority["acceptance_branch"],
        authority["successor_implementation_branch"],
        authority["successor_acceptance_branch"],
    )
    if (
        len(governed_paths) != len(set(governed_paths))
        or len(branches) != len(set(branches))
        or authority["successor_accepted_state"]["authorized_next"] == []
    ):
        raise RuntimeError("successor-gate closeout or path authority is ambiguous")
    return copy.deepcopy(authority)


def bootstrap_authority() -> dict[str, Any]:
    authority = _validate_authority(_load_trust()["successor_gate_bootstrap"])
    oracle = ROOT / authority["audit_policy"]["protected_oracle_path"]
    if (
        oracle.is_symlink()
        or not oracle.is_file()
        or hashlib.sha256(oracle.read_bytes()).hexdigest()
        != authority["audit_policy"]["protected_oracle_sha256"]
    ):
        raise RuntimeError("protected successor behavior oracle drifted")
    return authority


def bundle_paths(authority: dict[str, Any]) -> dict[str, str]:
    directory = authority["bundle_directory"]
    return {
        "bundle": f"{directory}/bundle.json",
        "oracle": f"{directory}/semantic-oracle.py.txt",
        "cases": f"{directory}/adversarial-cases.json",
        "closeout": authority["closeout_path"],
        "successor_closeout": authority["successor_closeout_path"],
    }


def authority_governed_paths(
    authority: dict[str, Any],
    *,
    post_successor_closeout: dict[str, Any] | None = None,
) -> frozenset[str]:
    paths = set(bundle_paths(authority).values())
    for key in (
        "gate_bootstrap_diff",
        "gate_acceptance_diff",
        "successor_implementation_diff",
        "successor_acceptance_diff",
    ):
        paths.update(
            path for path in authority[key] if path not in _SHARED_MUTABLE_PATHS
        )
    if post_successor_closeout is not None:
        paths.update(
            path
            for path in post_successor_closeout["diff"]
            if path not in _SHARED_MUTABLE_PATHS
        )
    return frozenset(paths)


def _file_mode(repository: Path, ref: str, path: str) -> str:
    line = str(_git(repository, "ls-tree", ref, "--", path))
    fields = line.split(None, 3)
    if len(fields) != 4 or fields[3].split("\t", 1)[-1] != path:
        raise SystemExit(f"gate path is missing from the candidate tree: {path}")
    return fields[0]


def _changed_diff(repository: Path, base: str, head: str) -> dict[str, str]:
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
    if not isinstance(raw, bytes):
        raise SystemExit("successor gate diff did not return bytes")
    fields = raw.split(b"\0")
    if fields[-1:] != [b""]:
        raise SystemExit("successor gate diff is not NUL terminated")
    entries = fields[:-1]
    if len(entries) % 2:
        raise SystemExit("successor gate diff contains an incomplete status/path pair")
    result: dict[str, str] = {}
    for index in range(0, len(entries), 2):
        try:
            disposition = entries[index].decode("ascii")
            path = entries[index + 1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SystemExit("successor gate diff contains malformed path bytes") from exc
        if disposition not in {"A", "M"} or path in result:
            raise SystemExit("successor gate diff contains deletion, rename, or duplicate path")
        if not _safe_path(path):
            raise SystemExit("successor gate diff contains an unsafe path")
        result[path] = disposition
    return result


def _schema_set_sha256(repository: Path, ref: str) -> tuple[int, str]:
    names = str(_git(repository, "ls-tree", "-r", "--name-only", ref, "--", "schemas"))
    paths = sorted(path for path in names.splitlines() if path.endswith(".schema.json"))
    payload = b"".join(
        path.encode("utf-8")
        + b"\0"
        + hashlib.sha256(_git_bytes(repository, ref, path)).hexdigest().encode("ascii")
        + b"\n"
        for path in paths
    )
    return len(paths), hashlib.sha256(payload).hexdigest()


def _gate_baseline_ref(
    repository: Path,
    ref: str,
    *,
    authority: dict[str, Any],
) -> str:
    """Return the immutable gate-bootstrap merge used to sign bundle dependencies.

    Before gate acceptance the candidate itself is the only available baseline.  From G2 onward
    the accepted gate closeout records the bootstrap merge.  Later successor phases may make
    explicitly authorized Schema/component changes, so the bundle must remain bound to this
    historical baseline rather than being re-signed against the evolving candidate tree.
    """

    closeout_path = authority["closeout_path"]
    if not _exists(repository, ref, closeout_path):
        return ref
    closeout = _git_json(repository, ref, closeout_path)
    baseline = closeout.get("implementation_merge_commit")
    if not isinstance(baseline, str) or _GIT_OID.fullmatch(baseline) is None:
        raise SystemExit("accepted gate closeout has no canonical bootstrap merge")
    if str(_git(repository, "cat-file", "-t", baseline)) != "commit":
        raise SystemExit("accepted gate baseline is not a commit")
    if str(_git(repository, "merge-base", baseline, ref)) != baseline:
        raise SystemExit("accepted gate baseline is not an ancestor of the audited ref")
    return baseline


def _current_kernel_identity(repository: Path, ref: str) -> dict[str, Any]:
    raw = _git_bytes(repository, ref, COMPONENT_LOCK_PATH)
    value = _canonical_json(raw, label=COMPONENT_LOCK_PATH, require_canonical=False)
    if not isinstance(value, dict):
        raise SystemExit("current component lock is not an object")
    kernel = value.get("valuation_kernel")
    if (
        not isinstance(kernel, dict)
        or kernel.get("commit") != _KERNEL["commit"]
        or kernel.get("annotated_tag_object") != _KERNEL["tag_object"]
        or kernel.get("tag") != _KERNEL["tag"]
        or kernel.get("release_evidence", {}).get("wheel_sha256")
        != _KERNEL["wheel_sha256"]
        or not isinstance(kernel.get("public_schema_sha256"), dict)
        or len(kernel["public_schema_sha256"]) != 8
        or not all(
            _safe_path(path) and _sha256(digest)
            for path, digest in kernel["public_schema_sha256"].items()
        )
    ):
        raise SystemExit("current component lock drifted from pinned rc.2")
    return value


def _validate_oracle_ast(raw: bytes) -> dict[str, Any]:
    """Parse the inert oracle as a closed literal manifest, never executable Python.

    The historical ``.py.txt`` suffix is retained for compatibility with the already-reviewed
    gate layout.  Its bytes are data: functions, imports, calls, control flow, attributes and
    every other executable surface are forbidden.
    """

    if not raw or len(raw) > _MAX_ORACLE_BYTES:
        raise SystemExit("successor semantic oracle manifest exceeds its fixed byte bound")
    try:
        source = raw.decode("utf-8")
        tree = ast.parse(source, filename="semantic-oracle.py.txt")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise SystemExit(f"successor semantic oracle is not parseable UTF-8 Python: {exc}") from exc
    if sum(1 for _ in ast.walk(tree)) > _MAX_ORACLE_AST_NODES:
        raise SystemExit("successor semantic oracle manifest exceeds its fixed AST bound")
    values: dict[str, Any] = {}
    for node in tree.body:
        if (
            not isinstance(node, ast.Assign)
            or len(node.targets) != 1
            or not isinstance(node.targets[0], ast.Name)
            or node.targets[0].id not in _ORACLE_MANIFEST_KEYS
            or node.targets[0].id in values
        ):
            raise SystemExit("successor semantic oracle is not a closed literal manifest")
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError) as exc:
            raise SystemExit(
                "successor semantic oracle contains a non-literal value"
            ) from exc
        values[node.targets[0].id] = value
    if tuple(values) != _ORACLE_MANIFEST_KEYS:
        raise SystemExit("successor semantic oracle manifest keys or order drifted")
    if (
        values["SCHEMA_VERSION"] != "1.0.0"
        or not isinstance(values["GATE_ID"], str)
        or not isinstance(values["AUDIT_PROFILE"], str)
        or not isinstance(values["ADVERSARIAL_CASE_IDS"], tuple)
        or not isinstance(values["EXPECTED_TEST_NODEIDS"], tuple)
        or not all(
            isinstance(item, str) and item
            for key in ("ADVERSARIAL_CASE_IDS", "EXPECTED_TEST_NODEIDS")
            for item in values[key]
        )
        or tuple(sorted(values["ADVERSARIAL_CASE_IDS"]))
        != values["ADVERSARIAL_CASE_IDS"]
        or tuple(sorted(values["EXPECTED_TEST_NODEIDS"]))
        != values["EXPECTED_TEST_NODEIDS"]
        or len(set(values["ADVERSARIAL_CASE_IDS"]))
        != len(values["ADVERSARIAL_CASE_IDS"])
        or len(set(values["EXPECTED_TEST_NODEIDS"]))
        != len(values["EXPECTED_TEST_NODEIDS"])
    ):
        raise SystemExit("successor semantic oracle literal manifest is malformed")
    return values


def _validate_cases(raw: bytes) -> tuple[str, ...]:
    if not raw or len(raw) > _MAX_CASE_BYTES:
        raise SystemExit("successor adversarial cases exceed their fixed byte bound")
    value = _canonical_json(raw, label="successor adversarial cases")
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "cases"}
        or value.get("schema_version") != "1.0.0"
        or not isinstance(value.get("cases"), list)
        or not value["cases"]
    ):
        raise SystemExit("successor adversarial cases have an open shape")
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
            raise SystemExit("successor adversarial case has an open shape")
        identifiers.append(item["case_id"])
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise SystemExit("successor adversarial case IDs are not unique canonical order")
    return tuple(identifiers)


def _validate_next_gate_seed(
    seed: object,
    *,
    authority: dict[str, Any],
    post_successor_closeout: dict[str, Any],
) -> dict[str, Any] | None:
    post_state = post_successor_closeout["accepted_state"]
    expected_sha = authority["next_gate_authority_sha256"]
    if seed is None:
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
        if expected_sha is not None or post_state["authorized_next"] != expected_authorization:
            raise SystemExit("post-successor state lacks its protected next authority")
        return None
    if expected_sha is None:
        raise SystemExit("candidate supplied an unpinned next-gate authority")
    try:
        validated = _validate_authority(seed)
    except RuntimeError as exc:
        raise SystemExit(f"next-gate seed is malformed: {exc}") from exc
    seed_payload = (
        json.dumps(validated, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if hashlib.sha256(seed_payload).hexdigest() != expected_sha:
        raise SystemExit("next-gate seed differs from the protected authority hash")
    expected_label = f'{validated["owner_phase"]} successor-gate bootstrap'
    current_paths = authority_governed_paths(
        authority,
        post_successor_closeout=post_successor_closeout,
    )
    next_paths = authority_governed_paths(validated)
    current_branches = {
        authority["bootstrap_branch"],
        authority["acceptance_branch"],
        authority["successor_implementation_branch"],
        authority["successor_acceptance_branch"],
        post_successor_closeout["branch"],
    }
    next_branches = {
        validated["bootstrap_branch"],
        validated["acceptance_branch"],
        validated["successor_implementation_branch"],
        validated["successor_acceptance_branch"],
    }
    refrozen_external_prefixes = True
    if authority["owner_phase"] == _EXTERNAL_TARGET_PHASE:
        released_paths = {
            path
            for path in authority["successor_implementation_diff"]
            if any(
                path == prefix or path.startswith(prefix.rstrip("/") + "/")
                for prefix in _EXTERNAL_RELEASABLE_FORBIDDEN_PREFIXES
            )
        }
        refrozen_external_prefixes = (
            _EXTERNAL_RELEASABLE_FORBIDDEN_PREFIXES.issubset(
                validated["forbidden_prefixes"]
            )
            and released_paths.issubset(validated["frozen_paths"])
        )
    if (
        validated["gate_id"] == authority["gate_id"]
        or validated["owner_phase"] == authority["owner_phase"]
        or validated["owner_phase"] != authority["next_owner_phase"]
        or current_paths & next_paths
        or current_branches & next_branches
        or post_state["authorized_next"] != [expected_label]
        or expected_label in post_state["prohibited"]
        or validated["pending_gate_state"]["authorized_next"]
        != [f'{validated["owner_phase"]} successor-gate acceptance closeout']
        or validated["audit_policy"]["predecessor_test_count"]
        != post_successor_closeout["expected_test_count"]
        or validated["audit_policy"]["predecessor_nodeid_sha256"]
        != post_successor_closeout["expected_nodeid_sha256"]
        or not (
            {*authority["frozen_paths"], *current_paths}
            <= set(validated["frozen_paths"])
        )
        or not set(authority["forbidden_prefixes"]).issubset(
            validated["forbidden_prefixes"]
        )
        or not refrozen_external_prefixes
    ):
        raise SystemExit("next-gate seed reuses authority or self-authorizes production")
    return validated


def _validate_external_authority_seed(
    seed: object,
    *,
    authority: dict[str, Any],
    post_successor_closeout: dict[str, Any],
) -> dict[str, Any]:
    """Validate the Controller-approved 2C-0 seed without candidate self-authorization."""

    if (
        authority["next_owner_phase"] != _EXTERNAL_FEASIBILITY_PHASE
        or authority["next_gate_authority_sha256"] is not None
        or _PHASE_SUCCESSOR.get(_EXTERNAL_FEASIBILITY_PHASE) != _EXTERNAL_TARGET_PHASE
    ):
        raise SystemExit("external feasibility handoff is not at the protected boundary")
    try:
        validated = _validate_authority(seed)
    except RuntimeError as exc:
        raise SystemExit(f"external 2C-0 authority seed is malformed: {exc}") from exc
    if (
        validated["gate_id"] != "phase5e2c0"
        or validated["owner_phase"] != _EXTERNAL_TARGET_PHASE
        or validated["next_owner_phase"] != _PHASE_SUCCESSOR[_EXTERNAL_TARGET_PHASE]
        or validated["next_gate_authority_sha256"] is not None
        or validated["bundle_directory"] != _EXTERNAL_GATE_DIRECTORY
        or validated["audit_policy"]["protected_oracle_path"]
        != _EXTERNAL_PROTECTED_ORACLE_PATH
        or validated["audit_policy"]["protected_oracle_sha256"]
        != _EXTERNAL_PROTECTED_ORACLE_SHA256
        or validated["successor_implementation_diff"]
        != _EXTERNAL_2C0_IMPLEMENTATION_DIFF
        or validated["audit_policy"]["predecessor_test_count"]
        != post_successor_closeout["expected_test_count"]
        or validated["audit_policy"]["predecessor_nodeid_sha256"]
        != post_successor_closeout["expected_nodeid_sha256"]
    ):
        raise SystemExit("external handoff does not install the exact immediate 2C-0 gate")

    current_paths = authority_governed_paths(
        authority,
        post_successor_closeout=post_successor_closeout,
    )
    next_paths = authority_governed_paths(validated)
    current_branches = {
        authority["bootstrap_branch"],
        authority["acceptance_branch"],
        authority["successor_implementation_branch"],
        authority["successor_acceptance_branch"],
        post_successor_closeout["branch"],
    }
    next_branches = {
        validated["bootstrap_branch"],
        validated["acceptance_branch"],
        validated["successor_implementation_branch"],
        validated["successor_acceptance_branch"],
    }
    released_frozen = set(authority["frozen_paths"]) - set(validated["frozen_paths"])
    released_prefixes = set(authority["forbidden_prefixes"]) - set(
        validated["forbidden_prefixes"]
    )
    successor_paths = set(validated["successor_implementation_diff"])
    required_frozen = (
        set(authority["frozen_paths"])
        - _EXTERNAL_RELEASABLE_FROZEN_PATHS
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
        validated["gate_id"] == authority["gate_id"]
        or validated["bootstrap_branch"] != _EXTERNAL_CONTROLLER_BRANCH
        or current_paths & next_paths
        or current_branches & next_branches
        or not required_frozen.issubset(validated["frozen_paths"])
        or not released_frozen.issubset(_EXTERNAL_RELEASABLE_FROZEN_PATHS)
        or not released_frozen.issubset(successor_paths)
        or not released_prefixes.issubset(_EXTERNAL_RELEASABLE_FORBIDDEN_PREFIXES)
        or (released_prefixes and not released_prefix_paths)
        or not released_prefix_paths.issubset(_EXTERNAL_RELEASE_PATH_ALLOWLIST)
        or any(
            prefix in validated["forbidden_prefixes"]
            for prefix in released_prefixes
        )
        or not _CONTROL_PLANE_FORBIDDEN_PREFIXES.issubset(
            validated["forbidden_prefixes"]
        )
        or any(
            path in _EXTERNAL_RELEASABLE_FROZEN_PATHS
            and path not in validated["frozen_paths"]
            and path not in successor_paths
            for path in authority["frozen_paths"]
        )
    ):
        raise SystemExit("external 2C-0 seed releases or reuses unreviewed authority")
    return validated


def _external_handoff_seed(
    repository: Path,
    ref: str,
    *,
    authority: dict[str, Any],
    bundle: dict[str, Any],
) -> dict[str, Any] | None:
    """Return one fully bound Controller handoff seed, or ``None`` before feasibility."""

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
    handoff_raw = _git_bytes(repository, ref, _EXTERNAL_HANDOFF_PATH)
    if not handoff_raw or len(handoff_raw) > _MAX_EXTERNAL_HANDOFF_BYTES:
        raise SystemExit("external feasibility Controller handoff exceeds its byte bound")
    handoff = _canonical_json(
        handoff_raw,
        label=_EXTERNAL_HANDOFF_PATH,
        require_canonical=True,
    )
    if not isinstance(handoff, dict) or set(handoff) != _EXTERNAL_HANDOFF_KEYS:
        raise SystemExit("external feasibility Controller handoff has an open shape")
    predecessor = handoff.get("predecessor_commit")
    predecessor_tree = handoff.get("predecessor_tree")
    predecessor_fingerprint = handoff.get("predecessor_state_fingerprint")
    approved_at = handoff.get("approved_at")
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
        or not _sha256(predecessor_fingerprint)
        or _utc_timestamp(approved_at) is None
        or not _sha256(handoff.get("challenge_nonce"))
        or handoff.get("policy_path") != _FUTU_POLICY_PATH
        or handoff.get("policy_sha256") != _FUTU_POLICY_SHA256
        or handoff.get("policy_overlay_path") != _FUTU_OVERLAY_PATH
        or handoff.get("policy_overlay_sha256") != _FUTU_OVERLAY_SHA256
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
        raise SystemExit("external feasibility Controller handoff identity is malformed")
    if (
        str(_git(repository, "cat-file", "-t", predecessor)) != "commit"
        or _tree(repository, predecessor) != predecessor_tree
        or str(_git(repository, "merge-base", predecessor, ref)) != predecessor
    ):
        raise SystemExit("external feasibility predecessor commit is not immutable ancestry")
    predecessor_status = _git_json(repository, predecessor, STATUS_PATH)
    if (
        _status_without_history(predecessor_status)
        != bundle["post_successor_closeout"]["accepted_state"]
        or _canonical_payload_sha256(predecessor_status) != predecessor_fingerprint
    ):
        raise SystemExit("external feasibility predecessor state fingerprint drifted")
    seed = _validate_external_authority_seed(
        handoff.get("authority_seed"),
        authority=authority,
        post_successor_closeout=bundle["post_successor_closeout"],
    )
    authority_seed_sha256 = _canonical_payload_sha256(seed)
    if handoff.get("authority_seed_sha256") != authority_seed_sha256:
        raise SystemExit("external feasibility authority seed hash drifted")
    component_lock_sha256 = hashlib.sha256(
        _git_bytes(repository, predecessor, COMPONENT_LOCK_PATH)
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
            "authority_seed_sha256": authority_seed_sha256,
            "policy_sha256": _FUTU_POLICY_SHA256,
            "challenge_nonce": handoff["challenge_nonce"],
        },
        approved_at=approved_at,
    )
    if handoff.get("receipt_set_sha256") != _canonical_payload_sha256(list(receipts)):
        raise SystemExit("external feasibility signed receipt set hash drifted")
    successor_diff = seed["successor_implementation_diff"]
    released_prefixes = set(authority["forbidden_prefixes"]) - set(
        seed["forbidden_prefixes"]
    )
    for prefix in released_prefixes:
        tracked = _tracked_paths(repository, predecessor, prefix)
        mutable = {
            path
            for path in successor_diff
            if path == prefix or path.startswith(prefix.rstrip("/") + "/")
        }
        if (
            not (tracked - mutable).issubset(seed["frozen_paths"])
            or not mutable.issubset(_EXTERNAL_RELEASE_PATH_ALLOWLIST)
            or any(
                successor_diff[path] != ("M" if path in tracked else "A")
                for path in mutable
            )
        ):
            raise SystemExit("external seed does not freeze the unmodified released prefix")

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
        raise SystemExit("external Controller handoff introduction is missing or ambiguous")
    introduction = additions[0]
    if (
        _parents(repository, introduction) != (predecessor,)
        or _changed_diff(repository, predecessor, introduction) != _EXTERNAL_CONTROLLER_DIFF
        or _status_without_history(_git_json(repository, introduction, STATUS_PATH))
        != seed["pending_gate_state"]
    ):
        raise SystemExit("external Controller handoff is not one exact direct transition")
    for path in _EXTERNAL_CONTROLLER_DIFF:
        if path == STATUS_PATH:
            continue
        if (
            _file_mode(repository, introduction, path) != "100644"
            or _git_bytes(repository, introduction, path)
            != _git_bytes(repository, ref, path)
        ):
            raise SystemExit("external Controller handoff evidence drifted after introduction")
    if (
        not _exists(repository, predecessor, _EXTERNAL_PROTECTED_ORACLE_PATH)
        or _file_mode(repository, predecessor, _EXTERNAL_PROTECTED_ORACLE_PATH)
        != "100644"
        or hashlib.sha256(
            _git_bytes(repository, predecessor, _EXTERNAL_PROTECTED_ORACLE_PATH)
        ).hexdigest()
        != _EXTERNAL_PROTECTED_ORACLE_SHA256
        or _git_bytes(repository, ref, _EXTERNAL_PROTECTED_ORACLE_PATH)
        != _git_bytes(repository, predecessor, _EXTERNAL_PROTECTED_ORACLE_PATH)
    ):
        raise SystemExit("protected-base 2C-0 oracle is missing, drifted, or candidate-installed")
    seed_bundle = validate_bundle(repository, ref, authority=seed)
    if seed_bundle["predecessor_state_fingerprint"] != predecessor_fingerprint:
        raise SystemExit("external 2C-0 bundle is not bound to the feasibility predecessor")
    return seed


def validate_bundle(
    repository: Path,
    ref: str,
    *,
    authority: dict[str, Any] | None = None,
) -> dict[str, Any]:
    authority = bootstrap_authority() if authority is None else authority
    paths = bundle_paths(authority)
    bundle_raw = _git_bytes(repository, ref, paths["bundle"])
    if not bundle_raw or len(bundle_raw) > _MAX_BUNDLE_BYTES:
        raise SystemExit("successor gate bundle exceeds its fixed byte bound")
    bundle = _canonical_json(bundle_raw, label="successor gate bundle")
    # The pull_request_target structure job intentionally has no candidate-controlled dependency
    # installation.  This protected verifier therefore implements the same closed shape with the
    # standard library rather than importing jsonschema in the authority process.  The repository
    # verification suite separately validates the Draft 2020-12 documentation Schema.
    if not isinstance(bundle, dict) or set(bundle) != _BUNDLE_KEYS:
        raise SystemExit("successor gate bundle has an open shape")
    if (
        bundle.get("schema_version") != "2.0.0"
        or bundle.get("gate_id") != authority["gate_id"]
        or bundle.get("owner_phase") != authority["owner_phase"]
        or not _sha256(bundle.get("predecessor_state_fingerprint"))
        or bundle.get("gate_bootstrap_branch") != authority["bootstrap_branch"]
        or bundle.get("gate_acceptance_branch") != authority["acceptance_branch"]
        or any(
            bundle.get(key) != authority[key]
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
        or bundle.get("execution_mode") != "protected_base_only_after_gate_acceptance"
        or bundle.get("successor_production_authorized_by_bundle") is not False
        or bundle.get("public_schema_count") != 43
        or not _sha256(bundle.get("public_schema_set_sha256"))
        or not _sha256(bundle.get("component_lock_sha256"))
    ):
        raise SystemExit("successor gate bundle violates its closed identity policy")
    if (
        bundle.get("successor_implementation_branch")
        != authority["successor_implementation_branch"]
        or bundle.get("successor_acceptance_branch")
        != authority["successor_acceptance_branch"]
    ):
        raise SystemExit("successor gate bundle attempts to choose its own bootstrap authority")
    audit = bundle.get("audit")
    audit_policy = authority["audit_policy"]
    implementation_test_paths = sorted(
        path
        for path, disposition in authority["successor_implementation_diff"].items()
        if disposition == "A" and path.startswith("tests/test_") and path.endswith(".py")
    )
    if (
        not isinstance(audit, dict)
        or set(audit) != _AUDIT_KEYS
        or audit.get("profile_id") != audit_policy["profile_id"]
        or audit.get("audit_version") != audit_policy["audit_version"]
        or audit.get("protected_oracle_path")
        != audit_policy["protected_oracle_path"]
        or audit.get("protected_oracle_sha256")
        != audit_policy["protected_oracle_sha256"]
        or audit.get("predecessor_test_count")
        != audit_policy["predecessor_test_count"]
        or audit.get("predecessor_nodeid_sha256")
        != audit_policy["predecessor_nodeid_sha256"]
        or audit.get("expected_added_test_nodeids")
        != audit_policy["expected_added_test_nodeids"]
        or not implementation_test_paths
        or not all(
            isinstance(nodeid, str)
            and any(nodeid.startswith(path + "::") for path in implementation_test_paths)
            for nodeid in audit["expected_added_test_nodeids"]
        )
        or audit.get("expected_check_ids") != audit_policy["mandatory_check_ids"]
    ):
        raise SystemExit("successor gate audit profile is malformed")
    post_successor_closeout = bundle.get("post_successor_closeout")
    expected_test_count = int(audit_policy["predecessor_test_count"]) + len(
        audit_policy["expected_added_test_nodeids"]
    )
    if not _valid_post_successor_closeout(
        post_successor_closeout,
        expected_test_count=expected_test_count,
    ) or (
        post_successor_closeout["implementation_audit_profile"]
        != audit_policy["profile_id"]
        or post_successor_closeout["implementation_audit_version"]
        != audit_policy["audit_version"]
        or post_successor_closeout["transition_audit_profile"]
        == audit_policy["profile_id"]
    ):
        raise SystemExit("successor post-closeout authority is malformed")
    next_seed = _validate_next_gate_seed(
        bundle.get("next_gate_seed"),
        authority=authority,
        post_successor_closeout=post_successor_closeout,
    )
    post_state = post_successor_closeout["accepted_state"]
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
            authority["next_owner_phase"] is not None
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
        raise SystemExit("successor post-closeout machine-state semantics are malformed")
    oracle_manifest: dict[str, Any] | None = None
    adversarial_case_ids: tuple[str, ...] | None = None
    for key, expected_path in (
        ("semantic_oracle", paths["oracle"]),
        ("adversarial_cases", paths["cases"]),
    ):
        value = bundle.get(key)
        if (
            not isinstance(value, dict)
            or set(value) != _HASHED_PATH_KEYS
            or value.get("path") != expected_path
            or not _sha256(value.get("sha256"))
        ):
            raise SystemExit(f"successor gate {key} binding is malformed")
        raw = _git_bytes(repository, ref, expected_path)
        if hashlib.sha256(raw).hexdigest() != value["sha256"]:
            raise SystemExit(f"successor gate {key} hash drifted")
        if _file_mode(repository, ref, expected_path) != "100644":
            raise SystemExit(f"successor gate {key} is not a regular 100644 file")
        if key == "semantic_oracle":
            oracle_manifest = _validate_oracle_ast(raw)
        else:
            adversarial_case_ids = _validate_cases(raw)
    if (
        oracle_manifest is None
        or adversarial_case_ids is None
        or oracle_manifest["GATE_ID"] != authority["gate_id"]
        or oracle_manifest["AUDIT_PROFILE"] != audit_policy["profile_id"]
        or oracle_manifest["ADVERSARIAL_CASE_IDS"] != adversarial_case_ids
        or oracle_manifest["EXPECTED_TEST_NODEIDS"]
        != tuple(audit_policy["expected_added_test_nodeids"])
    ):
        raise SystemExit("successor semantic oracle manifest is not bound to gate evidence")
    frozen = authority["frozen_paths"]
    forbidden = authority["forbidden_prefixes"]
    if (
        not isinstance(frozen, list)
        or frozen != sorted(frozen)
        or len(frozen) != len(set(frozen))
        or not all(_safe_path(path) for path in frozen)
        or not isinstance(forbidden, list)
        or forbidden != sorted(forbidden)
        or len(forbidden) != len(set(forbidden))
        or not all(_safe_path(path) for path in forbidden)
    ):
        raise SystemExit("successor gate frozen/forbidden path policy is malformed")
    controlled_paths = set(authority["successor_implementation_diff"]) | set(
        authority["successor_acceptance_diff"]
    ) | set(post_successor_closeout["diff"])
    if controlled_paths & set(frozen) or any(
        path == prefix or path.startswith(prefix.rstrip("/") + "/")
        for path in controlled_paths
        for prefix in forbidden
    ):
        raise SystemExit("successor gate attempts to authorize a frozen or forbidden path")
    baseline_ref = _gate_baseline_ref(repository, ref, authority=authority)
    if baseline_ref != ref:
        for governed_path in (paths["bundle"], paths["oracle"], paths["cases"]):
            if (
                _file_mode(repository, baseline_ref, governed_path) != "100644"
                or _git_bytes(repository, baseline_ref, governed_path)
                != _git_bytes(repository, ref, governed_path)
            ):
                raise SystemExit("accepted successor-gate evidence drifted after bootstrap")
    component_raw = _git_bytes(repository, baseline_ref, COMPONENT_LOCK_PATH)
    component = _canonical_json(
        component_raw,
        label=COMPONENT_LOCK_PATH,
        require_canonical=False,
    )
    schema_count, schema_set_sha = _schema_set_sha256(repository, baseline_ref)
    current_schema_count, _ = _schema_set_sha256(repository, ref)
    current_component = _current_kernel_identity(repository, ref)
    kernel = bundle.get("kernel_release")
    if (
        hashlib.sha256(component_raw).hexdigest() != bundle["component_lock_sha256"]
        or schema_count != 43
        or current_schema_count != 43
        or schema_set_sha != bundle["public_schema_set_sha256"]
        or not isinstance(kernel, dict)
        or set(kernel) != {*_KERNEL, "schema_sha256"}
        or any(kernel.get(key) != value for key, value in _KERNEL.items())
        or not isinstance(kernel.get("schema_sha256"), dict)
        or len(kernel["schema_sha256"]) != 8
        or not all(
            _safe_path(path) and _sha256(digest)
            for path, digest in kernel["schema_sha256"].items()
        )
        or not isinstance(component, dict)
        or component.get("valuation_kernel", {}).get("commit") != _KERNEL["commit"]
        or component.get("valuation_kernel", {}).get("annotated_tag_object")
        != _KERNEL["tag_object"]
        or component.get("valuation_kernel", {}).get("tag") != _KERNEL["tag"]
        or component.get("valuation_kernel", {}).get("release_evidence", {}).get("wheel_sha256")
        != _KERNEL["wheel_sha256"]
        or component.get("valuation_kernel", {}).get("public_schema_sha256")
        != kernel["schema_sha256"]
        or current_component.get("valuation_kernel", {}).get("public_schema_sha256")
        != kernel["schema_sha256"]
    ):
        raise SystemExit("successor gate component, public Schema, or kernel identity drifted")
    return bundle


def _event_branch(event: dict[str, Any], *, repository_slug: str, base: str, head: str) -> str:
    pull = event.get("pull_request", {})
    if (
        not _GIT_OID.fullmatch(base)
        or not _GIT_OID.fullmatch(head)
        or event.get("repository", {}).get("full_name") != repository_slug
        or pull.get("base", {}).get("ref") != "main"
        or pull.get("base", {}).get("sha") != base
        or pull.get("base", {}).get("repo", {}).get("full_name") != repository_slug
        or pull.get("head", {}).get("sha") != head
        or pull.get("head", {}).get("repo", {}).get("full_name") != repository_slug
        or not isinstance(pull.get("head", {}).get("ref"), str)
        or type(event.get("number")) is not int
        or event["number"] <= 0
    ):
        raise SystemExit("successor-gate GitHub event identity is invalid")
    return str(pull["head"]["ref"])


def _status_without_history(value: dict[str, Any]) -> dict[str, Any]:
    return {key: value.get(key) for key in _STATE_KEYS}


def _expected_status(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    expected = copy.deepcopy(base)
    expected.update(copy.deepcopy(patch))
    return expected


def _assert_linear_candidate(repository: Path, *, base: str, head: str) -> None:
    if not _GIT_OID.fullmatch(base) or not _GIT_OID.fullmatch(head):
        raise SystemExit("successor transition requires full 40-hex commit identities")
    for ref in (base, head):
        if str(_git(repository, "cat-file", "-t", ref)) != "commit":
            raise SystemExit("successor transition identity is not a commit")
    if str(_git(repository, "merge-base", base, head)) != base:
        raise SystemExit("successor transition is not based on current main")


def _parents(repository: Path, ref: str) -> tuple[str, ...]:
    raw = str(_git(repository, "show", "-s", "--format=%P", ref))
    parents = tuple(raw.split()) if raw else ()
    if any(not _GIT_OID.fullmatch(parent) for parent in parents):
        raise SystemExit("successor transition has a malformed parent identity")
    return parents


def _tree(repository: Path, ref: str) -> str:
    value = str(_git(repository, "rev-parse", f"{ref}^{{tree}}"))
    if not _GIT_OID.fullmatch(value):
        raise SystemExit("successor transition tree identity is malformed")
    return value


def _canonical_positive_id(value: object) -> bool:
    return type(value) is int and value > 0


def _canonical_run_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.isascii()
        and value.isdigit()
        and value != "0"
        and str(int(value)) == value
    )


def _closeout_shape(
    value: object,
    *,
    gate_id: str,
    audit_profile: str,
    audit_version: str,
    implementation_merge: str | None = None,
    implementation_head: str | None = None,
    implementation_tree: str | None = None,
    acceptance_number: int | None = None,
    expected_test_count: int | None = None,
) -> bool:
    required = {
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
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0.0"
        or value.get("gate_id") != gate_id
        or not _canonical_positive_id(value.get("implementation_pull_request"))
        or not _canonical_positive_id(value.get("acceptance_pull_request"))
        or not _GIT_OID.fullmatch(str(value.get("implementation_head_commit")))
        or not _GIT_OID.fullmatch(str(value.get("implementation_merge_commit")))
        or not _GIT_OID.fullmatch(str(value.get("implementation_tree_sha")))
        or not all(
            _canonical_run_id(value.get(key))
            for key in ("pr_ci_run_id", "main_ci_run_id")
        )
        or not _canonical_positive_id(value.get("audit_workflow_id"))
        or value.get("audit_tool") != "owner-research-phase5e-readonly"
        or value.get("audit_profile") != audit_profile
        or value.get("audit_version") != audit_version
        or not all(
            _sha256(value.get(key))
            for key in (
                "audit_report_sha256",
                "audit_artifact_sha256",
                "test_inventory_sha256",
                "runtime_matrix_sha256",
                "audit_wheelhouse_manifest_sha256",
            )
        )
        or not _canonical_positive_id(value.get("controller_app_id"))
        or not isinstance(value.get("controller_app_slug"), str)
        or _CHECK_ID.fullmatch(value["controller_app_slug"]) is None
        or not _canonical_positive_id(value.get("controller_installation_id"))
        or value.get("finding_counts") != {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
        or not _canonical_positive_id(value.get("test_count"))
    ):
        return False
    return not (
        (
            implementation_merge is not None
            and value["implementation_merge_commit"] != implementation_merge
        )
        or (
            implementation_head is not None
            and value["implementation_head_commit"] != implementation_head
        )
        or (
            implementation_tree is not None
            and value["implementation_tree_sha"] != implementation_tree
        )
        or (
            acceptance_number is not None
            and value["acceptance_pull_request"] != acceptance_number
        )
        or (
            expected_test_count is not None
            and value["test_count"] != expected_test_count
        )
    )


def _verify_acceptance_structure(
    *,
    repository: Path,
    base: str,
    head: str,
    event: dict[str, Any],
    repository_slug: str,
    branch: str,
    closeout_path: str,
    expected_diff: dict[str, str],
    expected_status_patch: dict[str, Any],
    gate_id: str,
    audit_profile: str,
    audit_version: str,
    expected_test_count: int,
) -> tuple[str, str, dict[str, Any]]:
    _assert_linear_candidate(repository, base=base, head=head)
    if _event_branch(
        event,
        repository_slug=repository_slug,
        base=base,
        head=head,
    ) != branch:
        raise SystemExit("successor acceptance branch is not the protected authority")
    merge_parents = _parents(repository, base)
    if len(merge_parents) != 2:
        raise SystemExit("successor implementation base is not a two-parent PR merge")
    implementation_base, implementation_head = merge_parents
    if _tree(repository, base) != _tree(repository, implementation_head):
        raise SystemExit("successor implementation merge tree differs from its PR head")
    if _parents(repository, head) != (base,):
        raise SystemExit("successor acceptance must be one direct non-merge commit")
    if _changed_diff(repository, base, head) != expected_diff:
        raise SystemExit("successor acceptance diff is not acceptance-only")
    base_status = _git_json(repository, base, STATUS_PATH)
    candidate_status = _git_json(repository, head, STATUS_PATH)
    if candidate_status != _expected_status(base_status, expected_status_patch):
        raise SystemExit("successor acceptance modified immutable phase history")
    closeout = _git_json(repository, head, closeout_path)
    if _file_mode(repository, head, closeout_path) != "100644" or not _closeout_shape(
        closeout,
        gate_id=gate_id,
        audit_profile=audit_profile,
        audit_version=audit_version,
        implementation_merge=base,
        implementation_head=implementation_head,
        implementation_tree=_tree(repository, base),
        acceptance_number=int(event["number"]),
        expected_test_count=expected_test_count,
    ):
        raise SystemExit("successor acceptance closeout is not closed typed evidence")
    return implementation_base, implementation_head, closeout


def verify_bootstrap_transition(
    *, repository: Path, base: str, head: str, event: dict[str, Any], repository_slug: str
) -> None:
    position = resolve_gate_position(repository, base)
    if position.stage == "s3":
        authority = position.authority
    elif position.stage == "g5" and position.bundle is not None:
        authority = _validate_next_gate_seed(
            position.bundle.get("next_gate_seed"),
            authority=position.authority,
            post_successor_closeout=position.bundle["post_successor_closeout"],
        )
        if authority is None:
            raise SystemExit("accepted successor has no next-gate seed")
    else:
        raise SystemExit("successor-gate bootstrap base is not an accepted predecessor")
    paths = bundle_paths(authority)
    _assert_linear_candidate(repository, base=base, head=head)
    branch = _event_branch(event, repository_slug=repository_slug, base=base, head=head)
    if branch != authority["bootstrap_branch"]:
        raise SystemExit("successor-gate bootstrap branch is not the preinstalled authority")
    bundle = validate_bundle(repository, head, authority=authority)
    if _changed_diff(repository, base, head) != authority["gate_bootstrap_diff"]:
        raise SystemExit("successor-gate bootstrap diff escaped its exact inert-data boundary")
    predecessor = _git_json(repository, base, STATUS_PATH)
    if hashlib.sha256(
        (json.dumps(predecessor, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest() != bundle["predecessor_state_fingerprint"]:
        raise SystemExit("successor-gate predecessor state fingerprint drifted")
    candidate = _git_json(repository, head, STATUS_PATH)
    if candidate != _expected_status(predecessor, authority["pending_gate_state"]):
        raise SystemExit("successor-gate pending machine state is not the bundle state")
    for path in (paths["bundle"], paths["oracle"], paths["cases"]):
        if _file_mode(repository, head, path) != "100644":
            raise SystemExit("successor-gate bootstrap contains a non-regular file")


def verify_external_controller_handoff_transition(
    *, repository: Path, base: str, head: str, event: dict[str, Any], repository_slug: str
) -> None:
    """Install the first post-feasibility 2C-0 gate through one Controller-only diff."""

    position = resolve_gate_position(repository, base)
    if (
        position.stage != "g5"
        or position.bundle is None
        or position.authority["next_owner_phase"] != _EXTERNAL_FEASIBILITY_PHASE
        or position.bundle.get("next_gate_seed") is not None
    ):
        raise SystemExit("external Controller handoff base is not the protected G5 boundary")
    _assert_linear_candidate(repository, base=base, head=head)
    if (
        _event_branch(
            event,
            repository_slug=repository_slug,
            base=base,
            head=head,
        )
        != _EXTERNAL_CONTROLLER_BRANCH
    ):
        raise SystemExit("external Controller handoff branch is not the reserved authority")
    if _changed_diff(repository, base, head) != _EXTERNAL_CONTROLLER_DIFF:
        raise SystemExit("external Controller handoff escaped its fixed control-plane diff")
    seed = _external_handoff_seed(
        repository,
        head,
        authority=position.authority,
        bundle=position.bundle,
    )
    if seed is None:
        raise SystemExit("external Controller handoff did not install a validated 2C-0 seed")
    handoff = _git_json(repository, head, _EXTERNAL_HANDOFF_PATH)
    if (
        handoff.get("predecessor_commit") != base
        or _parents(repository, head) != (base,)
        or str(
            _git(
                repository,
                "log",
                "--format=%H",
                "--diff-filter=A",
                f"{base}..{head}",
                "--",
                _EXTERNAL_HANDOFF_PATH,
            )
        )
        != head
    ):
        raise SystemExit("external Controller handoff is not the unique direct candidate commit")
    if _git_json(repository, head, STATUS_PATH) != _expected_status(
        _git_json(repository, base, STATUS_PATH),
        seed["pending_gate_state"],
    ):
        raise SystemExit("external Controller handoff did not install the 2C-0 pending state")
    candidate_position = resolve_gate_position(repository, head)
    if (
        candidate_position.stage != "g1"
        or candidate_position.depth != position.depth + 1
        or candidate_position.gate_id != seed["gate_id"]
    ):
        raise SystemExit("external Controller handoff did not advance exactly to 2C-0 G1")


def verify_acceptance_transition(
    *,
    repository: Path,
    base: str,
    head: str,
    event: dict[str, Any],
    repository_slug: str,
    require_remote: bool = False,
    remote_verifier: RemoteEvidenceVerifier | None = None,
) -> None:
    position = resolve_gate_position(repository, base)
    authority = position.authority
    bundle = validate_bundle(repository, base, authority=authority)
    if position.stage != "g1":
        raise SystemExit("successor-gate acceptance base is not pending acceptance")
    implementation_base, implementation_head, closeout = _verify_acceptance_structure(
        repository=repository,
        base=base,
        head=head,
        event=event,
        repository_slug=repository_slug,
        branch=authority["acceptance_branch"],
        closeout_path=authority["closeout_path"],
        expected_diff=authority["gate_acceptance_diff"],
        expected_status_patch=authority["accepted_gate_state"],
        gate_id=authority["gate_id"],
        audit_profile="phase5e-successor-gate-bootstrap",
        audit_version="2.3.2.3.4.1",
        expected_test_count=int(bundle["audit"]["predecessor_test_count"]),
    )
    if not require_remote or remote_verifier is None:
        raise SystemExit("successor-gate acceptance requires protected remote evidence replay")
    remote_verifier(
        transition="gate_acceptance",
        repository=repository,
        repository_slug=repository_slug,
        implementation_base=implementation_base,
        implementation_merge=base,
        implementation_head=implementation_head,
        closeout=closeout,
        bundle=bundle,
    )


def verify_successor_implementation(
    *, repository: Path, base: str, head: str, event: dict[str, Any], repository_slug: str
) -> None:
    position = resolve_gate_position(repository, base)
    authority = position.authority
    _assert_linear_candidate(repository, base=base, head=head)
    if position.stage != "g2":
        raise SystemExit("successor implementation base is not an accepted gate")
    branch = _event_branch(event, repository_slug=repository_slug, base=base, head=head)
    validate_bundle(repository, base, authority=authority)
    if branch != authority["successor_implementation_branch"]:
        raise SystemExit("successor implementation branch is not the accepted bundle authority")
    if _changed_diff(repository, base, head) != authority["successor_implementation_diff"]:
        raise SystemExit("successor implementation diff escaped the accepted bundle")
    base_status = _git_json(repository, base, STATUS_PATH)
    candidate = _git_json(repository, head, STATUS_PATH)
    if candidate != _expected_status(base_status, authority["successor_pending_state"]):
        raise SystemExit("successor pending machine state is not the accepted bundle state")
    paths = bundle_paths(authority)
    for path in (
        *authority["frozen_paths"],
        paths["bundle"],
        paths["oracle"],
        paths["cases"],
        paths["closeout"],
    ):
        if _git_bytes(repository, base, path) != _git_bytes(repository, head, path):
            raise SystemExit("successor candidate modified an accepted gate trust root")


def verify_successor_acceptance_transition(
    *,
    repository: Path,
    base: str,
    head: str,
    event: dict[str, Any],
    repository_slug: str,
    require_remote: bool = False,
    remote_verifier: RemoteEvidenceVerifier | None = None,
) -> None:
    position = resolve_gate_position(repository, base)
    authority = position.authority
    bundle = validate_bundle(repository, base, authority=authority)
    if position.stage != "g3":
        raise SystemExit("successor acceptance base is not pending acceptance")
    implementation_base, implementation_head, closeout = _verify_acceptance_structure(
        repository=repository,
        base=base,
        head=head,
        event=event,
        repository_slug=repository_slug,
        branch=authority["successor_acceptance_branch"],
        closeout_path=authority["successor_closeout_path"],
        expected_diff=authority["successor_acceptance_diff"],
        expected_status_patch=authority["successor_accepted_state"],
        gate_id=authority["gate_id"],
        audit_profile=bundle["audit"]["profile_id"],
        audit_version=bundle["audit"]["audit_version"],
        expected_test_count=(
            int(bundle["audit"]["predecessor_test_count"])
            + len(bundle["audit"]["expected_added_test_nodeids"])
        ),
    )
    if not require_remote or remote_verifier is None:
        raise SystemExit("successor acceptance requires protected remote evidence replay")
    remote_verifier(
        transition="successor_acceptance",
        repository=repository,
        repository_slug=repository_slug,
        implementation_base=implementation_base,
        implementation_merge=base,
        implementation_head=implementation_head,
        closeout=closeout,
        bundle=bundle,
    )


def verify_post_successor_closeout_transition(
    *,
    repository: Path,
    base: str,
    head: str,
    event: dict[str, Any],
    repository_slug: str,
    require_remote: bool = False,
    remote_verifier: RemoteEvidenceVerifier | None = None,
) -> None:
    position = resolve_gate_position(repository, base)
    if position.stage != "g4" or position.bundle is None:
        raise SystemExit("post-successor closeout base is not an accepted successor")
    authority = position.authority
    bundle = position.bundle
    post = bundle["post_successor_closeout"]
    implementation_base, implementation_head, closeout = _verify_acceptance_structure(
        repository=repository,
        base=base,
        head=head,
        event=event,
        repository_slug=repository_slug,
        branch=post["branch"],
        closeout_path=post["closeout_path"],
        expected_diff=post["diff"],
        expected_status_patch=post["accepted_state"],
        gate_id=authority["gate_id"],
        audit_profile=post["implementation_audit_profile"],
        audit_version=post["implementation_audit_version"],
        expected_test_count=post["expected_test_count"],
    )
    if not require_remote or remote_verifier is None:
        raise SystemExit("post-successor closeout requires protected remote evidence replay")
    remote_verifier(
        transition="post_successor_closeout",
        repository=repository,
        repository_slug=repository_slug,
        implementation_base=implementation_base,
        implementation_merge=base,
        implementation_head=implementation_head,
        closeout=closeout,
        bundle=bundle,
    )


def _authority_stage(
    repository: Path,
    ref: str,
    *,
    authority: dict[str, Any],
    allow_root_predecessor: bool,
) -> tuple[str, dict[str, Any] | None]:
    paths = bundle_paths(authority)
    status = _git_json(repository, ref, STATUS_PATH)
    has_bundle = _exists(repository, ref, paths["bundle"])
    has_closeout = _exists(repository, ref, paths["closeout"])
    has_successor_closeout = _exists(repository, ref, paths["successor_closeout"])
    implementation_markers = [
        path
        for path, disposition in authority["successor_implementation_diff"].items()
        if disposition == "A" and path != STATUS_PATH
    ]
    has_implementation = bool(implementation_markers) and all(
        _exists(repository, ref, path) for path in implementation_markers
    )
    if any(_exists(repository, ref, path) for path in implementation_markers) != has_implementation:
        return "invalid", None
    predecessor_patch = _load_trust().get("states", {}).get("s3", {}).get("status_patch")
    if (
        not has_bundle
        and not has_closeout
        and not has_implementation
        and not has_successor_closeout
    ):
        return (
            (
                "s3"
                if allow_root_predecessor
                and isinstance(predecessor_patch, dict)
                and _status_without_history(status) == predecessor_patch
                else "absent"
            ),
            None,
        )
    if not has_bundle:
        return "invalid", None
    bundle = validate_bundle(repository, ref, authority=authority)
    post_path = bundle["post_successor_closeout"]["closeout_path"]
    has_post_closeout = _exists(repository, ref, post_path)
    if has_bundle and not has_closeout:
        return (
            (
                "g1"
                if not has_implementation
                and not has_successor_closeout
                and not has_post_closeout
                and _status_without_history(status) == authority["pending_gate_state"]
                else "invalid"
            ),
            bundle,
        )
    if has_bundle and has_closeout and not has_implementation and not has_successor_closeout:
        return (
            (
                "g2"
                if not has_post_closeout
                and _closeout_shape(
                    _git_json(repository, ref, paths["closeout"]),
                    gate_id=authority["gate_id"],
                    audit_profile="phase5e-successor-gate-bootstrap",
                    audit_version="2.3.2.3.4.1",
                    expected_test_count=int(bundle["audit"]["predecessor_test_count"]),
                )
                and _status_without_history(status) == authority["accepted_gate_state"]
                else "invalid"
            ),
            bundle,
        )
    if has_bundle and has_closeout and has_implementation and not has_successor_closeout:
        return (
            (
                "g3"
                if not has_post_closeout
                and _status_without_history(status) == authority["successor_pending_state"]
                else "invalid"
            ),
            bundle,
        )
    if has_bundle and has_closeout and has_implementation and has_successor_closeout:
        successor_shape = _closeout_shape(
            _git_json(repository, ref, paths["successor_closeout"]),
            gate_id=authority["gate_id"],
            audit_profile=bundle["audit"]["profile_id"],
            audit_version=bundle["audit"]["audit_version"],
            expected_test_count=(
                int(bundle["audit"]["predecessor_test_count"])
                + len(bundle["audit"]["expected_added_test_nodeids"])
            ),
        )
        if not has_post_closeout:
            return (
                (
                    "g4"
                    if successor_shape
                    and _status_without_history(status) == authority["successor_accepted_state"]
                    else "invalid"
                ),
                bundle,
            )
        post = bundle["post_successor_closeout"]
        next_seed = _validate_next_gate_seed(
            bundle.get("next_gate_seed"),
            authority=authority,
            post_successor_closeout=post,
        )
        external_seed = _external_handoff_seed(
            repository,
            ref,
            authority=authority,
            bundle=bundle,
        )
        has_next_bundle = bool(
            (next_seed is not None or external_seed is not None)
            and _exists(
                repository,
                ref,
                bundle_paths(next_seed or external_seed)["bundle"],
            )
        )
        return (
            (
                "g5"
                if successor_shape
                and _closeout_shape(
                    _git_json(repository, ref, post_path),
                    gate_id=authority["gate_id"],
                    audit_profile=post["implementation_audit_profile"],
                    audit_version=post["implementation_audit_version"],
                    expected_test_count=post["expected_test_count"],
                )
                and (
                    _status_without_history(status) == post["accepted_state"]
                    or has_next_bundle
                )
                else "invalid"
            ),
            bundle,
        )
    return "invalid", bundle


def resolve_gate_position(repository: Path, ref: str) -> GatePosition:
    authority = bootstrap_authority()
    seen_gate_ids: set[str] = set()
    seen_directories: set[str] = set()
    seen_paths: set[str] = set()
    seen_branches: set[str] = set()
    depth = 0
    allow_root_predecessor = True
    while True:
        if (
            authority["gate_id"] in seen_gate_ids
            or authority["bundle_directory"] in seen_directories
        ):
            raise SystemExit("successor-gate authority chain is cyclic or reuses a path")
        seen_gate_ids.add(authority["gate_id"])
        seen_directories.add(authority["bundle_directory"])
        authority_paths = set(authority_governed_paths(authority))
        authority_branches = {
            authority["bootstrap_branch"],
            authority["acceptance_branch"],
            authority["successor_implementation_branch"],
            authority["successor_acceptance_branch"],
        }
        if seen_paths & authority_paths or seen_branches & authority_branches:
            raise SystemExit("successor-gate authority chain reuses a path or branch")
        seen_paths.update(authority_paths)
        seen_branches.update(authority_branches)
        stage, bundle = _authority_stage(
            repository,
            ref,
            authority=authority,
            allow_root_predecessor=allow_root_predecessor,
        )
        if bundle is not None:
            post = bundle["post_successor_closeout"]
            if post["closeout_path"] in seen_paths or post["branch"] in seen_branches:
                raise SystemExit("successor post-closeout reuses prior gate authority")
            seen_paths.update(
                authority_governed_paths(
                    authority,
                    post_successor_closeout=post,
                )
            )
            seen_branches.add(post["branch"])
        if stage != "g5" or bundle is None:
            return GatePosition(
                authority=copy.deepcopy(authority),
                gate_id=authority["gate_id"],
                depth=depth,
                stage=stage,
                bundle=copy.deepcopy(bundle),
            )
        seed = _validate_next_gate_seed(
            bundle.get("next_gate_seed"),
            authority=authority,
            post_successor_closeout=bundle["post_successor_closeout"],
        )
        if seed is None:
            seed = _external_handoff_seed(
                repository,
                ref,
                authority=authority,
                bundle=bundle,
            )
        if seed is None or not _exists(repository, ref, bundle_paths(seed)["bundle"]):
            return GatePosition(
                authority=copy.deepcopy(authority),
                gate_id=authority["gate_id"],
                depth=depth,
                stage="g5",
                bundle=copy.deepcopy(bundle),
            )
        authority = seed
        depth += 1
        allow_root_predecessor = False


def state_id(repository: Path, ref: str) -> str:
    return resolve_gate_position(repository, ref).stage


def verify_pull_request(
    *,
    repository: Path,
    base: str,
    head: str,
    event: dict[str, Any],
    repository_slug: str,
    require_remote: bool = False,
    remote_verifier: RemoteEvidenceVerifier | None = None,
) -> None:
    state = resolve_gate_position(repository, base).stage
    if state == "s3":
        verify_bootstrap_transition(
            repository=repository,
            base=base,
            head=head,
            event=event,
            repository_slug=repository_slug,
        )
        return
    if state == "g1":
        verify_acceptance_transition(
            repository=repository,
            base=base,
            head=head,
            event=event,
            repository_slug=repository_slug,
            require_remote=require_remote,
            remote_verifier=remote_verifier,
        )
        return
    if state == "g2":
        verify_successor_implementation(
            repository=repository,
            base=base,
            head=head,
            event=event,
            repository_slug=repository_slug,
        )
        return
    if state == "g3":
        verify_successor_acceptance_transition(
            repository=repository,
            base=base,
            head=head,
            event=event,
            repository_slug=repository_slug,
            require_remote=require_remote,
            remote_verifier=remote_verifier,
        )
        return
    if state == "g4":
        verify_post_successor_closeout_transition(
            repository=repository,
            base=base,
            head=head,
            event=event,
            repository_slug=repository_slug,
            require_remote=require_remote,
            remote_verifier=remote_verifier,
        )
        return
    if state == "g5":
        position = resolve_gate_position(repository, base)
        if _is_sealed_controller_reauthorization(position):
            raise SystemExit(
                "sealed controller reauthorization boundary rejects ordinary pull requests"
            )
        if (
            position.bundle is not None
            and position.authority["next_owner_phase"] == _EXTERNAL_FEASIBILITY_PHASE
            and position.bundle.get("next_gate_seed") is None
        ):
            verify_external_controller_handoff_transition(
                repository=repository,
                base=base,
                head=head,
                event=event,
                repository_slug=repository_slug,
            )
        else:
            verify_bootstrap_transition(
                repository=repository,
                base=base,
                head=head,
                event=event,
                repository_slug=repository_slug,
            )
        return
    raise SystemExit("current governance state has no authorized successor-gate transition")


def _is_sealed_controller_reauthorization(position: GatePosition) -> bool:
    bundle = position.bundle
    if position.stage != "g5" or position.depth != 1 or not isinstance(bundle, dict):
        return False
    authority = position.authority
    post = bundle.get("post_successor_closeout")
    accepted = post.get("accepted_state") if isinstance(post, dict) else None
    prohibited = accepted.get("prohibited") if isinstance(accepted, dict) else None
    return (
        position.gate_id == "phase5e2c0"
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--event-json", type=Path)
    parser.add_argument("--repository-slug")
    parser.add_argument("--validate-bundle-ref")
    parser.add_argument("--describe-position-ref")
    parser.add_argument("--structural-only", action="store_true")
    args = parser.parse_args()
    repository = args.repository.resolve()
    if args.validate_bundle_ref:
        validate_bundle(repository, args.validate_bundle_ref)
        return 0
    if args.describe_position_ref:
        position = resolve_gate_position(repository, args.describe_position_ref)
        payload = {
            "authority": position.authority,
            "bundle": position.bundle,
            "depth": position.depth,
            "gate_id": position.gate_id,
            "stage": position.stage,
        }
        print(json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":")))
        return 0
    if not args.base or not args.head or args.event_json is None:
        parser.error("pull-request verification requires --base, --head, and --event-json")
    event = _canonical_json(args.event_json.read_bytes(), label="GitHub event")
    repository_slug = args.repository_slug
    if not isinstance(repository_slug, str) or not repository_slug:
        parser.error("pull-request verification requires --repository-slug")
    position = resolve_gate_position(repository, args.base)

    def remote_verified_elsewhere(**_: Any) -> None:
        return None

    verify_pull_request(
        repository=repository,
        base=args.base,
        head=args.head,
        event=event,
        repository_slug=repository_slug,
        require_remote=(
            args.structural_only and position.stage in {"g1", "g3", "g4"}
        ),
        remote_verifier=(
            remote_verified_elsewhere
            if args.structural_only and position.stage in {"g1", "g3", "g4"}
            else None
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
