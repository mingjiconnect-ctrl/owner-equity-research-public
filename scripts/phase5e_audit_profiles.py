#!/usr/bin/env python3
"""Protected-controller audit profiles for the Phase 5E 2A/2B hand-off.

The profile is selected from the protected controller commit, never from candidate input.  It
fixes the audit version and the closed check identity set that the controller, public writer, and
remote acceptance verifiers must all replay.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

AUDIT_TOOL = "owner-research-phase5e-readonly"
PHASE5E2B12A_AUDIT_PROFILE = "phase5e2b12a"
PHASE5E2B12B_AUDIT_PROFILE = "phase5e2b12b"
PHASE5E_SUCCESSOR_BOOTSTRAP_AUDIT_PROFILE = "phase5e-successor-gate-bootstrap"
PHASE5E2B12C_AUDIT_PROFILE = "phase5e-2b12c"
PHASE5E2B12A_TEST_COUNT = 1374
PHASE5E2B12A_NODEID_SHA256 = (
    "eab85a4981f3fdcfe841c5e730af10f3e2b50ce41c617f3f9204b17a7ba4a79b"
)
PHASE5E2B12B_ADDED_TEST_NODEIDS = (
    "tests/test_phase5e2b12b_canonical_event_consumption.py::"
    "test_canonical_event_two_sources_is_consumed_once",
    "tests/test_phase5e2b12b_canonical_event_consumption.py::"
    "test_canonical_event_three_sources_is_consumed_once",
    "tests/test_phase5e2b12b_canonical_event_consumption.py::"
    "test_canonical_event_magnitude_conflict_blocks",
    "tests/test_phase5e2b12b_canonical_event_consumption.py::"
    "test_canonical_event_date_conflict_blocks",
    "tests/test_phase5e2b12b_canonical_event_consumption.py::"
    "test_distinct_legal_event_ids_are_consumed_independently",
    "tests/test_phase5e2b12b_canonical_event_consumption.py::"
    "test_missing_legal_identity_blocks",
    "tests/test_phase5e2b12b_canonical_event_consumption.py::"
    "test_same_day_same_amount_without_distinct_legal_ids_blocks",
    "tests/test_phase5e2b12b_canonical_event_consumption.py::"
    "test_option_event_is_consumed_once_per_canonical_group",
    "tests/test_phase5e2b12b_canonical_event_consumption.py::"
    "test_event_input_order_is_irrelevant",
    "tests/test_phase5e2b12b_canonical_event_consumption.py::"
    "test_corroborating_source_changes_closure_not_share_value",
    "tests/test_phase5e2b12b_canonical_event_consumption.py::"
    "test_cumulative_event_fact_cannot_be_consumed_as_an_increment",
    "tests/test_phase5e2b12b_canonical_event_consumption.py::"
    "test_canonical_event_fact_preserves_all_member_lineage",
)
PHASE5E_SUCCESSOR_PREDECESSOR_TEST_COUNT = 1327
PHASE5E_SUCCESSOR_PREDECESSOR_NODEID_SHA256 = (
    "1712ac9325cfbe65a147369193fc7a1241e7f808a8a5c7f5b0f690ea625aadc6"
)
PHASE5E2B12C_ADDED_TEST_NODEIDS = (
    "tests/test_phase5e2b12c_coverage_claim_closure.py::"
    "test_bundle_closure_rejects_cross_issuer_or_security_evidence",
    "tests/test_phase5e2b12c_coverage_claim_closure.py::"
    "test_bundle_closure_rejects_dangling_or_cyclic_parent_lineage",
    "tests/test_phase5e2b12c_coverage_claim_closure.py::"
    "test_bundle_closure_rejects_future_or_outside_bundle_evidence",
    "tests/test_phase5e2b12c_coverage_claim_closure.py::"
    "test_canonical_group_coverage_consumes_each_occurrence_once",
    "tests/test_phase5e2b12c_coverage_claim_closure.py::"
    "test_claim_transition_is_bound_to_one_canonical_group",
    "tests/test_phase5e2b12c_coverage_claim_closure.py::"
    "test_conflicting_remaining_claim_blocks_entire_lineage",
    "tests/test_phase5e2b12c_coverage_claim_closure.py::"
    "test_cross_directory_replay_is_byte_identical",
    "tests/test_phase5e2b12c_coverage_claim_closure.py::"
    "test_exact_recursive_closure_contains_all_typed_evidence",
    "tests/test_phase5e2b12c_coverage_claim_closure.py::"
    "test_input_order_does_not_change_current_share_result",
    "tests/test_phase5e2b12c_coverage_claim_closure.py::"
    "test_no_event_rollforward_requires_complete_zero_or_na_coverage",
    "tests/test_phase5e2b12c_coverage_claim_closure.py::"
    "test_option_group_triggers_one_reviewed_transition",
    "tests/test_phase5e2b12c_coverage_claim_closure.py::"
    "test_warrant_and_convertible_transitions_route_specialist",
)

_COMMON_CHECK_IDS = frozenset(
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
        "phase5e2b11-frozen-acceptance",
        "read-only-checkout",
        "tracked-bytes-immutable",
    }
)

_PHASE5E2B12A_CHECK_IDS = frozenset(
    {
        "phase5e2b12a-independent-semantic-oracle",
        "phase5e2b12a-integration-contracts",
        "phase5e2b12a-repository-wide-changed-path-boundary",
        "phase5e2b12a-synchronized-resign-attack-oracle",
    }
)

_PHASE5E2B12B_CHECK_IDS = frozenset(
    {
        "phase5e2b12a-frozen-contract-replay",
        "phase5e2b12b-independent-semantic-oracle",
        "phase5e2b12b-repository-wide-changed-path-boundary",
    }
)

_PHASE5E_SUCCESSOR_BOOTSTRAP_CHECK_IDS = frozenset(
    {
        "phase5e-successor-gate-bundle-validation",
        "phase5e-successor-gate-independent-structural-oracle",
        "phase5e-successor-repository-wide-changed-path-boundary",
    }
)

_PHASE5E_SUCCESSOR_CHECK_IDS = frozenset(
    {
        "phase5e-successor-independent-semantic-oracle",
        "phase5e-successor-repository-wide-changed-path-boundary",
    }
)

_PHASE5E_SEALED_REAUTHORIZATION_CHECK_IDS = frozenset(
    {
        "phase5e-successor-controller-reauthorization-boundary",
        "phase5e-successor-repository-wide-changed-path-boundary",
    }
)


@dataclass(frozen=True, slots=True)
class AuditProfile:
    profile_id: str
    phase: str
    audit_version: str
    expected_check_ids: frozenset[str]
    semantic_oracle_path: str
    expected_test_count: int
    predecessor_test_count: int
    predecessor_nodeid_sha256: str
    expected_added_test_nodeids: tuple[str, ...]
    profile_kind: str
    policy_sha256: str = ""
    semantic_oracle_sha256: str = ""
    gate_id: str | None = None
    gate_depth: int = -1
    gate_stage: str | None = None


AUDIT_PROFILES = {
    PHASE5E2B12A_AUDIT_PROFILE: AuditProfile(
        profile_id=PHASE5E2B12A_AUDIT_PROFILE,
        phase="Phase 5E-2B.1-2A",
        audit_version="2.3.2.3.3",
        expected_check_ids=_COMMON_CHECK_IDS | _PHASE5E2B12A_CHECK_IDS,
        semantic_oracle_path="scripts/verify_phase5e2b12a_semantic_oracle.py",
        expected_test_count=PHASE5E2B12A_TEST_COUNT,
        predecessor_test_count=PHASE5E2B12A_TEST_COUNT,
        predecessor_nodeid_sha256=PHASE5E2B12A_NODEID_SHA256,
        expected_added_test_nodeids=(),
        profile_kind="legacy_2a",
    ),
    PHASE5E2B12B_AUDIT_PROFILE: AuditProfile(
        profile_id=PHASE5E2B12B_AUDIT_PROFILE,
        phase="Phase 5E-2B.1-2B",
        audit_version="2.3.2.3.4",
        expected_check_ids=_COMMON_CHECK_IDS | _PHASE5E2B12B_CHECK_IDS,
        semantic_oracle_path="scripts/verify_phase5e2b12b_semantic_oracle.py",
        expected_test_count=(
            PHASE5E2B12A_TEST_COUNT + len(PHASE5E2B12B_ADDED_TEST_NODEIDS)
        ),
        predecessor_test_count=PHASE5E2B12A_TEST_COUNT,
        predecessor_nodeid_sha256=PHASE5E2B12A_NODEID_SHA256,
        expected_added_test_nodeids=PHASE5E2B12B_ADDED_TEST_NODEIDS,
        profile_kind="legacy_2b",
    ),
    PHASE5E_SUCCESSOR_BOOTSTRAP_AUDIT_PROFILE: AuditProfile(
        profile_id=PHASE5E_SUCCESSOR_BOOTSTRAP_AUDIT_PROFILE,
        phase="Phase 5E successor-gate bootstrap",
        audit_version="2.3.2.3.4.1",
        expected_check_ids=_COMMON_CHECK_IDS | _PHASE5E_SUCCESSOR_BOOTSTRAP_CHECK_IDS,
        semantic_oracle_path="scripts/verify_phase5e_successor_gate_oracle.py",
        expected_test_count=PHASE5E_SUCCESSOR_PREDECESSOR_TEST_COUNT,
        predecessor_test_count=PHASE5E_SUCCESSOR_PREDECESSOR_TEST_COUNT,
        predecessor_nodeid_sha256=PHASE5E_SUCCESSOR_PREDECESSOR_NODEID_SHA256,
        expected_added_test_nodeids=(),
        profile_kind="successor_bootstrap",
    ),
    PHASE5E2B12C_AUDIT_PROFILE: AuditProfile(
        profile_id=PHASE5E2B12C_AUDIT_PROFILE,
        phase="Phase 5E-2B.1-2C",
        audit_version="2.3.2.3.5",
        expected_check_ids=_COMMON_CHECK_IDS | _PHASE5E_SUCCESSOR_CHECK_IDS,
        semantic_oracle_path="scripts/verify_phase5e2b12c_semantic_oracle.py",
        expected_test_count=(
            PHASE5E_SUCCESSOR_PREDECESSOR_TEST_COUNT
            + len(PHASE5E2B12C_ADDED_TEST_NODEIDS)
        ),
        predecessor_test_count=PHASE5E_SUCCESSOR_PREDECESSOR_TEST_COUNT,
        predecessor_nodeid_sha256=PHASE5E_SUCCESSOR_PREDECESSOR_NODEID_SHA256,
        expected_added_test_nodeids=PHASE5E2B12C_ADDED_TEST_NODEIDS,
        profile_kind="successor_dynamic",
    ),
}


def _policy_sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        (json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()


def _git_bytes(repository: Path, ref: str, path: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(repository), "show", f"{ref}:{path}"],
    )


def _git_json(repository: Path, ref: str, path: str) -> dict[str, Any]:
    raw = _git_bytes(repository, ref, path)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = child
        return value

    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON constant: {token}")
        ),
    )
    # The historical phase ledger predates the canonical serializer and contains preserved
    # indentation quirks.  Gate authority never derives from formatting, so require strict JSON
    # with duplicate/non-finite rejection while leaving those immutable historical bytes intact.
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a strict JSON object at {ref}")
    return value


def _git_path_exists(repository: Path, ref: str, path: str) -> bool:
    return (
        subprocess.run(
            ["git", "-C", str(repository), "cat-file", "-e", f"{ref}:{path}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def resolve_controller_gate_position(repository: Path, ref: str) -> dict[str, Any]:
    """Resolve recursive gate state in an isolated protected-controller process.

    The audit-profile registry must not import a candidate-controlled module or trust a cached
    ``sys.modules`` entry.  The protected verifier is therefore executed by absolute path under
    isolated mode and emits one closed canonical payload.
    """

    verifier = Path(__file__).with_name("verify_phase5e_successor_gate.py")
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(verifier),
            "--repository",
            str(repository.resolve()),
            "--describe-position-ref",
            ref,
        ],
        cwd="/",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"protected successor-gate position resolution failed: {message}")
    try:
        payload = json.loads(
            completed.stdout.decode("utf-8"),
            object_pairs_hook=lambda pairs: _closed_pairs(pairs),
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("protected successor-gate position output is malformed") from exc
    expected = (
        json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if (
        not isinstance(payload, dict)
        or set(payload) != {"authority", "bundle", "depth", "gate_id", "stage"}
        or completed.stdout != expected
    ):
        raise ValueError("protected successor-gate position output has an open shape")
    return payload


def _closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = child
    return value


def _dynamic_profile(
    *,
    profile_id: str,
    phase: str,
    audit_version: str,
    expected_check_ids: frozenset[str],
    expected_test_count: int,
    predecessor_test_count: int,
    predecessor_nodeid_sha256: str,
    expected_added_test_nodeids: tuple[str, ...],
    profile_kind: str,
    policy: dict[str, Any],
    gate_id: str,
    gate_depth: int,
    gate_stage: str,
) -> AuditProfile:
    requires_protected_behavior = profile_kind in {
        "sealed_controller_reauthorization",
        "successor_dynamic",
        "successor_transition",
    }
    oracle_path = policy.get("protected_oracle_path")
    oracle_sha256 = policy.get("protected_oracle_sha256")
    if requires_protected_behavior:
        if (
            not isinstance(oracle_path, str)
            or not oracle_path
            or oracle_path.startswith("/")
            or Path(oracle_path).as_posix() != oracle_path
            or ".." in Path(oracle_path).parts
            or not oracle_path.startswith(("scripts/", "governance/phase5e-gates/"))
            or not isinstance(oracle_sha256, str)
            or len(oracle_sha256) != 64
            or any(character not in "0123456789abcdef" for character in oracle_sha256)
        ):
            raise ValueError("dynamic audit policy lacks one protected semantic oracle identity")
    else:
        oracle_path = "scripts/verify_phase5e_successor_gate_oracle.py"
        oracle_sha256 = ""
    return AuditProfile(
        profile_id=profile_id,
        phase=phase,
        audit_version=audit_version,
        expected_check_ids=expected_check_ids,
        semantic_oracle_path=oracle_path,
        expected_test_count=expected_test_count,
        predecessor_test_count=predecessor_test_count,
        predecessor_nodeid_sha256=predecessor_nodeid_sha256,
        expected_added_test_nodeids=expected_added_test_nodeids,
        profile_kind=profile_kind,
        policy_sha256=_policy_sha256(policy),
        semantic_oracle_sha256=oracle_sha256,
        gate_id=gate_id,
        gate_depth=gate_depth,
        gate_stage=gate_stage,
    )


def audit_profile_policy_sha256(profile: AuditProfile) -> str:
    """Return the controller-owned policy identity for static and recursive profiles."""

    if profile.policy_sha256:
        return profile.policy_sha256
    return _policy_sha256(
        {
            "audit_version": profile.audit_version,
            "expected_added_test_nodeids": list(profile.expected_added_test_nodeids),
            "expected_check_ids": sorted(profile.expected_check_ids),
            "expected_test_count": profile.expected_test_count,
            "predecessor_nodeid_sha256": profile.predecessor_nodeid_sha256,
            "predecessor_test_count": profile.predecessor_test_count,
            "profile_id": profile.profile_id,
            "profile_kind": profile.profile_kind,
        }
    )


def audit_profile_context_sha256(profile: AuditProfile) -> str:
    """Bind a report to one exact profile, recursive gate and controller policy."""

    payload = {
            "audit_version": profile.audit_version,
            "gate_depth": profile.gate_depth,
            "gate_id": profile.gate_id,
            "gate_stage": profile.gate_stage,
            "phase": profile.phase,
            "policy_sha256": audit_profile_policy_sha256(profile),
            "profile_id": profile.profile_id,
            "profile_kind": profile.profile_kind,
        }
    if profile.semantic_oracle_sha256:
        payload["semantic_oracle_sha256"] = profile.semantic_oracle_sha256
    return _policy_sha256(payload)


def _is_sealed_controller_reauthorization(
    *,
    authority: dict[str, Any],
    bundle: dict[str, Any],
    depth: int,
) -> bool:
    post = bundle.get("post_successor_closeout")
    accepted = post.get("accepted_state") if isinstance(post, dict) else None
    prohibited = accepted.get("prohibited") if isinstance(accepted, dict) else None
    return (
        depth == 1
        and authority.get("gate_id") == "phase5e2c0"
        and authority.get("owner_phase") == "Phase 5E-2C-0"
        and authority.get("next_owner_phase") == "Phase 5E-2C-1"
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


def _generic_controller_profile(repository: Path, ref: str) -> AuditProfile:
    """Resolve one recursive successor audit profile from protected gate state."""

    position = resolve_controller_gate_position(repository, ref)
    authority = position["authority"]
    policy = authority["audit_policy"]
    stage = position["stage"]
    depth = int(position["depth"])
    gate_id = str(position["gate_id"])
    bundle = position["bundle"]
    bootstrap_checks = _COMMON_CHECK_IDS | _PHASE5E_SUCCESSOR_BOOTSTRAP_CHECK_IDS
    successor_checks = _COMMON_CHECK_IDS | _PHASE5E_SUCCESSOR_CHECK_IDS
    if stage in {"s3", "g1"}:
        return _dynamic_profile(
            profile_id=PHASE5E_SUCCESSOR_BOOTSTRAP_AUDIT_PROFILE,
            phase=f'{authority["owner_phase"]} successor-gate bootstrap',
            audit_version="2.3.2.3.4.1",
            expected_check_ids=bootstrap_checks,
            expected_test_count=int(policy["predecessor_test_count"]),
            predecessor_test_count=int(policy["predecessor_test_count"]),
            predecessor_nodeid_sha256=str(policy["predecessor_nodeid_sha256"]),
            expected_added_test_nodeids=(),
            profile_kind="successor_bootstrap",
            policy={
                "profile_id": PHASE5E_SUCCESSOR_BOOTSTRAP_AUDIT_PROFILE,
                "audit_version": "2.3.2.3.4.1",
                "mandatory_check_ids": sorted(bootstrap_checks),
                "predecessor_test_count": policy["predecessor_test_count"],
                "predecessor_nodeid_sha256": policy["predecessor_nodeid_sha256"],
            },
            gate_id=gate_id,
            gate_depth=depth,
            gate_stage=stage,
        )
    if stage in {"g2", "g3"} and isinstance(bundle, dict):
        bundle_policy = bundle["audit"]
        if frozenset(bundle_policy["expected_check_ids"]) != successor_checks:
            raise ValueError("accepted successor bundle weakens controller-owned checks")
        added = tuple(bundle_policy["expected_added_test_nodeids"])
        predecessor_count = int(bundle_policy["predecessor_test_count"])
        return _dynamic_profile(
            profile_id=str(bundle_policy["profile_id"]),
            phase=str(authority["owner_phase"]),
            audit_version=str(bundle_policy["audit_version"]),
            expected_check_ids=successor_checks,
            expected_test_count=predecessor_count + len(added),
            predecessor_test_count=predecessor_count,
            predecessor_nodeid_sha256=str(bundle_policy["predecessor_nodeid_sha256"]),
            expected_added_test_nodeids=added,
            profile_kind="successor_dynamic",
            policy=bundle_policy,
            gate_id=gate_id,
            gate_depth=depth,
            gate_stage=stage,
        )
    if stage == "g4" and isinstance(bundle, dict):
        post = bundle["post_successor_closeout"]
        if frozenset(post["transition_check_ids"]) != successor_checks:
            raise ValueError("post-successor transition weakens controller-owned checks")
        transition_policy = {
            "profile_id": post["transition_audit_profile"],
            "audit_version": post["transition_audit_version"],
            "protected_oracle_path": policy["protected_oracle_path"],
            "protected_oracle_sha256": policy["protected_oracle_sha256"],
            "mandatory_check_ids": post["transition_check_ids"],
            "predecessor_test_count": post["expected_test_count"],
            "predecessor_nodeid_sha256": post["expected_nodeid_sha256"],
            "expected_added_test_nodeids": [],
        }
        return _dynamic_profile(
            profile_id=str(post["transition_audit_profile"]),
            phase=f'{authority["owner_phase"]} total closeout',
            audit_version=str(post["transition_audit_version"]),
            expected_check_ids=successor_checks,
            expected_test_count=int(post["expected_test_count"]),
            predecessor_test_count=int(post["expected_test_count"]),
            predecessor_nodeid_sha256=str(post["expected_nodeid_sha256"]),
            expected_added_test_nodeids=(),
            profile_kind="successor_transition",
            policy=transition_policy,
            gate_id=gate_id,
            gate_depth=depth,
            gate_stage=stage,
        )
    if stage == "g5" and isinstance(bundle, dict):
        seed = bundle.get("next_gate_seed")
        if seed is None and authority.get("next_owner_phase") == "Phase 5E-2C-P":
            post = bundle["post_successor_closeout"]
            return _dynamic_profile(
                profile_id="phase5e-2cp-futu-feasibility",
                phase="Phase 5E-2C-P Futu feasibility gate",
                audit_version="2.3.2.3.7",
                expected_check_ids=successor_checks,
                expected_test_count=int(post["expected_test_count"]),
                predecessor_test_count=int(post["expected_test_count"]),
                predecessor_nodeid_sha256=str(post["expected_nodeid_sha256"]),
                expected_added_test_nodeids=(),
                profile_kind="external_feasibility",
                policy={
                    "profile_id": "phase5e-2cp-futu-feasibility",
                    "audit_version": "2.3.2.3.7",
                    "mandatory_check_ids": sorted(successor_checks),
                    "predecessor_test_count": post["expected_test_count"],
                    "predecessor_nodeid_sha256": post["expected_nodeid_sha256"],
                    "external_only": True,
                },
                gate_id=str(authority["gate_id"]),
                gate_depth=depth,
                gate_stage="g5-external-feasibility",
            )
        if seed is None and _is_sealed_controller_reauthorization(
            authority=authority,
            bundle=bundle,
            depth=depth,
        ):
            post = bundle["post_successor_closeout"]
            oracle_path = "scripts/verify_phase5e_successor_gate_oracle.py"
            oracle_sha256 = hashlib.sha256(
                _git_bytes(repository, ref, oracle_path)
            ).hexdigest()
            sealed_checks = _COMMON_CHECK_IDS | _PHASE5E_SEALED_REAUTHORIZATION_CHECK_IDS
            return _dynamic_profile(
                profile_id="phase5e-2c0-controller-reauthorization-sealed",
                phase="Phase 5E-2C-0 sealed Controller reauthorization boundary",
                audit_version="2.3.2.4.2",
                expected_check_ids=sealed_checks,
                expected_test_count=int(post["expected_test_count"]),
                predecessor_test_count=int(post["expected_test_count"]),
                predecessor_nodeid_sha256=str(post["expected_nodeid_sha256"]),
                expected_added_test_nodeids=(),
                profile_kind="sealed_controller_reauthorization",
                policy={
                    "profile_id": "phase5e-2c0-controller-reauthorization-sealed",
                    "audit_version": "2.3.2.4.2",
                    "mandatory_check_ids": sorted(sealed_checks),
                    "predecessor_test_count": post["expected_test_count"],
                    "predecessor_nodeid_sha256": post["expected_nodeid_sha256"],
                    "protected_oracle_path": oracle_path,
                    "protected_oracle_sha256": oracle_sha256,
                    "sealed_controller_reauthorization": True,
                },
                gate_id=str(authority["gate_id"]),
                gate_depth=depth,
                gate_stage="g5-controller-reauthorization-sealed",
            )
        if not isinstance(seed, dict):
            raise ValueError("terminal successor gate has no authorized audit target")
        seed_policy = seed["audit_policy"]
        return _dynamic_profile(
            profile_id=PHASE5E_SUCCESSOR_BOOTSTRAP_AUDIT_PROFILE,
            phase=f'{seed["owner_phase"]} successor-gate bootstrap',
            audit_version="2.3.2.3.4.1",
            expected_check_ids=bootstrap_checks,
            expected_test_count=int(seed_policy["predecessor_test_count"]),
            predecessor_test_count=int(seed_policy["predecessor_test_count"]),
            predecessor_nodeid_sha256=str(seed_policy["predecessor_nodeid_sha256"]),
            expected_added_test_nodeids=(),
            profile_kind="successor_bootstrap",
            policy={
                "profile_id": PHASE5E_SUCCESSOR_BOOTSTRAP_AUDIT_PROFILE,
                "audit_version": "2.3.2.3.4.1",
                "mandatory_check_ids": sorted(bootstrap_checks),
                "predecessor_test_count": seed_policy["predecessor_test_count"],
                "predecessor_nodeid_sha256": seed_policy["predecessor_nodeid_sha256"],
                "next_gate_id": seed["gate_id"],
            },
            gate_id=str(seed["gate_id"]),
            gate_depth=depth + 1,
            gate_stage="g5-next-bootstrap",
        )
    raise ValueError("controller gate state has no authorized recursive audit profile")


def resolve_controller_audit_profile(
    repository: Path,
    ref: str = "HEAD",
    *,
    has_2a_closeout: bool | None = None,
) -> AuditProfile:
    """Resolve legacy or recursive controller audit authority for one protected ref."""

    status = _git_json(repository, ref, "docs/phase-status.json")
    if has_2a_closeout is None:
        has_2a_closeout = _git_path_exists(
            repository,
            ref,
            "docs/phase5e2b12a-acceptance-closeout.json",
        )
    # Once the generic predecessor or any recursive gate exists, the accepted bundle—not the
    # historical static status table—is the sole profile authority.  Resolve it first so G2/G3
    # reports bind the exact gate/policy rather than merely reusing a familiar profile ID.
    position_error: ValueError | None = None
    try:
        position = resolve_controller_gate_position(repository, ref)
    except ValueError as exc:
        position_error = exc
        position = {"stage": "invalid"}
    if position.get("stage") in {"s3", "g1", "g2", "g3", "g4", "g5"}:
        return _generic_controller_profile(repository, ref)
    try:
        profile_id = controller_profile_id(status, has_2a_closeout=has_2a_closeout)
    except ValueError:
        if position_error is not None:
            raise position_error from None
        return _generic_controller_profile(repository, ref)
    if position_error is not None and profile_id in {
        PHASE5E_SUCCESSOR_BOOTSTRAP_AUDIT_PROFILE,
        PHASE5E2B12C_AUDIT_PROFILE,
    }:
        raise position_error
    return audit_profile(profile_id)


def audit_profile(profile_id: str) -> AuditProfile:
    """Return one closed profile or fail closed for an unknown identifier."""

    try:
        return AUDIT_PROFILES[profile_id]
    except KeyError as exc:
        raise ValueError(f"unknown Phase 5E audit profile: {profile_id}") from exc


def controller_profile_id(status: dict[str, Any], *, has_2a_closeout: bool) -> str:
    """Derive the next audit subject from the immutable controller state.

    The pending 2A controller audits 2A corrections and its acceptance-only transition.  Once the
    2A closeout exists, the accepted 2A or pending 2B controller audits the 2B implementation and
    acceptance transition.  An accepted 2B controller deliberately has no profile here: a later
    phase must install a new protected successor gate before production can advance.
    """

    phase = status.get("current_phase")
    state = status.get("status")
    if (
        not has_2a_closeout
        and phase == "Phase 5E-2B.1"
        and state == "implementation_complete_pending_acceptance"
    ):
        return PHASE5E2B12A_AUDIT_PROFILE
    if has_2a_closeout and (
        (phase == "Phase 5E-2B.1-2A" and state == "accepted_closed")
        or (
            phase == "Phase 5E-2B.1-2B"
            and state == "implementation_complete_pending_acceptance"
        )
    ):
        return PHASE5E2B12B_AUDIT_PROFILE
    if (
        phase == "Phase 5E-2B.1-2B"
        and state == "accepted_closed"
        and status.get("authorized_next")
        == ["Phase 5E-2B.1-2C successor-gate bootstrap"]
    ) or (
        phase == "Phase 5E-2B.1-2C-gate"
        and state == "implementation_complete_pending_acceptance"
    ):
        return PHASE5E_SUCCESSOR_BOOTSTRAP_AUDIT_PROFILE
    if (
        phase == "Phase 5E-2B.1-2C-gate"
        and state == "accepted_closed"
    ) or (
        phase == "Phase 5E-2B.1-2C"
        and state == "implementation_complete_pending_acceptance"
    ):
        return PHASE5E2B12C_AUDIT_PROFILE
    raise ValueError("controller state has no authorized Phase 5E audit profile")


__all__ = (
    "AUDIT_PROFILES",
    "AUDIT_TOOL",
    "AuditProfile",
    "PHASE5E2B12A_AUDIT_PROFILE",
    "PHASE5E2B12A_NODEID_SHA256",
    "PHASE5E2B12A_TEST_COUNT",
    "PHASE5E2B12B_AUDIT_PROFILE",
    "PHASE5E2B12B_ADDED_TEST_NODEIDS",
    "PHASE5E2B12C_ADDED_TEST_NODEIDS",
    "PHASE5E2B12C_AUDIT_PROFILE",
    "PHASE5E_SUCCESSOR_BOOTSTRAP_AUDIT_PROFILE",
    "PHASE5E_SUCCESSOR_PREDECESSOR_NODEID_SHA256",
    "PHASE5E_SUCCESSOR_PREDECESSOR_TEST_COUNT",
    "audit_profile",
    "audit_profile_context_sha256",
    "audit_profile_policy_sha256",
    "controller_profile_id",
    "resolve_controller_audit_profile",
    "resolve_controller_gate_position",
)
