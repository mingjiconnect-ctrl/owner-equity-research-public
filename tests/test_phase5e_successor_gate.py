from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts import phase5e_audit_profiles as audit_profiles
from scripts import verify_phase5e2b12c_semantic_oracle as behavior_oracle
from scripts import verify_phase5e_successor_gate as gate
from scripts import verify_phase5e_successor_gate_oracle as independent_gate_oracle

ROOT = Path(__file__).resolve().parents[1]
SLUG = "owner/research"
INDEPENDENT_ORACLE = ROOT / "scripts/verify_phase5e_successor_gate_oracle.py"
_TEST_RECEIPT_SEEDS = {
    "legal": bytes.fromhex("11" * 32),
    "account": bytes.fromhex("22" * 32),
    "protocol": bytes.fromhex("33" * 32),
}
_TEST_RECEIPT_SIGNING: dict[str, Any] = {}


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repository), *args], text=True).strip()


def _commit(repository: Path, message: str) -> str:
    subprocess.run(["git", "-C", str(repository), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-m", message],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return _git(repository, "rev-parse", "HEAD")


def _merge_to_main(repository: Path, branch: str, message: str) -> str:
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "main"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "-C", str(repository), "merge", "--no-ff", branch, "-m", message],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return _git(repository, "rev-parse", "HEAD")


def _canonical(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n")


def _test_ed25519_keypair(seed: bytes) -> tuple[str, Any]:
    digest = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public_key = gate._ed_encode(gate._ed_scalarmult(gate._ED_BASE, scalar))

    def sign(message: bytes) -> str:
        nonce = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little")
        nonce %= gate._ED_L
        encoded_r = gate._ed_encode(gate._ed_scalarmult(gate._ED_BASE, nonce))
        challenge = int.from_bytes(
            hashlib.sha512(encoded_r + public_key + message).digest(),
            "little",
        ) % gate._ED_L
        signature_scalar = (nonce + challenge * scalar) % gate._ED_L
        return (encoded_r + signature_scalar.to_bytes(32, "little")).hex()

    return public_key.hex(), sign


def _test_receipt_authority() -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    signers: dict[str, dict[str, str]] = {}
    signing: dict[str, Any] = {}
    for kind in gate._EXTERNAL_RECEIPT_KINDS:
        public_key, signer = _test_ed25519_keypair(_TEST_RECEIPT_SEEDS[kind])
        signers[kind] = {
            "key_id": f"test-{kind}-receipt-key",
            "public_key_hex": public_key,
        }
        signing[kind] = signer
    return signers, signing


def _signed_receipt_fixture(
    *,
    expected: dict[str, object],
    signers: dict[str, dict[str, str]],
    signing: dict[str, Any],
) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    prior_receipt_sha256: str | None = None
    for sequence, kind in enumerate(gate._EXTERNAL_RECEIPT_KINDS, start=1):
        artifact_sha256 = str(sequence) * 64
        payload = {
            "schema_version": "1.0.0",
            "kind": kind,
            "sequence": sequence,
            "receipt_id": f"futu-{kind}-receipt",
            "decision": "passed",
            "feasibility_conditions": list(
                gate._EXTERNAL_CONDITION_COVERAGE[kind]
            ),
            **expected,
            "issued_at": f"2026-07-22T0{sequence}:00:00Z",
            "expires_at": "2026-07-23T00:00:00Z",
            "artifact_store": "private_worm_cas",
            "artifact_object_id": artifact_sha256,
            "artifact_version": f"version-{sequence}",
            "artifact_sha256": artifact_sha256,
            "prior_receipt_sha256": prior_receipt_sha256,
            "signer_key_id": signers[kind]["key_id"],
        }
        envelope = {
            "payload": payload,
            "signature_hex": signing[kind](gate._receipt_payload_bytes(payload)),
        }
        receipts.append(envelope)
        prior_receipt_sha256 = gate._canonical_payload_sha256(envelope)
    return receipts


def _receipt_expected_context() -> dict[str, object]:
    return {
        "repository_id": 1312436919,
        "repository": "mingjiconnect-ctrl/owner-equity-research-public",
        "source_gate_id": "phase5e2b12c",
        "source_owner_phase": "Phase 5E-2B.1-2C",
        "target_owner_phase": "Phase 5E-2C-0",
        "predecessor_commit": "a" * 40,
        "predecessor_tree": "b" * 40,
        "predecessor_state_fingerprint": "c" * 64,
        "component_lock_sha256": "d" * 64,
        "authority_seed_sha256": "e" * 64,
        "policy_sha256": "f" * 64,
        "challenge_nonce": "9" * 64,
    }


def _closeout(
    *,
    gate_id: str,
    implementation_head: str,
    implementation_merge: str,
    implementation_tree: str,
    audit_profile: str,
    audit_version: str,
    test_count: int,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "gate_id": gate_id,
        "implementation_pull_request": 80,
        "implementation_head_commit": implementation_head,
        "implementation_merge_commit": implementation_merge,
        "implementation_tree_sha": implementation_tree,
        "acceptance_pull_request": 81,
        "pr_ci_run_id": "1",
        "main_ci_run_id": "2",
        "audit_workflow_id": 456,
        "audit_tool": "owner-research-phase5e-readonly",
        "audit_profile": audit_profile,
        "audit_version": audit_version,
        "audit_report_sha256": "a" * 64,
        "audit_artifact_sha256": "b" * 64,
        "test_inventory_sha256": "c" * 64,
        "runtime_matrix_sha256": "d" * 64,
        "audit_wheelhouse_manifest_sha256": "e" * 64,
        "controller_app_id": 98765,
        "controller_app_slug": "phase5e-controller",
        "controller_installation_id": 54321,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0, "P3": 0},
        "test_count": test_count,
    }


def _event(base: str, head: str, branch: str) -> dict[str, Any]:
    return {
        "number": 81,
        "repository": {"full_name": SLUG},
        "pull_request": {
            "base": {"sha": base, "ref": "main", "repo": {"full_name": SLUG}},
            "head": {"sha": head, "ref": branch, "repo": {"full_name": SLUG}},
        },
    }


def _run_independent_oracle(
    repository: Path,
    *,
    controller_ref: str,
    candidate_ref: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(INDEPENDENT_ORACLE),
            "--repository",
            str(repository),
            "--controller-root",
            str(repository),
            "--controller-ref",
            controller_ref,
            "--candidate-ref",
            candidate_ref,
        ],
        cwd="/",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def _state(*, phase: str, status: str, authorized: str, prohibited: list[str]) -> dict[str, Any]:
    return {
        "current_phase": phase,
        "status": status,
        "authorized_next": [authorized],
        "prohibited": prohibited,
        "release_tag": None,
    }


def _next_gate_seed(predecessor_test_count: int) -> dict[str, Any]:
    prohibited = [
        "Phase 5E-2C-0",
        "Phase 5E-2C-1",
        "Phase 5E-2C-2",
        "Phase 5E-2C-3",
        "Phase 5E-2C-4",
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
    ]
    return {
        "gate_id": "phase5e2c0",
        "owner_phase": "Phase 5E-2C-0",
        "next_owner_phase": "Phase 5E-2C-1",
        "next_gate_authority_sha256": None,
        "bootstrap_branch": "feature/phase5e2c0-gate-bootstrap",
        "acceptance_branch": "feature/phase5e2c0-gate-acceptance-closeout",
        "bundle_directory": "governance/phase5e-gates/phase5e2c0",
        "closeout_path": "docs/phase5e2c0-gate-acceptance-closeout.json",
        "successor_closeout_path": "docs/phase5e2c0-acceptance-closeout.json",
        "successor_implementation_branch": "feature/phase5e2c0-exact-decimal-contract",
        "successor_acceptance_branch": "feature/phase5e2c0-acceptance-closeout",
        "gate_bootstrap_diff": {
            "docs/phase-status.json": "M",
            "governance/phase5e-gates/phase5e2c0/adversarial-cases.json": "A",
            "governance/phase5e-gates/phase5e2c0/bundle.json": "A",
            "governance/phase5e-gates/phase5e2c0/semantic-oracle.py.txt": "A",
        },
        "gate_acceptance_diff": {
            "docs/phase-status.json": "M",
            "docs/phase5e2c0-gate-acceptance-closeout.json": "A",
        },
        # This is the generic protected next-authority fixture.  Keep its
        # implementation surface outside every inherited frozen path and
        # forbidden prefix.  The external Controller handoff fixture replaces
        # this with _EXTERNAL_2C0_IMPLEMENTATION_DIFF only after applying the
        # separately reviewed release policy.
        "successor_implementation_diff": {
            "docs/phase-status.json": "M",
            "src/owner_research/valuation_vendor_market_contract_types.py": "A",
            "tests/test_phase5e2c0_vendor_market_contract.py": "A",
        },
        "successor_acceptance_diff": {
            "docs/phase-status.json": "M",
            "docs/phase5e2c0-acceptance-closeout.json": "A",
        },
        "pending_gate_state": _state(
            phase="Phase 5E-2C-0-gate",
            status="implementation_complete_pending_acceptance",
            authorized="Phase 5E-2C-0 successor-gate acceptance closeout",
            prohibited=prohibited,
        ),
        "accepted_gate_state": _state(
            phase="Phase 5E-2C-0-gate",
            status="accepted_closed",
            authorized="Phase 5E-2C-0 exact-decimal contract implementation",
            prohibited=prohibited[1:],
        ),
        "successor_pending_state": _state(
            phase="Phase 5E-2C-0",
            status="implementation_complete_pending_acceptance",
            authorized="Phase 5E-2C-0 acceptance closeout",
            prohibited=prohibited[1:],
        ),
        "successor_accepted_state": _state(
            phase="Phase 5E-2C-0",
            status="accepted_closed",
            authorized="Phase 5E-2C-0 total closeout",
            prohibited=prohibited[1:],
        ),
        "frozen_paths": [
            "component-lock.json",
            "docs/phase5e2b12c-acceptance-closeout.json",
            "docs/phase5e2b12c-gate-acceptance-closeout.json",
            "docs/phase5e2b13-acceptance-closeout.json",
            "governance/phase5e-gates/phase5e2b12c/adversarial-cases.json",
            "governance/phase5e-gates/phase5e2b12c/bundle.json",
            "governance/phase5e-gates/phase5e2b12c/semantic-oracle.py.txt",
            "pyproject.toml",
            "schemas/market-reference-snapshot.schema.json",
            "tests/test_phase5e2b12a_acceptance_gate.py",
            "tests/test_phase5e2b12b_acceptance_gate.py",
            "tests/test_phase5e_audit.py",
            "tests/test_phase5e_successor_gate.py",
        ],
        "forbidden_prefixes": [".github", "plugins", "schemas", "scripts"],
        "audit_policy": {
            "profile_id": "phase5e-2c0",
            "audit_version": "2.3.2.4",
            "protected_oracle_path": gate._EXTERNAL_PROTECTED_ORACLE_PATH,
            "protected_oracle_sha256": hashlib.sha256(
                (ROOT / gate._EXTERNAL_PROTECTED_ORACLE_PATH).read_bytes()
            ).hexdigest(),
            "expected_added_test_nodeids": [
                "tests/test_phase5e2c0_vendor_market_contract.py::test_vendor_market_contract"
            ],
            "mandatory_check_ids": sorted(gate._GENERIC_SUCCESSOR_CHECK_IDS),
            "predecessor_test_count": predecessor_test_count,
            "predecessor_nodeid_sha256": "f" * 64,
        },
    }


def _post_successor_closeout(
    *,
    expected_test_count: int,
) -> dict[str, Any]:
    return {
        "accepted_state": {
            "current_phase": "Phase 5E-2B.1-2C",
            "status": "accepted_closed",
            "authorized_next": ["Phase 5E-2C-P Futu feasibility gate"],
            "prohibited": [
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
            ],
            "release_tag": None,
        },
        "implementation_audit_profile": "phase5e-2b12c",
        "implementation_audit_version": "2.3.2.3.5",
        "transition_audit_profile": "phase5e-2b13-closeout",
        "transition_audit_version": "2.3.2.3.6",
        "transition_check_ids": sorted(gate._GENERIC_SUCCESSOR_CHECK_IDS),
        "branch": "feature/phase5e2b13-total-corrective-closeout",
        "closeout_path": "docs/phase5e2b13-acceptance-closeout.json",
        "diff": {
            "docs/phase-status.json": "M",
            "docs/phase5e2b13-acceptance-closeout.json": "A",
        },
        "expected_test_count": expected_test_count,
        "expected_nodeid_sha256": "f" * 64,
    }


def _write_gate_bootstrap_candidate(
    repository: Path,
    *,
    authority: dict[str, Any],
    predecessor: dict[str, Any],
    next_gate_seed: dict[str, Any] | None = None,
) -> dict[str, Any]:
    paths = gate.bundle_paths(authority)
    case_id = f'{authority["gate_id"]}-001'
    oracle = (
        "SCHEMA_VERSION = '1.0.0'\n"
        f"GATE_ID = {authority['gate_id']!r}\n"
        f"AUDIT_PROFILE = {authority['audit_policy']['profile_id']!r}\n"
        f"ADVERSARIAL_CASE_IDS = {(case_id,)!r}\n"
        "EXPECTED_TEST_NODEIDS = "
        f"{tuple(authority['audit_policy']['expected_added_test_nodeids'])!r}\n"
    ).encode()
    cases = {
        "schema_version": "1.0.0",
        "cases": [
            {
                "case_id": case_id,
                "expectation": "The next gate remains inert until its acceptance closeout.",
                "priority": "P0",
            }
        ],
    }
    cases_raw = (json.dumps(cases, indent=2, sort_keys=True) + "\n").encode()
    component = json.loads((repository / "component-lock.json").read_text())
    schema_count, schema_set_sha = gate._schema_set_sha256(repository, "HEAD")
    assert schema_count == 43
    expected_test_count = authority["audit_policy"]["predecessor_test_count"] + len(
        authority["audit_policy"]["expected_added_test_nodeids"]
    )
    post_prohibited = list(authority["successor_accepted_state"]["prohibited"])
    post_state = {
        "current_phase": authority["owner_phase"],
        "status": "accepted_closed",
        "authorized_next": (
            [f'{next_gate_seed["owner_phase"]} successor-gate bootstrap']
            if next_gate_seed is not None
            else []
        ),
        "prohibited": post_prohibited,
        "release_tag": None,
    }
    bundle = {
        "schema_version": "2.0.0",
        "gate_id": authority["gate_id"],
        "owner_phase": authority["owner_phase"],
        "predecessor_state_fingerprint": hashlib.sha256(
            (json.dumps(predecessor, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest(),
        "gate_bootstrap_branch": authority["bootstrap_branch"],
        "gate_acceptance_branch": authority["acceptance_branch"],
        "gate_bootstrap_diff": authority["gate_bootstrap_diff"],
        "gate_acceptance_diff": authority["gate_acceptance_diff"],
        "successor_implementation_branch": authority["successor_implementation_branch"],
        "successor_acceptance_branch": authority["successor_acceptance_branch"],
        "successor_implementation_diff": authority["successor_implementation_diff"],
        "successor_acceptance_diff": authority["successor_acceptance_diff"],
        "pending_gate_state": authority["pending_gate_state"],
        "accepted_gate_state": authority["accepted_gate_state"],
        "successor_pending_state": authority["successor_pending_state"],
        "successor_accepted_state": authority["successor_accepted_state"],
        "post_successor_closeout": {
            "accepted_state": post_state,
            "implementation_audit_profile": authority["audit_policy"]["profile_id"],
            "implementation_audit_version": authority["audit_policy"]["audit_version"],
            "transition_audit_profile": f'{authority["gate_id"]}-total-closeout',
            "transition_audit_version": "2.3.2.4.1",
            "transition_check_ids": sorted(gate._GENERIC_SUCCESSOR_CHECK_IDS),
            "branch": f'feature/{authority["gate_id"]}-total-closeout',
            "closeout_path": f'docs/{authority["gate_id"]}-total-closeout.json',
            "diff": {
                "docs/phase-status.json": "M",
                f'docs/{authority["gate_id"]}-total-closeout.json': "A",
            },
            "expected_test_count": expected_test_count,
            "expected_nodeid_sha256": "a" * 64,
        },
        "next_gate_seed": next_gate_seed,
        "audit": {
            "profile_id": authority["audit_policy"]["profile_id"],
            "audit_version": authority["audit_policy"]["audit_version"],
            "protected_oracle_path": authority["audit_policy"][
                "protected_oracle_path"
            ],
            "protected_oracle_sha256": authority["audit_policy"][
                "protected_oracle_sha256"
            ],
            "predecessor_test_count": authority["audit_policy"]["predecessor_test_count"],
            "predecessor_nodeid_sha256": authority["audit_policy"][
                "predecessor_nodeid_sha256"
            ],
            "expected_added_test_nodeids": authority["audit_policy"][
                "expected_added_test_nodeids"
            ],
            "expected_check_ids": authority["audit_policy"]["mandatory_check_ids"],
        },
        "semantic_oracle": {
            "path": paths["oracle"],
            "sha256": hashlib.sha256(oracle).hexdigest(),
        },
        "adversarial_cases": {
            "path": paths["cases"],
            "sha256": hashlib.sha256(cases_raw).hexdigest(),
        },
        "frozen_paths": authority["frozen_paths"],
        "forbidden_prefixes": authority["forbidden_prefixes"],
        "component_lock_sha256": hashlib.sha256(
            (repository / "component-lock.json").read_bytes()
        ).hexdigest(),
        "public_schema_count": 43,
        "public_schema_set_sha256": schema_set_sha,
        "kernel_release": {
            "tag": gate._KERNEL["tag"],
            "tag_object": gate._KERNEL["tag_object"],
            "commit": gate._KERNEL["commit"],
            "wheel_sha256": gate._KERNEL["wheel_sha256"],
            "schema_sha256": component["valuation_kernel"]["public_schema_sha256"],
        },
        "execution_mode": "protected_base_only_after_gate_acceptance",
        "successor_production_authorized_by_bundle": False,
    }
    _canonical(
        repository / gate.STATUS_PATH,
        gate._expected_status(predecessor, authority["pending_gate_state"]),
    )
    oracle_path = repository / paths["oracle"]
    oracle_path.parent.mkdir(parents=True, exist_ok=True)
    oracle_path.write_bytes(oracle)
    (repository / paths["cases"]).write_bytes(cases_raw)
    _canonical(repository / paths["bundle"], bundle)
    return bundle


def _generic_future_authority(
    *,
    gate_id: str,
    owner_phase: str,
    next_owner_phase: str,
    predecessor_test_count: int,
) -> dict[str, Any]:
    owner_slug = owner_phase.lower().replace("phase ", "").replace(".", "").replace("-", "")
    prohibited = [
        next_owner_phase,
        "Phase 5E-2C-3",
        "Phase 5E-2C-4",
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
    ]
    next_hash = "9" * 64
    return {
        "gate_id": gate_id,
        "owner_phase": owner_phase,
        "next_owner_phase": next_owner_phase,
        "next_gate_authority_sha256": next_hash,
        "bootstrap_branch": f"feature/{gate_id}-gate-bootstrap",
        "acceptance_branch": f"feature/{gate_id}-gate-acceptance-closeout",
        "bundle_directory": f"governance/phase5e-gates/{gate_id}",
        "closeout_path": f"docs/{gate_id}-gate-acceptance-closeout.json",
        "successor_closeout_path": f"docs/{gate_id}-acceptance-closeout.json",
        "successor_implementation_branch": f"feature/{gate_id}-implementation",
        "successor_acceptance_branch": f"feature/{gate_id}-acceptance-closeout",
        "gate_bootstrap_diff": {
            "docs/phase-status.json": "M",
            f"governance/phase5e-gates/{gate_id}/adversarial-cases.json": "A",
            f"governance/phase5e-gates/{gate_id}/bundle.json": "A",
            f"governance/phase5e-gates/{gate_id}/semantic-oracle.py.txt": "A",
        },
        "gate_acceptance_diff": {
            "docs/phase-status.json": "M",
            f"docs/{gate_id}-gate-acceptance-closeout.json": "A",
        },
        "successor_implementation_diff": {
            "docs/phase-status.json": "M",
            f"tests/test_{owner_slug}_contract.py": "A",
        },
        "successor_acceptance_diff": {
            "docs/phase-status.json": "M",
            f"docs/{gate_id}-acceptance-closeout.json": "A",
        },
        "pending_gate_state": _state(
            phase=f"{owner_phase}-gate",
            status="implementation_complete_pending_acceptance",
            authorized=f"{owner_phase} successor-gate acceptance closeout",
            prohibited=[owner_phase, *prohibited],
        ),
        "accepted_gate_state": _state(
            phase=f"{owner_phase}-gate",
            status="accepted_closed",
            authorized=f"{owner_phase} contract implementation",
            prohibited=prohibited,
        ),
        "successor_pending_state": _state(
            phase=owner_phase,
            status="implementation_complete_pending_acceptance",
            authorized=f"{owner_phase} acceptance closeout",
            prohibited=prohibited,
        ),
        "successor_accepted_state": _state(
            phase=owner_phase,
            status="accepted_closed",
            authorized=f"{owner_phase} total closeout",
            prohibited=prohibited,
        ),
        "frozen_paths": sorted(gate._CONTROL_PLANE_FROZEN_PATHS),
        "forbidden_prefixes": sorted(
            gate._CONTROL_PLANE_FORBIDDEN_PREFIXES | {"plugins", "schemas"}
        ),
        "audit_policy": {
            "profile_id": gate_id,
            "audit_version": "2.3.2.4.1",
            "protected_oracle_path": "scripts/verify_phase5e2b12c_semantic_oracle.py",
            "protected_oracle_sha256": hashlib.sha256(
                (ROOT / "scripts/verify_phase5e2b12c_semantic_oracle.py").read_bytes()
            ).hexdigest(),
            "expected_added_test_nodeids": [
                f"tests/test_{owner_slug}_contract.py::test_contract"
            ],
            "mandatory_check_ids": sorted(gate._GENERIC_SUCCESSOR_CHECK_IDS),
            "predecessor_test_count": predecessor_test_count,
            "predecessor_nodeid_sha256": "8" * 64,
        },
    }


def _write_external_handoff_candidate(
    repository: Path,
    *,
    base: str,
    bundle: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    predecessor_status = json.loads((repository / gate.STATUS_PATH).read_text())
    predecessor_status.update(
        {
            "schema_version": "2.0.0",
            "baseline_release": {"tag": None, "commit": base},
            "closeout": "Phase 5E-2B.1-2C",
            "prior_closeouts": ["Phase 5E-2B.1-2A", "Phase 5E-2B.1-2B"],
        }
    )
    _canonical(repository / gate.STATUS_PATH, predecessor_status)
    predecessor = _commit(repository, "bind full external predecessor status")
    predecessor_status = json.loads((repository / gate.STATUS_PATH).read_text())
    seed = _next_gate_seed(bundle["post_successor_closeout"]["expected_test_count"])
    seed["bootstrap_branch"] = gate._EXTERNAL_CONTROLLER_BRANCH
    seed["gate_bootstrap_diff"] = dict(gate._EXTERNAL_CONTROLLER_DIFF)
    seed["audit_policy"]["protected_oracle_path"] = gate._EXTERNAL_PROTECTED_ORACLE_PATH
    seed["audit_policy"]["protected_oracle_sha256"] = hashlib.sha256(
        (ROOT / gate._EXTERNAL_PROTECTED_ORACLE_PATH).read_bytes()
    ).hexdigest()
    seed["successor_implementation_diff"] = dict(
        gate._EXTERNAL_2C0_IMPLEMENTATION_DIFF
    )
    seed["forbidden_prefixes"] = sorted(
        set(seed["forbidden_prefixes"]) - {"plugins", "schemas"}
    )
    frozen = set(seed["frozen_paths"])
    frozen.difference_update(seed["successor_implementation_diff"])
    frozen.update(
        set(gate.bootstrap_authority()["frozen_paths"])
        - set(gate._EXTERNAL_RELEASABLE_FROZEN_PATHS)
    )
    frozen.update(
        gate.authority_governed_paths(
            gate.bootstrap_authority(),
            post_successor_closeout=bundle["post_successor_closeout"],
        )
    )
    frozen.update({gate._EXTERNAL_HANDOFF_PATH, gate._EXTERNAL_PROTECTED_ORACLE_PATH})
    for prefix in ("plugins", "schemas"):
        frozen.update(gate._tracked_paths(repository, predecessor, prefix))
    frozen.difference_update(seed["successor_implementation_diff"])
    seed["frozen_paths"] = sorted(frozen)
    seed = gate._validate_external_authority_seed(
        seed,
        authority=gate.bootstrap_authority(),
        post_successor_closeout=bundle["post_successor_closeout"],
    )
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", gate._EXTERNAL_CONTROLLER_BRANCH],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    _write_gate_bootstrap_candidate(
        repository,
        authority=seed,
        predecessor=predecessor_status,
        next_gate_seed=None,
    )
    authority_seed_sha256 = gate._canonical_payload_sha256(seed)
    predecessor_tree = _git(repository, "rev-parse", f"{predecessor}^{{tree}}")
    predecessor_fingerprint = gate._canonical_payload_sha256(predecessor_status)
    component_lock_sha256 = hashlib.sha256(
        (repository / gate.COMPONENT_LOCK_PATH).read_bytes()
    ).hexdigest()
    challenge_nonce = "9" * 64
    receipt_expected = {
            "repository_id": 1312436919,
            "repository": "mingjiconnect-ctrl/owner-equity-research-public",
            "source_gate_id": gate.bootstrap_authority()["gate_id"],
            "source_owner_phase": gate.bootstrap_authority()["owner_phase"],
            "target_owner_phase": gate._EXTERNAL_TARGET_PHASE,
            "predecessor_commit": predecessor,
            "predecessor_tree": predecessor_tree,
            "predecessor_state_fingerprint": predecessor_fingerprint,
            "component_lock_sha256": component_lock_sha256,
            "authority_seed_sha256": authority_seed_sha256,
            "policy_sha256": gate._FUTU_POLICY_SHA256,
            "challenge_nonce": challenge_nonce,
    }
    receipts = _signed_receipt_fixture(
        expected=receipt_expected,
        signers=gate._RECEIPT_SIGNERS,
        signing=_TEST_RECEIPT_SIGNING,
    )
    handoff = {
        "schema_version": "1.0.0",
        "external_phase": gate._EXTERNAL_FEASIBILITY_PHASE,
        "source_gate_id": gate.bootstrap_authority()["gate_id"],
        "source_owner_phase": gate.bootstrap_authority()["owner_phase"],
        "target_owner_phase": gate._EXTERNAL_TARGET_PHASE,
        "predecessor_commit": predecessor,
        "predecessor_tree": predecessor_tree,
        "predecessor_state_fingerprint": predecessor_fingerprint,
        "receipt_bindings": receipts,
        "receipt_set_sha256": gate._canonical_payload_sha256(receipts),
        "challenge_nonce": challenge_nonce,
        "policy_path": gate._FUTU_POLICY_PATH,
        "policy_sha256": gate._FUTU_POLICY_SHA256,
        "policy_overlay_path": gate._FUTU_OVERLAY_PATH,
        "policy_overlay_sha256": gate._FUTU_OVERLAY_SHA256,
        "authority_seed": seed,
        "authority_seed_sha256": authority_seed_sha256,
        "author_app_id": 24680,
        "author_app_slug": "phase5e-gate-author",
        "author_installation_id": 13579,
        "controller_app_id": 98765,
        "controller_app_slug": "phase5e-controller",
        "controller_installation_id": 54321,
        "approved_at": "2026-07-22T04:00:00Z",
    }
    _canonical(repository / gate._EXTERNAL_HANDOFF_PATH, handoff)
    head = _commit(repository, "install external 2C-0 authority")
    return head, handoff


def _repository(tmp_path: Path) -> tuple[Path, str, dict[str, Any], dict[str, Any]]:
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(["git", "-C", str(repository), "init", "-b", "main"], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.name", "Gate Test"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "gate@example.com"],
        check=True,
    )
    shutil.copy2(ROOT / "component-lock.json", repository / "component-lock.json")
    shutil.copy2(ROOT / "pyproject.toml", repository / "pyproject.toml")
    for relative in (
        "plugins/owner-equity-research/.codex-plugin/plugin.json",
        "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md",
        "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md",
        "docs/phase5-completion-overlay-v3.md",
        "scripts/phase5e-futu-market-authority-policy-v1.json",
        "scripts/verify_phase5e2c0_semantic_oracle.py",
    ):
        source = ROOT / relative
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    trust_destination = repository / gate.TRUST_PATH.relative_to(ROOT)
    trust_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(gate.TRUST_PATH, trust_destination)
    base_trust_destination = repository / gate.BASE_TRUST_PATH.relative_to(ROOT)
    signers, signing = _test_receipt_authority()
    base_trust = json.loads(gate.BASE_TRUST_PATH.read_text())
    base_trust["external_feasibility_receipt_authority"]["status"] = "pinned"
    base_trust["external_feasibility_receipt_authority"]["signers"] = signers
    _canonical(base_trust_destination, base_trust)
    gate._RECEIPT_AUTHORITY_STATUS = "pinned"
    gate._RECEIPT_SIGNERS = signers
    global _TEST_RECEIPT_SIGNING
    _TEST_RECEIPT_SIGNING = signing
    protected_behavior_oracle = gate.bootstrap_authority()["audit_policy"][
        "protected_oracle_path"
    ]
    protected_behavior_destination = repository / protected_behavior_oracle
    protected_behavior_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / protected_behavior_oracle, protected_behavior_destination)
    shutil.copytree(ROOT / "schemas", repository / "schemas")
    (repository / "tests").mkdir()
    for protected_test in sorted(gate._CONTROL_PLANE_FROZEN_PATHS):
        if protected_test.startswith("tests/"):
            destination = repository / protected_test
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / protected_test, destination)
    compiler = repository / "src/owner_research/valuation_current_share_compiler.py"
    compiler.parent.mkdir(parents=True)
    shutil.copy2(ROOT / compiler.relative_to(repository), compiler)
    prohibited = [
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
    ]
    predecessor = _state(
        phase="Phase 5E-2B.1-2B",
        status="accepted_closed",
        authorized="Phase 5E-2B.1-2C successor-gate bootstrap",
        prohibited=prohibited,
    )
    _canonical(repository / gate.STATUS_PATH, predecessor)
    base = _commit(repository, "s3")
    authority = gate.bootstrap_authority()
    paths = gate.bundle_paths(authority)
    oracle = (
        "SCHEMA_VERSION = '1.0.0'\n"
        f"GATE_ID = {authority['gate_id']!r}\n"
        f"AUDIT_PROFILE = {authority['audit_policy']['profile_id']!r}\n"
        "ADVERSARIAL_CASE_IDS = ('P5E-GATE-001',)\n"
        "EXPECTED_TEST_NODEIDS = "
        f"{tuple(authority['audit_policy']['expected_added_test_nodeids'])!r}\n"
    ).encode()
    cases = {
        "schema_version": "1.0.0",
        "cases": [
            {
                "case_id": "P5E-GATE-001",
                "expectation": "The candidate oracle remains inert until gate acceptance.",
                "priority": "P0",
            }
        ],
    }
    cases_raw = (json.dumps(cases, indent=2, sort_keys=True) + "\n").encode()
    component = json.loads((repository / "component-lock.json").read_text())
    schema_count, schema_set_sha = gate._schema_set_sha256(repository, base)
    assert schema_count == 43
    pending = authority["pending_gate_state"]
    accepted = authority["accepted_gate_state"]
    successor_pending = authority["successor_pending_state"]
    successor_accepted = authority["successor_accepted_state"]
    bundle = {
        "schema_version": "2.0.0",
        "gate_id": authority["gate_id"],
        "owner_phase": authority["owner_phase"],
        "predecessor_state_fingerprint": hashlib.sha256(
            (json.dumps(predecessor, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest(),
        "gate_bootstrap_branch": authority["bootstrap_branch"],
        "gate_acceptance_branch": authority["acceptance_branch"],
        "gate_bootstrap_diff": authority["gate_bootstrap_diff"],
        "gate_acceptance_diff": authority["gate_acceptance_diff"],
        "successor_implementation_branch": authority["successor_implementation_branch"],
        "successor_acceptance_branch": authority["successor_acceptance_branch"],
        "successor_implementation_diff": authority["successor_implementation_diff"],
        "successor_acceptance_diff": authority["successor_acceptance_diff"],
        "pending_gate_state": pending,
        "accepted_gate_state": accepted,
        "successor_pending_state": successor_pending,
        "successor_accepted_state": successor_accepted,
        "post_successor_closeout": _post_successor_closeout(
            expected_test_count=(
                authority["audit_policy"]["predecessor_test_count"]
                + len(authority["audit_policy"]["expected_added_test_nodeids"])
            )
        ),
        "next_gate_seed": None,
        "audit": {
            "profile_id": authority["audit_policy"]["profile_id"],
            "audit_version": authority["audit_policy"]["audit_version"],
            "protected_oracle_path": authority["audit_policy"][
                "protected_oracle_path"
            ],
            "protected_oracle_sha256": authority["audit_policy"][
                "protected_oracle_sha256"
            ],
            "predecessor_test_count": authority["audit_policy"]["predecessor_test_count"],
            "predecessor_nodeid_sha256": authority["audit_policy"][
                "predecessor_nodeid_sha256"
            ],
            "expected_added_test_nodeids": authority["audit_policy"][
                "expected_added_test_nodeids"
            ],
            "expected_check_ids": authority["audit_policy"]["mandatory_check_ids"],
        },
        "semantic_oracle": {"path": paths["oracle"], "sha256": hashlib.sha256(oracle).hexdigest()},
        "adversarial_cases": {
            "path": paths["cases"],
            "sha256": hashlib.sha256(cases_raw).hexdigest(),
        },
        "frozen_paths": authority["frozen_paths"],
        "forbidden_prefixes": authority["forbidden_prefixes"],
        "component_lock_sha256": hashlib.sha256(
            (repository / "component-lock.json").read_bytes()
        ).hexdigest(),
        "public_schema_count": 43,
        "public_schema_set_sha256": schema_set_sha,
        "kernel_release": {
            "tag": gate._KERNEL["tag"],
            "tag_object": gate._KERNEL["tag_object"],
            "commit": gate._KERNEL["commit"],
            "wheel_sha256": gate._KERNEL["wheel_sha256"],
            "schema_sha256": component["valuation_kernel"]["public_schema_sha256"],
        },
        "execution_mode": "protected_base_only_after_gate_acceptance",
        "successor_production_authorized_by_bundle": False,
    }
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", authority["bootstrap_branch"]],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    _canonical(repository / gate.STATUS_PATH, pending)
    oracle_path = repository / paths["oracle"]
    oracle_path.parent.mkdir(parents=True, exist_ok=True)
    oracle_path.write_bytes(oracle)
    cases_path = repository / paths["cases"]
    cases_path.write_bytes(cases_raw)
    _canonical(repository / paths["bundle"], bundle)
    return repository, base, bundle, predecessor


def _accepted_gate(
    tmp_path: Path,
) -> tuple[Path, dict[str, Any], str, str]:
    repository, _, bundle, _ = _repository(tmp_path)
    bootstrap_head = _commit(repository, "bootstrap")
    bootstrap_merge = _merge_to_main(
        repository,
        bundle["gate_bootstrap_branch"],
        "merge bootstrap",
    )
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", bundle["gate_acceptance_branch"]],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    _canonical(repository / gate.STATUS_PATH, bundle["accepted_gate_state"])
    _canonical(
        repository / gate.bundle_paths(gate.bootstrap_authority())["closeout"],
        _closeout(
            gate_id=bundle["gate_id"],
            implementation_head=bootstrap_head,
            implementation_merge=bootstrap_merge,
            implementation_tree=_git(repository, "rev-parse", f"{bootstrap_merge}^{{tree}}"),
            audit_profile="phase5e-successor-gate-bootstrap",
            audit_version="2.3.2.3.4.1",
            test_count=bundle["audit"]["predecessor_test_count"],
        ),
    )
    gate_acceptance_head = _commit(repository, "gate acceptance")
    gate_acceptance_merge = _merge_to_main(
        repository,
        bundle["gate_acceptance_branch"],
        "merge gate acceptance",
    )
    assert gate.state_id(repository, gate_acceptance_merge) == "g2"
    return repository, bundle, gate_acceptance_head, gate_acceptance_merge


def test_bootstrap_accepts_exact_inert_bundle_without_executing_oracle(tmp_path: Path) -> None:
    repository, base, bundle, _ = _repository(tmp_path)
    head = _commit(repository, "bootstrap")
    gate.verify_bootstrap_transition(
        repository=repository,
        base=base,
        head=head,
        event=_event(base, head, bundle["gate_bootstrap_branch"]),
        repository_slug=SLUG,
    )
    oracle = _run_independent_oracle(
        repository,
        controller_ref=base,
        candidate_ref=head,
    )
    assert oracle.returncode == 0, oracle.stdout


@pytest.mark.parametrize(
    "mutation",
    (
        "unknown_field",
        "kernel_commit",
        "execution_mode",
        "production_authorized",
        "predecessor_fingerprint",
        "unexpected_next_seed",
    ),
)
def test_independent_oracle_rejects_resigned_security_mutations(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository, base, bundle, _ = _repository(tmp_path)
    path = repository / gate.bundle_paths(gate.bootstrap_authority())["bundle"]
    if mutation == "unknown_field":
        bundle["candidate_extension"] = True
    elif mutation == "kernel_commit":
        bundle["kernel_release"]["commit"] = "0" * 40
    elif mutation == "execution_mode":
        bundle["execution_mode"] = "candidate_executes_itself"
    elif mutation == "production_authorized":
        bundle["successor_production_authorized_by_bundle"] = True
    elif mutation == "predecessor_fingerprint":
        bundle["predecessor_state_fingerprint"] = "0" * 64
    else:
        bundle["next_gate_seed"] = _next_gate_seed(
            bundle["audit"]["predecessor_test_count"]
            + len(bundle["audit"]["expected_added_test_nodeids"])
        )
    _canonical(path, bundle)
    head = _commit(repository, mutation)
    oracle = _run_independent_oracle(
        repository,
        controller_ref=base,
        candidate_ref=head,
    )
    assert oracle.returncode != 0


def test_independent_oracle_reads_commit_blobs_not_dirty_worktree(tmp_path: Path) -> None:
    repository, base, _, _ = _repository(tmp_path)
    head = _commit(repository, "bootstrap")
    (repository / gate.bundle_paths(gate.bootstrap_authority())["oracle"]).write_text(
        "raise SystemExit(0)\n"
    )
    oracle = _run_independent_oracle(
        repository,
        controller_ref=base,
        candidate_ref=head,
    )
    assert oracle.returncode == 0, oracle.stdout


def test_independent_oracle_requires_full_commit_ids(tmp_path: Path) -> None:
    repository, base, _, _ = _repository(tmp_path)
    _commit(repository, "bootstrap")
    oracle = _run_independent_oracle(
        repository,
        controller_ref=base,
        candidate_ref="HEAD",
    )
    assert oracle.returncode != 0


def test_bootstrap_rejects_an_extra_candidate_path(tmp_path: Path) -> None:
    repository, base, bundle, _ = _repository(tmp_path)
    (repository / "src/escape.py").write_text("VALUE = 1\n")
    head = _commit(repository, "escape")
    with pytest.raises(SystemExit, match="exact inert-data boundary"):
        gate.verify_bootstrap_transition(
            repository=repository,
            base=base,
            head=head,
            event=_event(base, head, bundle["gate_bootstrap_branch"]),
            repository_slug=SLUG,
        )


@pytest.mark.parametrize(
    "attack",
    ("oracle_hash", "cases_duplicate", "forbidden_ast", "component_lock", "schema"),
)
def test_bundle_validation_fails_closed(tmp_path: Path, attack: str) -> None:
    repository, _, bundle, _ = _repository(tmp_path)
    paths = gate.bundle_paths(gate.bootstrap_authority())
    if attack == "oracle_hash":
        bundle["semantic_oracle"]["sha256"] = "f" * 64
        _canonical(repository / paths["bundle"], bundle)
    elif attack == "cases_duplicate":
        cases = {
            "schema_version": "1.0.0",
            "cases": [
                {"case_id": "same", "priority": "P0", "expectation": "one"},
                {"case_id": "same", "priority": "P1", "expectation": "two"},
            ],
        }
        raw = (json.dumps(cases, indent=2, sort_keys=True) + "\n").encode()
        (repository / paths["cases"]).write_bytes(raw)
        bundle["adversarial_cases"]["sha256"] = hashlib.sha256(raw).hexdigest()
        _canonical(repository / paths["bundle"], bundle)
    elif attack == "forbidden_ast":
        raw = b"import socket\n"
        (repository / paths["oracle"]).write_bytes(raw)
        bundle["semantic_oracle"]["sha256"] = hashlib.sha256(raw).hexdigest()
        _canonical(repository / paths["bundle"], bundle)
    elif attack == "component_lock":
        payload = json.loads((repository / "component-lock.json").read_text())
        payload["plugin_version"] = "attacker"
        _canonical(repository / "component-lock.json", payload)
    else:
        (repository / "schemas/market-reference-snapshot.schema.json").write_text("{}\n")
    ref = _commit(repository, attack)
    with pytest.raises(SystemExit):
        gate.validate_bundle(repository, ref)


def test_bundle_cannot_rebind_the_protected_behavior_oracle(tmp_path: Path) -> None:
    repository, _, bundle, _ = _repository(tmp_path)
    structural = ROOT / "scripts/verify_phase5e_successor_gate_oracle.py"
    bundle["audit"]["protected_oracle_path"] = str(structural.relative_to(ROOT))
    bundle["audit"]["protected_oracle_sha256"] = hashlib.sha256(
        structural.read_bytes()
    ).hexdigest()
    _canonical(
        repository / gate.bundle_paths(gate.bootstrap_authority())["bundle"],
        bundle,
    )
    ref = _commit(repository, "rebind protected behavior oracle")
    with pytest.raises(SystemExit, match="audit profile"):
        gate.validate_bundle(repository, ref)


def test_protected_behavior_oracle_rejects_candidate_local_v2_stubs(
    tmp_path: Path,
) -> None:
    compiler = tmp_path / behavior_oracle.COMPILER
    compiler.parent.mkdir(parents=True)
    compiler.write_text(
        "\n".join(
            (
                "class CorporateActionCoverageLedgerV2: pass",
                "class CurrentShareBundleEvidenceClosure: pass",
                "class CurrentShareEvidenceClosureV2: pass",
                "class GroupBoundClaimTransitionReconciliation: pass",
                "def derive_current_share_evidence_closure_v2(*, graph, grouping_result, "
                "opening_share_fact, security_compilation_result, claim_control_authority, "
                "quote_date, data_cutoff_date):",
                "    return None",
                "def compile_quote_date_current_common_shares():",
                "    return derive_current_share_evidence_closure_v2(",
                "        graph=None, grouping_result=None, opening_share_fact=None,",
                "        security_compilation_result=None, claim_control_authority=None,",
                "        quote_date='2026-07-10', data_cutoff_date='2026-07-10')",
                "",
            )
        ),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="protected V2 closure surface"):
        behavior_oracle.verify_surface(tmp_path)


def test_gate_bundle_rejects_path_traversal_even_with_a_resigned_payload(tmp_path: Path) -> None:
    repository, _, bundle, _ = _repository(tmp_path)
    paths = gate.bundle_paths(gate.bootstrap_authority())
    bundle["successor_implementation_diff"]["../escape.py"] = "A"
    _canonical(repository / paths["bundle"], bundle)
    ref = _commit(repository, "traversal")
    with pytest.raises(SystemExit, match="fixed Schema|identity policy"):
        gate.validate_bundle(repository, ref)


def test_gate_state_progresses_only_through_acceptance(tmp_path: Path) -> None:
    repository, base, bundle, _ = _repository(tmp_path)
    bootstrap_head = _commit(repository, "bootstrap")
    assert gate.state_id(repository, bootstrap_head) == "g1"
    bootstrap_merge = _merge_to_main(
        repository,
        bundle["gate_bootstrap_branch"],
        "merge bootstrap",
    )
    assert gate.state_id(repository, bootstrap_merge) == "g1"
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", bundle["gate_acceptance_branch"]],
        check=True,
    )
    _canonical(repository / gate.STATUS_PATH, bundle["accepted_gate_state"])
    closeout = _closeout(
        gate_id=bundle["gate_id"],
        implementation_head=bootstrap_head,
        implementation_merge=bootstrap_merge,
        implementation_tree=_git(repository, "rev-parse", f"{bootstrap_merge}^{{tree}}"),
        audit_profile="phase5e-successor-gate-bootstrap",
        audit_version="2.3.2.3.4.1",
        test_count=bundle["audit"]["predecessor_test_count"],
    )
    _canonical(repository / gate.bundle_paths(gate.bootstrap_authority())["closeout"], closeout)
    accepted = _commit(repository, "acceptance")
    calls: list[str] = []
    gate.verify_acceptance_transition(
        repository=repository,
        base=bootstrap_merge,
        head=accepted,
        event=_event(bootstrap_merge, accepted, bundle["gate_acceptance_branch"]),
        repository_slug=SLUG,
        require_remote=True,
        remote_verifier=lambda **kwargs: calls.append(kwargs["transition"]),
    )
    assert calls == ["gate_acceptance"]
    assert gate.state_id(repository, accepted) == "g2"
    assert base != accepted


def test_bundle_cannot_self_authorize_phase9_or_weaken_frozen_roots(tmp_path: Path) -> None:
    repository, _, bundle, _ = _repository(tmp_path)
    paths = gate.bundle_paths(gate.bootstrap_authority())
    bundle["accepted_gate_state"]["authorized_next"] = ["Phase 9 production"]
    bundle["accepted_gate_state"]["prohibited"] = []
    bundle["frozen_paths"] = []
    bundle["forbidden_prefixes"] = []
    _canonical(repository / paths["bundle"], bundle)
    ref = _commit(repository, "candidate self authorization")
    with pytest.raises(SystemExit):
        gate.validate_bundle(repository, ref)


def _next_authority_case() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    authority = gate.bootstrap_authority()
    authority["next_owner_phase"] = "Phase 5E-2C-0"
    post = _post_successor_closeout(
        expected_test_count=(
            authority["audit_policy"]["predecessor_test_count"]
            + len(authority["audit_policy"]["expected_added_test_nodeids"])
        )
    )
    post["accepted_state"]["authorized_next"] = [
        "Phase 5E-2C-0 successor-gate bootstrap"
    ]
    seed = _next_gate_seed(post["expected_test_count"])
    return authority, post, seed


def test_next_gate_seed_must_be_pinned_by_predecessor_authority() -> None:
    authority, post, seed = _next_authority_case()
    authority["next_gate_authority_sha256"] = None
    with pytest.raises(SystemExit, match="unpinned"):
        gate._validate_next_gate_seed(
            seed,
            authority=authority,
            post_successor_closeout=post,
        )


def test_next_gate_seed_must_match_protected_authority_hash() -> None:
    authority, post, seed = _next_authority_case()
    authority["next_gate_authority_sha256"] = "0" * 64
    with pytest.raises(SystemExit, match="protected authority hash"):
        gate._validate_next_gate_seed(
            seed,
            authority=authority,
            post_successor_closeout=post,
        )


@pytest.mark.parametrize(
    "omission",
    ("predecessor_frozen", "predecessor_governed", "forbidden_prefix"),
)
def test_next_gate_seed_must_refreeze_every_predecessor_surface(
    omission: str,
) -> None:
    authority, post, seed = _next_authority_case()
    if omission == "predecessor_frozen":
        seed["frozen_paths"].remove("component-lock.json")
    elif omission == "predecessor_governed":
        governed = gate.authority_governed_paths(
            authority,
            post_successor_closeout=post,
        )
        released = next(path for path in sorted(governed) if path in seed["frozen_paths"])
        seed["frozen_paths"].remove(released)
    else:
        seed["forbidden_prefixes"].remove("plugins")
    authority["next_gate_authority_sha256"] = gate._canonical_payload_sha256(seed)
    with pytest.raises(SystemExit, match="reuses authority|malformed"):
        gate._validate_next_gate_seed(
            seed,
            authority=authority,
            post_successor_closeout=post,
        )


def test_nonterminal_authority_cannot_end_chain_with_null_seed() -> None:
    authority, post, _ = _next_authority_case()
    authority["next_gate_authority_sha256"] = None
    post["accepted_state"]["authorized_next"] = []
    with pytest.raises(SystemExit, match="nonterminal"):
        gate._validate_next_gate_seed(
            None,
            authority=authority,
            post_successor_closeout=post,
        )


def test_external_feasibility_boundary_requires_no_repository_seed() -> None:
    authority = gate.bootstrap_authority()
    post = _post_successor_closeout(
        expected_test_count=(
            authority["audit_policy"]["predecessor_test_count"]
            + len(authority["audit_policy"]["expected_added_test_nodeids"])
        )
    )
    assert (
        gate._validate_next_gate_seed(
            None,
            authority=authority,
            post_successor_closeout=post,
        )
        is None
    )
    assert (
        independent_gate_oracle._next_seed(
            None,
            authority=authority,
            post=post,
        )
        is None
    )


def test_terminal_authority_has_no_next_seed_and_does_not_crash() -> None:
    authority = {
        "owner_phase": "Phase 5F-4",
        "next_owner_phase": None,
        "next_gate_authority_sha256": None,
    }
    post = {"accepted_state": {"authorized_next": []}}
    assert (
        gate._validate_next_gate_seed(
            None,
            authority=authority,
            post_successor_closeout=post,
        )
        is None
    )
    assert gate._phase_is_prohibited(None, ["Phase 6"]) is False


def test_later_authority_cannot_reuse_prior_production_path() -> None:
    authority, post, seed = _next_authority_case()
    prior_source = next(
        path
        for path in authority["successor_implementation_diff"]
        if path != gate.STATUS_PATH and path.startswith("src/")
    )
    seed = copy.deepcopy(seed)
    seed["successor_implementation_diff"][prior_source] = "M"
    authority["next_gate_authority_sha256"] = hashlib.sha256(
        (
            json.dumps(seed, allow_nan=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode()
    ).hexdigest()
    with pytest.raises(SystemExit, match="reuses authority"):
        gate._validate_next_gate_seed(
            seed,
            authority=authority,
            post_successor_closeout=post,
        )


def test_later_authority_cannot_reuse_prior_test_path() -> None:
    authority, post, seed = _next_authority_case()
    prior_test = next(
        path
        for path in authority["successor_implementation_diff"]
        if path.startswith("tests/test_")
    )
    seed = copy.deepcopy(seed)
    seed["successor_implementation_diff"][prior_test] = "M"
    authority["next_gate_authority_sha256"] = hashlib.sha256(
        (
            json.dumps(seed, allow_nan=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode()
    ).hexdigest()
    with pytest.raises(SystemExit, match="reuses authority"):
        gate._validate_next_gate_seed(
            seed,
            authority=authority,
            post_successor_closeout=post,
        )


def test_bootstrap_cannot_rewrite_phase_history(tmp_path: Path) -> None:
    repository, base, bundle, _ = _repository(tmp_path)
    status_path = repository / gate.STATUS_PATH
    status = json.loads(status_path.read_text())
    status["prior_closeouts"] = [{"attacker": True}]
    _canonical(status_path, status)
    head = _commit(repository, "rewrite history")
    with pytest.raises(SystemExit, match="pending machine state"):
        gate.verify_bootstrap_transition(
            repository=repository,
            base=base,
            head=head,
            event=_event(base, head, bundle["gate_bootstrap_branch"]),
            repository_slug=SLUG,
        )


@pytest.mark.parametrize(
    "oracle",
    (
        b"import os\ndef main():\n    return os.system('true')\n",
        b"import importlib\ndef main():\n    return importlib.import_module('subprocess')\n",
        b"while True:\n    pass\n",
        b"def main():\n    return __builtins__\n",
        b"def main() -> int:\n    return 0\n",
        b"if True:\n    raise SystemExit(0)\n",
        b"f = open\nf('/scratch/escape', 'w')\n",
        b"import sys\ngetattr(sys.modules['os'], 'system')('true')\n",
    ),
)
def test_candidate_oracle_cannot_expand_its_authority(tmp_path: Path, oracle: bytes) -> None:
    repository, _, bundle, _ = _repository(tmp_path)
    paths = gate.bundle_paths(gate.bootstrap_authority())
    (repository / paths["oracle"]).write_bytes(oracle)
    bundle["semantic_oracle"]["sha256"] = hashlib.sha256(oracle).hexdigest()
    _canonical(repository / paths["bundle"], bundle)
    ref = _commit(repository, "unsafe oracle")
    with pytest.raises(SystemExit, match="oracle"):
        gate.validate_bundle(repository, ref)


def test_gate_acceptance_requires_remote_replay(tmp_path: Path) -> None:
    repository, _, bundle, _ = _repository(tmp_path)
    bootstrap_head = _commit(repository, "bootstrap")
    bootstrap_merge = _merge_to_main(
        repository,
        bundle["gate_bootstrap_branch"],
        "merge bootstrap",
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "checkout",
            "-b",
            bundle["gate_acceptance_branch"],
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    _canonical(repository / gate.STATUS_PATH, bundle["accepted_gate_state"])
    _canonical(
        repository / gate.bundle_paths(gate.bootstrap_authority())["closeout"],
        _closeout(
            gate_id=bundle["gate_id"],
            implementation_head=bootstrap_head,
            implementation_merge=bootstrap_merge,
            implementation_tree=_git(
                repository,
                "rev-parse",
                f"{bootstrap_merge}^{{tree}}",
            ),
            audit_profile="phase5e-successor-gate-bootstrap",
            audit_version="2.3.2.3.4.1",
            test_count=bundle["audit"]["predecessor_test_count"],
        ),
    )
    gate_acceptance_head = _commit(repository, "gate acceptance")
    with pytest.raises(SystemExit, match="remote evidence replay"):
        gate.verify_acceptance_transition(
            repository=repository,
            base=bootstrap_merge,
            head=gate_acceptance_head,
            event=_event(bootstrap_merge, gate_acceptance_head, bundle["gate_acceptance_branch"]),
            repository_slug=SLUG,
        )


def _g5_repository(
    tmp_path: Path,
) -> tuple[Path, dict[str, Any], str, dict[str, Any]]:
    repository, bundle, _, accepted_gate_merge = _accepted_gate(tmp_path)
    g2_profile = audit_profiles.resolve_controller_audit_profile(
        repository,
        accepted_gate_merge,
    )
    assert (g2_profile.gate_stage, g2_profile.gate_depth, g2_profile.profile_kind) == (
        "g2",
        0,
        "successor_dynamic",
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "checkout",
            "-b",
            bundle["successor_implementation_branch"],
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    compiler = repository / "src/owner_research/valuation_current_share_compiler.py"
    compiler.write_text(compiler.read_text() + "\n# successor fixture\n")
    test_path = repository / "tests/test_phase5e2b12c_coverage_claim_closure.py"
    test_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.write_text("def test_exact_recursive_closure():\n    assert True\n")
    base_status = json.loads((repository / gate.STATUS_PATH).read_text())
    _canonical(
        repository / gate.STATUS_PATH,
        gate._expected_status(base_status, bundle["successor_pending_state"]),
    )
    implementation_head = _commit(repository, "successor implementation")
    gate.verify_successor_implementation(
        repository=repository,
        base=accepted_gate_merge,
        head=implementation_head,
        event=_event(
            accepted_gate_merge,
            implementation_head,
            bundle["successor_implementation_branch"],
        ),
        repository_slug=SLUG,
    )
    implementation_merge = _merge_to_main(
        repository,
        bundle["successor_implementation_branch"],
        "merge successor implementation",
    )
    assert gate.state_id(repository, implementation_merge) == "g3"
    g3_profile = audit_profiles.resolve_controller_audit_profile(
        repository,
        implementation_merge,
    )
    assert (g3_profile.gate_stage, g3_profile.gate_depth, g3_profile.profile_kind) == (
        "g3",
        0,
        "successor_dynamic",
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "checkout",
            "-b",
            bundle["successor_acceptance_branch"],
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    pending_status = json.loads((repository / gate.STATUS_PATH).read_text())
    _canonical(
        repository / gate.STATUS_PATH,
        gate._expected_status(pending_status, bundle["successor_accepted_state"]),
    )
    _canonical(
        repository / gate.bundle_paths(gate.bootstrap_authority())["successor_closeout"],
        _closeout(
            gate_id=bundle["gate_id"],
            implementation_head=implementation_head,
            implementation_merge=implementation_merge,
            implementation_tree=_git(
                repository,
                "rev-parse",
                f"{implementation_merge}^{{tree}}",
            ),
            audit_profile=bundle["audit"]["profile_id"],
            audit_version=bundle["audit"]["audit_version"],
            test_count=(
                bundle["audit"]["predecessor_test_count"]
                + len(bundle["audit"]["expected_added_test_nodeids"])
            ),
        ),
    )
    acceptance_head = _commit(repository, "successor acceptance")
    calls: list[str] = []
    gate.verify_successor_acceptance_transition(
        repository=repository,
        base=implementation_merge,
        head=acceptance_head,
        event=_event(
            implementation_merge,
            acceptance_head,
            bundle["successor_acceptance_branch"],
        ),
        repository_slug=SLUG,
        require_remote=True,
        remote_verifier=lambda **kwargs: calls.append(kwargs["transition"]),
    )
    assert calls == ["successor_acceptance"]
    assert gate.state_id(repository, acceptance_head) == "g4"
    acceptance_merge = _merge_to_main(
        repository,
        bundle["successor_acceptance_branch"],
        "merge successor acceptance",
    )
    assert gate.state_id(repository, acceptance_merge) == "g4"
    g4_profile = audit_profiles.resolve_controller_audit_profile(
        repository,
        acceptance_merge,
    )
    assert (g4_profile.gate_stage, g4_profile.gate_depth, g4_profile.profile_kind) == (
        "g4",
        0,
        "successor_transition",
    )

    post = bundle["post_successor_closeout"]
    subprocess.run(
        ["git", "-C", str(repository), "checkout", "-b", post["branch"]],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    _canonical(repository / gate.STATUS_PATH, post["accepted_state"])
    _canonical(
        repository / post["closeout_path"],
        _closeout(
            gate_id=bundle["gate_id"],
            implementation_head=acceptance_head,
            implementation_merge=acceptance_merge,
            implementation_tree=_git(
                repository,
                "rev-parse",
                f"{acceptance_merge}^{{tree}}",
            ),
            audit_profile=post["implementation_audit_profile"],
            audit_version=post["implementation_audit_version"],
            test_count=post["expected_test_count"],
        ),
    )
    post_head = _commit(repository, "total corrective closeout")
    gate.verify_post_successor_closeout_transition(
        repository=repository,
        base=acceptance_merge,
        head=post_head,
        event=_event(acceptance_merge, post_head, post["branch"]),
        repository_slug=SLUG,
        require_remote=True,
        remote_verifier=lambda **kwargs: calls.append(kwargs["transition"]),
    )
    assert calls == ["successor_acceptance", "post_successor_closeout"]
    post_merge = _merge_to_main(repository, post["branch"], "merge total closeout")
    position = gate.resolve_gate_position(repository, post_merge)
    assert position.stage == "g5"
    assert position.gate_id == bundle["gate_id"]
    g5_profile = audit_profiles.resolve_controller_audit_profile(repository, post_merge)
    assert (g5_profile.gate_stage, g5_profile.gate_depth, g5_profile.profile_kind) == (
        "g5-external-feasibility",
        0,
        "external_feasibility",
    )
    assert g5_profile.expected_check_ids == (
        audit_profiles._COMMON_CHECK_IDS | audit_profiles._PHASE5E_SUCCESSOR_CHECK_IDS
    )
    assert bundle["next_gate_seed"] is None
    assert post["accepted_state"]["authorized_next"] == [
        "Phase 5E-2C-P Futu feasibility gate"
    ]
    return repository, bundle, post_merge, post


def test_successor_state_progresses_through_g5_and_stops_at_external_feasibility_gate(
    tmp_path: Path,
) -> None:
    repository, bundle, post_merge, post = _g5_repository(tmp_path)
    assert gate.resolve_gate_position(repository, post_merge).stage == "g5"
    assert bundle["next_gate_seed"] is None
    assert post["accepted_state"]["authorized_next"] == [
        "Phase 5E-2C-P Futu feasibility gate"
    ]


def test_external_controller_handoff_advances_exactly_to_2c0_g1(tmp_path: Path) -> None:
    repository, bundle, _, _ = _g5_repository(tmp_path)
    head, handoff = _write_external_handoff_candidate(
        repository,
        base=_git(repository, "rev-parse", "HEAD"),
        bundle=bundle,
    )
    base = handoff["predecessor_commit"]
    gate.verify_external_controller_handoff_transition(
        repository=repository,
        base=base,
        head=head,
        event=_event(base, head, gate._EXTERNAL_CONTROLLER_BRANCH),
        repository_slug=SLUG,
    )
    position = gate.resolve_gate_position(repository, head)
    assert (position.gate_id, position.depth, position.stage) == ("phase5e2c0", 1, "g1")
    independent = _run_independent_oracle(
        repository,
        controller_ref=base,
        candidate_ref=head,
    )
    assert independent.returncode == 0, independent.stdout


def test_external_controller_handoff_rejects_a_stale_predecessor(tmp_path: Path) -> None:
    repository, bundle, g5_base, _ = _g5_repository(tmp_path)
    head, handoff = _write_external_handoff_candidate(
        repository,
        base=g5_base,
        bundle=bundle,
    )
    assert handoff["predecessor_commit"] != g5_base
    with pytest.raises(SystemExit, match="unique direct candidate commit"):
        gate.verify_external_controller_handoff_transition(
            repository=repository,
            base=g5_base,
            head=head,
            event=_event(g5_base, head, gate._EXTERNAL_CONTROLLER_BRANCH),
            repository_slug=SLUG,
        )


def test_external_receipts_reject_impossible_calendar_dates() -> None:
    assert gate._utc_timestamp("2026-02-31T00:00:00Z") is None


def test_external_receipts_are_signed_bound_ordered_and_time_limited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signers, signing = _test_receipt_authority()
    expected = _receipt_expected_context()
    monkeypatch.setattr(gate, "_RECEIPT_AUTHORITY_STATUS", "pinned")
    monkeypatch.setattr(gate, "_RECEIPT_SIGNERS", signers)
    monkeypatch.setattr(
        independent_gate_oracle,
        "_PROTECTED_EXTERNAL_TRUST",
        {
            "external_feasibility_receipt_authority": {
                "algorithm": "ed25519",
                "domain": gate._RECEIPT_DOMAIN,
                "max_validity_seconds": gate._RECEIPT_MAX_VALIDITY_SECONDS,
                "required_order": list(gate._EXTERNAL_RECEIPT_KINDS),
                "condition_coverage": {
                    kind: list(values)
                    for kind, values in gate._EXTERNAL_CONDITION_COVERAGE.items()
                },
                "signers": signers,
                "status": "pinned",
            }
        },
    )
    receipts = _signed_receipt_fixture(
        expected=expected,
        signers=signers,
        signing=signing,
    )

    accepted = gate._external_receipts(
        receipts,
        expected=expected,
        approved_at="2026-07-22T04:00:00Z",
    )
    assert list(accepted) == receipts
    assert list(
        independent_gate_oracle._external_receipts(
            receipts,
            expected=expected,
            approved_at="2026-07-22T04:00:00Z",
        )
    ) == receipts

    wrong_context = copy.deepcopy(receipts)
    wrong_context[0]["payload"]["predecessor_commit"] = "0" * 40
    wrong_context[0]["signature_hex"] = signing["legal"](
        gate._receipt_payload_bytes(wrong_context[0]["payload"])
    )
    with pytest.raises(SystemExit, match="payload is malformed"):
        gate._external_receipts(
            wrong_context,
            expected=expected,
            approved_at="2026-07-22T04:00:00Z",
        )
    with pytest.raises(SystemExit, match="payload is malformed"):
        independent_gate_oracle._external_receipts(
            wrong_context,
            expected=expected,
            approved_at="2026-07-22T04:00:00Z",
        )

    with pytest.raises(SystemExit, match="time bound"):
        gate._external_receipts(
            receipts,
            expected=expected,
            approved_at="2026-07-23T00:00:01Z",
        )

    with pytest.raises(SystemExit, match="payload is malformed"):
        gate._external_receipts(
            list(reversed(receipts)),
            expected=expected,
            approved_at="2026-07-22T04:00:00Z",
        )

    for field, value in (
        ("sequence", True),
        ("repository_id", 1312436919.0),
        ("feasibility_conditions", ["raw_protobuf_s2c_bytes_are_stably_capturable"]),
    ):
        malformed = copy.deepcopy(receipts)
        malformed[0]["payload"][field] = value
        malformed[0]["signature_hex"] = signing["legal"](
            gate._receipt_payload_bytes(malformed[0]["payload"])
        )
        with pytest.raises(SystemExit, match="payload is malformed"):
            gate._external_receipts(
                malformed,
                expected=expected,
                approved_at="2026-07-22T04:00:00Z",
            )
        with pytest.raises(SystemExit, match="payload is malformed"):
            independent_gate_oracle._external_receipts(
                malformed,
                expected=expected,
                approved_at="2026-07-22T04:00:00Z",
            )


def test_external_receipt_ed25519_rejects_identity_point_forgery() -> None:
    identities = (
        b"\x01" + b"\x00" * 31,
        b"\x01" + b"\x00" * 30 + b"\x80",
    )
    for identity_bytes in identities:
        identity = identity_bytes.hex()
        forged_signature = identity + (b"\x00" * 32).hex()
        assert not gate._verify_ed25519(identity, forged_signature, b"forged")
        assert not independent_gate_oracle._verify_ed25519(
            identity,
            forged_signature,
            b"forged",
        )


def test_external_receipt_ed25519_matches_rfc8032_vector_one() -> None:
    public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    signature = (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert gate._verify_ed25519(public_key, signature, b"")
    assert independent_gate_oracle._verify_ed25519(public_key, signature, b"")
    assert not gate._verify_ed25519(public_key, signature, b"changed")
    assert not independent_gate_oracle._verify_ed25519(
        public_key,
        signature,
        b"changed",
    )


def test_external_receipt_ed25519_rejects_low_order_encodings() -> None:
    encodings = (
        b"\x00" * 32,
        (gate._ED_Q - 1).to_bytes(32, "little"),
    )
    for encoded in encodings:
        public_key = encoded.hex()
        forged_signature = encoded.hex() + (b"\x00" * 32).hex()
        assert not gate._verify_ed25519(public_key, forged_signature, b"forged")
        assert not independent_gate_oracle._verify_ed25519(
            public_key,
            forged_signature,
            b"forged",
        )


def test_external_seed_rejects_any_unapproved_2c0_production_path(
    tmp_path: Path,
) -> None:
    repository, bundle, _, _ = _g5_repository(tmp_path)
    _, handoff = _write_external_handoff_candidate(
        repository,
        base=_git(repository, "rev-parse", "HEAD"),
        bundle=bundle,
    )
    seed = handoff["authority_seed"]
    gate._validate_external_authority_seed(
        seed,
        authority=gate.bootstrap_authority(),
        post_successor_closeout=bundle["post_successor_closeout"],
    )

    for path, expected_error in (
        (
            "src/owner_research/futu_trading_and_kernel_runner.py",
            "exact immediate 2C-0 gate",
        ),
        (
            gate._EXTERNAL_PROTECTED_ORACLE_PATH,
            "authority seed is malformed",
        ),
    ):
        mutated = copy.deepcopy(seed)
        mutated["successor_implementation_diff"][path] = "A" if path not in seed[
            "successor_implementation_diff"
        ] else "M"
        with pytest.raises(SystemExit, match=expected_error):
            gate._validate_external_authority_seed(
                mutated,
                authority=gate.bootstrap_authority(),
                post_successor_closeout=bundle["post_successor_closeout"],
            )


def test_external_2c0_seed_cannot_pre_authorize_2c1_authority(
    tmp_path: Path,
) -> None:
    repository, bundle, _, _ = _g5_repository(tmp_path)
    _, handoff = _write_external_handoff_candidate(
        repository,
        base=_git(repository, "rev-parse", "HEAD"),
        bundle=bundle,
    )
    seed = handoff["authority_seed"]
    assert seed["next_gate_authority_sha256"] is None

    mutated = copy.deepcopy(seed)
    attacker_chosen_next = _generic_future_authority(
        gate_id="phase5e2c1-attacker",
        owner_phase="Phase 5E-2C-1",
        next_owner_phase="Phase 5E-2C-2",
        predecessor_test_count=bundle["post_successor_closeout"]["expected_test_count"] + 1,
    )
    mutated["next_gate_authority_sha256"] = gate._canonical_payload_sha256(
        attacker_chosen_next
    )
    with pytest.raises(SystemExit, match="exact immediate 2C-0 gate"):
        gate._validate_external_authority_seed(
            mutated,
            authority=gate.bootstrap_authority(),
            post_successor_closeout=bundle["post_successor_closeout"],
        )


def test_2c0_total_closeout_is_a_sealed_controller_reauthorization_boundary() -> None:
    authority = _next_gate_seed(100)
    post = {"accepted_state": {"authorized_next": []}}
    assert authority["owner_phase"] == gate._EXTERNAL_TARGET_PHASE
    assert authority["next_gate_authority_sha256"] is None
    assert (
        gate._validate_next_gate_seed(
            None,
            authority=authority,
            post_successor_closeout=post,
        )
        is None
    )


@pytest.mark.parametrize("conflict_kind", ("frozen", "forbidden"))
def test_production_and_independent_authority_reject_own_control_plane_conflicts(
    conflict_kind: str,
) -> None:
    authority = _generic_future_authority(
        gate_id="phase5e2c1",
        owner_phase="Phase 5E-2C-1",
        next_owner_phase="Phase 5E-2C-2",
        predecessor_test_count=100,
    )
    implementation_path = next(
        path
        for path in authority["successor_implementation_diff"]
        if path != gate.STATUS_PATH
    )
    if conflict_kind == "frozen":
        authority["frozen_paths"] = sorted(
            {*authority["frozen_paths"], implementation_path}
        )
    else:
        authority["forbidden_prefixes"] = sorted(
            {*authority["forbidden_prefixes"], implementation_path.rsplit("/", 1)[0]}
        )
    with pytest.raises(RuntimeError, match="own control plane"):
        gate._validate_authority(copy.deepcopy(authority))
    with pytest.raises(SystemExit, match="weakens its control plane"):
        independent_gate_oracle._authority(copy.deepcopy(authority))


def test_dynamic_profile_requires_one_exact_protected_oracle_identity() -> None:
    base = {
        "profile_id": "phase5e-test",
        "phase": "Phase 5E test",
        "audit_version": "9.9.9",
        "expected_check_ids": frozenset({"check"}),
        "expected_test_count": 1,
        "predecessor_test_count": 1,
        "predecessor_nodeid_sha256": "a" * 64,
        "expected_added_test_nodeids": (),
        "profile_kind": "successor_dynamic",
        "gate_id": "gate",
        "gate_depth": 1,
        "gate_stage": "g2",
    }
    with pytest.raises(ValueError, match="protected semantic oracle identity"):
        audit_profiles._dynamic_profile(
            **base,
            policy={"protected_oracle_path": "scripts/oracle.py"},
        )
    profile = audit_profiles._dynamic_profile(
        **base,
        policy={
            "protected_oracle_path": "scripts/oracle.py",
            "protected_oracle_sha256": "b" * 64,
        },
    )
    assert profile.semantic_oracle_sha256 == "b" * 64
    changed = audit_profiles._dynamic_profile(
        **base,
        policy={
            "protected_oracle_path": "scripts/oracle.py",
            "protected_oracle_sha256": "c" * 64,
        },
    )
    assert (
        audit_profiles.audit_profile_context_sha256(profile)
        != audit_profiles.audit_profile_context_sha256(changed)
    )


def test_sealed_g5_has_an_exact_head_audit_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    authority = _next_gate_seed(100)
    bundle = {
        "next_gate_seed": None,
        "post_successor_closeout": {
            "expected_test_count": 101,
            "expected_nodeid_sha256": "d" * 64,
            "accepted_state": {
                "status": "accepted_closed",
                "authorized_next": [],
                "prohibited": [
                    "Phase 5E-2C-1",
                    "Phase 6",
                    "Phase 7",
                    "Phase 8",
                    "Phase 9",
                ],
            },
        },
    }
    monkeypatch.setattr(
        audit_profiles,
        "resolve_controller_gate_position",
        lambda repository, ref: {
            "authority": authority,
            "bundle": bundle,
            "depth": 1,
            "gate_id": "phase5e2c0",
            "stage": "g5",
        },
    )
    monkeypatch.setattr(audit_profiles, "_git_bytes", lambda *args: b"protected")
    profile = audit_profiles._generic_controller_profile(tmp_path, "HEAD")
    assert profile.profile_kind == "sealed_controller_reauthorization"
    assert profile.gate_stage == "g5-controller-reauthorization-sealed"
    assert profile.semantic_oracle_sha256 == hashlib.sha256(b"protected").hexdigest()


def test_corrupt_recursive_position_never_falls_back_to_static_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        audit_profiles,
        "_git_json",
        lambda *args: {
            "current_phase": "Phase 5E-2B.1-2C-gate",
            "status": "accepted_closed",
        },
    )
    monkeypatch.setattr(audit_profiles, "_git_path_exists", lambda *args: True)
    monkeypatch.setattr(
        audit_profiles,
        "resolve_controller_gate_position",
        lambda *args: (_ for _ in ()).throw(ValueError("corrupt recursive gate")),
    )
    with pytest.raises(ValueError, match="corrupt recursive gate"):
        audit_profiles.resolve_controller_audit_profile(tmp_path, "HEAD")


def test_sealed_controller_boundary_rejects_every_ordinary_pull_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    authority = _next_gate_seed(100)
    accepted = {
        "status": "accepted_closed",
        "authorized_next": [],
        "prohibited": [
            "Phase 5E-2C-1",
            "Phase 6",
            "Phase 7",
            "Phase 8",
            "Phase 9",
        ],
    }
    bundle = {
        "next_gate_seed": None,
        "post_successor_closeout": {"accepted_state": accepted},
    }
    position = gate.GatePosition(
        authority=authority,
        gate_id="phase5e2c0",
        depth=1,
        stage="g5",
        bundle=bundle,
    )
    assert gate._is_sealed_controller_reauthorization(position)
    independent_position = independent_gate_oracle.Position(
        authority=authority,
        depth=1,
        stage="g5",
        bundle=bundle,
    )
    assert independent_gate_oracle._sealed_controller_reauthorization(
        independent_position
    )
    monkeypatch.setattr(gate, "resolve_gate_position", lambda *args, **kwargs: position)
    monkeypatch.setattr(
        gate,
        "verify_bootstrap_transition",
        lambda **kwargs: pytest.fail("sealed state must not enter generic bootstrap"),
    )
    with pytest.raises(SystemExit, match="rejects ordinary pull requests"):
        gate.verify_pull_request(
            repository=tmp_path,
            base="a" * 40,
            head="b" * 40,
            event={},
            repository_slug=SLUG,
        )


@pytest.mark.parametrize("phase", ("Phase 6", "Phase 7", "Phase 8", "Phase 9"))
def test_every_successor_state_must_explicitly_prohibit_phase6_through_phase9(
    phase: str,
) -> None:
    authority = _next_gate_seed(100)
    for state_name in (
        "pending_gate_state",
        "accepted_gate_state",
        "successor_pending_state",
        "successor_accepted_state",
    ):
        mutated = copy.deepcopy(authority)
        mutated[state_name]["prohibited"].remove(phase)
        with pytest.raises(RuntimeError, match="machine-state semantics"):
            gate._validate_authority(mutated)


def test_package_root_cli_and_skills_do_not_expose_successor_gate_execution() -> None:
    package_root = (ROOT / "src/owner_research/__init__.py").read_text()
    cli_path = ROOT / "src/owner_research/cli.py"
    cli = cli_path.read_text() if cli_path.exists() else ""
    skills = "\n".join(path.read_text() for path in (ROOT / "plugins").rglob("SKILL.md"))
    for surface in (package_root, cli, skills):
        assert "verify_phase5e_successor_gate" not in surface
        assert "successor-gate bootstrap" not in surface
