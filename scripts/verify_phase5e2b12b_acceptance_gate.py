#!/usr/bin/env python3
"""Protected-base structural gate for Phase 5E-2B.1-2B.

This module is installed by the accepted 2A controller.  It reads candidate Git objects but never
imports candidate Python.  Every transition is an exact deep-copy update of the prior machine
state; acceptance additionally requires a caller-supplied, protected-controller remote-evidence
verifier.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

TRUST_PATH = Path(__file__).with_name("phase5e2b12b-acceptance-trust.json")
STATUS_PATH = "docs/phase-status.json"
PHASE5E2B12A_CLOSEOUT_PATH = "docs/phase5e2b12a-acceptance-closeout.json"
PHASE5E2B12B_CLOSEOUT_PATH = "docs/phase5e2b12b-acceptance-closeout.json"
PHASE5E2B12B_TEST_PATH = "tests/test_phase5e2b12b_canonical_event_consumption.py"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
_RUN_ID = re.compile(r"[1-9][0-9]*\Z")


def _load_trust() -> dict[str, Any]:
    raw = TRUST_PATH.read_bytes()

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeError(f"duplicate 2B trust key: {key}")
            result[key] = value
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "4.0.0"
        or raw
        != (json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    ):
        raise RuntimeError("Phase 5E-2B.1-2B trust snapshot is malformed")
    expected_keys = {
        "schema_version",
        "phase",
        "implementation_branch",
        "acceptance_branch",
        "implementation_diff",
        "acceptance_diff",
        "states",
        "audit",
        "controller_app_id_variable",
        "github_actions_app_id",
        "required_branch_protection_checks",
        "expected_added_test_nodeids",
        "successor_gate_bootstrap",
        "successor_production_authorized",
    }
    if set(value) != expected_keys or set(value.get("states", {})) != {"s0", "s1", "s2", "s3"}:
        raise RuntimeError("Phase 5E-2B.1-2B trust shape is open")
    for state in value["states"].values():
        if (
            not isinstance(state, dict)
            or set(state) != {"markers", "status_patch"}
            or set(state["markers"])
            != {
                "phase5e2b12a_closeout",
                "phase5e2b12b_closeout",
                "phase5e2b12b_test",
            }
            or any(type(item) is not bool for item in state["markers"].values())
            or set(state["status_patch"])
            != {"current_phase", "status", "authorized_next", "prohibited", "release_tag"}
            or state["status_patch"]["release_tag"] is not None
            or set(state["status_patch"]["authorized_next"])
            & set(state["status_patch"]["prohibited"])
        ):
            raise RuntimeError("Phase 5E-2B.1-2B state trust is malformed")
    if value.get("successor_production_authorized") is not False:
        raise RuntimeError("Phase 5E-2B.1-2B trust cannot authorize successor production")
    successor = value.get("successor_gate_bootstrap")
    if (
        not isinstance(successor, dict)
        or set(successor)
        != {
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
        or successor.get("gate_id") != "phase5e2b12c"
        or successor.get("bootstrap_branch")
        != "feature/phase5e2b12c-gate-bootstrap"
        or successor.get("acceptance_branch")
        != "feature/phase5e2b12c-gate-acceptance-closeout"
        or successor.get("bundle_directory")
        != "governance/phase5e-gates/phase5e2b12c"
        or successor.get("closeout_path")
        != "docs/phase5e2b12c-gate-acceptance-closeout.json"
    ):
        raise RuntimeError("Phase 5E successor-gate bootstrap identity is malformed")
    successor_verifier = Path(__file__).with_name("verify_phase5e_successor_gate.py")
    if successor_verifier.is_symlink() or not successor_verifier.is_file():
        raise RuntimeError("Phase 5E successor-gate verifier is not a regular local file")
    module_name = "_phase5e2b12b_protected_successor_gate"
    spec = importlib.util.spec_from_file_location(module_name, successor_verifier)
    if spec is None or spec.loader is None:
        raise RuntimeError("Phase 5E successor-gate verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    prior = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        protected_authority = module.bootstrap_authority()
    except BaseException:
        raise
    finally:
        if prior is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = prior
    if protected_authority != successor:
        raise RuntimeError("Phase 5E successor-gate bootstrap semantics are malformed")
    return value


TRUST = _load_trust()
IMPLEMENTATION_BRANCH = str(TRUST["implementation_branch"])
ACCEPTANCE_BRANCH = str(TRUST["acceptance_branch"])
IMPLEMENTATION_DIFF = dict(TRUST["implementation_diff"])
ACCEPTANCE_DIFF = dict(TRUST["acceptance_diff"])
AUDIT_TOOL = str(TRUST["audit"]["tool"])
AUDIT_PROFILE = str(TRUST["audit"]["profile"])
AUDIT_VERSION = str(TRUST["audit"]["version"])
CONTROLLER_APP_ID_VARIABLE = str(TRUST["controller_app_id_variable"])
if CONTROLLER_APP_ID_VARIABLE != "PHASE5E_CONTROLLER_APP_ID":
    raise RuntimeError("Phase 5E controller App variable identity drifted")
EXPECTED_ADDED_TEST_NODEIDS = tuple(TRUST["expected_added_test_nodeids"])
EXPECTED_TEST_COUNT = 1315 + len(EXPECTED_ADDED_TEST_NODEIDS)
STATE_PATCHES = {
    key: copy.deepcopy(value["status_patch"]) for key, value in TRUST["states"].items()
}
STATE_MARKERS = {
    key: copy.deepcopy(value["markers"]) for key, value in TRUST["states"].items()
}
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

RemoteEvidenceVerifier = Callable[..., None]


def _git(repository: Path, *args: str, text: bool = True) -> str | bytes:
    value = subprocess.check_output(
        ["git", "-C", str(repository), *args],
        stderr=subprocess.STDOUT,
    )
    return value.decode().strip() if text else value


def _parents(repository: Path, commit: str) -> tuple[str, ...]:
    value = _git(repository, "show", "-s", "--format=%P", commit)
    assert isinstance(value, str)
    return tuple(value.split())


def _tree(repository: Path, commit: str) -> str:
    value = _git(repository, "rev-parse", f"{commit}^{{tree}}")
    assert isinstance(value, str)
    return value


def _path_exists(repository: Path, commit: str, path: str) -> bool:
    value = _git(repository, "ls-tree", commit, "--", path)
    assert isinstance(value, str)
    return bool(value)


def _mode(repository: Path, commit: str, path: str) -> str:
    value = _git(repository, "ls-tree", commit, "--", path)
    assert isinstance(value, str)
    if not value:
        raise SystemExit(f"missing gated path: {path}")
    return value.split()[0]


def _diff(repository: Path, base: str, head: str) -> dict[str, str]:
    value = _git(repository, "diff", "--name-status", "--no-renames", base, head, "--")
    assert isinstance(value, str)
    result: dict[str, str] = {}
    for line in value.splitlines():
        status, path = line.split("\t", 1)
        if path in result:
            raise SystemExit(f"duplicated diff path: {path}")
        result[path] = status
    return result


def _read_json(repository: Path, commit: str, path: str) -> dict[str, Any]:
    raw = _git(repository, "show", f"{commit}:{path}", text=False)
    assert isinstance(raw, bytes)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SystemExit(f"{path} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant: {token}")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{path} is not canonical UTF-8 JSON") from exc
    if not isinstance(value, dict) or raw != (
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode():
        raise SystemExit(f"{path} is not canonically serialized")
    return value


def _markers(repository: Path, commit: str) -> dict[str, bool]:
    return {
        "phase5e2b12a_closeout": _path_exists(
            repository, commit, PHASE5E2B12A_CLOSEOUT_PATH
        ),
        "phase5e2b12b_closeout": _path_exists(
            repository, commit, PHASE5E2B12B_CLOSEOUT_PATH
        ),
        "phase5e2b12b_test": _path_exists(repository, commit, PHASE5E2B12B_TEST_PATH),
    }


def _status_patch_matches(status: dict[str, Any], patch: dict[str, Any]) -> bool:
    return all(status.get(key) == value for key, value in patch.items())


def state_id(repository: Path, commit: str) -> str:
    status = _read_json(repository, commit, STATUS_PATH)
    markers = _markers(repository, commit)
    matches = [
        name
        for name in ("s0", "s1", "s2", "s3")
        if markers == STATE_MARKERS[name] and _status_patch_matches(status, STATE_PATCHES[name])
    ]
    if len(matches) != 1:
        raise SystemExit("unknown or ambiguous Phase 5E-2B.1 governance state")
    return matches[0]


def _expected_status(base_status: dict[str, Any], target_state: str) -> dict[str, Any]:
    expected = copy.deepcopy(base_status)
    expected.update(copy.deepcopy(STATE_PATCHES[target_state]))
    return expected


def _event_identity(
    event: dict[str, Any],
    *,
    repository_slug: str,
    base: str,
    head: str,
    branch: str,
) -> None:
    pull_request = event.get("pull_request", {})
    if (
        event.get("repository", {}).get("full_name") != repository_slug
        or pull_request.get("base", {}).get("ref") != "main"
        or pull_request.get("base", {}).get("repo", {}).get("full_name")
        != repository_slug
        or pull_request.get("head", {}).get("repo", {}).get("full_name")
        != repository_slug
        or pull_request.get("base", {}).get("sha") != base
        or pull_request.get("head", {}).get("sha") != head
        or pull_request.get("head", {}).get("ref") != branch
    ):
        raise SystemExit("GitHub event identity does not match the protected 2B transition")


def _verify_exact_diff(
    repository: Path, *, base: str, head: str, expected: dict[str, str]
) -> None:
    if _diff(repository, base, head) != expected:
        raise SystemExit("Phase 5E-2B.1-2B transition escaped its exact path boundary")
    for path in expected:
        if _mode(repository, head, path) != "100644":
            raise SystemExit("Phase 5E-2B.1-2B transition contains a non-regular file")


def verify_implementation_transition(
    *,
    repository: Path,
    base: str,
    head: str,
    event: dict[str, Any] | None = None,
    repository_slug: str | None = None,
) -> None:
    if state_id(repository, base) != "s1":
        raise SystemExit("2B implementation base is not exact accepted 2A state")
    if event is not None:
        if not repository_slug:
            raise SystemExit("2B implementation event lacks repository identity")
        _event_identity(
            event,
            repository_slug=repository_slug,
            base=base,
            head=head,
            branch=IMPLEMENTATION_BRANCH,
        )
    merge_base = _git(repository, "merge-base", base, head)
    assert isinstance(merge_base, str)
    if merge_base != base:
        raise SystemExit("2B implementation is not based on current protected main")
    _verify_exact_diff(repository, base=base, head=head, expected=IMPLEMENTATION_DIFF)
    if _path_exists(repository, head, PHASE5E2B12B_CLOSEOUT_PATH):
        raise SystemExit("2B implementation cannot create its acceptance closeout")
    base_status = _read_json(repository, base, STATUS_PATH)
    if _read_json(repository, head, STATUS_PATH) != _expected_status(base_status, "s2"):
        raise SystemExit("2B implementation changed immutable phase history")
    if state_id(repository, head) != "s2":
        raise SystemExit("2B implementation does not stop at pending acceptance")


def _canonical_positive_run_id(value: object) -> bool:
    return isinstance(value, str) and _RUN_ID.fullmatch(value) is not None


def _closeout_shape(
    closeout: dict[str, Any],
    *,
    implementation_merge: str,
    implementation_head: str,
    implementation_tree: str,
    acceptance_number: object,
) -> bool:
    hashes = (
        "audit_report_sha256",
        "audit_artifact_sha256",
        "test_inventory_sha256",
        "runtime_matrix_sha256",
        "audit_wheelhouse_manifest_sha256",
    )
    return (
        set(closeout) == EXPECTED_CLOSEOUT_KEYS
        and closeout.get("schema_version") == "1.0.0"
        and closeout.get("phase") == "Phase 5E-2B.1-2B"
        and closeout.get("implementation_merge_commit") == implementation_merge
        and closeout.get("implementation_head_commit") == implementation_head
        and closeout.get("implementation_tree_sha") == implementation_tree
        and type(closeout.get("implementation_pull_request")) is int
        and closeout["implementation_pull_request"] > 0
        and type(closeout.get("acceptance_pull_request")) is int
        and closeout.get("acceptance_pull_request") == acceptance_number
        and _canonical_positive_run_id(closeout.get("pr_ci_run_id"))
        and _canonical_positive_run_id(closeout.get("main_ci_run_id"))
        and closeout["pr_ci_run_id"] != closeout["main_ci_run_id"]
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
        and closeout.get("audit_tool") == AUDIT_TOOL
        and closeout.get("audit_profile") == AUDIT_PROFILE
        and closeout.get("audit_version") == AUDIT_VERSION
        and all(
            isinstance(closeout.get(field), str) and _SHA256.fullmatch(closeout[field])
            for field in hashes
        )
        and type(closeout.get("test_count")) is int
        and closeout["test_count"] == EXPECTED_TEST_COUNT
        and _GIT_OID.fullmatch(implementation_merge) is not None
        and _GIT_OID.fullmatch(implementation_head) is not None
        and _GIT_OID.fullmatch(implementation_tree) is not None
    )


def verify_merged_acceptance_structure(
    *,
    repository: Path,
    base: str,
    head: str,
    acceptance_number: object,
) -> tuple[str, str, dict[str, Any]]:
    if state_id(repository, base) != "s2":
        raise SystemExit("2B acceptance base is not pending acceptance")
    parents = _parents(repository, base)
    if len(parents) != 2:
        raise SystemExit("2B implementation base is not a two-parent PR merge")
    implementation_base, implementation_head = parents
    if _tree(repository, base) != _tree(repository, implementation_head):
        raise SystemExit("2B implementation merge tree differs from its PR head")
    verify_implementation_transition(
        repository=repository,
        base=implementation_base,
        head=implementation_head,
    )
    if _parents(repository, head) != (base,):
        raise SystemExit("2B acceptance must be one direct non-merge commit")
    _verify_exact_diff(repository, base=base, head=head, expected=ACCEPTANCE_DIFF)
    base_status = _read_json(repository, base, STATUS_PATH)
    if _read_json(repository, head, STATUS_PATH) != _expected_status(base_status, "s3"):
        raise SystemExit("2B acceptance changed immutable phase history")
    if state_id(repository, head) != "s3":
        raise SystemExit("2B acceptance attempts to authorize 2C production")
    closeout = _read_json(repository, head, PHASE5E2B12B_CLOSEOUT_PATH)
    if not _closeout_shape(
        closeout,
        implementation_merge=base,
        implementation_head=implementation_head,
        implementation_tree=_tree(repository, base),
        acceptance_number=acceptance_number,
    ):
        raise SystemExit("2B acceptance closeout is not closed typed evidence")
    return implementation_base, implementation_head, closeout


def verify_acceptance_transition(
    *,
    repository: Path,
    base: str,
    head: str,
    event: dict[str, Any],
    repository_slug: str,
    token: str | None,
    require_remote: bool,
    remote_verifier: RemoteEvidenceVerifier | None,
) -> None:
    _event_identity(
        event,
        repository_slug=repository_slug,
        base=base,
        head=head,
        branch=ACCEPTANCE_BRANCH,
    )
    implementation_base, implementation_head, closeout = verify_merged_acceptance_structure(
        repository=repository,
        base=base,
        head=head,
        acceptance_number=event.get("number"),
    )
    if not require_remote or token is None or remote_verifier is None:
        raise SystemExit("2B acceptance requires protected remote evidence replay")
    remote_verifier(
        repository=repository,
        repository_slug=repository_slug,
        token=token,
        implementation_base=implementation_base,
        implementation_merge=base,
        implementation_head=implementation_head,
        closeout=closeout,
    )


def verify_pull_request(
    *,
    repository: Path,
    base: str,
    head: str,
    event: dict[str, Any],
    repository_slug: str,
    token: str | None = None,
    require_remote: bool = False,
    remote_verifier: RemoteEvidenceVerifier | None = None,
) -> None:
    current = state_id(repository, base)
    if current == "s1":
        if require_remote:
            raise SystemExit("2B implementation structure cannot self-attest remote acceptance")
        verify_implementation_transition(
            repository=repository,
            base=base,
            head=head,
            event=event,
            repository_slug=repository_slug,
        )
        return
    if current == "s2":
        verify_acceptance_transition(
            repository=repository,
            base=base,
            head=head,
            event=event,
            repository_slug=repository_slug,
            token=token,
            require_remote=require_remote,
            remote_verifier=remote_verifier,
        )
        return
    raise SystemExit("current governance state is not an authorized 2B transition")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--event-json", type=Path)
    parser.add_argument("--repository-slug")
    parser.add_argument("--structural-only", action="store_true")
    parser.add_argument("--describe-state-ref")
    args = parser.parse_args()
    if args.describe_state_ref:
        print(state_id(args.repository.resolve(), args.describe_state_ref))
        return 0
    if not args.structural_only:
        parser.error("the protected CLI exposes only structural verification")
    if not args.base or not args.head or args.event_json is None or not args.repository_slug:
        parser.error("structural verification requires base, head, event, and repository identity")
    event = json.loads(args.event_json.read_bytes())

    def remote_verified_elsewhere(**_: Any) -> None:
        return None

    current = state_id(args.repository.resolve(), args.base)
    verify_pull_request(
        repository=args.repository.resolve(),
        base=args.base,
        head=args.head,
        event=event,
        repository_slug=args.repository_slug,
        token="remote-evidence-is-controller-owned" if current == "s2" else None,
        require_remote=current == "s2",
        remote_verifier=remote_verified_elsewhere if current == "s2" else None,
    )
    return 0


def trust_material_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


__all__ = (
    "ACCEPTANCE_BRANCH",
    "AUDIT_PROFILE",
    "AUDIT_TOOL",
    "AUDIT_VERSION",
    "CONTROLLER_APP_ID_VARIABLE",
    "EXPECTED_ADDED_TEST_NODEIDS",
    "EXPECTED_TEST_COUNT",
    "IMPLEMENTATION_BRANCH",
    "PHASE5E2B12B_CLOSEOUT_PATH",
    "STATE_MARKERS",
    "STATE_PATCHES",
    "STATUS_PATH",
    "state_id",
    "trust_material_sha256",
    "verify_acceptance_transition",
    "verify_implementation_transition",
    "verify_merged_acceptance_structure",
    "verify_pull_request",
)


if __name__ == "__main__":
    raise SystemExit(main())
