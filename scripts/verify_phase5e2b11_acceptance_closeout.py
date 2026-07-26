#!/usr/bin/env python3
"""Verify the governance-only Phase 5E-2B.1-1 acceptance closeout."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_PR = 72
IMPLEMENTATION_HEAD = "527a18e19ff164325dc310f8dc3da547e5519769"
IMPLEMENTATION_MERGE = "11e8ba904bee27fd247ca4f6f9ae5194ba24897a"
IMPLEMENTATION_TREE = "70609764d5710a137d4555ca86cf7b793263548e"
PR_CI_RUN = "29481851736"
MAIN_CI_RUN = "29482340802"
REPORT_SHA256 = "670cc6b66c9d178511c6e546c7b8b93af75eb6d5f16a94257b4f49337a152415"
ARTIFACT_SHA256 = "dc930942fc3cdc47230317e0db6fa1aefe0ebfa22fbc73df11966147d2147451"
AUDIT_EVIDENCE_SHA256 = "a0884e96b7ca394591713bd9aa66c399df49ad1c418a9386e112521962418bde"

ALLOWED_FILES = {
    "AGENTS.md",
    "README.md",
    "docs/phase-status.json",
    "docs/phase5e2b11-acceptance-closeout.md",
    "docs/phase5e2b11-production-grouping.md",
    "docs/roadmap.md",
    "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md",
    "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md",
    "scripts/run_phase5e_audit.py",
    "scripts/verify_all.py",
    "scripts/verify_phase5e2b11_acceptance_closeout.py",
    "scripts/verify_phase_state.py",
    "tests/test_phase4d5_phase_state.py",
    "tests/test_phase5e_audit.py",
}

FROZEN_PATHS = {
    ".github/workflows/ci.yml",
    "component-lock.json",
    "pyproject.toml",
    "plugins/owner-equity-research/.codex-plugin/plugin.json",
    "src/owner_research/__init__.py",
    "src/owner_research/valuation_current_share_compiler.py",
    "src/owner_research/valuation_current_share_evidence.py",
    "src/owner_research/valuation_share_event_identity.py",
    "src/owner_research/valuation_share_event_grouping.py",
    "tests/fixtures/phase5e2b1/adversarial-cases.json",
    "tests/test_phase5e2b1_share_event_identity_policy.py",
    "tests/test_phase5e2b11_share_event_grouping.py",
    "tests/test_phase5e2b_current_share_compiler.py",
}
FROZEN_PREFIXES = (
    "schemas/",
    "src/owner_research/resources/market_access/",
)


def _git(*args: str, text: bool = True) -> str | bytes:
    value = subprocess.check_output(
        ["git", "-C", str(ROOT), *args],
        text=text,
        stderr=subprocess.STDOUT,
    )
    return value.strip() if text else value


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _assert_frozen(relative: str) -> None:
    baseline = _git("show", f"{IMPLEMENTATION_MERGE}:{relative}", text=False)
    assert isinstance(baseline, bytes)
    current = ROOT / relative
    if not current.is_file() or _sha(current.read_bytes()) != _sha(baseline):
        raise SystemExit(f"acceptance closeout changed frozen semantics: {relative}")


def main() -> int:
    if subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", IMPLEMENTATION_MERGE, "HEAD"],
        check=False,
    ).returncode:
        raise SystemExit("acceptance closeout is not based on the implementation merge")

    changed = set(_git("diff", "--name-only", IMPLEMENTATION_MERGE, "HEAD").splitlines())
    if changed != ALLOWED_FILES:
        raise SystemExit(f"acceptance closeout changed an invalid file set: {sorted(changed)}")

    frozen = set(FROZEN_PATHS)
    tree_files = _git("ls-tree", "-r", "--name-only", IMPLEMENTATION_MERGE).splitlines()
    frozen.update(path for path in tree_files if path.startswith(FROZEN_PREFIXES))
    for relative in sorted(frozen):
        _assert_frozen(relative)

    if _git("rev-parse", f"{IMPLEMENTATION_HEAD}^{{tree}}") != IMPLEMENTATION_TREE or _git(
        "rev-parse", f"{IMPLEMENTATION_MERGE}^{{tree}}"
    ) != IMPLEMENTATION_TREE:
        raise SystemExit("implementation head and merge do not share the recorded tree")

    state = json.loads((ROOT / "docs/phase-status.json").read_text(encoding="utf-8"))
    closeout = state["closeout"]
    implementation = closeout["implementation"]
    audit = implementation["audit"]
    if (
        state["current_phase"] != "Phase 5E-2B.1"
        or state["status"] != "semantic_closeout_required"
        or state["authorized_next"]
        != [
            "Phase 5E-2B.1-2 coverage, claim-transition, and recursive-closure integration"
        ]
        or "Phase 5E-2B.1-2" in state["prohibited"]
        or "Phase 5E-2C" not in state["prohibited"]
        or "Phase 5E-3" not in state["prohibited"]
        or state["release_tag"] is not None
        or closeout["phase"] != "Phase 5E-2B.1-1"
        or closeout["kind"] != "corrective_semantic_implementation_acceptance"
        or closeout["policy_closeout"]["phase"] != "Phase 5E-2B.1-0"
        or implementation["implementation_pull_request"] != IMPLEMENTATION_PR
        or implementation["substantive_head_commit"] != IMPLEMENTATION_HEAD
        or implementation["substantive_merge_commit"] != IMPLEMENTATION_MERGE
        or implementation["substantive_tree_sha"] != IMPLEMENTATION_TREE
        or implementation["pr_ci_run_id"] != PR_CI_RUN
        or implementation["main_ci_run_id"] != MAIN_CI_RUN
        or audit["tool"] != "owner-research-phase5e-readonly"
        or audit["version"] != "2.3.2.3.2"
        or audit["reviewed_commit"] != IMPLEMENTATION_MERGE
        or audit["canonical_report_sha256"] != REPORT_SHA256
        or audit["artifact_sha256"] != ARTIFACT_SHA256
        or audit["audit_evidence_sha256"] != AUDIT_EVIDENCE_SHA256
        or audit["test_counts"]
        != {"collected": 897, "passed": 897, "skipped": 0, "failed": 0}
        or any(audit["finding_counts"].values())
        or closeout["component_lock_sha256"]
        != "957c43bf4b9cca4f2168e816b5ea89b9ca7d86bdad5d967cc8de76e38bfdf1c7"
        or closeout["public_schema_count"] != 43
    ):
        raise SystemExit("Phase 5E-2B.1-1 acceptance evidence or successor boundary drifted")

    print("Phase 5E-2B.1-1 governance-only acceptance closeout verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
