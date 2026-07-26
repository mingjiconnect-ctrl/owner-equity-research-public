#!/usr/bin/env python3
"""Verify the accepted Phase 5E-2B.1-1 snapshot without constraining successors."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from scripts.public_bootstrap import commit_exists, verify_public_bootstrap_snapshot
except ModuleNotFoundError:  # Direct ``python -I scripts/...`` execution.
    from public_bootstrap import commit_exists, verify_public_bootstrap_snapshot

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "4fd643df73108b1fa3ab3ce1eb258ae3c3ce8a6d"
BASELINE_TREE = "598b62617a6e40aa2dfecaa8820081ab8202e1fb"
IMPLEMENTATION_TREE = "70609764d5710a137d4555ca86cf7b793263548e"
EXPECTED_FILE_SHA256 = {
    "docs/phase-status.json": (
        "dd9aa49a43383f21cfc290f8933d2e8fc94354980d12f0663d04eaaf26df42be"
    ),
    "docs/phase5e2b11-acceptance-closeout.md": (
        "d90020cc43ca0471662cec3eee74486c06ca3fd2594232f01ce9c506460fe0c6"
    ),
    "scripts/verify_phase5e2b11_acceptance_closeout.py": (
        "e9af4b340069da0ace4e2671cf07277212b7cffa8bc3433d7bf0d2914f6e18d0"
    ),
}


def _git(*arguments: str, text: bool = False) -> bytes | str:
    output = subprocess.check_output(
        ["git", "-C", str(ROOT), *arguments],
        stderr=subprocess.STDOUT,
    )
    return output.decode().strip() if text else output


def _baseline_file(relative: str) -> bytes:
    value = _git("show", f"{BASELINE}:{relative}")
    assert isinstance(value, bytes)
    return value


def main() -> int:
    if not commit_exists(BASELINE, ROOT):
        verify_public_bootstrap_snapshot(ROOT)
        for relative, expected in EXPECTED_FILE_SHA256.items():
            if relative == "docs/phase-status.json":
                continue
            if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != expected:
                raise SystemExit(f"Phase 5E-2B.1-1 frozen evidence drifted: {relative}")
        state = json.loads((ROOT / "docs/phase-status.json").read_bytes())
        implementation = state["closeout"]["implementation"]
        audit = implementation["audit"]
        if (
            implementation["phase"] != "Phase 5E-2B.1-1"
            or implementation["implementation_pull_request"] != 72
            or implementation["substantive_merge_commit"]
            != "11e8ba904bee27fd247ca4f6f9ae5194ba24897a"
            or implementation["substantive_tree_sha"] != IMPLEMENTATION_TREE
            or audit["version"] != "2.3.2.3.2"
            or any(audit["finding_counts"].values())
            or "Phase 5E-2C" not in state["prohibited"]
        ):
            raise SystemExit("public Phase 5E-2B.1-1 closeout evidence is invalid")
        print("Phase 5E-2B.1-1 public provenance snapshot verified")
        return 0
    if subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", BASELINE, "HEAD"],
        check=False,
    ).returncode:
        raise SystemExit("Phase 5E-2B.1-1 accepted baseline is not an ancestor")
    tree = _git("rev-parse", f"{BASELINE}^{{tree}}", text=True)
    if tree != BASELINE_TREE:
        raise SystemExit("Phase 5E-2B.1-1 accepted baseline tree drifted")
    for relative, expected in EXPECTED_FILE_SHA256.items():
        if hashlib.sha256(_baseline_file(relative)).hexdigest() != expected:
            raise SystemExit(f"Phase 5E-2B.1-1 frozen evidence drifted: {relative}")
    state = json.loads(_baseline_file("docs/phase-status.json"))
    closeout = state["closeout"]
    audit = closeout["implementation"]["audit"]
    if (
        state["current_phase"] != "Phase 5E-2B.1"
        or state["status"] != "semantic_closeout_required"
        or closeout["phase"] != "Phase 5E-2B.1-1"
        or closeout["implementation"]["implementation_pull_request"] != 72
        or closeout["implementation"]["substantive_merge_commit"]
        != "11e8ba904bee27fd247ca4f6f9ae5194ba24897a"
        or audit["version"] != "2.3.2.3.2"
        or any(audit["finding_counts"].values())
        or state["authorized_next"]
        != [
            "Phase 5E-2B.1-2 coverage, claim-transition, and recursive-closure integration"
        ]
        or "Phase 5E-2C" not in state["prohibited"]
    ):
        raise SystemExit("Phase 5E-2B.1-1 frozen acceptance evidence is invalid")
    with tempfile.TemporaryDirectory(prefix="phase5e2b11-frozen-") as directory:
        checkout = Path(directory) / "repository"
        subprocess.run(
            ["git", "clone", "--no-local", "--quiet", str(ROOT), str(checkout)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(checkout), "checkout", "--detach", "--quiet", BASELINE],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(checkout), "remote", "remove", "origin"],
            check=True,
        )
        for verifier in (
            "verify_phase5e2a2_rc2_current_share.py",
            "verify_phase5e2a21_recursive_evidence.py",
            "verify_phase5e2b_current_share_compiler.py",
            "verify_phase5e2b10_frozen.py",
            "verify_phase5e2b11_share_event_grouping.py",
            "verify_phase5e2b11_acceptance_closeout.py",
        ):
            environment = os.environ.copy()
            # The active development virtualenv is editable and otherwise points
            # imports back at the successor checkout.  Put the detached accepted
            # snapshot first so historical verifiers actually exercise the
            # frozen tree rather than the working tree under review.
            environment["PYTHONPATH"] = str(checkout / "src")
            environment["PYTHONNOUSERSITE"] = "1"
            environment["OWNER_VALUATION_REPO"] = str(
                Path(
                    os.environ.get(
                        "OWNER_VALUATION_REPO",
                        str(ROOT.parent / "owner-valuation-kernel"),
                    )
                ).resolve()
            )
            subprocess.run(
                [sys.executable, str(checkout / "scripts" / verifier)],
                cwd=checkout,
                env=environment,
                check=True,
            )
    print("Phase 5E-2B.1-1 frozen acceptance snapshot verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
