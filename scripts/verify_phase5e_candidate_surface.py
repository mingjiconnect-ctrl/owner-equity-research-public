#!/usr/bin/env python3
"""Credential-free feedback checks for candidate-owned pull-request CI.

Acceptance-grade semantic verification is deliberately owned by the protected-base
``pull_request_target`` workflow.  This script provides fast candidate feedback without
requiring the private valuation kernel or any repository secret.  Its result is not an
acceptance authority because both this file and the workflow that invokes it are candidate-owned.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
_FORBIDDEN_WORKFLOW_TOKENS = (
    "OWNER_VALUATION_DEPLOY_KEY",
    "PHASE5E_KERNEL_READER_PRIVATE_KEY",
    "PHASE5E_KERNEL_READER_APP_ID",
    "PHASE5E_KERNEL_READER_APP_JWT",
    "secrets.",
    "vars.",
    "environment:",
    "pull_request_target",
    ": write",
    "pull-requests: write",
)
_CANONICAL_JSON_PATHS = frozenset(
    {
        "docs/phase-status.json",
        "scripts/phase5e-audit-runtime-matrix.json",
        "scripts/phase5e2b12a-acceptance-trust.json",
        "scripts/phase5e2b12b-acceptance-trust.json",
        "tests/fixtures/phase5e2b12a/adversarial-cases.json",
    }
)


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args],
        text=True,
        stderr=subprocess.STDOUT,
    ).strip()


def _strict_json(path: Path, *, require_canonical: bool) -> None:
    raw = path.read_bytes()

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise SystemExit(f"duplicate JSON key in {path}: {key}")
            value[key] = child
        return value

    def reject_constant(token: str) -> None:
        raise SystemExit(f"non-finite JSON constant in {path}: {token}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid UTF-8 JSON: {path}") from exc
    canonical = (json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    if require_canonical and raw != canonical:
        raise SystemExit(f"noncanonical JSON: {path}")


def verify(repository: Path, reviewed_commit: str) -> None:
    if _GIT_OID.fullmatch(reviewed_commit) is None:
        raise SystemExit("reviewed commit is not a canonical Git object ID")
    if _git(repository, "rev-parse", "HEAD") != reviewed_commit:
        raise SystemExit("candidate checkout is not at the reviewed commit")
    if _git(repository, "status", "--porcelain=v1"):
        raise SystemExit("candidate checkout is dirty before static verification")
    for path in sorted(repository.rglob("*.json")):
        if ".git" not in path.parts:
            relative = path.relative_to(repository).as_posix()
            _strict_json(path, require_canonical=relative in _CANONICAL_JSON_PATHS)
    workflow = (repository / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for token in _FORBIDDEN_WORKFLOW_TOKENS:
        if token in workflow:
            raise SystemExit(f"candidate-owned CI contains forbidden capability: {token}")
    if _git(repository, "status", "--porcelain=v1"):
        raise SystemExit("static verification modified the candidate checkout")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--reviewed-commit", required=True)
    args = parser.parse_args()
    verify(args.repository.resolve(), args.reviewed_commit)
    print("candidate credential-isolation feedback checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
