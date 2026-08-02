#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
STATUS_PATH = ROOT / "docs/phase5-v1-status.json"
CI_WORKFLOW_PATH = ROOT / ".github/workflows/ci.yml"
WORKFLOW_DIRECTORY = ROOT / ".github/workflows"
LEGACY_WORKFLOW_PATH = ROOT / ".github/workflows/phase5e2b12a-acceptance-gate.yml"
LEGACY_ARCHIVE_PATH = ROOT / "legacy_governance/phase5e2b12a-acceptance-gate.yml"
LEGACY_ARCHIVE_SHA256 = "51d3e43dffb66b507fe6a1718cd85b1e21dfac77938cb44c6a4045afeb29cf08"
LEGACY_BASELINE_COMMIT = "e5fb637538ce57772a027746651b7527a99268c5"

PHASE_LABEL = "Phase 5 v1 market-reference vertical slice"
AUTHORIZED_NEXT = ["PR1 market-reference vertical slice"]
REQUIRED_CHECKS = [
    "verify (3.11)",
    "verify (3.12)",
    "verify (3.13)",
    "phase5/semantic-audit",
]
PRIORITIES = ("P0", "P1", "P2", "P3")
VERIFY_JOB_CANONICAL_SHA256 = "2f1e67040b42d4706447b5a25ca5a169ddd2a43814accc24605dd31eb53538bc"
CI_WORKFLOW_SHA256 = "c18a6e80ab5a21f13780003a4274385640b0846a49c34832dfa3d575b02f0a6d"
ACTIVE_WORKFLOW_NAMES = {"ci.yml", "phase5e2b12a-acceptance-gate.yml"}
ACTIVE_WORKFLOW_SHA256 = {
    "ci.yml": CI_WORKFLOW_SHA256,
    "phase5e2b12a-acceptance-gate.yml": (
        "d9bbb3ad9ea6018efa4b7c3188afcb3c6c1e592c7dc258492495472638da1cb9"
    ),
}

# These tests preserve the retired recursive/acceptance-only controller. They remain runnable from
# the manual legacy workflow at the frozen legacy commit, but cannot enter a current required check.
LEGACY_TEST_PATHS = (
    "tests/test_phase4d5_phase_state.py",
    "tests/test_phase5e2b12a_acceptance_gate.py",
    "tests/test_phase5e2b12b_acceptance_gate.py",
    "tests/test_phase5e_audit.py",
    "tests/test_phase5e_successor_gate.py",
)

SEMANTIC_REPLAY_PATHS = (
    "tests/test_phase5e1_market_access.py",
    "tests/test_phase5e2a_snapshot_contract.py",
    "tests/test_phase5e2b11_share_event_grouping.py",
    "tests/test_phase5e2b12b_canonical_event_consumption.py",
    "tests/test_phase5e2b_current_share_compiler.py",
)

PHASE5_V1_TEST_GLOBS = (
    "test_phase5_v1_*.py",
    "test_market_reference_v4.py",
    "test_human_reviewed_file_provider.py",
    "test_prepare_owner_valuation.py",
)


@dataclass(frozen=True)
class Finding:
    priority: str
    code: str
    message: str


def _run(command: list[str], *, hash_seed: str = "0") -> int:
    print("+", " ".join(command), flush=True)
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = hash_seed
    completed = subprocess.run(command, cwd=ROOT, env=environment, check=False)
    return completed.returncode


def _git(*arguments: str) -> str:
    return subprocess.check_output(
        ["git", *arguments],
        cwd=ROOT,
        text=True,
    ).strip()


def _test_counts(path: Path) -> dict[str, int]:
    if not path.is_file():
        return {"collected": 0, "passed": 0, "skipped": 0, "failed": 1}
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    collected = sum(int(suite.attrib.get("tests", 0)) for suite in suites)
    failed = sum(
        int(suite.attrib.get("failures", 0)) + int(suite.attrib.get("errors", 0))
        for suite in suites
    )
    skipped = sum(int(suite.attrib.get("skipped", 0)) for suite in suites)
    return {
        "collected": collected,
        "passed": collected - failed - skipped,
        "skipped": skipped,
        "failed": failed,
    }


def _pytest(
    temporary_directory: Path,
    *,
    label: str,
    paths: Iterable[str] | None = None,
    ignore_legacy: bool = False,
    hash_seed: str = "0",
) -> tuple[int, dict[str, int]]:
    junit_path = temporary_directory / f"{label}.xml"
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        f"--junitxml={junit_path}",
    ]
    if ignore_legacy:
        command.extend(f"--ignore={path}" for path in LEGACY_TEST_PATHS)
    if paths is not None:
        command.extend(paths)
    result = _run(command, hash_seed=hash_seed)
    counts = _test_counts(junit_path)
    if result != 0 and counts["failed"] == 0:
        counts["failed"] = 1
    return result, counts


def _phase5_v1_test_paths() -> list[str]:
    tests = ROOT / "tests"
    paths: set[str] = set()
    for pattern in PHASE5_V1_TEST_GLOBS:
        paths.update(path.relative_to(ROOT).as_posix() for path in tests.glob(pattern))
    return sorted(paths)


def _semantic_paths() -> list[str]:
    paths = [path for path in SEMANTIC_REPLAY_PATHS if (ROOT / path).is_file()]
    paths.extend(_phase5_v1_test_paths())
    return list(dict.fromkeys(paths))


def _workflow_events(path: Path) -> set[str]:
    events: set[str] = set()
    in_on_block = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "on:":
            in_on_block = True
            continue
        if not in_on_block:
            continue
        if line and not line.startswith(" "):
            break
        match = re.match(r"^  ([a-zA-Z0-9_-]+):", line)
        if match:
            events.add(match.group(1))
    return events


def _top_level_blocks(text: str, key: str) -> list[tuple[str, ...]]:
    lines = text.splitlines()
    blocks: list[tuple[str, ...]] = []
    for index, line in enumerate(lines):
        if line != f"{key}:":
            continue
        block: list[str] = []
        for nested in lines[index + 1 :]:
            if nested and not nested[0].isspace():
                break
            block.append(nested)
        while block and not block[-1].strip():
            block.pop()
        blocks.append(tuple(block))
    return blocks


def _has_credential_or_write_surface(text: str) -> bool:
    forbidden_markers = (
        "github.token",
        "GITHUB_TOKEN",
        "id-token:",
    )
    return any(marker in text for marker in forbidden_markers) or bool(
        re.search(r":\s*write(?:-all)?(?:\s|[,}#]|$)", text)
    )


def _contains_ci_run_id(value: object) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = key.lower().replace("-", "_")
            if re.search(
                r"(?:^|_)(?:(?:ci|workflow)_)?run_(?:id|ids|url|urls)$",
                normalized_key,
            ):
                return True
            if _contains_ci_run_id(item):
                return True
    elif isinstance(value, list):
        return any(_contains_ci_run_id(item) for item in value)
    return False


def _scalar_paths(
    value: object,
    *,
    path: tuple[object, ...] = (),
) -> list[tuple[tuple[object, ...], str]]:
    found: list[tuple[tuple[object, ...], str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            found.extend(_scalar_paths(item, path=(*path, key)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_scalar_paths(item, path=(*path, index)))
    elif isinstance(value, str):
        found.append((path, value))
    return found


def _kernel_reader_ci_findings(ci_text: str) -> list[Finding]:
    code = "P5V1-KERNEL-READER-CI"
    try:
        parsed = yaml.safe_load(ci_text)
        verify = parsed["jobs"]["verify"]
        steps = verify["steps"]
    except (KeyError, TypeError, yaml.YAMLError) as exc:
        return [Finding("P1", code, f"kernel-reader workflow shape is invalid: {exc}")]
    if (
        not isinstance(parsed, dict)
        or set(parsed) != {"name", True, "permissions", "env", "concurrency", "jobs"}
        or not isinstance(parsed.get("jobs"), dict)
        or set(parsed["jobs"]) != {"verify", "semantic-audit"}
        or "defaults" in parsed
        or "environment" in parsed["jobs"].get("semantic-audit", {})
    ):
        return [Finding("P1", code, "active workflow or job boundary drifted")]
    verify_projection = json.dumps(
        verify,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if hashlib.sha256(verify_projection).hexdigest() != VERIFY_JOB_CANONICAL_SHA256:
        return [Finding("P1", code, "kernel-reader verify job is not the exact closed projection")]
    expected_step_names = [
        "Check out the exact current candidate",
        "Mint the scoped private-kernel reader token",
        "Check out the exact private-kernel source without persisted credentials",
        "Verify the pinned kernel and remove its remote",
        "Revoke the private-kernel reader token before candidate code runs",
        "Set up Python",
        "Install current project and verification dependencies",
        "Run the non-legacy suite without network access",
        "Upload the canonical verification summary",
    ]
    if (
        not isinstance(verify, dict)
        or verify.get("environment") != "phase5e-private-kernel-readonly"
        or "env" in verify
        or not isinstance(steps, list)
        or [step.get("name") for step in steps if isinstance(step, dict)]
        != expected_step_names
        or any(not isinstance(step, dict) for step in steps)
    ):
        return [Finding("P1", code, "kernel-reader job boundary or step order drifted")]
    workflow_env = parsed.get("env")
    if workflow_env != {
        "KERNEL_COMMIT": "be9b0773d5a78f5f8a33ba982494512668df85fe",
        "KERNEL_TAG": "v2.0.0-rc.2",
        "KERNEL_TAG_OBJECT": "4e19ce6a59bc4321ebcd368e807ed764f4e8abde",
    }:
        return [Finding("P1", code, "kernel identity environment drifted")]
    token_step = steps[1]
    kernel_checkout = steps[2]
    verify_kernel = steps[3]
    revoke = steps[4]
    run_tests = steps[7]
    if set(token_step) != {"name", "id", "uses", "with"} or token_step != {
        "name": expected_step_names[1],
        "id": "kernel-reader-token",
        "uses": "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
        "with": {
            "app-id": "${{ vars.PHASE5E_KERNEL_READER_APP_ID }}",
            "private-key": "${{ secrets.PHASE5E_KERNEL_READER_PRIVATE_KEY }}",
            "owner": "mingjiconnect-ctrl",
            "repositories": "owner-valuation-kernel",
            "permission-contents": "read",
            "permission-metadata": "read",
            "skip-token-revoke": True,
        },
    }:
        return [Finding("P1", code, "kernel-reader token step is not the closed projection")]
    if set(kernel_checkout) != {"name", "uses", "with"} or kernel_checkout != {
        "name": expected_step_names[2],
        "uses": "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
        "with": {
            "repository": "mingjiconnect-ctrl/owner-valuation-kernel",
            "ref": "${{ env.KERNEL_COMMIT }}",
            "fetch-depth": 0,
            "path": "_kernel_source",
            "token": "${{ steps.kernel-reader-token.outputs.token }}",
            "persist-credentials": False,
            "submodules": False,
            "lfs": False,
        },
    }:
        return [Finding("P1", code, "private-kernel checkout is not the closed projection")]
    verify_run = verify_kernel.get("run") if isinstance(verify_kernel, dict) else None
    if (
        set(verify_kernel) != {"name", "shell", "run"}
        or verify_kernel.get("shell") != "bash"
        or not isinstance(verify_run, str)
        or "git -C _kernel_source remote remove origin" not in verify_run
        or 'test -z "$(git -C _kernel_source remote)"' not in verify_run
        or "rev-parse \"$KERNEL_TAG^{}\"" not in verify_run
    ):
        return [Finding("P1", code, "kernel identity or remote-removal step drifted")]
    if revoke != {
        "name": expected_step_names[4],
        "if": "always() && steps.kernel-reader-token.outputs.token != ''",
        "env": {"GH_TOKEN": "${{ steps.kernel-reader-token.outputs.token }}"},
        "run": "gh api --method DELETE /installation/token",
    }:
        return [Finding("P1", code, "kernel-reader revocation step is not fail-closed")]
    test_run = run_tests.get("run") if isinstance(run_tests, dict) else None
    if (
        set(run_tests) != {"name", "shell", "env", "run"}
        or run_tests.get("shell") != "bash"
        or run_tests.get("env")
        != {"OWNER_VALUATION_REPO": "${{ github.workspace }}/_kernel_source"}
        or not isinstance(test_run, str)
        or "sudo unshare --net --" not in test_run
        or 'env OWNER_VALUATION_REPO="$OWNER_VALUATION_REPO"' not in test_run
    ):
        return [Finding("P1", code, "candidate verification is not pinned and netless")]
    if any("continue-on-error" in step for step in steps):
        return [Finding("P1", code, "kernel-reader steps may not continue on error")]
    token_marker = "${{ steps.kernel-reader-token.outputs.token }}"
    scalar_paths = _scalar_paths(parsed)
    secret_paths = {
        path
        for path, item in scalar_paths
        if re.search(r"\bsecrets\s*(?:\.|\[)", item)
    }
    variable_paths = {
        path
        for path, item in scalar_paths
        if re.search(r"\bvars\s*(?:\.|\[)", item)
    }
    token_paths = {path for path, item in scalar_paths if token_marker in item}
    if secret_paths != {("jobs", "verify", "steps", 1, "with", "private-key")}:
        return [Finding("P1", code, "an Actions secret escaped the exact token input")]
    if variable_paths != {("jobs", "verify", "steps", 1, "with", "app-id")}:
        return [Finding("P1", code, "an Actions variable escaped the exact token input")]
    if token_paths != {
        ("jobs", "verify", "steps", 2, "with", "token"),
        ("jobs", "verify", "steps", 4, "env", "GH_TOKEN"),
    }:
        return [Finding("P1", code, "kernel-reader token escaped checkout or revocation")]
    return []


def _active_workflow_findings(workflow_directory: Path = WORKFLOW_DIRECTORY) -> list[Finding]:
    names = {
        path.name
        for path in workflow_directory.iterdir()
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    }
    if names != ACTIVE_WORKFLOW_NAMES:
        return [
            Finding(
                "P1",
                "P5V1-WORKFLOW-INVENTORY",
                f"active workflow inventory drifted: {sorted(names)}",
            )
        ]
    for name, expected_sha256 in ACTIVE_WORKFLOW_SHA256.items():
        actual = hashlib.sha256((workflow_directory / name).read_bytes()).hexdigest()
        if actual != expected_sha256:
            return [
                Finding(
                    "P1",
                    "P5V1-WORKFLOW-PROJECTION",
                    f"active workflow bytes drifted: {name}",
                )
            ]
    return []


def _has_exact_keys(value: object, expected: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def _governance_findings(expected_commit: str | None) -> list[Finding]:
    findings: list[Finding] = []
    try:
        status = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [Finding("P0", "P5V1-STATUS-UNREADABLE", str(exc))]
    if not isinstance(status, dict):
        return [Finding("P0", "P5V1-STATUS-SHAPE", "current product state is not an object")]

    semantic_policy_value = status.get("semantic_audit_policy")
    semantic_policy = semantic_policy_value if isinstance(semantic_policy_value, dict) else {}
    pull_request_policy = semantic_policy.get("pull_request")
    pull_request_policy = pull_request_policy if isinstance(pull_request_policy, dict) else {}
    independent_review_value = semantic_policy.get("independent_fresh_context_review")
    independent_review = (
        independent_review_value if isinstance(independent_review_value, dict) else {}
    )
    release_candidate_policy = semantic_policy.get("release_candidate")
    release_candidate_policy = (
        release_candidate_policy if isinstance(release_candidate_policy, dict) else {}
    )
    legacy_value = status.get("legacy_governance")
    legacy = legacy_value if isinstance(legacy_value, dict) else {}
    if not all(
        (
            _has_exact_keys(
                status,
                {
                    "authorized_next",
                    "current_phase",
                    "legacy_governance",
                    "release_candidate_selector",
                    "release_tag",
                    "required_checks",
                    "schema_version",
                    "semantic_audit_policy",
                    "status",
                },
            ),
            _has_exact_keys(
                semantic_policy,
                {
                    "independent_fresh_context_review",
                    "main",
                    "pull_request",
                    "release_candidate",
                    "run_ids_in_product_state",
                },
            ),
            _has_exact_keys(pull_request_policy, {"execution", "kind", "required_zero"}),
            _has_exact_keys(
                independent_review,
                {
                    "enforcement",
                    "pull_request_required_zero",
                    "release_required_zero",
                    "report_binding",
                },
            ),
            _has_exact_keys(release_candidate_policy, {"required_zero"}),
            _has_exact_keys(
                legacy,
                {
                    "archive",
                    "archive_sha256",
                    "baseline_commit",
                    "recursive_authority",
                    "replay_workflow",
                    "status_file",
                    "test_policy",
                },
            ),
        )
    ):
        findings.append(
            Finding("P1", "P5V1-STATUS-SHAPE", "current product state shape drifted")
        )

    if (
        status.get("current_phase") != PHASE_LABEL
        or status.get("status") != "in_progress"
        or status.get("authorized_next") != AUTHORIZED_NEXT
        or status.get("schema_version") != "1.0.0"
    ):
        findings.append(
            Finding(
                "P0",
                "P5V1-STATUS-AUTHORITY",
                "current Phase 5 v1 label, state, or sole authorization drifted",
            )
        )
    if status.get("required_checks") != REQUIRED_CHECKS:
        findings.append(
            Finding("P1", "P5V1-REQUIRED-CHECKS", "required check contexts drifted")
        )
    if (
        status.get("release_candidate_selector") != "v*-rc* tag"
        or status.get("release_tag") is not None
    ):
        findings.append(
            Finding("P1", "P5V1-RC-POLICY", "release-candidate selector drifted")
        )
    if (
        pull_request_policy.get("execution") != "once at the exact pull-request head"
        or pull_request_policy.get("kind")
        != "deterministic candidate replay, not independent review"
        or pull_request_policy.get("required_zero") != ["P0", "P1"]
        or independent_review.get("enforcement")
        != "external PR review evidence before merge"
        or independent_review.get("pull_request_required_zero") != ["P0", "P1"]
        or independent_review.get("release_required_zero")
        != ["P0", "P1", "P2", "P3"]
        or independent_review.get("report_binding")
        != ["commit", "tree", "tests", "P0", "P1", "P2", "P3", "report_sha256"]
        or release_candidate_policy.get("required_zero") != ["P0", "P1", "P2", "P3"]
        or semantic_policy.get("main") != "smoke and deterministic replay"
        or semantic_policy.get("run_ids_in_product_state") is not False
    ):
        findings.append(
            Finding("P1", "P5V1-SEVERITY-POLICY", "semantic severity policy drifted")
        )
    if _contains_ci_run_id(status):
        findings.append(
            Finding("P1", "P5V1-CI-ID-IN-STATE", "current product state contains a CI run ID")
        )
    if (
        legacy.get("recursive_authority") != "retired"
        or legacy.get("status_file") != "docs/phase-status.json"
        or legacy.get("archive")
        != "legacy_governance/phase5e2b12a-acceptance-gate.yml"
        or legacy.get("archive_sha256") != LEGACY_ARCHIVE_SHA256
        or legacy.get("baseline_commit") != LEGACY_BASELINE_COMMIT
        or legacy.get("replay_workflow")
        != ".github/workflows/phase5e2b12a-acceptance-gate.yml"
        or legacy.get("test_policy") != "explicit historical replay only"
    ):
        findings.append(
            Finding("P1", "P5V1-LEGACY-BOUNDARY", "legacy governance boundary drifted")
        )
    if (
        not LEGACY_ARCHIVE_PATH.is_file()
        or hashlib.sha256(LEGACY_ARCHIVE_PATH.read_bytes()).hexdigest()
        != LEGACY_ARCHIVE_SHA256
    ):
        findings.append(
            Finding("P1", "P5V1-LEGACY-ARCHIVE", "frozen legacy workflow archive drifted")
        )

    ci_text = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
    if hashlib.sha256(ci_text.encode("utf-8")).hexdigest() != CI_WORKFLOW_SHA256:
        findings.append(
            Finding("P1", "P5V1-CI-PROJECTION", "active CI workflow bytes drifted")
        )
    findings.extend(_active_workflow_findings())
    ci_events = _workflow_events(CI_WORKFLOW_PATH)
    expected_ci_triggers = (
        "  pull_request:",
        "    branches: [main]",
        "  push:",
        "    branches: [main]",
        '    tags: ["v*-rc*"]',
        "  workflow_dispatch:",
    )
    if (
        ci_events != {"pull_request", "push", "workflow_dispatch"}
        or _top_level_blocks(ci_text, "on") != [expected_ci_triggers]
    ):
        findings.append(
            Finding("P1", "P5V1-CI-TRIGGERS", f"unexpected current CI triggers: {ci_events}")
        )
    if (
        _top_level_blocks(ci_text, "permissions") != [("  contents: read",)]
        or ci_text.count("permissions:") != 1
        or ci_text.count("persist-credentials: false") != 3
        or _has_credential_or_write_surface(ci_text)
    ):
        findings.append(
            Finding(
                "P1",
                "P5V1-CI-CREDENTIAL-SURFACE",
                "current CI gained a credential or write-permission surface",
            )
        )
    findings.extend(_kernel_reader_ci_findings(ci_text))
    for check in REQUIRED_CHECKS:
        if f"name: {check}" not in ci_text and check not in {
            "verify (3.11)",
            "verify (3.12)",
            "verify (3.13)",
        }:
            findings.append(
                Finding("P1", "P5V1-CHECK-NAME", f"missing required check name: {check}")
            )
    if ci_text.count("name: phase5/semantic-audit") != 1:
        findings.append(
            Finding("P1", "P5V1-SEMANTIC-COUNT", "semantic audit is not one non-matrix job")
        )
    if "name: verify (${{ matrix.python-version }})" not in ci_text:
        findings.append(
            Finding("P1", "P5V1-VERIFY-NAME", "matrix verify check name is not exact")
        )
    if '["3.11", "3.12", "3.13"]' not in ci_text:
        findings.append(
            Finding("P1", "P5V1-PYTHON-MATRIX", "supported Python matrix drifted")
        )
    reviewed_expression = "${{ github.event.pull_request.head.sha || github.sha }}"
    if (
        ci_text.count(f"ref: {reviewed_expression}") != 2
        or ci_text.count(f"REVIEWED_COMMIT: {reviewed_expression}") != 1
        or ci_text.count('--expected-commit "$REVIEWED_COMMIT"') != 1
    ):
        findings.append(
            Finding("P0", "P5V1-PR-HEAD", "CI does not explicitly select the pull-request head")
        )
    if 'tags: ["v*-rc*"]' not in ci_text:
        findings.append(
            Finding("P1", "P5V1-RC-SELECTOR", "release-candidate tag selector drifted")
        )
    if not all(
        policy in ci_text
        for policy in (
            "mode=semantic-audit",
            "mode=main-smoke",
            "require_zero=P0,P1",
            "require_zero=P0,P1,P2,P3",
        )
    ):
        findings.append(
            Finding("P1", "P5V1-CI-POLICY", "workflow severity or main-smoke policy drifted")
        )

    legacy_events = _workflow_events(LEGACY_WORKFLOW_PATH)
    legacy_workflow_text = LEGACY_WORKFLOW_PATH.read_text(encoding="utf-8")
    if legacy_events != {"workflow_dispatch"} or _top_level_blocks(
        legacy_workflow_text, "on"
    ) != [("  workflow_dispatch:",)]:
        findings.append(
            Finding(
                "P0",
                "P5V1-LEGACY-AUTO-TRIGGER",
                f"legacy governance still has automatic triggers: {legacy_events}",
            )
        )
    if (
        _top_level_blocks(legacy_workflow_text, "permissions") != [("  contents: read",)]
        or legacy_workflow_text.count("permissions:") != 1
        or legacy_workflow_text.count("persist-credentials: false") != 1
        or _has_credential_or_write_surface(legacy_workflow_text)
        or "pull_request_target" in legacy_workflow_text
        or "workflow_run" in legacy_workflow_text
    ):
        findings.append(
            Finding(
                "P0",
                "P5V1-LEGACY-CREDENTIAL-SURFACE",
                "manual legacy replay retains an active credential or status surface",
            )
        )
    replayed_legacy_tests = tuple(
        re.findall(
            r"^\s+(tests/test_[^\s]+\.py)(?:\s+\\)?\s*$",
            legacy_workflow_text,
            re.MULTILINE,
        )
    )
    if (
        legacy_workflow_text.count(f"ref: {LEGACY_BASELINE_COMMIT}") != 1
        or replayed_legacy_tests != LEGACY_TEST_PATHS
    ):
        findings.append(
            Finding(
                "P1",
                "P5V1-LEGACY-REPLAY-SCOPE",
                "manual legacy replay baseline or historical test scope drifted",
            )
        )

    documentation_markers = {
        ROOT / "AGENTS.md": "### Historical phase record",
        ROOT / "README.md": "## Historical phase record",
        ROOT / "docs/roadmap.md": "## Historical phase record",
    }
    for path, historical_marker in documentation_markers.items():
        text = path.read_text(encoding="utf-8")
        if PHASE_LABEL not in text or "legacy_governance" not in text:
            findings.append(
                Finding(
                    "P2",
                    "P5V1-DOCUMENTATION",
                    f"{path.relative_to(ROOT)} does not declare the current/legacy boundary",
                )
            )
        if (
            PHASE_LABEL not in text
            or AUTHORIZED_NEXT[0] not in text
            or historical_marker not in text
            or text.index(historical_marker) < text.index(PHASE_LABEL)
        ):
            findings.append(
                Finding(
                    "P1",
                    "P5V1-DOCUMENTATION-AUTHORITY",
                    f"{path.relative_to(ROOT)} does not separate current and historical authority",
                )
            )

    commit = _git("rev-parse", "HEAD")
    if expected_commit is not None and commit != expected_commit:
        findings.append(
            Finding(
                "P0",
                "P5V1-REVIEWED-COMMIT",
                f"reviewed commit {commit} does not match expected commit {expected_commit}",
            )
        )
    if _git("status", "--porcelain", "--untracked-files=all"):
        findings.append(
            Finding("P3", "P5V1-DIRTY-WORKTREE", "audit ran with uncommitted workspace changes")
        )
    return findings


def _write_summary(
    output: Path,
    *,
    mode: str,
    tests: dict[str, object],
    findings: list[Finding],
    required_zero: tuple[str, ...],
) -> None:
    counts = {priority: 0 for priority in PRIORITIES}
    for finding in findings:
        counts[finding.priority] += 1
    report: dict[str, object] = {
        "commit": _git("rev-parse", "HEAD"),
        "findings": [asdict(finding) for finding in findings],
        "mode": mode,
        "report_kind": {
            "verify": "nonlegacy_verification",
            "semantic-audit": "deterministic_candidate_replay",
            "main-smoke": "deterministic_main_replay",
        }[mode],
        **counts,
        "required_zero": list(required_zero),
        "schema_version": "1.0.0",
        "tests": tests,
        "tree": _git("rev-parse", "HEAD^{tree}"),
    }
    canonical_report = json.dumps(report, sort_keys=True, separators=(",", ":"))
    report["report_sha256"] = hashlib.sha256(canonical_report.encode("utf-8")).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Phase 5 v1 audit summary: {output}")


def _parse_required_zero(raw: str) -> tuple[str, ...]:
    if not raw:
        return ()
    values = tuple(item.strip() for item in raw.split(",") if item.strip())
    invalid = set(values) - set(PRIORITIES)
    if invalid or len(values) != len(set(values)):
        raise argparse.ArgumentTypeError("--require-zero must be unique P0,P1,P2,P3 values")
    return values


def _output_path(raw: str | None) -> Path:
    candidate = (
        Path(tempfile.gettempdir()) / "phase5-v1-audit-summary.json"
        if raw is None
        else Path(raw).expanduser()
    )
    path = candidate.resolve()
    try:
        path.relative_to(ROOT)
    except ValueError:
        return path
    raise SystemExit("audit summary must be written outside the repository")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=("verify", "semantic-audit", "main-smoke"))
    parser.add_argument("--require-zero", default="")
    parser.add_argument("--expected-commit")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        required_zero = _parse_required_zero(args.require_zero)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    output = _output_path(args.output)
    findings: list[Finding] = []

    with tempfile.TemporaryDirectory(prefix="phase5-v1-") as temporary:
        temporary_directory = Path(temporary)
        if args.mode == "verify":
            result, tests = _pytest(
                temporary_directory,
                label="verify",
                ignore_legacy=True,
            )
            tests["excluded_legacy_paths"] = list(LEGACY_TEST_PATHS)
            if result != 0:
                findings.append(Finding("P0", "P5V1-TESTS", "non-legacy test suite failed"))
            if _run([sys.executable, "-m", "ruff", "check", "src", "tests", "scripts"]):
                findings.append(Finding("P1", "P5V1-RUFF", "ruff verification failed"))
            environment = os.environ.copy()
            environment["PYTHONPYCACHEPREFIX"] = str(temporary_directory / "pycache")
            print("+", sys.executable, "-m compileall -q src scripts", flush=True)
            if subprocess.run(
                [sys.executable, "-m", "compileall", "-q", "src", "scripts"],
                cwd=ROOT,
                env=environment,
                check=False,
            ).returncode:
                findings.append(
                    Finding("P1", "P5V1-COMPILE", "Python syntax compilation failed")
                )
        else:
            paths = _semantic_paths()
            phase5_v1_paths = _phase5_v1_test_paths()
            if not any("current_share" in path for path in phase5_v1_paths) or not any(
                "market" in path for path in phase5_v1_paths
            ):
                findings.append(
                    Finding(
                        "P0",
                        "P5V1-TEST-SURFACE",
                        "Phase 5 v1 tests do not cover both current shares and market reference",
                    )
                )
            result, tests = _pytest(
                temporary_directory,
                label="semantic-1" if args.mode == "semantic-audit" else "main-smoke-1",
                paths=paths,
                hash_seed="0",
            )
            if result != 0:
                findings.append(Finding("P0", "P5V1-SEMANTICS", "semantic replay failed"))
            tests["runs"] = 1
            tests["hash_seeds"] = ["0"]
            tests["paths"] = paths
            if args.mode == "main-smoke":
                replay_result, replay_counts = _pytest(
                    temporary_directory,
                    label="main-smoke-2",
                    paths=paths,
                    hash_seed="1",
                )
                tests["runs"] = 2
                tests["hash_seeds"] = ["0", "1"]
                tests["replay_counts_match"] = replay_counts == {
                    key: tests[key] for key in ("collected", "passed", "skipped", "failed")
                }
                if replay_result != 0 or not tests["replay_counts_match"]:
                    findings.append(
                        Finding("P0", "P5V1-REPLAY", "main deterministic replay failed")
                    )
            findings.extend(_governance_findings(args.expected_commit))

    _write_summary(
        output,
        mode=args.mode,
        tests=tests,
        findings=findings,
        required_zero=required_zero,
    )
    counts = {priority: 0 for priority in PRIORITIES}
    for finding in findings:
        counts[finding.priority] += 1
    for priority in PRIORITIES:
        print(f"{priority}={counts[priority]}")
    return int(any(counts[priority] for priority in required_zero) or any(
        finding.code in {"P5V1-TESTS", "P5V1-RUFF", "P5V1-COMPILE"}
        for finding in findings
    ))


if __name__ == "__main__":
    raise SystemExit(main())
