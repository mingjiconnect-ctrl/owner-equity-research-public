#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
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

PHASE_LABEL = "Phase 5 v1 comprehensive Skill single-PR3 delivery"
AUTHORIZED_NEXT = [
    "single PR3 comprehensive Skill delivery with four ordered implementation slices"
]
REQUIRED_CHECKS = [
    "verify (3.11)",
    "verify (3.12)",
    "verify (3.13)",
    "phase5/semantic-audit",
]
PRIORITIES = ("P0", "P1", "P2", "P3")
SIDECAR_PYTHON_ENV = "PHASE5_V1_SIDECAR_PYTHON"
SIDECAR_TEST_PATH = "sidecars/futu-opend/tests"
SIDECAR_TEST_FILE_TIMEOUT_SECONDS = 300
COMMAND_TIMEOUT_RETURN_CODE = 124
CANONICAL_SOURCE_DATE_EPOCH = "1580601600"
SIDECAR_REQUIRED_DISTRIBUTIONS = {
    "attrs": "26.1.0",
    "cffi": "2.1.1",
    "cryptography": "50.0.0",
    "futu-api": "10.10.7008",
    "hatchling": "1.27.0",
    "iniconfig": "2.3.0",
    "jsonschema": "4.26.0",
    "jsonschema-specifications": "2025.9.1",
    "numpy": "2.4.2",
    "owner-research-futu-sidecar": "1.0.0.dev0",
    "packaging": "26.3",
    "pandas": "3.0.5",
    "pathspec": "1.1.1",
    "pluggy": "1.6.0",
    "protobuf": "7.35.1",
    "pycparser": "3.0",
    "pycryptodome": "3.23.0",
    "pygments": "2.20.0",
    "pytest": "8.4.2",
    "python-dateutil": "2.9.0.post0",
    "referencing": "0.37.0",
    "rpds-py": "2026.6.3",
    "ruff": "0.12.9",
    "setuptools": "80.9.0",
    "simplejson": "4.1.1",
    "six": "1.17.0",
    "trove-classifiers": "2026.6.1.19",
    "typing-extensions": "4.16.0",
    "wheel": "0.48.0",
}
VERIFY_JOB_CANONICAL_SHA256 = "f86875eaa0db7a52358af89a5428be10ab429c7184a95858ac1ee390caa7edcc"
SEMANTIC_AUDIT_JOB_CANONICAL_SHA256 = (
    "45315c8cb09bcda3567800010814fc1e4fe4c2faba71257730268bd977f2bad9"
)
CI_WORKFLOW_SHA256 = "d25e48763eb729af3cf1ba038989afe9cc116612ea710e94575c360a154e3ce1"
RELEASE_TAG_BLOCK_STEP = {
    "name": "Fail closed until external release control is deployed",
    "if": "startsWith(github.ref, 'refs/tags/')",
    "shell": "bash",
    "run": (
        "set -euo pipefail\n"
        "printf '%s\\n' \\\n"
        "  '::error title=Release control unavailable::"
        "release_control_root_not_deployed' >&2\n"
        "exit 1\n"
    ),
}
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
PR3_SEMANTIC_TEST_PATHS = {
    "tests/test_phase5_v1_ci_runtime_supply.py",
    "tests/test_phase5_v1_final_request.py",
    "tests/test_phase5_v1_kernel_materializer.py",
    "tests/test_phase5_v1_kernel_execution.py",
    "tests/test_phase5_v1_dual_panel_e2e.py",
    "tests/test_phase5_v1_owner_execution.py",
    "tests/test_phase5_v1_futu_data_plane.py",
    "tests/test_phase5_v1_owner_equity_research.py",
    "tests/test_phase5_v1_owner_scorecard.py",
    "tests/test_phase5_v1_release_supply_chain.py",
    "tests/test_phase5_v1_report_publisher.py",
    "tests/test_phase5_v1_run_archive.py",
    "tests/test_phase5_v1_run_context.py",
    "tests/test_phase5_v1_run_orchestration.py",
    "tests/test_phase5_v1_release_shadow.py",
    "tests/test_phase5_v1_stable_release_gate.py",
    "tests/test_phase5_v1_valuation_cli.py",
    "tests/test_phase5_v1_valuation_synthesis.py",
    "tests/test_phase5_v1_workflow_cli.py",
}
PUBLIC_ZERO_SKIP_SEMANTIC_TEST_PATHS = {
    "tests/test_phase5_v1_dual_panel_e2e.py",
    "tests/test_phase5_v1_final_request.py",
}


@dataclass(frozen=True)
class Finding:
    priority: str
    code: str
    message: str


def _read_bounded_file(path: Path, *, maximum_size: int = 16 * 1024 * 1024) -> bytes:
    """Read one stable regular checkout file without following its final component."""

    absolute = Path(path).expanduser().absolute()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(absolute, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum_size
        ):
            raise ValueError(f"verification input is not one bounded regular file: {path}")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_size - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum_size:
                raise ValueError(f"verification input exceeds its byte limit: {path}")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        path_after = absolute.lstat()

        def identity(item: os.stat_result) -> tuple[int, ...]:
            return (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_nlink,
                item.st_uid,
                item.st_gid,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if (
            consumed != before.st_size
            or identity(before) != identity(after)
            or identity(after) != identity(path_after)
        ):
            raise ValueError(f"verification input changed while being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_bounded_text(path: Path) -> str:
    return _read_bounded_file(path).decode("utf-8")


def _run(
    command: list[str],
    *,
    hash_seed: str = "0",
    environment_overrides: dict[str, str] | None = None,
    timeout_seconds: float | None = None,
) -> int:
    print("+", " ".join(command), flush=True)
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = hash_seed
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if environment_overrides is not None:
        environment.update(environment_overrides)
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        print(
            f"verification command timed out after {timeout_seconds} seconds: "
            + " ".join(command),
            file=sys.stderr,
            flush=True,
        )
        return COMMAND_TIMEOUT_RETURN_CODE
    return completed.returncode


def _run_distribution(command: list[str]) -> int:
    return _run(
        command,
        environment_overrides={"SOURCE_DATE_EPOCH": CANONICAL_SOURCE_DATE_EPOCH},
    )


def _git(*arguments: str) -> str:
    return subprocess.check_output(
        ["git", *arguments],
        cwd=ROOT,
        text=True,
    ).strip()


def _test_counts(path: Path) -> dict[str, int]:
    if not path.is_file():
        return {"collected": 0, "passed": 0, "skipped": 0, "failed": 1}
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return {"collected": 0, "passed": 0, "skipped": 0, "failed": 1}
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


def _retry_test_tree_cleanup(function, path: str, _error) -> None:
    os.chmod(path, stat.S_IRWXU)
    function(path)


def _remove_test_tree(path: Path) -> bool:
    if path.is_symlink():
        try:
            path.unlink()
        except OSError:
            return False
        return not path.exists() and not path.is_symlink()
    if not path.exists():
        return True
    try:
        for directory, child_directories, files in os.walk(path, topdown=True):
            os.chmod(directory, stat.S_IRWXU)
            for name in child_directories:
                child = Path(directory, name)
                if not child.is_symlink():
                    os.chmod(child, stat.S_IRWXU)
            for name in files:
                child = Path(directory, name)
                if not child.is_symlink():
                    os.chmod(child, stat.S_IRUSR | stat.S_IWUSR)
        shutil.rmtree(path, onerror=_retry_test_tree_cleanup)
    except OSError:
        return False
    return not path.exists()


def _pytest(
    temporary_directory: Path,
    *,
    label: str,
    paths: Iterable[str] | None = None,
    ignore_legacy: bool = False,
    hash_seed: str = "0",
    python_executable: str | Path = sys.executable,
    timeout_seconds: float | None = None,
) -> tuple[int, dict[str, int]]:
    junit_path = temporary_directory / f"{label}.xml"
    pytest_temporary_directory = temporary_directory / f"{label}-pytest"
    if not _remove_test_tree(pytest_temporary_directory):
        return 1, {"collected": 0, "passed": 0, "skipped": 0, "failed": 1}
    command = [
        os.fspath(python_executable),
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        f"--junitxml={junit_path}",
        f"--basetemp={pytest_temporary_directory}",
    ]
    if ignore_legacy:
        command.extend(f"--ignore={path}" for path in LEGACY_TEST_PATHS)
    if paths is not None:
        command.extend(paths)
    result = _run(
        command,
        hash_seed=hash_seed,
        environment_overrides={"SOURCE_DATE_EPOCH": CANONICAL_SOURCE_DATE_EPOCH},
        timeout_seconds=timeout_seconds,
    )
    counts = _test_counts(junit_path)
    if not _remove_test_tree(pytest_temporary_directory):
        result = 1
    if result != 0 and counts["failed"] == 0:
        counts["failed"] = 1
    return result, counts


def _expanded_test_files(
    paths: Iterable[str] | None,
    *,
    ignore_legacy: bool,
) -> tuple[str, ...]:
    candidates: set[str] = set()
    requested = ("tests",) if paths is None else tuple(paths)
    for raw in requested:
        target = ROOT / raw
        if target.is_dir():
            candidates.update(
                path.relative_to(ROOT).as_posix()
                for path in target.rglob("test_*.py")
                if path.is_file()
            )
        elif target.is_file():
            candidates.add(target.relative_to(ROOT).as_posix())
    if ignore_legacy:
        candidates.difference_update(LEGACY_TEST_PATHS)
    return tuple(sorted(candidates))


def _pytest_by_file(
    temporary_directory: Path,
    *,
    label: str,
    paths: Iterable[str] | None = None,
    ignore_legacy: bool = False,
    hash_seed: str = "0",
    python_executable: str | Path = sys.executable,
) -> tuple[int, dict[str, int]]:
    test_files = _expanded_test_files(paths, ignore_legacy=ignore_legacy)
    if not test_files:
        return 1, {"collected": 0, "passed": 0, "skipped": 0, "failed": 1}
    result = 0
    counts: list[dict[str, int]] = []
    for index, test_file in enumerate(test_files, start=1):
        file_result, file_counts = _pytest(
            temporary_directory,
            label=f"{label}-{index:03d}",
            paths=(test_file,),
            hash_seed=hash_seed,
            python_executable=python_executable,
            timeout_seconds=(
                SIDECAR_TEST_FILE_TIMEOUT_SECONDS
                if test_file.startswith(f"{SIDECAR_TEST_PATH}/")
                else None
            ),
        )
        if (
            test_file in PUBLIC_ZERO_SKIP_SEMANTIC_TEST_PATHS
            and file_counts["skipped"] != 0
        ):
            print(
                f"dedicated public semantic test skipped unexpectedly: {test_file}",
                file=sys.stderr,
                flush=True,
            )
            file_result = 1
        result |= file_result
        counts.append(file_counts)
    return result, _merge_test_counts(*counts)


def _merge_test_counts(*values: dict[str, int]) -> dict[str, int]:
    keys = ("collected", "passed", "skipped", "failed")
    return {key: sum(value[key] for value in values) for key in keys}


def _sidecar_python() -> Path:
    raw = os.environ.get(SIDECAR_PYTHON_ENV, sys.executable)
    path = Path(raw)
    if not path.is_absolute() or not path.exists():
        raise ValueError(f"{SIDECAR_PYTHON_ENV} must name an existing absolute interpreter")
    return path


def _verify_sidecar_environment(python_executable: Path) -> int:
    expected = json.dumps(SIDECAR_REQUIRED_DISTRIBUTIONS, sort_keys=True)
    code = (
        "import importlib.metadata as m,json,sys;"
        f"expected=json.loads({expected!r});"
        "actual={name:m.version(name) for name in expected};"
        "sys.exit(0 if actual==expected and sys.version_info[:2] in "
        "{(3,11),(3,12),(3,13)} else 1)"
    )
    return _run([os.fspath(python_executable), "-I", "-c", code])


def _verify_research_distributions(temporary_directory: Path) -> int:
    distribution_directory = temporary_directory / "research-distributions"
    distribution_directory.mkdir()
    build_result = _run_distribution(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(distribution_directory),
            str(ROOT),
        ]
    )
    if build_result:
        return build_result
    wheels = [
        item
        for item in distribution_directory.iterdir()
        if item.is_file() and not item.is_symlink() and item.suffix == ".whl"
    ]
    sdists = [
        item
        for item in distribution_directory.iterdir()
        if item.is_file() and not item.is_symlink() and item.name.endswith(".tar.gz")
    ]
    if (
        len(wheels) != 1
        or len(sdists) != 1
        or len(tuple(distribution_directory.iterdir())) != 2
    ):
        return 1
    exact_commit = _git("rev-parse", "HEAD")
    for verifier, artifact in (
        ("verify_sdist.py", sdists[0]),
        ("verify_wheel.py", wheels[0]),
    ):
        result = _run_distribution(
            [
                sys.executable,
                "-I",
                str(ROOT / "scripts" / verifier),
                "--source-root",
                str(ROOT),
                "--expected-commit",
                exact_commit,
                str(artifact),
            ]
        )
        if result:
            return result
    return 0


def _verify_sidecar_distributions(temporary_directory: Path) -> int:
    distribution_directory = temporary_directory / "sidecar-distributions"
    distribution_directory.mkdir()
    build_result = _run_distribution(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(distribution_directory),
            str(ROOT / "sidecars" / "futu-opend"),
        ]
    )
    if build_result:
        return build_result
    wheels = tuple(distribution_directory.glob("*.whl"))
    sdists = tuple(distribution_directory.glob("*.tar.gz"))
    if (
        len(wheels) != 1
        or len(sdists) != 1
        or len(tuple(distribution_directory.iterdir())) != 2
    ):
        return 1
    exact_commit = _git("rev-parse", "HEAD")
    for command, artifact in (("wheel", wheels[0]), ("sdist", sdists[0])):
        result = _run_distribution(
            [
                sys.executable,
                "-I",
                str(ROOT / "scripts" / "verify_sidecar_distribution.py"),
                command,
                "--source-root",
                str(ROOT),
                "--expected-commit",
                exact_commit,
                str(artifact),
            ]
        )
        if result:
            return result
    return 0


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
    for line in _read_bounded_text(path).splitlines():
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
    semantic_projection = json.dumps(
        parsed["jobs"]["semantic-audit"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if (
        hashlib.sha256(semantic_projection).hexdigest()
        != SEMANTIC_AUDIT_JOB_CANONICAL_SHA256
    ):
        return [Finding("P1", code, "semantic audit job is not the exact closed projection")]
    expected_step_names = [
        "Fail closed until external release control is deployed",
        "Check out the exact current candidate",
        "Set up fixed Python without a post-job package cache",
        "Validate the machine-readable direct-runtime supply identity",
        "Materialize the exact dependency lock files before private access",
        "Materialize the exact dependency supply validator",
        "Prefetch and seal the exact dependency supply before private access",
        "Mint the scoped private-kernel reader token",
        "Check out the exact private-kernel source without persisted credentials",
        "Verify the pinned kernel and remove its remote",
        "Revoke the private-kernel reader token before candidate code runs",
        "Stage netless, then verify in the authorized 3.11 container",
        "Run the exact candidate in the authorized 3.11 container",
        "Delete private channels and rebuild one allowlisted canonical summary",
        "Upload only the allowlisted canonical verification summary",
    ]
    semantic_steps = parsed["jobs"]["semantic-audit"].get("steps")
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
    if (
        steps[0] != RELEASE_TAG_BLOCK_STEP
        or not isinstance(semantic_steps, list)
        or not semantic_steps
        or semantic_steps[0] != RELEASE_TAG_BLOCK_STEP
    ):
        return [
            Finding(
                "P0",
                code,
                "release tags are not hard-blocked before either required job",
            )
        ]
    workflow_env = parsed.get("env")
    if workflow_env != {
        "KERNEL_COMMIT": "be9b0773d5a78f5f8a33ba982494512668df85fe",
        "KERNEL_RUNTIME_IMAGE": (
            "docker.io/library/python@sha256:"
            "eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
        ),
        "KERNEL_RUNTIME_IMAGE_ID": (
            "sha256:d299dee73063206fe64248b8eb62cbef36f6baedfc2c5e2ef4c7618ad18efb3a"
        ),
        "KERNEL_TAG": "v2.0.0-rc.2",
        "KERNEL_TAG_OBJECT": "4e19ce6a59bc4321ebcd368e807ed764f4e8abde",
    }:
        return [Finding("P1", code, "kernel identity environment drifted")]
    setup_python = steps[2]
    supply_authority = steps[3]
    materialize_locks = steps[4]
    materialize_validator = steps[5]
    prefetch = steps[6]
    token_step = steps[7]
    kernel_checkout = steps[8]
    verify_kernel = steps[9]
    revoke = steps[10]
    stage_tests = steps[11]
    run_tests = steps[12]
    sanitize = steps[13]
    upload = steps[14]
    if setup_python != {
        "name": expected_step_names[2],
        "id": "python",
        "uses": "actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c",
        "with": {
            "python-version": "${{ matrix.python-version }}",
            "check-latest": False,
        },
    }:
        return [Finding("P1", code, "verify Python setup or cache boundary drifted")]
    if (
        not isinstance(supply_authority, dict)
        or supply_authority.get("shell") != "bash"
        or set(supply_authority) != {"name", "shell", "run"}
        or "phase5_v1_dependency_lock.py validate" not in supply_authority.get("run", "")
        or "--expected-git-commit" not in supply_authority.get("run", "")
    ):
        return [Finding("P1", code, "machine-readable supply preflight drifted")]
    lock_run = (
        materialize_locks.get("run") if isinstance(materialize_locks, dict) else None
    )
    validator_run = (
        materialize_validator.get("run")
        if isinstance(materialize_validator, dict)
        else None
    )
    download_run = prefetch.get("run") if isinstance(prefetch, dict) else None
    prefetch_run = (
        "\n".join((lock_run, validator_run, download_run))
        if all(isinstance(item, str) for item in (lock_run, validator_run, download_run))
        else None
    )
    if (
        set(materialize_locks) != {"name", "shell", "run"}
        or materialize_locks.get("shell") != "bash"
        or set(materialize_validator) != {"name", "shell", "run"}
        or materialize_validator.get("shell") != "bash"
        or set(prefetch) != {"name", "id", "shell", "run"}
        or prefetch.get("id") != "supply"
        or prefetch.get("shell") != "bash"
        or not isinstance(prefetch_run, str)
        or not all(
            marker in prefetch_run
            for marker in (
                "-I -m pip download",
                "--require-hashes",
                "--only-binary=:all:",
                "--no-binary=:all:",
                "--no-deps",
                "--no-cache-dir",
                "futu-api==10.10.7008",
                "futu_api-10.10.7008.tar.gz",
                "phase5_v1_dependency_lock.py \\",
                "verify-artifacts",
                "--wheelhouse \"$wheelhouse\"",
                "--python-target \"$minor\"",
                "--ci-supply-lock \"$supply_lock\"",
                "--ci-supply-lock \"$sidecar_lock\"",
                "--ci-supply-lock \"$futu_source_lock\"",
                "numpy==2.4.2",
                "protobuf==7.35.1",
                "sidecar.lock",
                "/usr/bin/docker pull --platform linux/amd64",
                'test "$(command -v docker)" = /usr/bin/docker',
                "--entrypoint=/bin/sh",
                '-ceu \'test "$(command -v git)" = /usr/bin/git\'',
                "candidate-tree=$candidate_tree",
                "scripts/bootstrap_linux_x64_report_toolchain.py",
                "2f80b744f1e397a8b9b7570b3464c313fa14629bf358e69aa2c7b4089b3c8790",
                "2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b",
                "f4b3aa468ddfbc8214410f611e7014f6d311a9d5922ac8e5e41ef25dbaa0775c",
                "4a2ac210d3aafabdfc2c6f887552632ec6f0dc78c6b232261445074312b1378c",
                "81a40c76ba93c36365e3ed965949685d4e1042dfb4cc5b285ef2a3f9c51a4b42",
                "feb6abd5dea694c23d4e94151ef09719f1a47e124a8d98a24d1f331a9c352f41",
                "1d224c0e9a26652d51c531f78e15de5a361d7f6f9c3029486846cce90d272f11",
                'sudo chmod 0555 "$report_runtime/tectonic"',
                'observed != candidate["offline_bundle"]',
            )
        )
        or any(
            marker in prefetch_run
            for marker in ("pip download .", " -e ", "git+")
        )
        or prefetch_run.count("--no-binary=:all:") != 1
    ):
        return [Finding("P1", code, "binary or container prefetch boundary drifted")]
    if set(token_step) != {"name", "id", "uses", "with"} or token_step != {
        "name": expected_step_names[7],
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
        "name": expected_step_names[8],
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
        "name": expected_step_names[10],
        "if": "always() && steps.kernel-reader-token.outputs.token != ''",
        "env": {"GH_TOKEN": "${{ steps.kernel-reader-token.outputs.token }}"},
        "run": "gh api --method DELETE /installation/token",
    }:
        return [Finding("P1", code, "kernel-reader revocation step is not fail-closed")]
    stage_run = stage_tests.get("run") if isinstance(stage_tests, dict) else None
    container_run = run_tests.get("run") if isinstance(run_tests, dict) else None
    test_run = (
        "\n".join((stage_run, container_run))
        if isinstance(stage_run, str) and isinstance(container_run, str)
        else None
    )
    if (
        set(stage_tests) != {"name", "shell", "run"}
        or stage_tests.get("shell") != "bash"
        or set(run_tests) != {"name", "if", "shell", "run"}
        or run_tests.get("if") != "matrix.python-version == '3.11'"
        or run_tests.get("shell") != "bash"
        or not isinstance(test_run, str)
        or not all(
            marker in test_run
            for marker in (
                "/usr/bin/sudo -n /usr/bin/unshare",
                "--mount --net --pid --fork --kill-child --mount-proc",
                "candidate_uid=65534",
                "candidate_gid=65534",
                ': > "$private_root/stage.stdout"',
                ': > "$private_root/stage.stderr"',
                ': > "$private_root/container.stdout"',
                ': > "$private_root/container.stderr"',
                'test "$host_uid" -gt 0 && test "$host_gid" -gt 0',
                'test "$candidate_uid" -ne "$host_uid"',
                "test -x /usr/bin/setpriv",
                'test "$(id -u)" -eq 0',
                "mount --make-rprivate /",
                'test "$(readlink -f /var/run)" = /run',
                "mount -t tmpfs -o mode=0755,nosuid,nodev,noexec tmpfs /run",
                "test -x /usr/sbin/ip",
                "/usr/sbin/ip link set dev lo up",
                "/usr/sbin/ip link show dev lo | grep -F '<LOOPBACK,UP,'",
                "test -d /tmp && test ! -L /tmp",
                "mount -t tmpfs -o rw,exec,nosuid,nodev,size=268435456,mode=1777 "
                "tmpfs /tmp",
                "workspace=/run/owner-research/workspace",
                "kernel_checkout=/run/owner-research/private-kernel",
                "wheelhouse=/run/owner-research/wheelhouse",
                "supply_lock=/run/owner-research/supply.lock",
                "validator=/run/owner-research/validator.py",
                "private_root=/run/owner-research/private",
                "mkdir -m 0700 /run/owner-research/tmp",
                "-o rw,exec,nosuid,nodev,size=1073741824,mode=0700",
                "tmpfs /run/owner-research/tmp",
                "stage_code=70",
                "stage_code=75",
                "for privileged_channel in /usr/bin/docker /usr/bin/sudo",
                'mount --bind /dev/null "$privileged_channel"',
                'find "$kernel_source" -xdev',
                "-type f -links +1",
                'chown -R --no-dereference "$candidate_uid:$candidate_gid" '
                '"$kernel_source"',
                '! -user "$candidate_uid"',
                '! -group "$candidate_gid"',
                'mount --bind "$kernel_source" "$kernel_source"',
                'mount -o remount,bind,ro "$kernel_source"',
                'mount --bind "$wheelhouse_source" "$wheelhouse_source"',
                'mount -o remount,bind,ro,noexec,nosuid,nodev "$wheelhouse_source"',
                'mount --bind "$wheelhouse_source" "$wheelhouse"',
                'mount -o remount,bind,ro,noexec,nosuid,nodev "$wheelhouse"',
                'mount --bind "$supply_lock_source" "$supply_lock_source"',
                'mount -o remount,bind,ro,noexec,nosuid,nodev "$supply_lock_source"',
                'mount --bind "$supply_lock_source" "$supply_lock"',
                'mount -o remount,bind,ro,noexec,nosuid,nodev "$supply_lock"',
                'mount --bind "$validator_source" "$validator_source"',
                'mount -o remount,bind,ro,noexec,nosuid,nodev "$validator_source"',
                'mount --bind "$validator_source" "$validator"',
                'mount -o remount,bind,ro,noexec,nosuid,nodev "$validator"',
                'mount --bind "$report_runtime_source" "$report_runtime_source"',
                'mount -o remount,bind,ro,exec,nosuid,nodev "$report_runtime_source"',
                'mount --bind "$report_runtime_source" "$report_runtime"',
                'mount -o remount,bind,ro,exec,nosuid,nodev "$report_runtime"',
                '"$report_runtime/home/.cache/tectonic"',
                '"$private_root/home/.cache/tectonic"',
                'mount --bind "$private_root_source" "$private_root_source"',
                'mount -o remount,bind,rw,exec,nosuid,nodev "$private_root_source"',
                'mount --bind "$private_root_source" "$private_root"',
                'mount -o remount,bind,rw,exec,nosuid,nodev "$private_root"',
                '/usr/bin/git config --file "$private_root/home/.gitconfig"',
                '--add safe.directory "$workspace"',
                '--add safe.directory "$kernel_checkout"',
                'chown -R --no-dereference "$candidate_uid:$candidate_gid"',
                '"$private_root/venv"',
                '"$private_root/kernel-cas"',
                'chmod 0711 "$private_root"',
                'chmod 0755 "$private_root/output"',
                "stat -c '%u:%g:%a' \"$private_root\"",
                "stat -c '%u:%g:%a:%h' \"$protected_path\"",
                "/usr/bin/setpriv",
                "stage_code=80",
                "stage_code=96",
                'trap \'exit "$stage_code"\' ERR',
                "trap - ERR",
                '--reuid="$candidate_uid"',
                '--regid="$candidate_gid"',
                "--clear-groups",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--bounding-set=-all",
                "--no-new-privs",
                'test ! -w "$private_root"',
                "test ! -x /usr/bin/docker",
                "test ! -x /usr/bin/sudo",
                "test ! -S /var/run/docker.sock",
                "test ! -S /run/docker.sock",
                'test "$(command -v docker)" = /usr/bin/docker',
                'test "$(command -v sudo)" = /usr/bin/sudo',
                "/usr/bin/env -i",
                'GIT_CONFIG_GLOBAL="$private_root/home/.gitconfig"',
                "GIT_CONFIG_COUNT=2",
                "GIT_CONFIG_GLOBAL=/dev/null",
                "GIT_CONFIG_KEY_0=safe.directory",
                "GIT_CONFIG_KEY_1=safe.directory",
                "GIT_CONFIG_NOSYSTEM=1",
                "GIT_CONFIG_VALUE_0=/workspace",
                "GIT_CONFIG_VALUE_1=/private-kernel",
                "GIT_OPTIONAL_LOCKS=0",
                'test "$(command -v git)" = /usr/bin/git',
                'git -C "$workspace" rev-parse --show-toplevel',
                "git -C /private-kernel rev-parse --show-toplevel",
                "CapInh CapPrm CapEff CapBnd CapAmb",
                'NoNewPrivs:/ {print $2}',
                "/proc/net/dev",
                'test "${network_interfaces[*]}" = lo',
                'test -z "$(awk \'NR > 1 {print; exit}\' /proc/net/route)"',
                'findmnt -n -o OPTIONS --target "$workspace"',
                'findmnt -n -o OPTIONS --target "$kernel_checkout"',
                'findmnt -n -o OPTIONS --target "$wheelhouse"',
                'findmnt -n -o OPTIONS --target "$supply_lock"',
                'findmnt -n -o OPTIONS --target "$validator"',
                'findmnt -n -o OPTIONS --target "$report_runtime"',
                'findmnt -n -o OPTIONS --target "$report_cache"',
                'test "$(command -v tectonic)" = "$report_runtime/tectonic"',
                "93898e5680acc5ae857b96a3ac1447d84f3bb2eb8dd39398c9859e284afb5443",
                'findmnt -n -o OPTIONS --target "$private_root"',
                'test "$TMPDIR" = /run/owner-research/tmp',
                'tmp_mount_options=$(findmnt -n -o OPTIONS --target "$TMPDIR")',
                "for required_option in rw nosuid nodev",
                "for forbidden_option in ro noexec",
                "stat -c '%u:%g:%a' \"$TMPDIR\"",
                "for required_option in ro noexec nosuid nodev",
                'test -r "$validator" && test ! -w "$validator"',
                'test -r "$supply_lock" && test ! -w "$supply_lock"',
                'test -r "$wheelhouse" && test -x "$wheelhouse"',
                "PIP_NO_INDEX=1",
                "TMPDIR=/run/owner-research/tmp",
                "--no-index",
                "--no-isolation",
                "futu_api-10.10.7008.tar.gz",
                "5aa0c0cfae77213d5d16bf67426c28f53a76c1dc1273f8627fb87cd40d78168e",
                "verify_sidecar_distribution.py",
                "PHASE5_V1_SIDECAR_PYTHON",
                "/usr/bin/docker run --rm --interactive --pull=never",
                '--user="$candidate_uid:$candidate_gid"',
                "--platform=linux/amd64",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--mount=\"type=bind,src=$GITHUB_WORKSPACE,dst=/workspace,readonly\"",
                "--mount=\"type=bind,src=$private_kernel,dst=/private-kernel,readonly\"",
                "--mount=\"type=bind,src=$report_runtime,dst=/report-toolchain,readonly\"",
                "--mount=\"type=bind,src=$attestation_directory,dst=/run/owner-research,readonly\"",
                "--mount=\"type=bind,src=$private_root/output,dst=/output\"",
                "--entrypoint=/usr/bin/env",
                "TMPDIR=/output/tmp",
                "OWNER_VALUATION_REPO",
                "OWNER_RESEARCH_KERNEL_CAS",
                "OWNER_RESEARCH_KERNEL_RUNTIME_MANIFEST",
                "OWNER_RESEARCH_KERNEL_RUNTIME_MANIFEST_FILE_SHA256",
                "OWNER_RESEARCH_TRUSTED_CONTAINER_ATTESTATION_SHA256",
                "HOME=/report-toolchain/home",
                "PATH=/report-toolchain:/usr/local/bin:/usr/bin:/bin",
                'test -d "$HOME/.cache/tectonic" && test ! -w "$HOME/.cache/tectonic"',
                "PHASE5_V1_KERNEL_EXECUTION_REQUIRED=0",
                "PHASE5_V1_KERNEL_EXECUTION_REQUIRED=1",
                "stage.stdout",
                "stage.stderr",
                "container.stdout",
                "container.stderr",
            )
        )
        or any(
            marker in test_run
            for marker in (
                "unshare --user",
                "--map-root-user",
                "--init-groups",
                '--reuid="$host_uid"',
                '--regid="$host_gid"',
                "docker pull",
                "OWNER_RESEARCH_KERNEL_PYTHON",
                "OWNER_RESEARCH_TRUSTED_CONTAINER_ATTESTATION=/",
                "GITHUB_ENV",
                "GITHUB_OUTPUT",
                "GITHUB_PATH",
                "GITHUB_STEP_SUMMARY",
                "--mount=/var/run/docker.sock",
                "src=/var/run/docker.sock",
                'chown -R --no-dereference "$candidate_uid:$candidate_gid" "$private_root"',
                'chown --no-dereference "$candidate_uid:$candidate_gid" "$private_root"',
                'chown -R --no-dereference "$candidate_uid:$candidate_gid" "$workspace"',
                'chown --no-dereference "$candidate_uid:$candidate_gid" "$workspace"',
                'chown -R --no-dereference "$candidate_uid:$candidate_gid" "$workspace_source"',
                'chown --no-dereference "$candidate_uid:$candidate_gid" "$workspace_source"',
                '"$private_root/tmp"',
            )
        )
        or test_run.count(
            "for protected_log in stage.stdout stage.stderr container.stdout "
            "container.stderr; do"
        )
        != 2
        or "TMPDIR=/tmp" in test_run
        or test_run.count("TMPDIR=/run/owner-research/tmp") != 1
        or test_run.count("TMPDIR=/output/tmp") != 1
    ):
        return [Finding("P1", code, "candidate verification is not pinned and netless")]
    if (
        test_run.index("mount --make-rprivate /")
        >= test_run.index("exec /usr/bin/setpriv")
        or test_run.index("test -d /tmp && test ! -L /tmp")
        >= test_run.index(
            "mount -t tmpfs -o rw,exec,nosuid,nodev,size=268435456,mode=1777 "
            "tmpfs /tmp"
        )
        or test_run.index(
            "mount -t tmpfs -o rw,exec,nosuid,nodev,size=268435456,mode=1777 "
            "tmpfs /tmp"
        )
        >= test_run.index("exec /usr/bin/setpriv")
        or test_run.index("exec /usr/bin/setpriv")
        >= test_run.index("TMPDIR=/run/owner-research/tmp")
        or test_run.index("exec /usr/bin/setpriv")
        >= test_run.index('tmp_mount_options=$(findmnt -n -o OPTIONS --target "$TMPDIR")')
        or test_run.index('tmp_mount_options=$(findmnt -n -o OPTIONS --target "$TMPDIR")')
        >= test_run.index('"$runner_python" -I -c')
        or test_run.index(
            'chown -R --no-dereference "$candidate_uid:$candidate_gid" '
            '"$kernel_source"'
        )
        >= test_run.index('mount --bind "$kernel_source" "$kernel_source"')
        or test_run.index('mount -o remount,bind,ro "$kernel_source"')
        >= test_run.index('mount --bind "$kernel_source" "$kernel_checkout"')
        or test_run.index('mount -o remount,bind,ro,noexec,nosuid,nodev "$wheelhouse_source"')
        >= test_run.index('mount --bind "$wheelhouse_source" "$wheelhouse"')
        or test_run.index('mount --bind "$wheelhouse_source" "$wheelhouse"')
        >= test_run.index("exec /usr/bin/setpriv")
        or test_run.index('mount -o remount,bind,rw,exec,nosuid,nodev "$private_root_source"')
        >= test_run.index('mount --bind "$private_root_source" "$private_root"')
        or test_run.index('mount --bind "$private_root_source" "$private_root"')
        >= test_run.index("exec /usr/bin/setpriv")
        or test_run.index("exec /usr/bin/setpriv")
        >= test_run.index('"$runner_python" -I "$validator"')
    ):
        return [Finding("P1", code, "candidate code can run before the privilege drop")]
    sanitize_run = sanitize.get("run") if isinstance(sanitize, dict) else None
    if (
        set(sanitize) != {"name", "id", "if", "shell", "run"}
        or sanitize.get("id") != "sanitize"
        or sanitize.get("if") != "always()"
        or sanitize.get("shell") != "bash"
        or not isinstance(sanitize_run, str)
        or not all(
            marker in sanitize_run
            for marker in (
                "os.O_NOFOLLOW",
                "MAXIMUM_RAW_BYTES = 1024 * 1024",
                '"/usr/bin/sudo", "/bin/rm", "-rf"',
                "finding code is duplicated",
                "upload directory is not a single regular file",
                'raise SystemExit("canonical summary unavailable")',
            )
        )
        or "owner_research" in sanitize_run
    ):
        return [Finding("P1", code, "trusted summary sanitizer boundary drifted")]
    if upload != {
        "name": expected_step_names[14],
        "if": "always() && steps.sanitize.outcome == 'success'",
        "uses": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "with": {
            "name": (
                "phase5-v1-verify-${{ matrix.python-version }}-${{ "
                "github.event.pull_request.head.sha || github.sha }}"
            ),
            "path": (
                "${{ runner.temp }}/phase5-v1-upload-${{ matrix.python-version }}/"
                "phase5-v1-verify.json"
            ),
            "retention-days": 30,
            "if-no-files-found": "error",
        },
    }:
        return [Finding("P1", code, "canonical summary upload boundary drifted")]
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
    if secret_paths != {("jobs", "verify", "steps", 7, "with", "private-key")}:
        return [Finding("P1", code, "an Actions secret escaped the exact token input")]
    if variable_paths != {("jobs", "verify", "steps", 7, "with", "app-id")}:
        return [Finding("P1", code, "an Actions variable escaped the exact token input")]
    if token_paths != {
        ("jobs", "verify", "steps", 8, "with", "token"),
        ("jobs", "verify", "steps", 10, "env", "GH_TOKEN"),
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
        actual = hashlib.sha256(_read_bounded_file(workflow_directory / name)).hexdigest()
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
        status = json.loads(_read_bounded_text(STATUS_PATH))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
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
                    "bounded_io_policy",
                    "current_phase",
                    "delivery",
                    "legacy_governance",
                    "product_invariants",
                    "recommendation_policy",
                    "report_policy",
                    "release_candidate_selector",
                    "release_policy",
                    "release_tag",
                    "required_checks",
                    "schema_version",
                    "scoring_policy",
                    "semantic_audit_policy",
                    "status",
                    "valuation_synthesis_policy",
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
        or status.get("status") != "code_complete_preview"
        or status.get("authorized_next") != AUTHORIZED_NEXT
        or status.get("schema_version") != "2.0.0"
    ):
        findings.append(
            Finding(
                "P0",
                "P5V1-STATUS-AUTHORITY",
                "current Phase 5 v1 label, state, or sole authorization drifted",
            )
        )
    expected_delivery = {
        "acceptance_points": 1,
        "mode": "single_pull_request",
        "pull_request": "PR3",
        "slices": [
            {"id": "trusted_run_archive_core", "ordinal": 1, "status": "implemented"},
            {
                "id": "sec_ir_and_futu_data_plane",
                "ordinal": 2,
                "status": "implemented",
            },
            {
                "id": "valuation_synthesis_and_four_lens_scoring",
                "ordinal": 3,
                "status": "implemented",
            },
            {
                "id": "report_pdf_local_publisher_and_skill",
                "ordinal": 4,
                "status": "implemented",
            },
        ],
        "successor_gate": "none",
        "verification_head": "exact_final_pr_head",
    }
    expected_product_invariants = {
        "initial_supported_universe": "one SEC-reporting XNYS/XNAS USD ordinary common stock",
        "futu_activation": "explicit_valuation_intent_only",
        "futu_financial_and_company_data_role": "secondary_to_sec_ir",
        "futu_runtime": "quote_only_no_trade_or_account_protocols",
        "kernel_call_count": 1,
        "ordinary_research": "target_price_and_market_capitalization_blind_with_zero_futu_calls",
        "publication": "local_only",
        "score_reverse_dependency": "forbidden",
        "valuation_archive_member_count": 6,
        "valuation_synthesis": "post_kernel_project_extension_all_three_panels_required",
    }
    expected_bounded_io = {
        "core_json_member_bytes": 16 * 1024 * 1024,
        "six_file_archive_cumulative_bytes": 64 * 1024 * 1024,
        "research_input_member_bytes": 64 * 1024 * 1024,
        "research_input_cumulative_bytes": 256 * 1024 * 1024,
        "publisher_member_count": 512,
        "publisher_cumulative_bytes": 512 * 1024 * 1024,
    }
    expected_report = {
        "language": "simplified_chinese_with_bilingual_key_terms",
        "page_count_min": 30,
        "page_count_max": 60,
        "profiles": ["research_only", "full_valuation"],
        "typesetting": "latex_pdf_with_python_generated_models_tables_and_charts",
    }
    expected_synthesis = {
        "composites": ["current_intrinsic_value", "twelve_month_target"],
        "missing_or_ineligible_result": None,
        "panel_count_required": 3,
        "panels": ["mckinsey", "penman", "comparables"],
        "two_panel_fallback": False,
        "weighting": "unweighted_median_of_three_eligible_compatible_panels",
    }
    expected_scoring = {
        "item_points_max": 20,
        "items_per_lens": 5,
        "lens_points_max": 100,
        "lenses": ["graham", "buffett", "munger", "duan_yongping"],
        "overall": "equal_arithmetic_mean_of_four_complete_lenses",
        "unknown_or_partial_numeric_coercion": "forbidden_score_is_null",
    }
    expected_recommendation = {
        "evaluation_order": ["无法评级", "回避", "重点关注", "关注", "观察"],
        "rules": {
            "回避": {
                "any_of": [
                    "overall_score < 50",
                    "market_price >= intrinsic_value * 1.15",
                    "permanent_capital_loss_critical_red_flag == true",
                ]
            },
            "关注": {
                "all_of": {
                    "confidence_percent_min": 70,
                    "critical_red_flag": False,
                    "margin_of_safety_percent_min": 15,
                    "overall_score_min": 70,
                    "twelve_month_upside_percent_min": 10,
                }
            },
            "观察": "complete_and_neither_higher_attention_nor_avoidance",
            "无法评级": {
                "any_run_state": [
                    "partial",
                    "blocked",
                    "specialist_required",
                    "contested",
                ]
            },
            "重点关注": {
                "all_of": {
                    "confidence_percent_min": 80,
                    "critical_red_flag": False,
                    "margin_of_safety_percent_min": 25,
                    "overall_score_min": 80,
                    "twelve_month_upside_percent_min": 20,
                }
            },
        },
    }
    expected_release = {
        "development_version_required_until_release_acceptance": True,
        "release_candidate": {
            "exact_merged_main_required": True,
            "real_futu_canary_required": True,
            "required_canary_data_families": [
                "market",
                "financial_statement",
                "company_information",
            ],
            "required_canary_path": [
                "signed_legal_account_protocol_receipts",
                "qot_logged_in_with_closed_read_only_protocol_allowlist",
                "private_cas_binding",
                "sec_ir_reconciliation",
                "strict_six_file_archive_reload",
                "local_pdf_publication_reload",
            ],
            "status": "blocked",
            "target_tag": "v1.0.0-rc.1",
        },
        "stable": {
            "current_external_rights_and_isolation_required": True,
            "status": "blocked",
            "target_tag": "v1.0.0",
        },
    }
    if (
        status.get("delivery") != expected_delivery
        or status.get("product_invariants") != expected_product_invariants
        or status.get("bounded_io_policy") != expected_bounded_io
        or status.get("report_policy") != expected_report
        or status.get("valuation_synthesis_policy") != expected_synthesis
        or status.get("scoring_policy") != expected_scoring
        or status.get("recommendation_policy") != expected_recommendation
        or status.get("release_policy") != expected_release
    ):
        findings.append(
            Finding(
                "P0",
                "P5V1-COMPREHENSIVE-AUTHORITY",
                "ADR 0044 delivery, data, synthesis, scoring, or release policy drifted",
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
        pull_request_policy.get("execution")
        != "once at the exact final pull-request head"
        or pull_request_policy.get("kind")
        != "deterministic candidate replay, not independent review"
        or pull_request_policy.get("required_zero") != ["P0", "P1", "P2", "P3"]
        or independent_review.get("enforcement")
        != "external exact-head PR review evidence before merge"
        or independent_review.get("pull_request_required_zero")
        != ["P0", "P1", "P2", "P3"]
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
    try:
        legacy_archive_sha256 = hashlib.sha256(
            _read_bounded_file(LEGACY_ARCHIVE_PATH)
        ).hexdigest()
    except (OSError, ValueError):
        legacy_archive_sha256 = None
    if legacy_archive_sha256 != LEGACY_ARCHIVE_SHA256:
        findings.append(
            Finding("P1", "P5V1-LEGACY-ARCHIVE", "frozen legacy workflow archive drifted")
        )

    ci_text = _read_bounded_text(CI_WORKFLOW_PATH)
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
        or ci_text.count('"$REVIEWED_COMMIT" <<\'ROOT_BASH\'') != 1
        or ci_text.count("reviewed_commit=${13}") != 1
        or ci_text.count('"$reviewed_commit" <<\'CANDIDATE_BASH\'') != 1
        or ci_text.count("reviewed_commit=${11}") != 1
        or ci_text.count('--expected-commit "$reviewed_commit"') != 4
        or ci_text.count('--expected-git-commit "$reviewed_commit"') != 1
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
    if (
        'if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then\n'
        "            mode=semantic-audit\n"
        "            require_zero=P0,P1,P2,P3\n"
    ) not in ci_text:
        findings.append(
            Finding(
                "P1",
                "P5V1-PR-SEVERITY",
                "pull-request semantic audit does not require P0-P3 all zero",
            )
        )

    legacy_events = _workflow_events(LEGACY_WORKFLOW_PATH)
    legacy_workflow_text = _read_bounded_text(LEGACY_WORKFLOW_PATH)
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
        text = _read_bounded_text(path)
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
            or "one pr3" not in text.lower()
            or "four ordered" not in text.lower()
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
        try:
            sidecar_python = _sidecar_python()
        except ValueError:
            sidecar_python = Path(sys.executable)
            sidecar_environment_result = 1
        else:
            sidecar_environment_result = _verify_sidecar_environment(sidecar_python)
        if args.mode == "verify":
            result, root_tests = _pytest_by_file(
                temporary_directory,
                label="verify",
                ignore_legacy=True,
            )
            sidecar_result, sidecar_tests = _pytest_by_file(
                temporary_directory,
                label="verify-sidecar",
                paths=(SIDECAR_TEST_PATH,),
                python_executable=sidecar_python,
            )
            tests = _merge_test_counts(root_tests, sidecar_tests)
            tests["excluded_legacy_paths"] = list(LEGACY_TEST_PATHS)
            if result != 0 or sidecar_result != 0 or sidecar_environment_result != 0:
                findings.append(Finding("P0", "P5V1-TESTS", "non-legacy test suite failed"))
            root_ruff_result = _run(
                [
                    sys.executable,
                    "-m",
                    "ruff",
                    "check",
                    "--no-cache",
                    "src",
                    "tests",
                    "scripts",
                ]
            )
            sidecar_ruff_result = _run(
                [
                    os.fspath(sidecar_python),
                    "-I",
                    "-m",
                    "ruff",
                    "check",
                    "--no-cache",
                    "sidecars/futu-opend/src",
                    "sidecars/futu-opend/tests",
                    "sidecars/futu-opend/tools",
                ]
            )
            if root_ruff_result or sidecar_ruff_result:
                findings.append(Finding("P1", "P5V1-RUFF", "ruff verification failed"))
            environment = os.environ.copy()
            environment["PYTHONPYCACHEPREFIX"] = str(temporary_directory / "pycache")
            compile_paths = [
                "src",
                "scripts",
                "sidecars/futu-opend/src",
                "sidecars/futu-opend/tests",
                "sidecars/futu-opend/tools",
            ]
            print("+", sys.executable, "-m compileall -q", *compile_paths, flush=True)
            if subprocess.run(
                [sys.executable, "-m", "compileall", "-q", *compile_paths],
                cwd=ROOT,
                env=environment,
                check=False,
            ).returncode:
                findings.append(
                    Finding("P1", "P5V1-COMPILE", "Python syntax compilation failed")
                )
            if _verify_research_distributions(
                temporary_directory
            ) or _verify_sidecar_distributions(temporary_directory):
                findings.append(
                    Finding(
                        "P0",
                        "P5V1-WHEEL",
                        "research wheel or sdist build/verification failed",
                    )
                )
        else:
            paths = _semantic_paths()
            phase5_v1_paths = _phase5_v1_test_paths()
            if (
                not any("current_share" in path for path in phase5_v1_paths)
                or not any("market" in path for path in phase5_v1_paths)
                or not PR3_SEMANTIC_TEST_PATHS.issubset(phase5_v1_paths)
            ):
                findings.append(
                    Finding(
                        "P0",
                        "P5V1-TEST-SURFACE",
                        "Phase 5 v1 tests do not cover the complete PR1-PR3 semantic surface",
                    )
                )
            result, root_tests = _pytest_by_file(
                temporary_directory,
                label="semantic-1" if args.mode == "semantic-audit" else "main-smoke-1",
                paths=paths,
                hash_seed="0",
            )
            sidecar_result, sidecar_tests = _pytest_by_file(
                temporary_directory,
                label=(
                    "semantic-sidecar-1"
                    if args.mode == "semantic-audit"
                    else "main-smoke-sidecar-1"
                ),
                paths=(SIDECAR_TEST_PATH,),
                hash_seed="0",
                python_executable=sidecar_python,
            )
            tests = _merge_test_counts(root_tests, sidecar_tests)
            if result != 0 or sidecar_result != 0 or sidecar_environment_result != 0:
                findings.append(Finding("P0", "P5V1-SEMANTICS", "semantic replay failed"))
            tests["runs"] = 1
            tests["hash_seeds"] = ["0"]
            tests["paths"] = [*paths, SIDECAR_TEST_PATH]
            if args.mode == "main-smoke":
                replay_result, root_replay_counts = _pytest_by_file(
                    temporary_directory,
                    label="main-smoke-2",
                    paths=paths,
                    hash_seed="1",
                )
                sidecar_replay_result, sidecar_replay_counts = _pytest_by_file(
                    temporary_directory,
                    label="main-smoke-sidecar-2",
                    paths=(SIDECAR_TEST_PATH,),
                    hash_seed="1",
                    python_executable=sidecar_python,
                )
                replay_counts = _merge_test_counts(
                    root_replay_counts, sidecar_replay_counts
                )
                tests["runs"] = 2
                tests["hash_seeds"] = ["0", "1"]
                tests["replay_counts_match"] = replay_counts == {
                    key: tests[key] for key in ("collected", "passed", "skipped", "failed")
                }
                if (
                    replay_result != 0
                    or sidecar_replay_result != 0
                    or not tests["replay_counts_match"]
                ):
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
        finding.code
        in {"P5V1-TESTS", "P5V1-SEMANTICS", "P5V1-RUFF", "P5V1-COMPILE", "P5V1-WHEEL"}
        for finding in findings
    ))


if __name__ == "__main__":
    raise SystemExit(main())
