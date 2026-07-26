#!/usr/bin/env python3
"""Independently aggregate the three private Phase 5E audit runtimes.

This verifier deliberately does not import the audit runner, report writer, or any
owner_research production module.  Raw findings, JUnit, and node-id inventories remain
root-owned controller evidence; the only output is a bounded, sanitized manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
_PRIORITIES = ("P0", "P1", "P2", "P3")
_PRIVATE_LIMITS = {
    "findings.json": 4 * 1024 * 1024,
    "phase5e-independent.xml": 16 * 1024 * 1024,
    "phase5e-nodeids.txt": 4 * 1024 * 1024,
}
_RUNTIME_KEYS = frozenset(
    {
        "runtime_id",
        "python_version",
        "implementation",
        "abi",
        "operating_system",
        "architecture",
        "threading",
    }
)
_COMMON_FINDINGS_KEYS = frozenset(
    {
        "audit_tool",
        "audit_profile",
        "audit_version",
        "reviewed_commit",
        "phase5d_baseline_commit",
        "phase5e0_baseline_commit",
        "phase5e11_baseline_commit",
        "phase5e2a_baseline_commit",
        "phase5e2b10_baseline_commit",
        "phase5e2b11_baseline_commit",
        "valuation_kernel_commit",
        "runtime_identity",
        "audit_trust",
        "started_at",
        "finished_at",
        "audited_file_sha256",
        "test_counts",
        "check_ids",
        "check_ids_sha256",
        "checks",
        "findings",
    }
)
_TEST_COUNT_KEYS = frozenset(
    {
        "collected_tests",
        "passed_tests",
        "skipped_tests",
        "failed_tests",
        "nodeid_sha256",
        "junit_sha256",
    }
)
_AUDIT_TRUST_KEYS = frozenset(
    {
        "controller_commit",
        "controller_tree",
        "candidate_tree",
        "workflow_sha256",
        "audit_controller_sha256",
        "launcher_sha256",
        "candidate_executor_sha256",
        "semantic_oracle_sha256",
        "audit_profile_context_sha256",
        "audit_profile_policy_sha256",
        "audit_profile_registry_sha256",
        "requirements_lock_sha256",
        "runtime_matrix_sha256",
        "runtime_matrix_oracle_sha256",
        "audit_wheelhouse_manifest_sha256",
        "kernel_interface_sha256",
        "control_oracle_tree_sha256",
        "sandbox_profile",
    }
)
_CHECK_KEYS = frozenset({"check_id", "status", "evidence_sha256", "evidence_size"})
_FINDING_KEYS = frozenset(
    {"finding_id", "priority", "check_id", "summary", "evidence_sha256"}
)


def _canonical_json_bytes(raw: bytes, *, label: str) -> tuple[dict[str, Any], bytes]:

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(token: str) -> None:
        raise ValueError(f"non-finite JSON constant: {token}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not a JSON object")
    canonical = (json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    if raw != canonical:
        raise ValueError(f"{label} is not canonically serialized")
    return value, raw


def _canonical_json(path: Path) -> tuple[dict[str, Any], bytes]:
    return _canonical_json_bytes(path.read_bytes(), label=path.name)


def _private_file(path: Path, *, maximum_bytes: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != 0
            or metadata.st_size > maximum_bytes
        ):
            raise ValueError(f"private evidence boundary is invalid: {path.name}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if len(raw) > maximum_bytes:
        raise ValueError(f"private evidence exceeds its bound: {path.name}")
    return raw


def _canonical_nodeids(raw: bytes) -> tuple[str, ...]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("node-id inventory is not UTF-8") from exc
    values = tuple(text.splitlines())
    if not values or raw != ("\n".join(values) + "\n").encode():
        raise ValueError("node-id inventory is not canonical")
    if tuple(sorted(values)) != values or len(set(values)) != len(values):
        raise ValueError("node-id inventory is unordered or duplicated")
    if any("::" not in item or not item for item in values):
        raise ValueError("node-id inventory contains an invalid test identity")
    return values


def _strict_junit(raw: bytes, expected_nodeids: tuple[str, ...]) -> dict[str, int]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError("JUnit evidence is malformed") from exc
    if root.tag != "testsuites" or root.attrib != {"name": "pytest tests"}:
        raise ValueError("JUnit root shape is open")
    suites = tuple(root)
    if len(suites) != 1 or suites[0].tag != "testsuite":
        raise ValueError("JUnit must contain exactly one suite")
    suite = suites[0]
    expected_suite_keys = {
        "name",
        "errors",
        "failures",
        "skipped",
        "tests",
        "time",
        "timestamp",
        "hostname",
    }
    if set(suite.attrib) != expected_suite_keys or suite.attrib["name"] != "pytest":
        raise ValueError("JUnit suite shape is open")
    for key in ("tests", "errors", "failures", "skipped"):
        value = suite.attrib[key]
        if not value.isascii() or not value.isdigit() or str(int(value)) != value:
            raise ValueError("JUnit count is noncanonical")
    if any(suite.attrib[key] != "0" for key in ("errors", "failures", "skipped")):
        raise ValueError("JUnit contains a failure or skip")
    cases = tuple(suite)
    if (
        any(child.tag != "testcase" for child in cases)
        or len(cases) != int(suite.attrib["tests"])
    ):
        raise ValueError("JUnit testcase count does not reconcile")
    executed: list[str] = []
    for case in cases:
        if set(case.attrib) != {"classname", "name", "time"}:
            raise ValueError("JUnit testcase attribute shape is open")
        try:
            duration = float(case.attrib["time"])
        except ValueError as exc:
            raise ValueError("JUnit testcase duration is malformed") from exc
        if duration < 0 or duration == float("inf") or duration != duration:
            raise ValueError("JUnit testcase duration is not finite and nonnegative")
        children = tuple(case)
        if len(children) != 1 or children[0].tag != "properties" or children[0].attrib:
            raise ValueError("JUnit testcase has an open child shape")
        properties = tuple(children[0])
        if len(properties) != 1:
            raise ValueError("JUnit testcase does not bind one node id")
        item = properties[0]
        if (
            item.tag != "property"
            or set(item.attrib) != {"name", "value"}
            or item.attrib["name"] != "phase5e_nodeid"
            or not item.attrib["value"]
            or tuple(item)
        ):
            raise ValueError("JUnit testcase node-id property is malformed")
        executed.append(item.attrib["value"])
    if tuple(sorted(executed)) != expected_nodeids:
        raise ValueError("JUnit execution inventory differs from collection")
    count = len(expected_nodeids)
    return {
        "collected_tests": count,
        "passed_tests": count,
        "skipped_tests": 0,
        "failed_tests": 0,
    }


def _blocked_junit_diagnostics(
    runtime_roots: dict[str, Path],
) -> tuple[dict[str, Any], ...]:
    """Extract only public test identities from otherwise valid blocked JUnit.

    The protected controller deliberately withholds assertion text, stdout, paths outside the
    repository, and raw evidence.  Test node ids are already part of the public repository and are
    sufficient to make a failed audit actionable without weakening the zero-finding gate.
    """

    diagnostics: list[dict[str, Any]] = []
    for runtime_id in sorted(runtime_roots):
        raw = _private_file(
            runtime_roots[runtime_id] / "phase5e-independent.xml",
            maximum_bytes=_PRIVATE_LIMITS["phase5e-independent.xml"],
        )
        root = ET.fromstring(raw)
        if root.tag != "testsuites" or root.attrib != {"name": "pytest tests"}:
            raise ValueError("blocked JUnit root shape is open")
        suites = tuple(root)
        if len(suites) != 1 or suites[0].tag != "testsuite":
            raise ValueError("blocked JUnit must contain exactly one suite")
        suite = suites[0]
        expected_suite_keys = {
            "name",
            "errors",
            "failures",
            "skipped",
            "tests",
            "time",
            "timestamp",
            "hostname",
        }
        if set(suite.attrib) != expected_suite_keys or suite.attrib["name"] != "pytest":
            raise ValueError("blocked JUnit suite shape is open")
        for key in ("tests", "errors", "failures", "skipped"):
            value = suite.attrib[key]
            if not value.isascii() or not value.isdigit() or str(int(value)) != value:
                raise ValueError("blocked JUnit count is noncanonical")
        failed_count = int(suite.attrib["errors"]) + int(suite.attrib["failures"])
        skipped_count = int(suite.attrib["skipped"])
        cases = tuple(suite)
        if (
            any(child.tag != "testcase" for child in cases)
            or len(cases) != int(suite.attrib["tests"])
        ):
            raise ValueError("blocked JUnit testcase count does not reconcile")
        blocked: list[dict[str, str]] = []
        observed_failed = 0
        observed_skipped = 0
        for case in cases:
            if set(case.attrib) != {"classname", "name", "time"}:
                raise ValueError("blocked JUnit testcase attribute shape is open")
            children = tuple(case)
            if not children or children[0].tag != "properties" or children[0].attrib:
                raise ValueError("blocked JUnit testcase properties are malformed")
            properties = tuple(children[0])
            if len(properties) != 1:
                raise ValueError("blocked JUnit testcase does not bind one node id")
            item = properties[0]
            nodeid = item.attrib.get("value")
            if (
                item.tag != "property"
                or set(item.attrib) != {"name", "value"}
                or item.attrib["name"] != "phase5e_nodeid"
                or not isinstance(nodeid, str)
                or not nodeid.startswith("tests/")
                or "::" not in nodeid
                or len(nodeid) > 512
                or any(ord(character) < 32 for character in nodeid)
                or tuple(item)
            ):
                raise ValueError("blocked JUnit testcase node id is malformed")
            outcomes = children[1:]
            if len(outcomes) > 1:
                raise ValueError("blocked JUnit testcase has multiple outcomes")
            if not outcomes:
                continue
            outcome = outcomes[0]
            if (
                outcome.tag not in {"failure", "error", "skipped"}
                or not set(outcome.attrib).issubset({"message", "type"})
                or tuple(outcome)
            ):
                raise ValueError("blocked JUnit testcase outcome shape is open")
            status = "skipped" if outcome.tag == "skipped" else "failed"
            if status == "skipped":
                observed_skipped += 1
            else:
                observed_failed += 1
            blocked.append({"nodeid": nodeid, "status": status})
        if (
            observed_failed != failed_count
            or observed_skipped != skipped_count
            or len({item["nodeid"] for item in blocked}) != len(blocked)
        ):
            raise ValueError("blocked JUnit outcomes do not reconcile")
        diagnostics.append(
            {
                "runtime_id": runtime_id,
                "failed_tests": failed_count,
                "skipped_tests": skipped_count,
                "blocked_test_nodeids": sorted(
                    blocked, key=lambda item: (item["nodeid"], item["status"])
                ),
            }
        )
    return tuple(diagnostics)


def _canonical_utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} is malformed") from exc
    if parsed.tzinfo != UTC:
        raise ValueError(f"{label} is not UTC")
    return parsed


def _validate_findings_payload(findings: dict[str, Any]) -> None:
    for field in (
        "reviewed_commit",
        "phase5d_baseline_commit",
        "phase5e0_baseline_commit",
        "phase5e11_baseline_commit",
        "phase5e2a_baseline_commit",
        "phase5e2b10_baseline_commit",
        "phase5e2b11_baseline_commit",
        "valuation_kernel_commit",
    ):
        if not isinstance(findings.get(field), str) or _GIT_OID.fullmatch(
            findings[field]
        ) is None:
            raise ValueError(f"findings commit identity is malformed: {field}")
    trust = findings.get("audit_trust")
    if not isinstance(trust, dict) or set(trust) != _AUDIT_TRUST_KEYS:
        raise ValueError("findings audit trust shape is open")
    for field in ("controller_commit", "controller_tree", "candidate_tree"):
        if not isinstance(trust.get(field), str) or _GIT_OID.fullmatch(trust[field]) is None:
            raise ValueError("findings audit trust Git identity is malformed")
    for field in _AUDIT_TRUST_KEYS - {
        "controller_commit",
        "controller_tree",
        "candidate_tree",
        "sandbox_profile",
    }:
        if not isinstance(trust.get(field), str) or _SHA256.fullmatch(trust[field]) is None:
            raise ValueError("findings audit trust hash is malformed")
    if trust.get("sandbox_profile") != "linux-root-controller-net-pid-v2":
        raise ValueError("findings sandbox profile is not the protected profile")
    started = _canonical_utc(findings.get("started_at"), label="audit start")
    finished = _canonical_utc(findings.get("finished_at"), label="audit finish")
    if finished < started:
        raise ValueError("findings audit timestamps are inverted")
    audited = findings.get("audited_file_sha256")
    if (
        not isinstance(audited, dict)
        or not audited
        or any(
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or ".." in Path(path).parts
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
            for path, digest in audited.items()
        )
    ):
        raise ValueError("findings audited-file hashes are malformed")
    checks = findings.get("checks")
    declared = findings.get("check_ids")
    if not isinstance(checks, list) or not isinstance(declared, list) or not checks:
        raise ValueError("findings checks are malformed")
    check_by_id: dict[str, dict[str, Any]] = {}
    for check in checks:
        if not isinstance(check, dict) or set(check) != _CHECK_KEYS:
            raise ValueError("findings check shape is open")
        check_id = check.get("check_id")
        if not isinstance(check_id, str) or not check_id or check_id in check_by_id:
            raise ValueError("findings check identity is invalid or duplicated")
        if check.get("status") not in {"passed", "failed"}:
            raise ValueError("findings check status is invalid")
        if not isinstance(check.get("evidence_sha256"), str) or _SHA256.fullmatch(
            check["evidence_sha256"]
        ) is None:
            raise ValueError("findings check evidence hash is invalid")
        if type(check.get("evidence_size")) is not int or check["evidence_size"] < 0:
            raise ValueError("findings check evidence size is invalid")
        check_by_id[check_id] = check
    declared_ids = tuple(declared)
    if (
        tuple(sorted(check_by_id)) != declared_ids
        or len(set(declared_ids)) != len(declared_ids)
        or findings.get("check_ids_sha256")
        != hashlib.sha256(("\n".join(declared_ids) + "\n").encode()).hexdigest()
    ):
        raise ValueError("findings check identity set is invalid")
    failed = {check_id for check_id, check in check_by_id.items() if check["status"] == "failed"}
    findings_list = findings.get("findings")
    if not isinstance(findings_list, list):
        raise ValueError("findings list is malformed")
    seen: set[str] = set()
    for finding in findings_list:
        if not isinstance(finding, dict) or set(finding) != _FINDING_KEYS:
            raise ValueError("finding shape is open")
        check_id = finding.get("check_id")
        priority = finding.get("priority")
        if (
            priority not in _PRIORITIES
            or check_id not in failed
            or check_id in seen
            or finding.get("finding_id") != f"{priority}:{check_id}"
            or finding.get("evidence_sha256") != check_by_id[check_id]["evidence_sha256"]
            or not isinstance(finding.get("summary"), str)
            or not finding["summary"]
        ):
            raise ValueError("finding does not map one-to-one to a failed check")
        seen.add(check_id)
    if seen != failed:
        raise ValueError("every failed check must have exactly one finding")


def _matrix(path: Path, wheelhouse_manifest: Path) -> tuple[dict[str, Any], bytes, bytes]:
    value, raw = _canonical_json(path)
    if set(value) != {
        "schema_version",
        "platform",
        "runtimes",
        "union_wheel_count",
        "union_wheel_manifest_sha256",
    }:
        raise ValueError("runtime matrix shape is open")
    if value["schema_version"] != "1.0.0":
        raise ValueError("runtime matrix version is unsupported")
    platform_value = value["platform"]
    if platform_value != {
        "architecture": "x86_64",
        "implementation": "CPython",
        "linux_platform": "manylinux2014_x86_64",
        "operating_system": "Linux",
        "threading": "gil",
    }:
        raise ValueError("runtime matrix platform is not the fixed Linux target")
    expected = (
        ("cp311", "3.11.15"),
        ("cp312", "3.12.13"),
        ("cp313", "3.13.13"),
    )
    runtimes = value["runtimes"]
    if not isinstance(runtimes, list) or len(runtimes) != 3:
        raise ValueError("runtime matrix must contain three runtimes")
    for item, (runtime_id, version) in zip(runtimes, expected, strict=True):
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "runtime_id",
                "python_version",
                "abi",
                "wheel_count",
                "wheel_manifest_sha256",
            }
            or item["runtime_id"] != runtime_id
            or item["python_version"] != version
            or item["abi"] != runtime_id
            or item["wheel_count"] != 25
            or not isinstance(item["wheel_manifest_sha256"], str)
            or _SHA256.fullmatch(item["wheel_manifest_sha256"]) is None
        ):
            raise ValueError("runtime matrix entry drifted")
    wheel_raw = wheelhouse_manifest.read_bytes()
    if (
        len(wheel_raw.splitlines()) != value["union_wheel_count"]
        or value["union_wheel_count"] != 33
        or hashlib.sha256(wheel_raw).hexdigest()
        != value["union_wheel_manifest_sha256"]
    ):
        raise ValueError("wheelhouse manifest differs from the runtime matrix")
    lines = wheel_raw.splitlines(keepends=True)
    if not lines or b"".join(lines) != wheel_raw:
        raise ValueError("wheelhouse manifest is not LF terminated")
    names: list[bytes] = []
    for line in lines:
        if not line.endswith(b"\n") or len(line) < 68 or line[64:66] != b"  ":
            raise ValueError("wheelhouse manifest line is malformed")
        digest, name = line[:64], line[66:-1]
        if _SHA256.fullmatch(digest.decode("ascii", errors="ignore")) is None:
            raise ValueError("wheelhouse manifest digest is malformed")
        if not name or b"/" in name or b"\\" in name or not name.endswith(b".whl"):
            raise ValueError("wheelhouse manifest name is unsafe")
        names.append(name)
    if names != sorted(names) or len(set(names)) != len(names):
        raise ValueError("wheelhouse manifest is unordered or duplicated")
    return value, raw, wheel_raw


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def aggregate(
    *,
    matrix_path: Path,
    wheelhouse_manifest: Path,
    runtime_roots: dict[str, Path],
    output: Path,
    reviewed_commit: str,
    ci_run_ids: tuple[str, ...],
) -> dict[str, Any]:
    if _GIT_OID.fullmatch(reviewed_commit) is None:
        raise ValueError("reviewed commit is malformed")
    if tuple(sorted(set(ci_run_ids))) != ci_run_ids or any(
        not value.isascii() or not value.isdigit() for value in ci_run_ids
    ):
        raise ValueError("CI run identities are not canonical")
    matrix, matrix_raw, wheel_raw = _matrix(matrix_path, wheelhouse_manifest)
    expected_ids = tuple(item["runtime_id"] for item in matrix["runtimes"])
    if tuple(sorted(runtime_roots)) != tuple(sorted(expected_ids)):
        raise ValueError("runtime evidence set is incomplete or duplicated")

    runtime_results: list[dict[str, Any]] = []
    common: dict[str, Any] | None = None
    inventory_raw: bytes | None = None
    started_values: list[str] = []
    finished_values: list[str] = []
    for expected in matrix["runtimes"]:
        runtime_id = expected["runtime_id"]
        root = runtime_roots[runtime_id]
        private = {
            name: _private_file(root / name, maximum_bytes=limit)
            for name, limit in _PRIVATE_LIMITS.items()
        }
        findings, findings_raw = _canonical_json_bytes(
            private["findings.json"], label=f"{runtime_id} findings.json"
        )
        if findings_raw != private["findings.json"] or set(findings) != _COMMON_FINDINGS_KEYS:
            raise ValueError(f"{runtime_id} findings shape is open")
        _validate_findings_payload(findings)
        identity = findings["runtime_identity"]
        if not isinstance(identity, dict) or set(identity) != _RUNTIME_KEYS:
            raise ValueError(f"{runtime_id} runtime identity shape is open")
        expected_identity = {
            "runtime_id": runtime_id,
            "python_version": expected["python_version"],
            "implementation": matrix["platform"]["implementation"],
            "abi": expected["abi"],
            "operating_system": matrix["platform"]["operating_system"],
            "architecture": matrix["platform"]["architecture"],
            "threading": matrix["platform"]["threading"],
        }
        if identity != expected_identity:
            raise ValueError(f"{runtime_id} runtime identity differs from policy")
        nodeids = _canonical_nodeids(private["phase5e-nodeids.txt"])
        counts = _strict_junit(private["phase5e-independent.xml"], nodeids)
        declared_counts = findings["test_counts"]
        if (
            not isinstance(declared_counts, dict)
            or set(declared_counts) != _TEST_COUNT_KEYS
            or any(declared_counts.get(key) != value for key, value in counts.items())
            or declared_counts.get("nodeid_sha256")
            != hashlib.sha256(private["phase5e-nodeids.txt"]).hexdigest()
            or declared_counts.get("junit_sha256")
            != hashlib.sha256(private["phase5e-independent.xml"]).hexdigest()
        ):
            raise ValueError(f"{runtime_id} test counts do not replay")
        if findings.get("reviewed_commit") != reviewed_commit:
            raise ValueError(f"{runtime_id} reviewed commit differs")
        finding_counts = {priority: 0 for priority in _PRIORITIES}
        for finding in findings["findings"]:
            if not isinstance(finding, dict) or finding.get("priority") not in finding_counts:
                raise ValueError(f"{runtime_id} finding is malformed")
            finding_counts[finding["priority"]] += 1
        common_candidate = {
            key: findings[key]
            for key in (
                "audit_tool",
                "audit_profile",
                "audit_version",
                "reviewed_commit",
                "phase5d_baseline_commit",
                "phase5e0_baseline_commit",
                "phase5e11_baseline_commit",
                "phase5e2a_baseline_commit",
                "phase5e2b10_baseline_commit",
                "phase5e2b11_baseline_commit",
                "valuation_kernel_commit",
                "audit_trust",
                "audited_file_sha256",
                "check_ids",
                "check_ids_sha256",
            )
        }
        if common is None:
            common = common_candidate
            inventory_raw = private["phase5e-nodeids.txt"]
        elif common_candidate != common or private["phase5e-nodeids.txt"] != inventory_raw:
            raise ValueError("runtime evidence differs in common trust or test inventory")
        started_values.append(findings["started_at"])
        finished_values.append(findings["finished_at"])
        runtime_results.append(
            {
                "runtime_id": runtime_id,
                "python_version": identity["python_version"],
                "implementation": identity["implementation"],
                "abi": identity["abi"],
                "operating_system": identity["operating_system"],
                "architecture": identity["architecture"],
                "threading": identity["threading"],
                "test_counts": counts,
                "finding_counts": finding_counts,
                "check_ids_sha256": findings["check_ids_sha256"],
            }
        )
    if common is None or inventory_raw is None:
        raise ValueError("runtime evidence set is empty")
    trust = common["audit_trust"]
    if (
        trust["runtime_matrix_sha256"] != hashlib.sha256(matrix_raw).hexdigest()
        or trust["audit_wheelhouse_manifest_sha256"]
        != hashlib.sha256(wheel_raw).hexdigest()
        or trust["runtime_matrix_oracle_sha256"]
        != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    ):
        raise ValueError("runtime aggregation authority hashes do not match protected bytes")
    aggregate_counts = {
        priority: sum(item["finding_counts"][priority] for item in runtime_results)
        for priority in _PRIORITIES
    }
    report: dict[str, Any] = {
        **common,
        "started_at": min(started_values),
        "finished_at": max(finished_values),
        "finding_counts": aggregate_counts,
        "test_counts": runtime_results[0]["test_counts"],
        "test_inventory_sha256": hashlib.sha256(inventory_raw).hexdigest(),
        "runtime_matrix_sha256": hashlib.sha256(matrix_raw).hexdigest(),
        "audit_wheelhouse_manifest_sha256": hashlib.sha256(wheel_raw).hexdigest(),
        "runtime_results": runtime_results,
        "check_count": len(common["check_ids"]),
        "ci_run_ids": list(ci_run_ids),
    }
    report["report_sha256"] = hashlib.sha256(
        json.dumps(report, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    payload = (json.dumps(report, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    _write_exclusive(output, payload)
    return report


def _write_emergency_manifest(
    *,
    output: Path,
    reviewed_commit: str,
    ci_run_ids: tuple[str, ...],
    error: Exception,
    runtime_roots: dict[str, Path],
) -> None:
    """Persist a sanitized P0 marker when private aggregation cannot complete."""

    error_code = "protected_runtime_aggregation_failed"
    runtime_diagnostics: tuple[dict[str, Any], ...] = ()
    if isinstance(error, ValueError) and str(error) == "JUnit contains a failure or skip":
        error_code = "protected_runtime_junit_blocked"
        try:
            runtime_diagnostics = _blocked_junit_diagnostics(runtime_roots)
        except (OSError, ValueError, ET.ParseError):
            error_code = "protected_runtime_junit_diagnostics_failed"
    payload = {
        "schema_version": "1.0.0",
        "status": "blocked",
        "audit_tool": "owner-research-phase5e-readonly",
        "reviewed_commit": reviewed_commit if _GIT_OID.fullmatch(reviewed_commit) else None,
        "ci_run_ids": list(ci_run_ids),
        "finding_counts": {"P0": 1, "P1": 0, "P2": 0, "P3": 0},
        "error_code": error_code,
        "error_fingerprint": hashlib.sha256(
            f"{type(error).__name__}:{error}".encode("utf-8", errors="replace")
        ).hexdigest(),
        "runtime_diagnostics": list(runtime_diagnostics),
    }
    raw = (json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    _write_exclusive(output, raw)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-matrix", type=Path, required=True)
    parser.add_argument("--wheelhouse-manifest", type=Path, required=True)
    parser.add_argument("--runtime-root", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reviewed-commit", required=True)
    parser.add_argument("--ci-run-id", action="append", default=[])
    args = parser.parse_args()
    roots: dict[str, Path] = {}
    for item in args.runtime_root:
        runtime_id, separator, raw_path = item.partition("=")
        if not separator or runtime_id in roots or runtime_id not in {"cp311", "cp312", "cp313"}:
            parser.error("runtime roots must be unique cp311/cp312/cp313 assignments")
        roots[runtime_id] = Path(raw_path)
    ci_run_ids = tuple(sorted(set(args.ci_run_id)))
    try:
        report = aggregate(
            matrix_path=args.runtime_matrix,
            wheelhouse_manifest=args.wheelhouse_manifest,
            runtime_roots=roots,
            output=args.output,
            reviewed_commit=args.reviewed_commit,
            ci_run_ids=ci_run_ids,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        try:
            _write_emergency_manifest(
                output=args.output,
                reviewed_commit=args.reviewed_commit,
                ci_run_ids=ci_run_ids,
                error=exc,
                runtime_roots=roots,
            )
        except OSError:
            pass
        print("protected Phase 5E runtime aggregation failed", file=sys.stderr)
        return 1
    return 1 if any(report["finding_counts"].values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
