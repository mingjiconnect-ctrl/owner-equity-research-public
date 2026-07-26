#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

RESEARCH_BASELINE = "30d6e77780175deeffc5c211749bcb0169aa1dde"
RESEARCH_TAG = "v0.4.0-alpha.1"
KERNEL_BASELINE = "a7dd1528c34f09702686b32ffbb8a397439665f0"
KERNEL_TAG = "v2.0.0-rc.1"
KERNEL_SCHEMAS = (
    "assumption-ledger.schema.json",
    "fact-ledger.schema.json",
    "sec-company-profile.schema.json",
    "sec-company-review.schema.json",
    "sec-evidence-pack.schema.json",
    "sec-scenario-policy.schema.json",
    "valuation-request.schema.json",
    "valuation-result.schema.json",
)
INTERFACE_SCHEMAS = (
    "fact-ledger.schema.json",
    "assumption-ledger.schema.json",
    "valuation-request.schema.json",
    "valuation-result.schema.json",
)
REQUIRED_DOCS = (
    "docs/phase5-plan.md",
    "docs/phase5-methodology.md",
    "docs/phase5-interface-matrix.json",
    "docs/phase5-failure-mode-matrix.json",
    "docs/adr/0023-research-to-valuation-boundary.md",
    "docs/phase5-acceptance.md",
)
ALLOWED_DIFF_PATHS = {
    ".github/workflows/ci.yml",
    "AGENTS.md",
    "README.md",
    "docs/phase-status.json",
    "docs/roadmap.md",
    "scripts/run_phase5p_audit.py",
    "scripts/verify_phase5p_plan.py",
    "scripts/verify_phase_state.py",
    "scripts/write_phase5p_audit.py",
    "tests/test_phase4d5_phase_state.py",
    *REQUIRED_DOCS,
}


class VerificationError(RuntimeError):
    pass


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args],
        text=True,
        stderr=subprocess.STDOUT,
    ).strip()


def _load_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    if not path.is_file():
        raise VerificationError(f"missing required JSON document: {path}")
    raw = path.read_text(encoding="utf-8")
    if not raw.endswith("\n") or raw.endswith("\n\n") or "\t" in raw:
        raise VerificationError(f"JSON document is not normalized text: {path}")
    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"invalid JSON document {path}: {exc}") from exc


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _required_objects(schema: Any, pointer: str = "") -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    if isinstance(schema, dict):
        required = schema.get("required")
        if isinstance(required, list):
            result[pointer or "/"] = tuple(str(item) for item in required)
        for key, value in schema.items():
            child = f"{pointer}/{_pointer_token(str(key))}"
            result.update(_required_objects(value, child))
    elif isinstance(schema, list):
        for index, value in enumerate(schema):
            result.update(_required_objects(value, f"{pointer}/{index}"))
    return result


def _verify_baselines(repository: Path, kernel: Path) -> None:
    if _git(repository, "rev-parse", f"{RESEARCH_TAG}^{{}}") != RESEARCH_BASELINE:
        raise VerificationError("research release tag does not resolve to the fixed baseline")
    if _git(repository, "cat-file", "-t", RESEARCH_TAG) != "tag":
        raise VerificationError("research release tag is not annotated")
    if subprocess.run(
        ["git", "-C", str(repository), "merge-base", "--is-ancestor", RESEARCH_BASELINE, "HEAD"],
        check=False,
    ).returncode:
        raise VerificationError("Phase 5P head is not descended from the fixed research baseline")
    if _git(kernel, "rev-parse", "HEAD") != KERNEL_BASELINE:
        raise VerificationError("valuation kernel checkout is not at the fixed commit")
    if _git(kernel, "rev-parse", f"{KERNEL_TAG}^{{}}") != KERNEL_BASELINE:
        raise VerificationError("valuation kernel tag does not resolve to the fixed commit")
    if _git(kernel, "cat-file", "-t", KERNEL_TAG) != "tag":
        raise VerificationError("valuation kernel tag is not annotated")
    if _git(kernel, "status", "--porcelain"):
        raise VerificationError("valuation kernel checkout is not clean")


def _verify_kernel_hashes(repository: Path, kernel: Path) -> None:
    lock = _load_json(repository / "component-lock.json")
    kernel_lock = lock.get("valuation_kernel", {})
    if kernel_lock.get("commit") != KERNEL_BASELINE or kernel_lock.get("tag") != KERNEL_TAG:
        raise VerificationError("component lock kernel identity drifted")
    hashes = kernel_lock.get("public_schema_sha256")
    if not isinstance(hashes, dict) or len(hashes) != len(KERNEL_SCHEMAS):
        raise VerificationError("component lock does not contain exactly eight kernel schemas")
    expected_paths = {f"schemas/{name}" for name in KERNEL_SCHEMAS}
    if set(hashes) != expected_paths:
        raise VerificationError("component lock kernel schema set drifted")
    for relative, expected in hashes.items():
        if _sha256(kernel / relative) != expected:
            raise VerificationError(f"pinned kernel schema hash mismatch: {relative}")


def _verify_interface_matrix(repository: Path, kernel: Path) -> None:
    matrix = _load_json(repository / "docs" / "phase5-interface-matrix.json")
    if matrix.get("schema_version") != "1.0.0":
        raise VerificationError("interface matrix schema version drifted")
    if matrix.get("research_baseline", {}).get("commit") != RESEARCH_BASELINE:
        raise VerificationError("interface matrix research baseline drifted")
    if matrix.get("kernel_baseline", {}).get("commit") != KERNEL_BASELINE:
        raise VerificationError("interface matrix kernel baseline drifted")

    strategies = matrix.get("strategies")
    if not isinstance(strategies, list):
        raise VerificationError("interface matrix lacks strategies")
    strategy_ids = [item.get("strategy_id") for item in strategies if isinstance(item, dict)]
    if len(strategy_ids) != len(set(strategy_ids)) or None in strategy_ids:
        raise VerificationError("interface matrix strategy IDs are missing or duplicated")

    mappings = matrix.get("interface_mappings")
    if not isinstance(mappings, list):
        raise VerificationError("interface matrix lacks mappings")
    mapping_ids = [item.get("mapping_id") for item in mappings if isinstance(item, dict)]
    if len(mapping_ids) != len(set(mapping_ids)) or None in mapping_ids:
        raise VerificationError("interface mapping IDs are missing or duplicated")
    for item in mappings:
        if item.get("strategy_id") not in strategy_ids:
            raise VerificationError(f"mapping uses unknown strategy: {item.get('mapping_id')}")
        if not item.get("rule") or not item.get("failure_ids"):
            raise VerificationError(f"mapping lacks rule or failures: {item.get('mapping_id')}")

    expected: dict[tuple[str, str], tuple[str, ...]] = {}
    for schema_name in INTERFACE_SCHEMAS:
        schema = _load_json(kernel / "schemas" / schema_name)
        for pointer, fields in _required_objects(schema).items():
            expected[(schema_name, pointer)] = fields

    coverage = matrix.get("kernel_required_coverage")
    if not isinstance(coverage, list):
        raise VerificationError("interface matrix lacks kernel required-field coverage")
    observed: dict[tuple[str, str], tuple[str, ...]] = {}
    for item in coverage:
        key = (item.get("schema"), item.get("object_pointer"))
        if key in observed:
            raise VerificationError(f"duplicate required-object coverage: {key}")
        if item.get("strategy_id") not in strategy_ids:
            raise VerificationError(f"coverage uses unknown strategy: {key}")
        observed[key] = tuple(item.get("required_fields", ()))
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        wrong = sorted(
            key for key in set(expected) & set(observed) if expected[key] != observed[key]
        )
        raise VerificationError(
            "kernel required-field coverage mismatch: "
            f"missing={missing}, extra={extra}, wrong={wrong}"
        )

    invariants = "\n".join(matrix.get("architectural_invariants", ()))
    required_invariants = (
        "price-blind",
        "market_equity_value_fact_id",
        "owner-valuation-kernel",
        "never averaged",
    )
    if any(token not in invariants for token in required_invariants):
        raise VerificationError("interface matrix omits a required Phase 5 boundary")


def _verify_failure_matrix(repository: Path) -> None:
    matrix = _load_json(repository / "docs" / "phase5-failure-mode-matrix.json")
    failures = matrix.get("failure_modes")
    if not isinstance(failures, list) or not failures:
        raise VerificationError("failure-mode matrix is empty")
    ids = [item.get("failure_id") for item in failures if isinstance(item, dict)]
    if len(ids) != len(set(ids)) or None in ids:
        raise VerificationError("failure-mode IDs are missing or duplicated")
    invalid = [
        item.get("failure_id")
        for item in failures
        if item.get("priority") not in {"P0", "P1", "P2", "P3"}
        or not item.get("owner_phase")
        or not item.get("trigger")
        or not item.get("fail_closed")
        or not item.get("verification")
    ]
    if invalid:
        raise VerificationError(f"failure modes lack required fail-closed ownership: {invalid}")
    if not {"P0", "P1"}.issubset({item["priority"] for item in failures}):
        raise VerificationError("failure matrix must include P0 and P1 paths")

    interface = _load_json(repository / "docs" / "phase5-interface-matrix.json")
    referenced = {
        failure_id
        for mapping in interface["interface_mappings"]
        for failure_id in mapping["failure_ids"]
    }
    if referenced != set(ids):
        raise VerificationError(
            "interface/failure cross-reference mismatch: "
            f"unreferenced={sorted(set(ids)-referenced)}, "
            f"unknown={sorted(referenced-set(ids))}"
        )


def _verify_docs(repository: Path) -> None:
    for relative in REQUIRED_DOCS:
        path = repository / relative
        if not path.is_file() or not path.read_text(encoding="utf-8").strip():
            raise VerificationError(f"missing or empty planning document: {relative}")
    combined = "\n".join(
        (repository / relative).read_text(encoding="utf-8")
        for relative in REQUIRED_DOCS
        if relative.endswith(".md")
    )
    required = (
        "price-blind-input.json",
        "market_equity_value_fact_id",
        "protected_mckinsey_sha256",
        "protected_penman_assumptions_sha256",
        "ValuationHandoff",
        "MarketReferenceSnapshot",
        "ValuationAssumptionCandidate",
        "ValuationAssumptionReviewDecision",
        "v0.5.0-alpha.1",
        "PROJECT_OPERATIONALIZATION",
    )
    missing = [token for token in required if token not in combined]
    if missing:
        raise VerificationError(f"Phase 5 planning documents omit required decisions: {missing}")


def _verify_diff_boundary(repository: Path, kernel: Path) -> None:
    changed = set(
        filter(None, _git(repository, "diff", "--name-only", RESEARCH_BASELINE).splitlines())
    )
    untracked = set(
        filter(None, _git(repository, "ls-files", "--others", "--exclude-standard").splitlines())
    )
    try:
        kernel_relative = kernel.relative_to(repository).as_posix().rstrip("/")
    except ValueError:
        kernel_relative = None
    if kernel_relative is not None:
        untracked = {
            path
            for path in untracked
            if path != kernel_relative and not path.startswith(f"{kernel_relative}/")
        }
    changed.update(untracked)
    unauthorized = sorted(changed - ALLOWED_DIFF_PATHS)
    if unauthorized:
        raise VerificationError(f"Phase 5P changed unauthorized paths: {unauthorized}")
    required_changes = set(REQUIRED_DOCS) | {
        ".github/workflows/ci.yml",
        "AGENTS.md",
        "README.md",
        "docs/phase-status.json",
        "docs/roadmap.md",
        "scripts/run_phase5p_audit.py",
        "scripts/verify_phase5p_plan.py",
        "scripts/verify_phase_state.py",
        "scripts/write_phase5p_audit.py",
        "tests/test_phase4d5_phase_state.py",
    }
    missing = sorted(required_changes - changed)
    if missing:
        raise VerificationError(f"Phase 5P diff lacks required planning/audit files: {missing}")
    forbidden_prefixes = ("src/", "schemas/", "plugins/")
    if any(path.startswith(forbidden_prefixes) for path in changed):
        raise VerificationError("Phase 5P changed production, schema, or Plugin files")
    immutable = ("pyproject.toml", "component-lock.json")
    if any(path in changed for path in immutable):
        raise VerificationError("Phase 5P changed package version or component lock")

    audit_source = "\n".join(
        (repository / name).read_text(encoding="utf-8")
        for name in (
            "scripts/run_phase5p_audit.py",
            "scripts/verify_phase5p_plan.py",
            "scripts/write_phase5p_audit.py",
        )
    )
    forbidden_import = re.compile(
        r"^\s*(?:from|import)\s+(?:httpx|requests|owner_valuation)\b", re.M
    )
    if forbidden_import.search(audit_source):
        raise VerificationError("planning audit imports network or valuation production code")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--valuation-repo", type=Path)
    args = parser.parse_args()
    repository = args.repository.resolve()
    kernel = (
        args.valuation_repo.resolve()
        if args.valuation_repo is not None
        else (repository.parent / "owner-valuation-kernel").resolve()
    )
    try:
        _verify_baselines(repository, kernel)
        _verify_kernel_hashes(repository, kernel)
        _verify_docs(repository)
        _verify_interface_matrix(repository, kernel)
        _verify_failure_matrix(repository)
        _verify_diff_boundary(repository, kernel)
    except (OSError, subprocess.CalledProcessError, VerificationError) as exc:
        raise SystemExit(f"Phase 5P planning verification failed: {exc}") from exc
    print("Phase 5P planning and pinned-interface verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
