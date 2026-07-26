#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AUDIT_TOOL = "owner-research-phase4c-readonly"
AUDIT_VERSION = "1.5.5"


def _git(repository: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def _record(
    checks: list[dict[str, Any]],
    findings: list[dict[str, str]],
    *,
    check_id: str,
    passed: bool,
    summary: str,
    evidence: str,
    priority: str = "P1",
) -> None:
    digest = hashlib.sha256(evidence.encode()).hexdigest()
    checks.append(
        {
            "check_id": check_id,
            "status": "passed" if passed else "failed",
            "evidence_sha256": digest,
        }
    )
    if not passed:
        findings.append(
            {
                "finding_id": f"{priority}:{check_id}",
                "priority": priority,
                "check_id": check_id,
                "summary": summary,
                "evidence_sha256": digest,
            }
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--valuation-repo", type=Path, required=True)
    parser.add_argument("--reviewed-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    repository = args.repository.resolve()
    checks: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    head = _git(repository, "rev-parse", "HEAD")
    _record(
        checks,
        findings,
        check_id="reviewed-commit",
        passed=head == args.reviewed_commit,
        summary="Audit checkout does not match the reviewed commit.",
        evidence=f"expected={args.reviewed_commit}\nactual={head}",
    )
    remotes = _git(repository, "remote")
    _record(
        checks,
        findings,
        check_id="no-remote",
        passed=not remotes,
        summary="Audit checkout retains a Git remote.",
        evidence=remotes or "no remotes",
    )
    business_schema = json.loads(
        (repository / "schemas" / "business-model-snapshot.schema.json").read_text(
            encoding="utf-8"
        )
    )
    candidate_schema = json.loads(
        (repository / "schemas" / "analytical-claim-candidate.schema.json").read_text(
            encoding="utf-8"
        )
    )
    component_properties = business_schema["$defs"]["component"]["properties"]
    semantic_contract_ok = (
        business_schema["properties"]["schema_version"].get("const") == "3.0.0"
        and candidate_schema["properties"]["schema_version"].get("const") == "2.0.0"
        and "material_scopes" in business_schema["properties"]
        and "shared_scope_relations" in business_schema["properties"]
        and "attribute_evidence_bindings" in component_properties
        and "business_attribute_role" in candidate_schema["properties"]
        and "business_component_type" in candidate_schema["properties"]
    )
    _record(
        checks,
        findings,
        check_id="phase4c2-semantic-contract",
        passed=semantic_contract_ok,
        summary="Phase 4C-2 semantic evidence or material-scope contract is missing.",
        evidence=json.dumps(
            {
                "business_model_version": business_schema["properties"][
                    "schema_version"
                ].get("const"),
                "candidate_version": candidate_schema["properties"]["schema_version"].get(
                    "const"
                ),
                "component_fields": sorted(component_properties),
            },
            sort_keys=True,
        ),
    )
    diagnostics = (
        repository / "src" / "owner_research" / "mechanism_diagnostics.py"
    ).read_text(encoding="utf-8")
    required_diagnostic_boundaries = {
        'DIAGNOSTIC_VERSION = "1.0.0"',
        'CALCULATOR_ID = "owner-research-mechanism-diagnostics"',
        "input_unit_rules",
        "period_semantics",
        "allowed_scope_types",
        "minimum_observations",
        "forbidden_shortcuts",
        "input_assumption_ids\": []",
        "diagnostic scope lacks a deterministic Fact mapping",
    }
    missing_diagnostic_boundaries = sorted(
        token for token in required_diagnostic_boundaries if token not in diagnostics
    )
    _record(
        checks,
        findings,
        check_id="phase4c3-mechanism-diagnostic-boundary",
        passed=not missing_diagnostic_boundaries,
        summary="Phase 4C-3 deterministic diagnostic boundary is incomplete.",
        evidence=json.dumps(
            {"missing_tokens": missing_diagnostic_boundaries}, sort_keys=True
        ),
    )
    resolver_text = (
        repository / "src" / "owner_research" / "competitive_advantages.py"
    ).read_text(encoding="utf-8")
    review_text = (
        repository / "src" / "owner_research" / "analytical_claims.py"
    ).read_text(encoding="utf-8")
    validation_text = (
        repository / "src" / "owner_research" / "validation.py"
    ).read_text(encoding="utf-8")
    required_resolver_boundaries = {
        "review_analytical_claim_candidate": review_text,
        "resolve_competitive_advantage_hypothesis": resolver_text,
        "predecessor counterevidence cannot be deleted": resolver_text,
        "falsifying status requires a reviewed falsification Claim": resolver_text,
        "status was not deterministically resolved": validation_text,
    }
    missing_resolver_boundaries = sorted(
        token for token, content in required_resolver_boundaries.items() if token not in content
    )
    _record(
        checks,
        findings,
        check_id="phase4c4-reviewed-hypothesis-resolver",
        passed=not missing_resolver_boundaries,
        summary="Phase 4C-4 reviewed Claim or deterministic resolver boundary is incomplete.",
        evidence=json.dumps(
            {"missing_tokens": missing_resolver_boundaries}, sort_keys=True
        ),
    )
    review_builder = (
        repository / "src" / "owner_research" / "business_quality_reviews.py"
    ).read_text(encoding="utf-8")
    primary_skill = (
        repository
        / "plugins"
        / "owner-equity-research"
        / "skills"
        / "owner-equity-research"
    )
    required_reference_files = {
        "business-model.md",
        "mechanism-diagnostics.md",
        "hypothesis-review.md",
        "business-quality-review-shadow.md",
    }
    reference_files = {
        item.name for item in (primary_skill / "references").glob("*.md")
    }
    shadow_dir = repository / "evals" / "shadow" / "2026-07-11"
    shadow_files = {
        "business-quality-amazon.json",
        "business-quality-salesforce.json",
        "business-quality-union-pacific.json",
    }
    closeout_ok = (
        "build_business_quality_review" in review_builder
        and "latest_hypotheses" in review_builder
        and 'for status in ("proposed", "supported", "contested", "falsified", "blocked")'
        in review_builder
        and required_reference_files.issubset(reference_files)
        and all((shadow_dir / item).is_file() for item in shadow_files)
    )
    _record(
        checks,
        findings,
        check_id="phase4c5-review-shadow-closeout",
        passed=closeout_ok,
        summary="Phase 4C-5 deterministic Review or metadata-only shadow boundary is incomplete.",
        evidence=json.dumps(
            {
                "reference_files": sorted(reference_files),
                "shadow_files": sorted(
                    item for item in shadow_files if (shadow_dir / item).is_file()
                ),
            },
            sort_keys=True,
        ),
    )
    tracked = _git(repository, "ls-files").splitlines()
    writable = [
        item
        for item in tracked
        if (repository / item).stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    ]
    _record(
        checks,
        findings,
        check_id="readonly-tree",
        passed=not writable,
        summary="Audit checkout contains writable tracked files.",
        evidence="\n".join(writable) if writable else "all tracked files read-only",
    )
    before = _git(repository, "status", "--porcelain")
    _record(
        checks,
        findings,
        check_id="clean-before",
        passed=not before,
        summary="Audit checkout is dirty before verification.",
        evidence=before or "clean",
    )

    test_manifest = args.output.with_name("phase4c-test-counts.json")
    environment = os.environ.copy()
    environment["OWNER_VALUATION_REPO"] = str(args.valuation_repo.resolve())
    completed = subprocess.run(
        [
            sys.executable,
            str(repository / "scripts" / "verify_all.py"),
            "--test-manifest",
            str(test_manifest),
        ],
        cwd=repository,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    _record(
        checks,
        findings,
        check_id="repository-verification",
        passed=completed.returncode == 0,
        summary="Phase 4C repository verification failed.",
        evidence=completed.stdout,
    )
    after = _git(repository, "status", "--porcelain")
    _record(
        checks,
        findings,
        check_id="clean-after",
        passed=not after,
        summary="Verification modified the read-only audit checkout.",
        evidence=after or "clean",
    )
    test_counts = (
        json.loads(test_manifest.read_text(encoding="utf-8"))
        if test_manifest.is_file()
        else {"collected_tests": 0, "passed_tests": 0, "skipped_tests": 0, "failed_tests": 1}
    )
    payload = {
        "audit_tool": AUDIT_TOOL,
        "audit_version": AUDIT_VERSION,
        "reviewed_commit": args.reviewed_commit,
        "started_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "test_counts": test_counts,
        "checks": checks,
        "findings": findings,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 1 if any(item["priority"] in {"P0", "P1"} for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
