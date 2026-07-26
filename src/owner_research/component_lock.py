from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class VerificationResult:
    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


def load_component_lock(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def default_component_lock_path() -> Path:
    packaged = Path(__file__).parent / "component-lock.json"
    if packaged.is_file():
        return packaged
    repository = Path(__file__).parents[2] / "component-lock.json"
    if repository.is_file():
        return repository
    raise FileNotFoundError("component-lock.json is unavailable")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_research_schema_lock(lock_path: Path, repository_root: Path) -> VerificationResult:
    lock = load_component_lock(lock_path)
    errors: list[str] = []
    locked = lock["owner_equity_research"]["public_schema_sha256"]
    actual_paths = {
        str(path.relative_to(repository_root))
        for path in (repository_root / "schemas").glob("*.schema.json")
    }
    if set(locked) != actual_paths:
        errors.append(
            "Research schema lock set mismatch: "
            f"missing={sorted(actual_paths - set(locked))}, "
            f"extra={sorted(set(locked) - actual_paths)}"
        )
    for relative_path, expected in locked.items():
        path = repository_root / relative_path
        if not path.is_file():
            errors.append(f"Missing research schema: {relative_path}")
        elif file_sha256(path) != expected:
            errors.append(f"Research schema hash mismatch: {relative_path}")
    return VerificationResult(tuple(errors))


def verify_future_mapping_contract(
    mapping_path: Path,
    *,
    source_repo: Path,
) -> VerificationResult:
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if mapping.get("mapping_status") not in {
        "NOT_IMPLEMENTED_PHASE_1",
        "POLICY_DEFINED_PHASE_5B0",
        "RAW_IMPLEMENTED_PHASE_5B1",
        "DERIVED_IMPLEMENTED_PHASE_5B2",
        "READINESS_IMPLEMENTED_PHASE_5B3",
        "IMPLEMENTED_PHASE_5B",
    }:
        errors.append("Future mapping fixture has an unknown implementation state")

    target_path = source_repo / "schemas" / mapping.get("target_schema", "")
    if not target_path.is_file():
        return VerificationResult((f"Future mapping target schema is missing: {target_path}",))
    target = json.loads(target_path.read_text(encoding="utf-8"))
    target_fact = target.get("properties", {}).get("facts", {}).get("items", {})
    target_required = set(target_fact.get("required", []))
    policies = mapping.get("target_required_field_policy", {})
    if set(policies) != target_required:
        missing = sorted(target_required - set(policies))
        extra = sorted(set(policies) - target_required)
        errors.append(
            f"Future mapping policy does not cover target required fields; "
            f"missing={missing}, extra={extra}"
        )
    if any(not isinstance(policy, str) or not policy.strip() for policy in policies.values()):
        errors.append("Future mapping policy contains an empty decision")

    eligible = mapping.get("eligible_fact", {})
    required_source = {
        "fact_id",
        "concept",
        "value_type",
        "value",
        "unit",
        "currency",
        "period",
        "source_document_id",
        "source_locator",
        "confidence",
    }
    if not required_source.issubset(eligible):
        errors.append("Eligible research fact lacks required Phase 5 source fields")
    numeric_value = isinstance(eligible.get("value"), (int, float)) and not isinstance(
        eligible.get("value"), bool
    )
    if eligible.get("value_type") != "number" or not numeric_value:
        errors.append("Only a numeric research fact may enter the future mapping boundary")
    return VerificationResult(tuple(errors))


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def verify_component_lock(
    lock_path: Path,
    *,
    source_repo: Path,
    require_clean: bool = False,
    require_pinned_head: bool = False,
) -> VerificationResult:
    lock = load_component_lock(lock_path)
    kernel = lock["valuation_kernel"]
    errors: list[str] = []

    try:
        head = _git(source_repo, "rev-parse", "HEAD")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return VerificationResult((f"Cannot read valuation-kernel checkout: {exc}",))

    if require_pinned_head and head != kernel["commit"]:
        errors.append(f"HEAD {head} does not match pinned commit {kernel['commit']}")
    try:
        tag_object = _git(source_repo, "rev-parse", kernel["tag"])
        tag_type = _git(source_repo, "cat-file", "-t", kernel["tag"])
        tag_commit = _git(source_repo, "rev-parse", f"{kernel['tag']}^{{}}")
        if tag_type != "tag":
            errors.append(f"Tag {kernel['tag']} is not annotated")
        if tag_object != kernel.get("annotated_tag_object"):
            errors.append(
                f"Tag object {tag_object} does not match pinned annotated tag object"
            )
        if tag_commit != kernel["commit"]:
            errors.append(f"Tag {kernel['tag']} resolves to {tag_commit}, not pinned commit")
    except subprocess.CalledProcessError as exc:
        errors.append(f"Cannot resolve pinned tag {kernel['tag']}: {exc.output.strip()}")

    if require_clean and _git(source_repo, "status", "--porcelain"):
        errors.append("Valuation-kernel checkout is not clean")

    project = source_repo / "pyproject.toml"
    if not project.is_file() or f'version = "{kernel["package_version"]}"' not in project.read_text(
        encoding="utf-8"
    ):
        errors.append("Pinned valuation package version does not match component lock")

    for field, relative in (
        ("release_manifest_sha256", "references/release_manifest.json"),
        ("source_manifest_sha256", "references/source_manifest.json"),
    ):
        path = source_repo / relative
        if not path.is_file() or file_sha256(path) != kernel.get(field):
            errors.append(f"Pinned valuation {relative} does not match component lock")

    for relative_path, expected in kernel["public_schema_sha256"].items():
        path = source_repo / relative_path
        if not path.is_file():
            errors.append(f"Missing pinned schema: {relative_path}")
        elif file_sha256(path) != expected:
            errors.append(f"Schema hash mismatch: {relative_path}")

    manifest_path = source_repo / "plugins" / "owner-valuation" / ".codex-plugin" / "plugin.json"
    if not manifest_path.is_file():
        errors.append("Pinned valuation plugin manifest is missing")
    else:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("version") != kernel["plugin_version"]:
            errors.append("Pinned valuation plugin version does not match component lock")

    fact_schema_path = source_repo / "schemas" / "fact-ledger.schema.json"
    if fact_schema_path.is_file():
        schema = json.loads(fact_schema_path.read_text(encoding="utf-8"))
        facts = schema.get("properties", {}).get("facts", {}).get("items", {})
        required = set(facts.get("required", []))
        future_mapping_fields = {
            "fact_id",
            "concept",
            "value",
            "unit",
            "source_id",
            "source_location",
            "as_of_date",
        }
        if not future_mapping_fields.issubset(required):
            errors.append("Pinned FactLedger no longer exposes required Phase 5 mapping fields")
        if facts.get("properties", {}).get("value", {}).get("type") != "number":
            errors.append("Pinned FactLedger value is no longer numeric-only")

    return VerificationResult(tuple(errors))
