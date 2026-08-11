from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


@dataclass(frozen=True, slots=True)
class VerificationResult:
    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key in component lock: {key}")
        value[key] = item
    return value


def load_component_lock(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_json_keys,
    )
    if not isinstance(value, dict):
        raise ValueError("component lock must be a JSON object")
    return value


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


def _read_package_file_nofollow(
    package_root: Path,
    relative_path: str,
    *,
    maximum_size: int = 8 * 1024 * 1024,
) -> bytes:
    """Read one locked package member without following or racing a symlink."""

    logical = PurePosixPath(relative_path)
    if logical.is_absolute() or not logical.parts or ".." in logical.parts:
        raise ValueError(f"locked package path is unsafe: {relative_path}")
    path = package_root.joinpath(*logical.parts)
    current = package_root
    for part in logical.parts[:-1]:
        current /= part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"locked package parent is unsafe: {relative_path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_size:
            raise ValueError(
                f"locked package member is not a bounded regular file: {relative_path}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_size + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_size:
                raise ValueError(f"locked package member exceeds its size limit: {relative_path}")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after:
            raise ValueError(f"locked package member changed while read: {relative_path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def verify_kernel_runtime_lock(lock_path: Path | None = None) -> VerificationResult:
    """Verify the packaged pinned-kernel runtime authority and executable code.

    The package directory, resource paths, and code paths are deliberately not
    caller-controlled.  A caller may supply only a lock file for adversarial
    validation; production uses the packaged/default component lock.
    """

    path = lock_path or default_component_lock_path()
    errors: list[str] = []
    try:
        lock = load_component_lock(path)
        runtime = lock["valuation_kernel_runtime"]
        kernel = lock["valuation_kernel"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return VerificationResult((f"Kernel runtime component lock is unavailable: {exc}",))

    expected_lock_keys = {
        "lock_version",
        "generated_date",
        "owner_equity_research",
        "market_access_authority",
        "valuation_kernel",
        "valuation_kernel_runtime",
    }
    if set(lock) != expected_lock_keys:
        return VerificationResult(("Kernel runtime top-level component-lock shape mismatch",))

    expected_runtime_keys = {
        "authority_version",
        "runtime_authority",
        "materializer_code",
        "runner_code",
        "expected_release_wheel_sha256",
        "manifest_policy_id",
        "manifest_policy_version",
    }
    if not isinstance(runtime, dict) or set(runtime) != expected_runtime_keys:
        return VerificationResult(("Kernel runtime component-lock shape mismatch",))
    if not isinstance(kernel, dict):
        return VerificationResult(("Kernel component-lock identity is not an object",))
    if lock.get("lock_version") != "1.2.0":
        errors.append("Kernel runtime requires component-lock 1.2.0")
    if runtime.get("authority_version") != "1.0.0":
        errors.append("Kernel runtime authority version mismatch")
    if runtime.get("manifest_policy_id") != "owner-research-pinned-kernel-runtime":
        errors.append("Kernel runtime manifest policy ID mismatch")
    if runtime.get("manifest_policy_version") != "1.0.0":
        errors.append("Kernel runtime manifest policy version mismatch")

    package_root = Path(__file__).resolve().parent
    locked_bytes: dict[str, bytes] = {}
    expected_paths = {
        "runtime_authority": "resources/phase5-v1-kernel-runtime/runtime-authority.json",
        "materializer_code": "valuation_kernel_materializer.py",
        "runner_code": "valuation_pinned_kernel.py",
    }
    for key in ("runtime_authority", "materializer_code", "runner_code"):
        entry = runtime.get(key)
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            errors.append(f"Kernel runtime {key} lock entry is invalid")
            continue
        relative = entry.get("path")
        expected = entry.get("sha256")
        if not isinstance(relative, str) or not isinstance(expected, str):
            errors.append(f"Kernel runtime {key} path or digest is invalid")
            continue
        if relative != expected_paths[key]:
            errors.append(f"Kernel runtime {key} path is not the closed package member")
            continue
        try:
            raw = _read_package_file_nofollow(package_root, relative)
        except (OSError, ValueError) as exc:
            errors.append(f"Kernel runtime {key} package member is unavailable: {exc}")
            continue
        locked_bytes[key] = raw
        if hashlib.sha256(raw).hexdigest() != expected:
            errors.append(f"Kernel runtime {key} hash mismatch")

    authority_raw = locked_bytes.get("runtime_authority")
    if authority_raw is None:
        return VerificationResult(tuple(errors))
    try:
        authority = json.loads(
            authority_raw,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        errors.append(f"Kernel runtime authority payload is invalid: {exc}")
        return VerificationResult(tuple(errors))
    if not isinstance(authority, dict) or not isinstance(authority.get("kernel"), dict):
        errors.append("Kernel runtime authority must contain a kernel object")
        return VerificationResult(tuple(errors))
    authority_kernel = authority["kernel"]

    if authority.get("schema_version") != runtime.get("authority_version"):
        errors.append("Kernel runtime authority Schema version mismatch")

    if (
        authority.get("policy_id") != runtime.get("manifest_policy_id")
        or authority.get("policy_version") != runtime.get("manifest_policy_version")
    ):
        errors.append("Kernel runtime manifest policy identity mismatch")
    if authority_kernel.get("wheel_sha256") != runtime.get(
        "expected_release_wheel_sha256"
    ):
        errors.append("Kernel runtime expected wheel hash mismatch")

    cross_links = {
        "repository": "repository",
        "tag": "tag",
        "tag_object": "annotated_tag_object",
        "commit": "commit",
        "package_version": "package_version",
        "plugin_version": "plugin_version",
        "source_manifest_sha256": "source_manifest_sha256",
        "release_manifest_sha256": "release_manifest_sha256",
    }
    for authority_key, lock_key in cross_links.items():
        if authority_kernel.get(authority_key) != kernel.get(lock_key):
            errors.append(f"Kernel runtime authority drifted at {authority_key}")
    release = kernel.get("release_evidence")
    if not isinstance(release, dict) or authority_kernel.get("wheel_sha256") != release.get(
        "wheel_sha256"
    ):
        errors.append("Kernel runtime wheel differs from pinned release evidence")

    authority_schemas = authority_kernel.get("schema_sha256")
    locked_schemas = kernel.get("public_schema_sha256")
    if not isinstance(authority_schemas, dict) or not isinstance(locked_schemas, dict):
        errors.append("Kernel runtime Schema authority is invalid")
    else:
        normalized = {
            f"schemas/{name}": digest for name, digest in authority_schemas.items()
        }
        if normalized != locked_schemas:
            errors.append("Kernel runtime Schema hashes differ from component lock")

    authority_runtime = authority.get("runtime")
    expected_runtime_keys = {
        "platform",
        "python_implementations",
        "result_schema",
        "container",
        "python_minors",
        "request_transport",
        "result_transport",
        "kernel_call",
        "kernel_call_count",
        "network_mode",
        "result_bytes_preserved",
    }
    if not isinstance(authority_runtime, dict) or set(authority_runtime) != expected_runtime_keys:
        errors.append("Kernel runtime execution authority shape mismatch")
        return VerificationResult(tuple(errors))
    expected_result_schema = {
        "filename": "valuation-result.schema.json",
        "sha256": authority_kernel.get("schema_sha256", {}).get(
            "valuation-result.schema.json"
        ),
    }
    if authority_runtime.get("result_schema") != expected_result_schema:
        errors.append("Kernel runtime result Schema authority drifted")

    container = authority_runtime.get("container")
    expected_container_keys = {
        "engine",
        "engine_path",
        "image_repository",
        "image_tag",
        "image_manifest_digest",
        "image_config_digest",
        "image_reference",
        "platform",
        "os",
        "architecture",
        "python_minor",
        "python_patch",
        "python_executable",
        "pull_policy",
        "network_mode",
        "read_only_rootfs",
        "cap_drop",
        "security_opt",
        "user_policy",
        "pids_limit",
        "memory_limit_bytes",
        "memory_swap_limit_bytes",
        "cpu_limit",
        "tmpfs",
        "ulimits",
        "read_only_mounts",
        "trusted_attestation_path_env",
        "trusted_attestation_sha256_env",
    }
    expected_container_identity = {
        "engine": "docker",
        "engine_path": "/usr/bin/docker",
        "image_repository": "docker.io/library/python",
        "image_tag": "3.11.15-bookworm",
        "image_manifest_digest": (
            "sha256:eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
        ),
        "image_config_digest": (
            "sha256:d299dee73063206fe64248b8eb62cbef36f6baedfc2c5e2ef4c7618ad18efb3a"
        ),
        "image_reference": (
            "docker.io/library/python@"
            "sha256:eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
        ),
        "platform": "linux/amd64",
        "os": "linux",
        "architecture": "amd64",
        "python_minor": "3.11",
        "python_patch": "3.11.15",
        "python_executable": "/usr/local/bin/python3",
        "pull_policy": "never",
        "network_mode": "none",
    }
    if not isinstance(container, dict) or set(container) != expected_container_keys:
        errors.append("Kernel runtime container authority shape mismatch")
    elif any(container.get(key) != value for key, value in expected_container_identity.items()):
        errors.append("Kernel runtime container identity drifted")
    if (
        authority_runtime.get("platform") != "linux_x86_64"
        or authority_runtime.get("python_implementations") != ["cpython"]
        or set(authority_runtime.get("python_minors", {})) != {"3.11"}
        or authority_runtime.get("request_transport") != "canonical_json_stdin"
        or authority_runtime.get("result_transport") != "canonical_json_stdout"
        or authority_runtime.get("kernel_call") != "owner_valuation.run_dual_panel"
        or authority_runtime.get("kernel_call_count") != 1
        or authority_runtime.get("network_mode") != "docker_network_none"
        or authority_runtime.get("result_bytes_preserved") is not True
    ):
        errors.append("Kernel runtime execution policy drifted")

    return VerificationResult(tuple(errors))


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

    errors.extend(verify_kernel_runtime_lock(lock_path).errors)

    return VerificationResult(tuple(errors))
