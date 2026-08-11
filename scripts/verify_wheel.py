#!/usr/bin/env python3
"""Verify the closed public contents and runtime bindings of a research wheel."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any
from zipfile import BadZipFile, ZipFile

REQUIRED = {
    "owner_research/__init__.py",
    "owner_research/component_lock.py",
    "owner_research/contracts.py",
    "owner_research/schemas/source-document.schema.json",
    "owner_research/schemas/filing-artifact.schema.json",
    "owner_research/schemas/business-model-snapshot.schema.json",
    "owner_research/schemas/management-statement.schema.json",
    "owner_research/schemas/capital-allocation-event.schema.json",
    "owner_research/research_bundle_builder.py",
    "owner_research/research_bundle_artifacts.py",
    "owner_research/schemas/research-bundle.schema.json",
    "owner_research/component-lock.json",
    "owner_research/resources/market_access/provider-registry.json",
    "owner_research/resources/market_access/calendar-registry.json",
    "owner_research/resources/market_access/calendars/XNYS-2026.json",
    "owner_research/resources/market_access/calendars/XNAS-2026.json",
    "owner_research/resources/market_access/security-identity-policy.json",
    "owner_research/resources/market_access/secret-policy.json",
    "owner_research/valuation_market_adapters.py",
    "owner_research/valuation_market_parsers.py",
    "owner_research/valuation_share_event_integration_types.py",
    "owner_research/resources/current_share/canonical-event-integration-policy.json",
    "owner_research/valuation_kernel_projection.py",
    "owner_research/valuation_final_request.py",
    "owner_research/valuation_owner_execution.py",
    "owner_research/valuation_kernel_materializer.py",
    "owner_research/valuation_pinned_kernel.py",
    "owner_research/resources/phase5-v1-kernel-runtime/runtime-authority.json",
}
FORBIDDEN_PREFIXES = ("tests/", "evals/", "plugins/", "docs/", ".git/")
RUNTIME_RESOURCE_PREFIX = "owner_research/resources/phase5-v1-kernel-runtime/"
RUNTIME_AUTHORITY = RUNTIME_RESOURCE_PREFIX + "runtime-authority.json"
EXPECTED_RELEASE_WHEEL_SHA256 = "fb27d01b1ee75fbd542371510150e890516d306218d33f3608f2aa3caa0e55a5"
EXPECTED_PACKAGE_INVENTORY_COUNT = 137
EXPECTED_PACKAGE_INVENTORY_SHA256 = (
    "953654f3aff238bd727d301760eb6eaa130f84ef16f4e6f200dfa612c5cd0fca"
)
EXPECTED_DIST_INFO = {
    "owner_equity_research-0.6.0.dev2.dist-info/METADATA",
    "owner_equity_research-0.6.0.dev2.dist-info/RECORD",
    "owner_equity_research-0.6.0.dev2.dist-info/WHEEL",
    "owner_equity_research-0.6.0.dev2.dist-info/entry_points.txt",
}
EXPECTED_RESULT_SCHEMA = {
    "filename": "valuation-result.schema.json",
    "sha256": "bbfed2049ed258b767002b74ff45fb6847eb5723ffd6c1d31c53cf119625a683",
}
EXPECTED_RUNTIME_DEPENDENCIES = [
    [
        "attrs-26.1.0-py3-none-any.whl",
        "c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309",
    ],
    [
        "jsonschema-4.26.0-py3-none-any.whl",
        "d489f15263b8d200f8387e64b4c3a75f06629559fb73deb8fdfb525f2dab50ce",
    ],
    [
        "jsonschema_specifications-2025.9.1-py3-none-any.whl",
        "98802fee3a11ee76ecaca44429fda8a41bff98b00a0f2838151b113f210cc6fe",
    ],
    [
        "referencing-0.37.0-py3-none-any.whl",
        "381329a9f99628c9069361716891d34ad94af76e461dcb0335825aecc7692231",
    ],
    [
        "rpds_py-2026.6.3-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "9c1255b302953c86a486b81d330d5ee1d5bd937691ce271b6be0ef0e299eaab7",
    ],
    [
        "typing_extensions-4.16.0-py3-none-any.whl",
        "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8",
    ],
]
EXPECTED_RUNTIME_CONTAINER = {
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
        "docker.io/library/python@sha256:"
        "eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
    ),
    "platform": "linux/amd64",
    "os": "linux",
    "architecture": "amd64",
    "python_minor": "3.11",
    "python_patch": "3.11.15",
    "python_executable": "/usr/local/bin/python3",
    "pull_policy": "never",
    "network_mode": "none",
    "read_only_rootfs": True,
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "user_policy": "host_uid_gid",
    "pids_limit": 64,
    "memory_limit_bytes": 1610612736,
    "memory_swap_limit_bytes": 1610612736,
    "cpu_limit": "1.0",
    "tmpfs": ["/tmp:rw,exec,nosuid,nodev,size=268435456,mode=1777"],
    "ulimits": ["core=0:0", "fsize=67108864:67108864", "nofile=64:64"],
    "read_only_mounts": ["manifest", "request", "runner", "wheelhouse"],
}
EXPECTED_TRUSTED_WORKFLOW = {
    "attestation_path": "/run/owner-research/trusted-container-attestation.json",
    "attestation_mount_target": "/run/owner-research",
    "attestation_sha256_env": "OWNER_RESEARCH_TRUSTED_CONTAINER_ATTESTATION_SHA256",
    "read_only_mounts": [
        {"role": "candidate_workspace", "target": "/workspace"},
        {"role": "private_kernel_checkout", "target": "/private-kernel"},
        {"role": "binary_supply_wheelhouse", "target": "/supply"},
        {"role": "binary_supply_lock", "target": "/supply.lock"},
        {"role": "verified_research_wheel", "target": "/research-wheel"},
        {"role": "runtime_cas", "target": "/runtime-cas"},
        {
            "role": "trusted_attestation_directory",
            "target": "/run/owner-research",
        },
    ],
    "writable_mounts": [
        {"role": "canonical_summary_output", "target": "/output"}
    ],
}
LOCKED_RUNTIME_MEMBERS = {
    "runtime_authority": RUNTIME_AUTHORITY,
    "materializer_code": "owner_research/valuation_kernel_materializer.py",
    "runner_code": "owner_research/valuation_pinned_kernel.py",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _load_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not a JSON object")
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _runtime_binding_errors(archive: ZipFile) -> list[str]:
    errors: list[str] = []
    try:
        lock = _load_json(archive.read("owner_research/component-lock.json"), "component lock")
        authority = _load_json(archive.read(RUNTIME_AUTHORITY), "runtime authority")
        runtime_lock = lock["valuation_kernel_runtime"]
        kernel_lock = lock["valuation_kernel"]
    except (KeyError, ValueError) as exc:
        return [f"wheel runtime authority is unavailable: {exc}"]

    expected_runtime_keys = {
        "authority_version",
        "runtime_authority",
        "materializer_code",
        "runner_code",
        "expected_release_wheel_sha256",
        "manifest_policy_id",
        "manifest_policy_version",
    }
    if set(lock) != {
        "lock_version",
        "generated_date",
        "owner_equity_research",
        "market_access_authority",
        "valuation_kernel_runtime",
        "valuation_kernel",
    }:
        errors.append("embedded component-lock top-level shape is not closed")
    if lock.get("lock_version") != "1.2.0":
        errors.append("embedded component-lock version is not 1.2.0")
    if not isinstance(runtime_lock, dict) or set(runtime_lock) != expected_runtime_keys:
        return [*errors, "embedded kernel-runtime lock shape is not closed"]
    if not isinstance(kernel_lock, dict):
        return [*errors, "embedded valuation-kernel lock is not an object"]

    for key, member in LOCKED_RUNTIME_MEMBERS.items():
        entry = runtime_lock.get(key)
        expected_path = member.removeprefix("owner_research/")
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            errors.append(f"embedded runtime lock entry is invalid: {key}")
            continue
        if entry.get("path") != expected_path:
            errors.append(f"embedded runtime lock path drifted: {key}")
            continue
        raw = archive.read(member)
        if entry.get("sha256") != _sha256(raw):
            errors.append(f"embedded runtime member hash mismatch: {key}")

    kernel = authority.get("kernel")
    if not isinstance(kernel, dict):
        return [*errors, "embedded runtime authority kernel is not an object"]
    runtime = authority.get("runtime")
    if set(authority) != {
        "schema_version",
        "policy_id",
        "policy_version",
        "kernel",
        "build",
        "runtime",
    }:
        errors.append("runtime authority top-level shape is not closed")
    if not isinstance(runtime, dict):
        return [*errors, "runtime authority runtime is not an object"]
    if runtime.get("container") != EXPECTED_RUNTIME_CONTAINER:
        errors.append("runtime container identity is not the pinned image")
    if runtime.get("trusted_workflow") != EXPECTED_TRUSTED_WORKFLOW:
        errors.append("runtime trusted-workflow boundary is not pinned")
    if runtime.get("result_schema") != EXPECTED_RESULT_SCHEMA:
        errors.append("runtime result Schema identity is not pinned")
    if (
        isinstance(kernel.get("schema_sha256"), dict)
        and kernel["schema_sha256"].get(EXPECTED_RESULT_SCHEMA["filename"])
        != EXPECTED_RESULT_SCHEMA["sha256"]
    ):
        errors.append("runtime result Schema differs from the kernel Schema map")
    if set(runtime) != {
        "platform",
        "python_implementations",
        "result_schema",
        "container",
        "trusted_workflow",
        "python_minors",
        "request_transport",
        "result_transport",
        "kernel_call",
        "kernel_call_count",
        "network_mode",
        "result_bytes_preserved",
    }:
        errors.append("runtime authority runtime shape is not closed")
    if runtime.get("python_minors") != {"3.11": EXPECTED_RUNTIME_DEPENDENCIES}:
        errors.append("runtime Python-minor inventory is not closed")
    expected_runtime_transport = {
        "platform": "linux_x86_64",
        "python_implementations": ["cpython"],
        "request_transport": "canonical_json_stdin",
        "result_transport": "canonical_json_stdout",
        "kernel_call": "owner_valuation.run_dual_panel",
        "kernel_call_count": 1,
        "network_mode": "docker_network_none",
        "result_bytes_preserved": True,
    }
    if any(runtime.get(key) != value for key, value in expected_runtime_transport.items()):
        errors.append("runtime transport authority is not pinned")
    if runtime_lock.get("authority_version") != "1.0.0":
        errors.append("runtime authority version is not the pinned value")
    if (
        runtime_lock.get("manifest_policy_id") != "owner-research-pinned-kernel-runtime"
        or runtime_lock.get("manifest_policy_version") != "1.0.0"
    ):
        errors.append("runtime policy identity is not the pinned value")
    if runtime_lock.get("expected_release_wheel_sha256") != EXPECTED_RELEASE_WHEEL_SHA256:
        errors.append("runtime release-wheel hash is not the pinned value")
    if authority.get("schema_version") != runtime_lock.get("authority_version"):
        errors.append("runtime authority version differs from the component lock")
    if (
        authority.get("policy_id") != runtime_lock.get("manifest_policy_id")
        or authority.get("policy_version") != runtime_lock.get("manifest_policy_version")
    ):
        errors.append("runtime policy identity differs from the component lock")
    wheel_sha256 = kernel.get("wheel_sha256")
    if wheel_sha256 != runtime_lock.get("expected_release_wheel_sha256"):
        errors.append("runtime release-wheel hash differs from the runtime lock")
    release_evidence = kernel_lock.get("release_evidence")
    if not isinstance(release_evidence, dict) or wheel_sha256 != release_evidence.get(
        "wheel_sha256"
    ):
        errors.append("runtime release-wheel hash differs from release evidence")

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
        if kernel.get(authority_key) != kernel_lock.get(lock_key):
            errors.append(f"runtime kernel identity drifted: {authority_key}")
    schemas = kernel.get("schema_sha256")
    locked_schemas = kernel_lock.get("public_schema_sha256")
    if not isinstance(schemas, dict) or not isinstance(locked_schemas, dict):
        errors.append("runtime Schema hash maps are invalid")
    elif {f"schemas/{name}": digest for name, digest in schemas.items()} != locked_schemas:
        errors.append("runtime Schema hashes differ from the valuation-kernel lock")
    return errors


def verify(wheel: Path) -> tuple[str, ...]:
    errors: list[str] = []
    try:
        metadata = wheel.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            return ("wheel path is not a regular non-symlink file",)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(wheel, flags)
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as handle, ZipFile(handle) as archive:
                infos = archive.infolist()
                ordered_names = [item.filename for item in infos]
                names = set(ordered_names)
                if len(ordered_names) != len(names):
                    errors.append("wheel contains duplicate archive members")
                for item in infos:
                    logical = PurePosixPath(item.filename)
                    mode = item.external_attr >> 16
                    if (
                        not item.filename
                        or item.filename.startswith("/")
                        or "\\" in item.filename
                        or ".." in logical.parts
                        or stat.S_ISLNK(mode)
                    ):
                        errors.append(f"wheel contains an unsafe member: {item.filename!r}")
                if archive.testzip() is not None:
                    errors.append("wheel CRC verification failed")
                missing = sorted(REQUIRED - names)
                if missing:
                    errors.append(f"wheel is missing required entries: {missing}")
                package_members = sorted(
                    name for name in names if ".dist-info/" not in name
                )
                package_inventory_sha256 = _sha256(
                    json.dumps(
                        package_members, ensure_ascii=False, separators=(",", ":")
                    ).encode()
                )
                dist_info = {name for name in names if ".dist-info/" in name}
                if (
                    len(package_members) != EXPECTED_PACKAGE_INVENTORY_COUNT
                    or package_inventory_sha256 != EXPECTED_PACKAGE_INVENTORY_SHA256
                    or dist_info != EXPECTED_DIST_INFO
                ):
                    errors.append("wheel member inventory is not the exact public projection")
                forbidden = sorted(
                    name
                    for name in names
                    if name.startswith(FORBIDDEN_PREFIXES)
                    or name.endswith(".html")
                    or name.lower().endswith(".whl")
                    or "owner_valuation" in PurePosixPath(name).parts
                    or (name.startswith(RUNTIME_RESOURCE_PREFIX) and name != RUNTIME_AUTHORITY)
                )
                if forbidden:
                    errors.append(
                        "wheel contains repository-only, private-kernel, or generated runtime "
                        f"content: {forbidden}"
                    )
                if not missing and not errors:
                    errors.extend(_runtime_binding_errors(archive))
        finally:
            os.close(descriptor)
    except (BadZipFile, OSError, ValueError) as exc:
        errors.append(f"wheel could not be verified: {exc}")
    return tuple(errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    errors = verify(args.wheel)
    for error in errors:
        print(error)
    if errors:
        return 1
    print(f"wheel content verification passed: {args.wheel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
