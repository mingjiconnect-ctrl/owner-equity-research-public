from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUPPLY = PROJECT_ROOT / "supply"
LOCK = SUPPLY / "dependency-lock-v1.json"
GENERATED = {
    SUPPLY / "sbom.cdx.json",
    SUPPLY / "source-inputs-v1.json",
    SUPPLY / "provenance-build-definition-v1.json",
    SUPPLY / "sidecar-source-manifest-v1.json",
}
EXCLUDED_PARTS = {
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
}
MAXIMUM_SOURCE_MEMBERS = 512
MAXIMUM_MEMBER_BYTES = 16 * 1024 * 1024
MAXIMUM_TOTAL_BYTES = 64 * 1024 * 1024
PROJECT_LICENSE_EXPRESSION = "LicenseRef-Owner-Research-Proprietary"


@dataclass(frozen=True, slots=True)
class _Snapshot:
    raw: bytes
    mode: int


@dataclass(slots=True)
class _ReadBudget:
    maximum_members: int = MAXIMUM_SOURCE_MEMBERS
    maximum_bytes: int = MAXIMUM_TOTAL_BYTES
    consumed_members: int = 0
    consumed_bytes: int = 0
    _snapshots: dict[str, _Snapshot] = field(default_factory=dict)

    def read(self, path: Path, *, maximum_bytes: int = MAXIMUM_MEMBER_BYTES) -> _Snapshot:
        key = os.path.abspath(os.fspath(path))
        cached = self._snapshots.get(key)
        if cached is not None:
            return cached
        if self.consumed_members >= self.maximum_members:
            raise ValueError("source member-count budget exceeded")

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ValueError(f"source member cannot be opened safely: {path}") from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError(f"source member is not a single-link regular file: {path}")
            if before.st_size > maximum_bytes:
                raise ValueError(f"source member exceeds its byte limit: {path}")
            if self.consumed_bytes + before.st_size > self.maximum_bytes:
                raise ValueError("source cumulative byte budget exceeded")
            raw = bytearray()
            while len(raw) <= maximum_bytes:
                chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(descriptor)
            identity = lambda item: (  # noqa: E731 - compact immutable identity helper
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
            if identity(before) != identity(after) or len(raw) != before.st_size:
                raise ValueError(f"source member changed while being read: {path}")
            if len(raw) > maximum_bytes:
                raise ValueError(f"source member exceeds its byte limit: {path}")
            snapshot = _Snapshot(bytes(raw), stat.S_IMODE(before.st_mode))
        finally:
            os.close(descriptor)
        self._snapshots[key] = snapshot
        self.consumed_members += 1
        self.consumed_bytes += len(snapshot.raw)
        return snapshot


def _bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _read_json(path: Path, *, budget: _ReadBudget) -> tuple[dict[str, Any], bytes]:
    raw = budget.read(path).raw
    value = json.loads(
        raw,
        object_pairs_hook=_reject_duplicates,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict):
        raise ValueError(f"expected object: {path}")
    return value, raw


def _write(path: Path, value: dict[str, Any]) -> None:
    path.write_bytes(_canonical_bytes(value) + b"\n")


def _sbom(lock: dict[str, Any], *, lock_raw: bytes) -> dict[str, Any]:
    lock_sha = _bytes_sha256(lock_raw)
    components = []
    for item in lock["components"]:
        components.append(
            {
                "bom-ref": f"pkg:pypi/{item['name']}@{item['version']}",
                "type": "library",
                "name": item["name"],
                "version": item["version"],
                "scope": "required" if "runtime" in item["scopes"] else "excluded",
                "purl": f"pkg:pypi/{item['name']}@{item['version']}",
                "hashes": [{"alg": "SHA-256", "content": item["sha256"]}],
                "licenses": [{"expression": item["license"]}],
                "properties": [
                    {
                        "name": "owner-research:artifact",
                        "value": item["artifact"],
                    },
                    {
                        "name": "owner-research:scopes",
                        "value": ",".join(item["scopes"]),
                    },
                ],
            }
        )
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, lock_sha)}",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": "pkg:pypi/owner-research-futu-sidecar@1.0.0.dev0",
                "type": "application",
                "name": "owner-research-futu-sidecar",
                "version": "1.0.0.dev0",
                "licenses": [{"expression": PROJECT_LICENSE_EXPRESSION}],
            },
            "properties": [
                {
                    "name": "owner-research:dependency-lock-sha256",
                    "value": lock_sha,
                },
                {
                    "name": "owner-research:raw-vendor-data-included",
                    "value": "false",
                },
            ],
        },
        "components": components,
    }


def _source_inputs(*, budget: _ReadBudget) -> dict[str, Any]:
    paths = [
        "pyproject.toml",
        "resources/futu-api-runtime-tree-v1.json",
        "resources/sdk-adapter-registry-v1.json",
        "supply/dependency-lock-v1.json",
        "wire/v2/common.schema.json",
        "wire/v2/request.schema.json",
        "wire/v2/response.schema.json",
    ]
    inputs = []
    for relative in paths:
        raw = budget.read(PROJECT_ROOT / relative).raw
        inputs.append({"path": relative, "sha256": _bytes_sha256(raw), "size": len(raw)})
    return {
        "schema_version": "1.0.0",
        "manifest_id": "owner-research-futu-sidecar-source-inputs-v1",
        "final_release_binding": "required_from_external_supply_verifier",
        "protobuf_descriptor_set_sha256": (
            "c2b13581ef9acdbe2b9a95da26b95d6321058f7beb27b56fef90908519e312f8"
        ),
        "futu_api_sdist_sha256": (
            "3c607c7dce02a3a2b308f3424420277a360d7b3a4ba4508b39eaa4ff11271f98"
        ),
        "inputs": inputs,
    }


def _provenance(
    lock: dict[str, Any],
    *,
    lock_raw: bytes,
    sbom_raw: bytes,
    source_inputs_raw: bytes,
) -> dict[str, Any]:
    lock_sha = _bytes_sha256(lock_raw)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "dependency-lock-v1.json",
                "digest": {"sha256": lock_sha},
            },
            {
                "name": "sbom.cdx.json",
                "digest": {"sha256": _bytes_sha256(sbom_raw)},
            },
            {
                "name": "source-inputs-v1.json",
                "digest": {"sha256": _bytes_sha256(source_inputs_raw)},
            },
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://owner-research.invalid/build/futu-sidecar/v1",
                "externalParameters": {
                    "python_requires": lock["python_requires"],
                    "bytecode_compilation": False,
                    "network_policy": "dependency-fetch-only-before-isolated-build",
                    "raw_vendor_data_included": False,
                },
                "internalParameters": {
                    "final_subjects_required": True,
                    "exact_commit_tree_required": True,
                },
                "resolvedDependencies": [
                    {
                        "uri": f"pkg:pypi/{item['name']}@{item['version']}",
                        "digest": {"sha256": item["sha256"]},
                    }
                    for item in lock["components"]
                ],
            },
            "runDetails": {
                "builder": {"id": "owner-research:release-supply-verifier"},
                "metadata": {"invocationId": ("urn:sha256:" + _bytes_sha256(source_inputs_raw))},
                "byproducts": [],
            },
        },
    }


def _source_manifest(*, budget: _ReadBudget) -> dict[str, Any]:
    manifest_path = SUPPLY / "sidecar-source-manifest-v1.json"
    members = []
    for path in sorted(PROJECT_ROOT.rglob("*")):
        if path == manifest_path:
            continue
        relative = path.relative_to(PROJECT_ROOT)
        if any(part in EXCLUDED_PARTS or part.startswith(".") for part in relative.parts):
            continue
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"unsafe source member: {relative}")
        snapshot = budget.read(path)
        raw = snapshot.raw
        members.append(
            {
                "mode": f"{snapshot.mode:04o}",
                "path": relative.as_posix(),
                "sha256": _bytes_sha256(raw),
                "size": len(raw),
            }
        )
    return {
        "schema_version": "1.0.0",
        "manifest_id": "owner-research-futu-sidecar-source-manifest-v1",
        "self_member_excluded": "supply/sidecar-source-manifest-v1.json",
        "external_signature_required": True,
        "member_count": len(members),
        "members": members,
        "tree_sha256": _bytes_sha256(_canonical_bytes(members)),
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        print("usage: generate_supply_artifacts.py", file=sys.stderr)
        return 2
    initial_budget = _ReadBudget()
    lock, lock_raw = _read_json(LOCK, budget=initial_budget)
    canonical_lock_raw = _canonical_bytes(lock) + b"\n"
    if lock_raw != canonical_lock_raw:
        _write(LOCK, lock)
    budget = _ReadBudget()
    lock, lock_raw = _read_json(LOCK, budget=budget)
    sbom = _sbom(lock, lock_raw=lock_raw)
    source_inputs = _source_inputs(budget=budget)
    _write(SUPPLY / "sbom.cdx.json", sbom)
    _write(SUPPLY / "source-inputs-v1.json", source_inputs)
    _write(
        SUPPLY / "provenance-build-definition-v1.json",
        _provenance(
            lock,
            lock_raw=lock_raw,
            sbom_raw=_canonical_bytes(sbom) + b"\n",
            source_inputs_raw=_canonical_bytes(source_inputs) + b"\n",
        ),
    )
    _write(
        SUPPLY / "sidecar-source-manifest-v1.json",
        _source_manifest(budget=budget),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
