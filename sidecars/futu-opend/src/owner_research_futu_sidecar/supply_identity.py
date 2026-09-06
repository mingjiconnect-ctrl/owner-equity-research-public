from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .attestation import validate_supply_attestation
from .canonical import (
    SidecarContractError,
    bytes_sha256,
    canonical_bytes,
    canonical_sha256,
    reject_duplicate_pairs,
    require_sha256,
)
from .secure_reader import ReadBudget, read_bounded_snapshot

SIDECAR_PROVIDER_ID = "futu-opend-official"
SIDECAR_PROVIDER_VERSION = "1.0.0.dev0"
MAXIMUM_IDENTITY_FILE_BYTES = 16 * 1024 * 1024
MAXIMUM_IDENTITY_CUMULATIVE_BYTES = 64 * 1024 * 1024

_PACKAGE_ROOT = Path(__file__).absolute().parent
_RUNTIME_SOURCE_MEMBERS = (
    "__init__.py",
    "attestation.py",
    "canonical.py",
    "cas.py",
    "cli.py",
    "frame_guard.py",
    "launcher.py",
    "opend_adapter.py",
    "operation_registry.py",
    "protobuf_parser.py",
    "runtime_authorization.py",
    "sdk_logging.py",
    "secure_reader.py",
    "server.py",
    "supervisor.py",
    "supply_identity.py",
    "wire.py",
)
_WIRE_DESCRIPTOR_MEMBERS = (
    "wire/v3/common.schema.json",
    "wire/v3/request.schema.json",
    "wire/v3/response.schema.json",
)
_SOURCE_INPUT_PATHS = (
    "pyproject.toml",
    "resources/futu-api-runtime-tree-v1.json",
    "resources/sdk-adapter-registry-v1.json",
    "supply/dependency-lock-v1.json",
    *_WIRE_DESCRIPTOR_MEMBERS,
)
_GENERATED_SUPPLY_MEMBERS = (
    "supply/sbom.cdx.json",
    "supply/source-inputs-v1.json",
    "supply/provenance-build-definition-v1.json",
    "supply/sidecar-source-manifest-v1.json",
)
_REQUIRED_SOURCE_MANIFEST_MEMBERS = (
    "pyproject.toml",
    *(f"src/owner_research_futu_sidecar/{name}" for name in _RUNTIME_SOURCE_MEMBERS),
    "resources/futu-api-runtime-tree-v1.json",
    "resources/sdk-adapter-registry-v1.json",
    "wire/v3/README.md",
    *_WIRE_DESCRIPTOR_MEMBERS,
    "launcher/README.md",
    "launcher/launch-rootless.sh",
    "launcher/owner-research-futu-sidecar.service.in",
    "supply/README.md",
    "supply/THIRD_PARTY_NOTICES.md",
    "supply/dependency-lock-v1.json",
    *_GENERATED_SUPPLY_MEMBERS[:-1],
)


class SupplyIdentityError(SidecarContractError):
    """Raised when installed sidecar bytes differ from signed supply identity."""


@dataclass(frozen=True, slots=True)
class LocalSupplyIdentity:
    protocol_descriptor_sha256: str
    facade_sha256: str
    adapter_sha256: str
    parser_sha256: str
    source_manifest_tree_sha256: str
    sbom_sha256: str
    source_inputs_sha256: str
    provenance_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "protocol_descriptor_sha256": self.protocol_descriptor_sha256,
            "facade_sha256": self.facade_sha256,
            "adapter_sha256": self.adapter_sha256,
            "parser_sha256": self.parser_sha256,
            "source_manifest_tree_sha256": self.source_manifest_tree_sha256,
            "sbom_sha256": self.sbom_sha256,
            "source_inputs_sha256": self.source_inputs_sha256,
            "provenance_sha256": self.provenance_sha256,
        }


def verify_local_supply_identity() -> LocalSupplyIdentity:
    budget = ReadBudget(MAXIMUM_IDENTITY_CUMULATIVE_BYTES)
    actual_modules = {path.name for path in _PACKAGE_ROOT.iterdir() if path.name.endswith(".py")}
    if actual_modules != set(_RUNTIME_SOURCE_MEMBERS):
        raise SupplyIdentityError("installed sidecar Python member set differs from authority")
    source_records = _records(
        tuple((name, _PACKAGE_ROOT / name) for name in _RUNTIME_SOURCE_MEMBERS),
        budget=budget,
    )
    source_by_name = {record["path"]: record for record in source_records}
    descriptor_records = _records(
        tuple((name, _runtime_path(name)) for name in _WIRE_DESCRIPTOR_MEMBERS),
        budget=budget,
    )
    artifacts = _verify_supply_artifacts(budget=budget)
    return LocalSupplyIdentity(
        protocol_descriptor_sha256=canonical_sha256(
            {
                "domain": "owner-research-futu-wire-descriptor-v2",
                "members": descriptor_records,
            }
        ),
        facade_sha256=canonical_sha256(
            {
                "domain": "owner-research-futu-runtime-and-supply-v2",
                "members": source_records,
                "supply": artifacts,
            }
        ),
        adapter_sha256=source_by_name["opend_adapter.py"]["sha256"],
        parser_sha256=source_by_name["protobuf_parser.py"]["sha256"],
        source_manifest_tree_sha256=artifacts["source_manifest_tree_sha256"],
        sbom_sha256=artifacts["sbom_sha256"],
        source_inputs_sha256=artifacts["source_inputs_sha256"],
        provenance_sha256=artifacts["provenance_sha256"],
    )


def verify_local_supply_attestation(value: Any) -> dict[str, str]:
    attestation = validate_supply_attestation(value)
    local = verify_local_supply_identity()
    if (
        attestation["provider_id"] != SIDECAR_PROVIDER_ID
        or attestation["provider_version"] != SIDECAR_PROVIDER_VERSION
        or attestation["protocol_descriptor_sha256"] != local.protocol_descriptor_sha256
        or attestation["facade_sha256"] != local.facade_sha256
        or attestation["adapter_sha256"] != local.adapter_sha256
        or attestation["parser_sha256"] != local.parser_sha256
    ):
        raise SupplyIdentityError(
            "signed supply attestation differs from installed sidecar source bytes"
        )
    return attestation


def _records(values: tuple[tuple[str, Path], ...], *, budget: ReadBudget) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name, path in values:
        raw = read_bounded_snapshot(
            path,
            maximum_bytes=MAXIMUM_IDENTITY_FILE_BYTES,
            budget=budget,
        )
        records.append({"path": name, "sha256": bytes_sha256(raw), "size": len(raw)})
    return records


def _verify_supply_artifacts(*, budget: ReadBudget) -> dict[str, str]:
    lock_raw = _read_runtime_path("supply/dependency-lock-v1.json", budget=budget)
    lock = _json_object(lock_raw, label="sidecar dependency lock", canonical=False)
    if (
        lock.get("schema_version") != "1.0.0"
        or lock.get("python_requires") != ">=3.11,<3.14"
        or not isinstance(lock.get("components"), list)
        or not lock["components"]
    ):
        raise SupplyIdentityError("sidecar dependency lock is incomplete")
    component_keys: set[tuple[str, str]] = set()
    components_by_name: dict[str, dict[str, Any]] = {}
    for component in lock["components"]:
        if not isinstance(component, dict):
            raise SupplyIdentityError("sidecar dependency lock component is invalid")
        key = (component.get("name"), component.get("version"))
        if (
            not all(isinstance(item, str) and item for item in key)
            or key in component_keys
            or component.get("name") in components_by_name
            or require_sha256(component.get("sha256"), "dependency source SHA-256")
            != component["sha256"]
        ):
            raise SupplyIdentityError("sidecar dependency lock identity is invalid")
        component_keys.add(key)
        components_by_name[component["name"]] = component
    pyproject_raw = _read_runtime_path("pyproject.toml", budget=budget)
    _verify_pyproject_dependencies(
        pyproject_raw,
        lock=lock,
        components_by_name=components_by_name,
    )

    generated: dict[str, tuple[dict[str, Any], bytes]] = {}
    for relative in _GENERATED_SUPPLY_MEMBERS:
        raw = _read_runtime_path(relative, budget=budget)
        generated[relative] = (
            _json_object(raw, label=relative, canonical=True),
            raw,
        )
    sbom, sbom_raw = generated["supply/sbom.cdx.json"]
    source_inputs, source_inputs_raw = generated["supply/source-inputs-v1.json"]
    provenance, provenance_raw = generated["supply/provenance-build-definition-v1.json"]
    manifest, _ = generated["supply/sidecar-source-manifest-v1.json"]
    _verify_sbom(sbom, lock=lock, lock_raw=lock_raw)
    _verify_source_inputs(source_inputs, budget=budget)
    _verify_provenance(provenance, source_inputs_raw=source_inputs_raw)
    tree_sha = _verify_source_manifest(manifest, budget=budget)
    return {
        "source_manifest_tree_sha256": tree_sha,
        "sbom_sha256": bytes_sha256(sbom_raw),
        "source_inputs_sha256": bytes_sha256(source_inputs_raw),
        "provenance_sha256": bytes_sha256(provenance_raw),
    }


def _verify_pyproject_dependencies(
    raw: bytes,
    *,
    lock: dict[str, Any],
    components_by_name: dict[str, dict[str, Any]],
) -> None:
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SupplyIdentityError("sidecar pyproject is invalid TOML") from exc
    project = value.get("project", {})
    build_system = value.get("build-system", {})
    optional = project.get("optional-dependencies", {})
    if (
        project.get("name") != "owner-research-futu-sidecar"
        or project.get("version") != SIDECAR_PROVIDER_VERSION
        or project.get("requires-python") != lock["python_requires"]
        or not isinstance(project.get("dependencies"), list)
        or not isinstance(build_system.get("requires"), list)
        or not isinstance(optional.get("test"), list)
    ):
        raise SupplyIdentityError("sidecar pyproject identity is incomplete")
    for scope, requirements in (
        ("runtime", project["dependencies"]),
        ("build", build_system["requires"]),
        ("test", optional["test"]),
    ):
        for requirement in requirements:
            if not isinstance(requirement, str):
                raise SupplyIdentityError("sidecar dependency requirement is invalid")
            pin = requirement.split(";", 1)[0].strip()
            if pin.count("==") != 1:
                raise SupplyIdentityError("sidecar dependency is not exactly pinned")
            name, version = (part.strip() for part in pin.split("==", 1))
            component = components_by_name.get(name)
            if (
                not name
                or not version
                or component is None
                or component["version"] != version
                or scope not in component["scopes"]
            ):
                raise SupplyIdentityError("sidecar dependency differs from its source lock")


def _verify_sbom(value: dict[str, Any], *, lock: dict[str, Any], lock_raw: bytes) -> None:
    components = value.get("components")
    properties = value.get("metadata", {}).get("properties", [])
    lock_property = {
        item.get("value")
        for item in properties
        if isinstance(item, dict) and item.get("name") == "owner-research:dependency-lock-sha256"
    }
    actual = {
        (item.get("name"), item.get("version"))
        for item in components or []
        if isinstance(item, dict)
    }
    expected = {(item["name"], item["version"]) for item in lock["components"]}
    if (
        value.get("bomFormat") != "CycloneDX"
        or value.get("specVersion") != "1.6"
        or actual != expected
        or lock_property != {bytes_sha256(lock_raw)}
    ):
        raise SupplyIdentityError("sidecar SBOM does not replay the dependency lock")


def _verify_source_inputs(value: dict[str, Any], *, budget: ReadBudget) -> None:
    inputs = value.get("inputs")
    if (
        value.get("schema_version") != "1.0.0"
        or not isinstance(inputs, list)
        or [item.get("path") for item in inputs if isinstance(item, dict)]
        != list(_SOURCE_INPUT_PATHS)
    ):
        raise SupplyIdentityError("sidecar source-input manifest is incomplete")
    for item in inputs:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise SupplyIdentityError("sidecar source-input member is invalid")
        raw = _read_runtime_path(item["path"], budget=budget)
        if len(raw) != item["size"] or bytes_sha256(raw) != item["sha256"]:
            raise SupplyIdentityError("sidecar source input differs from its manifest")


def _verify_provenance(value: dict[str, Any], *, source_inputs_raw: bytes) -> None:
    subjects = value.get("subject")
    build = value.get("predicate", {}).get("buildDefinition", {})
    if (
        value.get("_type") != "https://in-toto.io/Statement/v1"
        or value.get("predicateType") != "https://slsa.dev/provenance/v1"
        or not isinstance(subjects, list)
        or not subjects
        or build.get("externalParameters", {}).get("python_requires") != ">=3.11,<3.14"
        or not any(
            isinstance(subject, dict)
            and subject.get("name") == "source-inputs-v1.json"
            and subject.get("digest", {}).get("sha256") == bytes_sha256(source_inputs_raw)
            for subject in subjects
        )
    ):
        raise SupplyIdentityError("sidecar provenance build definition is incomplete")


def _verify_source_manifest(value: dict[str, Any], *, budget: ReadBudget) -> str:
    members = value.get("members")
    tree_sha = value.get("tree_sha256")
    if (
        value.get("schema_version") != "1.0.0"
        or value.get("self_member_excluded") != "supply/sidecar-source-manifest-v1.json"
        or value.get("external_signature_required") is not True
        or not isinstance(members, list)
        or value.get("member_count") != len(members)
        or len(members) < len(_REQUIRED_SOURCE_MANIFEST_MEMBERS)
        or require_sha256(tree_sha, "sidecar source tree SHA-256")
        != bytes_sha256(canonical_bytes(members))
    ):
        raise SupplyIdentityError("sidecar source manifest identity is invalid")
    indexed: dict[str, dict[str, Any]] = {}
    for item in members:
        if (
            not isinstance(item, dict)
            or set(item) != {"mode", "path", "sha256", "size"}
            or not isinstance(item["path"], str)
            or item["path"] in indexed
        ):
            raise SupplyIdentityError("sidecar source manifest member is invalid")
        indexed[item["path"]] = item
    for relative in _REQUIRED_SOURCE_MANIFEST_MEMBERS:
        item = indexed.get(relative)
        if item is None:
            raise SupplyIdentityError("sidecar source manifest omits a runtime member")
        raw = _read_manifest_source_path(relative, budget=budget)
        if len(raw) != item["size"] or bytes_sha256(raw) != item["sha256"]:
            raise SupplyIdentityError("installed sidecar member differs from source manifest")
    return tree_sha


def _read_manifest_source_path(relative: str, *, budget: ReadBudget) -> bytes:
    if relative.startswith("src/owner_research_futu_sidecar/"):
        path = _PACKAGE_ROOT / relative.rsplit("/", 1)[1]
    else:
        path = _runtime_path(relative)
    return read_bounded_snapshot(
        path,
        maximum_bytes=MAXIMUM_IDENTITY_FILE_BYTES,
        budget=budget,
    )


def _read_runtime_path(relative: str, *, budget: ReadBudget) -> bytes:
    return read_bounded_snapshot(
        _runtime_path(relative),
        maximum_bytes=MAXIMUM_IDENTITY_FILE_BYTES,
        budget=budget,
    )


def _runtime_path(relative: str) -> Path:
    source_root = _PACKAGE_ROOT.parent
    project_root = source_root.parent
    if source_root.name == "src" and (project_root / "pyproject.toml").is_file():
        return project_root / relative
    if relative == "pyproject.toml":
        return _PACKAGE_ROOT / "supply" / "source-pyproject.toml"
    return _PACKAGE_ROOT / relative


def _json_object(raw: bytes, *, label: str, canonical: bool) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupplyIdentityError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise SupplyIdentityError(f"{label} must be one JSON object")
    if canonical and raw != canonical_bytes(value) + b"\n":
        raise SupplyIdentityError(f"{label} is not canonical JSON")
    return value


__all__ = (
    "LocalSupplyIdentity",
    "SupplyIdentityError",
    "verify_local_supply_attestation",
    "verify_local_supply_identity",
)
