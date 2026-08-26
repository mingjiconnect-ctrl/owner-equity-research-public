from __future__ import annotations

import importlib
import inspect
import json
import os
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from importlib import metadata, resources
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .canonical import (
    SidecarContractError,
    bytes_sha256,
    canonical_sha256,
    reject_duplicate_pairs,
    require_sha256,
)
from .secure_reader import ReadBudget, read_bounded_snapshot

PINNED_SDK_DISTRIBUTION = "futu-api"
PINNED_SDK_VERSION = "10.10.7008"
PINNED_SDK_SDIST_SHA256 = "3c607c7dce02a3a2b308f3424420277a360d7b3a4ba4508b39eaa4ff11271f98"
SDK_ADAPTER_REGISTRY_SHA256 = "48be8aa86fd9c5fc5b5a3b201939c0bd4386b23dbe408d9f30a8e190ce3bbc4a"
PROTOBUF_DESCRIPTOR_SET_SHA256 = "c2b13581ef9acdbe2b9a95da26b95d6321058f7beb27b56fef90908519e312f8"
SDK_RUNTIME_INVENTORY_SHA256 = "adcd7f3d4eb801cdbf6c1cc50a28ad1e8173cd11711a989445ef87dfd3714e29"
SDK_RUNTIME_TREE_SHA256 = "03903eb13141b0a80c885b1f778375cba5be1bc661fdfbdbed6ff9a12873332f"
REGISTRY_RESOURCE = "sdk-adapter-registry-v1.json"
SDK_RUNTIME_INVENTORY_RESOURCE = "futu-api-runtime-tree-v1.json"
MAXIMUM_REGISTRY_BYTES = 1024 * 1024
MAXIMUM_SDK_SOURCE_BYTES = 16 * 1024 * 1024
MAXIMUM_SDK_CUMULATIVE_BYTES = 64 * 1024 * 1024

_PB2_MODULES = {
    1002: "GetGlobalState_pb2",
    3103: "Qot_RequestHistoryKL_pb2",
    3104: "Qot_RequestHistoryKLQuota_pb2",
    3202: "Qot_GetStaticInfo_pb2",
    3227: "Qot_GetFinancialsStatements_pb2",
    3228: "Qot_GetFinancialsRevenueBreakdown_pb2",
    3229: "Qot_GetResearchAnalystConsensus_pb2",
    3230: "Qot_GetResearchRatingSummary_pb2",
    3232: "Qot_GetValuationDetail_pb2",
    3234: "Qot_GetCorporateActionsDividends_pb2",
    3235: "Qot_GetCorporateActionsBuybacks_pb2",
    3236: "Qot_GetCorporateActionsStockSplits_pb2",
    3243: "Qot_GetCompanyProfile_pb2",
    3244: "Qot_GetCompanyExecutives_pb2",
    3245: "Qot_GetCompanyExecutiveBackground_pb2",
    3246: "Qot_GetCompanyOperationalEfficiency_pb2",
}


@dataclass(frozen=True, slots=True)
class Operation:
    protocol_id: int
    sdk_method: str
    sdk_parameter_names: tuple[str, ...]
    host_parameter_names: tuple[str, ...]
    injected_parameter_names: tuple[str, ...]
    defaulted_parameter_names: tuple[str, ...]
    internal_pagination_parameter: str | None
    pagination_mode: str
    generated_descriptor_sha256: str


@dataclass(frozen=True, slots=True)
class SdkDistribution:
    package: str
    version: str
    archive_sha256: str
    open_context_base_sha256: str
    open_quote_context_sha256: str
    protobuf_descriptor_set_sha256: str


@dataclass(frozen=True, slots=True)
class OperationRegistry:
    registry_id: str
    registry_version: str
    registry_sha256: str
    sdk_distribution: SdkDistribution
    operations: MappingProxyType[int, Operation]


def _resource_bytes(*, budget: ReadBudget | None = None) -> bytes:
    return _named_resource_bytes(
        REGISTRY_RESOURCE,
        maximum_bytes=MAXIMUM_REGISTRY_BYTES,
        budget=budget,
    )


def _named_resource_bytes(
    name: str,
    *,
    maximum_bytes: int,
    budget: ReadBudget | None,
) -> bytes:
    candidates: list[Any] = []
    try:
        candidates.append(resources.files(__package__).joinpath("resources", name))
    except ModuleNotFoundError:
        pass
    candidates.append(Path(__file__).parents[2] / "resources" / name)
    for candidate in candidates:
        path = Path(candidate)
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SidecarContractError("SDK adapter registry cannot be inspected") from exc
        raw = read_bounded_snapshot(
            path,
            maximum_bytes=maximum_bytes,
            budget=budget,
        )
        return raw
    raise SidecarContractError("SDK adapter registry is unavailable")


def _verify_runtime_tree(
    distribution: metadata.Distribution,
    *,
    budget: ReadBudget,
) -> dict[str, Any]:
    raw = _named_resource_bytes(
        SDK_RUNTIME_INVENTORY_RESOURCE,
        maximum_bytes=MAXIMUM_REGISTRY_BYTES,
        budget=budget,
    )
    if bytes_sha256(raw) != SDK_RUNTIME_INVENTORY_SHA256:
        raise SidecarContractError("SDK runtime inventory differs from release authority")
    try:
        inventory = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SidecarContractError("SDK runtime inventory is invalid JSON") from exc
    if not isinstance(inventory, dict) or set(inventory) != {
        "inventory_id",
        "member_count",
        "members",
        "schema_version",
        "source_distribution",
        "total_size",
        "tree_sha256",
    }:
        raise SidecarContractError("SDK runtime inventory has an unexpected member set")
    source = inventory["source_distribution"]
    if (
        inventory["inventory_id"] != "futu-api-runtime-tree-v1"
        or inventory["schema_version"] != "1.0.0"
        or inventory["tree_sha256"] != SDK_RUNTIME_TREE_SHA256
        or not isinstance(source, dict)
        or source
        != {
            "archive_sha256": PINNED_SDK_SDIST_SHA256,
            "package": PINNED_SDK_DISTRIBUTION,
            "source_kind": "sdist",
            "version": PINNED_SDK_VERSION,
        }
    ):
        raise SidecarContractError("SDK runtime inventory authority is invalid")
    members = inventory["members"]
    if (
        not isinstance(members, list)
        or inventory["member_count"] != len(members)
        or canonical_sha256(members) != inventory["tree_sha256"]
    ):
        raise SidecarContractError("SDK runtime inventory identity does not replay")
    expected: dict[str, tuple[int, str]] = {}
    for item in members:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise SidecarContractError("SDK runtime inventory member is invalid")
        member_path = item["path"]
        if (
            not isinstance(member_path, str)
            or not member_path
            or member_path.startswith("/")
            or ".." in Path(member_path).parts
            or member_path in expected
            or type(item["size"]) is not int
            or item["size"] < 0
        ):
            raise SidecarContractError("SDK runtime inventory path is unsafe")
        expected[member_path] = (
            item["size"],
            require_sha256(item["sha256"], "SDK runtime member SHA-256"),
        )
    package_root = Path(distribution.locate_file("futu"))
    try:
        root_stat = package_root.lstat()
    except OSError as exc:
        raise SidecarContractError("installed futu package root is unavailable") from exc
    if not package_root.is_absolute() or not stat.S_ISDIR(root_stat.st_mode):
        raise SidecarContractError("installed futu package root is not a real directory")
    actual: set[str] = set()
    for directory, directory_names, file_names in os.walk(
        package_root, topdown=True, followlinks=False
    ):
        directory_path = Path(directory)
        relative_directory = directory_path.relative_to(package_root)
        if "__pycache__" in relative_directory.parts:
            raise SidecarContractError("installed SDK contains a bytecode cache directory")
        for name in tuple(directory_names):
            candidate = directory_path / name
            candidate_stat = candidate.lstat()
            if name == "__pycache__":
                raise SidecarContractError("installed SDK contains a bytecode cache directory")
            elif not stat.S_ISDIR(candidate_stat.st_mode):
                raise SidecarContractError("SDK package contains a linked directory")
        for name in file_names:
            relative = (relative_directory / name).as_posix()
            actual.add(relative)
    if actual != set(expected):
        raise SidecarContractError("installed futu package member set differs from authority")
    replayed: list[dict[str, Any]] = []
    total_size = 0
    for member_path in sorted(expected):
        size, expected_sha = expected[member_path]
        value = read_bounded_snapshot(
            package_root / member_path,
            maximum_bytes=MAXIMUM_SDK_SOURCE_BYTES,
            budget=budget,
        )
        if len(value) != size or bytes_sha256(value) != expected_sha:
            raise SidecarContractError(f"installed SDK member drifted: {member_path}")
        total_size += len(value)
        replayed.append({"path": member_path, "sha256": expected_sha, "size": size})
    if total_size != inventory["total_size"] or canonical_sha256(replayed) != (
        SDK_RUNTIME_TREE_SHA256
    ):
        raise SidecarContractError("installed SDK runtime tree does not replay")
    return {
        "sdk_runtime_inventory_sha256": SDK_RUNTIME_INVENTORY_SHA256,
        "sdk_runtime_tree_sha256": SDK_RUNTIME_TREE_SHA256,
        "sdk_runtime_member_count": len(replayed),
    }


def load_operation_registry(*, budget: ReadBudget | None = None) -> OperationRegistry:
    raw = _resource_bytes(budget=budget)
    if bytes_sha256(raw) != SDK_ADAPTER_REGISTRY_SHA256:
        raise SidecarContractError("SDK adapter registry bytes differ from the host authority")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SidecarContractError("SDK adapter registry is invalid JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "adapters",
        "registry_id",
        "registry_version",
        "sdk_distribution",
    }:
        raise SidecarContractError("SDK adapter registry has an unexpected member set")
    if (
        payload["registry_id"] != "futu-python-sdk-adapter-registry"
        or payload["registry_version"] != "1.0.0"
    ):
        raise SidecarContractError("SDK adapter registry identity is invalid")
    distribution_payload = payload["sdk_distribution"]
    if not isinstance(distribution_payload, dict) or set(distribution_payload) != {
        "archive_sha256",
        "open_context_base_sha256",
        "open_quote_context_sha256",
        "package",
        "protobuf_descriptor_set_sha256",
        "version",
    }:
        raise SidecarContractError("SDK distribution identity is invalid")
    distribution = SdkDistribution(**distribution_payload)
    if (
        distribution.package != PINNED_SDK_DISTRIBUTION
        or distribution.version != PINNED_SDK_VERSION
        or distribution.archive_sha256 != PINNED_SDK_SDIST_SHA256
        or distribution.protobuf_descriptor_set_sha256 != PROTOBUF_DESCRIPTOR_SET_SHA256
    ):
        raise SidecarContractError("SDK registry is rebound to another distribution")
    for value in (
        distribution.archive_sha256,
        distribution.open_context_base_sha256,
        distribution.open_quote_context_sha256,
        distribution.protobuf_descriptor_set_sha256,
    ):
        require_sha256(value, "SDK distribution digest")

    exact_keys = {
        "defaulted_parameter_names",
        "generated_descriptor_sha256",
        "host_parameter_names",
        "injected_parameter_names",
        "internal_pagination_parameter",
        "pagination_mode",
        "protocol_id",
        "sdk_method",
        "sdk_parameter_names",
    }
    operations: dict[int, Operation] = {}
    for item in payload["adapters"]:
        if not isinstance(item, dict) or set(item) != exact_keys:
            raise SidecarContractError("SDK adapter entry has an unexpected member set")
        protocol_id = item["protocol_id"]
        if type(protocol_id) is not int or protocol_id in operations:
            raise SidecarContractError("SDK adapter protocol IDs must be unique integers")
        for key in (
            "defaulted_parameter_names",
            "host_parameter_names",
            "injected_parameter_names",
            "sdk_parameter_names",
        ):
            values = item[key]
            if (
                not isinstance(values, list)
                or len(values) != len(set(values))
                or any(not isinstance(value, str) or not value for value in values)
            ):
                raise SidecarContractError(f"SDK adapter {key} is invalid")
        if item["pagination_mode"] not in {"none", "single_page", "internal"}:
            raise SidecarContractError("SDK adapter pagination mode is invalid")
        if item["internal_pagination_parameter"] is not None and not isinstance(
            item["internal_pagination_parameter"], str
        ):
            raise SidecarContractError("SDK adapter pagination parameter is invalid")
        require_sha256(item["generated_descriptor_sha256"], "generated descriptor digest")
        operation = Operation(
            protocol_id=protocol_id,
            sdk_method=item["sdk_method"],
            sdk_parameter_names=tuple(item["sdk_parameter_names"]),
            host_parameter_names=tuple(item["host_parameter_names"]),
            injected_parameter_names=tuple(item["injected_parameter_names"]),
            defaulted_parameter_names=tuple(item["defaulted_parameter_names"]),
            internal_pagination_parameter=item["internal_pagination_parameter"],
            pagination_mode=item["pagination_mode"],
            generated_descriptor_sha256=item["generated_descriptor_sha256"],
        )
        declared = {
            *operation.host_parameter_names,
            *operation.injected_parameter_names,
            *operation.defaulted_parameter_names,
        }
        if operation.internal_pagination_parameter is not None:
            declared.add(operation.internal_pagination_parameter)
        if declared != set(operation.sdk_parameter_names):
            raise SidecarContractError("SDK adapter parameter ownership is incomplete")
        operations[protocol_id] = operation
    if set(operations) != set(_PB2_MODULES):
        raise SidecarContractError("SDK adapter registry is incomplete or over-broad")
    return OperationRegistry(
        registry_id=payload["registry_id"],
        registry_version=payload["registry_version"],
        registry_sha256=SDK_ADAPTER_REGISTRY_SHA256,
        sdk_distribution=distribution,
        operations=MappingProxyType(operations),
    )


def _descriptor_set_sha256(*, budget: ReadBudget | None = None) -> tuple[str, dict[int, str]]:
    try:
        from google.protobuf import descriptor_pb2
    except ImportError as exc:
        raise SidecarContractError("protobuf runtime is unavailable") from exc
    descriptors: dict[str, Any] = {}
    per_protocol: dict[int, str] = {}

    def visit(descriptor: Any) -> None:
        if descriptor.name in descriptors:
            return
        descriptors[descriptor.name] = descriptor
        for dependency in descriptor.dependencies:
            visit(dependency)

    for protocol_id, module_name in _PB2_MODULES.items():
        module = importlib.import_module(f"futu.common.pb.{module_name}")
        descriptor = module.DESCRIPTOR
        visit(descriptor)
        module_path = inspect.getsourcefile(module)
        if module_path is None:
            raise SidecarContractError(
                f"generated protobuf source is unavailable for protocol {protocol_id}"
            )
        per_protocol[protocol_id] = bytes_sha256(
            read_bounded_snapshot(
                Path(module_path),
                maximum_bytes=MAXIMUM_SDK_SOURCE_BYTES,
                budget=budget,
            )
        )
    descriptor_set = descriptor_pb2.FileDescriptorSet()
    for name in sorted(descriptors):
        descriptors[name].CopyToProto(descriptor_set.file.add())
    encoded = descriptor_set.SerializeToString(deterministic=True)
    return bytes_sha256(encoded), per_protocol


def _verify_installed_sdk_in_process() -> dict[str, Any]:
    """Introspect the SDK in a disposable process-scoped HOME."""

    try:
        installed_distribution = metadata.distribution(PINNED_SDK_DISTRIBUTION)
        version = installed_distribution.version
        budget = ReadBudget(MAXIMUM_SDK_CUMULATIVE_BYTES)
        runtime_tree = _verify_runtime_tree(installed_distribution, budget=budget)
        from futu.common import open_context_base  # type: ignore[import-not-found]
        from futu.quote import open_quote_context  # type: ignore[import-not-found]
        from futu.quote.open_quote_context import (  # type: ignore[import-not-found]
            OpenQuoteContext,
        )
    except (ImportError, metadata.PackageNotFoundError) as exc:
        raise SidecarContractError("the pinned official futu-api SDK is not installed") from exc
    registry = load_operation_registry(budget=budget)
    distribution = registry.sdk_distribution
    if version != distribution.version:
        raise SidecarContractError("installed futu-api version differs from the pinned SDK")
    source_checks = (
        (open_context_base, distribution.open_context_base_sha256, "open_context_base.py"),
        (open_quote_context, distribution.open_quote_context_sha256, "open_quote_context.py"),
    )
    for module, expected_sha, label in source_checks:
        source_path = inspect.getsourcefile(module)
        if (
            source_path is None
            or bytes_sha256(
                read_bounded_snapshot(
                    Path(source_path),
                    maximum_bytes=MAXIMUM_SDK_SOURCE_BYTES,
                    budget=budget,
                )
            )
            != expected_sha
        ):
            raise SidecarContractError(f"installed {label} bytes differ from the authority")

    descriptor_set_sha, descriptor_shas = _descriptor_set_sha256(budget=budget)
    if descriptor_set_sha != distribution.protobuf_descriptor_set_sha256:
        raise SidecarContractError("installed protobuf descriptor set differs from the authority")
    checked: list[dict[str, Any]] = []
    for protocol_id, operation in registry.operations.items():
        method = getattr(OpenQuoteContext, operation.sdk_method, None)
        if method is None:
            raise SidecarContractError(f"SDK method is absent for protocol {protocol_id}")
        signature = inspect.signature(method)
        parameter_names = tuple(signature.parameters)[1:]
        if parameter_names != operation.sdk_parameter_names:
            raise SidecarContractError(f"SDK signature drifted for protocol {protocol_id}")
        if descriptor_shas[protocol_id] != operation.generated_descriptor_sha256:
            raise SidecarContractError(
                f"generated protobuf descriptor drifted for protocol {protocol_id}"
            )
        checked.append(
            {
                "protocol_id": protocol_id,
                "sdk_method": operation.sdk_method,
                "sdk_parameter_names": list(parameter_names),
                "generated_descriptor_sha256": descriptor_shas[protocol_id],
            }
        )
    return {
        "futu_api_version": version,
        "futu_api_distribution_sha256": distribution.archive_sha256,
        "sdk_operation_registry_sha256": registry.registry_sha256,
        "protobuf_descriptor_set_sha256": descriptor_set_sha,
        "operation_count": len(checked),
        "operations": checked,
        **runtime_tree,
    }


def verify_installed_sdk() -> dict[str, Any]:
    """Verify the SDK without importing its logging singleton into the caller."""

    with tempfile.TemporaryDirectory(prefix="owner-research-futu-sdk-verify-") as value:
        private_home = Path(value).resolve(strict=True)
        os.chmod(private_home, 0o700)
        environment = {
            **os.environ,
            "HOME": os.fspath(private_home),
            "XDG_CACHE_HOME": os.fspath(private_home / ".cache"),
            "XDG_CONFIG_HOME": os.fspath(private_home / ".config"),
            "XDG_DATA_HOME": os.fspath(private_home / ".local" / "share"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        source = (
            "from owner_research_futu_sidecar.canonical import canonical_json;"
            "from owner_research_futu_sidecar.operation_registry import "
            "_verify_installed_sdk_in_process;"
            "print(canonical_json(_verify_installed_sdk_in_process()))"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-c", source],
            cwd=private_home,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    if completed.returncode != 0 or completed.stderr or not completed.stdout:
        raise SidecarContractError("isolated pinned SDK verification did not complete silently")
    try:
        verified = json.loads(completed.stdout, object_pairs_hook=reject_duplicate_pairs)
    except json.JSONDecodeError as exc:
        raise SidecarContractError(
            "isolated pinned SDK verification returned invalid evidence"
        ) from exc
    if not isinstance(verified, dict):
        raise SidecarContractError("isolated pinned SDK verification is not one object")
    return verified


__all__ = (
    "Operation",
    "OperationRegistry",
    "PINNED_SDK_SDIST_SHA256",
    "PINNED_SDK_VERSION",
    "PROTOBUF_DESCRIPTOR_SET_SHA256",
    "SDK_ADAPTER_REGISTRY_SHA256",
    "load_operation_registry",
    "verify_installed_sdk",
)
