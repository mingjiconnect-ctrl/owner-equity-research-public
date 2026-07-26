#!/usr/bin/env python3
"""Protected-base semantic oracle for the future Phase 5E-2C-0 contract-only change."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any

EXPECTED_DIFF = {
    "component-lock.json": "M",
    "docs/phase-status.json": "M",
    "plugins/owner-equity-research/.codex-plugin/plugin.json": "M",
    "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md": "M",
    "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md": "M",
    "pyproject.toml": "M",
    "schemas/market-reference-snapshot.schema.json": "M",
    "schemas/valuation-handoff.schema.json": "M",
    "src/owner_research/resources/market_access/vendor-market-contract-policy.json": "A",
    "src/owner_research/valuation_vendor_market_contract_types.py": "A",
    "tests/fixtures/phase5e2c0/adversarial-cases.json": "A",
    "tests/test_phase5e2c0_vendor_market_contract.py": "A",
}
FORBIDDEN_SOURCE_TERMS = (
    "futu",
    "opend",
    "httpx",
    "requests",
    "socket",
    "websocket",
    "subprocess",
    "run_dual_panel",
    "market sourcedocument",
    "market-equity",
    "valuation request",
)
EXPECTED_PYTHON_VERSION = "0.5.0.dev12"
EXPECTED_PLUGIN_VERSION = "0.5.0-dev.12"
EXPECTED_COMPONENT_LOCK_VERSION = "1.3.0"
VENDOR_POLICY_PATH = (
    "src/owner_research/resources/market_access/vendor-market-contract-policy.json"
)
VENDOR_TYPES_PATH = "src/owner_research/valuation_vendor_market_contract_types.py"
SCHEMA_PATHS = {
    "schemas/market-reference-snapshot.schema.json": "4.0.0",
    "schemas/valuation-handoff.schema.json": "3.0.0",
}
SHA_OR_NULL = {
    "oneOf": [
        {"$ref": "#/$defs/sha256"},
        {"type": "null"},
    ]
}
SNAPSHOT_V4_PROPERTIES = {
    "source_authority_kind": {
        "const": "governed_broker_vendor",
        "type": "string",
    },
    "price_basis": {
        "const": "vendor_unadjusted_regular_session_daily_close",
        "type": "string",
    },
    "source_numeric_encoding": {
        "const": "ieee754_binary64",
        "type": "string",
    },
    "wire_binary64_hex": {"pattern": "^[0-9a-f]{16}$", "type": "string"},
    "roundtrip_decimal": {"$ref": "#/$defs/positiveDecimal"},
    "exact_binary64_decimal": {"$ref": "#/$defs/positiveDecimal"},
    "entitlement_receipt_sha256": {"$ref": "#/$defs/sha256"},
    "data_rights_decision_sha256": {"$ref": "#/$defs/sha256"},
    "runtime_isolation_receipt_sha256": {"$ref": "#/$defs/sha256"},
    "provider_runtime_sha256": {"$ref": "#/$defs/sha256"},
    "protocol_descriptor_sha256": {"$ref": "#/$defs/sha256"},
    "parser_sha256": {"$ref": "#/$defs/sha256"},
    "adapter_sha256": {"$ref": "#/$defs/sha256"},
    "private_cas_locator": {
        "pattern": "^cas://sha256/[0-9a-f]{64}$",
        "type": "string",
    },
    "current_share_compilation_fingerprint": {"$ref": "#/$defs/sha256"},
    "market_evidence_compilation_fingerprint": {"$ref": "#/$defs/sha256"},
    "market_equity_projection_witness_sha256": {"$ref": "#/$defs/sha256"},
}
HANDOFF_V3_PROPERTIES = {
    "market_authority_kind": {
        "const": "governed_broker_vendor",
        "type": "string",
    },
    "market_authority_policy_sha256": {"$ref": "#/$defs/sha256"},
    "market_reference_snapshot_fingerprint": copy.deepcopy(SHA_OR_NULL),
    "binary64_projection_witness_sha256": copy.deepcopy(SHA_OR_NULL),
}
EXPECTED_VENDOR_POLICY = {
    "schema_version": "1.0.0",
    "policy_id": "phase5e-provider-neutral-vendor-market-contract",
    "policy_version": "1.0.0",
    "source_authority_kind": "governed_broker_vendor",
    "price_basis": "vendor_unadjusted_regular_session_daily_close",
    "numeric_encoding": "ieee754_binary64",
    "public_schema_count": 43,
    "production_capability": False,
    "provider_specific_authority_allowed": False,
    "market_access_allowed": False,
    "market_evidence_compilation_allowed": False,
    "snapshot_build_allowed": False,
    "valuation_request_allowed": False,
    "kernel_execution_allowed": False,
    "raw_store": {
        "allowed_locator_schemes": ["cas://sha256/", "repo://tests/fixtures/"],
        "live_payload_repository_storage_allowed": False,
        "test_fixture_valuation_use_allowed": False,
    },
    "numeric_projection": {
        "authoritative_research_arithmetic": "decimal_from_exact_binary64",
        "binary64_projection_witness_required": True,
        "implicit_rounding_allowed": False,
        "tolerance_comparison_allowed": False,
    },
}
EXPECTED_PLUGIN_LONG_DESCRIPTION = (
    "Build source-linked SEC evidence packages, deterministic management and "
    "capital-allocation ledgers, governed business-quality evidence, and a validated "
    "ResearchBundle. Phase 5E-2C-0 defines provider-neutral vendor-close and binary64 "
    "contracts only; market access, market evidence, request compilation, kernel execution, "
    "reporting, and publishing remain unavailable."
)
EXPECTED_PENDING_STATUS = {
    "current_phase": "Phase 5E-2C-0",
    "status": "implementation_complete_pending_acceptance",
    "authorized_next": ["Phase 5E-2C-0 acceptance closeout"],
    "prohibited": [
        "Phase 5E-2C-1",
        "Phase 5E-2C-2",
        "Phase 5E-2C-3",
        "Phase 5E-2C-4",
        "Phase 5E-2D",
        "Phase 5E-2E",
        "Phase 5E-2F",
        "Phase 5E-3",
        "Phase 5E-4",
        "Phase 5E-5",
        "Phase 5E-6",
        "Phase 5F",
        "Phase 6",
        "Phase 7",
        "Phase 8",
        "Phase 9",
    ],
    "release_tag": None,
}
SKILL_APPENDICES = {
    "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md": (
        "\n\n## Phase 5E-2C-0 contract boundary\n\n"
        "Phase 5E-2C-0 exposes provider-neutral vendor-close and binary64 contracts only. "
        "It does not acquire a quote, create market evidence, build a Snapshot, compile a "
        "request, invoke the kernel, or write an artifact.\n"
    ),
    "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md": (
        "\n\n## Phase 5E-2C-0 contract audit\n\n"
        "When explicitly invoked, verify the closed provider-neutral vendor-close and "
        "binary64 contracts and confirm that no market access, evidence compiler, Snapshot "
        "builder, request compiler, kernel invocation, or writer was introduced.\n"
    ),
}
ALLOWED_TYPE_IMPORTS = {
    "__future__": frozenset({"annotations"}),
    "dataclasses": frozenset({"dataclass"}),
    "typing": frozenset({"Any", "Literal"}),
}
ALLOWED_ANNOTATION_NAMES = frozenset(
    {
        "Any",
        "Literal",
        "bool",
        "bytes",
        "dict",
        "float",
        "int",
        "list",
        "None",
        "str",
        "tuple",
        "ExactDecimalValue",
    }
)
EXPECTED_TYPE_FIELDS = (
    (
        "ExactDecimalValue",
        (
            ("canonical_decimal", "str"),
            ("coefficient", "int"),
            ("scale", "int"),
        ),
    ),
    (
        "RawEvidenceReference",
        (
            ("store_kind", "Literal['repo_fixture', 'private_cas']"),
            ("locator", "str"),
            ("content_type", "str"),
            ("raw_sha256", "str"),
        ),
    ),
    (
        "KernelNumericProjectionWitness",
        (
            ("authoritative_decimal", "ExactDecimalValue"),
            ("canonical_json_number_token", "str"),
            ("parsed_binary64_hex", "str"),
            ("parsed_decimal_text", "str"),
            ("product_decimal", "ExactDecimalValue"),
            ("model_unit_decimal", "ExactDecimalValue"),
        ),
    ),
)
EXPECTED_ADVERSARIAL_CASES = {
    "cases": [
        {
            "case_id": "P5E-2C0-001",
            "expected": "blocked",
            "scenario": "provider-specific execution capability appears in contract phase",
        },
        {
            "case_id": "P5E-2C0-002",
            "expected": "blocked",
            "scenario": "binary64 projection uses tolerance or implicit rounding",
        },
    ],
    "schema_version": "1.0.0",
}
EXPECTED_TEST_SOURCE = '''from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_vendor_market_contract() -> None:
    policy = json.loads(
        (
            ROOT
            / "src/owner_research/resources/market_access/vendor-market-contract-policy.json"
        ).read_text(encoding="utf-8")
    )
    assert policy["production_capability"] is False
    assert policy["provider_specific_authority_allowed"] is False
    assert policy["numeric_encoding"] == "ieee754_binary64"
'''


def _json_bytes(raw: bytes, *, label: str, canonical: bool) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise SystemExit(f"duplicate JSON key in {label}: {key}")
            value[key] = child
        return value

    def reject_nonfinite(token: str) -> None:
        raise SystemExit(f"non-finite JSON value in {label}: {token}")

    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid UTF-8 JSON: {label}") from exc
    canonical_raw = (
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode()
    if canonical and raw != canonical_raw:
        raise SystemExit(f"non-canonical JSON: {label}")
    return value


def _strict_json(path: Path) -> Any:
    return _json_bytes(path.read_bytes(), label=str(path), canonical=True)


def _git_bytes(repository: Path, ref: str, path: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(repository), "show", f"{ref}:{path}"],
    )


def _parent(repository: Path) -> str:
    parents = subprocess.check_output(
        ["git", "-C", str(repository), "show", "-s", "--format=%P", "HEAD"],
        text=True,
    ).split()
    if len(parents) != 1 or re.fullmatch(r"[0-9a-f]{40}", parents[0]) is None:
        raise SystemExit("2C-0 implementation must be one direct commit")
    return parents[0]


def _changed_diff(repository: Path) -> dict[str, str]:
    parent = _parent(repository)
    raw = subprocess.check_output(
        ["git", "-C", str(repository), "diff", "--name-status", parent, "HEAD"],
        text=True,
    )
    result: dict[str, str] = {}
    for line in raw.splitlines():
        status, path = line.split("\t", 1)
        if status not in {"A", "M"} or path in result:
            raise SystemExit("2C-0 implementation diff is malformed")
        result[path] = status
    return result


def _tree_entry(repository: Path, ref: str, path: str) -> tuple[str, str] | None:
    raw = subprocess.check_output(
        ["git", "-C", str(repository), "ls-tree", "-z", ref, "--", path]
    )
    if not raw:
        return None
    records = [item for item in raw.split(b"\0") if item]
    if len(records) != 1 or b"\t" not in records[0]:
        raise SystemExit(f"ambiguous Git tree entry: {ref}:{path}")
    metadata, encoded_path = records[0].split(b"\t", 1)
    parts = metadata.split()
    if len(parts) != 3 or encoded_path.decode("utf-8") != path:
        raise SystemExit(f"malformed Git tree entry: {ref}:{path}")
    return parts[0].decode("ascii"), parts[1].decode("ascii")


def _verify_regular_file_modes(repository: Path, parent: str) -> None:
    for path, disposition in EXPECTED_DIFF.items():
        if _tree_entry(repository, "HEAD", path) != ("100644", "blob"):
            raise SystemExit(f"2C-0 candidate path is not a regular file: {path}")
        parent_entry = _tree_entry(repository, parent, path)
        if disposition == "M" and parent_entry != ("100644", "blob"):
            raise SystemExit(f"2C-0 modified path inherited or changed an unsafe mode: {path}")
        if disposition == "A" and parent_entry is not None:
            raise SystemExit(f"2C-0 added path already exists in its parent: {path}")


def _verify_pyproject(repository: Path, parent: str) -> None:
    base = tomllib.loads(_git_bytes(repository, parent, "pyproject.toml").decode())
    candidate = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))
    if candidate.get("project", {}).get("version") != EXPECTED_PYTHON_VERSION:
        raise SystemExit("2C-0 Python version is not the exact planned dev release")
    normalized = copy.deepcopy(candidate)
    normalized["project"]["version"] = base["project"]["version"]
    if normalized != base:
        raise SystemExit("2C-0 changed pyproject semantics outside the version field")


def _verify_status(repository: Path, parent: str) -> None:
    path = "docs/phase-status.json"
    base = _json_bytes(
        _git_bytes(repository, parent, path),
        label=f"{parent}:{path}",
        canonical=False,
    )
    candidate = _strict_json(repository / path)
    expected = copy.deepcopy(base)
    expected.update(copy.deepcopy(EXPECTED_PENDING_STATUS))
    if candidate != expected:
        raise SystemExit("2C-0 phase status is not the exact pending transition")


def _verify_plugin(repository: Path, parent: str) -> None:
    path = "plugins/owner-equity-research/.codex-plugin/plugin.json"
    base = _json_bytes(
        _git_bytes(repository, parent, path),
        label=f"{parent}:{path}",
        canonical=False,
    )
    candidate = _json_bytes(
        (repository / path).read_bytes(),
        label=path,
        canonical=False,
    )
    if candidate.get("version") != EXPECTED_PLUGIN_VERSION:
        raise SystemExit("2C-0 Plugin version is not the exact planned dev release")
    normalized = copy.deepcopy(candidate)
    normalized["version"] = base["version"]
    base_long = base.get("interface", {}).get("longDescription")
    candidate_long = candidate.get("interface", {}).get("longDescription")
    if candidate_long != EXPECTED_PLUGIN_LONG_DESCRIPTION:
        raise SystemExit("2C-0 Plugin boundary description is missing")
    normalized["interface"]["longDescription"] = base_long
    if normalized != base:
        raise SystemExit("2C-0 changed Plugin capability outside version and boundary prose")
    if candidate.get("skills") != "./skills/" or candidate.get("interface", {}).get(
        "capabilities"
    ) != []:
        raise SystemExit("2C-0 introduced a Plugin execution capability")


def _verify_skill_appendices(repository: Path, parent: str) -> None:
    for relative, appendix in SKILL_APPENDICES.items():
        base = _git_bytes(repository, parent, relative).decode("utf-8")
        candidate = (repository / relative).read_text(encoding="utf-8")
        if candidate != base.rstrip("\n") + appendix:
            raise SystemExit(f"2C-0 Skill drifted outside its inert appendix: {relative}")


def _verify_annotation(node: ast.expr) -> None:
    """Accept only inert, future-annotation syntax with no evaluation surface."""

    if isinstance(node, ast.Name):
        if node.id not in ALLOWED_ANNOTATION_NAMES:
            raise SystemExit("2C-0 internal type uses an unapproved annotation name")
        return
    if isinstance(node, ast.Subscript):
        _verify_annotation(node.value)
        _verify_annotation(node.slice)
        return
    if isinstance(node, ast.Tuple):
        for item in node.elts:
            _verify_annotation(item)
        return
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        _verify_annotation(node.left)
        _verify_annotation(node.right)
        return
    if isinstance(node, ast.Constant) and (
        node.value is None
        or node.value is Ellipsis
        or type(node.value) in {str, int, bool}
    ):
        return
    raise SystemExit("2C-0 internal type annotation escapes the declarative grammar")


def _is_frozen_dataclass_decorator(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "dataclass"
        and not node.args
        and len(node.keywords) == 2
        and {item.arg for item in node.keywords} == {"frozen", "slots"}
        and all(
            isinstance(item.value, ast.Constant) and item.value.value is True
            for item in node.keywords
        )
    )


def _verify_declarative_types(source: str, *, filename: str) -> None:
    """Enforce a positive grammar: imports plus field-only frozen dataclasses."""

    tree = ast.parse(source, filename=filename)
    classes: list[ast.ClassDef] = []
    saw_docstring = False
    for index, node in enumerate(tree.body):
        if (
            index == 0
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            saw_docstring = True
            continue
        if isinstance(node, ast.ImportFrom):
            if node.level != 0 or node.module not in ALLOWED_TYPE_IMPORTS:
                raise SystemExit("2C-0 internal types import outside the declarative allowlist")
            names = {item.name for item in node.names}
            if (
                not names
                or any(item.asname is not None for item in node.names)
                or not names.issubset(ALLOWED_TYPE_IMPORTS[node.module])
            ):
                raise SystemExit("2C-0 internal types import an unapproved symbol")
            continue
        if isinstance(node, ast.ClassDef):
            classes.append(node)
            continue
        raise SystemExit("2C-0 internal types contain executable module-level code")
    if not saw_docstring or tuple(item.name for item in classes) != tuple(
        item[0] for item in EXPECTED_TYPE_FIELDS
    ):
        raise SystemExit("2C-0 internal type inventory differs from the protected manifest")
    for class_node, (_, expected_fields) in zip(
        classes, EXPECTED_TYPE_FIELDS, strict=True
    ):
        if (
            not re.fullmatch(r"[A-Z][A-Za-z0-9]{0,79}", class_node.name)
            or class_node.bases
            or class_node.keywords
            or len(class_node.decorator_list) != 1
            or not _is_frozen_dataclass_decorator(class_node.decorator_list[0])
        ):
            raise SystemExit("2C-0 internal records must be plain frozen slot dataclasses")
        actual_fields: list[tuple[str, str]] = []
        for child in class_node.body:
            if (
                not isinstance(child, ast.AnnAssign)
                or child.simple != 1
                or not isinstance(child.target, ast.Name)
                or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", child.target.id)
                or child.value is not None
            ):
                raise SystemExit(
                    "2C-0 internal records may contain only required annotated fields"
                )
            _verify_annotation(child.annotation)
            actual_fields.append((child.target.id, ast.unparse(child.annotation)))
        expected_ast_fields = [
            (field_name, ast.unparse(ast.parse(annotation, mode="eval").body))
            for field_name, annotation in expected_fields
        ]
        if actual_fields != expected_ast_fields:
            raise SystemExit(
                "2C-0 internal type fields differ from the protected manifest: "
                f"{class_node.name}"
            )


def _verify_schemas(repository: Path, parent: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative, version in SCHEMA_PATHS.items():
        raw = (repository / relative).read_bytes()
        schema = _json_bytes(raw, label=relative, canonical=False)
        base = _json_bytes(
            _git_bytes(repository, parent, relative),
            label=f"{parent}:{relative}",
            canonical=False,
        )
        expected = copy.deepcopy(base)
        expected["properties"]["schema_version"]["const"] = version
        additions = (
            SNAPSHOT_V4_PROPERTIES
            if relative.endswith("market-reference-snapshot.schema.json")
            else HANDOFF_V3_PROPERTIES
        )
        if set(additions) & set(expected.get("properties", {})):
            raise SystemExit(f"2C-0 planned Schema additions already exist: {relative}")
        expected["properties"].update(copy.deepcopy(additions))
        expected["required"] = [*expected["required"], *additions]
        if (
            not isinstance(schema, dict)
            or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
            or schema.get("type") != "object"
            or schema.get("additionalProperties") is not False
            or schema.get("properties", {}).get("schema_version", {}).get("const")
            != version
            or schema != expected
        ):
            raise SystemExit(
                f"2C-0 public contract is not the exact additive {version} overlay: "
                f"{relative}"
            )
        hashes[relative] = hashlib.sha256(raw).hexdigest()
    return hashes


def _verify_component_lock(
    repository: Path,
    parent: str,
    *,
    schema_hashes: dict[str, str],
) -> None:
    path = "component-lock.json"
    base = _json_bytes(
        _git_bytes(repository, parent, path),
        label=f"{parent}:{path}",
        canonical=False,
    )
    candidate = _strict_json(repository / path)
    expected_keys = {*base, "vendor_market_contract_authority"}
    if set(candidate) != expected_keys:
        raise SystemExit("2C-0 component lock has an unexpected authority subtree")
    if (
        candidate.get("lock_version") != EXPECTED_COMPONENT_LOCK_VERSION
        or candidate.get("generated_date") != "2026-07-22"
        or candidate.get("market_access_authority") != base.get("market_access_authority")
        or candidate.get("valuation_kernel") != base.get("valuation_kernel")
    ):
        raise SystemExit("2C-0 drifted a frozen component-lock authority")
    owner = copy.deepcopy(candidate.get("owner_equity_research"))
    base_owner = copy.deepcopy(base.get("owner_equity_research"))
    if not isinstance(owner, dict) or not isinstance(base_owner, dict):
        raise SystemExit("2C-0 component lock lacks research identity")
    if owner.get("plugin_version") != EXPECTED_PLUGIN_VERSION:
        raise SystemExit("2C-0 component lock Plugin version drifted")
    owner["plugin_version"] = base_owner["plugin_version"]
    candidate_schema_hashes = owner.get("public_schema_sha256")
    base_schema_hashes = base_owner.get("public_schema_sha256")
    if (
        not isinstance(candidate_schema_hashes, dict)
        or not isinstance(base_schema_hashes, dict)
        or set(candidate_schema_hashes) != set(base_schema_hashes)
    ):
        raise SystemExit("2C-0 component lock public Schema inventory drifted")
    for schema_path, digest in schema_hashes.items():
        if candidate_schema_hashes.get(schema_path) != digest:
            raise SystemExit("2C-0 component lock does not bind the changed Schema bytes")
        candidate_schema_hashes[schema_path] = base_schema_hashes[schema_path]
    if owner != base_owner:
        raise SystemExit("2C-0 changed a public Schema outside its two authorized contracts")
    policy_sha = hashlib.sha256((repository / VENDOR_POLICY_PATH).read_bytes()).hexdigest()
    types_sha = hashlib.sha256((repository / VENDOR_TYPES_PATH).read_bytes()).hexdigest()
    if candidate["vendor_market_contract_authority"] != {
        "authority_version": "1.0.0",
        "policy": {
            "path": "resources/market_access/vendor-market-contract-policy.json",
            "sha256": policy_sha,
        },
        "types_code": {
            "path": "valuation_vendor_market_contract_types.py",
            "sha256": types_sha,
        },
    }:
        raise SystemExit("2C-0 vendor contract authority is not content addressed")


def verify(repository: Path) -> None:
    if _changed_diff(repository) != EXPECTED_DIFF:
        raise SystemExit("2C-0 escaped its exact contract-only diff")
    parent = _parent(repository)
    _verify_regular_file_modes(repository, parent)
    _verify_status(repository, parent)
    _verify_pyproject(repository, parent)
    _verify_plugin(repository, parent)
    source_path = repository / "src/owner_research/valuation_vendor_market_contract_types.py"
    source = source_path.read_text(encoding="utf-8")
    lowered = source.casefold()
    if any(term in lowered for term in FORBIDDEN_SOURCE_TERMS):
        raise SystemExit("2C-0 internal types contain a provider or execution capability")
    _verify_declarative_types(source, filename=str(source_path))
    policy = _strict_json(
        repository
        / "src/owner_research/resources/market_access/vendor-market-contract-policy.json"
    )
    if policy != EXPECTED_VENDOR_POLICY:
        raise SystemExit("2C-0 vendor-neutral policy is not the closed protected payload")
    if _strict_json(repository / "tests/fixtures/phase5e2c0/adversarial-cases.json") != (
        EXPECTED_ADVERSARIAL_CASES
    ):
        raise SystemExit("2C-0 adversarial cases differ from the protected fixture")
    if (
        repository / "tests/test_phase5e2c0_vendor_market_contract.py"
    ).read_text(encoding="utf-8") != EXPECTED_TEST_SOURCE:
        raise SystemExit("2C-0 test source differs from the protected inert test")
    schema_hashes = _verify_schemas(repository, parent)
    _verify_component_lock(repository, parent, schema_hashes=schema_hashes)
    _verify_skill_appendices(repository, parent)
    if len(tuple((repository / "schemas").glob("*.schema.json"))) != 43:
        raise SystemExit("2C-0 changed the public Schema count")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    args = parser.parse_args()
    verify(args.repository.resolve())
    print("Phase 5E-2C-0 protected contract-only semantic replay passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
