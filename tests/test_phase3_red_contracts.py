from __future__ import annotations

import ast
import json
from pathlib import Path

from owner_research.contracts import CONTRACT_TYPES, contract_from_dict

ROOT = Path(__file__).parents[1]

PHASE3_SCHEMAS = {
    "filing-artifact",
    "extraction-candidate",
    "evidence-promotion",
    "segment-definition",
    "segment-snapshot",
    "footnote-review",
    "accounting-quality-finding",
    "accounting-quality-review",
}


def _collect_keys(value: object, keys: set[str]) -> None:
    if isinstance(value, dict):
        keys.update(value)
        for item in value.values():
            _collect_keys(item, keys)
    elif isinstance(value, list):
        for item in value:
            _collect_keys(item, keys)


def test_phase3_schemas_have_immutable_types(sample_payloads: dict[str, dict]) -> None:
    assert PHASE3_SCHEMAS.issubset(CONTRACT_TYPES)
    for name in PHASE3_SCHEMAS:
        assert contract_from_dict(name, sample_payloads[name]).to_dict() == sample_payloads[name]


def test_phase3_schemas_forbid_score_valuation_report_and_publisher_edges() -> None:
    for name in PHASE3_SCHEMAS:
        schema = json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text())
        keys = set()

        _collect_keys(schema, keys)
        assert not {"score", "score_id", "valuation", "report", "publisher"}.intersection(keys)


def test_phase3_runtime_has_no_model_sdk_arelle_or_report_dependency() -> None:
    forbidden = {"openai", "anthropic", "arelle", "reportlab", "weasyprint"}
    imports: set[str] = set()
    for module in (ROOT / "src" / "owner_research").glob("*.py"):
        tree = ast.parse(module.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
    assert not forbidden.intersection(imports)


def test_phase3_modules_are_present() -> None:
    for name in ("sec", "extraction", "promotion", "segments", "footnotes", "accounting_quality"):
        __import__(f"owner_research.{name}")
