from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

SCHEMA_NAMES = (
    "source-document",
    "fact",
    "claim",
    "assumption",
    "calculation-result",
    "score",
    "report-spec",
    "run-manifest",
    "research-bundle",
    "valuation-assumption-candidate",
    "valuation-assumption-review-decision",
    "market-reference-snapshot",
    "valuation-handoff",
    "fiscal-period",
    "quarterly-reconciliation",
    "quarterly-update",
    "filing-artifact",
    "extraction-candidate",
    "evidence-promotion",
    "segment-definition",
    "segment-snapshot",
    "footnote-review",
    "accounting-quality-finding",
    "accounting-quality-review",
    "context-observation",
    "competitive-context-snapshot",
    "analytical-claim-candidate",
    "analytical-claim-review-decision",
    "business-model-snapshot",
    "competitive-advantage-hypothesis",
    "business-quality-review",
    "management-statement",
    "management-statement-candidate",
    "management-statement-review-decision",
    "management-commitment",
    "management-outcome",
    "capital-allocation-event-candidate",
    "capital-allocation-event-review-decision",
    "capital-allocation-event",
    "capital-allocation-outcome",
    "source-search-receipt",
    "management-review",
    "capital-allocation-review",
)


def schema_directory() -> Path:
    packaged = Path(__file__).parent / "schemas"
    if packaged.is_dir():
        return packaged
    repository = Path(__file__).parents[2] / "schemas"
    if repository.is_dir():
        return repository
    raise FileNotFoundError("Public schema directory is unavailable")


@cache
def load_schema(name: str) -> dict[str, Any]:
    if name not in SCHEMA_NAMES:
        raise KeyError(f"Unknown public schema: {name}")
    path = schema_directory() / f"{name}.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


@cache
def schema_registry() -> Registry:
    return Registry().with_resources(
        (
            schema["$id"],
            Resource.from_contents(schema),
        )
        for schema in (load_schema(name) for name in SCHEMA_NAMES)
    )


@cache
def schema_validator(name: str) -> Draft202012Validator:
    schema = load_schema(name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
        registry=schema_registry(),
    )


def validate_payload(name: str, payload: dict[str, Any]) -> None:
    schema_validator(name).validate(payload)
