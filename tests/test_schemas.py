from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

from owner_research.schema_store import SCHEMA_NAMES, load_schema, validate_payload


def test_all_public_schemas_are_draft_2020_12() -> None:
    assert set(SCHEMA_NAMES) == {
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
    }
    for name in SCHEMA_NAMES:
        schema = load_schema(name)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["additionalProperties"] is False


def test_positive_examples_validate(sample_payloads: dict[str, dict]) -> None:
    for name, payload in sample_payloads.items():
        validate_payload(name, payload)


@pytest.mark.parametrize("schema_name", SCHEMA_NAMES)
def test_unknown_properties_are_rejected(
    schema_name: str, sample_payloads: dict[str, dict]
) -> None:
    invalid = copy.deepcopy(sample_payloads[schema_name])
    invalid["unexpected"] = True
    with pytest.raises(ValidationError):
        validate_payload(schema_name, invalid)


def test_numeric_fact_requires_unit_currency_and_period(sample_payloads: dict[str, dict]) -> None:
    for missing in ("unit", "currency", "period"):
        invalid = copy.deepcopy(sample_payloads["fact"])
        invalid.pop(missing)
        with pytest.raises(ValidationError):
            validate_payload("fact", invalid)


def test_numeric_extraction_candidate_cannot_auto_qualify_with_null_unit_or_currency(
    sample_payloads: dict[str, dict],
) -> None:
    from owner_research.contracts import contract_from_dict
    from owner_research.promotion import evaluate_candidate

    for field in ("unit", "currency"):
        invalid = copy.deepcopy(sample_payloads["extraction-candidate"])
        invalid[field] = None
        candidate = contract_from_dict("extraction-candidate", invalid)
        outcome = evaluate_candidate(
            candidate,
            source=contract_from_dict("source-document", sample_payloads["source-document"]),
            artifact=contract_from_dict("filing-artifact", sample_payloads["filing-artifact"]),
            reviewed_at="2026-02-16T02:00:00Z",
        )
        assert outcome.promotion.decision == "blocked"


def test_claim_requires_support_and_counterevidence_search(
    sample_payloads: dict[str, dict],
) -> None:
    unsupported = copy.deepcopy(sample_payloads["claim"])
    unsupported["supporting_fact_ids"] = []
    with pytest.raises(ValidationError):
        validate_payload("claim", unsupported)

    undocumented = copy.deepcopy(sample_payloads["claim"])
    undocumented["counterevidence_search_note"] = ""
    with pytest.raises(ValidationError):
        validate_payload("claim", undocumented)

    documented_counterevidence = copy.deepcopy(sample_payloads["claim"])
    documented_counterevidence["counterevidence_fact_ids"] = ["fact:counterexample"]
    documented_counterevidence["counterevidence_search_note"] = None
    validate_payload("claim", documented_counterevidence)


def test_calculation_requires_at_least_one_input(sample_payloads: dict[str, dict]) -> None:
    invalid = copy.deepcopy(sample_payloads["calculation-result"])
    invalid["input_fact_ids"] = []
    invalid["input_assumption_ids"] = []
    invalid["input_calculation_ids"] = []
    invalid["input_period_ids"] = []
    with pytest.raises(ValidationError):
        validate_payload("calculation-result", invalid)


def test_calculation_result_v2_is_explicitly_versioned(
    sample_payloads: dict[str, dict],
) -> None:
    assert sample_payloads["calculation-result"]["schema_version"] == "2.0.0"
    legacy_version = copy.deepcopy(sample_payloads["calculation-result"])
    legacy_version["schema_version"] = "1.0.0"
    with pytest.raises(ValidationError):
        validate_payload("calculation-result", legacy_version)


@pytest.mark.parametrize("schema_name", ["assumption", "calculation-result"])
def test_declared_scalar_type_must_match_value(
    schema_name: str, sample_payloads: dict[str, dict]
) -> None:
    invalid = copy.deepcopy(sample_payloads[schema_name])
    invalid["value_type"] = "number"
    invalid["value"] = "five"
    with pytest.raises(ValidationError):
        validate_payload(schema_name, invalid)


def test_score_requires_all_evidence_categories(sample_payloads: dict[str, dict]) -> None:
    for field in (
        "fact_ids",
        "claim_ids",
        "calculation_result_ids",
        "missing_evidence",
        "red_flags",
    ):
        invalid = copy.deepcopy(sample_payloads["score"])
        invalid[field] = []
        with pytest.raises(ValidationError):
            validate_payload("score", invalid)


def test_non_score_schemas_have_no_reverse_score_dependency() -> None:
    schema_dir = Path(__file__).parents[1] / "schemas"
    for path in schema_dir.glob("*.schema.json"):
        if path.name == "score.schema.json":
            continue
        text = json.dumps(json.loads(path.read_text()), sort_keys=True).lower()
        assert "score_id" not in text
        assert "score_ids" not in text


def test_dependency_matrix_makes_score_direction_explicit() -> None:
    matrix_path = Path(__file__).parents[1] / "docs" / "contract-dependency-matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    assert matrix["Score"] == ["Fact", "Claim", "CalculationResult"]
    non_score_dependencies = (
        dependencies for name, dependencies in matrix.items() if name != "Score"
    )
    assert all("Score" not in dependencies for dependencies in non_score_dependencies)
