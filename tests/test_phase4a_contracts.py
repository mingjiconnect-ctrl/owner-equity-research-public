from __future__ import annotations

import copy
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from jsonschema import ValidationError

from owner_research.contracts import contract_from_dict
from owner_research.schema_store import validate_payload
from owner_research.validation import PHASE4_EVENT_TYPES, PHASE4_MECHANISMS

PHASE4A_SCHEMAS = {
    "business-model-snapshot",
    "competitive-advantage-hypothesis",
    "business-quality-review",
    "management-statement",
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
ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize("schema_name", sorted(PHASE4A_SCHEMAS))
def test_phase4a_contract_is_immutable_and_fingerprint_stable(
    schema_name: str, sample_payloads: dict[str, dict]
) -> None:
    payload = copy.deepcopy(sample_payloads[schema_name])
    instance = contract_from_dict(schema_name, payload)
    second = contract_from_dict(schema_name, dict(reversed(list(payload.items()))))

    assert instance.to_dict() == payload
    assert instance.fingerprint == second.fingerprint
    with pytest.raises((FrozenInstanceError, AttributeError)):
        instance.schema_version = "changed"


@pytest.mark.parametrize("schema_name", sorted(PHASE4A_SCHEMAS))
def test_phase4a_schema_rejects_unknown_fields(
    schema_name: str, sample_payloads: dict[str, dict]
) -> None:
    payload = copy.deepcopy(sample_payloads[schema_name])
    payload["score"] = 99
    with pytest.raises(ValidationError):
        validate_payload(schema_name, payload)


def test_phase4a_controlled_vocabularies_are_exact(sample_payloads: dict[str, dict]) -> None:
    mechanisms = {
        row["mechanism"] for row in sample_payloads["business-quality-review"]["mechanism_coverage"]
    }
    event_types = {
        row["event_type"]
        for row in sample_payloads["capital-allocation-review"]["event_type_coverage"]
    }

    assert mechanisms == PHASE4_MECHANISMS
    assert event_types == PHASE4_EVENT_TYPES


def test_phase4a_review_schemas_forbid_scores_and_valuation(
    sample_payloads: dict[str, dict],
) -> None:
    for schema_name in (
        "business-quality-review",
        "management-review",
        "capital-allocation-review",
    ):
        for forbidden in ("score", "valuation", "target_price", "recommendation"):
            payload = copy.deepcopy(sample_payloads[schema_name])
            payload[forbidden] = 1
            with pytest.raises(ValidationError):
                validate_payload(schema_name, payload)


def test_language_model_statement_cannot_be_human_confirmed_without_reviewer(
    sample_payloads: dict[str, dict],
) -> None:
    payload = copy.deepcopy(sample_payloads["management-statement"])
    payload["extraction_method"] = "language_model"
    payload["verification_status"] = "human_confirmed"
    payload["reviewer_id"] = None
    payload["reviewed_at"] = None

    with pytest.raises(ValidationError):
        validate_payload("management-statement", payload)


def test_report_spec_and_dependency_matrix_expose_one_way_phase4a_edges() -> None:
    report_schema = json.loads((ROOT / "schemas" / "report-spec.schema.json").read_text())
    allowed_inputs = set(
        report_schema["properties"]["sections"]["items"]["properties"]["required_input_types"][
            "items"
        ]["enum"]
    )
    matrix = json.loads(
        (ROOT / "docs" / "contract-dependency-matrix.json").read_text(encoding="utf-8")
    )
    contract_names = {
        "ContextObservation",
        "CompetitiveContextSnapshot",
        "AnalyticalClaimCandidate",
        "AnalyticalClaimReviewDecision",
        "BusinessModelSnapshot",
        "CompetitiveAdvantageHypothesis",
        "BusinessQualityReview",
        "ManagementStatement",
        "ManagementCommitment",
        "ManagementOutcome",
        "CapitalAllocationEventCandidate",
        "CapitalAllocationEventReviewDecision",
        "CapitalAllocationEvent",
        "CapitalAllocationOutcome",
        "ManagementReview",
        "CapitalAllocationReview",
        "SourceSearchReceipt",
    }

    assert contract_names.issubset(allowed_inputs)
    assert contract_names.issubset(matrix)
    upstream = {
        "SourceDocument",
        "Fact",
        "Claim",
        "Assumption",
        "CalculationResult",
        "FiscalPeriod",
        "Score",
        "ReportSpec",
        "RunManifest",
    }
    assert all(contract_names.isdisjoint(matrix[name]) for name in upstream)
    assert all(
        {"Score", "ReportSpec", "Valuation", "Publisher"}.isdisjoint(matrix[name])
        for name in contract_names
    )
