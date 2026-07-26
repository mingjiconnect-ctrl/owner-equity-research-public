from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from quarterly_support import GOLDEN, load_case

from owner_research.contracts import CONTRACT_TYPES
from owner_research.schema_store import SCHEMA_NAMES, load_schema, validate_payload


@pytest.mark.parametrize(
    "name", ["fiscal-period", "quarterly-reconciliation", "quarterly-update"]
)
def test_phase2_public_schemas_are_draft_2020_12(name: str) -> None:
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / f"{name}.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False


def test_phase2_schemas_are_registered_with_python_types() -> None:
    expected = {"fiscal-period", "quarterly-reconciliation", "quarterly-update"}
    assert expected.issubset(SCHEMA_NAMES)
    assert expected.issubset(CONTRACT_TYPES)
    for name in expected:
        assert load_schema(name)["title"] == CONTRACT_TYPES[name].__name__


@pytest.mark.parametrize("path", sorted(GOLDEN.glob("*.json")))
def test_all_golden_periods_validate_against_public_schema(path: Path) -> None:
    case = json.loads(path.read_text(encoding="utf-8"))
    assert case["fixture_kind"] == "synthetic"
    for period in case["periods"]:
        validate_payload("fiscal-period", period)


def test_fiscal_period_rejects_unknown_fields_and_invalid_weeks() -> None:
    period = copy.deepcopy(load_case("non-calendar-53-week.json")["periods"][1])
    period["hidden_adjustment"] = 1
    with pytest.raises(ValidationError):
        validate_payload("fiscal-period", period)
    period.pop("hidden_adjustment")
    period["weeks"] = 15
    with pytest.raises(ValidationError):
        validate_payload("fiscal-period", period)


def test_quarterly_update_is_reference_only_and_rejects_valuation_results() -> None:
    payload = {
        "schema_version": "1.0.0",
        "update_id": "quarterly-update:test:q2",
        "issuer_id": "issuer:test",
        "as_of_date": "2026-07-20",
        "current_period_id": "period:test:2026-q2",
        "comparison_period_id": "period:test:2025-q2",
        "status": "partial",
        "comparability": {"status": "partially_comparable", "reasons": ["fx"]},
        "fact_ids": ["fact:test:revenue"],
        "calculation_result_ids": ["calc:test:growth"],
        "reconciliation_ids": [],
        "what_changed_claim_ids": ["claim:test:change"],
        "why_it_changed_claim_ids": [],
        "temporary_or_structural_claim_ids": [],
        "guidance_change_claim_ids": [],
        "long_term_thesis_impact_claim_ids": [],
        "impact_on_valuation_assumptions_claim_ids": [],
        "valuation_assumption_review_required": False,
        "confidence": "low",
        "missing_evidence": ["FX bridge"],
        "red_flags": [],
    }
    validate_payload("quarterly-update", payload)
    invalid = copy.deepcopy(payload)
    invalid["valuation_result_ids"] = ["valuation:test"]
    with pytest.raises(ValidationError):
        validate_payload("quarterly-update", invalid)


def test_blocked_update_requires_missing_evidence() -> None:
    schema = load_schema("quarterly-update")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    payload = {
        "schema_version": "1.0.0",
        "update_id": "quarterly-update:test:q2",
        "issuer_id": "issuer:test",
        "as_of_date": "2026-07-20",
        "current_period_id": "period:test:2026-q2",
        "comparison_period_id": "period:test:2025-q2",
        "status": "blocked",
        "comparability": {"status": "not_comparable", "reasons": []},
        "fact_ids": ["fact:test:revenue"],
        "calculation_result_ids": ["calc:test:growth"],
        "reconciliation_ids": [],
        "what_changed_claim_ids": ["claim:test:change"],
        "why_it_changed_claim_ids": [],
        "temporary_or_structural_claim_ids": [],
        "guidance_change_claim_ids": [],
        "long_term_thesis_impact_claim_ids": [],
        "impact_on_valuation_assumptions_claim_ids": [],
        "valuation_assumption_review_required": False,
        "confidence": "low",
        "missing_evidence": [],
        "red_flags": [],
    }
    assert list(validator.iter_errors(payload))


def test_quarterly_reconciliation_state_is_internally_consistent() -> None:
    payload = {
        "schema_version": "1.0.0",
        "reconciliation_id": "reconciliation:test:revenue",
        "issuer_id": "issuer:test",
        "period_id": "period:test:2026-q2",
        "basis": "single_quarter",
        "concept": "revenue",
        "candidate_fact_ids": ["fact:test:10-q", "fact:test:release"],
        "authoritative_fact_id": "fact:test:10-q",
        "delta_calculation_id": "calc:test:delta",
        "tolerance": 0.01,
        "status": "exact_match",
        "selection_rule": "regulatory_over_company_release",
        "blocked": False,
        "notes": "The regulatory filing is authoritative.",
    }
    validate_payload("quarterly-reconciliation", payload)

    inconsistent = copy.deepcopy(payload)
    inconsistent["blocked"] = True
    with pytest.raises(ValidationError):
        validate_payload("quarterly-reconciliation", inconsistent)

    no_authority = copy.deepcopy(payload)
    no_authority.update(
        authoritative_fact_id=None,
        delta_calculation_id="calc:test:delta",
        status="conflict",
        selection_rule="no_regulatory_authority",
        blocked=True,
    )
    with pytest.raises(ValidationError):
        validate_payload("quarterly-reconciliation", no_authority)


def test_complete_quarterly_update_requires_every_interpretive_dimension() -> None:
    payload = {
        "schema_version": "1.0.0",
        "update_id": "quarterly-update:test:q2",
        "issuer_id": "issuer:test",
        "as_of_date": "2026-07-20",
        "current_period_id": "period:test:2026-q2",
        "comparison_period_id": "period:test:2025-q2",
        "status": "complete",
        "comparability": {"status": "comparable", "reasons": []},
        "fact_ids": ["fact:test:revenue"],
        "calculation_result_ids": ["calc:test:growth"],
        "reconciliation_ids": [],
        "what_changed_claim_ids": ["claim:test:change"],
        "why_it_changed_claim_ids": [],
        "temporary_or_structural_claim_ids": [],
        "guidance_change_claim_ids": [],
        "long_term_thesis_impact_claim_ids": [],
        "impact_on_valuation_assumptions_claim_ids": [],
        "valuation_assumption_review_required": False,
        "confidence": "high",
        "missing_evidence": [],
        "red_flags": [],
    }
    with pytest.raises(ValidationError):
        validate_payload("quarterly-update", payload)

    for field in (
        "why_it_changed_claim_ids",
        "temporary_or_structural_claim_ids",
        "guidance_change_claim_ids",
        "long_term_thesis_impact_claim_ids",
    ):
        payload[field] = [f"claim:test:{field}"]
    validate_payload("quarterly-update", payload)

    payload["valuation_assumption_review_required"] = True
    with pytest.raises(ValidationError):
        validate_payload("quarterly-update", payload)
    payload["impact_on_valuation_assumptions_claim_ids"] = ["claim:test:valuation"]
    validate_payload("quarterly-update", payload)


def test_comparability_status_and_reasons_are_consistent() -> None:
    payload = {
        "schema_version": "1.0.0",
        "update_id": "quarterly-update:test:q2",
        "issuer_id": "issuer:test",
        "as_of_date": "2026-07-20",
        "current_period_id": "period:test:2026-q2",
        "comparison_period_id": "period:test:2025-q2",
        "status": "blocked",
        "comparability": {"status": "not_comparable", "reasons": []},
        "fact_ids": ["fact:test:revenue"],
        "calculation_result_ids": [],
        "reconciliation_ids": [],
        "what_changed_claim_ids": ["claim:test:change"],
        "why_it_changed_claim_ids": [],
        "temporary_or_structural_claim_ids": [],
        "guidance_change_claim_ids": [],
        "long_term_thesis_impact_claim_ids": [],
        "impact_on_valuation_assumptions_claim_ids": [],
        "valuation_assumption_review_required": False,
        "confidence": "low",
        "missing_evidence": ["comparability evidence"],
        "red_flags": [],
    }
    with pytest.raises(ValidationError):
        validate_payload("quarterly-update", payload)
    payload["comparability"] = {"status": "comparable", "reasons": ["fx"]}
    with pytest.raises(ValidationError):
        validate_payload("quarterly-update", payload)
