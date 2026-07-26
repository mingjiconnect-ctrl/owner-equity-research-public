from __future__ import annotations

import copy
from dataclasses import replace

import pytest
from jsonschema import ValidationError
from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.contracts import Fact, contract_from_dict
from owner_research.units import UnitError, migrate_fact_v1_to_v2
from owner_research.validation import ContractGraphError


def test_nonmonetary_fact_requires_null_currency(sample_payloads: dict[str, dict]) -> None:
    payload = copy.deepcopy(sample_payloads["fact"])
    payload.update(unit="customers", currency=None)
    assert Fact(**payload).currency is None

    payload["currency"] = "USD"
    with pytest.raises(ValidationError):
        Fact(**payload)


def test_monetary_fact_requires_currency(sample_payloads: dict[str, dict]) -> None:
    payload = copy.deepcopy(sample_payloads["fact"])
    payload["currency"] = None
    with pytest.raises(ValidationError):
        Fact(**payload)


def test_fact_v1_migration_is_controlled(sample_payloads: dict[str, dict]) -> None:
    legacy = copy.deepcopy(sample_payloads["fact"])
    legacy.update(schema_version="1.0.0", unit="millions")
    migrated = migrate_fact_v1_to_v2(legacy)
    assert migrated["schema_version"] == "2.0.0"
    assert migrated["unit"] == "currency_millions"

    legacy["unit"] = "mystery_scale"
    with pytest.raises(UnitError, match="explicit known mapping"):
        migrate_fact_v1_to_v2(legacy)


def test_narrative_statement_cannot_create_commitment(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    narrative = replace(
        graph.management_statements[0],
        commitment_eligibility="narrative_only",
        metric_bindings=(),
    )
    candidate = replace(graph.management_statement_candidates[0], metric_mentions=())
    decision = replace(
        graph.management_statement_review_decisions[0],
        candidate_fingerprint=candidate.fingerprint,
        output_fact_ids=(),
    )
    with pytest.raises(ContractGraphError, match="measurable Statement"):
        replace_graph(
            graph,
            management_statements=(narrative,),
            management_statement_candidates=(candidate,),
            management_statement_review_decisions=(decision,),
        ).validate()


def test_baseline_cannot_be_reused_as_target(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    commitment = replace(
        graph.management_commitments[0],
        baseline_bindings=(
            {
                "component_id": "primary",
                "fact_id": graph.management_commitments[0].target_bindings[0]["fact_id"],
            },
        ),
    )
    with pytest.raises(ContractGraphError, match="reuses baseline Fact as target"):
        replace_graph(graph, management_commitments=(commitment,)).validate()


def test_unregistered_policy_is_rejected(sample_payloads: dict[str, dict]) -> None:
    payload = copy.deepcopy(sample_payloads["management-commitment"])
    payload["evaluation_policy_id"] = "free_form_policy"
    with pytest.raises(ValidationError):
        contract_from_dict("management-commitment", payload)


def test_result_metric_cannot_be_wrapped_as_met(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    commitment = replace(graph.management_commitments[0], due_date="2026-06-30")
    outcome = replace(
        graph.management_outcomes[0],
        assessed_at="2026-07-15",
        evaluation_period={"start": "2026-01-01", "end": "2026-06-30"},
        status="met",
        result_bindings=(
            {
                "component_id": "primary",
                "role": "actual",
                "fact_id": graph.facts[0].fact_id,
                "calculation_result_id": None,
            },
        ),
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="metric concept mismatch"):
        replace_graph(
            graph,
            management_commitments=(commitment,),
            management_outcomes=(outcome,),
            management_reviews=(),
        ).validate()


def test_single_component_target_cannot_be_partially_met(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    commitment = replace(graph.management_commitments[0], due_date="2026-06-30")
    outcome = replace(
        graph.management_outcomes[0],
        assessed_at="2026-07-15",
        evaluation_period={"start": "2026-01-01", "end": "2026-06-30"},
        status="partially_met",
        result_bindings=(
            {
                "component_id": "primary",
                "role": "actual",
                "fact_id": graph.facts[1].fact_id,
                "calculation_result_id": None,
            },
        ),
        missing_evidence=(),
    )
    with pytest.raises(ContractGraphError, match="multi-component"):
        replace_graph(
            graph,
            management_commitments=(commitment,),
            management_outcomes=(outcome,),
            management_reviews=(),
        ).validate()


def test_withdrawn_commitment_is_not_due_or_missed(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    commitment = replace(
        graph.management_commitments[0],
        status="withdrawn",
        withdrawal_statement_id=graph.management_statements[0].statement_id,
    )
    outcome = replace(
        graph.management_outcomes[0],
        status="withdrawn",
        result_bindings=(),
        missing_evidence=(),
    )
    review = replace(
        graph.management_reviews[0],
        coverage={
            "statement_count": 1,
            "confirmed_count": 1,
            "open_count": 0,
            "not_due_count": 0,
            "due_count": 0,
            "evaluated_due_count": 0,
            "pending_count": 0,
            "met_count": 0,
            "partially_met_count": 0,
            "missed_count": 0,
            "unverifiable_count": 0,
            "blocked_count": 0,
            "withdrawn_count": 1,
            "superseded_count": 0,
        },
    )
    replace_graph(
        graph,
        management_commitments=(commitment,),
        management_outcomes=(outcome,),
        management_reviews=(review,),
    ).validate()
