from __future__ import annotations

import copy
from dataclasses import replace

import pytest
from phase4a_support import replace_graph, valid_phase4a_graph

from owner_research.contracts import FiscalPeriod
from owner_research.management_commitments import (
    CommitmentCompilationError,
    CommitmentRequest,
    compile_commitment,
    compile_supersession,
    compile_withdrawal,
    resolve_relative_fiscal_due_date,
)


def _request(**updates: object) -> CommitmentRequest:
    values: dict[str, object] = {
        "commitment_type": "guidance",
        "commitment_strength": "committed",
        "metric_concept": "revenue_growth",
        "baseline_bindings": (
            {"component_id": "primary", "fact_id": "fact:acme:revenue:2025"},
        ),
        "scope": {
            "scope_type": "issuer",
            "scope_id": "issuer:acme",
            "scope_label": "Acme consolidated",
        },
        "measurement_basis": {
            "accounting_basis": "gaap",
            "currency_basis": "reported",
            "growth_basis": "reported",
            "aggregation_basis": "period",
        },
        "comparison_direction": "exact",
        "start_date": "2026-01-01",
        "due_date": "2026-12-31",
        "relative_due": None,
        "evaluation_policy_id": "growth_range",
        "condition_claim_ids": (),
        "definition_reconciliation_calculation_ids": (),
    }
    values.update(updates)
    return CommitmentRequest(**values)


def _compile(sample_payloads: dict[str, dict], request: CommitmentRequest | None = None):
    graph = valid_phase4a_graph(sample_payloads)
    result = compile_commitment(
        statement=graph.management_statements[0],
        candidate=graph.management_statement_candidates[0],
        decision=graph.management_statement_review_decisions[0],
        facts=graph.facts,
        source_documents=graph.documents,
        request=request or _request(),
    )
    return graph, result


def test_compiler_emits_commitment_only_from_confirmed_metric_evidence(
    sample_payloads: dict[str, dict],
) -> None:
    graph, result = _compile(sample_payloads)
    assert result.exclusion_reason is None
    assert result.commitment is not None
    assert result.commitment.target_bindings == graph.management_commitments[0].target_bindings
    assert result.commitment.evaluation_policy_id == "growth_range"
    replace_graph(
        graph,
        management_commitments=(result.commitment,),
        management_outcomes=(),
        management_reviews=(),
    ).validate()


def test_narrative_statement_is_recorded_without_blocked_commitment(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    result = compile_commitment(
        statement=replace(
            graph.management_statements[0],
            commitment_eligibility="narrative_only",
            metric_bindings=(),
        ),
        candidate=replace(graph.management_statement_candidates[0], metric_mentions=()),
        decision=replace(
            graph.management_statement_review_decisions[0], output_fact_ids=()
        ),
        facts=graph.facts,
        source_documents=graph.documents,
        request=_request(),
    )
    assert result.commitment is None
    assert result.exclusion_reason == "statement_not_measurable"


def test_compiler_rejects_unconfirmed_statement(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    with pytest.raises(CommitmentCompilationError, match="human-confirmed"):
        compile_commitment(
            statement=replace(
                graph.management_statements[0],
                verification_status="pending",
                reviewer_id=None,
                reviewed_at=None,
            ),
            candidate=graph.management_statement_candidates[0],
            decision=graph.management_statement_review_decisions[0],
            facts=graph.facts,
            source_documents=graph.documents,
            request=_request(),
        )


def test_compiler_rejects_nonofficial_source(sample_payloads: dict[str, dict]) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    with pytest.raises(CommitmentCompilationError, match="official Statement evidence"):
        compile_commitment(
            statement=graph.management_statements[0],
            candidate=graph.management_statement_candidates[0],
            decision=graph.management_statement_review_decisions[0],
            facts=graph.facts,
            source_documents=(replace(graph.documents[0], authority_level="secondary"),),
            request=_request(),
        )


def test_compiler_rejects_unregistered_policy(sample_payloads: dict[str, dict]) -> None:
    with pytest.raises(CommitmentCompilationError, match="unregistered management policy"):
        _compile(sample_payloads, _request(evaluation_policy_id="free_form"))


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        (
            "measurement_basis",
            {
                "accounting_basis": "gaap",
                "currency_basis": "constant_currency",
                "growth_basis": "reported",
                "aggregation_basis": "period",
            },
            "measurement basis",
        ),
        (
            "scope",
            {
                "scope_type": "product",
                "scope_id": "product:other",
                "scope_label": "Other product",
            },
            "scope",
        ),
        ("metric_concept", "operating_margin", "metric"),
    ],
)
def test_compiler_rejects_target_semantic_mismatch(
    sample_payloads: dict[str, dict], field: str, replacement: object, message: str
) -> None:
    request = _request(**{field: replacement})
    with pytest.raises(CommitmentCompilationError, match=message):
        _compile(sample_payloads, request)


def test_compiler_rejects_ambiguous_relative_fiscal_deadline(
    sample_payloads: dict[str, dict],
) -> None:
    valid_phase4a_graph(sample_payloads)
    with pytest.raises(CommitmentCompilationError, match="unique fiscal period"):
        resolve_relative_fiscal_due_date(
            issuer_id="issuer:acme",
            statement_date="2026-02-15",
            relative_due="current_fiscal_year_end",
            fiscal_periods=(),
        )


def test_relative_fiscal_deadline_uses_explicit_noncalendar_period(
    sample_payloads: dict[str, dict],
) -> None:
    payload = copy.deepcopy(sample_payloads["fiscal-period"])
    payload.update(
        period_id="period:acme:2026-q4",
        fiscal_year=2026,
        fiscal_quarter=4,
        calendar_type="non_calendar",
        quarter_start="2026-11-01",
        quarter_end="2027-01-31",
        cumulative_start="2026-02-01",
        cumulative_end="2027-01-31",
        ttm_start="2026-02-01",
    )
    period = FiscalPeriod(**payload)
    assert resolve_relative_fiscal_due_date(
        issuer_id="issuer:acme",
        statement_date="2026-02-15",
        relative_due="current_fiscal_year_end",
        fiscal_periods=(period,),
    ) == "2027-01-31"


def test_compiler_requires_exactly_one_deadline_form(
    sample_payloads: dict[str, dict],
) -> None:
    with pytest.raises(CommitmentCompilationError, match="exactly one"):
        _compile(
            sample_payloads,
            _request(relative_due="current_fiscal_year_end"),
        )


def test_conditional_commitment_requires_recorded_condition_claim(
    sample_payloads: dict[str, dict],
) -> None:
    with pytest.raises(CommitmentCompilationError, match="condition Claims"):
        _compile(
            sample_payloads,
            _request(commitment_strength="conditional", condition_claim_ids=()),
        )


def test_maintain_or_improve_compiles_without_target_binding(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    baseline = replace(
        graph.facts[0],
        source_locator=graph.management_statements[0].source_locator,
    )
    statement = replace(
        graph.management_statements[0],
        metric_bindings=(
            {
                "component_id": "primary",
                "metric_concept": "revenue",
                "role": "point",
                "fact_id": baseline.fact_id,
            },
        ),
    )
    mention = dict(graph.management_statement_candidates[0].metric_mentions[0])
    mention.update(
        metric_concept="revenue",
        role="point",
        value=baseline.value,
        unit=baseline.unit,
        currency=baseline.currency,
        period=baseline.to_dict()["period"],
    )
    candidate = replace(
        graph.management_statement_candidates[0], metric_mentions=(mention,)
    )
    decision = replace(
        graph.management_statement_review_decisions[0],
        candidate_fingerprint=candidate.fingerprint,
        output_fact_ids=(baseline.fact_id,),
    )
    result = compile_commitment(
        statement=statement,
        candidate=candidate,
        decision=decision,
        facts=(baseline,),
        source_documents=graph.documents,
        request=_request(
            metric_concept="revenue",
            evaluation_policy_id="maintain_or_improve",
            comparison_direction="higher_is_better",
        ),
    )
    assert result.commitment is not None
    assert result.commitment.target_bindings == ()


def test_kpi_definition_change_requires_deterministic_bridge(
    sample_payloads: dict[str, dict],
) -> None:
    graph = valid_phase4a_graph(sample_payloads)
    statement = replace(
        graph.management_statements[0],
        statement_type="kpi_definition",
        kpi_concept="revenue_growth",
        definition_change="redefined",
        predecessor_statement_ids=("statement:prior",),
        kpi_definition_fact_ids=(graph.facts[0].fact_id,),
    )
    with pytest.raises(CommitmentCompilationError, match="deterministic bridge"):
        compile_commitment(
            statement=statement,
            candidate=graph.management_statement_candidates[0],
            decision=graph.management_statement_review_decisions[0],
            facts=graph.facts,
            source_documents=graph.documents,
            request=_request(),
        )


def test_withdrawal_and_supersession_are_compiled_as_lifecycle_changes(
    sample_payloads: dict[str, dict],
) -> None:
    graph, result = _compile(sample_payloads)
    assert result.commitment is not None
    withdrawal_statement = replace(
        graph.management_statements[0],
        statement_id="statement:acme:withdrawal:2026",
        statement_date="2026-06-01",
        metric_bindings=(),
        commitment_eligibility="narrative_only",
        statement_type="other",
    )
    withdrawn = compile_withdrawal(result.commitment, withdrawal_statement)
    assert withdrawn.status == "withdrawn"
    assert withdrawn.withdrawal_statement_id == withdrawal_statement.statement_id

    successor = replace(
        result.commitment,
        commitment_id="commitment:acme:revenue:2026-revised",
        start_date="2026-06-01",
    )
    superseded = compile_supersession(result.commitment, successor)
    assert superseded.status == "superseded"
    assert superseded.superseded_by_commitment_id == successor.commitment_id


def test_supersession_rejects_metric_change_or_nonlater_successor(
    sample_payloads: dict[str, dict],
) -> None:
    _, result = _compile(sample_payloads)
    assert result.commitment is not None
    with pytest.raises(CommitmentCompilationError, match="metric concept"):
        compile_supersession(
            result.commitment,
            replace(result.commitment, commitment_id="commitment:new", metric_concept="margin"),
        )
    with pytest.raises(CommitmentCompilationError, match="later start date"):
        compile_supersession(
            result.commitment,
            replace(result.commitment, commitment_id="commitment:new"),
        )
