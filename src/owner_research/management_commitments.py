from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import date
from typing import Any

from .contracts import (
    CalculationResult,
    Claim,
    Fact,
    FiscalPeriod,
    ManagementCommitment,
    ManagementStatement,
    ManagementStatementCandidate,
    ManagementStatementReviewDecision,
    SourceDocument,
)
from .fingerprints import canonical_sha256, to_json_value
from .management_policies import POLICY_REGISTRY_VERSION, policy


class CommitmentCompilationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CommitmentRequest:
    commitment_type: str
    commitment_strength: str
    metric_concept: str
    baseline_bindings: tuple[dict[str, str], ...]
    scope: dict[str, str]
    measurement_basis: dict[str, str]
    comparison_direction: str
    start_date: str
    due_date: str | None
    relative_due: str | None
    evaluation_policy_id: str
    condition_claim_ids: tuple[str, ...]
    definition_reconciliation_calculation_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CommitmentCompilation:
    commitment: ManagementCommitment | None
    exclusion_reason: str | None


RELATIVE_FISCAL_DEADLINES = frozenset(
    {
        "current_fiscal_year_end",
        "next_fiscal_year_end",
        "current_fiscal_quarter_end",
        "next_fiscal_quarter_end",
    }
)


def resolve_relative_fiscal_due_date(
    *,
    issuer_id: str,
    statement_date: str,
    relative_due: str,
    fiscal_periods: Sequence[FiscalPeriod],
) -> str:
    if relative_due not in RELATIVE_FISCAL_DEADLINES:
        raise CommitmentCompilationError("unsupported relative fiscal deadline")
    spoken_at = date.fromisoformat(statement_date)
    periods = [item for item in fiscal_periods if item.issuer_id == issuer_id]
    if relative_due == "current_fiscal_quarter_end":
        matches = [
            item
            for item in periods
            if date.fromisoformat(item.quarter_start)
            <= spoken_at
            <= date.fromisoformat(item.quarter_end)
        ]
    elif relative_due == "next_fiscal_quarter_end":
        future = [
            item for item in periods if date.fromisoformat(item.quarter_start) > spoken_at
        ]
        first_start = min(
            (date.fromisoformat(item.quarter_start) for item in future), default=None
        )
        matches = [
            item for item in future if date.fromisoformat(item.quarter_start) == first_start
        ]
    else:
        fiscal_years = [
            item
            for item in periods
            if item.fiscal_quarter == 4
            and date.fromisoformat(item.cumulative_start)
            <= spoken_at
            <= date.fromisoformat(item.quarter_end)
        ]
        if relative_due == "current_fiscal_year_end":
            matches = fiscal_years
        else:
            if len(fiscal_years) != 1:
                matches = fiscal_years
            else:
                next_year = fiscal_years[0].fiscal_year + 1
                matches = [
                    item
                    for item in periods
                    if item.fiscal_quarter == 4 and item.fiscal_year == next_year
                ]
    if len(matches) != 1:
        raise CommitmentCompilationError(
            "relative deadline does not resolve to a unique fiscal period"
        )
    return matches[0].quarter_end


def compile_commitment(
    *,
    statement: ManagementStatement,
    candidate: ManagementStatementCandidate,
    decision: ManagementStatementReviewDecision,
    facts: Sequence[Fact],
    source_documents: Sequence[SourceDocument],
    request: CommitmentRequest,
    fiscal_periods: Sequence[FiscalPeriod] = (),
    claims: Sequence[Claim] = (),
    calculations: Sequence[CalculationResult] = (),
) -> CommitmentCompilation:
    if statement.verification_status != "human_confirmed":
        raise CommitmentCompilationError("Commitment requires a human-confirmed Statement")
    if statement.commitment_eligibility != "measurable":
        reason = (
            "statement_not_measurable"
            if statement.commitment_eligibility == "narrative_only"
            else "statement_measurement_blocked"
        )
        return CommitmentCompilation(None, reason)
    _validate_review_chain(statement, candidate, decision)

    documents = {item.document_id: item for item in source_documents}
    statement_document = documents.get(statement.source_document_id)
    if statement_document is None or statement_document.authority_level not in {
        "primary_regulatory",
        "company_primary",
    }:
        raise CommitmentCompilationError("Commitment requires official Statement evidence")

    try:
        registered = policy(request.evaluation_policy_id, POLICY_REGISTRY_VERSION)
    except ValueError as exc:
        raise CommitmentCompilationError(str(exc)) from exc
    if request.comparison_direction not in registered.allowed_directions:
        raise CommitmentCompilationError("comparison direction violates registered policy")
    if request.commitment_strength == "conditional" and not request.condition_claim_ids:
        raise CommitmentCompilationError("conditional target requires condition Claims")
    if request.commitment_strength != "conditional" and request.condition_claim_ids:
        raise CommitmentCompilationError(
            "condition Claims require conditional commitment strength"
        )
    claim_map = {item.claim_id: item for item in claims}
    for claim_id in request.condition_claim_ids:
        condition = claim_map.get(claim_id)
        if condition is None or condition.issuer_id != statement.issuer_id:
            raise CommitmentCompilationError("condition Claim is missing or cross-issuer")
        if date.fromisoformat(condition.as_of_date) > date.fromisoformat(statement.statement_date):
            raise CommitmentCompilationError("condition Claim postdates the Statement")
    if (
        statement.statement_type == "kpi_definition"
        and statement.definition_change in {"renamed", "redefined"}
        and not request.definition_reconciliation_calculation_ids
    ):
        raise CommitmentCompilationError("KPI definition change requires deterministic bridge")
    calculation_map = {item.calculation_id: item for item in calculations}
    for calculation_id in request.definition_reconciliation_calculation_ids:
        bridge = calculation_map.get(calculation_id)
        if bridge is None or bridge.issuer_id != statement.issuer_id:
            raise CommitmentCompilationError("KPI deterministic bridge is missing or cross-issuer")
        if bridge.generator != "deterministic_program" or bridge.input_assumption_ids:
            raise CommitmentCompilationError("KPI bridge must be deterministic and assumption-free")

    statement_bindings, mentions = _target_evidence(
        statement=statement,
        candidate=candidate,
        metric_concept=request.metric_concept,
    )
    target_bindings = (
        [] if request.evaluation_policy_id == "maintain_or_improve" else statement_bindings
    )
    roles = {item["role"] for item in target_bindings}
    if roles != set(registered.target_roles):
        raise CommitmentCompilationError("target roles violate registered policy")
    for mention in mentions:
        if to_json_value(mention["scope"]) != request.scope:
            raise CommitmentCompilationError("target scope differs from confirmed Statement")
        if to_json_value(mention["measurement_basis"]) != request.measurement_basis:
            raise CommitmentCompilationError(
                "target measurement basis differs from confirmed Statement"
            )

    fact_map = {item.fact_id: item for item in facts}
    if len(fact_map) != len(facts):
        raise CommitmentCompilationError("duplicate Fact identifier")
    target_fact_ids = {item["fact_id"] for item in target_bindings}
    baseline_components: set[str] = set()
    for binding in request.baseline_bindings:
        if binding["component_id"] in baseline_components:
            raise CommitmentCompilationError("duplicate baseline component")
        baseline_components.add(binding["component_id"])
        fact_id = binding["fact_id"]
        if fact_id not in fact_map:
            raise CommitmentCompilationError("baseline Fact is missing")
        if fact_id in target_fact_ids:
            raise CommitmentCompilationError("baseline Fact cannot be reused as target")
        if fact_map[fact_id].issuer_id != statement.issuer_id:
            raise CommitmentCompilationError("baseline Fact issuer mismatch")
        if (
            request.evaluation_policy_id == "maintain_or_improve"
            and fact_map[fact_id].concept != request.metric_concept
        ):
            raise CommitmentCompilationError("maintenance baseline metric mismatch")
        source = documents.get(fact_map[fact_id].source_document_id)
        if source is None or source.authority_level not in {
            "primary_regulatory",
            "company_primary",
        }:
            raise CommitmentCompilationError("baseline Fact lacks official evidence")
    if registered.requires_baseline and not request.baseline_bindings:
        raise CommitmentCompilationError("registered policy requires baseline evidence")
    for binding, mention in zip(statement_bindings, mentions, strict=True):
        fact = fact_map.get(binding["fact_id"])
        if fact is None:
            raise CommitmentCompilationError("confirmed target Fact is missing")
        if any(
            (
                fact.issuer_id != statement.issuer_id,
                fact.concept != request.metric_concept,
                fact.value_type != mention["value_type"],
                fact.value != mention["value"],
                fact.unit != mention["unit"],
                fact.currency != mention["currency"],
                fact.to_dict()["period"] != to_json_value(mention["period"]),
            )
        ):
            raise CommitmentCompilationError("target Fact differs from confirmed metric")
        source = documents.get(fact.source_document_id)
        if source is None or source.authority_level not in {
            "primary_regulatory",
            "company_primary",
        }:
            raise CommitmentCompilationError("target Fact lacks official evidence")

    due_date = _resolve_due_date(
        statement=statement,
        request=request,
        fiscal_periods=fiscal_periods,
    )
    if date.fromisoformat(request.start_date) > date.fromisoformat(due_date):
        raise CommitmentCompilationError("Commitment starts after due date")
    digest = canonical_sha256(
        {
            "statement_id": statement.statement_id,
            "request": request,
            "target_bindings": target_bindings,
            "due_date": due_date,
        }
    )[:20]
    commitment = ManagementCommitment(
        schema_version="2.0.0",
        commitment_id=f"management-commitment:{statement.issuer_id}:{digest}",
        issuer_id=statement.issuer_id,
        statement_id=statement.statement_id,
        commitment_type=request.commitment_type,
        commitment_strength=request.commitment_strength,
        metric_concept=request.metric_concept,
        baseline_bindings=request.baseline_bindings,
        target_bindings=tuple(target_bindings),
        scope=request.scope,
        measurement_basis=request.measurement_basis,
        comparison_direction=request.comparison_direction,
        start_date=request.start_date,
        due_date=due_date,
        evaluation_policy_id=request.evaluation_policy_id,
        evaluation_policy_version=POLICY_REGISTRY_VERSION,
        condition_claim_ids=request.condition_claim_ids,
        definition_reconciliation_calculation_ids=(
            request.definition_reconciliation_calculation_ids
        ),
        status="open",
        withdrawal_statement_id=None,
        superseded_by_commitment_id=None,
        missing_evidence=(),
    )
    return CommitmentCompilation(commitment, None)


def compile_withdrawal(
    commitment: ManagementCommitment,
    withdrawal_statement: ManagementStatement,
) -> ManagementCommitment:
    if withdrawal_statement.issuer_id != commitment.issuer_id:
        raise CommitmentCompilationError("withdrawal Statement issuer mismatch")
    if withdrawal_statement.verification_status != "human_confirmed":
        raise CommitmentCompilationError("withdrawal requires a human-confirmed Statement")
    if date.fromisoformat(withdrawal_statement.statement_date) < date.fromisoformat(
        commitment.start_date
    ):
        raise CommitmentCompilationError("withdrawal Statement predates Commitment")
    return replace(
        commitment,
        status="withdrawn",
        withdrawal_statement_id=withdrawal_statement.statement_id,
        superseded_by_commitment_id=None,
        missing_evidence=(),
    )


def compile_supersession(
    commitment: ManagementCommitment,
    successor: ManagementCommitment,
) -> ManagementCommitment:
    if successor.issuer_id != commitment.issuer_id:
        raise CommitmentCompilationError("successor issuer mismatch")
    if successor.commitment_id == commitment.commitment_id:
        raise CommitmentCompilationError("successor must be a different Commitment")
    if successor.metric_concept != commitment.metric_concept:
        raise CommitmentCompilationError("successor changes metric concept")
    if date.fromisoformat(successor.start_date) <= date.fromisoformat(commitment.start_date):
        raise CommitmentCompilationError("successor requires a later start date")
    if successor.superseded_by_commitment_id == commitment.commitment_id:
        raise CommitmentCompilationError("supersession would create a cycle")
    return replace(
        commitment,
        status="superseded",
        withdrawal_statement_id=None,
        superseded_by_commitment_id=successor.commitment_id,
        missing_evidence=(),
    )


def _validate_review_chain(
    statement: ManagementStatement,
    candidate: ManagementStatementCandidate,
    decision: ManagementStatementReviewDecision,
) -> None:
    if decision.decision != "confirmed":
        raise CommitmentCompilationError("Statement candidate lacks confirmed review decision")
    if decision.candidate_id != candidate.candidate_id:
        raise CommitmentCompilationError("review decision references another candidate")
    if decision.candidate_fingerprint != candidate.fingerprint:
        raise CommitmentCompilationError("review decision candidate fingerprint mismatch")
    if decision.output_statement_id != statement.statement_id:
        raise CommitmentCompilationError("review decision references another Statement")
    if statement.issuer_id != candidate.issuer_id or decision.issuer_id != statement.issuer_id:
        raise CommitmentCompilationError("Statement review chain issuer mismatch")
    bound_fact_ids = {item["fact_id"] for item in statement.metric_bindings}
    if bound_fact_ids != set(decision.output_fact_ids):
        raise CommitmentCompilationError("review decision target Facts mismatch")


def _target_evidence(
    *,
    statement: ManagementStatement,
    candidate: ManagementStatementCandidate,
    metric_concept: str,
) -> tuple[list[dict[str, str]], list[Any]]:
    target_bindings = [
        to_json_value(item)
        for item in statement.metric_bindings
        if item["metric_concept"] == metric_concept
    ]
    if not target_bindings:
        raise CommitmentCompilationError("requested metric is absent from confirmed Statement")
    mention_map = {
        (item["component_id"], item["metric_concept"], item["role"]): item
        for item in candidate.metric_mentions
    }
    mentions = []
    for binding in target_bindings:
        key = (binding["component_id"], metric_concept, binding["role"])
        mention = mention_map.get(key)
        if mention is None:
            raise CommitmentCompilationError("confirmed target metric lacks candidate evidence")
        mentions.append(mention)
        binding.pop("metric_concept", None)
    return target_bindings, mentions


def _resolve_due_date(
    *,
    statement: ManagementStatement,
    request: CommitmentRequest,
    fiscal_periods: Sequence[FiscalPeriod],
) -> str:
    if (request.due_date is None) == (request.relative_due is None):
        raise CommitmentCompilationError(
            "exactly one of due_date and relative_due must be provided"
        )
    if request.due_date is not None:
        date.fromisoformat(request.due_date)
        return request.due_date
    assert request.relative_due is not None
    return resolve_relative_fiscal_due_date(
        issuer_id=statement.issuer_id,
        statement_date=statement.statement_date,
        relative_due=request.relative_due,
        fiscal_periods=fiscal_periods,
    )
