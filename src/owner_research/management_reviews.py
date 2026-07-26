from __future__ import annotations

from collections.abc import Sequence
from datetime import date

from .contracts import (
    CalculationResult,
    Claim,
    ManagementCommitment,
    ManagementOutcome,
    ManagementReview,
    ManagementStatement,
)
from .fingerprints import canonical_sha256


class ManagementReviewError(ValueError):
    pass


def build_management_review(
    *,
    issuer_id: str,
    review_period: dict[str, str],
    as_of_date: str,
    statements: Sequence[ManagementStatement],
    commitments: Sequence[ManagementCommitment],
    outcomes: Sequence[ManagementOutcome],
    claims: Sequence[Claim],
    calculations: Sequence[CalculationResult],
    review_claim_ids: Sequence[str] = (),
    explicit_missing_evidence: Sequence[str] = (),
) -> ManagementReview:
    review_start = date.fromisoformat(review_period["start"])
    review_end = date.fromisoformat(review_period["end"])
    cutoff = date.fromisoformat(as_of_date)
    if review_start > review_end or review_end > cutoff:
        raise ManagementReviewError("invalid ManagementReview period or cutoff")

    issuer_statements = {
        item.statement_id: item
        for item in statements
        if item.issuer_id == issuer_id and date.fromisoformat(item.statement_date) <= cutoff
    }
    selected_commitments = [
        item
        for item in commitments
        if item.issuer_id == issuer_id
        and date.fromisoformat(item.start_date) <= cutoff
        and _commitment_in_review(
            item,
            review_start=review_start,
            review_end=review_end,
            statements=issuer_statements,
        )
    ]
    selected_commitments.sort(key=lambda item: (item.start_date, item.commitment_id))
    commitment_ids = {item.commitment_id for item in selected_commitments}

    statement_ids = {
        item.statement_id
        for item in issuer_statements.values()
        if review_start <= date.fromisoformat(item.statement_date) <= review_end
    }
    for commitment in selected_commitments:
        statement_ids.add(commitment.statement_id)
        if commitment.withdrawal_statement_id is not None:
            statement_ids.add(commitment.withdrawal_statement_id)
    selected_statements = [
        issuer_statements[statement_id]
        for statement_id in sorted(statement_ids)
        if statement_id in issuer_statements
    ]

    eligible_outcomes = [
        item
        for item in outcomes
        if item.issuer_id == issuer_id
        and item.commitment_id in commitment_ids
        and date.fromisoformat(item.assessed_at) <= cutoff
        and date.fromisoformat(item.evaluation_period["end"]) >= review_start
    ]
    latest_outcomes: dict[str, ManagementOutcome] = {}
    for outcome in eligible_outcomes:
        current = latest_outcomes.get(outcome.commitment_id)
        if current is None or (outcome.assessed_at, outcome.outcome_id) > (
            current.assessed_at,
            current.outcome_id,
        ):
            latest_outcomes[outcome.commitment_id] = outcome
    selected_outcomes = sorted(
        latest_outcomes.values(), key=lambda item: (item.assessed_at, item.outcome_id)
    )

    due = [
        item
        for item in selected_commitments
        if item.status == "open" and date.fromisoformat(item.due_date) <= cutoff
    ]
    not_due = [
        item
        for item in selected_commitments
        if item.status == "open" and date.fromisoformat(item.due_date) > cutoff
    ]
    coverage = {
        "statement_count": len(selected_statements),
        "confirmed_count": sum(
            item.verification_status == "human_confirmed" for item in selected_statements
        ),
        "open_count": sum(item.status == "open" for item in selected_commitments),
        "not_due_count": len(not_due),
        "due_count": len(due),
        "evaluated_due_count": len(
            {
                item.commitment_id
                for item in selected_outcomes
                if item.status in {"met", "partially_met", "missed", "unverifiable"}
            }.intersection(item.commitment_id for item in due)
        ),
        "pending_count": sum(item.status == "pending" for item in selected_outcomes),
        "met_count": sum(item.status == "met" for item in selected_outcomes),
        "partially_met_count": sum(
            item.status == "partially_met" for item in selected_outcomes
        ),
        "missed_count": sum(item.status == "missed" for item in selected_outcomes),
        "unverifiable_count": sum(
            item.status == "unverifiable" for item in selected_outcomes
        ),
        "blocked_count": sum(item.status == "blocked" for item in selected_outcomes),
        "withdrawn_count": sum(
            item.status == "withdrawn" for item in selected_commitments
        ),
        "superseded_count": sum(
            item.status == "superseded" for item in selected_commitments
        ),
    }

    missing = set(explicit_missing_evidence)
    blocking: set[str] = set()
    if not selected_statements:
        blocking.add("management_statement_coverage_missing")
    elif coverage["confirmed_count"] != coverage["statement_count"]:
        missing.add("unconfirmed_management_statements")
    if selected_statements and not selected_commitments:
        missing.add("no_measurable_commitments")

    outcome_by_commitment = {item.commitment_id: item for item in selected_outcomes}
    for commitment in due:
        outcome = outcome_by_commitment.get(commitment.commitment_id)
        if outcome is None or outcome.status == "pending":
            blocking.add("due_commitment_without_final_outcome")
    for commitment in selected_commitments:
        if commitment.status in {"withdrawn", "superseded"}:
            outcome = outcome_by_commitment.get(commitment.commitment_id)
            if outcome is None or outcome.status != commitment.status:
                blocking.add("lifecycle_outcome_missing")
    for outcome in selected_outcomes:
        if outcome.status == "blocked":
            blocking.update(outcome.missing_evidence or ("blocked_outcome",))
        elif outcome.status == "unverifiable":
            missing.update(outcome.missing_evidence or ("unverifiable_outcome",))
    for commitment in not_due:
        if commitment.commitment_id not in outcome_by_commitment:
            missing.add("active_commitment_without_current_outcome")

    claim_map = {item.claim_id: item for item in claims if item.issuer_id == issuer_id}
    selected_claim_ids = set(review_claim_ids)
    for commitment in selected_commitments:
        selected_claim_ids.update(commitment.condition_claim_ids)
    for outcome in selected_outcomes:
        selected_claim_ids.update(outcome.claim_ids)
    valid_claim_ids: list[str] = []
    for claim_id in sorted(selected_claim_ids):
        claim = claim_map.get(claim_id)
        if claim is None or date.fromisoformat(claim.as_of_date) > cutoff:
            blocking.add("review_claim_unresolved")
        else:
            valid_claim_ids.append(claim_id)
    if not valid_claim_ids:
        blocking.add("review_claim_missing")

    calculation_map = {
        item.calculation_id: item for item in calculations if item.issuer_id == issuer_id
    }
    selected_calculation_ids = {
        calculation_id
        for commitment in selected_commitments
        for calculation_id in commitment.definition_reconciliation_calculation_ids
    }
    selected_calculation_ids.update(
        binding["calculation_result_id"]
        for outcome in selected_outcomes
        for binding in outcome.result_bindings
        if binding["calculation_result_id"] is not None
    )
    if not selected_calculation_ids.issubset(calculation_map):
        blocking.add("review_calculation_unresolved")
    valid_calculation_ids = tuple(
        sorted(selected_calculation_ids.intersection(calculation_map))
    )

    if blocking:
        status = "blocked"
        missing.update(blocking)
    elif missing:
        status = "partial"
    else:
        status = "complete"
    digest = canonical_sha256(
        {
            "issuer_id": issuer_id,
            "review_period": review_period,
            "as_of_date": as_of_date,
            "statement_ids": sorted(statement_ids),
            "commitment_ids": sorted(commitment_ids),
            "outcome_ids": sorted(item.outcome_id for item in selected_outcomes),
        }
    )[:20]
    return ManagementReview(
        schema_version="2.0.0",
        review_id=f"management-review:{issuer_id}:{digest}",
        issuer_id=issuer_id,
        review_period=review_period,
        as_of_date=as_of_date,
        status=status,
        statement_ids=tuple(item.statement_id for item in selected_statements),
        commitment_ids=tuple(item.commitment_id for item in selected_commitments),
        outcome_ids=tuple(item.outcome_id for item in selected_outcomes),
        coverage=coverage,
        claim_ids=tuple(valid_claim_ids),
        calculation_result_ids=valid_calculation_ids,
        missing_evidence=tuple(sorted(missing)),
    )


def _commitment_in_review(
    commitment: ManagementCommitment,
    *,
    review_start: date,
    review_end: date,
    statements: dict[str, ManagementStatement],
) -> bool:
    due_date = date.fromisoformat(commitment.due_date)
    start_date = date.fromisoformat(commitment.start_date)
    if review_start <= due_date <= review_end:
        return True
    if commitment.status == "open" and start_date <= review_end and due_date >= review_start:
        return True
    if commitment.status in {"withdrawn", "superseded"}:
        transition_id = commitment.withdrawal_statement_id or commitment.statement_id
        statement = statements.get(transition_id)
        return statement is not None and review_start <= date.fromisoformat(
            statement.statement_date
        ) <= review_end
    return False
