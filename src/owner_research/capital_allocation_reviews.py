from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

from .capital_allocation_ledger import source_family
from .capital_allocation_policies import (
    EVENT_TYPES,
    OFFICIAL_AUTHORITY_LEVELS,
    REVIEW_CLAIM_ROLES,
    REVIEW_POLICY_ID,
    REVIEW_POLICY_VERSION,
    SOURCE_FAMILIES,
)
from .contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    CalculationResult,
    CapitalAllocationEvent,
    CapitalAllocationOutcome,
    CapitalAllocationReview,
    Claim,
    SourceDocument,
    SourceSearchReceipt,
)
from .fingerprints import canonical_sha256
from .source_search_receipts import source_search_request_fingerprint


class CapitalAllocationReviewError(ValueError):
    pass


ACTIVITY_SOURCE_ROLES = frozenset(
    {
        "terms",
        "execution_update",
        "completion",
        "cancellation",
        "supersession",
        "financing_terms",
        "purchase_accounting",
        "periodic_recap",
    }
)


@dataclass(frozen=True, slots=True)
class CapitalReviewClaimEvidence:
    claim_id: str
    review_decision_id: str
    role_id: str


def _claim_bindings(
    *,
    issuer_id: str,
    as_of_date: date,
    evidence: Sequence[CapitalReviewClaimEvidence],
    claims: dict[str, Claim],
    candidates: dict[str, AnalyticalClaimCandidate],
    decisions: dict[str, AnalyticalClaimReviewDecision],
) -> tuple[tuple[dict[str, str], ...], dict[str, AnalyticalClaimCandidate]]:
    bindings: list[dict[str, str]] = []
    candidate_by_claim: dict[str, AnalyticalClaimCandidate] = {}
    for item in evidence:
        if item.role_id not in REVIEW_CLAIM_ROLES:
            raise CapitalAllocationReviewError("Review uses an unregistered Claim role")
        try:
            claim = claims[item.claim_id]
            decision = decisions[item.review_decision_id]
            candidate = candidates[decision.candidate_id]
        except KeyError as exc:
            raise CapitalAllocationReviewError("Review Claim chain is incomplete") from exc
        if (
            claim.issuer_id != issuer_id
            or candidate.issuer_id != issuer_id
            or decision.issuer_id != issuer_id
            or decision.decision != "confirmed"
            or decision.output_claim_id != claim.claim_id
            or decision.candidate_fingerprint != candidate.fingerprint
            or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
            or candidate.validation_status != "ready"
        ):
            raise CapitalAllocationReviewError("Review Claim lacks valid human confirmation")
        if date.fromisoformat(claim.as_of_date) > as_of_date:
            raise CapitalAllocationReviewError("Review Claim follows the cutoff")
        binding_id = f"capital-review-binding:{canonical_sha256([claim.claim_id, item.role_id])}"
        bindings.append(
            {
                "binding_id": binding_id,
                "claim_id": claim.claim_id,
                "review_decision_id": decision.decision_id,
                "role_id": item.role_id,
            }
        )
        candidate_by_claim[claim.claim_id] = candidate
    if len(candidate_by_claim) != len(evidence):
        raise CapitalAllocationReviewError("Review repeats a Claim")
    return tuple(sorted(bindings, key=lambda row: row["binding_id"])), candidate_by_claim


def _overlaps(
    start: date,
    end: date,
    period_start: str | None,
    period_end: str | None,
    *,
    open_end: date,
) -> bool:
    if period_start is None:
        return False
    left = date.fromisoformat(period_start)
    right = date.fromisoformat(period_end) if period_end is not None else open_end
    return left <= end and right >= start


def _event_is_active(
    event: CapitalAllocationEvent,
    *,
    start: date,
    end: date,
    cutoff: date,
    documents: dict[str, SourceDocument],
) -> bool:
    announced = date.fromisoformat(event.announcement_date)
    if start <= announced <= end:
        return True
    if _overlaps(
        start,
        end,
        event.execution_period["start"],
        event.execution_period["end"],
        open_end=cutoff,
    ):
        return True
    for binding in event.source_bindings:
        if binding["role_id"] not in ACTIVITY_SOURCE_ROLES:
            continue
        try:
            published = date.fromisoformat(documents[binding["source_document_id"]].published_date)
        except KeyError as exc:
            raise CapitalAllocationReviewError("Event activity source is unavailable") from exc
        if start <= published <= end:
            return True
    return False


def _outcome_is_active(
    outcome: CapitalAllocationOutcome,
    *,
    start: date,
    end: date,
) -> bool:
    return _overlaps(
        start,
        end,
        outcome.observation_period["start"],
        outcome.observation_period["end"],
        open_end=end,
    ) or start <= date.fromisoformat(outcome.assessed_at) <= end


def build_capital_allocation_review(
    *,
    issuer_id: str,
    review_period: dict[str, str],
    as_of_date: str,
    source_documents: Sequence[SourceDocument],
    source_search_receipts: Sequence[SourceSearchReceipt],
    events: Sequence[CapitalAllocationEvent],
    outcomes: Sequence[CapitalAllocationOutcome],
    calculations: Sequence[CalculationResult],
    claims: Sequence[Claim] = (),
    analytical_candidates: Sequence[AnalyticalClaimCandidate] = (),
    analytical_decisions: Sequence[AnalyticalClaimReviewDecision] = (),
    claim_evidence: Sequence[CapitalReviewClaimEvidence] = (),
) -> CapitalAllocationReview:
    cutoff = date.fromisoformat(as_of_date)
    start = date.fromisoformat(review_period["start"])
    end = date.fromisoformat(review_period["end"])
    if start > end or end > cutoff:
        raise CapitalAllocationReviewError("invalid capital-allocation Review period")
    documents = {item.document_id: item for item in source_documents}
    if len(documents) != len(source_documents):
        raise CapitalAllocationReviewError("Review repeats a SourceDocument")
    for document in source_documents:
        if document.issuer_id != issuer_id:
            raise CapitalAllocationReviewError("Review source issuer mismatch")
    claim_bindings, _ = _claim_bindings(
        issuer_id=issuer_id,
        as_of_date=cutoff,
        evidence=claim_evidence,
        claims={item.claim_id: item for item in claims},
        candidates={item.candidate_id: item for item in analytical_candidates},
        decisions={item.decision_id: item for item in analytical_decisions},
    )

    receipts = {item.receipt_id: item for item in source_search_receipts}
    if len(receipts) != len(source_search_receipts):
        raise CapitalAllocationReviewError("Review repeats a SourceSearchReceipt")
    cik_values: set[str] = set()
    for receipt in source_search_receipts:
        if receipt.issuer_id != issuer_id:
            raise CapitalAllocationReviewError("Review search receipt issuer mismatch")
        if dict(receipt.period) != review_period or receipt.cutoff_date != as_of_date:
            raise CapitalAllocationReviewError("Review search receipt scope mismatch")
        if set(receipt.query_scope["event_types"]) != set(EVENT_TYPES):
            raise CapitalAllocationReviewError("Review search receipt event coverage is incomplete")
        cik_values.add(receipt.query_scope["cik"])
        expected_request = source_search_request_fingerprint(
            issuer_id=receipt.issuer_id,
            source_family_id=receipt.source_family,
            query_scope=receipt.query_scope,
            period=receipt.period,
            cutoff_date=receipt.cutoff_date,
            searched_endpoints=receipt.searched_endpoints,
            tool_version=receipt.tool_version,
        )
        if receipt.request_fingerprint != expected_request:
            raise CapitalAllocationReviewError("Review search receipt fingerprint mismatch")
        for document_id in receipt.result_document_ids:
            try:
                document = documents[document_id]
            except KeyError as exc:
                raise CapitalAllocationReviewError(
                    "Review search result document is unavailable"
                ) from exc
            if (
                document.authority_level not in OFFICIAL_AUTHORITY_LEVELS
                or date.fromisoformat(document.published_date) > cutoff
                or source_family(document) != receipt.source_family
            ):
                raise CapitalAllocationReviewError("Review search result document is invalid")
    if len(cik_values) > 1:
        raise CapitalAllocationReviewError("Review search receipts mix CIKs")

    receipts_by_family = {
        family: tuple(item for item in source_search_receipts if item.source_family == family)
        for family in SOURCE_FAMILIES
    }
    source_rows: list[dict[str, object]] = []
    missing: set[str] = set()
    for family in sorted(SOURCE_FAMILIES):
        family_receipts = receipts_by_family[family]
        family_missing: set[str] = set()
        if not family_receipts:
            family_missing.add(f"search_receipt_missing:{family}")
            status = "blocked"
        elif any(item.status == "blocked" for item in family_receipts):
            family_missing.update(
                issue
                for item in family_receipts
                if item.status == "blocked"
                for issue in item.issues
            )
            status = "blocked"
        else:
            result_ids = {
                document_id for item in family_receipts for document_id in item.result_document_ids
            }
            status = "reviewed_present" if result_ids else "searched_not_found"
        result_ids = {
            document_id for item in family_receipts for document_id in item.result_document_ids
        }
        missing.update(family_missing)
        source_rows.append(
            {
                "source_family": family,
                "status": status,
                "source_document_ids": sorted(result_ids),
                "search_receipt_ids": sorted(item.receipt_id for item in family_receipts),
                "claim_binding_ids": [],
                "missing_evidence": sorted(family_missing),
            }
        )

    eligible_events: list[CapitalAllocationEvent] = []
    event_by_id: dict[str, CapitalAllocationEvent] = {}
    for event in events:
        if event.issuer_id != issuer_id:
            raise CapitalAllocationReviewError("Review Event issuer mismatch")
        if date.fromisoformat(event.announcement_date) > cutoff:
            continue
        for binding in event.source_bindings:
            try:
                document = documents[binding["source_document_id"]]
            except KeyError as exc:
                raise CapitalAllocationReviewError("Review Event source is unavailable") from exc
            if date.fromisoformat(document.published_date) > cutoff:
                raise CapitalAllocationReviewError("Review Event uses future evidence")
        eligible_events.append(event)
        event_by_id[event.event_id] = event

    eligible_outcomes: list[CapitalAllocationOutcome] = []
    for outcome in outcomes:
        if outcome.issuer_id != issuer_id:
            raise CapitalAllocationReviewError("Review Outcome issuer mismatch")
        if outcome.event_id not in event_by_id:
            raise CapitalAllocationReviewError("Review Outcome Event is unavailable")
        if date.fromisoformat(outcome.assessed_at) <= cutoff:
            eligible_outcomes.append(outcome)

    active_keys = {
        event.economic_event_key
        for event in eligible_events
        if _event_is_active(event, start=start, end=end, cutoff=cutoff, documents=documents)
    }
    active_keys.update(
        event_by_id[outcome.event_id].economic_event_key
        for outcome in eligible_outcomes
        if _outcome_is_active(outcome, start=start, end=end)
    )
    latest_by_key: dict[str, CapitalAllocationEvent] = {}
    for event in eligible_events:
        if event.economic_event_key not in active_keys:
            continue
        current = latest_by_key.get(event.economic_event_key)
        if current is None or event.event_version > current.event_version:
            latest_by_key[event.economic_event_key] = event
    selected_events = tuple(sorted(latest_by_key.values(), key=lambda item: item.event_id))
    selected_event_ids = {item.event_id for item in selected_events}

    latest_outcome_by_key: dict[str, CapitalAllocationOutcome] = {}
    for outcome in eligible_outcomes:
        key = event_by_id[outcome.event_id].economic_event_key
        if key not in active_keys:
            continue
        current = latest_outcome_by_key.get(key)
        if current is None or date.fromisoformat(outcome.assessed_at) > date.fromisoformat(
            current.assessed_at
        ):
            latest_outcome_by_key[key] = outcome
    selected_outcomes = tuple(
        sorted(latest_outcome_by_key.values(), key=lambda item: item.outcome_id)
    )
    missing_outcome_keys = active_keys - set(latest_outcome_by_key)
    missing.update(f"outcome_missing:{item}" for item in missing_outcome_keys)

    all_searches_resolved = all(item["status"] != "blocked" for item in source_rows)
    event_rows: list[dict[str, object]] = []
    for event_type in sorted(EVENT_TYPES):
        type_events = tuple(item for item in selected_events if item.event_type == event_type)
        receipt_ids = tuple(sorted(receipts))
        source_ids = {
            document_id
            for receipt in source_search_receipts
            for document_id in receipt.result_document_ids
        }
        source_ids.update(
            binding["source_document_id"]
            for event in type_events
            for binding in event.source_bindings
        )
        row_missing: set[str] = set()
        if type_events:
            status = "reviewed"
        elif all_searches_resolved:
            status = "not_found"
        else:
            status = "blocked"
            row_missing.add(f"event_type_search_incomplete:{event_type}")
        missing.update(row_missing)
        event_rows.append(
            {
                "event_type": event_type,
                "status": status,
                "event_ids": sorted(event.event_id for event in type_events),
                "source_document_ids": sorted(source_ids),
                "search_receipt_ids": list(receipt_ids),
                "claim_binding_ids": [],
                "missing_evidence": sorted(row_missing),
            }
        )

    outcome_statuses = {item.status for item in selected_outcomes}
    blocked = (
        not all_searches_resolved
        or any(item["status"] == "blocked" for item in event_rows)
        or "blocked" in outcome_statuses
    )
    incomplete = bool(missing_outcome_keys) or bool(
        outcome_statuses.intersection({"partial", "unverifiable"})
    )
    status = "blocked" if blocked else "partial" if incomplete else "complete"
    if status == "blocked" and not missing:
        missing.add("capital_allocation_review_blocked")
    calculation_ids = {
        binding["calculation_result_id"]
        for outcome in selected_outcomes
        for binding in outcome.result_bindings
        if binding["calculation_result_id"] is not None
    }
    available_calculations = {item.calculation_id for item in calculations}
    if not calculation_ids.issubset(available_calculations):
        raise CapitalAllocationReviewError("Review Outcome calculation is unavailable")
    coverage = {
        "logical_event_count": len(selected_events),
        "event_version_count": sum(
            item.economic_event_key in active_keys for item in eligible_events
        ),
        "outcome_count": len(selected_outcomes),
        "not_due_count": sum(item.status == "not_due" for item in selected_outcomes),
        "observed_count": sum(item.status == "observed" for item in selected_outcomes),
        "partial_count": sum(item.status == "partial" for item in selected_outcomes),
        "unverifiable_count": sum(item.status == "unverifiable" for item in selected_outcomes),
        "blocked_count": sum(item.status == "blocked" for item in selected_outcomes),
        "cancelled_count": sum(item.status == "cancelled" for item in selected_outcomes),
        "superseded_count": sum(item.status == "superseded" for item in selected_outcomes),
        "reviewed_type_count": sum(item["status"] == "reviewed" for item in event_rows),
        "not_found_type_count": sum(item["status"] == "not_found" for item in event_rows),
        "not_applicable_type_count": 0,
        "blocked_type_count": sum(item["status"] == "blocked" for item in event_rows),
        "reviewed_present_source_count": sum(
            item["status"] == "reviewed_present" for item in source_rows
        ),
        "searched_not_found_source_count": sum(
            item["status"] == "searched_not_found" for item in source_rows
        ),
        "not_applicable_source_count": 0,
        "blocked_source_count": sum(item["status"] == "blocked" for item in source_rows),
    }
    review_identity = {
        "period": review_period,
        "as_of_date": as_of_date,
        "policy_version": REVIEW_POLICY_VERSION,
    }
    review_id = f"capital-review:{issuer_id}:{canonical_sha256(review_identity)[:20]}"
    return CapitalAllocationReview(
        schema_version="3.0.0",
        review_id=review_id,
        issuer_id=issuer_id,
        review_policy_id=REVIEW_POLICY_ID,
        review_policy_version=REVIEW_POLICY_VERSION,
        review_period=review_period,
        as_of_date=as_of_date,
        status=status,
        source_coverage=tuple(source_rows),
        event_type_coverage=tuple(event_rows),
        event_ids=tuple(sorted(selected_event_ids)),
        outcome_ids=tuple(item.outcome_id for item in selected_outcomes),
        coverage=coverage,
        claim_bindings=claim_bindings,
        calculation_result_ids=tuple(sorted(calculation_ids)),
        missing_evidence=tuple(sorted(missing)),
    )
