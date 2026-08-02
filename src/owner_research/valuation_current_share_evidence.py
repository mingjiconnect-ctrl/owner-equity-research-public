"""Validation-only current-common-share evidence authority.

This module derives a closed witness from an already validated ContractGraph.  It deliberately
does not select a production share basis, write an artifact, or expose a package-root API.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from .capital_allocation_ledger import CapitalAllocationLedgerError, source_family
from .capital_allocation_policies import OFFICIAL_AUTHORITY_LEVELS, SOURCE_FAMILIES
from .contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    Claim,
    Fact,
    SourceDocument,
    SourceSearchReceipt,
)
from .fingerprints import canonical_sha256, to_json_value
from .source_search_receipts import source_search_request_fingerprint

CURRENT_SHARE_CLOSURE_POLICY_ID = "current-share-evidence-closure"
CURRENT_SHARE_CLOSURE_POLICY_VERSION = "1.0.0"

COMPLETED_SHARE_EVENT_SIGNS = {
    "common_shares_issued_completed": Decimal("1"),
    "common_shares_repurchased_completed": Decimal("-1"),
    "common_shares_retired_or_cancelled_completed": Decimal("-1"),
    "option_shares_exercised_completed": Decimal("1"),
    "rsu_shares_settled_completed": Decimal("1"),
    "convertible_shares_converted_completed": Decimal("1"),
    "warrant_shares_exercised_completed": Decimal("1"),
    "acquisition_consideration_shares_issued_completed": Decimal("1"),
}

EVENT_CONCEPT_TO_COVERAGE_CATEGORY = {
    "common_shares_issued_completed": "issuance",
    "common_shares_repurchased_completed": "repurchase",
    "common_shares_retired_or_cancelled_completed": "retirement_or_cancellation",
    "option_shares_exercised_completed": "option_exercise",
    "rsu_shares_settled_completed": "rsu_settlement",
    "convertible_shares_converted_completed": "convertible_conversion",
    "warrant_shares_exercised_completed": "warrant_exercise",
    "acquisition_consideration_shares_issued_completed": "acquisition_consideration",
}

CORPORATE_ACTION_COVERAGE_CATEGORIES = (
    "issuance",
    "repurchase",
    "retirement_or_cancellation",
    "option_exercise",
    "rsu_settlement",
    "convertible_conversion",
    "warrant_exercise",
    "acquisition_consideration",
    "employee_plan_issuance",
    "stock_dividend",
    "split_or_reverse_split",
    "treasury_stock_movement",
)

SHARE_COVERAGE_SEARCH_EVENT_TYPES = frozenset(
    {
        "acquisition",
        "buyback",
        "debt_issuance",
        "dividend",
        "equity_issuance",
        "stock_based_compensation",
    }
)

CLAIM_SENSITIVE_EVENT_CONCEPTS = {
    "option_shares_exercised_completed": "option_claim_remaining_outstanding",
    "convertible_shares_converted_completed": "convertible_claim_remaining_outstanding",
    "warrant_shares_exercised_completed": "warrant_claim_remaining_outstanding",
}

CLAIM_ROOT_CONCEPTS = frozenset(
    {
        "option_or_dilution_claim",
        "convertible_claim",
        "warrant_claim",
    }
)


class CurrentShareEvidenceError(ValueError):
    """Raised when the validation-only share evidence authority cannot close."""


def _sha(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise CurrentShareEvidenceError(f"{label} is not a lowercase SHA-256")


def _decimal(value: object, label: str, *, positive: bool = False) -> int:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise CurrentShareEvidenceError(f"{label} is not an exact decimal") from exc
    if not number.is_finite() or (positive and number <= 0) or number != number.to_integral():
        raise CurrentShareEvidenceError(f"{label} is not an eligible integer magnitude")
    return int(number)


@dataclass(frozen=True, slots=True)
class CorporateActionCoverageEntry:
    category: str
    status: str
    event_fact_ids: tuple[str, ...]
    zero_fact_id: str | None
    not_applicable_claim_id: str | None
    review_decision_id: str | None
    source_search_receipt_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.category not in CORPORATE_ACTION_COVERAGE_CATEGORIES:
            raise CurrentShareEvidenceError("share-activity coverage category is not registered")
        if self.status not in {
            "observed",
            "official_zero_or_no_activity",
            "not_applicable_with_reviewed_proof",
        }:
            raise CurrentShareEvidenceError("share-activity coverage status is not closed")
        event_ids = tuple(sorted(self.event_fact_ids))
        receipt_ids = tuple(sorted(self.source_search_receipt_ids))
        if len(event_ids) != len(set(event_ids)) or len(receipt_ids) != len(set(receipt_ids)):
            raise CurrentShareEvidenceError("share-activity coverage evidence is duplicated")
        if len(receipt_ids) != len(SOURCE_FAMILIES):
            raise CurrentShareEvidenceError("share-activity coverage lacks every source family")
        if self.status == "observed":
            if not event_ids or any(
                value is not None
                for value in (
                    self.zero_fact_id,
                    self.not_applicable_claim_id,
                    self.review_decision_id,
                )
            ):
                raise CurrentShareEvidenceError("observed share activity has conflicting proof")
        elif self.status == "official_zero_or_no_activity":
            if (
                self.zero_fact_id is None
                or event_ids
                or any(
                    value is not None
                    for value in (self.not_applicable_claim_id, self.review_decision_id)
                )
            ):
                raise CurrentShareEvidenceError("official zero share activity is incomplete")
        elif (
            self.not_applicable_claim_id is None
            or self.review_decision_id is None
            or event_ids
            or self.zero_fact_id is not None
        ):
            raise CurrentShareEvidenceError("not-applicable share activity lacks reviewed proof")
        object.__setattr__(self, "event_fact_ids", event_ids)
        object.__setattr__(self, "source_search_receipt_ids", receipt_ids)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class CorporateActionCoverageLedger:
    issuer_id: str
    security_id: str
    period_start: str
    period_end: str
    entries: tuple[CorporateActionCoverageEntry, ...]
    receipt_ids: tuple[str, ...]
    ledger_sha256: str

    def __post_init__(self) -> None:
        entries = tuple(sorted(self.entries, key=lambda item: item.category))
        receipts = tuple(sorted(self.receipt_ids))
        if {item.category for item in entries} != set(CORPORATE_ACTION_COVERAGE_CATEGORIES):
            raise CurrentShareEvidenceError("share-activity coverage is incomplete")
        if len(receipts) != len(set(receipts)):
            raise CurrentShareEvidenceError("share-activity receipt closure is duplicated")
        payload = {
            "issuer_id": self.issuer_id,
            "security_id": self.security_id,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "entries": tuple(item.to_dict() for item in entries),
            "receipt_ids": receipts,
        }
        if self.ledger_sha256 != canonical_sha256(payload):
            raise CurrentShareEvidenceError("share-activity coverage SHA does not replay")
        object.__setattr__(self, "entries", entries)
        object.__setattr__(self, "receipt_ids", receipts)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class CompletedClaimTransition:
    event_fact_id: str
    event_concept: str
    affected_claim_root_fact_id: str
    remaining_claim_fact_id: str
    remaining_claim_value: str
    claim_id: str
    candidate_id: str
    review_decision_id: str
    disposition: str

    def __post_init__(self) -> None:
        if self.event_concept not in CLAIM_SENSITIVE_EVENT_CONCEPTS:
            raise CurrentShareEvidenceError("completed claim transition event is not registered")
        if self.disposition not in {"extinguished", "remaining_claim_rebound"}:
            raise CurrentShareEvidenceError("completed claim transition disposition is invalid")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class CompletedClaimTransitionReconciliation:
    issuer_id: str
    security_id: str
    records: tuple[CompletedClaimTransition, ...]
    reconciliation_sha256: str

    def __post_init__(self) -> None:
        records = tuple(sorted(self.records, key=lambda item: item.event_fact_id))
        if len({item.event_fact_id for item in records}) != len(records):
            raise CurrentShareEvidenceError("completed claim transition is duplicated")
        payload = {
            "issuer_id": self.issuer_id,
            "security_id": self.security_id,
            "records": tuple(item.to_dict() for item in records),
        }
        if self.reconciliation_sha256 != canonical_sha256(payload):
            raise CurrentShareEvidenceError("completed claim transition SHA does not replay")
        object.__setattr__(self, "records", records)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class CurrentShareEvidenceClosure:
    closure_id: str
    issuer_id: str
    security_id: str
    quote_date: str
    evidence_kind: str
    output_share_fact_id: str
    output_share_fact_fingerprint: str
    numeric_root_fact_ids: tuple[str, ...]
    numeric_root_source_document_ids: tuple[str, ...]
    base_share_fact_id: str
    event_fact_ids: tuple[str, ...]
    coverage_receipt_ids: tuple[str, ...]
    security_binding_fingerprint: str
    temporal_closure_sha256: str
    source_closure_sha256: str
    numeric_lineage_sha256: str
    coverage_closure_sha256: str
    claim_transition_sha256: str
    object_fingerprints: tuple[tuple[str, str, str], ...]
    closure_sha256: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.output_share_fact_fingerprint, "output Fact fingerprint"),
            (self.security_binding_fingerprint, "security binding fingerprint"),
            (self.temporal_closure_sha256, "temporal closure SHA"),
            (self.source_closure_sha256, "source closure SHA"),
            (self.numeric_lineage_sha256, "numeric lineage SHA"),
            (self.coverage_closure_sha256, "coverage closure SHA"),
            (self.claim_transition_sha256, "claim transition SHA"),
            (self.closure_sha256, "current-share closure SHA"),
        ):
            _sha(value, label)
        roots = tuple(sorted(self.numeric_root_fact_ids))
        sources = tuple(sorted(self.numeric_root_source_document_ids))
        events = tuple(sorted(self.event_fact_ids))
        receipts = tuple(sorted(self.coverage_receipt_ids))
        fingerprints = tuple(sorted(self.object_fingerprints))
        if any(len(values) != len(set(values)) for values in (roots, sources, events, receipts)):
            raise CurrentShareEvidenceError("current-share closure contains duplicated evidence")
        payload = {
            "closure_id": self.closure_id,
            "issuer_id": self.issuer_id,
            "security_id": self.security_id,
            "quote_date": self.quote_date,
            "evidence_kind": self.evidence_kind,
            "output_share_fact_id": self.output_share_fact_id,
            "output_share_fact_fingerprint": self.output_share_fact_fingerprint,
            "numeric_root_fact_ids": roots,
            "numeric_root_source_document_ids": sources,
            "base_share_fact_id": self.base_share_fact_id,
            "event_fact_ids": events,
            "coverage_receipt_ids": receipts,
            "security_binding_fingerprint": self.security_binding_fingerprint,
            "temporal_closure_sha256": self.temporal_closure_sha256,
            "source_closure_sha256": self.source_closure_sha256,
            "numeric_lineage_sha256": self.numeric_lineage_sha256,
            "coverage_closure_sha256": self.coverage_closure_sha256,
            "claim_transition_sha256": self.claim_transition_sha256,
            "object_fingerprints": fingerprints,
        }
        if self.closure_sha256 != canonical_sha256(payload):
            raise CurrentShareEvidenceError("current-share evidence closure SHA does not replay")
        object.__setattr__(self, "numeric_root_fact_ids", roots)
        object.__setattr__(self, "numeric_root_source_document_ids", sources)
        object.__setattr__(self, "event_fact_ids", events)
        object.__setattr__(self, "coverage_receipt_ids", receipts)
        object.__setattr__(self, "object_fingerprints", fingerprints)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


def _formal_raw_fact(
    fact: Fact,
    *,
    expected_concept: str,
    issuer_id: str,
    cutoff: date,
    documents: dict[str, SourceDocument],
    unit: str = "shares",
    positive: bool = True,
) -> int:
    source = documents.get(fact.source_document_id)
    if (
        fact.issuer_id != issuer_id
        or fact.concept != expected_concept
        or fact.value_type != "number"
        or fact.unit != unit
        or fact.currency is not None
        or fact.confidence != "high"
        or fact.derivation is not None
        or fact.parent_fact_ids
        or source is None
        or source.issuer_id != issuer_id
        or source.authority_level not in OFFICIAL_AUTHORITY_LEVELS
        or date.fromisoformat(source.published_date) > cutoff
        or fact.period["end"] is None
        or date.fromisoformat(str(fact.period["end"])) > cutoff
    ):
        raise CurrentShareEvidenceError(
            "current-share numeric root is not raw, formal, high-confidence, and cutoff-safe"
        )
    return _decimal(fact.value, f"{expected_concept} value", positive=positive)


def _validate_output_fact(
    fact: Fact,
    *,
    issuer_id: str,
    trading_date: str,
    cutoff: date,
    documents: dict[str, SourceDocument],
) -> int:
    source = documents.get(fact.source_document_id)
    if (
        fact.issuer_id != issuer_id
        or fact.value_type != "number"
        or fact.concept != "common_shares_outstanding"
        or fact.unit != "shares"
        or fact.currency is not None
        or fact.period["start"] is not None
        or fact.period["end"] != trading_date
        or fact.confidence != "high"
    ):
        raise CurrentShareEvidenceError(
            "current-share output is not quote-date, formal, high-confidence evidence"
        )
    if (
        source is None
        or source.issuer_id != issuer_id
        or source.authority_level not in OFFICIAL_AUTHORITY_LEVELS
        or date.fromisoformat(source.published_date) > cutoff
    ):
        raise CurrentShareEvidenceError("current-share output source is not formal and cutoff-safe")
    return _decimal(fact.value, "current common shares", positive=True)


def _issued_less_treasury_roots(
    output: Fact,
    *,
    measurement_date: str,
    issuer_id: str,
    cutoff: date,
    facts: dict[str, Fact],
    documents: dict[str, SourceDocument],
) -> tuple[Fact, Fact]:
    parents = tuple(facts.get(parent_id) for parent_id in output.parent_fact_ids)
    if (
        output.derivation != "issued-less-treasury/1.0.0"
        or len(parents) != 2
        or any(parent is None for parent in parents)
        or {parent.concept for parent in parents if parent is not None}
        != {"common_shares_issued", "treasury_shares"}
    ):
        raise CurrentShareEvidenceError("issued-less-treasury lineage is not a closed grammar")
    typed = tuple(parent for parent in parents if parent is not None)
    issued = next(parent for parent in typed if parent.concept == "common_shares_issued")
    treasury = next(parent for parent in typed if parent.concept == "treasury_shares")
    for parent in typed:
        if parent.period["start"] is not None or parent.period["end"] != measurement_date:
            raise CurrentShareEvidenceError(
                "issued-less-treasury roots do not share one point date"
            )
    issued_value = _formal_raw_fact(
        issued,
        expected_concept="common_shares_issued",
        issuer_id=issuer_id,
        cutoff=cutoff,
        documents=documents,
    )
    treasury_value = _formal_raw_fact(
        treasury,
        expected_concept="treasury_shares",
        issuer_id=issuer_id,
        cutoff=cutoff,
        documents=documents,
        positive=False,
    )
    if issued_value < treasury_value or _decimal(output.value, "issued-less-treasury output") != (
        issued_value - treasury_value
    ):
        raise CurrentShareEvidenceError("issued-less-treasury arithmetic does not replay")
    return issued, treasury


def _receipt_replays(
    receipt: SourceSearchReceipt,
    *,
    issuer_id: str,
    period_start: str,
    period_end: str,
    cutoff_date: str,
    documents: dict[str, SourceDocument],
) -> bool:
    try:
        result_documents = tuple(documents[item] for item in receipt.result_document_ids)
        families = {source_family(item) for item in result_documents}
    except (KeyError, CapitalAllocationLedgerError):
        return False
    if (
        receipt.issuer_id != issuer_id
        or receipt.status != "completed"
        or receipt.issues
        or receipt.cutoff_date != cutoff_date
        or datetime.fromisoformat(receipt.completed_at.replace("Z", "+00:00")).date()
        < date.fromisoformat(period_end)
        or date.fromisoformat(receipt.period["start"]) > date.fromisoformat(period_start)
        or date.fromisoformat(receipt.period["end"]) < date.fromisoformat(period_end)
        or not SHARE_COVERAGE_SEARCH_EVENT_TYPES.issubset(set(receipt.query_scope["event_types"]))
        or receipt.request_fingerprint
        != source_search_request_fingerprint(
            issuer_id=receipt.issuer_id,
            source_family_id=receipt.source_family,
            query_scope=receipt.query_scope,
            period=receipt.period,
            cutoff_date=receipt.cutoff_date,
            searched_endpoints=receipt.searched_endpoints,
            tool_version=receipt.tool_version,
        )
        or any(
            item.issuer_id != issuer_id
            or item.authority_level not in OFFICIAL_AUTHORITY_LEVELS
            or date.fromisoformat(item.published_date) > date.fromisoformat(cutoff_date)
            for item in result_documents
        )
        or (result_documents and families != {receipt.source_family})
    ):
        return False
    return True


def _select_coverage_receipts(
    receipts: tuple[SourceSearchReceipt, ...],
    *,
    issuer_id: str,
    period_start: str,
    period_end: str,
    cutoff_date: str,
    documents: dict[str, SourceDocument],
) -> tuple[SourceSearchReceipt, ...]:
    selected: list[SourceSearchReceipt] = []
    for family in sorted(SOURCE_FAMILIES):
        eligible = tuple(
            item
            for item in receipts
            if item.source_family == family
            and _receipt_replays(
                item,
                issuer_id=issuer_id,
                period_start=period_start,
                period_end=period_end,
                cutoff_date=cutoff_date,
                documents=documents,
            )
        )
        if not eligible:
            raise CurrentShareEvidenceError(
                "roll-forward lacks complete SourceSearchReceipt coverage"
            )
        latest_time = max(item.completed_at for item in eligible)
        latest = tuple(item for item in eligible if item.completed_at == latest_time)
        if len(latest) != 1:
            raise CurrentShareEvidenceError(
                "roll-forward SourceSearchReceipt selection is ambiguous"
            )
        selected.append(latest[0])
    return tuple(selected)


def _reviewed_not_applicable(
    *,
    category: str,
    issuer_id: str,
    security_id: str,
    trading_date: str,
    cutoff: date,
    facts: dict[str, Fact],
    documents: dict[str, SourceDocument],
    claims: tuple[Claim, ...],
    candidates: tuple[AnalyticalClaimCandidate, ...],
    decisions: tuple[AnalyticalClaimReviewDecision, ...],
) -> tuple[Claim, AnalyticalClaimCandidate, AnalyticalClaimReviewDecision] | None:
    statement = f"Share activity category {category} is not applicable to security {security_id}."
    claims_by_id = {item.claim_id: item for item in claims}
    candidates_by_id = {item.candidate_id: item for item in candidates}
    matches: list[tuple[Claim, AnalyticalClaimCandidate, AnalyticalClaimReviewDecision]] = []
    for decision in decisions:
        candidate = candidates_by_id.get(decision.candidate_id)
        claim = claims_by_id.get(decision.output_claim_id or "")
        if candidate is None or claim is None:
            continue
        supporting_ids = {
            str(binding["fact_id"])
            for binding in candidate.supporting_evidence_bindings
            if binding["fact_id"] is not None
        }
        if (
            decision.issuer_id != issuer_id
            or decision.decision != "confirmed"
            or not decision.reviewer_id.startswith("human:")
            or decision.candidate_fingerprint != candidate.fingerprint
            or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
            or candidate.issuer_id != issuer_id
            or candidate.as_of_date > trading_date
            or date.fromisoformat(candidate.as_of_date) > cutoff
            or candidate.proposed_statement != statement
            or candidate.claim_role != "not_applicable"
            or candidate.validation_status != "ready"
            or candidate.business_attribute_role is not None
            or candidate.business_component_type is not None
            or candidate.scope["scope_type"] != "issuer_wide"
            or candidate.scope["segment_definition_ids"]
            or claim.issuer_id != issuer_id
            or claim.statement != statement
            or claim.as_of_date != candidate.as_of_date
            or not claim.supporting_fact_ids
            or not set(claim.supporting_fact_ids).issubset(supporting_ids)
            or not claim.counterevidence_search_note
            or not claim.falsification_condition
        ):
            continue
        try:
            for fact_id in claim.supporting_fact_ids:
                support = facts[fact_id]
                _formal_raw_fact(
                    support,
                    expected_concept=support.concept,
                    issuer_id=issuer_id,
                    cutoff=cutoff,
                    documents=documents,
                    unit=support.unit or "count",
                    positive=False,
                )
        except (KeyError, CurrentShareEvidenceError):
            continue
        matches.append((claim, candidate, decision))
    if len(matches) > 1:
        raise CurrentShareEvidenceError("share-activity not-applicable proof is ambiguous")
    return matches[0] if matches else None


def _coverage_ledger(
    *,
    issuer_id: str,
    security_id: str,
    opening_date: str,
    trading_date: str,
    cutoff_date: str,
    event_facts: tuple[Fact, ...],
    facts: dict[str, Fact],
    documents: dict[str, SourceDocument],
    receipts: tuple[SourceSearchReceipt, ...],
    claims: tuple[Claim, ...],
    candidates: tuple[AnalyticalClaimCandidate, ...],
    decisions: tuple[AnalyticalClaimReviewDecision, ...],
) -> CorporateActionCoverageLedger:
    selected_receipts = _select_coverage_receipts(
        receipts,
        issuer_id=issuer_id,
        period_start=opening_date,
        period_end=trading_date,
        cutoff_date=cutoff_date,
        documents=documents,
    )
    receipt_ids = tuple(item.receipt_id for item in selected_receipts)
    searched_document_ids = {
        document_id for receipt in selected_receipts for document_id in receipt.result_document_ids
    }
    cutoff = date.fromisoformat(cutoff_date)
    entries: list[CorporateActionCoverageEntry] = []
    for category in CORPORATE_ACTION_COVERAGE_CATEGORIES:
        observed = tuple(
            sorted(
                item.fact_id
                for item in event_facts
                if EVENT_CONCEPT_TO_COVERAGE_CATEGORY[item.concept] == category
            )
        )
        zero_concept = f"share_activity_{category}_count"
        zero_facts = tuple(
            item
            for item in facts.values()
            if item.concept == zero_concept
            and item.period["start"] == opening_date
            and item.period["end"] == trading_date
        )
        eligible_zero: tuple[Fact, ...] = ()
        if zero_facts:
            checked: list[Fact] = []
            for zero in zero_facts:
                value = _formal_raw_fact(
                    zero,
                    expected_concept=zero_concept,
                    issuer_id=issuer_id,
                    cutoff=cutoff,
                    documents=documents,
                    unit="count",
                    positive=False,
                )
                if value != 0:
                    raise CurrentShareEvidenceError("share-activity zero proof is not zero")
                checked.append(zero)
            eligible_zero = tuple(checked)
        not_applicable = _reviewed_not_applicable(
            category=category,
            issuer_id=issuer_id,
            security_id=security_id,
            trading_date=trading_date,
            cutoff=cutoff,
            facts=facts,
            documents=documents,
            claims=claims,
            candidates=candidates,
            decisions=decisions,
        )
        states = int(bool(observed)) + int(bool(eligible_zero)) + int(not_applicable is not None)
        if states != 1 or len(eligible_zero) > 1:
            raise CurrentShareEvidenceError(
                "share-activity category is missing, conflicting, or treats search silence as zero"
            )
        category_source_ids = {facts[fact_id].source_document_id for fact_id in observed}
        category_source_ids.update(item.source_document_id for item in eligible_zero)
        if not_applicable is not None:
            category_source_ids.update(
                facts[fact_id].source_document_id
                for fact_id in not_applicable[0].supporting_fact_ids
            )
        if not category_source_ids.issubset(searched_document_ids):
            raise CurrentShareEvidenceError(
                "share-activity proof is outside the completed source-search closure"
            )
        if observed:
            entry = CorporateActionCoverageEntry(
                category=category,
                status="observed",
                event_fact_ids=observed,
                zero_fact_id=None,
                not_applicable_claim_id=None,
                review_decision_id=None,
                source_search_receipt_ids=receipt_ids,
            )
        elif eligible_zero:
            entry = CorporateActionCoverageEntry(
                category=category,
                status="official_zero_or_no_activity",
                event_fact_ids=(),
                zero_fact_id=eligible_zero[0].fact_id,
                not_applicable_claim_id=None,
                review_decision_id=None,
                source_search_receipt_ids=receipt_ids,
            )
        else:
            assert not_applicable is not None
            claim, _, decision = not_applicable
            entry = CorporateActionCoverageEntry(
                category=category,
                status="not_applicable_with_reviewed_proof",
                event_fact_ids=(),
                zero_fact_id=None,
                not_applicable_claim_id=claim.claim_id,
                review_decision_id=decision.decision_id,
                source_search_receipt_ids=receipt_ids,
            )
        entries.append(entry)
    payload = {
        "issuer_id": issuer_id,
        "security_id": security_id,
        "period_start": opening_date,
        "period_end": trading_date,
        "entries": tuple(
            item.to_dict() for item in sorted(entries, key=lambda item: item.category)
        ),
        "receipt_ids": tuple(sorted(receipt_ids)),
    }
    return CorporateActionCoverageLedger(
        issuer_id=issuer_id,
        security_id=security_id,
        period_start=opening_date,
        period_end=trading_date,
        entries=tuple(entries),
        receipt_ids=receipt_ids,
        ledger_sha256=canonical_sha256(payload),
    )


def _confirmed_transition_chain(
    *,
    event: Fact,
    remaining_concept: str,
    issuer_id: str,
    security_id: str,
    trading_date: str,
    cutoff: date,
    facts: dict[str, Fact],
    documents: dict[str, SourceDocument],
    claims: tuple[Claim, ...],
    candidates: tuple[AnalyticalClaimCandidate, ...],
    decisions: tuple[AnalyticalClaimReviewDecision, ...],
) -> tuple[Fact, Fact, Claim, AnalyticalClaimCandidate, AnalyticalClaimReviewDecision]:
    claims_by_id = {item.claim_id: item for item in claims}
    candidates_by_id = {item.candidate_id: item for item in candidates}
    matches = []
    statement = f"Completed claim transition for event {event.fact_id} and security {security_id}."
    for decision in decisions:
        candidate = candidates_by_id.get(decision.candidate_id)
        claim = claims_by_id.get(decision.output_claim_id or "")
        if candidate is None or claim is None:
            continue
        supporting = tuple(facts[item] for item in claim.supporting_fact_ids if item in facts)
        affected = tuple(item for item in supporting if item.concept in CLAIM_ROOT_CONCEPTS)
        remaining = tuple(item for item in supporting if item.concept == remaining_concept)
        candidate_fact_ids = {
            str(binding["fact_id"])
            for binding in candidate.supporting_evidence_bindings
            if binding["fact_id"] is not None
        }
        if (
            decision.issuer_id != issuer_id
            or decision.decision != "confirmed"
            or not decision.reviewer_id.startswith("human:")
            or decision.candidate_fingerprint != candidate.fingerprint
            or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
            or candidate.issuer_id != issuer_id
            or candidate.as_of_date > trading_date
            or date.fromisoformat(candidate.as_of_date) > cutoff
            or candidate.proposed_statement != statement
            or candidate.claim_role != "support"
            or candidate.validation_status != "ready"
            or claim.issuer_id != issuer_id
            or claim.statement != statement
            or claim.as_of_date != candidate.as_of_date
            or date.fromisoformat(claim.as_of_date) > cutoff
            or claim.as_of_date > trading_date
            or event.fact_id not in claim.supporting_fact_ids
            or len(affected) != 1
            or len(remaining) != 1
            or not set(claim.supporting_fact_ids).issubset(candidate_fact_ids)
            or not claim.counterevidence_search_note
            or not claim.falsification_condition
        ):
            continue
        affected_fact, remaining_fact = affected[0], remaining[0]
        affected_value = _formal_raw_fact(
            affected_fact,
            expected_concept=affected_fact.concept,
            issuer_id=issuer_id,
            cutoff=cutoff,
            documents=documents,
            unit=affected_fact.unit or "shares",
            positive=True,
        )
        remaining_value = _formal_raw_fact(
            remaining_fact,
            expected_concept=remaining_concept,
            issuer_id=issuer_id,
            cutoff=cutoff,
            documents=documents,
            unit=remaining_fact.unit or "shares",
            positive=False,
        )
        if (
            remaining_fact.period["start"] is not None
            or remaining_fact.period["end"] != trading_date
            or event.unit != affected_fact.unit
            or remaining_fact.unit != affected_fact.unit
            or remaining_fact.currency != affected_fact.currency
        ):
            raise CurrentShareEvidenceError("remaining completed-claim evidence is not comparable")
        if affected_value - remaining_value != _decimal(
            event.value,
            "completed claim event magnitude",
            positive=True,
        ):
            raise CurrentShareEvidenceError("completed claim transition arithmetic does not replay")
        matches.append((affected_fact, remaining_fact, claim, candidate, decision))
    if len(matches) != 1:
        raise CurrentShareEvidenceError("completed share event lacks one reviewed claim transition")
    return matches[0]


def _claim_transition_reconciliation(
    *,
    issuer_id: str,
    security_id: str,
    trading_date: str,
    cutoff: date,
    event_facts: tuple[Fact, ...],
    facts: dict[str, Fact],
    documents: dict[str, SourceDocument],
    claims: tuple[Claim, ...],
    candidates: tuple[AnalyticalClaimCandidate, ...],
    decisions: tuple[AnalyticalClaimReviewDecision, ...],
    claim_control_authority: Any,
) -> CompletedClaimTransitionReconciliation:
    authority_roots = {
        *claim_control_authority.included_option_root_fact_ids,
        *claim_control_authority.excluded_option_root_fact_ids,
        *claim_control_authority.blocked_option_root_fact_ids,
    }
    records: list[CompletedClaimTransition] = []
    for event in event_facts:
        remaining_concept = CLAIM_SENSITIVE_EVENT_CONCEPTS.get(event.concept)
        if remaining_concept is None:
            continue
        affected, remaining, claim, candidate, decision = _confirmed_transition_chain(
            event=event,
            remaining_concept=remaining_concept,
            issuer_id=issuer_id,
            security_id=security_id,
            trading_date=trading_date,
            cutoff=cutoff,
            facts=facts,
            documents=documents,
            claims=claims,
            candidates=candidates,
            decisions=decisions,
        )
        remaining_value = _decimal(remaining.value, "remaining completed claim", positive=False)
        if remaining_value == 0:
            if affected.fact_id in authority_roots or remaining.fact_id in authority_roots:
                raise CurrentShareEvidenceError(
                    "extinguished claim remains in the frozen equity-bridge treatment"
                )
            disposition = "extinguished"
        else:
            if affected.fact_id in authority_roots or remaining.fact_id not in authority_roots:
                raise CurrentShareEvidenceError(
                    "remaining claim was not rebound in the frozen equity-bridge treatment"
                )
            disposition = "remaining_claim_rebound"
        records.append(
            CompletedClaimTransition(
                event_fact_id=event.fact_id,
                event_concept=event.concept,
                affected_claim_root_fact_id=affected.fact_id,
                remaining_claim_fact_id=remaining.fact_id,
                remaining_claim_value=format(remaining_value, "f"),
                claim_id=claim.claim_id,
                candidate_id=candidate.candidate_id,
                review_decision_id=decision.decision_id,
                disposition=disposition,
            )
        )
    payload = {
        "issuer_id": issuer_id,
        "security_id": security_id,
        "records": tuple(
            item.to_dict() for item in sorted(records, key=lambda item: item.event_fact_id)
        ),
    }
    return CompletedClaimTransitionReconciliation(
        **payload,
        reconciliation_sha256=canonical_sha256(payload),
    )


def derive_current_share_evidence_closure(
    *,
    graph: Any,
    share_fact: Fact,
    evidence_kind: str,
    trading_date: str,
    data_cutoff_date: str,
    security_compilation_result: Any,
    share_basis_decision: Any,
    claim_control_authority: Any,
) -> CurrentShareEvidenceClosure:
    """Derive the only accepted current-share roots, coverage, and claim transitions."""

    cutoff = date.fromisoformat(data_cutoff_date)
    quote_date = date.fromisoformat(trading_date)
    if quote_date > cutoff:
        raise CurrentShareEvidenceError("current-share quote date follows the data cutoff")
    security = security_compilation_result
    if (
        security.status != "eligible"
        or security.decision is None
        or security.evidence_closure is None
        or security.decision.share_class != "common"
        or security.decision.security_structure != "single_primary_common"
    ):
        raise CurrentShareEvidenceError("current-share evidence lacks one exact common security")
    issuer_id = security.decision.issuer_id
    security_id = security.decision.security_id
    share_basis = share_basis_decision
    if (
        share_basis.disposition != "eligible"
        or share_basis.issuer_id != issuer_id
        or share_basis.security_id != security_id
        or share_basis.share_fact_id != share_fact.fact_id
        or share_basis.evidence_kind != evidence_kind
        or share_basis.as_of_date != trading_date
        or share_basis.quote_date != trading_date
        or share_basis.split_factor != "1"
    ):
        raise CurrentShareEvidenceError(
            "current-share evidence is not bound to the exact eligible common security"
        )
    facts = {item.fact_id: item for item in graph.facts}
    documents = {item.document_id: item for item in graph.documents}
    _validate_output_fact(
        share_fact,
        issuer_id=issuer_id,
        trading_date=trading_date,
        cutoff=cutoff,
        documents=documents,
    )
    if (
        share_fact.fact_id not in facts
        or facts[share_fact.fact_id].fingerprint != share_fact.fingerprint
    ):
        raise CurrentShareEvidenceError("current-share output is not the exact graph Fact")

    event_facts: tuple[Fact, ...] = ()
    coverage: CorporateActionCoverageLedger | None = None
    if evidence_kind == "direct_point_in_time":
        if share_fact.derivation is not None or share_fact.parent_fact_ids:
            raise CurrentShareEvidenceError("direct current-share Fact must be a raw leaf")
        _formal_raw_fact(
            share_fact,
            expected_concept="common_shares_outstanding",
            issuer_id=issuer_id,
            cutoff=cutoff,
            documents=documents,
        )
        base = share_fact
        roots = (share_fact,)
    elif evidence_kind == "issued_less_treasury":
        roots = _issued_less_treasury_roots(
            share_fact,
            measurement_date=trading_date,
            issuer_id=issuer_id,
            cutoff=cutoff,
            facts=facts,
            documents=documents,
        )
        base = share_fact
    elif evidence_kind == "completed_event_rollforward":
        if (
            share_fact.derivation != "completed-event-rollforward/1.0.0"
            or len(share_fact.parent_fact_ids) < 2
        ):
            raise CurrentShareEvidenceError("completed-event roll-forward is incomplete")
        parents = tuple(facts.get(parent_id) for parent_id in share_fact.parent_fact_ids)
        if any(parent is None for parent in parents):
            raise CurrentShareEvidenceError("completed-event roll-forward is dangling")
        typed_parents = tuple(parent for parent in parents if parent is not None)
        opening = tuple(
            item for item in typed_parents if item.concept == "common_shares_outstanding"
        )
        event_facts = tuple(
            item for item in typed_parents if item.concept in COMPLETED_SHARE_EVENT_SIGNS
        )
        if len(opening) != 1 or len(event_facts) != len(typed_parents) - 1:
            raise CurrentShareEvidenceError("roll-forward uses an unregistered completed event")
        base = opening[0]
        opening_date = base.period["end"]
        if base.period["start"] is not None or not opening_date or not opening_date < trading_date:
            raise CurrentShareEvidenceError(
                "roll-forward opening shares are not earlier point evidence"
            )
        _validate_output_fact(
            base,
            issuer_id=issuer_id,
            trading_date=opening_date,
            cutoff=cutoff,
            documents=documents,
        )
        if base.derivation is None and not base.parent_fact_ids:
            _formal_raw_fact(
                base,
                expected_concept="common_shares_outstanding",
                issuer_id=issuer_id,
                cutoff=cutoff,
                documents=documents,
            )
            opening_roots: tuple[Fact, ...] = (base,)
        elif base.derivation == "issued-less-treasury/1.0.0":
            opening_roots = _issued_less_treasury_roots(
                base,
                measurement_date=opening_date,
                issuer_id=issuer_id,
                cutoff=cutoff,
                facts=facts,
                documents=documents,
            )
        else:
            raise CurrentShareEvidenceError(
                "roll-forward opening must be direct or issued-less-treasury evidence"
            )
        for event in event_facts:
            if (
                event.period["start"] is not None
                or event.period["end"] is None
                or not opening_date < event.period["end"] <= trading_date
            ):
                raise CurrentShareEvidenceError(
                    "roll-forward event date is outside the activity window"
                )
            _formal_raw_fact(
                event,
                expected_concept=event.concept,
                issuer_id=issuer_id,
                cutoff=cutoff,
                documents=documents,
            )
        expected = _decimal(base.value, "opening common shares", positive=True) + sum(
            (
                int(COMPLETED_SHARE_EVENT_SIGNS[event.concept])
                * _decimal(event.value, "completed share event", positive=True)
                for event in event_facts
            ),
            0,
        )
        if _decimal(share_fact.value, "roll-forward output", positive=True) != expected:
            raise CurrentShareEvidenceError(
                "completed-event roll-forward arithmetic does not replay"
            )
        roots = (*opening_roots, *event_facts)
        coverage = _coverage_ledger(
            issuer_id=issuer_id,
            security_id=security_id,
            opening_date=opening_date,
            trading_date=trading_date,
            cutoff_date=data_cutoff_date,
            event_facts=event_facts,
            facts=facts,
            documents=documents,
            receipts=tuple(graph.source_search_receipts),
            claims=tuple(graph.claims),
            candidates=tuple(graph.analytical_claim_candidates),
            decisions=tuple(graph.analytical_claim_review_decisions),
        )
    else:
        raise CurrentShareEvidenceError("current-share evidence kind is not registered")

    transitions = _claim_transition_reconciliation(
        issuer_id=issuer_id,
        security_id=security_id,
        trading_date=trading_date,
        cutoff=cutoff,
        event_facts=event_facts,
        facts=facts,
        documents=documents,
        claims=tuple(graph.claims),
        candidates=tuple(graph.analytical_claim_candidates),
        decisions=tuple(graph.analytical_claim_review_decisions),
        claim_control_authority=claim_control_authority,
    )
    root_ids = tuple(sorted(item.fact_id for item in roots))
    root_source_ids = tuple(sorted({item.source_document_id for item in roots}))
    security_binding = canonical_sha256(
        {
            "issuer_id": issuer_id,
            "security_id": security_id,
            "share_class": security.decision.share_class,
            "security_compilation_fingerprint": security.fingerprint,
            "security_evidence_closure_sha256": security.evidence_closure.closure_sha256,
            "share_basis_decision_fingerprint": share_basis.fingerprint,
            "output_share_fact_id": share_fact.fact_id,
            "numeric_root_fact_ids": root_ids,
        }
    )
    temporal_sha = canonical_sha256(
        {
            "data_cutoff_date": data_cutoff_date,
            "quote_date": trading_date,
            "facts": tuple(
                sorted(
                    (
                        item.fact_id,
                        item.period["start"],
                        item.period["end"],
                        documents[item.source_document_id].published_date,
                    )
                    for item in (share_fact, *roots)
                )
            ),
        }
    )
    source_objects = {
        documents[item.source_document_id].document_id: documents[item.source_document_id]
        for item in (share_fact, *roots)
    }
    coverage_receipts: tuple[SourceSearchReceipt, ...] = ()
    if coverage is not None:
        receipt_index = {item.receipt_id: item for item in graph.source_search_receipts}
        coverage_receipts = tuple(receipt_index[item] for item in coverage.receipt_ids)
        for receipt in coverage_receipts:
            for document_id in receipt.result_document_ids:
                source_objects[document_id] = documents[document_id]
        for entry in coverage.entries:
            if entry.zero_fact_id is not None:
                zero = facts[entry.zero_fact_id]
                source_objects[zero.source_document_id] = documents[zero.source_document_id]
            if entry.not_applicable_claim_id is not None:
                claim = next(
                    item for item in graph.claims if item.claim_id == entry.not_applicable_claim_id
                )
                for fact_id in claim.supporting_fact_ids:
                    support = facts[fact_id]
                    source_objects[support.source_document_id] = documents[
                        support.source_document_id
                    ]
    source_sha = canonical_sha256(
        tuple(
            (item.document_id, item.fingerprint)
            for item in sorted(source_objects.values(), key=lambda item: item.document_id)
        )
    )
    lineage_sha = canonical_sha256(
        {
            "output": (share_fact.fact_id, share_fact.fingerprint),
            "base": (base.fact_id, base.fingerprint),
            "roots": tuple(
                (item.fact_id, item.fingerprint)
                for item in sorted(roots, key=lambda item: item.fact_id)
            ),
            "events": tuple(
                (item.fact_id, item.concept)
                for item in sorted(event_facts, key=lambda item: item.fact_id)
            ),
        }
    )
    coverage_sha = (
        coverage.ledger_sha256
        if coverage is not None
        else canonical_sha256({"evidence_kind": evidence_kind, "coverage": "not_required"})
    )
    object_fingerprints: set[tuple[str, str, str]] = {
        ("Fact", share_fact.fact_id, share_fact.fingerprint),
        *(("Fact", item.fact_id, item.fingerprint) for item in roots),
        *(
            ("SourceDocument", item.document_id, item.fingerprint)
            for item in source_objects.values()
        ),
        *(("SourceSearchReceipt", item.receipt_id, item.fingerprint) for item in coverage_receipts),
    }
    if coverage is not None:
        for entry in coverage.entries:
            if entry.zero_fact_id is not None:
                zero = facts[entry.zero_fact_id]
                object_fingerprints.add(("Fact", zero.fact_id, zero.fingerprint))
            if entry.not_applicable_claim_id is not None:
                claim = next(
                    item for item in graph.claims if item.claim_id == entry.not_applicable_claim_id
                )
                decision = next(
                    item
                    for item in graph.analytical_claim_review_decisions
                    if item.decision_id == entry.review_decision_id
                )
                candidate = next(
                    item
                    for item in graph.analytical_claim_candidates
                    if item.candidate_id == decision.candidate_id
                )
                object_fingerprints.update(
                    {
                        ("Claim", claim.claim_id, claim.fingerprint),
                        ("AnalyticalClaimCandidate", candidate.candidate_id, candidate.fingerprint),
                        (
                            "AnalyticalClaimReviewDecision",
                            decision.decision_id,
                            decision.fingerprint,
                        ),
                    }
                )
    for transition in transitions.records:
        claim = next(item for item in graph.claims if item.claim_id == transition.claim_id)
        candidate = next(
            item
            for item in graph.analytical_claim_candidates
            if item.candidate_id == transition.candidate_id
        )
        decision = next(
            item
            for item in graph.analytical_claim_review_decisions
            if item.decision_id == transition.review_decision_id
        )
        object_fingerprints.update(
            {
                (
                    "Fact",
                    transition.affected_claim_root_fact_id,
                    facts[transition.affected_claim_root_fact_id].fingerprint,
                ),
                (
                    "Fact",
                    transition.remaining_claim_fact_id,
                    facts[transition.remaining_claim_fact_id].fingerprint,
                ),
                ("Claim", claim.claim_id, claim.fingerprint),
                ("AnalyticalClaimCandidate", candidate.candidate_id, candidate.fingerprint),
                ("AnalyticalClaimReviewDecision", decision.decision_id, decision.fingerprint),
            }
        )
    closure_id = (
        f"current-share-evidence:{issuer_id}:{security_id}:{trading_date}:"
        f"{canonical_sha256((evidence_kind, share_fact.fact_id, root_ids))[:20]}"
    )
    payload = {
        "closure_id": closure_id,
        "issuer_id": issuer_id,
        "security_id": security_id,
        "quote_date": trading_date,
        "evidence_kind": evidence_kind,
        "output_share_fact_id": share_fact.fact_id,
        "output_share_fact_fingerprint": share_fact.fingerprint,
        "numeric_root_fact_ids": root_ids,
        "numeric_root_source_document_ids": root_source_ids,
        "base_share_fact_id": base.fact_id,
        "event_fact_ids": tuple(sorted(item.fact_id for item in event_facts)),
        "coverage_receipt_ids": tuple(sorted(item.receipt_id for item in coverage_receipts)),
        "security_binding_fingerprint": security_binding,
        "temporal_closure_sha256": temporal_sha,
        "source_closure_sha256": source_sha,
        "numeric_lineage_sha256": lineage_sha,
        "coverage_closure_sha256": coverage_sha,
        "claim_transition_sha256": transitions.reconciliation_sha256,
        "object_fingerprints": tuple(sorted(object_fingerprints)),
    }
    return CurrentShareEvidenceClosure(**payload, closure_sha256=canonical_sha256(payload))


__all__ = ()
