"""Internal reviewed-chain replay for Phase 5E-2B.1 share-event grouping.

The module is intentionally outside the package root and has no CLI, writer, market-evidence,
roll-forward, or valuation surface.  Phase 5E-2B.1-1 may discover and group reviewed completed
share events, but it must stop before creating a derived event Fact or changing current shares.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path

from .capital_allocation_policies import OFFICIAL_AUTHORITY_LEVELS
from .contracts import (
    CapitalAllocationEvent,
    CapitalAllocationEventCandidate,
    CapitalAllocationEventReviewDecision,
    Fact,
    SourceDocument,
)
from .fingerprints import canonical_sha256
from .validation import ContractGraph, ContractGraphError
from .valuation_security_identity import SecurityIdentityCompilationResult
from .valuation_share_event_identity import (
    SHARE_EVENT_CONCEPT_POLICIES,
    SHARE_EVENT_GROUPING_POLICY_ID,
    SHARE_EVENT_GROUPING_POLICY_VERSION,
    ShareEventConflict,
    ShareEventEvidenceGroup,
    ShareEventEvidenceMember,
    ShareEventGroupingResult,
    ShareEventIdentity,
)

_ALLOWED_EVENT_ROLE_PAIRS = {
    "common_shares_issued_completed": frozenset({("equity_issuance", "shares_issued")}),
    "common_shares_repurchased_completed": frozenset({("buyback", "shares_repurched")}),
    "common_shares_retired_or_cancelled_completed": frozenset(
        {("buyback", "shares_repurched")}
    ),
    "option_shares_exercised_completed": frozenset(
        {("equity_issuance", "shares_issued")}
    ),
    "rsu_shares_settled_completed": frozenset({("equity_issuance", "shares_issued")}),
    "convertible_shares_converted_completed": frozenset(
        {("equity_issuance", "shares_issued")}
    ),
    "warrant_shares_exercised_completed": frozenset(
        {("equity_issuance", "shares_issued")}
    ),
    "acquisition_consideration_shares_issued_completed": frozenset(
        {("equity_issuance", "shares_issued")}
    ),
}


class ShareEventGroupingError(ValueError):
    """Fail-closed internal error raised before a promotable grouping result exists."""

    def __init__(self, issue_code: str) -> None:
        super().__init__(issue_code)
        self.issue_code = issue_code


@dataclass(frozen=True, slots=True)
class _ReviewedMemberInput:
    fact: Fact
    source: SourceDocument
    event: CapitalAllocationEvent
    candidate: CapitalAllocationEventCandidate
    decision: CapitalAllocationEventReviewDecision
    fact_role: str


@dataclass(frozen=True, slots=True)
class _IdentifiedMember:
    reviewed: _ReviewedMemberInput
    identity: ShareEventIdentity
    member: ShareEventEvidenceMember


def _parse_review_date(value: str) -> date:
    return date.fromisoformat(value[:10])


def _positive_integer_shares(value: object) -> Decimal | None:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    if not parsed.is_finite() or parsed <= 0 or parsed != parsed.to_integral():
        return None
    return parsed


def _eligible_event_fact(
    fact: Fact,
    *,
    issuer_id: str,
    opening: date,
    quote: date,
    cutoff: date,
    documents: dict[str, SourceDocument],
) -> SourceDocument | None:
    source = documents.get(fact.source_document_id)
    measurement = fact.period["end"]
    if (
        fact.issuer_id != issuer_id
        or fact.concept not in SHARE_EVENT_CONCEPT_POLICIES
        or fact.value_type != "number"
        or fact.unit != "shares"
        or fact.currency is not None
        or fact.period["start"] is not None
        or measurement is None
        or fact.confidence != "high"
        or fact.derivation is not None
        or fact.parent_fact_ids
        or _positive_integer_shares(fact.value) is None
        or source is None
        or source.issuer_id != issuer_id
        or source.authority_level not in OFFICIAL_AUTHORITY_LEVELS
    ):
        return None
    measured = date.fromisoformat(str(measurement))
    published = date.fromisoformat(source.published_date)
    if not opening < measured <= quote or published > cutoff:
        return None
    return source


def _cutoff_safe_event(
    event: CapitalAllocationEvent,
    *,
    cutoff: date,
    candidates: dict[str, CapitalAllocationEventCandidate],
    documents: dict[str, SourceDocument],
) -> bool:
    if date.fromisoformat(event.announcement_date) > cutoff:
        return False
    bound_candidate_ids = {
        str(binding["candidate_id"])
        for binding in (*event.source_bindings, *event.fact_bindings)
    }
    if not bound_candidate_ids:
        return False
    for candidate_id in bound_candidate_ids:
        candidate = candidates.get(candidate_id)
        if candidate is None or date.fromisoformat(candidate.as_of_date) > cutoff:
            return False
        source = documents.get(candidate.source_document_id)
        if source is None or date.fromisoformat(source.published_date) > cutoff:
            return False
    return True


def _current_events(
    graph: ContractGraph,
    *,
    issuer_id: str,
    cutoff: date,
    candidates: dict[str, CapitalAllocationEventCandidate],
    documents: dict[str, SourceDocument],
) -> tuple[CapitalAllocationEvent, ...]:
    latest: dict[str, CapitalAllocationEvent] = {}
    for event in graph.capital_allocation_events:
        if event.issuer_id != issuer_id or not _cutoff_safe_event(
            event,
            cutoff=cutoff,
            candidates=candidates,
            documents=documents,
        ):
            continue
        prior = latest.get(event.economic_event_key)
        if prior is None or event.event_version > prior.event_version:
            latest[event.economic_event_key] = event
        elif event.event_version == prior.event_version and event.fingerprint != prior.fingerprint:
            raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    superseded_ids = {
        event_id for event in latest.values() for event_id in event.supersedes_event_ids
    }
    return tuple(
        sorted(
            (
                event
                for event in latest.values()
                if event.event_id not in superseded_ids and event.lifecycle_status == "completed"
            ),
            key=lambda item: (item.economic_event_key, item.event_version, item.event_id),
        )
    )


def _active_decisions(
    graph: ContractGraph,
    *,
    cutoff: date,
) -> dict[str, CapitalAllocationEventReviewDecision]:
    eligible = tuple(
        item
        for item in graph.capital_allocation_event_review_decisions
        if _parse_review_date(item.reviewed_at) <= cutoff
    )
    superseded = {
        decision_id for item in eligible for decision_id in item.supersedes_decision_ids
    }
    return {
        item.decision_id: item
        for item in eligible
        if item.decision == "confirmed" and item.decision_id not in superseded
    }


def _event_ancestor_ids(
    event: CapitalAllocationEvent,
    *,
    events_by_id: dict[str, CapitalAllocationEvent],
) -> set[str]:
    result = {event.event_id}
    predecessor_id = event.predecessor_event_id
    while predecessor_id is not None:
        if predecessor_id in result or predecessor_id not in events_by_id:
            raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
        result.add(predecessor_id)
        predecessor_id = events_by_id[predecessor_id].predecessor_event_id
    return result


def _resolve_binding_chain(
    *,
    event: CapitalAllocationEvent,
    binding: Mapping[str, object],
    candidates: dict[str, CapitalAllocationEventCandidate],
    decisions: dict[str, CapitalAllocationEventReviewDecision],
    events_by_id: dict[str, CapitalAllocationEvent],
) -> tuple[CapitalAllocationEventCandidate, CapitalAllocationEventReviewDecision]:
    candidate_id = str(binding["candidate_id"])
    decision_id = str(binding["decision_id"])
    candidate = candidates.get(candidate_id)
    decision = decisions.get(decision_id)
    if candidate is None or decision is None:
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    if (
        decision.candidate_id != candidate.candidate_id
        or decision.candidate_fingerprint != candidate.fingerprint
        or decision.output_economic_event_key != event.economic_event_key
        or decision.output_event_id
        not in _event_ancestor_ids(event, events_by_id=events_by_id)
        or candidate.validation_status != "ready"
        or candidate.proposed_event_type != event.event_type
        or candidate.proposed_event_subtype != event.event_subtype
        or tuple(candidate.proposed_identity_components) != tuple(event.identity_components)
        or not decision.reviewer_id.startswith("human:")
        or len(decision.reviewer_id) <= len("human:")
    ):
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    matching_candidate_bindings = tuple(
        item
        for item in candidate.proposed_fact_bindings
        if item["binding_id"] == binding["binding_id"]
        and item["fact_id"] == binding["fact_id"]
        and item["role_id"] == binding["role_id"]
    )
    matching_source_bindings = tuple(
        item
        for item in event.source_bindings
        if item["candidate_id"] == candidate.candidate_id
        and item["decision_id"] == decision.decision_id
        and item["source_document_id"] == candidate.source_document_id
    )
    if len(matching_candidate_bindings) != 1 or len(matching_source_bindings) != 1:
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    return candidate, decision


def _discover_reviewed_member_inputs(
    *,
    graph: ContractGraph,
    issuer_id: str,
    opening_date: str,
    quote_date: str,
    data_cutoff_date: str,
) -> tuple[_ReviewedMemberInput, ...]:
    """Discover raw completed-event Facts and replay their reviewed capital-event chain."""

    try:
        graph.validate()
    except ContractGraphError as exc:
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous") from exc
    opening = date.fromisoformat(opening_date)
    quote = date.fromisoformat(quote_date)
    cutoff = date.fromisoformat(data_cutoff_date)
    if opening >= quote or quote > cutoff:
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    documents = {item.document_id: item for item in graph.documents}
    candidates = {
        item.candidate_id: item for item in graph.capital_allocation_event_candidates
    }
    events_by_id = {item.event_id: item for item in graph.capital_allocation_events}
    decisions = _active_decisions(graph, cutoff=cutoff)
    current_events = _current_events(
        graph,
        issuer_id=issuer_id,
        cutoff=cutoff,
        candidates=candidates,
        documents=documents,
    )
    bindings_by_fact: dict[
        str, list[tuple[CapitalAllocationEvent, Mapping[str, object]]]
    ] = {}
    for event in current_events:
        for binding in event.fact_bindings:
            bindings_by_fact.setdefault(str(binding["fact_id"]), []).append((event, binding))
    reviewed: list[_ReviewedMemberInput] = []
    for fact in sorted(graph.facts, key=lambda item: item.fact_id):
        source = _eligible_event_fact(
            fact,
            issuer_id=issuer_id,
            opening=opening,
            quote=quote,
            cutoff=cutoff,
            documents=documents,
        )
        if source is None:
            continue
        matches = bindings_by_fact.get(fact.fact_id, [])
        if len(matches) != 1:
            raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
        event, binding = matches[0]
        concept_policy = SHARE_EVENT_CONCEPT_POLICIES[fact.concept]
        role = str(binding["role_id"])
        if (
            event.event_type not in concept_policy["event_types"]
            or role not in concept_policy["fact_roles"]
            or (event.event_type, role) not in _ALLOWED_EVENT_ROLE_PAIRS[fact.concept]
        ):
            raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
        candidate, decision = _resolve_binding_chain(
            event=event,
            binding=binding,
            candidates=candidates,
            decisions=decisions,
            events_by_id=events_by_id,
        )
        reviewed.append(
            _ReviewedMemberInput(
                fact=fact,
                source=source,
                event=event,
                candidate=candidate,
                decision=decision,
                fact_role=role,
            )
        )
    return tuple(reviewed)


def _validate_security_compilation(
    *,
    graph: ContractGraph,
    result: SecurityIdentityCompilationResult,
    issuer_id: str,
    data_cutoff_date: str,
) -> tuple[str, str]:
    """Replay the immutable security closure against this exact graph."""

    decision = result.decision
    closure = result.evidence_closure
    if (
        result.status != "eligible"
        or decision is None
        or closure is None
        or result.proposal.issuer_id != issuer_id
        or result.proposal.data_cutoff_date != data_cutoff_date
        or decision.issuer_id != issuer_id
        or decision.disposition != "eligible"
        or decision.share_class != "common"
        or decision.security_structure != "single_primary_common"
        or closure.issuer_id != issuer_id
        or closure.data_cutoff_date != data_cutoff_date
    ):
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    graph_fingerprints = {
        (contract_type, object_id, item.fingerprint)
        for contract_type, items, id_attribute in (
            ("SourceDocument", graph.documents, "document_id"),
            ("Fact", graph.facts, "fact_id"),
            ("Claim", graph.claims, "claim_id"),
            (
                "AnalyticalClaimCandidate",
                graph.analytical_claim_candidates,
                "candidate_id",
            ),
            (
                "AnalyticalClaimReviewDecision",
                graph.analytical_claim_review_decisions,
                "decision_id",
            ),
        )
        for item in items
        for object_id in (getattr(item, id_attribute),)
    }
    if set(closure.object_fingerprints) != graph_fingerprints.intersection(
        set(closure.object_fingerprints)
    ):
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    if (
        tuple(sorted(binding.fact_id for binding in result.proposal.fact_bindings))
        != closure.fact_ids
        or result.proposal.structure_claim_id != closure.claim_id
        or result.proposal.analytical_candidate_id != closure.candidate_id
        or result.proposal.analytical_review_decision_id != closure.review_decision_id
    ):
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    return decision.security_id, decision.share_class


def _identity_components(event: CapitalAllocationEvent) -> dict[str, str]:
    return {
        str(item["role"]): " ".join(str(item["value"]).split()).casefold()
        for item in event.identity_components
    }


def _official_legal_event_id(
    event: CapitalAllocationEvent,
    *,
    target_share_class: str,
) -> str:
    components = _identity_components(event)
    if components.get("security_class") != target_share_class.casefold():
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    legal_roles = {
        "buyback": ("program_id",),
        "equity_issuance": ("program_id", "plan_id"),
    }.get(event.event_type)
    if legal_roles is None:
        # The frozen acquisition and SBC identities do not prove the affected security class.
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    resolved = tuple(
        (role, components[role]) for role in legal_roles if components.get(role)
    )
    if len(resolved) != 1:
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    role, value = resolved[0]
    return f"{role}:{value}"


def _canonical_share_magnitude(value: object) -> str:
    parsed = _positive_integer_shares(value)
    if parsed is None:
        raise ShareEventGroupingError("blocked_share_event_conflict")
    return format(parsed, "f")


def _derive_identity(
    reviewed: _ReviewedMemberInput,
    *,
    issuer_id: str,
    security_id: str,
    target_share_class: str,
) -> ShareEventIdentity:
    measurement_date = str(reviewed.fact.period["end"])
    candidate_period = reviewed.candidate.proposed_execution_period
    if (
        candidate_period["start"] is None
        or candidate_period["end"] is None
        or candidate_period["start"] != candidate_period["end"]
    ):
        # A period-wide or open execution disclosure cannot prove one incremental occurrence.
        raise ShareEventGroupingError("blocked_share_event_cumulative_amount")
    if candidate_period["end"] != measurement_date:
        raise ShareEventGroupingError("blocked_share_event_conflict")
    if reviewed.candidate.proposed_source_role not in {
        "completion",
        "periodic_recap",
        "execution_update",
    }:
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    official_legal_event_id = _official_legal_event_id(
        reviewed.event,
        target_share_class=target_share_class,
    )
    execution_occurrence_id = canonical_sha256(
        {
            "economic_event_key": reviewed.event.economic_event_key,
            "official_legal_event_id": official_legal_event_id,
            "legal_effective_date": measurement_date,
        }
    )
    legal_payload = {
        "issuer_id": issuer_id,
        "security_id": security_id,
        "economic_event_key": reviewed.event.economic_event_key,
        "official_legal_event_id": official_legal_event_id,
        "execution_occurrence_id": execution_occurrence_id,
    }
    legal_event_key = canonical_sha256(legal_payload)
    concept_policy = SHARE_EVENT_CONCEPT_POLICIES[reviewed.fact.concept]
    fields = {
        "policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
        "policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
        "issuer_id": issuer_id,
        "security_id": security_id,
        "economic_event_key": reviewed.event.economic_event_key,
        "official_legal_event_id": official_legal_event_id,
        "execution_occurrence_id": execution_occurrence_id,
        "legal_event_key": legal_event_key,
        "event_concept": reviewed.fact.concept,
        "legal_effective_date": measurement_date,
        "canonical_share_magnitude": _canonical_share_magnitude(reviewed.fact.value),
        "event_grain": str(concept_policy["event_grain"]),
    }
    return ShareEventIdentity(
        **fields,
        identity_fingerprint=canonical_sha256(fields),
    )


def _derive_member(
    reviewed: _ReviewedMemberInput,
    *,
    identity: ShareEventIdentity,
    data_cutoff_date: str,
) -> ShareEventEvidenceMember:
    identity_payload = {
        "legal_event_key": identity.legal_event_key,
        "fact_id": reviewed.fact.fact_id,
        "fact_fingerprint": reviewed.fact.fingerprint,
        "source_document_id": reviewed.source.document_id,
        "source_document_fingerprint": reviewed.source.fingerprint,
        "source_locator": reviewed.fact.source_locator,
        "capital_allocation_event_id": reviewed.event.event_id,
        "capital_allocation_event_fingerprint": reviewed.event.fingerprint,
        "candidate_ids": (reviewed.candidate.candidate_id,),
        "review_decision_ids": (reviewed.decision.decision_id,),
    }
    member_id = f"share-event-member:{canonical_sha256(identity_payload)[:24]}"
    fields = {
        "member_id": member_id,
        "legal_event_key": identity.legal_event_key,
        "fact_id": reviewed.fact.fact_id,
        "fact_fingerprint": reviewed.fact.fingerprint,
        "source_document_id": reviewed.source.document_id,
        "source_document_fingerprint": reviewed.source.fingerprint,
        "source_locator": reviewed.fact.source_locator,
        "source_authority_level": reviewed.source.authority_level,
        "source_published_date": reviewed.source.published_date,
        "fact_measurement_date": str(reviewed.fact.period["end"]),
        "data_cutoff_date": data_cutoff_date,
        "capital_allocation_event_id": reviewed.event.event_id,
        "capital_allocation_event_fingerprint": reviewed.event.fingerprint,
        "candidate_ids": (reviewed.candidate.candidate_id,),
        "review_decision_ids": (reviewed.decision.decision_id,),
    }
    return ShareEventEvidenceMember(
        **fields,
        member_fingerprint=canonical_sha256(fields),
    )


def _identify_reviewed_members(
    *,
    graph: ContractGraph,
    issuer_id: str,
    security_compilation_result: SecurityIdentityCompilationResult,
    opening_date: str,
    quote_date: str,
    data_cutoff_date: str,
) -> tuple[_IdentifiedMember, ...]:
    security_id, target_share_class = _validate_security_compilation(
        graph=graph,
        result=security_compilation_result,
        issuer_id=issuer_id,
        data_cutoff_date=data_cutoff_date,
    )
    reviewed = _discover_reviewed_member_inputs(
        graph=graph,
        issuer_id=issuer_id,
        opening_date=opening_date,
        quote_date=quote_date,
        data_cutoff_date=data_cutoff_date,
    )
    identified = []
    for item in reviewed:
        identity = _derive_identity(
            item,
            issuer_id=issuer_id,
            security_id=security_id,
            target_share_class=target_share_class,
        )
        identified.append(
            _IdentifiedMember(
                reviewed=item,
                identity=identity,
                member=_derive_member(
                    item,
                    identity=identity,
                    data_cutoff_date=data_cutoff_date,
                ),
            )
        )
    return tuple(sorted(identified, key=lambda item: item.member.member_id))


def _grouping_code_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _conflict(
    *,
    code: str,
    legal_event_key: str | None,
    fields: tuple[str, ...],
    members: tuple[ShareEventEvidenceMember, ...],
    compared_values: object,
) -> ShareEventConflict:
    compared_values_sha256 = canonical_sha256(compared_values)
    payload = {
        "conflict_code": code,
        "legal_event_key": legal_event_key,
        "conflicting_fields": tuple(sorted(fields)),
        "member_ids": tuple(sorted(item.member_id for item in members)),
        "compared_values_sha256": compared_values_sha256,
    }
    conflict_id = f"share-event-conflict:{canonical_sha256(payload)[:24]}"
    fields_with_id = {"conflict_id": conflict_id, **payload}
    return ShareEventConflict(
        **fields_with_id,
        conflict_fingerprint=canonical_sha256(fields_with_id),
    )


def _group(
    *,
    identity: ShareEventIdentity,
    members: tuple[ShareEventEvidenceMember, ...],
    status: str,
    conflict: ShareEventConflict | None = None,
) -> ShareEventEvidenceGroup:
    group_id = f"share-event-group:{identity.issuer_id}:{identity.legal_event_key[:24]}"
    fields = {
        "group_id": group_id,
        "identity": identity,
        "member_ids": tuple(sorted(item.member_id for item in members)),
        "status": status,
        "canonical_event_fact_id": (
            f"derived:share-event:{identity.identity_fingerprint[:24]}"
            if status == "canonical"
            else None
        ),
        "conflict_ids": () if conflict is None else (conflict.conflict_id,),
    }
    return ShareEventEvidenceGroup(
        **fields,
        group_fingerprint=canonical_sha256(fields),
    )


def _semantic_conflicting_fields(
    items: tuple[_IdentifiedMember, ...],
) -> tuple[str, ...]:
    compared = {
        "event_concept": {item.identity.event_concept for item in items},
        "legal_effective_date": {item.identity.legal_effective_date for item in items},
        "canonical_share_magnitude": {
            item.identity.canonical_share_magnitude for item in items
        },
        "security_id": {item.identity.security_id for item in items},
        "event_grain": {item.identity.event_grain for item in items},
    }
    return tuple(sorted(field for field, values in compared.items() if len(values) != 1))


def group_governed_completed_share_events(
    *,
    graph: ContractGraph,
    issuer_id: str,
    security_compilation_result: SecurityIdentityCompilationResult,
    opening_date: str,
    quote_date: str,
    data_cutoff_date: str,
) -> ShareEventGroupingResult:
    """Group reviewed completed-share evidence exactly once within the validated graph.

    This Phase 5E-2B.1-1 entry point deliberately stops at canonical evidence groups and stable
    *reserved* derived-Fact IDs.  It neither creates Facts nor changes the current-share ledger.
    ResearchBundle dependency-closure, coverage, transition, and recursive-closure integration
    remain the separately authorized Phase 5E-2B.1-2 work.
    """

    identified = _identify_reviewed_members(
        graph=graph,
        issuer_id=issuer_id,
        security_compilation_result=security_compilation_result,
        opening_date=opening_date,
        quote_date=quote_date,
        data_cutoff_date=data_cutoff_date,
    )
    security_decision = security_compilation_result.decision
    if security_decision is None:
        raise ShareEventGroupingError("blocked_share_event_identity_ambiguous")
    by_legal_key: dict[str, list[_IdentifiedMember]] = {}
    for item in identified:
        by_legal_key.setdefault(item.identity.legal_event_key, []).append(item)

    groups: list[ShareEventEvidenceGroup] = []
    conflicts: list[ShareEventConflict] = []
    for legal_event_key, raw_items in sorted(by_legal_key.items()):
        items = tuple(sorted(raw_items, key=lambda item: item.member.member_id))
        semantic_conflicts = _semantic_conflicting_fields(items)
        if semantic_conflicts:
            # The frozen 2B.1-0 contract cannot represent a neutral identity for a semantic
            # conflict without choosing one source.  Fail closed instead of selecting a value.
            raise ShareEventGroupingError("blocked_share_event_conflict")
        source_ids = tuple(item.member.source_document_id for item in items)
        if len(source_ids) != len(set(source_ids)):
            conflict = _conflict(
                code="blocked_share_event_identity_ambiguous",
                legal_event_key=legal_event_key,
                fields=("event_grain",),
                members=tuple(item.member for item in items),
                compared_values={
                    "reason": "same official source repeats one unpartitioned legal occurrence",
                    "member_fingerprints": tuple(
                        sorted(item.member.member_fingerprint for item in items)
                    ),
                },
            )
            conflicts.append(conflict)
            groups.append(
                _group(
                    identity=items[0].identity,
                    members=tuple(item.member for item in items),
                    status="blocked",
                    conflict=conflict,
                )
            )
            continue
        groups.append(
            _group(
                identity=items[0].identity,
                members=tuple(item.member for item in items),
                status="canonical",
            )
        )

    fields = {
        "policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
        "policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
        "grouping_code_sha256": _grouping_code_sha256(),
        "issuer_id": issuer_id,
        "security_id": security_decision.security_id,
        "opening_date": opening_date,
        "quote_date": quote_date,
        "status": "blocked" if conflicts else "grouped",
        "members": tuple(item.member for item in identified),
        "groups": tuple(groups),
        "conflicts": tuple(conflicts),
    }
    return ShareEventGroupingResult(
        **fields,
        grouping_fingerprint=canonical_sha256(fields),
    )


__all__: tuple[str, ...] = ()
