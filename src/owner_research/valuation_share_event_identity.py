"""Internal Phase 5E-2B.1 share-event identity contracts and closed policy.

This module deliberately contains no event discovery, grouping, roll-forward, writer, market
evidence, or valuation entry point.  It defines the immutable records that the separately
authorized Phase 5E-2B.1-1 implementation must produce.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Any

from .capital_allocation_policies import OFFICIAL_AUTHORITY_LEVELS
from .fingerprints import canonical_sha256, to_json_value

SHARE_EVENT_GROUPING_POLICY_ID = "cross-source-share-event-grouping"
SHARE_EVENT_GROUPING_POLICY_VERSION = "1.0.0"

SHARE_EVENT_GROUP_STATUSES = frozenset({"canonical", "blocked"})
SHARE_EVENT_GROUPING_STATUSES = frozenset({"grouped", "blocked"})
SHARE_EVENT_CONFLICT_CODES = frozenset(
    {
        "blocked_share_event_conflict",
        "blocked_share_event_identity_ambiguous",
        "blocked_share_event_cumulative_amount",
    }
)
SHARE_EVENT_CONFLICT_FIELDS = frozenset(
    {
        "canonical_share_magnitude",
        "event_concept",
        "legal_effective_date",
        "security_id",
        "event_grain",
    }
)

# The legacy ``shares_repurched`` spelling is frozen in the Phase 4D public policy.  This internal
# mapping records it explicitly instead of silently repairing historical contracts.
SHARE_EVENT_CONCEPT_POLICIES = MappingProxyType(
    {
        "common_shares_issued_completed": {
            "event_types": ("equity_issuance",),
            "fact_roles": ("shares_issued",),
            "event_grain": "incremental_completed_execution",
        },
        "common_shares_repurchased_completed": {
            "event_types": ("buyback",),
            "fact_roles": ("shares_repurched",),
            "event_grain": "incremental_completed_execution",
        },
        "common_shares_retired_or_cancelled_completed": {
            "event_types": ("buyback", "equity_issuance"),
            "fact_roles": ("shares_repurched", "shares_issued"),
            "event_grain": "incremental_completed_execution",
        },
        "option_shares_exercised_completed": {
            "event_types": ("equity_issuance", "stock_based_compensation"),
            "fact_roles": ("shares_issued",),
            "event_grain": "incremental_completed_execution",
        },
        "rsu_shares_settled_completed": {
            "event_types": ("equity_issuance", "stock_based_compensation"),
            "fact_roles": ("shares_issued", "shares_vested"),
            "event_grain": "incremental_completed_execution",
        },
        "convertible_shares_converted_completed": {
            "event_types": ("equity_issuance",),
            "fact_roles": ("shares_issued",),
            "event_grain": "incremental_completed_execution",
        },
        "warrant_shares_exercised_completed": {
            "event_types": ("equity_issuance",),
            "fact_roles": ("shares_issued",),
            "event_grain": "incremental_completed_execution",
        },
        "acquisition_consideration_shares_issued_completed": {
            "event_types": ("acquisition", "equity_issuance"),
            "fact_roles": ("stock_consideration", "shares_issued"),
            "event_grain": "incremental_completed_execution",
        },
    }
)


def _nonempty(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty")


def _sha(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _unique_sorted(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} must contain non-empty strings")
    normalized = tuple(sorted(values))
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{label} must be unique")
    return normalized


def _shares(value: str, label: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} must be an exact decimal string") from exc
    if (
        not parsed.is_finite()
        or parsed <= 0
        or parsed != parsed.to_integral()
        or value != format(parsed, "f")
    ):
        raise ValueError(f"{label} must be a canonical positive integer share magnitude")
    return parsed


@dataclass(frozen=True, slots=True)
class ShareEventIdentity:
    policy_id: str
    policy_version: str
    issuer_id: str
    security_id: str
    economic_event_key: str
    official_legal_event_id: str
    execution_occurrence_id: str
    legal_event_key: str
    event_concept: str
    legal_effective_date: str
    canonical_share_magnitude: str
    event_grain: str
    identity_fingerprint: str

    def __post_init__(self) -> None:
        if (self.policy_id, self.policy_version) != (
            SHARE_EVENT_GROUPING_POLICY_ID,
            SHARE_EVENT_GROUPING_POLICY_VERSION,
        ):
            raise ValueError("share-event identity policy mismatch")
        for value, label in (
            (self.issuer_id, "issuer ID"),
            (self.security_id, "security ID"),
            (self.economic_event_key, "economic-event key"),
            (self.official_legal_event_id, "official legal-event ID"),
            (self.execution_occurrence_id, "execution occurrence ID"),
        ):
            _nonempty(value, label)
        policy = SHARE_EVENT_CONCEPT_POLICIES.get(self.event_concept)
        if policy is None:
            raise ValueError("share-event concept is not registered")
        if self.event_grain != policy["event_grain"]:
            raise ValueError("share-event grain is not registered")
        date.fromisoformat(self.legal_effective_date)
        _shares(self.canonical_share_magnitude, "canonical share magnitude")
        if self.legal_event_key != self.expected_legal_event_key():
            raise ValueError("share-event legal key mismatch")
        if self.identity_fingerprint != self.expected_identity_fingerprint():
            raise ValueError("share-event identity fingerprint mismatch")

    def legal_key_payload(self) -> dict[str, str]:
        return {
            "issuer_id": self.issuer_id,
            "security_id": self.security_id,
            "economic_event_key": self.economic_event_key,
            "official_legal_event_id": self.official_legal_event_id,
            "execution_occurrence_id": self.execution_occurrence_id,
        }

    def expected_legal_event_key(self) -> str:
        return canonical_sha256(self.legal_key_payload())

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("identity_fingerprint")
        return payload

    def expected_identity_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return self.identity_fingerprint


@dataclass(frozen=True, slots=True)
class ShareEventEvidenceMember:
    member_id: str
    legal_event_key: str
    fact_id: str
    fact_fingerprint: str
    source_document_id: str
    source_document_fingerprint: str
    source_locator: str
    source_authority_level: str
    source_published_date: str
    fact_measurement_date: str
    data_cutoff_date: str
    capital_allocation_event_id: str
    capital_allocation_event_fingerprint: str
    candidate_ids: tuple[str, ...]
    review_decision_ids: tuple[str, ...]
    member_fingerprint: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.fact_id, "Fact ID"),
            (self.source_document_id, "SourceDocument ID"),
            (self.source_locator, "source locator"),
            (self.capital_allocation_event_id, "CapitalAllocationEvent ID"),
        ):
            _nonempty(value, label)
        for value, label in (
            (self.legal_event_key, "legal-event key"),
            (self.fact_fingerprint, "Fact fingerprint"),
            (self.source_document_fingerprint, "SourceDocument fingerprint"),
            (self.capital_allocation_event_fingerprint, "CapitalAllocationEvent fingerprint"),
        ):
            _sha(value, label)
        if self.source_authority_level not in OFFICIAL_AUTHORITY_LEVELS:
            raise ValueError("share-event member source is not official")
        published = date.fromisoformat(self.source_published_date)
        measured = date.fromisoformat(self.fact_measurement_date)
        cutoff = date.fromisoformat(self.data_cutoff_date)
        if published > cutoff or measured > cutoff:
            raise ValueError("share-event member exceeds the data cutoff")
        candidates = _unique_sorted(self.candidate_ids, "Candidate IDs")
        decisions = _unique_sorted(self.review_decision_ids, "ReviewDecision IDs")
        if not candidates or not decisions:
            raise ValueError("share-event member lacks its reviewed identity chain")
        object.__setattr__(self, "candidate_ids", candidates)
        object.__setattr__(self, "review_decision_ids", decisions)
        if self.member_id != self.expected_member_id():
            raise ValueError("share-event member ID mismatch")
        if self.member_fingerprint != self.expected_member_fingerprint():
            raise ValueError("share-event member fingerprint mismatch")

    def identity_payload(self) -> dict[str, Any]:
        return {
            "legal_event_key": self.legal_event_key,
            "fact_id": self.fact_id,
            "fact_fingerprint": self.fact_fingerprint,
            "source_document_id": self.source_document_id,
            "source_document_fingerprint": self.source_document_fingerprint,
            "source_locator": self.source_locator,
            "capital_allocation_event_id": self.capital_allocation_event_id,
            "capital_allocation_event_fingerprint": self.capital_allocation_event_fingerprint,
            "candidate_ids": self.candidate_ids,
            "review_decision_ids": self.review_decision_ids,
        }

    def expected_member_id(self) -> str:
        return f"share-event-member:{canonical_sha256(self.identity_payload())[:24]}"

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("member_fingerprint")
        return payload

    def expected_member_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return self.member_fingerprint


@dataclass(frozen=True, slots=True)
class ShareEventConflict:
    conflict_id: str
    conflict_code: str
    legal_event_key: str | None
    conflicting_fields: tuple[str, ...]
    member_ids: tuple[str, ...]
    compared_values_sha256: str
    conflict_fingerprint: str

    def __post_init__(self) -> None:
        if self.conflict_code not in SHARE_EVENT_CONFLICT_CODES:
            raise ValueError("share-event conflict code is not registered")
        if self.legal_event_key is not None:
            _sha(self.legal_event_key, "conflict legal-event key")
        if (
            self.conflict_code == "blocked_share_event_conflict"
            and self.legal_event_key is None
        ):
            raise ValueError("semantic share-event conflict lacks a legal-event key")
        fields = _unique_sorted(self.conflicting_fields, "conflicting fields")
        members = _unique_sorted(self.member_ids, "conflicting member IDs")
        if not fields or not set(fields).issubset(SHARE_EVENT_CONFLICT_FIELDS):
            raise ValueError("share-event conflict fields are not registered")
        if len(members) < 2:
            raise ValueError("share-event conflict requires at least two evidence members")
        _sha(self.compared_values_sha256, "compared-values SHA")
        object.__setattr__(self, "conflicting_fields", fields)
        object.__setattr__(self, "member_ids", members)
        if self.conflict_id != self.expected_conflict_id():
            raise ValueError("share-event conflict ID mismatch")
        if self.conflict_fingerprint != self.expected_conflict_fingerprint():
            raise ValueError("share-event conflict fingerprint mismatch")

    def identity_payload(self) -> dict[str, Any]:
        return {
            "conflict_code": self.conflict_code,
            "legal_event_key": self.legal_event_key,
            "conflicting_fields": self.conflicting_fields,
            "member_ids": self.member_ids,
            "compared_values_sha256": self.compared_values_sha256,
        }

    def expected_conflict_id(self) -> str:
        return f"share-event-conflict:{canonical_sha256(self.identity_payload())[:24]}"

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("conflict_fingerprint")
        return payload

    def expected_conflict_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return self.conflict_fingerprint


@dataclass(frozen=True, slots=True)
class ShareEventEvidenceGroup:
    group_id: str
    identity: ShareEventIdentity
    member_ids: tuple[str, ...]
    status: str
    canonical_event_fact_id: str | None
    conflict_ids: tuple[str, ...]
    group_fingerprint: str

    def __post_init__(self) -> None:
        if self.status not in SHARE_EVENT_GROUP_STATUSES:
            raise ValueError("share-event group status is not registered")
        members = _unique_sorted(self.member_ids, "share-event group member IDs")
        conflicts = _unique_sorted(self.conflict_ids, "share-event group conflict IDs")
        if not members:
            raise ValueError("share-event group has no evidence members")
        if self.status == "canonical":
            if self.canonical_event_fact_id is None or conflicts:
                raise ValueError("canonical share-event group lacks one derived event Fact")
        elif self.canonical_event_fact_id is not None or not conflicts:
            raise ValueError("blocked share-event group lacks its conflict evidence")
        object.__setattr__(self, "member_ids", members)
        object.__setattr__(self, "conflict_ids", conflicts)
        if self.group_id != self.expected_group_id():
            raise ValueError("share-event group ID mismatch")
        if self.group_fingerprint != self.expected_group_fingerprint():
            raise ValueError("share-event group fingerprint mismatch")

    def expected_group_id(self) -> str:
        return f"share-event-group:{self.identity.issuer_id}:{self.identity.legal_event_key[:24]}"

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("group_fingerprint")
        return payload

    def expected_group_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return self.group_fingerprint


@dataclass(frozen=True, slots=True)
class ShareEventGroupingResult:
    policy_id: str
    policy_version: str
    grouping_code_sha256: str
    issuer_id: str
    security_id: str
    opening_date: str
    quote_date: str
    status: str
    members: tuple[ShareEventEvidenceMember, ...]
    groups: tuple[ShareEventEvidenceGroup, ...]
    conflicts: tuple[ShareEventConflict, ...]
    grouping_fingerprint: str

    def __post_init__(self) -> None:
        if (self.policy_id, self.policy_version) != (
            SHARE_EVENT_GROUPING_POLICY_ID,
            SHARE_EVENT_GROUPING_POLICY_VERSION,
        ):
            raise ValueError("share-event grouping policy mismatch")
        _sha(self.grouping_code_sha256, "grouping code SHA")
        opening = date.fromisoformat(self.opening_date)
        quote = date.fromisoformat(self.quote_date)
        if opening >= quote:
            raise ValueError("share-event grouping window is invalid")
        if self.status not in SHARE_EVENT_GROUPING_STATUSES:
            raise ValueError("share-event grouping status is not registered")
        members = tuple(sorted(self.members, key=lambda item: item.member_id))
        groups = tuple(sorted(self.groups, key=lambda item: item.group_id))
        conflicts = tuple(sorted(self.conflicts, key=lambda item: item.conflict_id))
        if len(members) != len({item.member_id for item in members}):
            raise ValueError("share-event grouping contains duplicate members")
        if len(groups) != len({item.group_id for item in groups}):
            raise ValueError("share-event grouping contains duplicate groups")
        if len(conflicts) != len({item.conflict_id for item in conflicts}):
            raise ValueError("share-event grouping contains duplicate conflicts")
        member_ids = {item.member_id for item in members}
        conflict_ids = {item.conflict_id for item in conflicts}
        consumed: list[str] = []
        for group in groups:
            if (
                group.identity.issuer_id != self.issuer_id
                or group.identity.security_id != self.security_id
            ):
                raise ValueError("share-event group crosses issuer or security")
            if not set(group.member_ids).issubset(member_ids):
                raise ValueError("share-event group contains a dangling member")
            if not set(group.conflict_ids).issubset(conflict_ids):
                raise ValueError("share-event group contains a dangling conflict")
            consumed.extend(group.member_ids)
        if sorted(consumed) != sorted(member_ids) or len(consumed) != len(set(consumed)):
            raise ValueError("share-event members are not consumed exactly once")
        if self.status == "grouped" and (
            conflicts or any(group.status != "canonical" for group in groups)
        ):
            raise ValueError("grouped share-event result contains unresolved conflicts")
        if self.status == "blocked" and not conflicts:
            raise ValueError("blocked share-event result lacks a conflict")
        object.__setattr__(self, "members", members)
        object.__setattr__(self, "groups", groups)
        object.__setattr__(self, "conflicts", conflicts)
        if self.grouping_fingerprint != self.expected_grouping_fingerprint():
            raise ValueError("share-event grouping fingerprint mismatch")

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("grouping_fingerprint")
        return payload

    def expected_grouping_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return self.grouping_fingerprint


def share_event_grouping_policy_sha256() -> str:
    return canonical_sha256(
        {
            "policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
            "policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
            "concept_policies": dict(SHARE_EVENT_CONCEPT_POLICIES),
            "conflict_codes": sorted(SHARE_EVENT_CONFLICT_CODES),
            "conflict_fields": sorted(SHARE_EVENT_CONFLICT_FIELDS),
        }
    )


__all__ = (
    "SHARE_EVENT_CONCEPT_POLICIES",
    "SHARE_EVENT_CONFLICT_CODES",
    "SHARE_EVENT_GROUPING_POLICY_ID",
    "SHARE_EVENT_GROUPING_POLICY_VERSION",
    "ShareEventConflict",
    "ShareEventEvidenceGroup",
    "ShareEventEvidenceMember",
    "ShareEventGroupingResult",
    "ShareEventIdentity",
    "share_event_grouping_policy_sha256",
)
