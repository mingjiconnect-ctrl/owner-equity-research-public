from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import subprocess
import sys
from copy import copy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
import test_phase5d5_price_blind_freeze as phase5d5_freeze_test
from phase4a_support import replace_graph
from phase5e2a_support import (
    _phase5c_readiness_payload,
    resign_price_blind_artifact,
)
from test_phase4e0_research_bundle import _bundle_graph
from test_phase5d5_price_blind_freeze import _compile

import owner_research
import owner_research.valuation_share_event_integration_types as integration_types
from owner_research.analytical_claims import review_analytical_claim_candidate
from owner_research.calculation_integrity import build_calculation_result
from owner_research.capital_allocation_ledger import (
    build_event_candidate,
    compile_event,
    review_event_candidate,
)
from owner_research.capital_allocation_policies import EVENT_TYPES, SOURCE_FAMILIES
from owner_research.capital_allocation_reviews import build_capital_allocation_review
from owner_research.contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    Assumption,
    Claim,
    Fact,
    FilingArtifact,
    SourceDocument,
)
from owner_research.fingerprints import canonical_sha256
from owner_research.research_bundle_builder import build_research_bundle
from owner_research.research_bundle_policies import (
    dependency_closure_sha256,
)
from owner_research.research_bundle_validation import dependency_closure
from owner_research.source_search_receipts import build_source_search_receipt
from owner_research.validation import ContractGraph
from owner_research.valuation_current_share_evidence import (
    CLAIM_SENSITIVE_EVENT_CONCEPTS,
    COMPLETED_SHARE_EVENT_SIGNS,
    EVENT_CONCEPT_TO_COVERAGE_CATEGORY,
)
from owner_research.valuation_handoff_validation import candidate_evidence_graph_sha256
from owner_research.valuation_market_execution_policies import (
    SECURITY_IDENTITY_POLICY_ID,
    SECURITY_IDENTITY_POLICY_VERSION,
)
from owner_research.valuation_market_execution_types import SecurityIdentityDecision
from owner_research.valuation_price_blind_freeze import PriceBlindFreezeCompilationResult
from owner_research.valuation_security_identity import (
    SECURITY_EVIDENCE_POLICY_ID,
    SECURITY_EVIDENCE_POLICY_VERSION,
    SecurityAccessProposal,
    SecurityFactBinding,
    SecurityIdentityCompilationResult,
    SecurityIdentityEvidenceClosure,
)
from owner_research.valuation_share_event_grouping import _grouping_code_sha256
from owner_research.valuation_share_event_identity import (
    SHARE_EVENT_GROUPING_POLICY_ID,
    SHARE_EVENT_GROUPING_POLICY_VERSION,
    ShareEventEvidenceGroup,
    ShareEventEvidenceMember,
    ShareEventGroupingResult,
    ShareEventIdentity,
)
from owner_research.valuation_share_event_integration_types import (
    CANONICAL_EVENT_DERIVATION,
    CLAIM_TRANSITION_DERIVATION,
    COVERAGE_SEARCH_AUTHORITY_ID,
    COVERAGE_SEARCH_AUTHORITY_VERSION,
    COVERAGE_SEARCH_ENDPOINTS,
    COVERAGE_SEARCH_TOOL_VERSION,
    CURRENT_SHARE_EXTENSION_POLICY_ID,
    CURRENT_SHARE_EXTENSION_POLICY_VERSION,
    CURRENT_SHARE_INTEGRATION_POLICY_ID,
    CURRENT_SHARE_INTEGRATION_POLICY_VERSION,
    CURRENT_SHARE_ROLLFORWARD_DERIVATION,
    CanonicalShareEventFactMaterialization,
    CanonicalShareEventMemberBinding,
    CorporateActionCoverageEntryV2,
    CorporateActionCoverageLedgerV2,
    CurrentShareBundleEvidenceClosure,
    CurrentShareEvidenceClosureV2,
    GroupBoundClaimTransition,
    GroupBoundClaimTransitionReconciliation,
    GroupBoundDilutionClaimAuthority,
    ShareEventNumericConsumption,
    _canonical_event_source_locator,
    _claim_transition_source_locator,
    _current_share_v2_closure_id,
    _fact_share_integer,
    _integer_decimal,
    _output_share_source_locator,
    _primary_member_source_id,
    _remaining_claim_fact_id,
    _reserved_output_share_fact_id,
    _scoped_contract_graph_fingerprint,
    _typed_extension_dependency_closure,
    _validate_official_occurrence_collision_domain,
    coverage_search_authority_sha256,
    current_share_integration_code_sha256,
    current_share_integration_contract_sha256,
    current_share_integration_policy_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
ISSUER = "issuer:acme"
SECURITY = "security:issuer:acme:XNYS:ACME:common"
OPENING_DATE = "2026-03-31"
EVENT_DATE = "2026-06-15"
QUOTE_DATE = "2026-06-30"
CUTOFF = "2026-06-30"
ISSUER_CIK = "0000000123"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64


def _fingerprinted(cls, payload: dict, field: str):
    normalized = dict(payload)
    normalized[field] = canonical_sha256(normalized)
    return cls(**normalized)


def _source(
    suffix: str,
    *,
    document_type: str,
    authority_level: str = "primary_regulatory",
    published_date: str = "2026-06-20",
) -> SourceDocument:
    return SourceDocument(
        schema_version="1.0.0",
        document_id=f"doc:acme:{suffix}",
        issuer_id=ISSUER,
        document_type=document_type,
        period={"start": "2026-01-01", "end": QUOTE_DATE},
        published_date=published_date,
        retrieved_at="2026-07-01T00:00:00Z",
        source_url=(
            f"https://www.sec.gov/Archives/{suffix}.htm"
            if authority_level == "primary_regulatory"
            else f"https://investor.acme.example/{suffix}"
        ),
        authority_level=authority_level,
        content_sha256=canonical_sha256({"source": suffix}),
    )


def _fact(
    *,
    fact_id: str,
    concept: str,
    value: int,
    source: SourceDocument,
    end: str,
    start: str | None = None,
    unit: str = "shares",
    currency: str | None = None,
    derivation: str | None = None,
    parents: tuple[str, ...] = (),
    confidence: str = "high",
    source_locator: str | None = None,
) -> Fact:
    return Fact(
        schema_version="2.0.0",
        fact_id=fact_id,
        issuer_id=ISSUER,
        concept=concept,
        value_type="number",
        value=value,
        unit=unit,
        currency=currency,
        period={"start": start, "end": end},
        source_document_id=source.document_id,
        source_locator=source_locator or f"fixture:{fact_id}",
        derivation=derivation,
        parent_fact_ids=parents,
        confidence=confidence,
    )


def _identity(
    *,
    event,
    concept: str = "common_shares_repurchased_completed",
    magnitude: str = "5000000",
    event_date: str = EVENT_DATE,
) -> ShareEventIdentity:
    components = {
        str(item["role"]): str(item["value"]).casefold() for item in event.identity_components
    }
    legal_role = "program_id" if "program_id" in components else "plan_id"
    official_legal_event_id = f"{legal_role}:{components[legal_role]}"
    occurrence = canonical_sha256(
        {
            "economic_event_key": event.economic_event_key,
            "official_legal_event_id": official_legal_event_id,
            "legal_effective_date": event_date,
        }
    )
    payload = {
        "policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
        "policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
        "issuer_id": ISSUER,
        "security_id": SECURITY,
        "economic_event_key": event.economic_event_key,
        "official_legal_event_id": official_legal_event_id,
        "execution_occurrence_id": occurrence,
        "event_concept": concept,
        "legal_effective_date": event_date,
        "canonical_share_magnitude": magnitude,
        "event_grain": "incremental_completed_execution",
    }
    payload["legal_event_key"] = canonical_sha256(
        {
            key: payload[key]
            for key in (
                "issuer_id",
                "security_id",
                "economic_event_key",
                "official_legal_event_id",
                "execution_occurrence_id",
            )
        }
    )
    payload["identity_fingerprint"] = canonical_sha256(payload)
    return ShareEventIdentity(**payload)


def _member(
    identity: ShareEventIdentity,
    raw_fact: Fact,
    source: SourceDocument,
    event,
    candidate,
    decision,
) -> ShareEventEvidenceMember:
    payload = {
        "legal_event_key": identity.legal_event_key,
        "fact_id": raw_fact.fact_id,
        "fact_fingerprint": raw_fact.fingerprint,
        "source_document_id": source.document_id,
        "source_document_fingerprint": source.fingerprint,
        "source_locator": raw_fact.source_locator,
        "source_authority_level": source.authority_level,
        "source_published_date": source.published_date,
        "fact_measurement_date": identity.legal_effective_date,
        "data_cutoff_date": CUTOFF,
        "capital_allocation_event_id": event.event_id,
        "capital_allocation_event_fingerprint": event.fingerprint,
        "candidate_ids": (candidate.candidate_id,),
        "review_decision_ids": (decision.decision_id,),
    }
    member_identity = {
        key: payload[key]
        for key in (
            "legal_event_key",
            "fact_id",
            "fact_fingerprint",
            "source_document_id",
            "source_document_fingerprint",
            "source_locator",
            "capital_allocation_event_id",
            "capital_allocation_event_fingerprint",
            "candidate_ids",
            "review_decision_ids",
        )
    }
    full = {
        "member_id": f"share-event-member:{canonical_sha256(member_identity)[:24]}",
        **payload,
    }
    full["member_fingerprint"] = canonical_sha256(full)
    return ShareEventEvidenceMember(**full)


def _grouping(
    *,
    corroborating_count: int = 1,
    concept: str = "common_shares_repurchased_completed",
    event_date: str = EVENT_DATE,
    identity_suffix: str = "2026",
) -> tuple:
    is_buyback = concept == "common_shares_repurchased_completed"
    event_type = "buyback" if is_buyback else "equity_issuance"
    event_subtype = "open_market" if is_buyback else "public_offering"
    fact_role = "shares_repurched" if is_buyback else "shares_issued"
    identity_components = (
        (
            {"role": "program_id", "value": f"{concept}-program-{identity_suffix}"},
            {"role": "approval_date", "value": "2026-01-15"},
            {"role": "security_class", "value": "common"},
        )
        if is_buyback
        else (
            {"role": "program_id", "value": f"{concept}-program-{identity_suffix}"},
            {"role": "security_class", "value": "common"},
        )
    )
    sources: list[SourceDocument] = []
    facts: list[Fact] = []
    candidates = []
    decisions = []
    for index in range(corroborating_count):
        suffix = f"{concept}-{identity_suffix}-event-{index}"
        raw = f"Official completed share event {suffix}".encode()
        source = replace(
            _source(suffix, document_type="8-K"),
            content_sha256=hashlib.sha256(raw).hexdigest(),
        )
        fact = _fact(
            fact_id=f"fact:event:{identity_suffix}:{index}",
            concept=concept,
            value=5_000_000,
            source=source,
            end=event_date,
        )
        candidate = build_event_candidate(
            raw=raw,
            source_document=source,
            start=0,
            end=len(raw.decode()),
            as_of_date=source.published_date,
            event_type=event_type,
            event_subtype=event_subtype,
            scope={
                "scope_type": "issuer_wide",
                "segment_definition_ids": [],
                "business_unit": None,
                "product_service": None,
                "geography": None,
                "customer_group": None,
                "channel": None,
            },
            identity_components=identity_components,
            announcement_date="2026-01-15",
            execution_period={"start": event_date, "end": event_date},
            growth_classification="not_applicable",
            source_role="completion",
            fact_bindings=(
                {
                    "binding_id": f"binding:{suffix}",
                    "fact_id": fact.fact_id,
                    "role_id": fact_role,
                },
            ),
            extraction_method="deterministic",
            facts=(fact,),
            existing_candidates=tuple(candidates),
        )
        decision = review_event_candidate(
            candidate,
            source_document=source,
            decision="confirmed",
            reviewer_id=f"human:{suffix}",
            reviewed_at="2026-06-20T21:00:00Z",
            rationale="Named human confirmed the completed share event.",
            existing_decisions=tuple(decisions),
        )
        sources.append(source)
        facts.append(fact)
        candidates.append(candidate)
        decisions.append(decision)
    event = compile_event(
        candidates=tuple(candidates),
        decisions=tuple(decisions),
        source_documents=tuple(sources),
        facts=tuple(facts),
        as_of_date=CUTOFF,
    ).event
    identity = _identity(
        event=event,
        concept=concept,
        magnitude="5000000",
        event_date=event_date,
    )
    members = tuple(
        _member(identity, fact, source, event, candidate, decision)
        for fact, source, candidate, decision in zip(
            facts,
            sources,
            candidates,
            decisions,
            strict=True,
        )
    )
    group_payload = {
        "group_id": f"share-event-group:{ISSUER}:{identity.legal_event_key[:24]}",
        "identity": identity,
        "member_ids": tuple(sorted(item.member_id for item in members)),
        "status": "canonical",
        "canonical_event_fact_id": (f"derived:share-event:{identity.identity_fingerprint[:24]}"),
        "conflict_ids": (),
    }
    group = _fingerprinted(ShareEventEvidenceGroup, group_payload, "group_fingerprint")
    result_payload = {
        "policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
        "policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
        "grouping_code_sha256": _grouping_code_sha256(),
        "issuer_id": ISSUER,
        "security_id": SECURITY,
        "opening_date": OPENING_DATE,
        "quote_date": QUOTE_DATE,
        "status": "grouped",
        "members": tuple(sorted(members, key=lambda item: item.member_id)),
        "groups": (group,),
        "conflicts": (),
    }
    result = _fingerprinted(ShareEventGroupingResult, result_payload, "grouping_fingerprint")
    return (
        result,
        tuple(facts),
        tuple(sources),
        tuple(candidates),
        tuple(decisions),
        event,
    )


def _empty_grouping() -> ShareEventGroupingResult:
    return _fingerprinted(
        ShareEventGroupingResult,
        {
            "policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
            "policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
            "grouping_code_sha256": _grouping_code_sha256(),
            "issuer_id": ISSUER,
            "security_id": SECURITY,
            "opening_date": OPENING_DATE,
            "quote_date": QUOTE_DATE,
            "status": "grouped",
            "members": (),
            "groups": (),
            "conflicts": (),
        },
        "grouping_fingerprint",
    )


def _official_occurrence_split_groups() -> tuple[
    ShareEventEvidenceGroup,
    ShareEventEvidenceGroup,
    tuple[ShareEventEvidenceMember, ...],
]:
    first, *_ = _grouping(identity_suffix="first")
    second, *_ = _grouping(identity_suffix="second")
    first_group = first.groups[0]
    second_group = second.groups[0]
    identity_payload = second_group.identity.fingerprint_payload()
    identity_payload["official_legal_event_id"] = (
        first_group.identity.official_legal_event_id
    )
    identity_payload["execution_occurrence_id"] = canonical_sha256(
        {
            "economic_event_key": identity_payload["economic_event_key"],
            "official_legal_event_id": identity_payload["official_legal_event_id"],
            "legal_effective_date": identity_payload["legal_effective_date"],
        }
    )
    identity_payload["legal_event_key"] = canonical_sha256(
        {
            key: identity_payload[key]
            for key in (
                "issuer_id",
                "security_id",
                "economic_event_key",
                "official_legal_event_id",
                "execution_occurrence_id",
            )
        }
    )
    forged_identity = ShareEventIdentity(
        **identity_payload,
        identity_fingerprint=canonical_sha256(identity_payload),
    )
    group_payload = second_group.fingerprint_payload()
    group_payload.update(
        {
            "identity": forged_identity,
            "group_id": (
                f"share-event-group:{ISSUER}:"
                f"{forged_identity.legal_event_key[:24]}"
            ),
            "canonical_event_fact_id": (
                f"derived:share-event:{forged_identity.identity_fingerprint[:24]}"
            ),
        }
    )
    forged_group = ShareEventEvidenceGroup(
        **group_payload,
        group_fingerprint=canonical_sha256(group_payload),
    )
    return (
        first_group,
        forged_group,
        tuple(sorted((*first.members, *second.members), key=lambda item: item.member_id)),
    )


def test_validation_boundary_rejects_one_official_occurrence_split_across_groups() -> None:
    first_group, forged_group, _members = _official_occurrence_split_groups()

    with pytest.raises(ValueError, match="split across legal identities"):
        _validate_official_occurrence_collision_domain((first_group, forged_group))


def _materialization(
    *,
    corroborating_count: int = 1,
    grouping: ShareEventGroupingResult | None = None,
    raw_facts: tuple[Fact, ...] | None = None,
    event_sources: tuple[SourceDocument, ...] | None = None,
    event_candidates: tuple | None = None,
    event_decisions: tuple | None = None,
    capital_event=None,
) -> CanonicalShareEventFactMaterialization:
    if (
        grouping is None
        or raw_facts is None
        or event_sources is None
        or event_candidates is None
        or event_decisions is None
        or capital_event is None
    ):
        (
            grouping,
            raw_facts,
            event_sources,
            event_candidates,
            event_decisions,
            capital_event,
        ) = _grouping(corroborating_count=corroborating_count)
    group = grouping.groups[0]
    bindings = tuple(
        _fingerprinted(
            CanonicalShareEventMemberBinding,
            {
                "issuer_id": ISSUER,
                "security_id": SECURITY,
                "data_cutoff_date": CUTOFF,
                "member": member,
                "fact": next(item for item in raw_facts if item.fact_id == member.fact_id),
                "source_document": next(
                    item for item in event_sources if item.document_id == member.source_document_id
                ),
                "capital_allocation_event": capital_event,
                "candidates": (candidate,),
                "review_decisions": (decision,),
                "member_id": member.member_id,
                "member_fingerprint": member.member_fingerprint,
                "fact_id": member.fact_id,
                "fact_fingerprint": member.fact_fingerprint,
                "source_document_id": member.source_document_id,
                "source_document_fingerprint": member.source_document_fingerprint,
                "capital_allocation_event_id": member.capital_allocation_event_id,
                "capital_allocation_event_fingerprint": (
                    member.capital_allocation_event_fingerprint
                ),
                "candidate_bindings": ((candidate.candidate_id, candidate.fingerprint),),
                "review_decision_bindings": ((decision.decision_id, decision.fingerprint),),
            },
            "binding_fingerprint",
        )
        for member in grouping.members
        for candidate in event_candidates
        for decision in event_decisions
        if candidate.candidate_id in member.candidate_ids
        and decision.decision_id in member.review_decision_ids
    )
    primary_source_id = _primary_member_source_id(bindings)
    primary_source = next(item for item in event_sources if item.document_id == primary_source_id)
    canonical_fact = _fact(
        fact_id=str(group.canonical_event_fact_id),
        concept=group.identity.event_concept,
        value=int(group.identity.canonical_share_magnitude),
        source=primary_source,
        end=group.identity.legal_effective_date,
        derivation=CANONICAL_EVENT_DERIVATION,
        parents=tuple(sorted(item.fact_id for item in raw_facts)),
        source_locator=_canonical_event_source_locator(str(group.canonical_event_fact_id)),
    )
    return _fingerprinted(
        CanonicalShareEventFactMaterialization,
        {
            "policy_id": CURRENT_SHARE_INTEGRATION_POLICY_ID,
            "policy_version": CURRENT_SHARE_INTEGRATION_POLICY_VERSION,
            "materialization_code_sha256": current_share_integration_code_sha256(),
            "issuer_id": ISSUER,
            "security_id": SECURITY,
            "opening_date": OPENING_DATE,
            "quote_date": QUOTE_DATE,
            "data_cutoff_date": CUTOFF,
            "grouping_result": grouping,
            "group": group,
            "canonical_event_fact": canonical_fact,
            "grouping_result_fingerprint": grouping.grouping_fingerprint,
            "group_id": group.group_id,
            "group_fingerprint": group.group_fingerprint,
            "identity_fingerprint": group.identity.identity_fingerprint,
            "canonical_event_fact_id": str(group.canonical_event_fact_id),
            "canonical_event_fact_fingerprint": canonical_fact.fingerprint,
            "event_concept": group.identity.event_concept,
            "legal_effective_date": group.identity.legal_effective_date,
            "canonical_share_magnitude": group.identity.canonical_share_magnitude,
            "primary_source_document_id": primary_source.document_id,
            "members": bindings,
        },
        "materialization_fingerprint",
    )


def _consumption(item: CanonicalShareEventFactMaterialization):
    return _fingerprinted(
        ShareEventNumericConsumption,
        {
            "group_id": item.group_id,
            "group_fingerprint": item.group_fingerprint,
            "identity_fingerprint": item.identity_fingerprint,
            "canonical_event_fact_id": item.canonical_event_fact_id,
            "canonical_event_fact_fingerprint": item.canonical_event_fact_fingerprint,
            "event_concept": item.event_concept,
            "sign": format(COMPLETED_SHARE_EVENT_SIGNS[item.event_concept], "f"),
            "channel": "current_share_rollforward",
            "window_start": OPENING_DATE,
            "window_end": QUOTE_DATE,
        },
        "consumption_fingerprint",
    )


def _coverage_documents() -> tuple[SourceDocument, SourceDocument]:
    return (
        _source("opening", document_type="10-Q"),
        _source("coverage", document_type="10-K"),
    )


def _receipts(
    sources: tuple[SourceDocument, ...],
    *,
    period_end: str = QUOTE_DATE,
    cutoff_date: str = CUTOFF,
) -> tuple:
    by_family = {
        "10-K": tuple(item for item in sources if item.document_type == "10-K"),
        "10-Q": tuple(item for item in sources if item.document_type == "10-Q"),
        "8-K": tuple(item for item in sources if item.document_type == "8-K"),
    }
    return tuple(
        build_source_search_receipt(
            issuer_id=ISSUER,
            source_family_id=family,
            query_scope={
                "cik": ISSUER_CIK,
                "event_types": sorted(EVENT_TYPES),
            },
            period={"start": OPENING_DATE, "end": period_end},
            cutoff_date=cutoff_date,
            searched_endpoints=COVERAGE_SEARCH_ENDPOINTS[family],
            result_documents=by_family.get(family, ()),
            completed_at="2026-07-16T01:00:00Z",
            tool_version=COVERAGE_SEARCH_TOOL_VERSION,
        )
        for family in sorted(SOURCE_FAMILIES)
    )


def _coverage(
    materialization: CanonicalShareEventFactMaterialization | None,
    coverage_source: SourceDocument,
    receipts: tuple,
    result_sources: tuple[SourceDocument, ...],
    *,
    period_end: str = QUOTE_DATE,
    data_cutoff_date: str = CUTOFF,
) -> CorporateActionCoverageLedgerV2:
    receipt_ids = tuple(sorted(item.receipt_id for item in receipts))
    observed_category = (
        EVENT_CONCEPT_TO_COVERAGE_CATEGORY[materialization.event_concept]
        if materialization is not None
        else None
    )
    entries: list[CorporateActionCoverageEntryV2] = []
    for category in CorporateActionCoverageLedgerV2.required_categories():
        if category == observed_category and materialization is not None:
            values = {
                "category": category,
                "status": "observed",
                "group_ids": (materialization.group_id,),
                "canonical_event_fact_ids": (materialization.canonical_event_fact_id,),
                "member_event_fact_ids": tuple(
                    sorted(item.fact_id for item in materialization.members)
                ),
                "observed_member_facts": tuple(
                    sorted(
                        (item.fact for item in materialization.members),
                        key=lambda item: item.fact_id,
                    )
                ),
                "observed_member_source_documents": tuple(
                    sorted(
                        (item.source_document for item in materialization.members),
                        key=lambda item: item.document_id,
                    )
                ),
                "zero_fact_id": None,
                "zero_fact": None,
            }
        else:
            zero = _fact(
                fact_id=f"fact:coverage-zero:{category}",
                concept=f"share_activity_{category}_count",
                value=0,
                source=coverage_source,
                start=OPENING_DATE,
                end=period_end,
                unit="count",
            )
            values = {
                "category": category,
                "status": "official_zero_or_no_activity",
                "group_ids": (),
                "canonical_event_fact_ids": (),
                "member_event_fact_ids": (),
                "observed_member_facts": (),
                "observed_member_source_documents": (),
                "zero_fact_id": zero.fact_id,
                "zero_fact": zero,
            }
        entries.append(
            _fingerprinted(
                CorporateActionCoverageEntryV2,
                {
                    **values,
                    "not_applicable_claim_id": None,
                    "not_applicable_claim": None,
                    "not_applicable_candidate": None,
                    "review_decision_id": None,
                    "review_decision": None,
                    "not_applicable_supporting_facts": (),
                    "not_applicable_counterevidence_facts": (),
                    "source_search_receipt_ids": receipt_ids,
                },
                "entry_fingerprint",
            )
        )
    payload = {
        "issuer_id": ISSUER,
        "issuer_cik": ISSUER_CIK,
        "security_id": SECURITY,
        "period_start": OPENING_DATE,
        "period_end": period_end,
        "data_cutoff_date": data_cutoff_date,
        "expected_group_ids": (() if materialization is None else (materialization.group_id,)),
        "entries": tuple(sorted(entries, key=lambda item: item.category)),
        "receipts": tuple(sorted(receipts, key=lambda item: item.source_family)),
        "result_source_documents": tuple(sorted(result_sources, key=lambda item: item.document_id)),
        "receipt_ids": receipt_ids,
        "search_authority_id": COVERAGE_SEARCH_AUTHORITY_ID,
        "search_authority_version": COVERAGE_SEARCH_AUTHORITY_VERSION,
        "search_authority_code_sha256": coverage_search_authority_sha256(),
    }
    payload["ledger_sha256"] = canonical_sha256(payload)
    return CorporateActionCoverageLedgerV2(**payload)


def _coverage_payload(
    ledger: CorporateActionCoverageLedgerV2,
    **updates,
) -> dict:
    payload = {
        "issuer_id": ledger.issuer_id,
        "issuer_cik": ledger.issuer_cik,
        "security_id": ledger.security_id,
        "period_start": ledger.period_start,
        "period_end": ledger.period_end,
        "data_cutoff_date": ledger.data_cutoff_date,
        "expected_group_ids": ledger.expected_group_ids,
        "entries": ledger.entries,
        "receipts": ledger.receipts,
        "result_source_documents": ledger.result_source_documents,
        "receipt_ids": ledger.receipt_ids,
        "search_authority_id": ledger.search_authority_id,
        "search_authority_version": ledger.search_authority_version,
        "search_authority_code_sha256": ledger.search_authority_code_sha256,
    }
    payload.update(updates)
    payload["ledger_sha256"] = canonical_sha256(payload)
    return payload


def _not_applicable_coverage_entry(
    *,
    category: str,
    source: SourceDocument,
    receipt_ids: tuple[str, ...],
    security_id: str = SECURITY,
    as_of_date: str = QUOTE_DATE,
    reviewer_id: str = "human:mingji",
    reviewed_at: str = "2026-06-30T12:00:00Z",
    support_fact: Fact | None = None,
    counterevidence_fact: Fact | None = None,
) -> tuple[
    CorporateActionCoverageEntryV2,
    Fact,
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    Claim,
]:
    support = support_fact or _fact(
        fact_id=f"fact:coverage-na:{category}",
        concept=f"share_activity_{category}_not_applicable_evidence",
        value=1,
        source=source,
        end=as_of_date,
        unit="count",
    )
    statement = (
        f"Share activity category {category} is not applicable to security {security_id}."
    )
    binding = {
        "binding_id": f"binding:coverage-na:{category}",
        "fact_id": support.fact_id,
        "calculation_result_id": None,
        "context_observation_id": None,
    }
    counterevidence_binding = (
        {
            "binding_id": f"binding:coverage-na:{category}:counterevidence",
            "fact_id": counterevidence_fact.fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
        if counterevidence_fact is not None
        else None
    )
    counterevidence_bindings = (
        (counterevidence_binding,) if counterevidence_binding is not None else ()
    )
    evidence_graph_sha256 = canonical_sha256(
        {
            "supporting_evidence_bindings": (binding,),
            "counterevidence_bindings": counterevidence_bindings,
        }
    )
    candidate = AnalyticalClaimCandidate(
        schema_version="2.0.0",
        candidate_id=f"candidate:coverage-na:{category}",
        issuer_id=ISSUER,
        as_of_date=as_of_date,
        proposed_statement=statement,
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        claim_role="not_applicable",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=(binding,),
        counterevidence_bindings=counterevidence_bindings,
        counterevidence_search_note=(
            f"Reviewed all governed source families for {category} activity."
        ),
        proposed_confidence="high",
        falsification_condition=(
            f"A formal source identifies completed {category} activity for this security."
        ),
        generation_method="manual",
        evidence_graph_sha256=evidence_graph_sha256,
        validation_status="ready",
        validation_issues=(),
    )
    claim, decision = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id=reviewer_id,
        reviewed_at=reviewed_at,
        rationale="Named human review confirmed category-specific non-applicability.",
    )
    assert claim is not None
    entry = _fingerprinted(
        CorporateActionCoverageEntryV2,
        {
            "category": category,
            "status": "not_applicable_with_reviewed_proof",
            "group_ids": (),
            "canonical_event_fact_ids": (),
            "member_event_fact_ids": (),
            "observed_member_facts": (),
            "observed_member_source_documents": (),
            "zero_fact_id": None,
            "zero_fact": None,
            "not_applicable_claim_id": claim.claim_id,
            "not_applicable_claim": claim,
            "not_applicable_candidate": candidate,
            "review_decision_id": decision.decision_id,
            "review_decision": decision,
            "not_applicable_supporting_facts": (support,),
            "not_applicable_counterevidence_facts": (
                (counterevidence_fact,) if counterevidence_fact is not None else ()
            ),
            "source_search_receipt_ids": receipt_ids,
        },
        "entry_fingerprint",
    )
    return entry, support, candidate, decision, claim


def _entries_with_receipts(
    entries: tuple[CorporateActionCoverageEntryV2, ...],
    receipt_ids: tuple[str, ...],
) -> tuple[CorporateActionCoverageEntryV2, ...]:
    updated = []
    for item in entries:
        payload = {
            **item.fingerprint_payload(),
            "source_search_receipt_ids": receipt_ids,
        }
        updated.append(
            replace(
                item,
                source_search_receipt_ids=receipt_ids,
                entry_fingerprint=canonical_sha256(payload),
            )
        )
    return tuple(updated)


def _claim_authority(
    sample_payloads,
    monkeypatch,
    *root_facts: Fact,
) -> GroupBoundDilutionClaimAuthority:
    authority, _graph, _freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        *root_facts,
    )
    return authority


def _claim_authority_context(
    sample_payloads,
    monkeypatch,
    *root_facts: Fact,
) -> tuple[
    GroupBoundDilutionClaimAuthority,
    ContractGraph,
    PriceBlindFreezeCompilationResult,
]:
    graph, freeze = _compile(sample_payloads, monkeypatch)
    frozen = freeze.artifact.to_dict()
    readiness = _phase5c_readiness_payload(
        issuer_id=frozen["issuer_id"],
        cutoff=frozen["data_cutoff_date"],
    )
    roots = tuple(sorted(item.fact_id for item in root_facts))
    if not roots:
        raise ValueError("graph-owned Claim authority fixture requires roots")
    source = next(item for item in graph.documents if item.authority_level == "primary_regulatory")
    normalized_roots = tuple(
        replace(item, source_document_id=source.document_id) for item in root_facts
    )
    diluted_fact = _fact(
        fact_id="fact:acme:phase5c:diluted-shares:2026",
        concept="diluted_shares",
        value=100_000_000,
        source=source,
        end=OPENING_DATE,
    )
    binding = {
        "binding_id": "economic-claim-binding:phase5c-reviewed-option-authority",
        "economic_identity": "option_or_dilution_claim",
        "identity_kind": "program",
        "identity_value": "fixture-option-program",
        "scope_id": f"scope:{ISSUER}:issuer-wide",
        "measurement_end": OPENING_DATE,
        "security_class": "common",
        "economic_claim_key": "",
        "status": "confirmed",
        "root_fact_ids": list(roots),
        "identity_evidence_fact_ids": list(roots),
        "diluted_share_treatment": "excluded",
        "diluted_share_fact_ids": [diluted_fact.fact_id],
        "candidate_id": "analytical-candidate:phase5c-reviewed-option-authority",
        "review_decision_id": "",
        "claim_id": "",
        "missing_evidence": [],
        "reason_codes": [],
    }
    binding["economic_claim_key"] = integration_types._phase5c_economic_claim_key(
        issuer_id=ISSUER,
        binding=binding,
    )
    support_ids = tuple(sorted({*roots, diluted_fact.fact_id}))
    supporting = tuple(
        {
            "binding_id": f"binding:phase5c-option:{fact_id}",
            "fact_id": fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
        for fact_id in support_ids
    )
    evidence_sha = canonical_sha256(
        {
            "supporting_evidence_bindings": supporting,
            "counterevidence_bindings": (),
        }
    )
    candidate = AnalyticalClaimCandidate(
        schema_version="2.0.0",
        candidate_id=binding["candidate_id"],
        issuer_id=ISSUER,
        as_of_date=OPENING_DATE,
        proposed_statement=integration_types._phase5c_economic_claim_statement(binding),
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        claim_role="support",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=supporting,
        counterevidence_bindings=(),
        counterevidence_search_note=(
            "Reviewed the plan, security class, diluted-share perimeter, and conflicting evidence."
        ),
        proposed_confidence="high",
        falsification_condition=(
            "A conflicting formal plan identity or diluted-share perimeter falsifies the binding."
        ),
        generation_method="manual",
        evidence_graph_sha256=evidence_sha,
        validation_status="ready",
        validation_issues=(),
    )
    claim, decision = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id="human:mingji",
        reviewed_at="2026-03-31T12:00:00Z",
        rationale="Named human review confirmed the Phase 5C economic-claim identity.",
    )
    assert claim is not None
    binding["review_decision_id"] = decision.decision_id
    binding["claim_id"] = claim.claim_id
    bridge = readiness["equity_bridge_result"]
    reconciliation = bridge["method_view_result"]["reconciliation_result"]
    reconciliation["economic_claim_bindings"] = [binding]
    reconciliation["economic_claim_candidates"] = [candidate.to_dict()]
    reconciliation["economic_claim_review_decisions"] = [decision.to_dict()]
    reconciliation["economic_claims"] = [claim.to_dict()]
    bridge["diluted_shares_fact_id"] = diluted_fact.fact_id
    bridge["diluted_share_root_fact_ids"] = [diluted_fact.fact_id]
    bridge["role_decisions"][0]["root_fact_ids"] = list(roots)
    bridge["role_decisions"][0]["status"] = "modeled"
    bridge["consumption_records"] = [
        {
            "root_fact_id": root_id,
            "economic_claim_key": binding["economic_claim_key"],
            "economic_identity": "option_or_dilution_claim",
            "channel": "mckinsey_equity_bridge",
            "method": "mckinsey",
            "group_id": "equity-bridge:option_or_dilution_claim",
            "consumption_kind": "economic_deduction",
        }
        for root_id in roots
    ]
    readiness["equity_bridge_fingerprint"] = canonical_sha256(bridge)
    artifact = resign_price_blind_artifact(freeze.artifact, readiness)
    handoffs = tuple(
        replace(
            item,
            price_blind_input_fingerprint=artifact.fingerprint,
            protected_mckinsey_sha256=artifact.payload["protected_mckinsey_sha256"],
        )
        if item.state in {"price_blind_input_frozen", "market_reference_allowed"}
        else item
        for item in freeze.handoffs
    )
    rebound = PriceBlindFreezeCompilationResult(
        artifact=artifact,
        handoffs=handoffs,
        candidates=freeze.candidates,
        decisions=freeze.decisions,
        supplemental_reference_closure=freeze.supplemental_reference_closure,
    )
    documents = {item.document_id: item for item in graph.documents}
    facts = {item.fact_id: item for item in graph.facts}
    facts.update({item.fact_id: item for item in normalized_roots})
    facts[diluted_fact.fact_id] = diluted_fact
    claims = {item.claim_id: item for item in graph.claims}
    claims[claim.claim_id] = claim
    analytical_candidates = {item.candidate_id: item for item in graph.analytical_claim_candidates}
    analytical_candidates[candidate.candidate_id] = candidate
    analytical_decisions = {
        item.decision_id: item for item in graph.analytical_claim_review_decisions
    }
    analytical_decisions[decision.decision_id] = decision
    graph = replace_graph(
        graph,
        documents=tuple(documents.values()),
        facts=tuple(facts.values()),
        claims=tuple(claims.values()),
        analytical_claim_candidates=tuple(analytical_candidates.values()),
        analytical_claim_review_decisions=tuple(analytical_decisions.values()),
        valuation_assumption_candidates=freeze.candidates,
        valuation_assumption_review_decisions=freeze.decisions,
        valuation_handoffs=rebound.handoffs,
        component_lock_path=ROOT / "component-lock.json",
    )
    graph.validate()
    authority = GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
        freeze=rebound,
        validation_graph=graph,
    )
    return authority, graph, rebound


def _rebind_freeze_with_readiness(
    freeze: PriceBlindFreezeCompilationResult,
    readiness: dict,
) -> PriceBlindFreezeCompilationResult:
    artifact = resign_price_blind_artifact(freeze.artifact, readiness)
    handoffs = tuple(
        replace(
            item,
            price_blind_input_fingerprint=artifact.fingerprint,
            protected_mckinsey_sha256=artifact.payload["protected_mckinsey_sha256"],
        )
        if item.state in {"price_blind_input_frozen", "market_reference_allowed"}
        else item
        for item in freeze.handoffs
    )
    return PriceBlindFreezeCompilationResult(
        artifact=artifact,
        handoffs=handoffs,
        candidates=freeze.candidates,
        decisions=freeze.decisions,
        supplemental_reference_closure=freeze.supplemental_reference_closure,
    )


def _empty_transitions() -> GroupBoundClaimTransitionReconciliation:
    payload = {
        "issuer_id": ISSUER,
        "security_id": SECURITY,
        "opening_date": OPENING_DATE,
        "quote_date": QUOTE_DATE,
        "data_cutoff_date": CUTOFF,
        "claim_control_authority": None,
        "claim_control_authority_fingerprint": None,
        "expected_claim_sensitive_group_ids": (),
        "records": (),
    }
    payload["reconciliation_sha256"] = canonical_sha256(payload)
    return GroupBoundClaimTransitionReconciliation(**payload)


def _claim_transition(
    *,
    materialization: CanonicalShareEventFactMaterialization,
    affected_fact: Fact,
    affected_source: SourceDocument,
    remaining_fact_id: str,
    economic_claim_key: str,
    initial_claim_root_fact_id: str | None = None,
) -> GroupBoundClaimTransition:
    initial_root_fact_id = initial_claim_root_fact_id or affected_fact.fact_id
    remaining_fact_id = _remaining_claim_fact_id(
        issuer_id=affected_fact.issuer_id,
        economic_claim_key=economic_claim_key,
        group_id=materialization.group_id,
        affected_claim_root_fact_id=affected_fact.fact_id,
        legal_effective_date=materialization.legal_effective_date,
    )
    remaining_value = int(affected_fact.value) - int(materialization.canonical_share_magnitude)
    remaining_source = affected_source
    remaining_fact = _fact(
        fact_id=remaining_fact_id,
        concept=CLAIM_SENSITIVE_EVENT_CONCEPTS[materialization.event_concept],
        value=remaining_value,
        source=remaining_source,
        end=materialization.legal_effective_date,
        derivation=CLAIM_TRANSITION_DERIVATION,
        parents=tuple(sorted((affected_fact.fact_id, materialization.canonical_event_fact_id))),
        source_locator=_claim_transition_source_locator(remaining_fact_id),
    )
    supporting_fact_ids = tuple(
        sorted(
            {
                affected_fact.fact_id,
                remaining_fact.fact_id,
                *(member.fact_id for member in materialization.members),
            }
        )
    )
    statement = (
        "The reviewed completed share event reconciles the affected dilution claim "
        f"to the disclosed remaining balance for economic claim {economic_claim_key}."
    )
    claim = Claim(
        schema_version="1.0.0",
        claim_id=f"claim:transition:{materialization.group_id}",
        issuer_id=ISSUER,
        statement=statement,
        as_of_date=CUTOFF,
        supporting_fact_ids=supporting_fact_ids,
        counterevidence_fact_ids=(),
        counterevidence_search_note=(
            "Reviewed all formal event and dilution-claim disclosures through cutoff."
        ),
        confidence="high",
        falsification_condition=(
            "A later formal filing shows a different event magnitude or remaining claim."
        ),
    )
    evidence_bindings = tuple(
        {
            "binding_id": f"binding:{fact_id}",
            "fact_id": fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
        for fact_id in supporting_fact_ids
    )
    candidate = AnalyticalClaimCandidate(
        schema_version="2.0.0",
        candidate_id=f"candidate:transition:{materialization.group_id}",
        issuer_id=ISSUER,
        as_of_date=CUTOFF,
        proposed_statement=statement,
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        claim_role="support",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=evidence_bindings,
        counterevidence_bindings=(),
        counterevidence_search_note=claim.counterevidence_search_note,
        proposed_confidence="high",
        falsification_condition=claim.falsification_condition,
        generation_method="manual",
        evidence_graph_sha256=canonical_sha256(
            {
                "supporting_evidence_bindings": evidence_bindings,
                "counterevidence_bindings": (),
            }
        ),
        validation_status="ready",
        validation_issues=(),
    )
    decision = AnalyticalClaimReviewDecision(
        schema_version="1.0.0",
        decision_id=f"decision:transition:{materialization.group_id}",
        issuer_id=ISSUER,
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=candidate.fingerprint,
        evidence_graph_sha256=candidate.evidence_graph_sha256,
        decision="confirmed",
        output_claim_id=claim.claim_id,
        reviewer_id="human:phase5e2b12a-reviewer",
        reviewed_at="2026-06-30T20:00:00Z",
        rationale="Named human confirmed the event-to-claim reconciliation.",
        issues=(),
    )
    lineage_id = (
        "claim-lineage:"
        + canonical_sha256(
            {
                "issuer_id": ISSUER,
                "security_root_fact_id": initial_root_fact_id,
            }
        )[:24]
    )
    disposition = "extinguished" if remaining_value == 0 else "remaining_claim_rebound"
    evidence_facts = tuple(
        sorted(
            {
                item.fact_id: item
                for item in (
                    affected_fact,
                    remaining_fact,
                    *(member.fact for member in materialization.members),
                )
            }.values(),
            key=lambda item: item.fact_id,
        )
    )
    evidence_sources = tuple(
        sorted(
            {
                item.document_id: item
                for item in (
                    affected_source,
                    remaining_source,
                    *(member.source_document for member in materialization.members),
                )
            }.values(),
            key=lambda item: item.document_id,
        )
    )
    return _fingerprinted(
        GroupBoundClaimTransition,
        {
            "claim_lineage_id": lineage_id,
            "economic_claim_key": economic_claim_key,
            "initial_claim_root_fact_id": initial_root_fact_id,
            "group_id": materialization.group_id,
            "group_fingerprint": materialization.group_fingerprint,
            "identity_fingerprint": materialization.identity_fingerprint,
            "canonical_event_fact_id": materialization.canonical_event_fact_id,
            "canonical_event_fact_fingerprint": (materialization.canonical_event_fact_fingerprint),
            "event_concept": materialization.event_concept,
            "legal_effective_date": materialization.legal_effective_date,
            "canonical_share_magnitude": materialization.canonical_share_magnitude,
            "affected_claim_root_fact_id": affected_fact.fact_id,
            "affected_claim_root_fact_fingerprint": affected_fact.fingerprint,
            "affected_claim_value": str(affected_fact.value),
            "affected_claim_root_fact": affected_fact,
            "affected_claim_source_document": affected_source,
            "remaining_claim_fact_id": remaining_fact.fact_id,
            "remaining_claim_fact_fingerprint": remaining_fact.fingerprint,
            "remaining_claim_value": str(remaining_fact.value),
            "remaining_claim_fact": remaining_fact,
            "remaining_claim_source_document": remaining_source,
            "evidence_facts": evidence_facts,
            "evidence_source_documents": evidence_sources,
            "claims": (claim,),
            "candidates": (candidate,),
            "review_decisions": (decision,),
            "claim_bindings": ((claim.claim_id, claim.fingerprint),),
            "candidate_bindings": ((candidate.candidate_id, candidate.fingerprint),),
            "review_decision_bindings": ((decision.decision_id, decision.fingerprint),),
            "disposition": disposition,
        },
        "transition_fingerprint",
    )


def _security_evidence(
    source: SourceDocument,
) -> tuple[
    tuple[Fact, ...],
    Claim,
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    SecurityIdentityCompilationResult,
]:
    values = {
        "ticker": ("security_ticker", "ACME"),
        "mic": ("security_mic", "XNYS"),
        "share_class": ("security_share_class", "common"),
        "security_structure": ("security_structure", "single_primary_common"),
    }
    facts = tuple(
        Fact(
            schema_version="2.0.0",
            fact_id=f"fact:security:{role}",
            issuer_id=ISSUER,
            concept=concept,
            value_type="text",
            value=value,
            unit=None,
            currency=None,
            period={"start": None, "end": CUTOFF},
            source_document_id=source.document_id,
            source_locator=f"fixture:security:{role}",
            derivation=None,
            parent_fact_ids=(),
            confidence="high",
        )
        for role, (concept, value) in values.items()
    )
    evidence_bindings = tuple(
        {
            "binding_id": f"binding:security:{index}",
            "fact_id": fact.fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
        for index, fact in enumerate(facts, start=1)
    )
    evidence_graph_sha256 = canonical_sha256(
        {
            "supporting_evidence_bindings": evidence_bindings,
            "counterevidence_bindings": (),
        }
    )
    candidate = AnalyticalClaimCandidate(
        schema_version="2.0.0",
        candidate_id="candidate:security:single-primary-common",
        issuer_id=ISSUER,
        as_of_date=CUTOFF,
        proposed_statement="ACME has one primary listed common-share security.",
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        claim_role="support",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=evidence_bindings,
        counterevidence_bindings=(),
        counterevidence_search_note=(
            "Reviewed formal class, ADR, cross-listing, and price-forming security disclosures."
        ),
        proposed_confidence="high",
        falsification_condition="A formal filing identifies another price-forming security.",
        generation_method="manual",
        evidence_graph_sha256=evidence_graph_sha256,
        validation_status="ready",
        validation_issues=(),
    )
    claim, review = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id="human:mingji",
        reviewed_at="2026-06-30T12:00:00Z",
        rationale="Formal security evidence and counterevidence search are complete.",
    )
    assert claim is not None
    proposal = SecurityAccessProposal(
        proposal_id="security-proposal:acme:2026-06-30",
        issuer_id=ISSUER,
        data_cutoff_date=CUTOFF,
        fact_bindings=tuple(
            SecurityFactBinding(role=role, fact_id=f"fact:security:{role}") for role in values
        ),
        structure_claim_id=claim.claim_id,
        analytical_candidate_id=candidate.candidate_id,
        analytical_review_decision_id=review.decision_id,
    )
    closure_payload = {
        "issuer_id": ISSUER,
        "data_cutoff_date": CUTOFF,
        "source_document_ids": (source.document_id,),
        "fact_ids": tuple(sorted(item.fact_id for item in facts)),
        "claim_id": claim.claim_id,
        "candidate_id": candidate.candidate_id,
        "review_decision_id": review.decision_id,
        "object_fingerprints": tuple(
            sorted(
                (
                    ("SourceDocument", source.document_id, source.fingerprint),
                    *(("Fact", item.fact_id, item.fingerprint) for item in facts),
                    ("Claim", claim.claim_id, claim.fingerprint),
                    ("AnalyticalClaimCandidate", candidate.candidate_id, candidate.fingerprint),
                    (
                        "AnalyticalClaimReviewDecision",
                        review.decision_id,
                        review.fingerprint,
                    ),
                )
            )
        ),
    }
    closure_payload["closure_sha256"] = canonical_sha256(closure_payload)
    evidence_closure = SecurityIdentityEvidenceClosure(**closure_payload)
    decision_identity = canonical_sha256(
        {"proposal": proposal.fingerprint, "closure": evidence_closure.closure_sha256}
    )
    security_decision = SecurityIdentityDecision(
        decision_id=f"security-decision:{decision_identity[:24]}",
        policy_id=SECURITY_IDENTITY_POLICY_ID,
        policy_version=SECURITY_IDENTITY_POLICY_VERSION,
        issuer_id=ISSUER,
        security_id=SECURITY,
        ticker="ACME",
        exchange="XNYS",
        share_class="common",
        security_structure="single_primary_common",
        quote_currency="USD",
        reporting_currency="USD",
        disposition="eligible",
        reason_codes=(),
    )
    result = SecurityIdentityCompilationResult(
        policy_id=SECURITY_EVIDENCE_POLICY_ID,
        policy_version=SECURITY_EVIDENCE_POLICY_VERSION,
        proposal=proposal,
        status="eligible",
        decision=security_decision,
        evidence_closure=evidence_closure,
        issue_codes=(),
    )
    return facts, claim, candidate, review, result


def _bundle_closure(
    *,
    graph: ContractGraph,
    opening_fact: Fact,
    materializations: tuple[CanonicalShareEventFactMaterialization, ...],
    coverage: CorporateActionCoverageLedgerV2,
    transitions: GroupBoundClaimTransitionReconciliation,
    grouping: ShareEventGroupingResult,
    security: SecurityIdentityCompilationResult,
    reserved_output_share_fact_id: str,
) -> CurrentShareBundleEvidenceClosure:
    assert len(graph.research_bundles) == len(graph.manifests) == 1
    research_bundle = graph.research_bundles[0]
    run_manifest = graph.manifests[0]
    extension_roots: set[str] = {
        opening_fact.fact_id,
        *(item.receipt_id for item in coverage.receipts),
        *(
            item.artifact_id
            for item in graph.filing_artifacts
            if item.issuer_id == ISSUER
        ),
    }
    for materialization in materializations:
        for member in materialization.members:
            extension_roots.update(
                {
                    member.fact_id,
                    member.capital_allocation_event_id,
                    *(identifier for identifier, _ in member.candidate_bindings),
                    *(identifier for identifier, _ in member.review_decision_bindings),
                }
            )
    for entry in coverage.entries:
        if entry.zero_fact is not None:
            extension_roots.add(entry.zero_fact.fact_id)
        if entry.not_applicable_claim_id is not None:
            extension_roots.add(entry.not_applicable_claim_id)
        if entry.not_applicable_candidate is not None:
            extension_roots.add(entry.not_applicable_candidate.candidate_id)
            for binding in (
                *entry.not_applicable_candidate.supporting_evidence_bindings,
                *entry.not_applicable_candidate.counterevidence_bindings,
            ):
                extension_roots.update(
                    str(binding[field_name])
                    for field_name in (
                        "fact_id",
                        "calculation_result_id",
                        "context_observation_id",
                    )
                    if binding[field_name] is not None
                )
        if entry.review_decision_id is not None:
            extension_roots.add(entry.review_decision_id)
    for transition in transitions.records:
        extension_roots.update(
            {
                transition.affected_claim_root_fact_id,
                transition.remaining_claim_fact_id,
                *(item.claim_id for item in transition.claims),
                *(item.candidate_id for item in transition.candidates),
                *(item.decision_id for item in transition.review_decisions),
            }
        )
        for candidate in transition.candidates:
            for binding in (
                *candidate.supporting_evidence_bindings,
                *candidate.counterevidence_bindings,
            ):
                extension_roots.update(
                    str(binding[field_name])
                    for field_name in (
                        "fact_id",
                        "calculation_result_id",
                        "context_observation_id",
                    )
                    if binding[field_name] is not None
                )
    authority = transitions.claim_control_authority
    if authority is not None:
        extension_roots.update(
            object_id
            for contract_type, object_id, _ in authority.phase5c_review_object_fingerprints
            if contract_type != "SourceDocument"
        )
    assert security.evidence_closure is not None
    extension_roots.update(
        {
            *security.evidence_closure.fact_ids,
            security.evidence_closure.claim_id,
            security.evidence_closure.candidate_id,
            security.evidence_closure.review_decision_id,
        }
    )
    public_roots = tuple(
        str(object_id)
        for reference in research_bundle.module_references
        for object_id in reference["object_ids"]
    )
    public_closure = dependency_closure(graph, public_roots)
    base_bindings = tuple(
        sorted(
            (contract_type, object_id, item.fingerprint)
            for object_id, (contract_type, item) in public_closure.items()
        )
    )
    extension_closure = _typed_extension_dependency_closure(
        graph,
        tuple(sorted(extension_roots)),
    )
    extension_bindings = tuple(
        sorted(
            (contract_type, object_id, item.fingerprint)
            for object_id, (contract_type, item) in extension_closure.items()
            if object_id not in public_closure
        )
    )
    bindings = tuple(sorted((*base_bindings, *extension_bindings)))
    expected_sources = tuple(
        sorted(
            (
                item
                for _, (contract_type, item) in extension_closure.items()
                if contract_type == "SourceDocument"
            ),
            key=lambda item: item.document_id,
        )
    )
    dependency_hash = dependency_closure_sha256(list(bindings))
    payload = {
        "research_bundle": research_bundle,
        "run_manifest": run_manifest,
        "research_bundle_id": research_bundle.bundle_id,
        "research_bundle_fingerprint": research_bundle.bundle_fingerprint,
        "issuer_id": ISSUER,
        "issuer_cik": ISSUER_CIK,
        "data_cutoff_date": CUTOFF,
        "component_lock_sha256": research_bundle.component_lock_sha256,
        "dependency_closure_sha256": research_bundle.dependency_closure_sha256,
        "current_share_dependency_closure_sha256": dependency_hash,
        "extension_policy_id": CURRENT_SHARE_EXTENSION_POLICY_ID,
        "extension_policy_version": CURRENT_SHARE_EXTENSION_POLICY_VERSION,
        "integration_contract_sha256": current_share_integration_contract_sha256(),
        "integration_policy_sha256": current_share_integration_policy_sha256(),
        "integration_code_sha256": current_share_integration_code_sha256(),
        "run_manifest_id": run_manifest.run_id,
        "security_compilation_result": security,
        "security_compilation_fingerprint": security.fingerprint,
        "grouping_result": grouping,
        "grouping_result_fingerprint": grouping.grouping_fingerprint,
        "opening_share_fact": opening_fact,
        "canonical_event_materializations": materializations,
        "canonical_event_fact_bindings": tuple(
            sorted(
                (
                    item.canonical_event_fact_id,
                    item.canonical_event_fact_fingerprint,
                )
                for item in materializations
            )
        ),
        "reserved_output_share_fact_id": reserved_output_share_fact_id,
        "claim_control_authority": authority,
        "claim_control_authority_fingerprint": (
            authority.authority_fingerprint if authority is not None else None
        ),
        "source_documents": expected_sources,
        "base_dependency_object_fingerprints": base_bindings,
        "extension_root_ids": tuple(sorted(extension_roots)),
        "extension_object_fingerprints": extension_bindings,
        "object_fingerprints": bindings,
        "contract_graph_fingerprint": _scoped_contract_graph_fingerprint(graph, bindings),
    }
    payload["closure_sha256"] = canonical_sha256(payload)
    return CurrentShareBundleEvidenceClosure(**payload, validation_graph=graph)


def _replay_bundle_against_graph(
    bundle: CurrentShareBundleEvidenceClosure,
    graph: ContractGraph,
) -> CurrentShareBundleEvidenceClosure:
    payload = _typed_bundle_payload(bundle)
    payload["contract_graph_fingerprint"] = _scoped_contract_graph_fingerprint(
        graph,
        bundle.object_fingerprints,
    )
    payload["closure_sha256"] = canonical_sha256(payload)
    return CurrentShareBundleEvidenceClosure(**payload, validation_graph=graph)


def _typed_bundle_payload(
    bundle: CurrentShareBundleEvidenceClosure,
) -> dict[str, object]:
    payload = bundle.hash_payload()
    payload.update(
        {
            "research_bundle": bundle.research_bundle,
            "run_manifest": bundle.run_manifest,
            "security_compilation_result": bundle.security_compilation_result,
            "grouping_result": bundle.grouping_result,
            "opening_share_fact": bundle.opening_share_fact,
            "canonical_event_materializations": bundle.canonical_event_materializations,
            "claim_control_authority": bundle.claim_control_authority,
            "source_documents": bundle.source_documents,
        }
    )
    return payload


def _governed_graph(
    sample_payloads: dict[str, dict],
    *,
    grouping_evidence: tuple | None,
    opening_fact: Fact,
    coverage: CorporateActionCoverageLedgerV2,
) -> tuple[ContractGraph, SecurityIdentityCompilationResult]:
    base, _ = _bundle_graph(sample_payloads)
    opening_source = next(
        item
        for item in coverage.result_source_documents
        if item.document_id == opening_fact.source_document_id
    )
    filing_artifact = FilingArtifact(
        schema_version="1.0.0",
        artifact_id="filing:acme:2026q2",
        issuer_id=ISSUER,
        source_document_id=opening_source.document_id,
        cik=ISSUER_CIK,
        accession="0000000123-26-000001",
        form=opening_source.document_type,
        filing_date=opening_source.published_date,
        report_period=str(opening_source.period["end"]),
        primary_document="acme-20260630.htm",
        source_url="https://www.sec.gov/Archives/edgar/data/123/acme-20260630.htm",
        raw_sha256=opening_source.content_sha256,
        normalized_sha256=canonical_sha256({"normalized": opening_source.content_sha256}),
        parser_id="fixture-filing-parser",
        parser_version="1.0.0",
        retrieved_at=opening_source.retrieved_at,
    )
    security_facts, security_claim, security_candidate, security_review, security_result = (
        _security_evidence(opening_source)
    )
    if grouping_evidence is None:
        raw_facts = ()
        event_sources = ()
        event_candidates = ()
        event_decisions = ()
        new_events = ()
    else:
        _, raw_facts, event_sources, event_candidates, event_decisions, event = grouping_evidence
        new_events = (event,)
    documents_by_id = {item.document_id: item for item in base.documents}
    for source in (
        *event_sources,
        *coverage.result_source_documents,
    ):
        documents_by_id[source.document_id] = source
    documents = tuple(sorted(documents_by_id.values(), key=lambda item: item.document_id))
    facts_by_id = {item.fact_id: item for item in base.facts}
    for fact in (
        *raw_facts,
        opening_fact,
        *security_facts,
        *(entry.zero_fact for entry in coverage.entries if entry.zero_fact is not None),
    ):
        assert fact is not None
        facts_by_id[fact.fact_id] = fact
    facts = tuple(sorted(facts_by_id.values(), key=lambda item: item.fact_id))
    candidates = tuple(
        sorted(
            (*base.capital_allocation_event_candidates, *event_candidates),
            key=lambda item: item.candidate_id,
        )
    )
    decisions = tuple(
        sorted(
            (*base.capital_allocation_event_review_decisions, *event_decisions),
            key=lambda item: item.decision_id,
        )
    )
    events = tuple(
        sorted(
            (*base.capital_allocation_events, *new_events),
            key=lambda item: item.event_id,
        )
    )
    review = build_capital_allocation_review(
        issuer_id=ISSUER,
        review_period={"start": OPENING_DATE, "end": QUOTE_DATE},
        as_of_date=CUTOFF,
        source_documents=documents,
        source_search_receipts=coverage.receipts,
        events=events,
        outcomes=base.capital_allocation_outcomes,
        calculations=base.calculations,
        claims=base.claims,
        analytical_candidates=base.analytical_claim_candidates,
        analytical_decisions=base.analytical_claim_review_decisions,
    )
    manifest = replace(
        base.manifests[0],
        completed_at="2026-07-16T02:00:00Z",
        input_document_hashes={item.document_id: item.content_sha256 for item in documents},
        output_artifact_hashes={},
    )
    graph = replace_graph(
        base,
        documents=documents,
        facts=facts,
        claims=tuple(sorted((*base.claims, security_claim), key=lambda item: item.claim_id)),
        analytical_claim_candidates=tuple(
            sorted(
                (*base.analytical_claim_candidates, security_candidate),
                key=lambda item: item.candidate_id,
            )
        ),
        analytical_claim_review_decisions=tuple(
            sorted(
                (*base.analytical_claim_review_decisions, security_review),
                key=lambda item: item.decision_id,
            )
        ),
        capital_allocation_event_candidates=candidates,
        capital_allocation_event_review_decisions=decisions,
        capital_allocation_events=events,
        source_search_receipts=coverage.receipts,
        capital_allocation_reviews=(review,),
        filing_artifacts=(filing_artifact,),
        manifests=(manifest,),
        research_bundles=(),
    )
    graph.validate()
    built = build_research_bundle(graph, run_id=manifest.run_id)
    completed = replace_graph(
        graph,
        manifests=(built.run_manifest,),
        research_bundles=(built.bundle,),
    )
    completed.validate()
    return completed, security_result


def _accepted_context(
    *,
    sample_payloads: dict[str, dict],
    corroborating_count: int = 1,
    opening_value: int = 100_000_000,
    output_value: int = 95_000_000,
    event_concept: str = "common_shares_repurchased_completed",
) -> tuple[CurrentShareEvidenceClosureV2, ContractGraph]:
    grouping_evidence = _grouping(
        concept=event_concept,
        corroborating_count=corroborating_count,
    )
    grouping, raw_facts, event_sources, candidates, decisions, event = grouping_evidence
    materialization = _materialization(
        grouping=grouping,
        raw_facts=raw_facts,
        event_sources=event_sources,
        event_candidates=candidates,
        event_decisions=decisions,
        capital_event=event,
    )
    opening_source, coverage_source = _coverage_documents()
    opening_fact = _fact(
        fact_id="fact:shares:opening",
        concept="common_shares_outstanding",
        value=opening_value,
        source=opening_source,
        end=OPENING_DATE,
    )
    receipts = _receipts((*event_sources, opening_source, coverage_source))
    coverage = _coverage(
        materialization,
        coverage_source,
        receipts,
        (*event_sources, opening_source, coverage_source),
    )
    transitions = _empty_transitions()
    output_fact_id = _reserved_output_share_fact_id(
        issuer_id=ISSUER,
        security_id=SECURITY,
        quote_date=QUOTE_DATE,
        opening_share_fact_id=opening_fact.fact_id,
        grouping_result_fingerprint=grouping.grouping_fingerprint,
    )
    output_fact = _fact(
        fact_id=output_fact_id,
        concept="common_shares_outstanding",
        value=output_value,
        source=opening_source,
        end=QUOTE_DATE,
        derivation=CURRENT_SHARE_ROLLFORWARD_DERIVATION,
        parents=tuple(sorted((opening_fact.fact_id, materialization.canonical_event_fact_id))),
        source_locator=_output_share_source_locator(output_fact_id),
    )
    graph, security = _governed_graph(
        sample_payloads,
        grouping_evidence=grouping_evidence,
        opening_fact=opening_fact,
        coverage=coverage,
    )
    bundle = _bundle_closure(
        graph=graph,
        opening_fact=opening_fact,
        materializations=(materialization,),
        coverage=coverage,
        transitions=transitions,
        grouping=grouping,
        security=security,
        reserved_output_share_fact_id=output_fact.fact_id,
    )
    consumption = _consumption(materialization)
    edges = tuple(
        sorted(
            (
                (output_fact.fact_id, opening_fact.fact_id),
                (output_fact.fact_id, materialization.canonical_event_fact_id),
                *(
                    (materialization.canonical_event_fact_id, item.fact_id)
                    for item in materialization.members
                ),
            )
        )
    )
    outer_objects = {
        (contract_type, object_id): (contract_type, object_id, fingerprint)
        for contract_type, object_id, fingerprint in bundle.object_fingerprints
    }
    outer_objects[("Fact", output_fact.fact_id)] = (
        "Fact",
        output_fact.fact_id,
        output_fact.fingerprint,
    )
    outer_objects[("Fact", materialization.canonical_event_fact_id)] = (
        "Fact",
        materialization.canonical_event_fact_id,
        materialization.canonical_event_fact_fingerprint,
    )
    object_fingerprints = tuple(sorted(outer_objects.values()))
    numeric_lineage_sha256 = canonical_sha256(
        {
            "opening_fact": opening_fact.to_dict(),
            "output_fact": output_fact.to_dict(),
            "materialization_fingerprints": [materialization.materialization_fingerprint],
            "consumption_fingerprints": [consumption.consumption_fingerprint],
            "fact_parent_edges": edges,
        }
    )
    source_closure_sha256 = canonical_sha256(
        {
            "member_sources": sorted(
                {
                    (item.source_document_id, item.source_document_fingerprint)
                    for item in materialization.members
                }
            ),
            "receipt_fingerprints": sorted(
                (item.receipt_id, item.fingerprint) for item in receipts
            ),
            "opening_source": (opening_source.document_id, opening_source.fingerprint),
            "coverage_zero_sources": sorted(
                (
                    item.zero_fact.source_document_id,
                    next(
                        source.fingerprint
                        for source in bundle.source_documents
                        if source.document_id == item.zero_fact.source_document_id
                    ),
                )
                for item in coverage.entries
                if item.zero_fact is not None
            ),
            "claim_transition_sources": [],
            "security_sources": sorted(
                (
                    identifier,
                    next(
                        source.fingerprint
                        for source in bundle.source_documents
                        if source.document_id == identifier
                    ),
                )
                for identifier in security.evidence_closure.source_document_ids
            ),
            "extension_sources": sorted(
                (item.document_id, item.fingerprint) for item in bundle.source_documents
            ),
        }
    )
    temporal_closure_sha256 = canonical_sha256(
        {
            "issuer_id": ISSUER,
            "security_id": SECURITY,
            "opening_date": OPENING_DATE,
            "quote_date": QUOTE_DATE,
            "data_cutoff_date": CUTOFF,
            "event_effective_dates": [EVENT_DATE],
            "member_dates": sorted(
                (
                    item.member.fact_measurement_date,
                    item.member.source_published_date,
                    item.member.data_cutoff_date,
                )
                for item in materialization.members
            ),
            "receipt_periods": sorted(
                (
                    item.source_family,
                    item.period["start"],
                    item.period["end"],
                    item.cutoff_date,
                )
                for item in receipts
            ),
            "claim_transition_evidence_dates": [],
        }
    )
    payload = {
        "closure_id": _current_share_v2_closure_id(
            issuer_id=ISSUER,
            security_id=SECURITY,
            quote_date=QUOTE_DATE,
            opening_share_fact_id=opening_fact.fact_id,
            output_share_fact_id=output_fact.fact_id,
            grouping_result_fingerprint=grouping.grouping_fingerprint,
        ),
        "issuer_id": ISSUER,
        "security_id": SECURITY,
        "quote_date": QUOTE_DATE,
        "data_cutoff_date": CUTOFF,
        "grouping_result": grouping,
        "opening_share_fact": opening_fact,
        "output_share_fact": output_fact,
        "output_share_fact_id": output_fact.fact_id,
        "output_share_fact_fingerprint": output_fact.fingerprint,
        "opening_share_fact_id": opening_fact.fact_id,
        "rollforward_parent_fact_ids": tuple(sorted(output_fact.parent_fact_ids)),
        "ultimate_numeric_root_fact_ids": tuple(
            sorted((opening_fact.fact_id, *(item.fact_id for item in raw_facts)))
        ),
        "materializations": (materialization,),
        "numeric_consumptions": (consumption,),
        "bundle_evidence_closure": bundle,
        "coverage_ledger": coverage,
        "claim_transition_reconciliation": transitions,
        "fact_parent_edges": edges,
        "object_fingerprints": object_fingerprints,
        "grouping_policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
        "grouping_policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
        "grouping_code_sha256": grouping.grouping_code_sha256,
        "integration_contract_sha256": current_share_integration_contract_sha256(),
        "integration_policy_sha256": current_share_integration_policy_sha256(),
        "integration_code_sha256": current_share_integration_code_sha256(),
        "grouping_result_fingerprint": grouping.grouping_fingerprint,
        "numeric_lineage_sha256": numeric_lineage_sha256,
        "coverage_closure_sha256": coverage.ledger_sha256,
        "claim_transition_sha256": transitions.reconciliation_sha256,
        "source_closure_sha256": source_closure_sha256,
        "temporal_closure_sha256": temporal_closure_sha256,
    }
    payload["closure_sha256"] = canonical_sha256(payload)
    return CurrentShareEvidenceClosureV2(**payload), graph


def _accepted_closure(
    *,
    sample_payloads: dict[str, dict],
    corroborating_count: int = 1,
    output_value: int = 95_000_000,
) -> CurrentShareEvidenceClosureV2:
    return _accepted_context(
        sample_payloads=sample_payloads,
        corroborating_count=corroborating_count,
        output_value=output_value,
    )[0]


def test_bundle_constructor_wires_official_occurrence_collision_validation(
    sample_payloads,
) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    first_group, forged_group, members = _official_occurrence_split_groups()
    grouping_payload = closure.bundle_evidence_closure.grouping_result.fingerprint_payload()
    grouping_payload.update(
        {
            "members": members,
            "groups": tuple(
                sorted(
                    (first_group, forged_group),
                    key=lambda item: item.group_id,
                )
            ),
        }
    )
    split_grouping = ShareEventGroupingResult(
        **grouping_payload,
        grouping_fingerprint=canonical_sha256(grouping_payload),
    )
    bundle_payload = _typed_bundle_payload(closure.bundle_evidence_closure)
    bundle_payload.update(
        {
            "grouping_result": split_grouping,
            "grouping_result_fingerprint": split_grouping.grouping_fingerprint,
        }
    )
    bundle_payload["closure_sha256"] = canonical_sha256(bundle_payload)

    with pytest.raises(ValueError, match="split across legal identities"):
        CurrentShareBundleEvidenceClosure(
            **bundle_payload,
            validation_graph=graph,
        )


def test_recursive_opening_and_output_require_high_confidence(sample_payloads) -> None:
    closure, _graph = _accepted_context(sample_payloads=sample_payloads)
    medium_opening = replace(closure.opening_share_fact, confidence="medium")
    with pytest.raises(ValueError, match="governed raw stock Fact"):
        replace(
            closure,
            opening_share_fact=medium_opening,
            closure_sha256=SHA_A,
        )
    medium_output = replace(closure.output_share_fact, confidence="medium")
    with pytest.raises(ValueError, match="governed roll-forward result"):
        replace(
            closure,
            output_share_fact=medium_output,
            output_share_fact_fingerprint=medium_output.fingerprint,
            closure_sha256=SHA_A,
        )


def test_share_values_require_canonical_integer_strings_and_json_integers(
    sample_payloads,
) -> None:
    for invalid in ("5000000.0", "05", "+5", "5e0", "-1"):
        with pytest.raises(ValueError, match="canonical .*integer string"):
            _integer_decimal(invalid, "adversarial share value")

    closure, _graph = _accepted_context(sample_payloads=sample_payloads)
    float_opening = replace(closure.opening_share_fact, value=100_000_000.0)
    with pytest.raises(ValueError, match="exact JSON integer"):
        replace(
            closure,
            opening_share_fact=float_opening,
            closure_sha256=SHA_A,
        )

    with pytest.raises(ValueError, match="exact JSON integer"):
        _fact_share_integer(
            float(9_007_199_254_740_993),
            "lossy binary64 share value",
            positive=True,
        )


def test_generated_fact_parent_order_is_canonical_not_set_equivalent(sample_payloads) -> None:
    closure = _accepted_closure(sample_payloads=sample_payloads, corroborating_count=2)
    material = closure.materializations[0]
    reversed_canonical = replace(
        material.canonical_event_fact,
        parent_fact_ids=tuple(reversed(material.canonical_event_fact.parent_fact_ids)),
    )
    material_payload = material.fingerprint_payload()
    material_payload.update(
        {
            "canonical_event_fact": reversed_canonical.to_dict(),
            "canonical_event_fact_fingerprint": reversed_canonical.fingerprint,
        }
    )
    with pytest.raises(ValueError, match="exactly materialize"):
        replace(
            material,
            canonical_event_fact=reversed_canonical,
            canonical_event_fact_fingerprint=reversed_canonical.fingerprint,
            materialization_fingerprint=canonical_sha256(material_payload),
        )

    reversed_output = replace(
        closure.output_share_fact,
        parent_fact_ids=tuple(reversed(closure.output_share_fact.parent_fact_ids)),
    )
    with pytest.raises(ValueError, match="exact roll-forward parents"):
        replace(
            closure,
            output_share_fact=reversed_output,
            output_share_fact_fingerprint=reversed_output.fingerprint,
            closure_sha256=SHA_A,
        )


def test_recursive_closure_id_is_deterministic(sample_payloads) -> None:
    closure = _accepted_closure(sample_payloads=sample_payloads)
    assert closure.closure_id == _current_share_v2_closure_id(
        issuer_id=closure.issuer_id,
        security_id=closure.security_id,
        quote_date=closure.quote_date,
        opening_share_fact_id=closure.opening_share_fact_id,
        output_share_fact_id=closure.output_share_fact_id,
        grouping_result_fingerprint=closure.grouping_result_fingerprint,
    )
    with pytest.raises(ValueError, match="closure ID is not deterministic"):
        replace(
            closure,
            closure_id="current-share-closure:caller-controlled",
            closure_sha256=SHA_A,
        )

def test_output_share_fact_retains_opening_official_source_and_deterministic_locator(
    sample_payloads,
) -> None:
    closure, _graph = _accepted_context(sample_payloads=sample_payloads)
    alternate_source = next(
        item
        for item in closure.bundle_evidence_closure.source_documents
        if item.document_id != closure.opening_share_fact.source_document_id
    )
    source_drift = replace(
        closure.output_share_fact,
        source_document_id=alternate_source.document_id,
    )
    with pytest.raises(ValueError, match="governed roll-forward result"):
        replace(
            closure,
            output_share_fact=source_drift,
            output_share_fact_fingerprint=source_drift.fingerprint,
            closure_sha256=SHA_A,
        )

    locator_drift = replace(
        closure.output_share_fact,
        source_locator="derived:attacker-controlled-output-locator",
    )
    with pytest.raises(ValueError, match="governed roll-forward result"):
        replace(
            closure,
            output_share_fact=locator_drift,
            output_share_fact_fingerprint=locator_drift.fingerprint,
            closure_sha256=SHA_A,
        )


def test_recursive_opening_source_must_remain_official_primary(sample_payloads) -> None:
    closure, _graph = _accepted_context(sample_payloads=sample_payloads)
    bundle = copy(closure.bundle_evidence_closure)
    changed_sources = tuple(
        replace(
            item,
            authority_level="secondary",
            source_url="https://example.test/unofficial-opening",
        )
        if item.document_id == closure.opening_share_fact.source_document_id
        else item
        for item in bundle.source_documents
    )
    object.__setattr__(bundle, "source_documents", changed_sources)
    with pytest.raises(ValueError, match="official primary source"):
        replace(
            closure,
            bundle_evidence_closure=bundle,
            closure_sha256=SHA_A,
        )


@pytest.mark.parametrize("collision_target", ("canonical", "output"))
def test_reserved_generated_fact_ids_reject_any_existing_graph_fact(
    sample_payloads,
    collision_target: str,
) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    reserved_id = (
        closure.materializations[0].canonical_event_fact_id
        if collision_target == "canonical"
        else closure.output_share_fact_id
    )
    collision = replace(
        closure.opening_share_fact,
        fact_id=reserved_id,
        concept="unrelated_historical_metric",
        value=123,
        unit="count",
    )
    colliding_graph = replace_graph(graph, facts=(*graph.facts, collision))
    colliding_graph.validate()
    expected = (
        "noncanonical graph bytes"
        if collision_target == "canonical"
        else "already occupied"
    )
    with pytest.raises(ValueError, match=expected):
        _replay_bundle_against_graph(
            closure.bundle_evidence_closure,
            colliding_graph,
        )


@pytest.mark.parametrize("collision_target", ("canonical", "output"))
def test_reserved_generated_fact_ids_reject_cross_domain_occupants(
    sample_payloads,
    collision_target: str,
) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    reserved_id = (
        closure.materializations[0].canonical_event_fact_id
        if collision_target == "canonical"
        else closure.output_share_fact_id
    )
    occupant = Claim(
        schema_version="1.0.0",
        claim_id=reserved_id,
        issuer_id=ISSUER,
        statement="An unrelated reviewed statement occupies a reserved generated ID.",
        as_of_date=CUTOFF,
        supporting_fact_ids=(closure.opening_share_fact_id,),
        counterevidence_fact_ids=(),
        counterevidence_search_note="Reviewed the governed fixture evidence.",
        confidence="high",
        falsification_condition="The statement is withdrawn by an official source.",
    )
    colliding_graph = replace_graph(graph, claims=(*graph.claims, occupant))
    colliding_graph.validate()
    expected = (
        "noncanonical graph bytes"
        if collision_target == "canonical"
        else "already occupied"
    )
    with pytest.raises(ValueError, match=expected):
        _replay_bundle_against_graph(
            closure.bundle_evidence_closure,
            colliding_graph,
        )


def test_reserved_canonical_fact_id_accepts_only_exact_deterministic_materialization(
    sample_payloads,
) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    future_generated_fact = closure.materializations[0].canonical_event_fact
    colliding_graph = replace_graph(
        graph,
        facts=(*graph.facts, future_generated_fact),
    )
    colliding_graph.validate()

    replayed = _replay_bundle_against_graph(
        closure.bundle_evidence_closure,
        colliding_graph,
    )
    assert replayed.canonical_event_materializations == closure.materializations


def test_canonical_materialization_rejects_resigned_source_locator(sample_payloads) -> None:
    closure, _graph = _accepted_context(sample_payloads=sample_payloads)
    materialization = closure.materializations[0]
    resigned_fact = replace(
        materialization.canonical_event_fact,
        source_locator="derived:attacker-controlled-locator",
    )

    with pytest.raises(ValueError, match="exactly materialize"):
        replace(
            materialization,
            canonical_event_fact=resigned_fact,
            canonical_event_fact_fingerprint=resigned_fact.fingerprint,
            materialization_fingerprint=SHA_A,
        )


def test_bundle_rejects_caller_rewrite_of_generated_fact_reservations(
    sample_payloads,
) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    bundle = closure.bundle_evidence_closure

    canonical_payload = _typed_bundle_payload(bundle)
    canonical_payload["canonical_event_fact_bindings"] = (
        (bundle.canonical_event_fact_bindings[0][0], SHA_B),
    )
    canonical_payload["closure_sha256"] = canonical_sha256(canonical_payload)
    with pytest.raises(ValueError, match="deterministic materialization"):
        CurrentShareBundleEvidenceClosure(
            **canonical_payload,
            validation_graph=graph,
        )

    output_payload = _typed_bundle_payload(bundle)
    output_payload["reserved_output_share_fact_id"] = (
        "derived:current-shares:attacker-controlled"
    )
    output_payload["closure_sha256"] = canonical_sha256(output_payload)
    with pytest.raises(ValueError, match="deterministically derived"):
        CurrentShareBundleEvidenceClosure(
            **output_payload,
            validation_graph=graph,
        )


def test_outer_closure_rejects_resigned_opening_fact_outside_bundle_authority(
    sample_payloads,
) -> None:
    closure, _graph = _accepted_context(sample_payloads=sample_payloads)
    resigned_opening = replace(closure.opening_share_fact, value=200_000_000)
    resigned_output = replace(
        closure.output_share_fact,
        value=195_000_000,
    )

    with pytest.raises(ValueError, match="generated Fact reservations"):
        replace(
            closure,
            opening_share_fact=resigned_opening,
            output_share_fact=resigned_output,
            output_share_fact_fingerprint=resigned_output.fingerprint,
            closure_sha256=SHA_A,
        )


def _accepted_empty_context(
    *, sample_payloads: dict[str, dict]
) -> tuple[CurrentShareEvidenceClosureV2, ContractGraph]:
    grouping = _empty_grouping()
    opening_source, coverage_source = _coverage_documents()
    opening_fact = _fact(
        fact_id="fact:shares:opening:no-events",
        concept="common_shares_outstanding",
        value=100_000_000,
        source=opening_source,
        end=OPENING_DATE,
    )
    receipts = _receipts((opening_source, coverage_source))
    coverage = _coverage(
        None,
        coverage_source,
        receipts,
        (opening_source, coverage_source),
    )
    transitions = _empty_transitions()
    output_fact_id = _reserved_output_share_fact_id(
        issuer_id=ISSUER,
        security_id=SECURITY,
        quote_date=QUOTE_DATE,
        opening_share_fact_id=opening_fact.fact_id,
        grouping_result_fingerprint=grouping.grouping_fingerprint,
    )
    output_fact = _fact(
        fact_id=output_fact_id,
        concept="common_shares_outstanding",
        value=100_000_000,
        source=opening_source,
        end=QUOTE_DATE,
        derivation=CURRENT_SHARE_ROLLFORWARD_DERIVATION,
        parents=(opening_fact.fact_id,),
        source_locator=_output_share_source_locator(output_fact_id),
    )
    graph, security = _governed_graph(
        sample_payloads,
        grouping_evidence=None,
        opening_fact=opening_fact,
        coverage=coverage,
    )
    bundle = _bundle_closure(
        graph=graph,
        opening_fact=opening_fact,
        materializations=(),
        coverage=coverage,
        transitions=transitions,
        grouping=grouping,
        security=security,
        reserved_output_share_fact_id=output_fact.fact_id,
    )
    edges = ((output_fact.fact_id, opening_fact.fact_id),)
    object_fingerprints = tuple(
        sorted(
            (
                *bundle.object_fingerprints,
                ("Fact", output_fact.fact_id, output_fact.fingerprint),
            )
        )
    )
    numeric_lineage_sha256 = canonical_sha256(
        {
            "opening_fact": opening_fact.to_dict(),
            "output_fact": output_fact.to_dict(),
            "materialization_fingerprints": [],
            "consumption_fingerprints": [],
            "fact_parent_edges": edges,
        }
    )
    source_closure_sha256 = canonical_sha256(
        {
            "member_sources": [],
            "receipt_fingerprints": sorted(
                (item.receipt_id, item.fingerprint) for item in receipts
            ),
            "opening_source": (opening_source.document_id, opening_source.fingerprint),
            "coverage_zero_sources": sorted(
                (
                    item.zero_fact.source_document_id,
                    next(
                        source.fingerprint
                        for source in bundle.source_documents
                        if source.document_id == item.zero_fact.source_document_id
                    ),
                )
                for item in coverage.entries
                if item.zero_fact is not None
            ),
            "claim_transition_sources": [],
            "security_sources": sorted(
                (
                    identifier,
                    next(
                        source.fingerprint
                        for source in bundle.source_documents
                        if source.document_id == identifier
                    ),
                )
                for identifier in security.evidence_closure.source_document_ids
            ),
            "extension_sources": sorted(
                (item.document_id, item.fingerprint) for item in bundle.source_documents
            ),
        }
    )
    temporal_closure_sha256 = canonical_sha256(
        {
            "issuer_id": ISSUER,
            "security_id": SECURITY,
            "opening_date": OPENING_DATE,
            "quote_date": QUOTE_DATE,
            "data_cutoff_date": CUTOFF,
            "event_effective_dates": [],
            "member_dates": [],
            "receipt_periods": sorted(
                (
                    item.source_family,
                    item.period["start"],
                    item.period["end"],
                    item.cutoff_date,
                )
                for item in receipts
            ),
            "claim_transition_evidence_dates": [],
        }
    )
    payload = {
        "closure_id": _current_share_v2_closure_id(
            issuer_id=ISSUER,
            security_id=SECURITY,
            quote_date=QUOTE_DATE,
            opening_share_fact_id=opening_fact.fact_id,
            output_share_fact_id=output_fact.fact_id,
            grouping_result_fingerprint=grouping.grouping_fingerprint,
        ),
        "issuer_id": ISSUER,
        "security_id": SECURITY,
        "quote_date": QUOTE_DATE,
        "data_cutoff_date": CUTOFF,
        "grouping_result": grouping,
        "opening_share_fact": opening_fact,
        "output_share_fact": output_fact,
        "output_share_fact_id": output_fact.fact_id,
        "output_share_fact_fingerprint": output_fact.fingerprint,
        "opening_share_fact_id": opening_fact.fact_id,
        "rollforward_parent_fact_ids": (opening_fact.fact_id,),
        "ultimate_numeric_root_fact_ids": (opening_fact.fact_id,),
        "materializations": (),
        "numeric_consumptions": (),
        "bundle_evidence_closure": bundle,
        "coverage_ledger": coverage,
        "claim_transition_reconciliation": transitions,
        "fact_parent_edges": edges,
        "object_fingerprints": object_fingerprints,
        "grouping_policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
        "grouping_policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
        "grouping_code_sha256": grouping.grouping_code_sha256,
        "integration_contract_sha256": current_share_integration_contract_sha256(),
        "integration_policy_sha256": current_share_integration_policy_sha256(),
        "integration_code_sha256": current_share_integration_code_sha256(),
        "grouping_result_fingerprint": grouping.grouping_fingerprint,
        "numeric_lineage_sha256": numeric_lineage_sha256,
        "coverage_closure_sha256": coverage.ledger_sha256,
        "claim_transition_sha256": transitions.reconciliation_sha256,
        "source_closure_sha256": source_closure_sha256,
        "temporal_closure_sha256": temporal_closure_sha256,
    }
    payload["closure_sha256"] = canonical_sha256(payload)
    return CurrentShareEvidenceClosureV2(**payload), graph


def test_internal_contracts_are_frozen_and_not_exposed(sample_payloads) -> None:
    closure = _accepted_closure(sample_payloads=sample_payloads)
    module_bytes = Path(integration_types.__file__).read_bytes()
    assert current_share_integration_code_sha256() == hashlib.sha256(module_bytes).hexdigest()
    assert current_share_integration_code_sha256() != hashlib.sha256(
        module_bytes + b"\n"
    ).hexdigest()
    assert (
        closure.materializations[0].materialization_code_sha256
        == current_share_integration_code_sha256()
    )
    with pytest.raises(FrozenInstanceError):
        closure.quote_date = "2026-07-01"  # type: ignore[misc]
    names = {
        "CanonicalShareEventMemberBinding",
        "CanonicalShareEventFactMaterialization",
        "ShareEventNumericConsumption",
        "CorporateActionCoverageEntryV2",
        "CorporateActionCoverageLedgerV2",
        "GroupBoundDilutionClaimAuthority",
        "GroupBoundClaimTransition",
        "GroupBoundClaimTransitionReconciliation",
        "CurrentShareBundleEvidenceClosure",
        "CurrentShareEvidenceClosureV2",
    }
    assert all(not hasattr(owner_research, name) for name in names)
    assert integration_types.__all__ == ()
    for path in (
        ROOT / "src/owner_research/cli.py",
        ROOT / "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md",
        ROOT / "plugins/owner-equity-research/skills/owner-research-audit/SKILL.md",
    ):
        text = path.read_text(encoding="utf-8")
        assert not any(name in text for name in names)


def test_zero_event_closure_binds_integration_contract_policy_and_code(
    sample_payloads,
) -> None:
    closure, graph = _accepted_empty_context(sample_payloads=sample_payloads)
    expected = (
        current_share_integration_contract_sha256(),
        current_share_integration_policy_sha256(),
        current_share_integration_code_sha256(),
    )
    assert (
        closure.integration_contract_sha256,
        closure.integration_policy_sha256,
        closure.integration_code_sha256,
    ) == expected
    assert (
        closure.bundle_evidence_closure.integration_contract_sha256,
        closure.bundle_evidence_closure.integration_policy_sha256,
        closure.bundle_evidence_closure.integration_code_sha256,
    ) == expected

    with pytest.raises(ValueError, match="integration policy or code identity drifted"):
        replace(
            closure.bundle_evidence_closure,
            integration_policy_sha256="0" * 64,
            closure_sha256=canonical_sha256(
                {
                    **closure.bundle_evidence_closure.hash_payload(),
                    "integration_policy_sha256": "0" * 64,
                }
            ),
            validation_graph=graph,
        )


def test_bundle_closure_rejects_binary_float_opening_share_root(sample_payloads) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    bundle = closure.bundle_evidence_closure
    opening = bundle.opening_share_fact
    forged = replace(opening, value=float(opening.value))
    forged_graph = replace_graph(
        graph,
        facts=tuple(forged if item.fact_id == opening.fact_id else item for item in graph.facts),
    )
    forged_graph.validate()
    extension_objects = tuple(
        (
            contract_type,
            object_id,
            forged.fingerprint
            if contract_type == "Fact" and object_id == forged.fact_id
            else fingerprint,
        )
        for contract_type, object_id, fingerprint in bundle.extension_object_fingerprints
    )
    all_objects = tuple(
        (
            contract_type,
            object_id,
            forged.fingerprint
            if contract_type == "Fact" and object_id == forged.fact_id
            else fingerprint,
        )
        for contract_type, object_id, fingerprint in bundle.object_fingerprints
    )
    payload = _typed_bundle_payload(bundle)
    payload.update(
        {
            "opening_share_fact": forged,
            "extension_object_fingerprints": extension_objects,
            "object_fingerprints": all_objects,
            "current_share_dependency_closure_sha256": dependency_closure_sha256(
                list(all_objects)
            ),
            "contract_graph_fingerprint": _scoped_contract_graph_fingerprint(
                forged_graph,
                all_objects,
            ),
        }
    )
    payload["closure_sha256"] = canonical_sha256(payload)
    with pytest.raises(ValueError, match="exact JSON integer"):
        CurrentShareBundleEvidenceClosure(**payload, validation_graph=forged_graph)
    with pytest.raises(ValueError, match="accepted grouping result"):
        replace(
            closure,
            integration_contract_sha256="0" * 64,
            closure_sha256=canonical_sha256(
                {
                    **closure.hash_payload(),
                    "integration_contract_sha256": "0" * 64,
                }
            ),
        )


def test_policy_and_adversarial_fixture_are_closed() -> None:
    policy_path = (
        ROOT / "src/owner_research/resources/current_share/"
        "canonical-event-integration-policy.json"
    )
    fixture_path = ROOT / "tests/fixtures/phase5e2b12a/adversarial-cases.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert hashlib.sha256(policy_path.read_bytes()).hexdigest() == (
        "815fbbd41f8ae307b6b758fd210830deb777a9e952e171b09e61e1a2b68fb16b"
    )
    assert hashlib.sha256(fixture_path.read_bytes()).hexdigest() == (
        "7f8ba762df20c51fbea5edee89e440ec7205c546416676211090ca950f65ec0d"
    )
    assert (policy["policy_id"], policy["policy_version"]) == (
        CURRENT_SHARE_INTEGRATION_POLICY_ID,
        CURRENT_SHARE_INTEGRATION_POLICY_VERSION,
    )
    assert fixture["schema_version"] == "2.0.0"
    assert len({item["case_id"] for item in fixture["cases"]}) == len(fixture["cases"])
    assert len({item["test_nodeid"] for item in fixture["cases"]}) == len(fixture["cases"])


def _independent_ast_sha256(source: str) -> str:
    tree = ast.parse(source, type_comments=True)
    payload = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def test_exact_type_module_ast_and_raw_bytes_reject_surface_and_body_mutations() -> None:
    path = ROOT / "src/owner_research/valuation_share_event_integration_types.py"
    source = path.read_text(encoding="utf-8")
    expected_ast = {
        (3, 11): "d242cf697494f21377f3260a25f5e6f3d2cacdaedeca65034dc5b448e5761a1c",
        (3, 12): "e18d6d9c55fd19392a6009252710865d9676d825186704dab7254fdafb6c629c",
        (3, 13): "78c8f6e361f62cbbefe10834517d5dcaba9fd43258e2507b7dcb9f7655dc0411",
        (3, 14): "78c8f6e361f62cbbefe10834517d5dcaba9fd43258e2507b7dcb9f7655dc0411",
    }
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        "003dfad8e1da2d07bddeaaf39310ad5a7529643e9a2aedbaffaa6d552683051d"
    )
    assert _independent_ast_sha256(source) == expected_ast[sys.version_info[:2]]

    mutations = (
        "\nimport os\n",
        "\ndef helper():\n    return None\n",
        "\nclass ExtraSurface:\n    pass\n",
        "\nif True:\n    side_effect = 1\n",
        source.replace(
            "class ShareEventNumericConsumption:\n",
            "class ShareEventNumericConsumption:\n"
            "    def emit_market_evidence(self):\n"
            "        return None\n\n",
            1,
        ),
        source.replace(
            "def _nonempty(value: str, label: str) -> None:\n",
            "def _nonempty(value: str, label: str) -> None:\n    value = value.strip()\n",
            1,
        ),
    )
    for mutation in mutations:
        mutated = source + mutation if not mutation.startswith("from __future__") else mutation
        if mutation.startswith("\n"):
            mutated = source + mutation
        assert _independent_ast_sha256(mutated) != expected_ast[sys.version_info[:2]]


def test_policy_loader_rejects_duplicate_unknown_numeric_and_nonfinite_json() -> None:
    path = (
        ROOT
        / "src/owner_research/resources/current_share/"
        "canonical-event-integration-policy.json"
    )
    raw = path.read_text(encoding="utf-8")

    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def load(value: str):
        return json.loads(
            value,
            object_pairs_hook=reject_duplicates,
            parse_int=lambda value: (_ for _ in ()).throw(ValueError(value)),
            parse_float=lambda value: (_ for _ in ()).throw(ValueError(value)),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )

    policy = load(raw)
    assert isinstance(policy, dict)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        "815fbbd41f8ae307b6b758fd210830deb777a9e952e171b09e61e1a2b68fb16b"
    )
    canonical = json.dumps(
        policy,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert hashlib.sha256(canonical).hexdigest() == (
        "332ba7d4cf4370126119fdc172082f5f3b19a82da8f65fe3a1e811fa726dc96f"
    )
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load('{"schema_version":"1.0.0","schema_version":"2.0.0"}')
    for invalid in (
        '{"unexpected":1}',
        '{"unexpected":1.0}',
        '{"unexpected":NaN}',
        '{"unexpected":Infinity}',
    ):
        with pytest.raises(ValueError):
            load(invalid)


def test_corroborating_sources_are_all_parents_but_consumed_once(sample_payloads) -> None:
    closure = _accepted_closure(sample_payloads=sample_payloads, corroborating_count=2)
    material = closure.materializations[0]
    assert len(material.members) == 2
    assert len(closure.numeric_consumptions) == 1
    assert closure.output_share_fact.value == 95_000_000
    assert set(material.canonical_event_fact.parent_fact_ids) == {
        item.fact_id for item in material.members
    }


def test_one_and_two_corroborating_sources_preserve_value_but_change_closure(
    sample_payloads,
) -> None:
    one = _accepted_closure(sample_payloads=sample_payloads, corroborating_count=1)
    two = _accepted_closure(sample_payloads=sample_payloads, corroborating_count=2)
    assert one.output_share_fact.value == two.output_share_fact.value == 95_000_000
    assert len(one.numeric_consumptions) == len(two.numeric_consumptions) == 1
    assert one.materializations[0].canonical_share_magnitude == (
        two.materializations[0].canonical_share_magnitude
    )
    assert one.materializations[0].materialization_fingerprint != (
        two.materializations[0].materialization_fingerprint
    )
    assert one.closure_sha256 != two.closure_sha256


def test_member_binding_rejects_a_forged_typed_fact(sample_payloads) -> None:
    material = _accepted_closure(sample_payloads=sample_payloads).materializations[0]
    member = material.members[0]
    forged_fact = replace(member.fact, value=int(member.fact.value) + 1)
    with pytest.raises(ValueError, match="does not replay"):
        replace(member, fact=forged_fact)


def test_bundle_closure_replays_the_complete_contract_graph(sample_payloads) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    raw_member_id = closure.materializations[0].members[0].fact_id
    incomplete = replace_graph(
        graph,
        facts=tuple(item for item in graph.facts if item.fact_id != raw_member_id),
    )
    with pytest.raises(ValueError):
        replace(
            closure.bundle_evidence_closure,
            validation_graph=incomplete,
        )


def test_grouping_magnitude_or_future_date_cannot_be_self_attested(sample_payloads) -> None:
    material = _accepted_closure(sample_payloads=sample_payloads).materializations[0]
    with pytest.raises(ValueError, match="grouping result"):
        replace(
            material,
            canonical_share_magnitude="9000000",
            materialization_fingerprint=canonical_sha256(
                {
                    **material.fingerprint_payload(),
                    "canonical_share_magnitude": "9000000",
                }
            ),
        )
    with pytest.raises(ValueError, match="execution start is invalid"):
        _grouping(event_date="2026-07-10")


def test_coverage_requires_all_eight_receipts_and_governed_zero_facts(sample_payloads) -> None:
    closure = _accepted_closure(sample_payloads=sample_payloads)
    ledger = closure.coverage_ledger
    with pytest.raises(ValueError, match="exactly one receipt"):
        replace(ledger, receipts=ledger.receipts[:1], receipt_ids=ledger.receipt_ids[:1])
    zero_entry = next(item for item in ledger.entries if item.zero_fact is not None)
    assert zero_entry.zero_fact is not None
    bad_zero = replace(zero_entry.zero_fact, value=1)
    bad_entry = _fingerprinted(
        CorporateActionCoverageEntryV2,
        {
            **zero_entry.fingerprint_payload(),
            "zero_fact": bad_zero,
        },
        "entry_fingerprint",
    )
    entries = tuple(bad_entry if item == zero_entry else item for item in ledger.entries)
    payload = {
        "issuer_id": ledger.issuer_id,
        "issuer_cik": ledger.issuer_cik,
        "security_id": ledger.security_id,
        "period_start": ledger.period_start,
        "period_end": ledger.period_end,
        "data_cutoff_date": ledger.data_cutoff_date,
        "expected_group_ids": ledger.expected_group_ids,
        "entries": entries,
        "receipts": ledger.receipts,
        "result_source_documents": ledger.result_source_documents,
        "receipt_ids": ledger.receipt_ids,
        "search_authority_id": ledger.search_authority_id,
        "search_authority_version": ledger.search_authority_version,
        "search_authority_code_sha256": ledger.search_authority_code_sha256,
    }
    payload["ledger_sha256"] = canonical_sha256(payload)
    with pytest.raises(ValueError, match="zero"):
        CorporateActionCoverageLedgerV2(**payload)


@pytest.mark.parametrize(
    ("updates", "message"),
    (
        ({"value": 5_000_000.0}, "exact JSON integer"),
        ({"confidence": "medium"}, "canonical group evidence"),
        ({"period": {"start": OPENING_DATE, "end": "2026-06-15"}}, "canonical group evidence"),
    ),
)
def test_observed_coverage_entry_rejects_noncanonical_numeric_evidence(
    sample_payloads,
    updates,
    message,
) -> None:
    closure = _accepted_closure(sample_payloads=sample_payloads)
    entry = next(item for item in closure.coverage_ledger.entries if item.status == "observed")
    original = entry.observed_member_facts[0]
    forged = replace(original, **updates)
    observed = tuple(
        forged if item.fact_id == original.fact_id else item
        for item in entry.observed_member_facts
    )
    payload = {**entry.fingerprint_payload(), "observed_member_facts": observed}
    with pytest.raises(ValueError, match=message):
        replace(
            entry,
            observed_member_facts=observed,
            entry_fingerprint=canonical_sha256(payload),
        )


@pytest.mark.parametrize(
    "event_date",
    (OPENING_DATE, "2026-07-01"),
)
def test_observed_coverage_ledger_rejects_event_outside_closed_window(
    sample_payloads,
    event_date,
) -> None:
    closure = _accepted_closure(sample_payloads=sample_payloads)
    ledger = closure.coverage_ledger
    entry = next(item for item in ledger.entries if item.status == "observed")
    original = entry.observed_member_facts[0]
    forged = replace(original, period={"start": None, "end": event_date})
    observed = tuple(
        forged if item.fact_id == original.fact_id else item
        for item in entry.observed_member_facts
    )
    entry_payload = {**entry.fingerprint_payload(), "observed_member_facts": observed}
    forged_entry = replace(
        entry,
        observed_member_facts=observed,
        entry_fingerprint=canonical_sha256(entry_payload),
    )
    entries = tuple(forged_entry if item == entry else item for item in ledger.entries)
    payload = _coverage_payload(ledger, entries=entries)
    with pytest.raises(ValueError, match="closed activity window"):
        CorporateActionCoverageLedgerV2(**payload)


def test_coverage_cik_is_bound_to_receipts_and_bundle_filing_authority(
    sample_payloads,
) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    ledger = closure.coverage_ledger
    forged_cik = "9999999999"
    documents = {item.document_id: item for item in ledger.result_source_documents}
    forged_receipts = tuple(
        build_source_search_receipt(
            issuer_id=receipt.issuer_id,
            source_family_id=receipt.source_family,
            query_scope={
                "cik": forged_cik,
                "event_types": tuple(receipt.query_scope["event_types"]),
            },
            period=receipt.period,
            cutoff_date=receipt.cutoff_date,
            searched_endpoints=receipt.searched_endpoints,
            result_documents=tuple(
                documents[identifier] for identifier in receipt.result_document_ids
            ),
            completed_at=receipt.completed_at,
            tool_version=receipt.tool_version,
        )
        for receipt in ledger.receipts
    )
    forged_receipt_ids = tuple(sorted(item.receipt_id for item in forged_receipts))
    forged_entries = _entries_with_receipts(ledger.entries, forged_receipt_ids)

    with pytest.raises(ValueError, match="does not replay"):
        CorporateActionCoverageLedgerV2(
            **_coverage_payload(
                ledger,
                entries=forged_entries,
                receipts=forged_receipts,
                receipt_ids=forged_receipt_ids,
            )
        )

    forged_ledger = CorporateActionCoverageLedgerV2(
        **_coverage_payload(
            ledger,
            issuer_cik=forged_cik,
            entries=forged_entries,
            receipts=forged_receipts,
            receipt_ids=forged_receipt_ids,
        )
    )
    assert forged_ledger.issuer_cik == forged_cik

    bundle_payload = _typed_bundle_payload(closure.bundle_evidence_closure)
    bundle_payload["issuer_cik"] = forged_cik
    bundle_payload["closure_sha256"] = canonical_sha256(bundle_payload)
    with pytest.raises(ValueError, match="issuer CIK authority"):
        CurrentShareBundleEvidenceClosure(
            **bundle_payload,
            validation_graph=graph,
        )


def test_complete_official_zero_coverage_closes_an_empty_event_window() -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(
        None,
        coverage_source,
        receipts,
        (opening_source, coverage_source),
    )
    assert ledger.expected_group_ids == ()
    assert len(ledger.entries) == len(CorporateActionCoverageLedgerV2.required_categories())
    assert all(item.status == "official_zero_or_no_activity" for item in ledger.entries)
    assert all(item.zero_fact is not None and item.zero_fact.value == 0 for item in ledger.entries)


def test_coverage_rejects_a_duplicate_registered_category() -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(
        None,
        coverage_source,
        receipts,
        (opening_source, coverage_source),
    )
    duplicated_entries = tuple(
        sorted((*ledger.entries, ledger.entries[0]), key=lambda item: item.category)
    )
    with pytest.raises(ValueError, match="exactly one entry per registered category"):
        CorporateActionCoverageLedgerV2(
            **_coverage_payload(ledger, entries=duplicated_entries)
        )


def test_not_applicable_review_chain_is_category_and_security_specific() -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(None, coverage_source, receipts, (opening_source, coverage_source))
    first_category = "acquisition_consideration"
    second_category = "convertible_conversion"
    first, *_ = _not_applicable_coverage_entry(
        category=first_category,
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
    )
    reused = replace(
        first,
        category=second_category,
        entry_fingerprint=canonical_sha256(
            {**first.fingerprint_payload(), "category": second_category}
        ),
    )
    entries = tuple(
        first
        if item.category == first_category
        else reused
        if item.category == second_category
        else item
        for item in ledger.entries
    )
    with pytest.raises(ValueError, match="category-specific|review chain is reused"):
        CorporateActionCoverageLedgerV2(**_coverage_payload(ledger, entries=entries))


def test_not_applicable_review_requires_exact_scope_named_human_and_hashes() -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(None, coverage_source, receipts, (opening_source, coverage_source))
    entry, _, candidate, decision, claim = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
    )

    bad_scope_candidate = replace(
        candidate,
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": "generic",
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
    )
    with pytest.raises(ValueError, match="reviewed proof"):
        replace(
            entry,
            not_applicable_candidate=bad_scope_candidate,
            entry_fingerprint=canonical_sha256(
                {
                    **entry.fingerprint_payload(),
                    "not_applicable_candidate": bad_scope_candidate,
                }
            ),
        )

    unnamed_decision = replace(decision, reviewer_id="human:")
    with pytest.raises(ValueError, match="reviewed proof"):
        replace(
            entry,
            review_decision=unnamed_decision,
            entry_fingerprint=canonical_sha256(
                {
                    **entry.fingerprint_payload(),
                    "review_decision": unnamed_decision,
                }
            ),
        )

    mismatched_decision = replace(decision, candidate_fingerprint=SHA_E)
    with pytest.raises(ValueError, match="reviewed proof"):
        replace(
            entry,
            review_decision=mismatched_decision,
            entry_fingerprint=canonical_sha256(
                {
                    **entry.fingerprint_payload(),
                    "review_decision": mismatched_decision,
                }
            ),
        )


def test_not_applicable_candidate_and_claim_must_be_period_safe() -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(None, coverage_source, receipts, (opening_source, coverage_source))
    entry, *_ = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
        as_of_date="2026-07-01",
    )
    entries = tuple(
        entry if item.category == entry.category else item for item in ledger.entries
    )
    with pytest.raises(ValueError, match="period-safe"):
        CorporateActionCoverageLedgerV2(**_coverage_payload(ledger, entries=entries))


def test_not_applicable_candidate_may_follow_period_end_through_cutoff() -> None:
    opening_source, coverage_source = _coverage_documents()
    cutoff = "2026-07-02"
    candidate_date = "2026-07-01"
    receipts = _receipts(
        (opening_source, coverage_source),
        cutoff_date=cutoff,
    )
    ledger = _coverage(
        None,
        coverage_source,
        receipts,
        (opening_source, coverage_source),
        data_cutoff_date=cutoff,
    )
    entry, *_ = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
        as_of_date=candidate_date,
        reviewed_at="2026-07-02T12:00:00Z",
    )
    entries = tuple(
        entry if item.category == entry.category else item for item in ledger.entries
    )
    rebuilt = CorporateActionCoverageLedgerV2(
        **_coverage_payload(ledger, entries=entries)
    )
    reviewed = next(
        item for item in rebuilt.entries if item.category == entry.category
    )
    assert reviewed.not_applicable_candidate is not None
    assert reviewed.not_applicable_candidate.as_of_date == candidate_date


def test_not_applicable_candidate_cannot_predate_the_covered_period_end() -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(None, coverage_source, receipts, (opening_source, coverage_source))
    entry, *_ = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
        as_of_date="2026-06-25",
        reviewed_at="2026-06-26T12:00:00Z",
    )
    entries = tuple(
        entry if item.category == entry.category else item for item in ledger.entries
    )
    with pytest.raises(ValueError, match="period-safe"):
        CorporateActionCoverageLedgerV2(**_coverage_payload(ledger, entries=entries))


def test_not_applicable_chain_ids_cannot_be_reused_across_categories() -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(None, coverage_source, receipts, (opening_source, coverage_source))
    first, *_ = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
    )
    second, *_ = _not_applicable_coverage_entry(
        category="convertible_conversion",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
    )
    reused_payload = {
        **second.fingerprint_payload(),
        "not_applicable_claim_id": first.not_applicable_claim_id,
        "not_applicable_claim": first.not_applicable_claim,
        "not_applicable_candidate": first.not_applicable_candidate,
        "review_decision_id": first.review_decision_id,
        "review_decision": first.review_decision,
        "not_applicable_supporting_facts": first.not_applicable_supporting_facts,
        "not_applicable_counterevidence_facts": (
            first.not_applicable_counterevidence_facts
        ),
    }
    forged_second = replace(
        second,
        not_applicable_claim_id=first.not_applicable_claim_id,
        not_applicable_claim=first.not_applicable_claim,
        not_applicable_candidate=first.not_applicable_candidate,
        review_decision_id=first.review_decision_id,
        review_decision=first.review_decision,
        not_applicable_supporting_facts=first.not_applicable_supporting_facts,
        not_applicable_counterevidence_facts=(
            first.not_applicable_counterevidence_facts
        ),
        entry_fingerprint=canonical_sha256(reused_payload),
    )
    entries = tuple(
        first
        if item.category == first.category
        else forged_second
        if item.category == second.category
        else item
        for item in ledger.entries
    )
    with pytest.raises(ValueError, match="category-specific|review chain is reused"):
        CorporateActionCoverageLedgerV2(**_coverage_payload(ledger, entries=entries))


@pytest.mark.parametrize("reused_identity", ("candidate", "decision", "claim"))
def test_each_not_applicable_review_identity_is_unique_per_category(reused_identity) -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(None, coverage_source, receipts, (opening_source, coverage_source))
    first, _, first_candidate, first_decision, first_claim = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
    )
    second, _, second_candidate, second_decision, second_claim = _not_applicable_coverage_entry(
        category="convertible_conversion",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
    )
    updates: dict[str, object] = {}
    if reused_identity == "candidate":
        candidate = replace(second_candidate, candidate_id=first_candidate.candidate_id)
        decision = replace(
            second_decision,
            candidate_id=candidate.candidate_id,
            candidate_fingerprint=candidate.fingerprint,
        )
        updates = {
            "not_applicable_candidate": candidate,
            "review_decision": decision,
        }
    elif reused_identity == "decision":
        decision = replace(second_decision, decision_id=first_decision.decision_id)
        updates = {
            "review_decision_id": decision.decision_id,
            "review_decision": decision,
        }
    else:
        claim = replace(second_claim, claim_id=first_claim.claim_id)
        decision = replace(second_decision, output_claim_id=claim.claim_id)
        updates = {
            "not_applicable_claim_id": claim.claim_id,
            "not_applicable_claim": claim,
            "review_decision": decision,
        }
    second_payload = {**second.fingerprint_payload(), **updates}
    forged_second = replace(
        second,
        **updates,
        entry_fingerprint=canonical_sha256(second_payload),
    )
    entries = tuple(
        first
        if item.category == first.category
        else forged_second
        if item.category == second.category
        else item
        for item in ledger.entries
    )
    with pytest.raises(ValueError, match="review chain is reused"):
        CorporateActionCoverageLedgerV2(**_coverage_payload(ledger, entries=entries))


def test_distinct_not_applicable_chains_may_share_one_supporting_fact() -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(None, coverage_source, receipts, (opening_source, coverage_source))
    shared_support = _fact(
        fact_id="fact:coverage-na:shared-structure",
        concept="share_activity_scope_evidence",
        value=1,
        source=coverage_source,
        end=QUOTE_DATE,
        unit="count",
    )
    first, *_ = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
        support_fact=shared_support,
    )
    second, *_ = _not_applicable_coverage_entry(
        category="convertible_conversion",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
        support_fact=shared_support,
    )
    entries = tuple(
        first
        if item.category == first.category
        else second
        if item.category == second.category
        else item
        for item in ledger.entries
    )
    rebuilt = CorporateActionCoverageLedgerV2(**_coverage_payload(ledger, entries=entries))
    assert tuple(
        item.category
        for item in rebuilt.entries
        if item.status == "not_applicable_with_reviewed_proof"
    ) == ("acquisition_consideration", "convertible_conversion")


def test_not_applicable_claim_is_an_exact_candidate_projection() -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(None, coverage_source, receipts, (opening_source, coverage_source))
    entry, _, candidate, decision, claim = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
    )

    changed_claim = replace(claim, confidence="medium")
    with pytest.raises(ValueError, match="exact reviewed proof"):
        replace(
            entry,
            not_applicable_claim=changed_claim,
            entry_fingerprint=canonical_sha256(
                {
                    **entry.fingerprint_payload(),
                    "not_applicable_claim": changed_claim,
                }
            ),
        )

    forged_candidate = replace(candidate, evidence_graph_sha256=SHA_E)
    synchronized_decision = replace(
        decision,
        candidate_fingerprint=forged_candidate.fingerprint,
        evidence_graph_sha256=SHA_E,
    )
    with pytest.raises(ValueError, match="exact reviewed proof"):
        replace(
            entry,
            not_applicable_candidate=forged_candidate,
            review_decision=synchronized_decision,
            entry_fingerprint=canonical_sha256(
                {
                    **entry.fingerprint_payload(),
                    "not_applicable_candidate": forged_candidate,
                    "review_decision": synchronized_decision,
                }
            ),
        )


def test_not_applicable_review_and_support_must_replay_governed_time_and_sources() -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(None, coverage_source, receipts, (opening_source, coverage_source))
    entry, _, _, decision, _ = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
    )
    early_decision = replace(decision, reviewed_at="2026-03-01T12:00:00Z")
    early_entry = replace(
        entry,
        review_decision=early_decision,
        entry_fingerprint=canonical_sha256(
            {**entry.fingerprint_payload(), "review_decision": early_decision}
        ),
    )
    entries = tuple(
        early_entry if item.category == early_entry.category else item
        for item in ledger.entries
    )
    with pytest.raises(ValueError, match="period-safe"):
        CorporateActionCoverageLedgerV2(**_coverage_payload(ledger, entries=entries))

    outside_source = _source(
        "outside-na-search",
        document_type="10-K",
        published_date="2026-06-20",
    )
    outside_entry, *_ = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=outside_source,
        receipt_ids=ledger.receipt_ids,
    )
    outside_entries = tuple(
        outside_entry if item.category == outside_entry.category else item
        for item in ledger.entries
    )
    with pytest.raises(ValueError, match="period-safe"):
        CorporateActionCoverageLedgerV2(
            **_coverage_payload(ledger, entries=outside_entries)
        )


def test_not_applicable_review_cannot_postdate_the_data_cutoff() -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(None, coverage_source, receipts, (opening_source, coverage_source))
    future_entry, *_ = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
        reviewed_at="2026-07-01T00:00:00Z",
    )
    entries = tuple(
        future_entry if item.category == future_entry.category else item
        for item in ledger.entries
    )
    with pytest.raises(ValueError, match="period-safe"):
        CorporateActionCoverageLedgerV2(**_coverage_payload(ledger, entries=entries))


@pytest.mark.parametrize("future_evidence", ("fact_period", "source_publication"))
def test_not_applicable_support_cannot_postdate_the_candidate(future_evidence) -> None:
    opening_source, coverage_source = _coverage_documents()
    candidate_date = "2026-07-01"
    cutoff = "2026-07-02"
    support_source = (
        _source(
            "coverage-na-future-support-source",
            document_type="8-K",
            published_date=cutoff,
        )
        if future_evidence == "source_publication"
        else coverage_source
    )
    documents = tuple({
        item.document_id: item
        for item in (opening_source, coverage_source, support_source)
    }.values())
    receipts = _receipts(documents, cutoff_date=cutoff)
    ledger = _coverage(
        None,
        coverage_source,
        receipts,
        documents,
        data_cutoff_date=cutoff,
    )
    support = _fact(
        fact_id=f"fact:coverage-na:future-{future_evidence}",
        concept="share_activity_acquisition_consideration_not_applicable_evidence",
        value=1,
        source=support_source,
        end=cutoff if future_evidence == "fact_period" else candidate_date,
        unit="count",
    )
    future_entry, *_ = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
        as_of_date=candidate_date,
        reviewed_at="2026-07-02T12:00:00Z",
        support_fact=support,
    )
    entries = tuple(
        future_entry if item.category == future_entry.category else item
        for item in ledger.entries
    )
    with pytest.raises(ValueError, match="period-safe"):
        CorporateActionCoverageLedgerV2(**_coverage_payload(ledger, entries=entries))


@pytest.mark.parametrize("future_evidence", ("fact_period", "source_publication"))
def test_not_applicable_counterevidence_cannot_postdate_the_candidate(
    future_evidence,
) -> None:
    opening_source, coverage_source = _coverage_documents()
    candidate_date = "2026-07-01"
    cutoff = "2026-07-02"
    counter_source = _source(
        f"coverage-na-counter-{future_evidence}",
        document_type="8-K",
        published_date=(cutoff if future_evidence == "source_publication" else QUOTE_DATE),
    )
    documents = (opening_source, coverage_source, counter_source)
    receipts = _receipts(documents, cutoff_date=cutoff)
    ledger = _coverage(
        None,
        coverage_source,
        receipts,
        documents,
        data_cutoff_date=cutoff,
    )
    counter = _fact(
        fact_id=f"fact:coverage-na:counter-{future_evidence}",
        concept="share_activity_acquisition_consideration_counterevidence",
        value=1,
        source=counter_source,
        end=(cutoff if future_evidence == "fact_period" else candidate_date),
        unit="count",
    )
    entry, *_ = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
        as_of_date=candidate_date,
        reviewed_at="2026-07-02T12:00:00Z",
        counterevidence_fact=counter,
    )
    entries = tuple(
        entry if item.category == entry.category else item for item in ledger.entries
    )
    with pytest.raises(ValueError, match="period-safe"):
        CorporateActionCoverageLedgerV2(**_coverage_payload(ledger, entries=entries))


@pytest.mark.parametrize(
    "non_fact_field",
    ("calculation_result_id", "context_observation_id"),
)
def test_not_applicable_candidate_bindings_must_be_direct_fact_only(
    non_fact_field,
) -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(None, coverage_source, receipts, (opening_source, coverage_source))
    entry, _, candidate, decision, claim = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
    )
    extra_binding = {
        "binding_id": f"binding:coverage-na:extra-{non_fact_field}",
        "fact_id": None,
        "calculation_result_id": None,
        "context_observation_id": None,
    }
    extra_binding[non_fact_field] = f"evidence:unbound:{non_fact_field}"
    supporting_bindings = (*candidate.supporting_evidence_bindings, extra_binding)
    evidence_graph_sha256 = canonical_sha256(
        {
            "supporting_evidence_bindings": supporting_bindings,
            "counterevidence_bindings": candidate.counterevidence_bindings,
        }
    )
    forged_candidate = replace(
        candidate,
        supporting_evidence_bindings=supporting_bindings,
        evidence_graph_sha256=evidence_graph_sha256,
    )
    forged_decision = replace(
        decision,
        candidate_fingerprint=forged_candidate.fingerprint,
        evidence_graph_sha256=evidence_graph_sha256,
    )
    with pytest.raises(ValueError, match="direct Fact-only"):
        replace(
            entry,
            not_applicable_candidate=forged_candidate,
            review_decision=forged_decision,
            entry_fingerprint=canonical_sha256(
                {
                    **entry.fingerprint_payload(),
                    "not_applicable_candidate": forged_candidate,
                    "review_decision": forged_decision,
                }
            ),
        )


def test_not_applicable_binding_ids_are_unique_across_evidence_polarities() -> None:
    opening_source, coverage_source = _coverage_documents()
    receipts = _receipts((opening_source, coverage_source))
    ledger = _coverage(None, coverage_source, receipts, (opening_source, coverage_source))
    entry, _, candidate, decision, claim = _not_applicable_coverage_entry(
        category="acquisition_consideration",
        source=coverage_source,
        receipt_ids=ledger.receipt_ids,
    )
    reused_binding = {
        **candidate.supporting_evidence_bindings[0],
        "fact_id": "fact:coverage-na:counterevidence",
    }
    counterevidence_bindings = (reused_binding,)
    evidence_graph_sha256 = canonical_sha256(
        {
            "supporting_evidence_bindings": candidate.supporting_evidence_bindings,
            "counterevidence_bindings": counterevidence_bindings,
        }
    )
    forged_candidate = replace(
        candidate,
        counterevidence_bindings=counterevidence_bindings,
        evidence_graph_sha256=evidence_graph_sha256,
    )
    forged_decision = replace(
        decision,
        candidate_fingerprint=forged_candidate.fingerprint,
        evidence_graph_sha256=evidence_graph_sha256,
    )
    forged_claim = replace(
        claim,
        counterevidence_fact_ids=(str(reused_binding["fact_id"]),),
    )
    with pytest.raises(ValueError, match="exact reviewed proof"):
        replace(
            entry,
            not_applicable_claim=forged_claim,
            not_applicable_candidate=forged_candidate,
            review_decision=forged_decision,
            entry_fingerprint=canonical_sha256(
                {
                    **entry.fingerprint_payload(),
                    "not_applicable_claim": forged_claim,
                    "not_applicable_candidate": forged_candidate,
                    "review_decision": forged_decision,
                }
            ),
        )


def test_cross_issuer_coverage_and_synchronized_extra_objects_are_rejected(sample_payloads) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    ledger = closure.coverage_ledger
    ledger_payload = {
        "issuer_id": "issuer:other",
        "issuer_cik": ledger.issuer_cik,
        "security_id": ledger.security_id,
        "period_start": ledger.period_start,
        "period_end": ledger.period_end,
        "data_cutoff_date": ledger.data_cutoff_date,
        "expected_group_ids": ledger.expected_group_ids,
        "entries": ledger.entries,
        "receipts": ledger.receipts,
        "result_source_documents": ledger.result_source_documents,
        "receipt_ids": ledger.receipt_ids,
        "search_authority_id": ledger.search_authority_id,
        "search_authority_version": ledger.search_authority_version,
        "search_authority_code_sha256": ledger.search_authority_code_sha256,
    }
    ledger_payload["ledger_sha256"] = canonical_sha256(ledger_payload)
    with pytest.raises(ValueError, match="does not replay"):
        CorporateActionCoverageLedgerV2(**ledger_payload)

    extra = ("Fact", "fact:unrelated", SHA_E)
    bundle = closure.bundle_evidence_closure
    extended_objects = tuple(sorted((*closure.bundle_evidence_closure.object_fingerprints, extra)))
    bundle_payload = _typed_bundle_payload(bundle)
    bundle_payload.update(
        {
            "research_bundle": bundle.research_bundle,
            "run_manifest": bundle.run_manifest,
            "security_compilation_result": bundle.security_compilation_result,
            "grouping_result": bundle.grouping_result,
            "source_documents": bundle.source_documents,
            "current_share_dependency_closure_sha256": dependency_closure_sha256(
                list(extended_objects)
            ),
            "extension_object_fingerprints": tuple(
                sorted((*bundle.extension_object_fingerprints, extra))
            ),
            "object_fingerprints": extended_objects,
        }
    )
    bundle_payload["closure_sha256"] = canonical_sha256(bundle_payload)
    with pytest.raises(ValueError, match="does not resolve"):
        CurrentShareBundleEvidenceClosure(
            **bundle_payload,
            validation_graph=graph,
        )


def test_bundle_identity_and_contract_sha_cannot_be_self_attested(sample_payloads) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    bundle = closure.bundle_evidence_closure
    forged_payload = _typed_bundle_payload(bundle)
    forged_payload.update(
        {
            "research_bundle": bundle.research_bundle,
            "run_manifest": bundle.run_manifest,
            "security_compilation_result": bundle.security_compilation_result,
            "grouping_result": bundle.grouping_result,
            "source_documents": bundle.source_documents,
            "object_fingerprints": bundle.object_fingerprints,
            "research_bundle_fingerprint": SHA_E,
        }
    )
    forged_payload["closure_sha256"] = canonical_sha256(forged_payload)
    with pytest.raises(ValueError, match="does not replay"):
        CurrentShareBundleEvidenceClosure(**forged_payload, validation_graph=graph)

    material = closure.materializations[0]
    with pytest.raises(ValueError, match="code SHA"):
        replace(
            material,
            materialization_code_sha256=SHA_E,
            materialization_fingerprint=canonical_sha256(
                {
                    **material.fingerprint_payload(),
                    "materialization_code_sha256": SHA_E,
                }
            ),
        )


@pytest.mark.parametrize("conflicting_content", (False, True))
def test_bundle_rejects_duplicate_typed_source_documents(
    conflicting_content,
    sample_payloads,
) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    bundle = closure.bundle_evidence_closure
    duplicate = bundle.source_documents[0]
    if conflicting_content:
        duplicate = replace(duplicate, content_sha256=SHA_E)
    duplicated_sources = tuple(
        sorted(
            (*bundle.source_documents, duplicate),
            key=lambda item: item.document_id,
        )
    )
    payload = _typed_bundle_payload(bundle)
    payload.update(
        {
            "research_bundle": bundle.research_bundle,
            "run_manifest": bundle.run_manifest,
            "security_compilation_result": bundle.security_compilation_result,
            "grouping_result": bundle.grouping_result,
            "source_documents": duplicated_sources,
        }
    )
    payload["closure_sha256"] = canonical_sha256(payload)
    with pytest.raises(ValueError, match="SourceDocuments are duplicated"):
        CurrentShareBundleEvidenceClosure(**payload, validation_graph=graph)


@pytest.mark.parametrize(
    "substitution",
    ("official_zero_fact", "result_source_document"),
)
def test_recursive_closure_byte_binds_all_typed_coverage_evidence(
    substitution,
    sample_payloads,
) -> None:
    closure, _ = _accepted_empty_context(sample_payloads=sample_payloads)
    ledger = closure.coverage_ledger
    if substitution == "official_zero_fact":
        entry = ledger.entries[0]
        assert entry.zero_fact is not None
        forged_zero = replace(
            entry.zero_fact,
            source_locator="fixture:caller-forged-zero-evidence",
        )
        forged_entry = replace(
            entry,
            zero_fact=forged_zero,
            entry_fingerprint=canonical_sha256(
                {**entry.fingerprint_payload(), "zero_fact": forged_zero}
            ),
        )
        entries = tuple(
            forged_entry if item.category == entry.category else item
            for item in ledger.entries
        )
        forged_ledger = CorporateActionCoverageLedgerV2(
            **_coverage_payload(ledger, entries=entries)
        )
    else:
        source = ledger.result_source_documents[0]
        forged_source = replace(source, content_sha256=SHA_E)
        sources = tuple(
            forged_source if item.document_id == source.document_id else item
            for item in ledger.result_source_documents
        )
        forged_ledger = CorporateActionCoverageLedgerV2(
            **_coverage_payload(ledger, result_source_documents=sources)
        )

    outer_payload = closure.hash_payload()
    outer_payload.update(
        {
            "coverage_ledger": forged_ledger.to_dict(),
            "coverage_closure_sha256": forged_ledger.ledger_sha256,
        }
    )
    with pytest.raises(ValueError, match="byte-bound"):
        replace(
            closure,
            coverage_ledger=forged_ledger,
            coverage_closure_sha256=forged_ledger.ledger_sha256,
            closure_sha256=canonical_sha256(outer_payload),
        )


@pytest.mark.parametrize(
    "duplicate_field",
    (
        "fact_ids",
        "source_document_ids",
        "object_fingerprints",
        "object_fingerprint_conflict",
    ),
)
def test_bundle_replay_rejects_duplicate_security_closure_identities(
    duplicate_field,
    sample_payloads,
) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    bundle = closure.bundle_evidence_closure
    security = bundle.security_compilation_result
    assert security.evidence_closure is not None
    evidence = security.evidence_closure
    source_field = (
        "object_fingerprints"
        if duplicate_field == "object_fingerprint_conflict"
        else duplicate_field
    )
    duplicate_value = getattr(evidence, source_field)[0]
    if duplicate_field == "object_fingerprint_conflict":
        duplicate_value = (duplicate_value[0], duplicate_value[1], SHA_E)
    duplicated = tuple(sorted((*getattr(evidence, source_field), duplicate_value)))
    evidence_payload = {
        "issuer_id": evidence.issuer_id,
        "data_cutoff_date": evidence.data_cutoff_date,
        "source_document_ids": tuple(sorted(evidence.source_document_ids)),
        "fact_ids": tuple(sorted(evidence.fact_ids)),
        "claim_id": evidence.claim_id,
        "candidate_id": evidence.candidate_id,
        "review_decision_id": evidence.review_decision_id,
        "object_fingerprints": tuple(sorted(evidence.object_fingerprints)),
    }
    evidence_payload[source_field] = duplicated
    forged_evidence = SecurityIdentityEvidenceClosure(
        **evidence_payload,
        closure_sha256=canonical_sha256(evidence_payload),
    )
    forged_security = replace(security, evidence_closure=forged_evidence)
    payload = _typed_bundle_payload(bundle)
    payload.update(
        {
            "research_bundle": bundle.research_bundle,
            "run_manifest": bundle.run_manifest,
            "security_compilation_result": forged_security,
            "security_compilation_fingerprint": forged_security.fingerprint,
            "grouping_result": bundle.grouping_result,
            "source_documents": bundle.source_documents,
        }
    )
    payload["closure_sha256"] = canonical_sha256(payload)
    with pytest.raises(ValueError, match="duplicate typed identities"):
        CurrentShareBundleEvidenceClosure(**payload, validation_graph=graph)


def test_receipts_bind_completion_time_and_actual_source_family(sample_payloads) -> None:
    closure = _accepted_closure(sample_payloads=sample_payloads)
    ledger = closure.coverage_ledger
    first = ledger.receipts[0]
    early = replace(first, completed_at="2026-03-01T00:00:00Z")
    early_receipts = tuple(early if item == first else item for item in ledger.receipts)
    early_payload = {
        "issuer_id": ledger.issuer_id,
        "issuer_cik": ledger.issuer_cik,
        "security_id": ledger.security_id,
        "period_start": ledger.period_start,
        "period_end": ledger.period_end,
        "data_cutoff_date": ledger.data_cutoff_date,
        "expected_group_ids": ledger.expected_group_ids,
        "entries": ledger.entries,
        "receipts": early_receipts,
        "result_source_documents": ledger.result_source_documents,
        "receipt_ids": ledger.receipt_ids,
        "search_authority_id": ledger.search_authority_id,
        "search_authority_version": ledger.search_authority_version,
        "search_authority_code_sha256": ledger.search_authority_code_sha256,
    }
    early_payload["ledger_sha256"] = canonical_sha256(early_payload)
    with pytest.raises(ValueError, match="does not replay"):
        CorporateActionCoverageLedgerV2(**early_payload)

    ten_k = next(item for item in ledger.receipts if item.source_family == "10-K")
    ten_q_document = next(
        item for item in ledger.result_source_documents if item.document_type == "10-Q"
    )
    wrong_family = replace(ten_k, result_document_ids=(ten_q_document.document_id,))
    wrong_receipts = tuple(wrong_family if item == ten_k else item for item in ledger.receipts)
    wrong_payload = {**early_payload, "receipts": wrong_receipts}
    wrong_payload["ledger_sha256"] = canonical_sha256(wrong_payload)
    with pytest.raises(ValueError, match="does not replay|source family"):
        CorporateActionCoverageLedgerV2(**wrong_payload)

    naive = replace(first, completed_at="2026-07-16T01:00:00")
    naive_receipts = tuple(naive if item == first else item for item in ledger.receipts)
    naive_payload = {**early_payload, "receipts": naive_receipts}
    naive_payload["ledger_sha256"] = canonical_sha256(naive_payload)
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        CorporateActionCoverageLedgerV2(**naive_payload)

    unofficial = replace(
        ten_q_document,
        authority_level="secondary",
        source_url="https://example.org/unofficial-quarterly-source",
    )
    unofficial_documents = tuple(
        unofficial if item == ten_q_document else item for item in ledger.result_source_documents
    )
    unofficial_payload = {
        **early_payload,
        "receipts": ledger.receipts,
        "result_source_documents": unofficial_documents,
    }
    unofficial_payload["ledger_sha256"] = canonical_sha256(unofficial_payload)
    with pytest.raises(ValueError, match="official"):
        CorporateActionCoverageLedgerV2(**unofficial_payload)


def test_hidden_governed_event_cannot_be_closed_as_zero_activity(sample_payloads) -> None:
    grouping_evidence = _grouping()
    _, _, event_sources, _, _, _ = grouping_evidence
    opening_source, coverage_source = _coverage_documents()
    opening_fact = _fact(
        fact_id="fact:shares:hidden-event-opening",
        concept="common_shares_outstanding",
        value=100_000_000,
        source=opening_source,
        end=OPENING_DATE,
    )
    receipts = _receipts((*event_sources, opening_source, coverage_source))
    coverage = _coverage(
        None,
        coverage_source,
        receipts,
        (*event_sources, opening_source, coverage_source),
    )
    graph, security = _governed_graph(
        sample_payloads,
        grouping_evidence=grouping_evidence,
        opening_fact=opening_fact,
        coverage=coverage,
    )
    empty_grouping = _empty_grouping()
    with pytest.raises(ValueError, match="grouping does not replay"):
        _bundle_closure(
            graph=graph,
            opening_fact=opening_fact,
            materializations=(),
            coverage=coverage,
            transitions=_empty_transitions(),
            grouping=empty_grouping,
            security=security,
            reserved_output_share_fact_id=_reserved_output_share_fact_id(
                issuer_id=ISSUER,
                security_id=SECURITY,
                quote_date=QUOTE_DATE,
                opening_share_fact_id=opening_fact.fact_id,
                grouping_result_fingerprint=empty_grouping.grouping_fingerprint,
            ),
        )


def test_security_identity_is_replayed_after_synchronized_caller_forgery(
    sample_payloads,
) -> None:
    closure, graph = _accepted_empty_context(sample_payloads=sample_payloads)
    bundle = closure.bundle_evidence_closure
    assert bundle.security_compilation_result.decision is not None
    forged_security_id = "security:issuer:acme:XNYS:FORGED:common"
    forged_decision = replace(
        bundle.security_compilation_result.decision,
        security_id=forged_security_id,
        ticker="FORGED",
    )
    forged_security = replace(
        bundle.security_compilation_result,
        decision=forged_decision,
    )
    grouping_payload = bundle.grouping_result.fingerprint_payload()
    grouping_payload["security_id"] = forged_security_id
    forged_grouping = ShareEventGroupingResult(
        **grouping_payload,
        grouping_fingerprint=canonical_sha256(grouping_payload),
    )
    payload = _typed_bundle_payload(bundle)
    payload.update(
        {
            "research_bundle": bundle.research_bundle,
            "run_manifest": bundle.run_manifest,
            "security_compilation_result": forged_security,
            "security_compilation_fingerprint": forged_security.fingerprint,
            "grouping_result": forged_grouping,
            "grouping_result_fingerprint": forged_grouping.grouping_fingerprint,
            "source_documents": bundle.source_documents,
        }
    )
    payload["closure_sha256"] = canonical_sha256(payload)
    with pytest.raises(
        ValueError,
        match="deterministically derived|security identity does not replay",
    ):
        CurrentShareBundleEvidenceClosure(**payload, validation_graph=graph)


def test_counterevidence_is_inside_the_recursive_extension_closure(sample_payloads) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    bundle = closure.bundle_evidence_closure
    source = bundle.source_documents[0]
    support = _fact(
        fact_id="fact:extension-claim:support",
        concept="reviewed_extension_support",
        value=1,
        source=source,
        end=CUTOFF,
        unit="count",
    )
    counter = _fact(
        fact_id="fact:extension-claim:counterevidence",
        concept="reviewed_extension_counterevidence",
        value=1,
        source=source,
        end=CUTOFF,
        unit="count",
    )
    support_binding = {
        "binding_id": "binding:extension-claim:support",
        "fact_id": support.fact_id,
        "calculation_result_id": None,
        "context_observation_id": None,
    }
    counter_binding = {
        "binding_id": "binding:extension-claim:counterevidence",
        "fact_id": counter.fact_id,
        "calculation_result_id": None,
        "context_observation_id": None,
    }
    evidence_graph_sha256 = canonical_sha256(
        {
            "supporting_evidence_bindings": (support_binding,),
            "counterevidence_bindings": (counter_binding,),
        }
    )
    candidate = AnalyticalClaimCandidate(
        schema_version="2.0.0",
        candidate_id="candidate:extension-claim:counterevidence",
        issuer_id=ISSUER,
        as_of_date=CUTOFF,
        proposed_statement="The extension claim preserves reviewed counterevidence.",
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        claim_role="support",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=(support_binding,),
        counterevidence_bindings=(counter_binding,),
        counterevidence_search_note="Reviewed contradictory formal evidence through cutoff.",
        proposed_confidence="medium",
        falsification_condition="A later filing resolves the contradictory evidence.",
        generation_method="manual",
        evidence_graph_sha256=evidence_graph_sha256,
        validation_status="ready",
        validation_issues=(),
    )
    claim, decision = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id="human:mingji",
        reviewed_at="2026-06-30T22:00:00Z",
        rationale="Counterevidence remains material to the governed extension.",
    )
    assert claim is not None
    extended_graph = replace_graph(
        graph,
        facts=tuple(sorted((*graph.facts, support, counter), key=lambda item: item.fact_id)),
        claims=tuple(sorted((*graph.claims, claim), key=lambda item: item.claim_id)),
        analytical_claim_candidates=tuple(
            sorted(
                (*graph.analytical_claim_candidates, candidate),
                key=lambda item: item.candidate_id,
            )
        ),
        analytical_claim_review_decisions=tuple(
            sorted(
                (*graph.analytical_claim_review_decisions, decision),
                key=lambda item: item.decision_id,
            )
        ),
    )
    extended_graph.validate()
    extension_roots = tuple(sorted((*bundle.extension_root_ids, candidate.candidate_id)))
    public_roots = tuple(
        str(object_id)
        for reference in bundle.research_bundle.module_references
        for object_id in reference["object_ids"]
    )
    public_closure = dependency_closure(extended_graph, public_roots)
    extension_closure = _typed_extension_dependency_closure(
        extended_graph,
        extension_roots,
    )
    base_bindings = tuple(
        sorted(
            (contract_type, object_id, item.fingerprint)
            for object_id, (contract_type, item) in public_closure.items()
        )
    )
    extension_bindings = tuple(
        sorted(
            (contract_type, object_id, item.fingerprint)
            for object_id, (contract_type, item) in extension_closure.items()
            if object_id not in public_closure
        )
    )
    object_bindings = tuple(sorted((*base_bindings, *extension_bindings)))
    sources = tuple(
        sorted(
            (
                item
                for _, (contract_type, item) in extension_closure.items()
                if contract_type == "SourceDocument"
            ),
            key=lambda item: item.document_id,
        )
    )
    payload = _typed_bundle_payload(bundle)
    payload.update(
        {
            "research_bundle": bundle.research_bundle,
            "run_manifest": bundle.run_manifest,
            "security_compilation_result": bundle.security_compilation_result,
            "grouping_result": bundle.grouping_result,
            "source_documents": sources,
            "base_dependency_object_fingerprints": base_bindings,
            "extension_root_ids": extension_roots,
            "extension_object_fingerprints": extension_bindings,
            "object_fingerprints": object_bindings,
            "current_share_dependency_closure_sha256": dependency_closure_sha256(
                list(object_bindings)
            ),
            "contract_graph_fingerprint": _scoped_contract_graph_fingerprint(
                extended_graph,
                object_bindings,
            ),
        }
    )
    payload["closure_sha256"] = canonical_sha256(payload)
    extended_bundle = CurrentShareBundleEvidenceClosure(
        **payload,
        validation_graph=extended_graph,
    )
    counter_fact_id = counter.fact_id
    assert any(
        contract_type == "Fact" and object_id == counter_fact_id
        for contract_type, object_id, _ in extended_bundle.extension_object_fingerprints
    )

    truncated_extension = tuple(
        binding
        for binding in extended_bundle.extension_object_fingerprints
        if not (binding[0] == "Fact" and binding[1] == counter_fact_id)
    )
    truncated_objects = tuple(
        binding
        for binding in extended_bundle.object_fingerprints
        if not (binding[0] == "Fact" and binding[1] == counter_fact_id)
    )
    with pytest.raises(ValueError, match="scoped ContractGraph|dependency SHA|dependency closure"):
        replace(
            extended_bundle,
            extension_object_fingerprints=truncated_extension,
            object_fingerprints=truncated_objects,
            validation_graph=extended_graph,
        )


def test_source_content_change_invalidates_the_recursive_source_closure(sample_payloads) -> None:
    closure, graph = _accepted_context(sample_payloads=sample_payloads)
    bundle = closure.bundle_evidence_closure
    original = bundle.source_documents[0]
    changed = replace(original, content_sha256="f" * 64)
    changed_sources = tuple(
        changed if item.document_id == original.document_id else item
        for item in bundle.source_documents
    )
    with pytest.raises(ValueError, match="source set|source closure"):
        replace(bundle, source_documents=changed_sources, validation_graph=graph)


def test_observed_event_source_must_be_returned_by_governed_receipt(sample_payloads) -> None:
    closure = _accepted_closure(sample_payloads=sample_payloads)
    ledger = closure.coverage_ledger
    observed_source = closure.materializations[0].members[0].source_document
    family = next(
        item.source_family
        for item in ledger.receipts
        if observed_source.document_id in item.result_document_ids
    )
    replacement_receipts = []
    for receipt in ledger.receipts:
        documents = tuple(
            item
            for item in ledger.result_source_documents
            if item.document_id in receipt.result_document_ids
            and item.document_id != observed_source.document_id
        )
        replacement_receipts.append(
            build_source_search_receipt(
                issuer_id=receipt.issuer_id,
                source_family_id=receipt.source_family,
                query_scope=receipt.query_scope,
                period=receipt.period,
                cutoff_date=receipt.cutoff_date,
                searched_endpoints=COVERAGE_SEARCH_ENDPOINTS[receipt.source_family],
                result_documents=documents,
                completed_at=receipt.completed_at,
                tool_version=COVERAGE_SEARCH_TOOL_VERSION,
            )
        )
    assert family in SOURCE_FAMILIES
    receipts = tuple(sorted(replacement_receipts, key=lambda item: item.source_family))
    receipt_ids = tuple(sorted(item.receipt_id for item in receipts))
    entries = _entries_with_receipts(ledger.entries, receipt_ids)
    documents = tuple(
        item
        for item in ledger.result_source_documents
        if item.document_id != observed_source.document_id
    )
    with pytest.raises(ValueError, match="absent from its governed receipt"):
        CorporateActionCoverageLedgerV2(
            **_coverage_payload(
                ledger,
                entries=entries,
                receipts=receipts,
                receipt_ids=receipt_ids,
                result_source_documents=documents,
            )
        )


def test_search_endpoint_tool_and_receipt_identity_are_closed(sample_payloads) -> None:
    ledger = _accepted_closure(sample_payloads=sample_payloads).coverage_ledger
    original = ledger.receipts[0]
    documents = tuple(
        item
        for item in ledger.result_source_documents
        if item.document_id in original.result_document_ids
    )
    forged = build_source_search_receipt(
        issuer_id=original.issuer_id,
        source_family_id=original.source_family,
        query_scope=original.query_scope,
        period=original.period,
        cutoff_date=original.cutoff_date,
        searched_endpoints=("authority:evil-unregistered-endpoint",),
        result_documents=documents,
        completed_at=original.completed_at,
        tool_version="caller-self-attested/99.0.0",
    )
    receipts = tuple(forged if item == original else item for item in ledger.receipts)
    receipt_ids = tuple(sorted(item.receipt_id for item in receipts))
    entries = _entries_with_receipts(ledger.entries, receipt_ids)
    with pytest.raises(ValueError, match="does not replay"):
        CorporateActionCoverageLedgerV2(
            **_coverage_payload(
                ledger,
                entries=entries,
                receipts=receipts,
                receipt_ids=receipt_ids,
            )
        )


def test_wrong_output_arithmetic_is_rejected_even_when_all_hashes_are_recomputed(
    sample_payloads,
) -> None:
    with pytest.raises(ValueError, match="arithmetic"):
        _accepted_closure(sample_payloads=sample_payloads, output_value=85_000_000)


def test_claim_transition_chain_binds_fact_id_fingerprint_and_value(
    sample_payloads,
    monkeypatch,
) -> None:
    first_evidence = _grouping(concept="option_shares_exercised_completed")
    first_material = _materialization(
        grouping=first_evidence[0],
        raw_facts=first_evidence[1],
        event_sources=first_evidence[2],
        event_candidates=first_evidence[3],
        event_decisions=first_evidence[4],
        capital_event=first_evidence[5],
    )
    second_evidence = _grouping(
        concept="option_shares_exercised_completed",
        identity_suffix="2026-second",
    )
    second_material = _materialization(
        grouping=second_evidence[0],
        raw_facts=second_evidence[1],
        event_sources=second_evidence[2],
        event_candidates=second_evidence[3],
        event_decisions=second_evidence[4],
        capital_event=second_evidence[5],
    )
    affected_source = _source(
        "claim-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    affected_fact = _fact(
        fact_id="fact:claim:opening",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=affected_source,
        end=OPENING_DATE,
    )
    authority = _claim_authority(
        sample_payloads,
        monkeypatch,
        affected_fact,
    )
    economic_claim_key = dict(authority.root_economic_claim_bindings)[affected_fact.fact_id]
    first = _claim_transition(
        materialization=first_material,
        affected_fact=affected_fact,
        affected_source=affected_source,
        remaining_fact_id="fact:claim:remaining:first",
        economic_claim_key=economic_claim_key,
    )
    second = _claim_transition(
        materialization=second_material,
        affected_fact=affected_fact,
        affected_source=affected_source,
        remaining_fact_id="fact:claim:remaining:second",
        economic_claim_key=economic_claim_key,
    )

    with pytest.raises(ValueError, match="lineage ID is not deterministic"):
        replace(first, claim_lineage_id="claim-lineage:forged")
    with pytest.raises(ValueError, match="consumed more than once"):
        GroupBoundClaimTransitionReconciliation(
            issuer_id=ISSUER,
            security_id=SECURITY,
            opening_date=OPENING_DATE,
            quote_date=QUOTE_DATE,
            data_cutoff_date=CUTOFF,
            claim_control_authority=authority,
            claim_control_authority_fingerprint=authority.authority_fingerprint,
            expected_claim_sensitive_group_ids=(first.group_id, second.group_id),
            records=(first, second),
            reconciliation_sha256=SHA_A,
        )


def test_standard_option_transition_replays_one_reviewed_phase5c_dilution_root(
    sample_payloads,
    monkeypatch,
) -> None:
    event_concept = "option_shares_exercised_completed"
    evidence = _grouping(concept=event_concept)
    materialization = _materialization(
        grouping=evidence[0],
        raw_facts=evidence[1],
        event_sources=evidence[2],
        event_candidates=evidence[3],
        event_decisions=evidence[4],
        capital_event=evidence[5],
    )
    source = _source(
        f"phase5c-root-{event_concept}",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id=f"fact:claim-root:{event_concept}",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    authority = _claim_authority(sample_payloads, monkeypatch, root)
    economic_claim_key = dict(authority.root_economic_claim_bindings)[root.fact_id]
    transition = _claim_transition(
        materialization=materialization,
        affected_fact=root,
        affected_source=source,
        remaining_fact_id=f"fact:claim-remaining:{event_concept}",
        economic_claim_key=economic_claim_key,
    )
    payload = {
        "issuer_id": ISSUER,
        "security_id": SECURITY,
        "opening_date": OPENING_DATE,
        "quote_date": QUOTE_DATE,
        "data_cutoff_date": CUTOFF,
        "claim_control_authority": authority,
        "claim_control_authority_fingerprint": authority.authority_fingerprint,
        "expected_claim_sensitive_group_ids": (materialization.group_id,),
        "records": (transition,),
    }
    payload["reconciliation_sha256"] = canonical_sha256(payload)
    reconciliation = GroupBoundClaimTransitionReconciliation(**payload)
    assert reconciliation.records == (transition,)
    assert transition.affected_claim_root_fact.concept == "option_or_dilution_claim"
    assert transition.remaining_claim_fact.concept == CLAIM_SENSITIVE_EVENT_CONCEPTS[event_concept]


def test_claim_transition_review_chain_cannot_cross_the_data_cutoff(
    sample_payloads,
    monkeypatch,
) -> None:
    evidence = _grouping(concept="option_shares_exercised_completed")
    materialization = _materialization(
        grouping=evidence[0],
        raw_facts=evidence[1],
        event_sources=evidence[2],
        event_candidates=evidence[3],
        event_decisions=evidence[4],
        capital_event=evidence[5],
    )
    source = _source(
        "future-transition-root",
        document_type="10-K",
        published_date=OPENING_DATE,
    )
    root = _fact(
        fact_id="fact:claim-root:future-transition",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    authority = _claim_authority(sample_payloads, monkeypatch, root)
    economic_claim_key = dict(authority.root_economic_claim_bindings)[root.fact_id]
    transition = _claim_transition(
        materialization=materialization,
        affected_fact=root,
        affected_source=source,
        remaining_fact_id="fact:claim-remaining:future-transition",
        economic_claim_key=economic_claim_key,
    )
    candidate = replace(transition.candidates[0], as_of_date="2027-01-01")
    claim = replace(transition.claims[0], as_of_date="2027-01-01")
    decision = replace(
        transition.review_decisions[0],
        candidate_fingerprint=candidate.fingerprint,
        reviewed_at="2027-01-02T00:00:00Z",
    )
    transition_payload = transition.fingerprint_payload()
    transition_payload.update(
        {
            "claims": (claim.to_dict(),),
            "candidates": (candidate.to_dict(),),
            "review_decisions": (decision.to_dict(),),
            "claim_bindings": ((claim.claim_id, claim.fingerprint),),
            "candidate_bindings": ((candidate.candidate_id, candidate.fingerprint),),
            "review_decision_bindings": ((decision.decision_id, decision.fingerprint),),
        }
    )
    forged_transition = replace(
        transition,
        claims=(claim,),
        candidates=(candidate,),
        review_decisions=(decision,),
        claim_bindings=((claim.claim_id, claim.fingerprint),),
        candidate_bindings=((candidate.candidate_id, candidate.fingerprint),),
        review_decision_bindings=((decision.decision_id, decision.fingerprint),),
        transition_fingerprint=canonical_sha256(transition_payload),
    )
    reconciliation_payload = {
        "issuer_id": ISSUER,
        "security_id": SECURITY,
        "opening_date": OPENING_DATE,
        "quote_date": QUOTE_DATE,
        "data_cutoff_date": CUTOFF,
        "claim_control_authority": authority,
        "claim_control_authority_fingerprint": authority.authority_fingerprint,
        "expected_claim_sensitive_group_ids": (materialization.group_id,),
        "records": (forged_transition,),
    }
    reconciliation_payload["reconciliation_sha256"] = canonical_sha256(
        reconciliation_payload
    )
    with pytest.raises(ValueError, match="crosses the data cutoff"):
        GroupBoundClaimTransitionReconciliation(**reconciliation_payload)


def test_claim_transition_evidence_fact_cannot_cross_the_candidate_or_cutoff() -> None:
    evidence = _grouping(concept="option_shares_exercised_completed")
    materialization = _materialization(
        grouping=evidence[0],
        raw_facts=evidence[1],
        event_sources=evidence[2],
        event_candidates=evidence[3],
        event_decisions=evidence[4],
        capital_event=evidence[5],
    )
    source = _source(
        "future-transition-evidence",
        document_type="10-K",
        published_date="2026-06-20",
    )
    root = _fact(
        fact_id="fact:claim-root:future-evidence",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    transition = _claim_transition(
        materialization=materialization,
        affected_fact=root,
        affected_source=source,
        remaining_fact_id="fact:claim-remaining:future-evidence",
        economic_claim_key=SHA_A,
    )
    future_fact = _fact(
        fact_id="fact:claim-transition:future-support",
        concept="claim_transition_support",
        value=1,
        source=source,
        end="2027-01-01",
        unit="count",
    )
    candidate = transition.candidates[0]
    bindings = tuple(
        sorted(
            (
                *candidate.supporting_evidence_bindings,
                {
                    "binding_id": "binding:claim-transition:future-support",
                    "fact_id": future_fact.fact_id,
                    "calculation_result_id": None,
                    "context_observation_id": None,
                },
            ),
            key=lambda item: item["binding_id"],
        )
    )
    candidate = replace(
        candidate,
        supporting_evidence_bindings=bindings,
        evidence_graph_sha256=canonical_sha256(
            {
                "supporting_evidence_bindings": bindings,
                "counterevidence_bindings": candidate.counterevidence_bindings,
            }
        ),
    )
    claim = replace(
        transition.claims[0],
        supporting_fact_ids=tuple(
            sorted((*transition.claims[0].supporting_fact_ids, future_fact.fact_id))
        ),
    )
    decision = replace(
        transition.review_decisions[0],
        candidate_fingerprint=candidate.fingerprint,
        evidence_graph_sha256=candidate.evidence_graph_sha256,
    )
    evidence_facts = tuple(
        sorted((*transition.evidence_facts, future_fact), key=lambda item: item.fact_id)
    )
    payload = transition.fingerprint_payload()
    payload.update(
        {
            "evidence_facts": tuple(item.to_dict() for item in evidence_facts),
            "claims": (claim.to_dict(),),
            "candidates": (candidate.to_dict(),),
            "review_decisions": (decision.to_dict(),),
            "claim_bindings": ((claim.claim_id, claim.fingerprint),),
            "candidate_bindings": ((candidate.candidate_id, candidate.fingerprint),),
            "review_decision_bindings": (
                (decision.decision_id, decision.fingerprint),
            ),
        }
    )
    with pytest.raises(ValueError, match="analytical review chain"):
        replace(
            transition,
            evidence_facts=evidence_facts,
            claims=(claim,),
            candidates=(candidate,),
            review_decisions=(decision,),
            claim_bindings=((claim.claim_id, claim.fingerprint),),
            candidate_bindings=((candidate.candidate_id, candidate.fingerprint),),
            review_decision_bindings=((decision.decision_id, decision.fingerprint),),
            transition_fingerprint=canonical_sha256(payload),
        )


def test_claim_transition_evidence_source_cannot_postdate_the_candidate() -> None:
    evidence = _grouping(concept="option_shares_exercised_completed")
    materialization = _materialization(
        grouping=evidence[0],
        raw_facts=evidence[1],
        event_sources=evidence[2],
        event_candidates=evidence[3],
        event_decisions=evidence[4],
        capital_event=evidence[5],
    )
    claim_source = _source(
        "transition-source-publication-root",
        document_type="10-K",
        published_date=OPENING_DATE,
    )
    root = _fact(
        fact_id="fact:claim-root:source-publication",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=claim_source,
        end=OPENING_DATE,
    )
    transition = _claim_transition(
        materialization=materialization,
        affected_fact=root,
        affected_source=claim_source,
        remaining_fact_id="fact:claim-remaining:source-publication",
        economic_claim_key=SHA_A,
    )
    target = next(
        item
        for item in transition.evidence_source_documents
        if item.document_id != claim_source.document_id
    )
    future_source = replace(target, published_date="2027-01-01")
    sources = tuple(
        sorted(
            (
                future_source if item.document_id == target.document_id else item
                for item in transition.evidence_source_documents
            ),
            key=lambda item: item.document_id,
        )
    )
    payload = {
        **transition.fingerprint_payload(),
        "evidence_source_documents": tuple(item.to_dict() for item in sources),
    }
    with pytest.raises(ValueError, match="analytical review chain"):
        replace(
            transition,
            evidence_source_documents=sources,
            transition_fingerprint=canonical_sha256(payload),
        )


@pytest.mark.parametrize(
    "event_concept",
    (
        "convertible_shares_converted_completed",
        "warrant_shares_exercised_completed",
    ),
)
def test_convertible_and_warrant_transitions_require_specialist_authority(
    event_concept,
) -> None:
    evidence = _grouping(concept=event_concept)
    materialization = _materialization(
        grouping=evidence[0],
        raw_facts=evidence[1],
        event_sources=evidence[2],
        event_candidates=evidence[3],
        event_decisions=evidence[4],
        capital_event=evidence[5],
    )
    source = _source(
        f"specialist-root-{event_concept}",
        document_type="10-K",
        published_date="2026-03-31",
    )
    forged_generic_root = _fact(
        fact_id=f"fact:forged-generic-root:{event_concept}",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    with pytest.raises(ValueError, match="requires specialist authority"):
        _claim_transition(
            materialization=materialization,
            affected_fact=forged_generic_root,
            affected_source=source,
            remaining_fact_id=f"fact:specialist-remaining:{event_concept}",
            economic_claim_key=SHA_A,
        )


@pytest.mark.parametrize(
    "event_concept",
    (
        "convertible_shares_converted_completed",
        "warrant_shares_exercised_completed",
    ),
)
def test_current_share_closure_cannot_bypass_specialist_claim_authority(
    event_concept,
    sample_payloads,
) -> None:
    with pytest.raises(ValueError, match="requires specialist claim-transition authority"):
        _accepted_context(
            sample_payloads=sample_payloads,
            event_concept=event_concept,
            output_value=105_000_000,
        )


def test_claim_transition_rejects_common_shares_and_missing_canonical_parent() -> None:
    evidence = _grouping(concept="option_shares_exercised_completed")
    material = _materialization(
        grouping=evidence[0],
        raw_facts=evidence[1],
        event_sources=evidence[2],
        event_candidates=evidence[3],
        event_decisions=evidence[4],
        capital_event=evidence[5],
    )
    source = _source("claim-hardening", document_type="10-K", published_date="2026-03-31")
    ordinary_shares = _fact(
        fact_id="fact:ordinary-shares-not-claim",
        concept="common_shares_outstanding",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    with pytest.raises(ValueError, match="authoritative claim Facts"):
        _claim_transition(
            materialization=material,
            affected_fact=ordinary_shares,
            affected_source=source,
            remaining_fact_id="fact:ordinary-shares:remaining",
            economic_claim_key=SHA_A,
        )

    claim_root = _fact(
        fact_id="fact:option-claim:opening",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    transition = _claim_transition(
        materialization=material,
        affected_fact=claim_root,
        affected_source=source,
        remaining_fact_id="fact:option-claim:remaining",
        economic_claim_key=SHA_A,
    )
    broken_remaining = replace(
        transition.remaining_claim_fact,
        parent_fact_ids=(transition.affected_claim_root_fact_id,),
    )
    changed_payload = transition.fingerprint_payload()
    changed_payload.update(
        {
            "remaining_claim_fact": broken_remaining.to_dict(),
            "remaining_claim_fact_fingerprint": broken_remaining.fingerprint,
        }
    )
    with pytest.raises(ValueError, match="authoritative claim Facts"):
        replace(
            transition,
            remaining_claim_fact=broken_remaining,
            remaining_claim_fact_fingerprint=broken_remaining.fingerprint,
            transition_fingerprint=canonical_sha256(changed_payload),
        )


@pytest.mark.parametrize("attack", ("low-confidence", "free-locator", "unrelated-source"))
def test_claim_transition_remaining_fact_has_deterministic_authority(attack: str) -> None:
    evidence = _grouping(concept="option_shares_exercised_completed")
    material = _materialization(
        grouping=evidence[0],
        raw_facts=evidence[1],
        event_sources=evidence[2],
        event_candidates=evidence[3],
        event_decisions=evidence[4],
        capital_event=evidence[5],
    )
    source = _source(
        "claim-authority",
        document_type="10-K",
        published_date="2026-03-31",
    )
    claim_root = _fact(
        fact_id="fact:option-claim:authority-opening",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    transition = _claim_transition(
        materialization=material,
        affected_fact=claim_root,
        affected_source=source,
        remaining_fact_id="fact:option-claim:authority-remaining",
        economic_claim_key=SHA_A,
    )
    remaining_source = transition.remaining_claim_source_document
    if attack == "low-confidence":
        changed_fact = replace(transition.remaining_claim_fact, confidence="medium")
    elif attack == "free-locator":
        changed_fact = replace(
            transition.remaining_claim_fact,
            source_locator="fixture:caller-selected-remaining-source",
        )
    else:
        remaining_source = _source(
            "unrelated-authority",
            document_type="10-Q",
            published_date=EVENT_DATE,
        )
        changed_fact = replace(
            transition.remaining_claim_fact,
            source_document_id=remaining_source.document_id,
        )
    changed_payload = transition.fingerprint_payload()
    changed_payload.update(
        {
            "remaining_claim_fact": changed_fact.to_dict(),
            "remaining_claim_fact_fingerprint": changed_fact.fingerprint,
            "remaining_claim_source_document": remaining_source.to_dict(),
        }
    )
    with pytest.raises(ValueError, match="authoritative claim Facts"):
        replace(
            transition,
            remaining_claim_fact=changed_fact,
            remaining_claim_fact_fingerprint=changed_fact.fingerprint,
            remaining_claim_source_document=remaining_source,
            transition_fingerprint=canonical_sha256(changed_payload),
        )


def test_claim_transition_remaining_fact_identity_is_replay_deterministic() -> None:
    evidence = _grouping(concept="option_shares_exercised_completed")
    material = _materialization(
        grouping=evidence[0],
        raw_facts=evidence[1],
        event_sources=evidence[2],
        event_candidates=evidence[3],
        event_decisions=evidence[4],
        capital_event=evidence[5],
    )
    source = _source(
        "claim-identity",
        document_type="10-K",
        published_date="2026-03-31",
    )
    claim_root = _fact(
        fact_id="fact:option-claim:identity-opening",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    first = _claim_transition(
        materialization=material,
        affected_fact=claim_root,
        affected_source=source,
        remaining_fact_id="caller:a",
        economic_claim_key=SHA_A,
    )
    second = _claim_transition(
        materialization=material,
        affected_fact=claim_root,
        affected_source=source,
        remaining_fact_id="caller:b",
        economic_claim_key=SHA_A,
    )
    assert first.remaining_claim_fact_id == second.remaining_claim_fact_id
    assert first.transition_fingerprint == second.transition_fingerprint

    forged_fact = replace(
        first.remaining_claim_fact,
        fact_id="derived:claim-transition:caller-controlled",
        source_locator=_claim_transition_source_locator(
            "derived:claim-transition:caller-controlled"
        ),
    )
    forged_payload = first.fingerprint_payload()
    forged_payload.update(
        {
            "remaining_claim_fact_id": forged_fact.fact_id,
            "remaining_claim_fact_fingerprint": forged_fact.fingerprint,
            "remaining_claim_fact": forged_fact.to_dict(),
        }
    )
    with pytest.raises(ValueError, match="Fact ID is not deterministic"):
        replace(
            first,
            remaining_claim_fact_id=forged_fact.fact_id,
            remaining_claim_fact_fingerprint=forged_fact.fingerprint,
            remaining_claim_fact=forged_fact,
            transition_fingerprint=canonical_sha256(forged_payload),
        )


def test_claim_transition_review_chain_is_exact_and_economic_key_is_authorized(
    sample_payloads,
    monkeypatch,
) -> None:
    first_evidence = _grouping(concept="option_shares_exercised_completed")
    first_material = _materialization(
        grouping=first_evidence[0],
        raw_facts=first_evidence[1],
        event_sources=first_evidence[2],
        event_candidates=first_evidence[3],
        event_decisions=first_evidence[4],
        capital_event=first_evidence[5],
    )
    source = _source("two-economic-claims", document_type="10-K", published_date="2026-03-31")
    first_root = _fact(
        fact_id="fact:claim:first-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    second_root = _fact(
        fact_id="fact:claim:second-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    with pytest.raises(ValueError, match="multi-root economic claim"):
        _claim_authority(
            sample_payloads,
            monkeypatch,
            first_root,
            second_root,
        )
    authority = _claim_authority(sample_payloads, monkeypatch, first_root)
    reviewed_key = dict(authority.root_economic_claim_bindings)[first_root.fact_id]
    first = _claim_transition(
        materialization=first_material,
        affected_fact=first_root,
        affected_source=source,
        remaining_fact_id="fact:claim:first-remaining",
        economic_claim_key=reviewed_key,
    )
    with pytest.raises(ValueError, match="graph-owned full-freeze Phase 5C authority"):
        GroupBoundClaimTransitionReconciliation(
            issuer_id=ISSUER,
            security_id=SECURITY,
            opening_date=OPENING_DATE,
            quote_date=QUOTE_DATE,
            data_cutoff_date=CUTOFF,
            claim_control_authority=authority.phase5c_authority,  # type: ignore[arg-type]
            claim_control_authority_fingerprint=(authority.phase5c_authority_fingerprint),
            expected_claim_sensitive_group_ids=(first.group_id,),
            records=(first,),
            reconciliation_sha256=SHA_A,
        )
    for collection_name, binding_name, id_attribute in (
        ("claims", "claim_bindings", "claim_id"),
        ("candidates", "candidate_bindings", "candidate_id"),
        ("review_decisions", "review_decision_bindings", "decision_id"),
    ):
        original = getattr(first, collection_name)[0]
        for cardinality in (0, 2):
            items = ()
            if cardinality == 2:
                extra = replace(
                    original,
                    **{id_attribute: f"{getattr(original, id_attribute)}:extra"},
                )
                items = (original, extra)
            bindings = tuple(
                sorted((getattr(item, id_attribute), item.fingerprint) for item in items)
            )
            changed_payload = first.fingerprint_payload()
            changed_payload.update(
                {
                    collection_name: tuple(item.to_dict() for item in items),
                    binding_name: bindings,
                }
            )
            with pytest.raises(ValueError, match="exactly one"):
                replace(
                    first,
                    **{
                        collection_name: items,
                        binding_name: bindings,
                        "transition_fingerprint": canonical_sha256(changed_payload),
                    },
                )


def test_sequential_claim_transitions_chain_through_prior_remaining_fact(
    sample_payloads,
    monkeypatch,
) -> None:
    first_evidence = _grouping(
        concept="option_shares_exercised_completed",
        event_date="2026-05-15",
        identity_suffix="first-exercise",
    )
    second_evidence = _grouping(
        concept="option_shares_exercised_completed",
        event_date="2026-06-15",
        identity_suffix="second-exercise",
    )
    first_material = _materialization(
        grouping=first_evidence[0],
        raw_facts=first_evidence[1],
        event_sources=first_evidence[2],
        event_candidates=first_evidence[3],
        event_decisions=first_evidence[4],
        capital_event=first_evidence[5],
    )
    second_material = _materialization(
        grouping=second_evidence[0],
        raw_facts=second_evidence[1],
        event_sources=second_evidence[2],
        event_candidates=second_evidence[3],
        event_decisions=second_evidence[4],
        capital_event=second_evidence[5],
    )
    source = _source(
        "sequential-option-root",
        document_type="10-K",
        published_date=OPENING_DATE,
    )
    initial_root = _fact(
        fact_id="fact:claim:sequential-root",
        concept="option_or_dilution_claim",
        value=20_000_000,
        source=source,
        end=OPENING_DATE,
    )
    authority = _claim_authority(sample_payloads, monkeypatch, initial_root)
    economic_key = dict(authority.root_economic_claim_bindings)[initial_root.fact_id]
    first = _claim_transition(
        materialization=first_material,
        affected_fact=initial_root,
        affected_source=source,
        remaining_fact_id="fact:claim:sequential-after-first",
        economic_claim_key=economic_key,
    )
    second = _claim_transition(
        materialization=second_material,
        affected_fact=first.remaining_claim_fact,
        affected_source=first.remaining_claim_source_document,
        remaining_fact_id="fact:claim:sequential-after-second",
        economic_claim_key=economic_key,
        initial_claim_root_fact_id=initial_root.fact_id,
    )
    payload = {
        "issuer_id": ISSUER,
        "security_id": SECURITY,
        "opening_date": OPENING_DATE,
        "quote_date": QUOTE_DATE,
        "data_cutoff_date": CUTOFF,
        "claim_control_authority": authority,
        "claim_control_authority_fingerprint": authority.authority_fingerprint,
        "expected_claim_sensitive_group_ids": tuple(
            sorted((first.group_id, second.group_id))
        ),
        "records": (first, second),
    }
    payload["reconciliation_sha256"] = canonical_sha256(payload)
    reconciliation = GroupBoundClaimTransitionReconciliation(**payload)
    assert tuple(item.remaining_claim_value for item in reconciliation.records) == (
        "15000000",
        "10000000",
    )

    branched_second = _claim_transition(
        materialization=second_material,
        affected_fact=initial_root,
        affected_source=source,
        remaining_fact_id="fact:claim:sequential-branched",
        economic_claim_key=economic_key,
    )
    branched_payload = {**payload, "records": (first, branched_second)}
    branched_payload["reconciliation_sha256"] = canonical_sha256(branched_payload)
    with pytest.raises(ValueError):
        GroupBoundClaimTransitionReconciliation(**branched_payload)


def test_transition_rejects_blank_named_human_and_inverted_stock_period(
    sample_payloads,
    monkeypatch,
) -> None:
    evidence = _grouping(concept="option_shares_exercised_completed")
    materialization = _materialization(
        grouping=evidence[0],
        raw_facts=evidence[1],
        event_sources=evidence[2],
        event_candidates=evidence[3],
        event_decisions=evidence[4],
        capital_event=evidence[5],
    )
    source = _source("period-review-root", document_type="10-K", published_date=OPENING_DATE)
    root = _fact(
        fact_id="fact:claim:period-review-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    transition = _claim_transition(
        materialization=materialization,
        affected_fact=root,
        affected_source=source,
        remaining_fact_id="fact:claim:period-review-remaining",
        economic_claim_key=SHA_A,
    )
    decision = replace(transition.review_decisions[0], reviewer_id="human:   ")
    decision_bindings = ((decision.decision_id, decision.fingerprint),)
    changed_payload = transition.fingerprint_payload()
    changed_payload.update(
        {
            "review_decisions": (decision.to_dict(),),
            "review_decision_bindings": decision_bindings,
        }
    )
    with pytest.raises(ValueError, match="analytical review chain"):
        replace(
            transition,
            review_decisions=(decision,),
            review_decision_bindings=decision_bindings,
            transition_fingerprint=canonical_sha256(changed_payload),
        )

    inverted = replace(root, period={"start": "2099-01-01", "end": OPENING_DATE})
    with pytest.raises(ValueError):
        _claim_authority(sample_payloads, monkeypatch, inverted)


def test_phase5c_dilution_authority_cannot_be_caller_rewritten(
    sample_payloads,
    monkeypatch,
) -> None:
    root_id = "fact:claim:reviewed-option-root"
    source = _source(
        "reviewed-option-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id=root_id,
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    authority, graph, _freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    forged_root = "fact:claim:caller-injected-root"
    forged_phase5c = replace(
        authority.phase5c_authority,
        excluded_option_root_fact_ids=(forged_root,),
        option_bridge_root_fact_ids=(forged_root,),
    )
    with pytest.raises(ValueError, match="does not replay Phase 5C"):
        replace(
            authority,
            phase5c_authority=forged_phase5c,
            phase5c_authority_fingerprint=forged_phase5c.fingerprint,
            root_economic_claim_bindings=((forged_root, SHA_A),),
            authority_fingerprint=SHA_B,
            validation_graph=graph,
        )


def test_synchronized_artifact_and_handoffs_cannot_authorize_outside_graph_root(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "graph-owned-option-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:graph-owned-option-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    bridge = readiness["equity_bridge_result"]
    binding = bridge["method_view_result"]["reconciliation_result"]["economic_claim_bindings"][0]
    forged_root_id = "fact:claim:synchronized-outside-graph-root"
    binding["root_fact_ids"] = [forged_root_id]
    binding["identity_evidence_fact_ids"] = [forged_root_id]
    bridge["role_decisions"][0]["root_fact_ids"] = [forged_root_id]
    bridge["consumption_records"] = [
        {
            **bridge["consumption_records"][0],
            "root_fact_id": forged_root_id,
        }
    ]
    readiness["equity_bridge_fingerprint"] = canonical_sha256(bridge)
    forged_freeze = _rebind_freeze_with_readiness(freeze, readiness)
    forged_graph = replace_graph(graph, valuation_handoffs=forged_freeze.handoffs)
    forged_graph.validate()

    with pytest.raises(ValueError, match="outside ContractGraph"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=forged_freeze,
            validation_graph=forged_graph,
        )


def test_graph_owned_root_without_exact_human_review_chain_is_rejected(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "graph-owned-review-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:graph-owned-review-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    bridge = readiness["equity_bridge_result"]
    binding = bridge["method_view_result"]["reconciliation_result"]["economic_claim_bindings"][0]
    forged_root = replace(
        next(item for item in graph.facts if item.fact_id == root.fact_id),
        fact_id="fact:claim:graph-owned-but-unreviewed-root",
    )
    binding["root_fact_ids"] = [forged_root.fact_id]
    binding["identity_evidence_fact_ids"] = [forged_root.fact_id]
    bridge["role_decisions"][0]["root_fact_ids"] = [forged_root.fact_id]
    bridge["consumption_records"] = [
        {
            **bridge["consumption_records"][0],
            "root_fact_id": forged_root.fact_id,
        }
    ]
    readiness["equity_bridge_fingerprint"] = canonical_sha256(bridge)
    forged_freeze = _rebind_freeze_with_readiness(freeze, readiness)
    forged_graph = replace_graph(
        graph,
        facts=(*graph.facts, forged_root),
        valuation_handoffs=forged_freeze.handoffs,
    )
    forged_graph.validate()

    with pytest.raises(ValueError, match="binding review chain does not replay"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=forged_freeze,
            validation_graph=forged_graph,
        )


def test_synchronized_resign_cannot_hide_duplicate_phase5c_review_identity(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "duplicate-review-identity-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:duplicate-review-identity-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    candidates = readiness["equity_bridge_result"]["method_view_result"]["reconciliation_result"][
        "economic_claim_candidates"
    ]
    candidates.append(
        {
            **candidates[0],
            "proposed_statement": "Conflicting duplicate typed Candidate payload.",
        }
    )
    readiness["equity_bridge_fingerprint"] = canonical_sha256(readiness["equity_bridge_result"])
    forged_freeze = _rebind_freeze_with_readiness(freeze, readiness)
    forged_graph = replace_graph(graph, valuation_handoffs=forged_freeze.handoffs)
    forged_graph.validate()

    with pytest.raises(ValueError, match="contains duplicate IDs"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=forged_freeze,
            validation_graph=forged_graph,
        )


def test_synchronized_resign_cannot_reuse_phase5c_review_chain_across_bindings(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "reused-review-chain-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:reused-review-chain-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    reconciliation = readiness["equity_bridge_result"]["method_view_result"][
        "reconciliation_result"
    ]
    binding = reconciliation["economic_claim_bindings"][0]
    reconciliation["economic_claim_bindings"].append(
        {
            **binding,
            "binding_id": "binding:forged:reused-review-chain",
            "economic_identity": "debt",
            "identity_kind": "instrument",
            "identity_value": "forged-unique-debt-root",
            "security_class": None,
            "economic_claim_key": None,
            "root_fact_ids": ["fact:claim:forged-unique-debt-root"],
            "identity_evidence_fact_ids": ["fact:claim:forged-unique-debt-root"],
            "status": "blocked",
            "diluted_share_treatment": "not_applicable",
            "diluted_share_fact_ids": [],
            "claim_id": None,
            "missing_evidence": ["forged non-option binding"],
            "reason_codes": ["economic_claim_identity_unresolved"],
        }
    )
    readiness["equity_bridge_fingerprint"] = canonical_sha256(readiness["equity_bridge_result"])
    forged_freeze = _rebind_freeze_with_readiness(freeze, readiness)
    forged_graph = replace_graph(graph, valuation_handoffs=forged_freeze.handoffs)
    forged_graph.validate()

    with pytest.raises(ValueError, match="binding references are duplicated"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=forged_freeze,
            validation_graph=forged_graph,
        )


@pytest.mark.parametrize(
    "reference_field",
    ("candidate_id", "review_decision_id", "claim_id"),
)
def test_each_phase5c_review_reference_is_one_to_one(
    sample_payloads,
    monkeypatch,
    reference_field,
) -> None:
    source = _source(
        f"isolated-duplicate-{reference_field}",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id=f"fact:claim:isolated-duplicate-{reference_field}",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    reconciliation = readiness["equity_bridge_result"]["method_view_result"][
        "reconciliation_result"
    ]
    binding = reconciliation["economic_claim_bindings"][0]
    second_binding = {
        **binding,
        "binding_id": f"binding:forged:isolated-duplicate-{reference_field}",
        "identity_value": f"isolated-duplicate-{reference_field}",
        "root_fact_ids": [f"fact:claim:unique-{reference_field}"],
        "identity_evidence_fact_ids": [f"fact:claim:unique-{reference_field}"],
        "candidate_id": f"candidate:unique-{reference_field}",
        "review_decision_id": f"decision:unique-{reference_field}",
        "claim_id": f"claim:unique-{reference_field}",
        "economic_claim_key": "",
    }
    second_binding["economic_claim_key"] = integration_types._phase5c_economic_claim_key(
        issuer_id=ISSUER,
        binding=second_binding,
    )
    second_binding[reference_field] = binding[reference_field]
    reconciliation["economic_claim_bindings"].append(second_binding)
    bridge = readiness["equity_bridge_result"]
    second_root_id = second_binding["root_fact_ids"][0]
    bridge["role_decisions"][0]["root_fact_ids"].append(second_root_id)
    bridge["consumption_records"].append(
        {
            "root_fact_id": second_root_id,
            "economic_claim_key": second_binding["economic_claim_key"],
            "economic_identity": "option_or_dilution_claim",
            "channel": "mckinsey_equity_bridge",
            "method": "mckinsey",
            "group_id": "equity-bridge:option_or_dilution_claim",
            "consumption_kind": "economic_deduction",
        }
    )
    readiness["equity_bridge_fingerprint"] = canonical_sha256(bridge)
    forged_freeze = _rebind_freeze_with_readiness(freeze, readiness)
    forged_graph = replace_graph(graph, valuation_handoffs=forged_freeze.handoffs)
    forged_graph.validate()

    with pytest.raises(ValueError, match="binding references are duplicated"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=forged_freeze,
            validation_graph=forged_graph,
        )


def test_phase5c_root_fact_cannot_be_bound_twice(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "isolated-duplicate-binding-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:isolated-duplicate-binding-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    reconciliation = readiness["equity_bridge_result"]["method_view_result"][
        "reconciliation_result"
    ]
    binding = reconciliation["economic_claim_bindings"][0]
    reconciliation["economic_claim_bindings"].append(
        {
            **binding,
            "binding_id": "binding:forged:duplicate-root-only",
            "identity_value": "duplicate-root-only",
            "economic_claim_key": integration_types._phase5c_economic_claim_key(
                issuer_id=ISSUER,
                binding={**binding, "identity_value": "duplicate-root-only"},
            ),
            "candidate_id": "candidate:forged:duplicate-root-only",
            "review_decision_id": "decision:forged:duplicate-root-only",
            "claim_id": "claim:forged:duplicate-root-only",
        }
    )
    readiness["equity_bridge_fingerprint"] = canonical_sha256(readiness["equity_bridge_result"])
    forged_freeze = _rebind_freeze_with_readiness(freeze, readiness)
    forged_graph = replace_graph(graph, valuation_handoffs=forged_freeze.handoffs)
    forged_graph.validate()

    with pytest.raises(ValueError, match="option roots are duplicated"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=forged_freeze,
            validation_graph=forged_graph,
        )


@pytest.mark.parametrize(
    "missing_reference",
    ("candidate_id", "review_decision_id", "claim_id"),
)
def test_confirmed_phase5c_binding_requires_each_review_reference(
    sample_payloads,
    monkeypatch,
    missing_reference,
) -> None:
    source = _source(
        f"missing-confirmed-{missing_reference}",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id=f"fact:claim:missing-confirmed-{missing_reference}",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    binding = readiness["equity_bridge_result"]["method_view_result"]["reconciliation_result"][
        "economic_claim_bindings"
    ][0]
    binding[missing_reference] = None
    readiness["equity_bridge_fingerprint"] = canonical_sha256(readiness["equity_bridge_result"])
    forged_freeze = _rebind_freeze_with_readiness(freeze, readiness)
    forged_graph = replace_graph(graph, valuation_handoffs=forged_freeze.handoffs)
    forged_graph.validate()

    with pytest.raises(ValueError, match="must preserve its review chain"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=forged_freeze,
            validation_graph=forged_graph,
        )


def test_synchronized_resign_cannot_add_unreviewed_blocked_phase5c_binding(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "unreviewed-blocked-binding-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:unreviewed-blocked-binding-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    official_source = next(
        item for item in graph.documents if item.authority_level == "primary_regulatory"
    )
    unreviewed_root = _fact(
        fact_id="fact:claim:unreviewed-blocked-debt",
        concept="interest_bearing_debt",
        value=4_000_000,
        source=official_source,
        end=OPENING_DATE,
        unit="currency_units",
        currency="USD",
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    reconciliation = readiness["equity_bridge_result"]["method_view_result"][
        "reconciliation_result"
    ]
    binding = reconciliation["economic_claim_bindings"][0]
    reconciliation["economic_claim_bindings"].append(
        {
            **binding,
            "binding_id": "binding:forged:unreviewed-blocked",
            "economic_identity": "debt",
            "identity_kind": "instrument",
            "identity_value": "unreviewed-debt-instrument",
            "security_class": None,
            "economic_claim_key": None,
            "root_fact_ids": [unreviewed_root.fact_id],
            "identity_evidence_fact_ids": [unreviewed_root.fact_id],
            "status": "blocked",
            "diluted_share_treatment": "not_applicable",
            "diluted_share_fact_ids": [],
            "candidate_id": None,
            "review_decision_id": None,
            "claim_id": None,
            "missing_evidence": ["forged unreviewed binding"],
            "reason_codes": ["economic_claim_identity_unresolved"],
        }
    )
    readiness["equity_bridge_fingerprint"] = canonical_sha256(readiness["equity_bridge_result"])
    forged_freeze = _rebind_freeze_with_readiness(freeze, readiness)
    forged_graph = replace_graph(
        graph,
        facts=(*graph.facts, unreviewed_root),
        valuation_handoffs=forged_freeze.handoffs,
    )
    forged_graph.validate()

    with pytest.raises(ValueError, match="must preserve its review chain"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=forged_freeze,
            validation_graph=forged_graph,
        )


def test_synchronized_resign_cannot_hide_reviewed_blocked_binding(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "valid-multiple-binding-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:valid-multiple-binding-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    official_source = next(
        item for item in graph.documents if item.authority_level == "primary_regulatory"
    )
    blocked_root = _fact(
        fact_id="fact:claim:reviewed-blocked-debt",
        concept="interest_bearing_debt",
        value=5_000_000,
        source=official_source,
        end=OPENING_DATE,
        unit="currency_units",
        currency="USD",
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    reconciliation = readiness["equity_bridge_result"]["method_view_result"][
        "reconciliation_result"
    ]
    blocked_binding = {
        **reconciliation["economic_claim_bindings"][0],
        "binding_id": "binding:phase5c:reviewed-blocked-debt",
        "economic_identity": "debt",
        "identity_kind": "instrument",
        "identity_value": "fixture-debt-instrument",
        "security_class": None,
        "economic_claim_key": None,
        "root_fact_ids": [blocked_root.fact_id],
        "identity_evidence_fact_ids": [blocked_root.fact_id],
        "status": "blocked",
        "diluted_share_treatment": "not_applicable",
        "diluted_share_fact_ids": [],
        "candidate_id": "analytical-candidate:phase5c:reviewed-blocked-debt",
        "review_decision_id": "",
        "claim_id": None,
        "missing_evidence": ["debt identity remains unresolved"],
        "reason_codes": ["economic_claim_identity_unresolved"],
    }
    support_ids = tuple(
        sorted(
            {
                *blocked_binding["root_fact_ids"],
                *blocked_binding["identity_evidence_fact_ids"],
            }
        )
    )
    supporting = tuple(
        {
            "binding_id": f"binding:phase5c-blocked-debt:{fact_id}",
            "fact_id": fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
        for fact_id in support_ids
    )
    candidate = AnalyticalClaimCandidate(
        schema_version="2.0.0",
        candidate_id=blocked_binding["candidate_id"],
        issuer_id=ISSUER,
        as_of_date=OPENING_DATE,
        proposed_statement=integration_types._phase5c_economic_claim_statement(blocked_binding),
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        claim_role="support",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=supporting,
        counterevidence_bindings=(),
        counterevidence_search_note="Reviewed formal debt and dilution disclosures.",
        proposed_confidence="medium",
        falsification_condition="A formal instrument identity resolves the blocked binding.",
        generation_method="manual",
        evidence_graph_sha256=canonical_sha256(
            {
                "supporting_evidence_bindings": supporting,
                "counterevidence_bindings": (),
            }
        ),
        validation_status="ready",
        validation_issues=(),
    )
    claim, decision = review_analytical_claim_candidate(
        candidate,
        decision="blocked",
        reviewer_id="human:mingji",
        reviewed_at="2026-03-31T12:00:00Z",
        rationale="Named human review retained the unresolved binding.",
        issues=("economic claim identity remains unresolved",),
    )
    assert claim is None
    blocked_binding["review_decision_id"] = decision.decision_id
    reconciliation["economic_claim_bindings"].append(blocked_binding)
    reconciliation["economic_claim_candidates"].append(candidate.to_dict())
    reconciliation["economic_claim_review_decisions"].append(decision.to_dict())
    readiness["equity_bridge_fingerprint"] = canonical_sha256(readiness["equity_bridge_result"])
    rebound = _rebind_freeze_with_readiness(freeze, readiness)
    rebound_graph = replace_graph(
        graph,
        facts=(*graph.facts, blocked_root),
        analytical_claim_candidates=(
            *graph.analytical_claim_candidates,
            candidate,
        ),
        analytical_claim_review_decisions=(
            *graph.analytical_claim_review_decisions,
            decision,
        ),
        valuation_handoffs=rebound.handoffs,
    )
    rebound_graph.validate()

    with pytest.raises(ValueError, match="blocked Phase 5C binding"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=rebound,
            validation_graph=rebound_graph,
        )


@pytest.mark.parametrize(
    (
        "root_concept",
        "economic_identity",
        "identity_kind",
        "security_class",
        "expected_error",
    ),
    (
        (
            "option_or_dilution_claim",
            "option_or_dilution_claim",
            "plan",
            "common",
            "positive option claim",
        ),
        ("invested_capital", "debt", "instrument", None, "identity conflicts"),
        (
            "cash_and_nonoperating_investments",
            "debt",
            "instrument",
            None,
            "identity conflicts",
        ),
        (
            "interest_bearing_debt",
            "debt_equivalent",
            "instrument",
            None,
            "identity conflicts",
        ),
        ("debt_equivalent", "debt", "instrument", None, "identity conflicts"),
        (
            "operating_lease_liability",
            "debt",
            "instrument",
            None,
            "identity conflicts",
        ),
        ("unfunded_pension", "debt", "instrument", None, "identity conflicts"),
        ("preferred_stock", "debt", "instrument", None, "identity conflicts"),
        (
            "noncontrolling_interest",
            "debt",
            "instrument",
            None,
            "identity conflicts",
        ),
        ("option_or_dilution_claim", "debt", "instrument", None, "identity conflicts"),
        ("other_senior_claim", "debt", "instrument", None, "identity conflicts"),
    ),
)
def test_synchronized_resign_cannot_hide_positive_option_root_by_treatment_or_identity(
    sample_payloads,
    monkeypatch,
    root_concept,
    economic_identity,
    identity_kind,
    security_class,
    expected_error,
) -> None:
    source = _source(
        "base-option-root-for-hidden-positive",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:base-option-root-for-hidden-positive",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    official_source = next(
        item for item in graph.documents if item.authority_level == "primary_regulatory"
    )
    hidden_root = _fact(
        fact_id=f"fact:claim:hidden-{root_concept}-as-{economic_identity}",
        concept=root_concept,
        value=11_000_000,
        source=official_source,
        end=OPENING_DATE,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    reconciliation = readiness["equity_bridge_result"]["method_view_result"][
        "reconciliation_result"
    ]
    hidden_binding = {
        **reconciliation["economic_claim_bindings"][0],
        "binding_id": f"economic-claim-binding:hidden-{root_concept}-as-{economic_identity}",
        "economic_identity": economic_identity,
        "identity_kind": identity_kind,
        "identity_value": f"hidden-{root_concept}-as-{economic_identity}",
        "security_class": security_class,
        "economic_claim_key": "",
        "root_fact_ids": [hidden_root.fact_id],
        "identity_evidence_fact_ids": [hidden_root.fact_id],
        "diluted_share_treatment": "not_applicable",
        "diluted_share_fact_ids": [],
        "candidate_id": f"analytical-candidate:hidden-{root_concept}-as-{economic_identity}",
        "review_decision_id": "",
        "claim_id": "",
    }
    hidden_binding["economic_claim_key"] = integration_types._phase5c_economic_claim_key(
        issuer_id=ISSUER,
        binding=hidden_binding,
    )
    supporting = (
        {
            "binding_id": f"binding:phase5c-hidden-{root_concept}-as-{economic_identity}",
            "fact_id": hidden_root.fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        },
    )
    candidate = AnalyticalClaimCandidate(
        schema_version="2.0.0",
        candidate_id=hidden_binding["candidate_id"],
        issuer_id=ISSUER,
        as_of_date=OPENING_DATE,
        proposed_statement=integration_types._phase5c_economic_claim_statement(hidden_binding),
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        claim_role="support",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=supporting,
        counterevidence_bindings=(),
        counterevidence_search_note="Reviewed all formal option-plan evidence.",
        proposed_confidence="high",
        falsification_condition="A nonzero option claim requires a dilution treatment.",
        generation_method="manual",
        evidence_graph_sha256=canonical_sha256(
            {
                "supporting_evidence_bindings": supporting,
                "counterevidence_bindings": (),
            }
        ),
        validation_status="ready",
        validation_issues=(),
    )
    claim, decision = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id="human:mingji",
        reviewed_at="2026-03-31T12:00:00Z",
        rationale="Named human review confirmed the additional option-plan evidence.",
    )
    assert claim is not None
    hidden_binding["review_decision_id"] = decision.decision_id
    hidden_binding["claim_id"] = claim.claim_id
    reconciliation["economic_claim_bindings"].append(hidden_binding)
    reconciliation["economic_claim_candidates"].append(candidate.to_dict())
    reconciliation["economic_claim_review_decisions"].append(decision.to_dict())
    reconciliation["economic_claims"].append(claim.to_dict())
    readiness["equity_bridge_fingerprint"] = canonical_sha256(readiness["equity_bridge_result"])
    rebound = _rebind_freeze_with_readiness(freeze, readiness)
    rebound_graph = replace_graph(
        graph,
        facts=(*graph.facts, hidden_root),
        claims=(*graph.claims, claim),
        analytical_claim_candidates=(
            *graph.analytical_claim_candidates,
            candidate,
        ),
        analytical_claim_review_decisions=(
            *graph.analytical_claim_review_decisions,
            decision,
        ),
        valuation_handoffs=rebound.handoffs,
    )
    rebound_graph.validate()

    with pytest.raises(ValueError, match=expected_error):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=rebound,
            validation_graph=rebound_graph,
        )


def test_phase5c_identity_kind_matrix_matches_frozen_accounting_policy() -> None:
    expected_kinds = {
        "method_base": {"aggregate_perimeter"},
        "nonoperating_asset": {"aggregate_perimeter", "instrument"},
        "debt": {"instrument"},
        "debt_equivalent": {"instrument"},
        "lease_liability": {"instrument"},
        "unfunded_pension": {"instrument", "plan"},
        "preferred_stock": {"security_class"},
        "noncontrolling_interest": {"security_class", "aggregate_perimeter"},
        "option_or_dilution_claim": {"plan", "program", "aggregate_perimeter"},
        "other_senior_claim": {"instrument", "security_class"},
    }
    assert {
        identity: set(kinds)
        for identity, kinds in integration_types.PHASE5C_ECONOMIC_IDENTITY_KINDS.items()
    } == expected_kinds
    assert {
        policy.bridge_role or "method_base"
        for policy in integration_types.ACCOUNT_CONCEPT_POLICIES.values()
    } == set(expected_kinds)
    representative_concepts = {
        "invested_capital": "method_base",
        "cash_and_nonoperating_investments": "nonoperating_asset",
        "interest_bearing_debt": "debt",
        "debt_equivalent": "debt_equivalent",
        "operating_lease_liability": "lease_liability",
        "unfunded_pension": "unfunded_pension",
        "preferred_stock": "preferred_stock",
        "noncontrolling_interest": "noncontrolling_interest",
        "option_or_dilution_claim": "option_or_dilution_claim",
        "other_senior_claim": "other_senior_claim",
    }
    assert {
        concept: (integration_types.ACCOUNT_CONCEPT_POLICIES[concept].bridge_role or "method_base")
        for concept in representative_concepts
    } == representative_concepts


def test_distinct_confirmed_excluded_bindings_close_with_unique_review_chains(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "first-valid-excluded-option-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    first_root = _fact(
        fact_id="fact:claim:first-valid-excluded-option-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        first_root,
    )
    official_source = next(
        item for item in graph.documents if item.authority_level == "primary_regulatory"
    )
    second_root = _fact(
        fact_id="fact:claim:second-valid-excluded-option-root",
        concept="option_or_dilution_claim",
        value=5_000_000,
        source=official_source,
        end=OPENING_DATE,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    bridge = readiness["equity_bridge_result"]
    reconciliation = bridge["method_view_result"]["reconciliation_result"]
    first_binding = reconciliation["economic_claim_bindings"][0]
    second_binding = {
        **first_binding,
        "binding_id": "economic-claim-binding:second-valid-excluded-option",
        "identity_value": "fixture-second-option-program",
        "economic_claim_key": "",
        "root_fact_ids": [second_root.fact_id],
        "identity_evidence_fact_ids": [second_root.fact_id],
        "candidate_id": "analytical-candidate:second-valid-excluded-option",
        "review_decision_id": "",
        "claim_id": "",
    }
    second_binding["economic_claim_key"] = integration_types._phase5c_economic_claim_key(
        issuer_id=ISSUER,
        binding=second_binding,
    )
    support_ids = tuple(
        sorted(
            {
                second_root.fact_id,
                *second_binding["diluted_share_fact_ids"],
            }
        )
    )
    supporting = tuple(
        {
            "binding_id": f"binding:second-valid-excluded-option:{fact_id}",
            "fact_id": fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
        for fact_id in support_ids
    )
    candidate = AnalyticalClaimCandidate(
        schema_version="2.0.0",
        candidate_id=second_binding["candidate_id"],
        issuer_id=ISSUER,
        as_of_date=OPENING_DATE,
        proposed_statement=integration_types._phase5c_economic_claim_statement(second_binding),
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        claim_role="support",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=supporting,
        counterevidence_bindings=(),
        counterevidence_search_note="Reviewed the second formal option-plan perimeter.",
        proposed_confidence="high",
        falsification_condition="A conflicting formal plan identity falsifies this binding.",
        generation_method="manual",
        evidence_graph_sha256=canonical_sha256(
            {
                "supporting_evidence_bindings": supporting,
                "counterevidence_bindings": (),
            }
        ),
        validation_status="ready",
        validation_issues=(),
    )
    claim, decision = review_analytical_claim_candidate(
        candidate,
        decision="confirmed",
        reviewer_id="human:mingji",
        reviewed_at="2026-03-31T12:00:00Z",
        rationale="Named human review confirmed the second excluded option binding.",
    )
    assert claim is not None
    second_binding["review_decision_id"] = decision.decision_id
    second_binding["claim_id"] = claim.claim_id
    reconciliation["economic_claim_bindings"].append(second_binding)
    reconciliation["economic_claim_candidates"].append(candidate.to_dict())
    reconciliation["economic_claim_review_decisions"].append(decision.to_dict())
    reconciliation["economic_claims"].append(claim.to_dict())
    bridge["role_decisions"][0]["root_fact_ids"].append(second_root.fact_id)
    bridge["consumption_records"].append(
        {
            "root_fact_id": second_root.fact_id,
            "economic_claim_key": second_binding["economic_claim_key"],
            "economic_identity": "option_or_dilution_claim",
            "channel": "mckinsey_equity_bridge",
            "method": "mckinsey",
            "group_id": "equity-bridge:option_or_dilution_claim",
            "consumption_kind": "economic_deduction",
        }
    )
    readiness["equity_bridge_fingerprint"] = canonical_sha256(bridge)
    rebound = _rebind_freeze_with_readiness(freeze, readiness)
    rebound_graph = replace_graph(
        graph,
        facts=(*graph.facts, second_root),
        claims=(*graph.claims, claim),
        analytical_claim_candidates=(
            *graph.analytical_claim_candidates,
            candidate,
        ),
        analytical_claim_review_decisions=(
            *graph.analytical_claim_review_decisions,
            decision,
        ),
        valuation_handoffs=rebound.handoffs,
    )
    rebound_graph.validate()

    authority = GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
        freeze=rebound,
        validation_graph=rebound_graph,
    )

    assert dict(authority.root_economic_claim_bindings) == {
        first_root.fact_id: first_binding["economic_claim_key"],
        second_root.fact_id: second_binding["economic_claim_key"],
    }


def test_synchronized_resign_cannot_duplicate_phase5c_consumption_record(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "duplicate-consumption-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:duplicate-consumption-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    records = readiness["equity_bridge_result"]["consumption_records"]
    records.append(dict(records[0]))
    readiness["equity_bridge_fingerprint"] = canonical_sha256(readiness["equity_bridge_result"])
    forged_freeze = _rebind_freeze_with_readiness(freeze, readiness)
    forged_graph = replace_graph(graph, valuation_handoffs=forged_freeze.handoffs)
    forged_graph.validate()

    with pytest.raises(ValueError, match="duplicate economic treatment"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=forged_freeze,
            validation_graph=forged_graph,
        )


def test_synchronized_resign_cannot_duplicate_phase5c_option_role_root(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "duplicate-option-role-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:duplicate-option-role-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    role = readiness["equity_bridge_result"]["role_decisions"][0]
    role["root_fact_ids"].append(root.fact_id)
    readiness["equity_bridge_fingerprint"] = canonical_sha256(readiness["equity_bridge_result"])
    forged_freeze = _rebind_freeze_with_readiness(freeze, readiness)
    forged_graph = replace_graph(graph, valuation_handoffs=forged_freeze.handoffs)
    forged_graph.validate()

    with pytest.raises(ValueError, match=r"option bridge (?:roots|role)"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=forged_freeze,
            validation_graph=forged_graph,
        )


def test_synchronized_resign_cannot_add_unique_phase5c_consumption_record(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "unexpected-consumption-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:unexpected-consumption-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    records = readiness["equity_bridge_result"]["consumption_records"]
    records.append(
        {
            **records[0],
            "channel": "mckinsey_accounting_reconciliation",
            "group_id": "accounting-reconciliation:unexpected",
            "consumption_kind": "validation",
        }
    )
    readiness["equity_bridge_fingerprint"] = canonical_sha256(readiness["equity_bridge_result"])
    forged_freeze = _rebind_freeze_with_readiness(freeze, readiness)
    forged_graph = replace_graph(graph, valuation_handoffs=forged_freeze.handoffs)
    forged_graph.validate()

    with pytest.raises(ValueError, match="consumption records do not replay"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=forged_freeze,
            validation_graph=forged_graph,
        )


def test_synchronized_resign_cannot_add_unbound_phase5c_consumption_root(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "unbound-consumption-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:unbound-consumption-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    readiness = freeze.artifact.to_dict()["phase5c_readiness"]
    records = readiness["equity_bridge_result"]["consumption_records"]
    records.append(
        {
            **records[0],
            "root_fact_id": "fact:forged:unbound-consumption-root",
        }
    )
    readiness["equity_bridge_fingerprint"] = canonical_sha256(readiness["equity_bridge_result"])
    forged_freeze = _rebind_freeze_with_readiness(freeze, readiness)
    forged_graph = replace_graph(graph, valuation_handoffs=forged_freeze.handoffs)
    forged_graph.validate()

    with pytest.raises(ValueError, match="lacks its exact reviewed binding"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=forged_freeze,
            validation_graph=forged_graph,
        )


def test_claim_authority_rejects_a_superseded_freeze_run(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "superseded-freeze-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:superseded-freeze-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    old_root = freeze.handoffs[0]
    replacement_root = replace(
        old_root,
        handoff_id=f"{old_root.handoff_id}:replacement",
        handoff_run_id=f"{old_root.handoff_run_id}:replacement",
        transitioned_at="2026-07-01T00:00:00Z",
        supersedes_handoff_id=freeze.handoffs[-1].handoff_id,
    )
    superseded_graph = replace_graph(
        graph,
        valuation_handoffs=(*graph.valuation_handoffs, replacement_root),
    )
    superseded_graph.validate()

    with pytest.raises(ValueError, match="Handoff chain is not current"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=freeze,
            validation_graph=superseded_graph,
        )


def test_claim_authority_rejects_two_active_freeze_runs(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "two-active-freeze-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:two-active-freeze-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    clone_ids = {item.handoff_id: f"{item.handoff_id}:parallel" for item in freeze.handoffs}
    parallel = tuple(
        replace(
            item,
            handoff_id=clone_ids[item.handoff_id],
            handoff_run_id=f"{item.handoff_run_id}:parallel",
            transitioned_at=f"2026-07-02T0{index}:00:00Z",
            predecessor_handoff_id=(
                clone_ids[item.predecessor_handoff_id]
                if item.predecessor_handoff_id is not None
                else None
            ),
            supersedes_handoff_id=None,
        )
        for index, item in enumerate(freeze.handoffs)
    )
    two_active_graph = replace_graph(
        graph,
        valuation_handoffs=(*graph.valuation_handoffs, *parallel),
    )
    two_active_graph.validate()

    with pytest.raises(ValueError, match="Handoff chain is not current"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=freeze,
            validation_graph=two_active_graph,
        )


def test_same_graph_claim_sensitive_authority_closes_bundle_and_outer_evidence(
    sample_payloads,
    monkeypatch,
) -> None:
    grouping_evidence = _grouping(concept="option_shares_exercised_completed")
    grouping, raw_facts, event_sources, candidates, decisions, event = grouping_evidence
    materialization = _materialization(
        grouping=grouping,
        raw_facts=raw_facts,
        event_sources=event_sources,
        event_candidates=candidates,
        event_decisions=decisions,
        capital_event=event,
    )
    opening_source, coverage_source = _coverage_documents()
    opening_fact = _fact(
        fact_id="fact:shares:claim-sensitive-opening",
        concept="common_shares_outstanding",
        value=100_000_000,
        source=opening_source,
        end=OPENING_DATE,
    )
    receipts = _receipts((*event_sources, opening_source, coverage_source))
    coverage = _coverage(
        materialization,
        coverage_source,
        receipts,
        (*event_sources, opening_source, coverage_source),
    )
    freeze_seed_graph = phase5d5_freeze_test._valid_graph(sample_payloads)
    governed_graph, security = _governed_graph(
        sample_payloads,
        grouping_evidence=grouping_evidence,
        opening_fact=opening_fact,
        coverage=coverage,
    )
    governed_bundle = governed_graph.research_bundles[0]
    governed_candidates_list = []
    for candidate in freeze_seed_graph.valuation_assumption_candidates:
        rebound_candidate = replace(
            candidate,
            research_bundle_id=governed_bundle.bundle_id,
            research_bundle_fingerprint=governed_bundle.bundle_fingerprint,
            research_bundle_dependency_sha256=governed_bundle.dependency_closure_sha256,
        )
        governed_candidates_list.append(
            replace(
                rebound_candidate,
                evidence_graph_sha256=candidate_evidence_graph_sha256(
                    governed_graph,
                    rebound_candidate,
                ),
            )
        )
    governed_candidates = tuple(governed_candidates_list)
    governed_candidate_by_id = {item.candidate_id: item for item in governed_candidates}
    governed_decisions = tuple(
        replace(
            decision,
            candidate_fingerprint=governed_candidate_by_id[decision.candidate_id].fingerprint,
            evidence_graph_sha256=governed_candidate_by_id[
                decision.candidate_id
            ].evidence_graph_sha256,
        )
        for decision in freeze_seed_graph.valuation_assumption_review_decisions
    )
    governed_graph = replace_graph(
        governed_graph,
        valuation_assumption_candidates=governed_candidates,
        valuation_assumption_review_decisions=governed_decisions,
    )
    governed_graph.validate()
    monkeypatch.setattr(
        phase5d5_freeze_test,
        "_valid_graph",
        lambda _sample_payloads: governed_graph,
    )
    affected_seed = _fact(
        fact_id="fact:claim:positive-option-authority",
        concept="option_or_dilution_claim",
        value=10_000_000,
        source=opening_source,
        end=OPENING_DATE,
    )
    authority, graph, _freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        affected_seed,
    )
    affected_fact = next(item for item in graph.facts if item.fact_id == affected_seed.fact_id)
    affected_source = next(
        item for item in graph.documents if item.document_id == affected_fact.source_document_id
    )
    economic_claim_key = dict(authority.root_economic_claim_bindings)[affected_fact.fact_id]
    transition = _claim_transition(
        materialization=materialization,
        affected_fact=affected_fact,
        affected_source=affected_source,
        remaining_fact_id="derived:claim:positive-option-remaining",
        economic_claim_key=economic_claim_key,
    )
    transition_payload = {
        "issuer_id": ISSUER,
        "security_id": SECURITY,
        "opening_date": OPENING_DATE,
        "quote_date": QUOTE_DATE,
        "data_cutoff_date": CUTOFF,
        "claim_control_authority": authority,
        "claim_control_authority_fingerprint": authority.authority_fingerprint,
        "expected_claim_sensitive_group_ids": (materialization.group_id,),
        "records": (transition,),
    }
    transition_payload["reconciliation_sha256"] = canonical_sha256(transition_payload)
    transitions = GroupBoundClaimTransitionReconciliation(**transition_payload)
    facts = {item.fact_id: item for item in graph.facts}
    for fact in (
        materialization.canonical_event_fact,
        transition.remaining_claim_fact,
    ):
        facts[fact.fact_id] = fact
    claims = {item.claim_id: item for item in graph.claims}
    for claim in transition.claims:
        claims[claim.claim_id] = claim
    analytical_candidates = {item.candidate_id: item for item in graph.analytical_claim_candidates}
    for candidate in transition.candidates:
        analytical_candidates[candidate.candidate_id] = candidate
    analytical_decisions = {
        item.decision_id: item for item in graph.analytical_claim_review_decisions
    }
    for decision in transition.review_decisions:
        analytical_decisions[decision.decision_id] = decision
    graph = replace_graph(
        graph,
        facts=tuple(facts.values()),
        claims=tuple(claims.values()),
        analytical_claim_candidates=tuple(analytical_candidates.values()),
        analytical_claim_review_decisions=tuple(analytical_decisions.values()),
    )
    graph.validate()
    bundle = _bundle_closure(
        graph=graph,
        opening_fact=opening_fact,
        materializations=(materialization,),
        coverage=coverage,
        transitions=transitions,
        grouping=grouping,
        security=security,
        reserved_output_share_fact_id=_reserved_output_share_fact_id(
            issuer_id=ISSUER,
            security_id=SECURITY,
            quote_date=QUOTE_DATE,
            opening_share_fact_id=opening_fact.fact_id,
            grouping_result_fingerprint=grouping.grouping_fingerprint,
        ),
    )
    assert bundle.claim_control_authority == authority

    output_fact_id = bundle.reserved_output_share_fact_id
    output_fact = _fact(
        fact_id=output_fact_id,
        concept="common_shares_outstanding",
        value=105_000_000,
        source=opening_source,
        end=QUOTE_DATE,
        derivation=CURRENT_SHARE_ROLLFORWARD_DERIVATION,
        parents=tuple(sorted((opening_fact.fact_id, materialization.canonical_event_fact_id))),
        source_locator=_output_share_source_locator(output_fact_id),
    )
    consumption = _consumption(materialization)
    edges = tuple(
        sorted(
            (
                (output_fact.fact_id, opening_fact.fact_id),
                (output_fact.fact_id, materialization.canonical_event_fact_id),
                *(
                    (materialization.canonical_event_fact_id, item.fact_id)
                    for item in materialization.members
                ),
            )
        )
    )
    claim_sensitive_objects = {
        (contract_type, object_id): (contract_type, object_id, fingerprint)
        for contract_type, object_id, fingerprint in bundle.object_fingerprints
    }
    claim_sensitive_objects[("Fact", output_fact.fact_id)] = (
        "Fact",
        output_fact.fact_id,
        output_fact.fingerprint,
    )
    claim_sensitive_objects[("Fact", materialization.canonical_event_fact_id)] = (
        "Fact",
        materialization.canonical_event_fact_id,
        materialization.canonical_event_fact_fingerprint,
    )
    object_fingerprints = tuple(sorted(claim_sensitive_objects.values()))
    numeric_lineage_sha256 = canonical_sha256(
        {
            "opening_fact": opening_fact.to_dict(),
            "output_fact": output_fact.to_dict(),
            "materialization_fingerprints": [materialization.materialization_fingerprint],
            "consumption_fingerprints": [consumption.consumption_fingerprint],
            "fact_parent_edges": edges,
        }
    )
    extension_sources = {item.document_id: item for item in bundle.source_documents}
    source_closure_sha256 = canonical_sha256(
        {
            "member_sources": sorted(
                {
                    (item.source_document_id, item.source_document_fingerprint)
                    for item in materialization.members
                }
            ),
            "receipt_fingerprints": sorted(
                (item.receipt_id, item.fingerprint) for item in receipts
            ),
            "opening_source": (opening_source.document_id, opening_source.fingerprint),
            "coverage_zero_sources": sorted(
                (
                    item.zero_fact.source_document_id,
                    extension_sources[item.zero_fact.source_document_id].fingerprint,
                )
                for item in coverage.entries
                if item.zero_fact is not None
            ),
            "claim_transition_sources": sorted(
                {
                    (source.document_id, source.fingerprint)
                    for source in transition.evidence_source_documents
                }
            ),
            "security_sources": sorted(
                (
                    identifier,
                    extension_sources[identifier].fingerprint,
                )
                for identifier in security.evidence_closure.source_document_ids
            ),
            "extension_sources": sorted(
                (item.document_id, item.fingerprint) for item in extension_sources.values()
            ),
        }
    )
    temporal_closure_sha256 = canonical_sha256(
        {
            "issuer_id": ISSUER,
            "security_id": SECURITY,
            "opening_date": OPENING_DATE,
            "quote_date": QUOTE_DATE,
            "data_cutoff_date": CUTOFF,
            "event_effective_dates": [EVENT_DATE],
            "member_dates": sorted(
                (
                    item.member.fact_measurement_date,
                    item.member.source_published_date,
                    item.member.data_cutoff_date,
                )
                for item in materialization.members
            ),
            "receipt_periods": sorted(
                (
                    item.source_family,
                    item.period["start"],
                    item.period["end"],
                    item.cutoff_date,
                )
                for item in receipts
            ),
            "claim_transition_evidence_dates": sorted(
                (
                    fact.fact_id,
                    fact.period["end"],
                    extension_sources[fact.source_document_id].published_date,
                )
                for fact in transition.evidence_facts
            ),
        }
    )
    payload = {
        "closure_id": _current_share_v2_closure_id(
            issuer_id=ISSUER,
            security_id=SECURITY,
            quote_date=QUOTE_DATE,
            opening_share_fact_id=opening_fact.fact_id,
            output_share_fact_id=output_fact.fact_id,
            grouping_result_fingerprint=grouping.grouping_fingerprint,
        ),
        "issuer_id": ISSUER,
        "security_id": SECURITY,
        "quote_date": QUOTE_DATE,
        "data_cutoff_date": CUTOFF,
        "grouping_result": grouping,
        "opening_share_fact": opening_fact,
        "output_share_fact": output_fact,
        "output_share_fact_id": output_fact.fact_id,
        "output_share_fact_fingerprint": output_fact.fingerprint,
        "opening_share_fact_id": opening_fact.fact_id,
        "rollforward_parent_fact_ids": tuple(sorted(output_fact.parent_fact_ids)),
        "ultimate_numeric_root_fact_ids": tuple(
            sorted((opening_fact.fact_id, *(item.fact_id for item in raw_facts)))
        ),
        "materializations": (materialization,),
        "numeric_consumptions": (consumption,),
        "bundle_evidence_closure": bundle,
        "coverage_ledger": coverage,
        "claim_transition_reconciliation": transitions,
        "fact_parent_edges": edges,
        "object_fingerprints": object_fingerprints,
        "grouping_policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
        "grouping_policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
        "grouping_code_sha256": grouping.grouping_code_sha256,
        "integration_contract_sha256": current_share_integration_contract_sha256(),
        "integration_policy_sha256": current_share_integration_policy_sha256(),
        "integration_code_sha256": current_share_integration_code_sha256(),
        "grouping_result_fingerprint": grouping.grouping_fingerprint,
        "numeric_lineage_sha256": numeric_lineage_sha256,
        "coverage_closure_sha256": coverage.ledger_sha256,
        "claim_transition_sha256": transitions.reconciliation_sha256,
        "source_closure_sha256": source_closure_sha256,
        "temporal_closure_sha256": temporal_closure_sha256,
    }
    payload["closure_sha256"] = canonical_sha256(payload)
    outer = CurrentShareEvidenceClosureV2(**payload)
    assert outer.bundle_evidence_closure.claim_control_authority == authority
    assert outer.claim_transition_reconciliation.records == (transition,)

    decision = transition.review_decisions[0]
    forged_decision = replace(
        decision,
        rationale="Caller-rewritten rationale with the same Decision identity.",
    )
    forged_transition_payload = transition.fingerprint_payload()
    forged_transition_payload.update(
        {
            "review_decisions": (forged_decision.to_dict(),),
            "review_decision_bindings": (
                (forged_decision.decision_id, forged_decision.fingerprint),
            ),
        }
    )
    forged_transition = replace(
        transition,
        review_decisions=(forged_decision,),
        review_decision_bindings=(
            (forged_decision.decision_id, forged_decision.fingerprint),
        ),
        transition_fingerprint=canonical_sha256(forged_transition_payload),
    )
    forged_reconciliation_payload = transitions.hash_payload()
    forged_reconciliation_payload["records"] = (forged_transition.to_dict(),)
    forged_transitions = replace(
        transitions,
        records=(forged_transition,),
        reconciliation_sha256=canonical_sha256(forged_reconciliation_payload),
    )
    forged_outer_payload = outer.hash_payload()
    forged_outer_payload.update(
        {
            "claim_transition_reconciliation": forged_transitions.to_dict(),
            "claim_transition_sha256": forged_transitions.reconciliation_sha256,
        }
    )
    with pytest.raises(ValueError, match="claim-transition typed evidence.*byte-bound"):
        replace(
            outer,
            claim_transition_reconciliation=forged_transitions,
            claim_transition_sha256=forged_transitions.reconciliation_sha256,
            closure_sha256=canonical_sha256(forged_outer_payload),
        )


def test_freeze_handoff_chain_must_be_exactly_owned_by_current_graph(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "graph-owned-handoff-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:graph-owned-handoff-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    graph_without_authorization = replace_graph(
        graph,
        valuation_handoffs=freeze.handoffs[:-1],
    )

    with pytest.raises(ValueError, match="Handoff chain is not current and graph-owned"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=freeze,
            validation_graph=graph_without_authorization,
        )


def test_component_lock_drift_invalidates_graph_owned_claim_authority(
    sample_payloads,
    monkeypatch,
    tmp_path,
) -> None:
    source = _source(
        "component-lock-authority-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:component-lock-authority-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    _authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    drifted_lock = tmp_path / "component-lock.json"
    drifted_lock.write_text(
        (ROOT / "component-lock.json").read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    drifted_graph = replace_graph(graph, component_lock_path=drifted_lock)

    with pytest.raises(ValueError, match="ContractGraph is invalid|current freeze or lock"):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=freeze,
            validation_graph=drifted_graph,
        )


def test_claim_authority_ignores_unrelated_graph_history_but_rejects_missing_review_object(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "authority-subclosure-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:authority-subclosure-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    authority, graph, freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    unrelated = replace(
        next(item for item in graph.facts if item.issuer_id == ISSUER),
        fact_id="fact:unrelated:historical-context",
        concept="unrelated_historical_context",
    )
    graph_with_unrelated_history = replace_graph(
        graph,
        facts=(*graph.facts, unrelated),
    )
    graph_with_unrelated_history.validate()
    replayed = GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
        freeze=freeze,
        validation_graph=graph_with_unrelated_history,
    )
    assert replayed == authority

    bound_claim_ids = {
        object_id
        for contract_type, object_id, _ in authority.phase5c_review_object_fingerprints
        if contract_type == "Claim"
    }
    graph_without_review_claim = replace_graph(
        graph,
        claims=tuple(item for item in graph.claims if item.claim_id not in bound_claim_ids),
    )
    with pytest.raises(
        ValueError,
        match="ContractGraph is invalid|outside ContractGraph|payload is not graph-owned",
    ):
        GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
            freeze=freeze,
            validation_graph=graph_without_review_claim,
        )


def test_claim_authority_cannot_be_transplanted_into_bundle_from_another_graph(
    sample_payloads,
    monkeypatch,
) -> None:
    source = _source(
        "cross-graph-authority-root",
        document_type="10-K",
        published_date="2026-03-31",
    )
    root = _fact(
        fact_id="fact:claim:cross-graph-authority-root",
        concept="option_or_dilution_claim",
        value=7_000_000,
        source=source,
        end=OPENING_DATE,
    )
    authority, _authority_graph, _freeze = _claim_authority_context(
        sample_payloads,
        monkeypatch,
        root,
    )
    accepted, other_graph = _accepted_context(sample_payloads=sample_payloads)
    bundle = accepted.bundle_evidence_closure
    payload = _typed_bundle_payload(bundle)
    payload.update(
        {
            "research_bundle": bundle.research_bundle,
            "run_manifest": bundle.run_manifest,
            "security_compilation_result": bundle.security_compilation_result,
            "grouping_result": bundle.grouping_result,
            "source_documents": bundle.source_documents,
            "base_dependency_object_fingerprints": (bundle.base_dependency_object_fingerprints),
            "extension_root_ids": bundle.extension_root_ids,
            "extension_object_fingerprints": bundle.extension_object_fingerprints,
            "object_fingerprints": bundle.object_fingerprints,
            "claim_control_authority": authority,
            "claim_control_authority_fingerprint": authority.authority_fingerprint,
        }
    )
    payload["closure_sha256"] = canonical_sha256(payload)

    with pytest.raises(
        ValueError,
        match=(
            "outside ContractGraph|does not replay its current ContractGraph|"
            "payload is not graph-owned"
        ),
    ):
        CurrentShareBundleEvidenceClosure(**payload, validation_graph=other_graph)


def test_bundle_closure_is_independent_of_unrelated_graph_history(sample_payloads) -> None:
    accepted, graph = _accepted_context(sample_payloads=sample_payloads)
    bundle = accepted.bundle_evidence_closure
    unrelated = replace(
        next(item for item in graph.facts if item.issuer_id == ISSUER),
        # This ID deliberately collides with a non-reference string in a governed Fact.
        fact_id=accepted.opening_share_fact.source_locator,
        concept="unrelated_bundle_history",
    )
    extended_graph = replace_graph(graph, facts=(*graph.facts, unrelated))
    extended_graph.validate()
    payload = _typed_bundle_payload(bundle)
    payload.update(
        {
            "research_bundle": bundle.research_bundle,
            "run_manifest": bundle.run_manifest,
            "security_compilation_result": bundle.security_compilation_result,
            "grouping_result": bundle.grouping_result,
            "source_documents": bundle.source_documents,
            "base_dependency_object_fingerprints": (bundle.base_dependency_object_fingerprints),
            "extension_root_ids": bundle.extension_root_ids,
            "extension_object_fingerprints": bundle.extension_object_fingerprints,
            "object_fingerprints": bundle.object_fingerprints,
            "claim_control_authority": bundle.claim_control_authority,
            "contract_graph_fingerprint": _scoped_contract_graph_fingerprint(
                extended_graph,
                bundle.object_fingerprints,
            ),
        }
    )
    payload["closure_sha256"] = canonical_sha256(payload)
    replayed = CurrentShareBundleEvidenceClosure(
        **payload,
        validation_graph=extended_graph,
    )
    assert replayed.contract_graph_fingerprint == bundle.contract_graph_fingerprint
    assert replayed.closure_sha256 == bundle.closure_sha256


def test_typed_extension_event_and_decision_roots_replay_complete_event_evidence(
    sample_payloads,
) -> None:
    accepted, graph = _accepted_context(sample_payloads=sample_payloads)
    event_id = accepted.materializations[0].members[0].capital_allocation_event_id
    event = next(item for item in graph.capital_allocation_events if item.event_id == event_id)
    decision_id = event.source_bindings[0]["decision_id"]
    expected_ids = {
        event.event_id,
        *(binding["candidate_id"] for binding in event.source_bindings),
        *(binding["decision_id"] for binding in event.source_bindings),
        *(binding["source_document_id"] for binding in event.source_bindings),
        *(binding["fact_id"] for binding in event.fact_bindings),
    }
    event_closure = _typed_extension_dependency_closure(graph, (event.event_id,))
    decision_closure = _typed_extension_dependency_closure(graph, (decision_id,))
    assert expected_ids.issubset(event_closure)
    assert expected_ids.issubset(decision_closure)
    source = inspect.getsource(integration_types.CurrentShareBundleEvidenceClosure)
    assert "public_closure = dependency_closure" in source
    assert "extension_closure = _typed_extension_dependency_closure" in source


@pytest.mark.parametrize("reference", ("wrong_type", "missing"))
def test_typed_extension_rejects_wrong_type_or_dangling_fact_reference(
    sample_payloads,
    reference,
) -> None:
    _, graph = _accepted_context(sample_payloads=sample_payloads)
    template = next(iter(graph.analytical_claim_candidates))
    wrong_identifier = (
        next(iter(graph.claims)).claim_id if reference == "wrong_type" else "fact:missing"
    )
    binding = {
        "binding_id": f"binding:typed-extension:{reference}",
        "fact_id": wrong_identifier,
        "calculation_result_id": None,
        "context_observation_id": None,
    }
    candidate = replace(
        template,
        candidate_id=f"candidate:typed-extension:{reference}",
        supporting_evidence_bindings=(binding,),
        counterevidence_bindings=(),
        evidence_graph_sha256=canonical_sha256(
            {
                "supporting_evidence_bindings": (binding,),
                "counterevidence_bindings": (),
            }
        ),
    )
    extended = replace_graph(
        graph,
        analytical_claim_candidates=tuple(
            sorted(
                (*graph.analytical_claim_candidates, candidate),
                key=lambda item: item.candidate_id,
            )
        ),
    )
    with pytest.raises(
        ValueError,
        match="dangling or wrong-type dependency",
    ):
        _typed_extension_dependency_closure(extended, (candidate.candidate_id,))


def test_typed_extension_candidate_reaches_each_exclusive_evidence_domain(
    sample_payloads,
) -> None:
    _, graph = _accepted_context(sample_payloads=sample_payloads)
    fact = next(
        item for item in graph.facts if item.fact_id == "fact:acme:revenue:2025"
    )
    assumption = Assumption(**sample_payloads["assumption"])
    calculation = build_calculation_result(
        sample_payloads["calculation-result"],
        facts={fact.fact_id: fact},
        assumptions={assumption.assumption_id: assumption},
        calculations={},
    )
    context = next(iter(graph.context_observations))
    targets = (
        ("fact_id", fact.fact_id),
        ("calculation_result_id", calculation.calculation_id),
        ("context_observation_id", context.observation_id),
    )
    template = next(iter(graph.analytical_claim_candidates))
    candidates = []
    for field_name, identifier in targets:
        binding = {
            "binding_id": f"binding:typed-candidate:{field_name}",
            "fact_id": None,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
        binding[field_name] = identifier
        candidates.append(
            replace(
                template,
                candidate_id=f"candidate:typed-candidate:{field_name}",
                supporting_evidence_bindings=(binding,),
                counterevidence_bindings=(),
                evidence_graph_sha256=canonical_sha256(
                    {
                        "supporting_evidence_bindings": (binding,),
                        "counterevidence_bindings": (),
                    }
                ),
            )
        )
    extended = replace_graph(
        graph,
        assumptions=(*graph.assumptions, assumption),
        calculations=(*graph.calculations, calculation),
        analytical_claim_candidates=tuple(
            sorted(
                (*graph.analytical_claim_candidates, *candidates),
                key=lambda item: item.candidate_id,
            )
        ),
    )
    for candidate, (_, expected_id) in zip(candidates, targets, strict=True):
        closure = _typed_extension_dependency_closure(
            extended,
            (candidate.candidate_id,),
        )
        assert expected_id in closure


def test_typed_extension_calculation_reaches_all_four_input_domains(sample_payloads) -> None:
    _, graph = _accepted_context(sample_payloads=sample_payloads)
    fact = next(
        item for item in graph.facts if item.fact_id == "fact:acme:revenue:2025"
    )
    assumption = Assumption(**sample_payloads["assumption"])
    period = next(iter(graph.periods))
    parent_payload = {
        **sample_payloads["calculation-result"],
        "calculation_id": "calc:typed-extension:parent",
        "input_assumption_ids": [],
    }
    parent = build_calculation_result(
        parent_payload,
        facts={fact.fact_id: fact},
        assumptions={},
        calculations={},
    )
    root_payload = {
        **sample_payloads["calculation-result"],
        "calculation_id": "calc:typed-extension:root",
        "input_fact_ids": [fact.fact_id],
        "input_assumption_ids": [assumption.assumption_id],
        "input_calculation_ids": [parent.calculation_id],
        "input_period_ids": [period.period_id],
    }
    root = build_calculation_result(
        root_payload,
        facts={fact.fact_id: fact},
        assumptions={assumption.assumption_id: assumption},
        calculations={parent.calculation_id: parent},
        periods={period.period_id: period},
    )
    extended = replace_graph(
        graph,
        assumptions=(*graph.assumptions, assumption),
        calculations=(*graph.calculations, parent, root),
    )
    closure = _typed_extension_dependency_closure(extended, (root.calculation_id,))
    assert {
        fact.fact_id,
        assumption.assumption_id,
        parent.calculation_id,
        period.period_id,
    }.issubset(closure)


def test_management_commitment_scope_is_typed_only_for_segment_scope(sample_payloads) -> None:
    _, graph = _accepted_context(sample_payloads=sample_payloads)
    commitment = next(iter(graph.management_commitments))
    segment = next(iter(graph.segment_definitions))
    colliding_segment = replace(segment, segment_id=str(commitment.scope["scope_id"]))
    issuer_graph = replace_graph(
        graph,
        segment_definitions=(*graph.segment_definitions, colliding_segment),
    )
    issuer_closure = _typed_extension_dependency_closure(
        issuer_graph,
        (commitment.commitment_id,),
    )
    assert colliding_segment.segment_id not in issuer_closure

    segment_scope = {
        **commitment.scope,
        "scope_type": "segment",
        "scope_id": segment.segment_id,
    }
    scoped_commitment = replace(commitment, scope=segment_scope)
    scoped_graph = replace_graph(
        graph,
        management_commitments=tuple(
            scoped_commitment if item.commitment_id == commitment.commitment_id else item
            for item in graph.management_commitments
        ),
    )
    segment_closure = _typed_extension_dependency_closure(
        scoped_graph,
        (scoped_commitment.commitment_id,),
    )
    assert segment.segment_id in segment_closure


def test_artifact_only_dilution_authority_constructor_is_removed() -> None:
    assert not hasattr(GroupBoundDilutionClaimAuthority, "from_price_blind_artifact")


def test_primary_source_selection_is_order_independent() -> None:
    evidence = _grouping(corroborating_count=2)
    forward = _materialization(
        grouping=evidence[0],
        raw_facts=evidence[1],
        event_sources=evidence[2],
        event_candidates=evidence[3],
        event_decisions=evidence[4],
        capital_event=evidence[5],
    )
    reverse = _materialization(
        grouping=evidence[0],
        raw_facts=tuple(reversed(evidence[1])),
        event_sources=tuple(reversed(evidence[2])),
        event_candidates=tuple(reversed(evidence[3])),
        event_decisions=tuple(reversed(evidence[4])),
        capital_event=evidence[5],
    )
    assert reverse.primary_source_document_id == forward.primary_source_document_id
    assert reverse.canonical_event_fact == forward.canonical_event_fact
    assert reverse.materialization_fingerprint == forward.materialization_fingerprint


def test_input_order_is_stable_and_policy_module_has_no_production_surface(
    sample_payloads,
) -> None:
    closure = _accepted_closure(sample_payloads=sample_payloads, corroborating_count=2)
    replay = replace(
        closure,
        materializations=tuple(reversed(closure.materializations)),
        numeric_consumptions=tuple(reversed(closure.numeric_consumptions)),
        fact_parent_edges=tuple(reversed(closure.fact_parent_edges)),
        object_fingerprints=tuple(reversed(closure.object_fingerprints)),
    )
    assert replay.to_dict() == closure.to_dict()
    assert replay.closure_sha256 == closure.closure_sha256
    source = inspect.getsource(integration_types)
    for forbidden in (
        "def build_",
        "def compile_",
        "def write_",
        "def persist_",
        ".write_bytes(",
        ".write_text(",
        "run_dual_panel",
        "MarketReferenceSnapshot",
        "valuation-request.json",
    ):
        assert forbidden not in source


def test_all_governed_multi_item_collections_are_order_independent(
    sample_payloads,
) -> None:
    closure, graph = _accepted_context(
        sample_payloads=sample_payloads,
        corroborating_count=2,
    )
    ledger = closure.coverage_ledger
    replay_ledger = replace(
        ledger,
        entries=tuple(reversed(ledger.entries)),
        receipts=tuple(reversed(ledger.receipts)),
        result_source_documents=tuple(reversed(ledger.result_source_documents)),
    )
    assert replay_ledger.to_dict() == ledger.to_dict()
    assert replay_ledger.ledger_sha256 == ledger.ledger_sha256

    bundle = closure.bundle_evidence_closure
    replay_bundle = replace(
        bundle,
        canonical_event_materializations=tuple(
            reversed(bundle.canonical_event_materializations)
        ),
        canonical_event_fact_bindings=tuple(
            reversed(bundle.canonical_event_fact_bindings)
        ),
        source_documents=tuple(reversed(bundle.source_documents)),
        base_dependency_object_fingerprints=tuple(
            reversed(bundle.base_dependency_object_fingerprints)
        ),
        extension_root_ids=tuple(reversed(bundle.extension_root_ids)),
        extension_object_fingerprints=tuple(
            reversed(bundle.extension_object_fingerprints)
        ),
        object_fingerprints=tuple(reversed(bundle.object_fingerprints)),
        validation_graph=graph,
    )
    assert replay_bundle.to_dict() == bundle.to_dict()
    assert replay_bundle.closure_sha256 == bundle.closure_sha256


def test_recursive_fact_parent_edges_are_the_exact_deterministic_lineage(
    sample_payloads,
) -> None:
    closure = _accepted_closure(sample_payloads=sample_payloads)
    zero = next(
        entry.zero_fact
        for entry in closure.coverage_ledger.entries
        if entry.zero_fact is not None
    )
    assert zero is not None
    forged_edges = tuple(
        sorted((*closure.fact_parent_edges, (zero.fact_id, closure.opening_share_fact_id)))
    )
    payload = {
        **closure.hash_payload(),
        "fact_parent_edges": forged_edges,
    }
    with pytest.raises(ValueError, match="exact Fact parent edges"):
        replace(
            closure,
            fact_parent_edges=forged_edges,
            closure_sha256=canonical_sha256(payload),
        )


def test_complete_zero_event_rollforward_is_a_governed_deterministic_golden(
    sample_payloads,
    tmp_path,
) -> None:
    closure, _ = _accepted_empty_context(sample_payloads=sample_payloads)
    assert closure.materializations == ()
    assert closure.numeric_consumptions == ()
    assert closure.grouping_result.groups == ()
    assert closure.output_share_fact.value == closure.opening_share_fact.value
    assert all(
        item.status == "official_zero_or_no_activity" for item in closure.coverage_ledger.entries
    )
    assert len(closure.coverage_ledger.receipts) == len(SOURCE_FAMILIES) == 8
    assert closure.claim_transition_reconciliation.records == ()

    reversed_payloads = dict(reversed(tuple(sample_payloads.items())))
    replay, _ = _accepted_empty_context(sample_payloads=reversed_payloads)
    assert replay.to_dict() == closure.to_dict()
    assert replay.closure_sha256 == closure.closure_sha256

    payload = json.dumps(closure.to_dict(), sort_keys=True, separators=(",", ":"))
    first = tmp_path / "first" / "current-share-evidence.json"
    second = tmp_path / "second" / "current-share-evidence.json"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_text(payload, encoding="utf-8")
    second.write_text(payload, encoding="utf-8")
    assert first.read_bytes() == second.read_bytes()


def test_contract_replay_is_identical_across_root_parent_tmp_spaces_and_symlink(
    tmp_path,
) -> None:
    real = tmp_path / "directory with spaces"
    real.mkdir()
    symlink = tmp_path / "linked-work-directory"
    symlink.symlink_to(real, target_is_directory=True)
    script = (
        "import sys; "
        f"sys.path.insert(0, {str(ROOT / 'tests')!r}); "
        "import conftest, test_phase5e2b12a_integration_contracts as support; "
        "payloads=conftest.sample_payloads.__wrapped__(); "
        "print(support._accepted_closure(sample_payloads=payloads, "
        "corroborating_count=2).closure_sha256)"
    )
    environment = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT / "tests"))),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    directories = (ROOT, ROOT.parent, tmp_path, real, symlink)
    observed = []
    for directory in directories:
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=directory,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        observed.append(result.stdout.strip())
    assert len(set(observed)) == 1
