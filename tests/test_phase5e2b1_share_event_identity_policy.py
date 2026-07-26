from __future__ import annotations

import inspect
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import owner_research
import owner_research.valuation_share_event_identity as identity_policy
from owner_research.fingerprints import canonical_sha256
from owner_research.valuation_share_event_identity import (
    SHARE_EVENT_CONCEPT_POLICIES,
    SHARE_EVENT_GROUPING_POLICY_ID,
    SHARE_EVENT_GROUPING_POLICY_VERSION,
    ShareEventConflict,
    ShareEventEvidenceGroup,
    ShareEventEvidenceMember,
    ShareEventGroupingResult,
    ShareEventIdentity,
)

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests/fixtures/phase5e2b1/adversarial-cases.json"
BASELINE = "1449e544d9907297c43c8d930d33170c45a60abb"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _identity(**overrides) -> ShareEventIdentity:
    payload = {
        "policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
        "policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
        "issuer_id": "issuer:acme",
        "security_id": "security:acme:XNYS:ACME:common",
        "economic_event_key": "capital-event-key:buyback-program-2026",
        "official_legal_event_id": "buyback:2026-q2:execution-01",
        "execution_occurrence_id": "execution:2026-q2:01",
        "event_concept": "common_shares_repurchased_completed",
        "legal_effective_date": "2026-06-30",
        "canonical_share_magnitude": "5000000",
        "event_grain": "incremental_completed_execution",
    }
    payload.update(overrides)
    payload["legal_event_key"] = canonical_sha256(
        {
            "issuer_id": payload["issuer_id"],
            "security_id": payload["security_id"],
            "economic_event_key": payload["economic_event_key"],
            "official_legal_event_id": payload["official_legal_event_id"],
            "execution_occurrence_id": payload["execution_occurrence_id"],
        }
    )
    payload["identity_fingerprint"] = canonical_sha256(payload)
    return ShareEventIdentity(**payload)


def _member(identity: ShareEventIdentity, suffix: str) -> ShareEventEvidenceMember:
    payload = {
        "legal_event_key": identity.legal_event_key,
        "fact_id": f"fact:event:{suffix}",
        "fact_fingerprint": SHA_A if suffix == "8k" else SHA_B,
        "source_document_id": f"source:{suffix}",
        "source_document_fingerprint": SHA_B if suffix == "8k" else SHA_C,
        "source_locator": f"share-event:{suffix}:completion",
        "source_authority_level": (
            "primary_regulatory" if suffix != "ir" else "company_primary"
        ),
        "source_published_date": "2026-07-01",
        "fact_measurement_date": identity.legal_effective_date,
        "data_cutoff_date": "2026-07-16",
        "capital_allocation_event_id": "capital-event:issuer:acme:buyback-2026",
        "capital_allocation_event_fingerprint": SHA_C,
        "candidate_ids": (f"capital-candidate:{suffix}",),
        "review_decision_ids": (f"capital-decision:{suffix}",),
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
    member_id = f"share-event-member:{canonical_sha256(member_identity)[:24]}"
    full = {"member_id": member_id, **payload}
    full["member_fingerprint"] = canonical_sha256(full)
    return ShareEventEvidenceMember(**full)


def _group(identity: ShareEventIdentity, members: tuple[ShareEventEvidenceMember, ...]):
    payload = {
        "group_id": f"share-event-group:{identity.issuer_id}:{identity.legal_event_key[:24]}",
        "identity": identity,
        "member_ids": tuple(sorted(item.member_id for item in members)),
        "status": "canonical",
        "canonical_event_fact_id": f"derived:share-event:{identity.legal_event_key[:24]}",
        "conflict_ids": (),
    }
    payload["group_fingerprint"] = canonical_sha256(payload)
    return ShareEventEvidenceGroup(**payload)


def _result(
    identity: ShareEventIdentity,
    members: tuple[ShareEventEvidenceMember, ...],
) -> ShareEventGroupingResult:
    group = _group(identity, members)
    payload = {
        "policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
        "policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
        "grouping_code_sha256": SHA_A,
        "issuer_id": identity.issuer_id,
        "security_id": identity.security_id,
        "opening_date": "2026-03-31",
        "quote_date": "2026-06-30",
        "status": "grouped",
        "members": tuple(sorted(members, key=lambda item: item.member_id)),
        "groups": (group,),
        "conflicts": (),
    }
    payload["grouping_fingerprint"] = canonical_sha256(payload)
    return ShareEventGroupingResult(**payload)


def test_cross_source_identity_records_are_frozen_and_order_independent() -> None:
    identity = _identity()
    members = (_member(identity, "8k"), _member(identity, "10q"))
    result = _result(identity, members)
    replay = _result(identity, tuple(reversed(members)))
    assert result.to_dict() == replay.to_dict()
    assert result.fingerprint == replay.fingerprint
    assert result.groups[0].identity.canonical_share_magnitude == "5000000"
    assert len(result.groups[0].member_ids) == 2
    with pytest.raises(FrozenInstanceError):
        result.status = "blocked"  # type: ignore[misc]


def test_evidence_identity_cannot_change_the_legal_event_key() -> None:
    identity = _identity()
    first = _member(identity, "8k")
    second = _member(identity, "10q")
    assert first.fact_id != second.fact_id
    assert first.source_document_id != second.source_document_id
    assert first.source_locator != second.source_locator
    assert first.legal_event_key == second.legal_event_key == identity.legal_event_key


def test_identity_rejects_unregistered_or_non_incremental_event_semantics() -> None:
    with pytest.raises(ValueError, match="concept is not registered"):
        _identity(event_concept="weighted_average_diluted_shares")
    with pytest.raises(ValueError, match="grain is not registered"):
        _identity(event_grain="cumulative_to_date")
    with pytest.raises(ValueError, match="official legal-event ID"):
        _identity(official_legal_event_id="")


def test_conflict_contract_requires_registered_fields_and_multiple_members() -> None:
    identity = _identity()
    members = (_member(identity, "8k"), _member(identity, "10q"))
    payload = {
        "conflict_code": "blocked_share_event_conflict",
        "legal_event_key": identity.legal_event_key,
        "conflicting_fields": ("canonical_share_magnitude",),
        "member_ids": tuple(sorted(item.member_id for item in members)),
        "compared_values_sha256": SHA_A,
    }
    conflict_id = f"share-event-conflict:{canonical_sha256(payload)[:24]}"
    full = {"conflict_id": conflict_id, **payload}
    full["conflict_fingerprint"] = canonical_sha256(full)
    conflict = ShareEventConflict(**full)
    assert conflict.conflict_code == "blocked_share_event_conflict"
    with pytest.raises(ValueError, match="at least two"):
        ShareEventConflict(
            **{
                **full,
                "member_ids": (members[0].member_id,),
                "conflict_id": "share-event-conflict:invalid",
            }
        )


def test_closed_registry_preserves_historical_roles_without_public_migration() -> None:
    assert set(SHARE_EVENT_CONCEPT_POLICIES) == {
        "common_shares_issued_completed",
        "common_shares_repurchased_completed",
        "common_shares_retired_or_cancelled_completed",
        "option_shares_exercised_completed",
        "rsu_shares_settled_completed",
        "convertible_shares_converted_completed",
        "warrant_shares_exercised_completed",
        "acquisition_consideration_shares_issued_completed",
    }
    assert SHARE_EVENT_CONCEPT_POLICIES["common_shares_repurchased_completed"][
        "fact_roles"
    ] == ("shares_repurched",)


def test_adversarial_matrix_covers_the_independent_semantic_finding() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert payload["baseline_commit"] == BASELINE
    case_ids = {item["case_id"] for item in payload["cases"]}
    assert case_ids == {
        "same-repurchase-8k-10q",
        "same-issuance-8k-10q-ir",
        "same-legal-id-magnitude-conflict",
        "same-legal-id-date-conflict",
        "different-fact-ids-same-event",
        "same-date-amount-no-distinct-legal-id",
        "same-date-amount-distinct-legal-ids",
        "duplicate-option-exercise-transition",
        "input-order-reversal",
        "corroboration-closure-only-change",
        "ineligible-member-evidence",
        "cumulative-period-total",
    }


def test_baseline_legacy_key_reproduces_cross_source_double_count() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    case = next(item for item in payload["cases"] if item["case_id"] == "same-repurchase-8k-10q")
    legacy_members = tuple(
        {
            "concept": "common_shares_repurchased_completed",
            "period_end": event_date,
            "source_document_id": f"source:{source}",
            "source_locator": f"locator:{source}",
            "magnitude": int(magnitude),
        }
        for source, magnitude, event_date in zip(
            case["member_sources"], case["magnitudes"], case["dates"], strict=True
        )
    )
    legacy_keys = {
        (
            item["concept"],
            item["period_end"],
            item["source_document_id"],
            item["source_locator"],
        )
        for item in legacy_members
    }
    legacy_result = int(payload["opening_shares"]) - sum(
        item["magnitude"] for item in legacy_members
    )
    assert len(legacy_keys) == 2
    assert legacy_result == 90_000_000
    assert legacy_result != int(case["expected_current_shares"])


def test_policy_phase_exports_no_grouping_or_market_execution_surface() -> None:
    assert not hasattr(identity_policy, "group_share_events")
    assert not hasattr(identity_policy, "compile_share_event_groups")
    assert not hasattr(owner_research, "ShareEventIdentity")
    assert not hasattr(owner_research, "compile_share_event_groups")
    source = inspect.getsource(identity_policy)
    for forbidden in (
        "MarketReferenceSnapshot",
        "run_dual_panel",
        "market_equity",
        "valuation-request.json",
    ):
        assert forbidden not in source
