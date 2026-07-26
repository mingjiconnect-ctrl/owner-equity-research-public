"""Internal Phase 5E-2B.1-2A contracts for canonical share-event integration.

The records in this module are a hard boundary between the accepted cross-source grouping result
and the later production roll-forward.  They deliberately provide no discovery, materialization,
compiler, writer, market-evidence, request, or kernel-execution entry point.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import InitVar, dataclass
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, ClassVar

from . import source_search_receipts as source_search_receipt_module
from .capital_allocation_ledger import source_family
from .capital_allocation_policies import (
    OFFICIAL_AUTHORITY_LEVELS,
    SOURCE_FAMILIES,
)
from .component_lock import file_sha256
from .contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    CapitalAllocationEvent,
    CapitalAllocationEventCandidate,
    CapitalAllocationEventReviewDecision,
    Claim,
    Fact,
    ResearchBundle,
    RunManifest,
    SourceDocument,
    SourceSearchReceipt,
)
from .fingerprints import canonical_sha256, to_json_value
from .research_bundle_policies import bundle_payload_sha256, dependency_closure_sha256
from .research_bundle_validation import (
    GRAPH_DOMAIN_TYPES,
    ResearchBundleValidationError,
    _object_id,
    dependency_closure,
    validate_research_bundle,
)
from .source_search_receipts import source_search_request_fingerprint
from .validation import ContractGraph, ContractGraphError
from .valuation_accounting_policies import (
    ACCOUNT_CONCEPT_POLICIES,
    PHASE5C_POLICY_ID,
    PHASE5C_POLICY_VERSION,
)
from .valuation_current_share_evidence import (
    CLAIM_SENSITIVE_EVENT_CONCEPTS,
    COMPLETED_SHARE_EVENT_SIGNS,
    CORPORATE_ACTION_COVERAGE_CATEGORIES,
    EVENT_CONCEPT_TO_COVERAGE_CATEGORY,
    SHARE_COVERAGE_SEARCH_EVENT_TYPES,
)
from .valuation_market_reference_types import Phase5CDilutionClaimAuthority
from .valuation_price_blind_freeze import (
    PriceBlindFreezeCompilationResult,
    PriceBlindInputArtifact,
)
from .valuation_security_identity import (
    SECURITY_EVIDENCE_POLICY_ID,
    SECURITY_EVIDENCE_POLICY_VERSION,
    SECURITY_FACT_CONCEPTS,
    SUPPORTED_MIC_CURRENCY,
    SecurityIdentityCompilationResult,
)
from .valuation_share_event_grouping import (
    _grouping_code_sha256,
    group_governed_completed_share_events,
)
from .valuation_share_event_identity import (
    SHARE_EVENT_CONCEPT_POLICIES,
    SHARE_EVENT_GROUPING_POLICY_ID,
    SHARE_EVENT_GROUPING_POLICY_VERSION,
    ShareEventEvidenceGroup,
    ShareEventEvidenceMember,
    ShareEventGroupingResult,
)

CURRENT_SHARE_INTEGRATION_POLICY_ID = "canonical-share-event-current-share-integration"
CURRENT_SHARE_INTEGRATION_POLICY_VERSION = "2.0.0"
CURRENT_SHARE_INTEGRATION_STATUSES = frozenset({"eligible", "blocked", "specialist_required"})
CURRENT_SHARE_INTEGRATION_ISSUES = frozenset(
    {
        "bundle_closure_invalid",
        "canonical_event_materialization_invalid",
        "canonical_event_consumption_invalid",
        "canonical_event_coverage_invalid",
        "claim_transition_invalid",
        "recursive_closure_invalid",
    }
)
CURRENT_SHARE_ROLLFORWARD_CHANNEL = "current_share_rollforward"
CANONICAL_EVENT_DERIVATION = "cross-source-share-event-grouping/1.0.0"
CURRENT_SHARE_ROLLFORWARD_DERIVATION = "completed-event-rollforward/2.0.0"
CLAIM_TRANSITION_DERIVATION = "reviewed canonical share-event claim transition"
CURRENT_SHARE_EXTENSION_POLICY_ID = "research-bundle-current-share-extension"
CURRENT_SHARE_EXTENSION_POLICY_VERSION = "1.0.0"
CURRENT_SHARE_INTEGRATION_POLICY_PATH = (
    Path(__file__).parent
    / "resources/current_share/canonical-event-integration-policy.json"
)
GRAPH_OBJECT_ID_ATTRIBUTE = {
    "SourceDocument": "document_id",
    "Fact": "fact_id",
    "Claim": "claim_id",
    "Assumption": "assumption_id",
    "CalculationResult": "calculation_id",
    "FiscalPeriod": "period_id",
    "QuarterlyReconciliation": "reconciliation_id",
    "QuarterlyUpdate": "update_id",
    "FilingArtifact": "artifact_id",
    "ExtractionCandidate": "candidate_id",
    "EvidencePromotion": "promotion_id",
    "SegmentDefinition": "segment_id",
    "SegmentSnapshot": "snapshot_id",
    "FootnoteReview": "review_id",
    "AccountingQualityFinding": "finding_id",
    "AccountingQualityReview": "review_id",
    "ContextObservation": "observation_id",
    "CompetitiveContextSnapshot": "context_snapshot_id",
    "AnalyticalClaimCandidate": "candidate_id",
    "AnalyticalClaimReviewDecision": "decision_id",
    "BusinessModelSnapshot": "snapshot_id",
    "CompetitiveAdvantageHypothesis": "hypothesis_id",
    "BusinessQualityReview": "review_id",
    "ManagementStatement": "statement_id",
    "ManagementStatementCandidate": "candidate_id",
    "ManagementStatementReviewDecision": "decision_id",
    "ManagementCommitment": "commitment_id",
    "ManagementOutcome": "outcome_id",
    "CapitalAllocationEventCandidate": "candidate_id",
    "CapitalAllocationEventReviewDecision": "decision_id",
    "CapitalAllocationEvent": "event_id",
    "CapitalAllocationOutcome": "outcome_id",
    "SourceSearchReceipt": "receipt_id",
    "ManagementReview": "review_id",
    "CapitalAllocationReview": "review_id",
    "Score": "score_id",
    "RunManifest": "run_id",
}


def _canonical_event_source_locator(canonical_event_fact_id: str) -> str:
    _nonempty(canonical_event_fact_id, "canonical event Fact ID")
    return f"derived:{CANONICAL_EVENT_DERIVATION}:{canonical_event_fact_id}"


def _reserved_output_share_fact_id(
    *,
    issuer_id: str,
    security_id: str,
    quote_date: str,
    opening_share_fact_id: str,
    grouping_result_fingerprint: str,
) -> str:
    for value, label in (
        (issuer_id, "output-share issuer ID"),
        (security_id, "output-share security ID"),
        (opening_share_fact_id, "opening-share Fact ID"),
    ):
        _nonempty(value, label)
    _date(quote_date, "output-share quote date")
    _sha(grouping_result_fingerprint, "output-share grouping fingerprint")
    identity = canonical_sha256(
        {
            "issuer_id": issuer_id,
            "security_id": security_id,
            "quote_date": quote_date,
            "opening_share_fact_id": opening_share_fact_id,
            "grouping_result_fingerprint": grouping_result_fingerprint,
            "derivation": CURRENT_SHARE_ROLLFORWARD_DERIVATION,
        }
    )
    return f"derived:current-shares:{identity[:24]}"


def _output_share_source_locator(output_share_fact_id: str) -> str:
    _nonempty(output_share_fact_id, "output-share Fact ID")
    return f"derived:{CURRENT_SHARE_ROLLFORWARD_DERIVATION}:{output_share_fact_id}"


def _claim_transition_source_locator(remaining_claim_fact_id: str) -> str:
    _nonempty(remaining_claim_fact_id, "remaining-claim Fact ID")
    return f"derived:{CLAIM_TRANSITION_DERIVATION}:{remaining_claim_fact_id}"


def _remaining_claim_fact_id(
    *,
    issuer_id: str,
    economic_claim_key: str,
    group_id: str,
    affected_claim_root_fact_id: str,
    legal_effective_date: str,
) -> str:
    for value, label in (
        (issuer_id, "remaining-claim issuer ID"),
        (group_id, "remaining-claim group ID"),
        (affected_claim_root_fact_id, "remaining-claim affected Fact ID"),
    ):
        _nonempty(value, label)
    _sha(economic_claim_key, "remaining-claim economic key")
    _date(legal_effective_date, "remaining-claim effective date")
    identity = canonical_sha256(
        {
            "issuer_id": issuer_id,
            "economic_claim_key": economic_claim_key,
            "group_id": group_id,
            "affected_claim_root_fact_id": affected_claim_root_fact_id,
            "legal_effective_date": legal_effective_date,
        }
    )
    return f"derived:claim-transition:{identity[:24]}"


def _current_share_v2_closure_id(
    *,
    issuer_id: str,
    security_id: str,
    quote_date: str,
    opening_share_fact_id: str,
    output_share_fact_id: str,
    grouping_result_fingerprint: str,
) -> str:
    for value, label in (
        (issuer_id, "current-share closure issuer ID"),
        (security_id, "current-share closure security ID"),
        (opening_share_fact_id, "current-share closure opening Fact ID"),
        (output_share_fact_id, "current-share closure output Fact ID"),
    ):
        _nonempty(value, label)
    _date(quote_date, "current-share closure quote date")
    _sha(grouping_result_fingerprint, "current-share closure grouping fingerprint")
    identity = canonical_sha256(
        {
            "issuer_id": issuer_id,
            "security_id": security_id,
            "quote_date": quote_date,
            "opening_share_fact_id": opening_share_fact_id,
            "output_share_fact_id": output_share_fact_id,
            "grouping_result_fingerprint": grouping_result_fingerprint,
        }
    )
    return f"current-share-closure:{identity[:24]}"


def _validate_official_occurrence_collision_domain(
    groups: tuple[ShareEventEvidenceGroup, ...],
) -> None:
    """Reject one reviewed legal occurrence split across canonical groups.

    Phase 5E-2B.1-1 is frozen.  This validation-only boundary therefore checks the accepted
    grouping result without changing discovery or grouping production semantics.  Evidence IDs,
    documents and locators are intentionally absent from the collision identity.
    """

    by_occurrence: dict[tuple[str, str, str, str], set[str]] = {}
    for group in groups:
        identity = group.identity
        occurrence = (
            identity.issuer_id,
            identity.security_id,
            identity.official_legal_event_id,
            identity.legal_effective_date,
        )
        by_occurrence.setdefault(occurrence, set()).add(identity.legal_event_key)
    if any(len(legal_event_keys) != 1 for legal_event_keys in by_occurrence.values()):
        raise ValueError(
            "reviewed official share-event occurrence is split across legal identities"
        )


if set(GRAPH_OBJECT_ID_ATTRIBUTE) != set(GRAPH_DOMAIN_TYPES.values()):
    raise RuntimeError("typed current-share graph ID registry is not closed")
COVERAGE_SEARCH_AUTHORITY_ID = "current-share-source-search-authority"
COVERAGE_SEARCH_AUTHORITY_VERSION = "1.0.0"
COVERAGE_SEARCH_TOOL_VERSION = "owner-research-source-search/1.0.0"
COVERAGE_SEARCH_ENDPOINTS = {
    family: ("authority:issuer-official-ir" if family == "official_ir" else "authority:sec-edgar",)
    for family in SOURCE_FAMILIES
}
CLAIM_ROOT_CONCEPT_BY_EVENT = {
    "option_shares_exercised_completed": "option_or_dilution_claim",
}
STANDARD_CLAIM_TRANSITION_EVENT_CONCEPTS = frozenset(CLAIM_ROOT_CONCEPT_BY_EVENT)
SPECIALIST_REQUIRED_CLAIM_TRANSITION_EVENT_CONCEPTS = frozenset(
    {
        "convertible_shares_converted_completed",
        "warrant_shares_exercised_completed",
    }
)
if (
    STANDARD_CLAIM_TRANSITION_EVENT_CONCEPTS
    | SPECIALIST_REQUIRED_CLAIM_TRANSITION_EVENT_CONCEPTS
) != frozenset(CLAIM_SENSITIVE_EVENT_CONCEPTS) or (
    STANDARD_CLAIM_TRANSITION_EVENT_CONCEPTS
    & SPECIALIST_REQUIRED_CLAIM_TRANSITION_EVENT_CONCEPTS
):
    raise RuntimeError("claim-transition authority partition is not closed")
GROUP_BOUND_DILUTION_AUTHORITY_POLICY_ID = "phase5c-reviewed-dilution-claim-authority"
GROUP_BOUND_DILUTION_AUTHORITY_POLICY_VERSION = "2.0.0"
PHASE5C_ECONOMIC_IDENTITY_KINDS = {
    "method_base": frozenset({"aggregate_perimeter"}),
    "nonoperating_asset": frozenset({"aggregate_perimeter", "instrument"}),
    "debt": frozenset({"instrument"}),
    "debt_equivalent": frozenset({"instrument"}),
    "lease_liability": frozenset({"instrument"}),
    "unfunded_pension": frozenset({"instrument", "plan"}),
    "preferred_stock": frozenset({"security_class"}),
    "noncontrolling_interest": frozenset({"security_class", "aggregate_perimeter"}),
    "option_or_dilution_claim": frozenset({"plan", "program", "aggregate_perimeter"}),
    "other_senior_claim": frozenset({"instrument", "security_class"}),
}


def coverage_search_authority_sha256() -> str:
    return canonical_sha256(
        {
            "authority_id": COVERAGE_SEARCH_AUTHORITY_ID,
            "authority_version": COVERAGE_SEARCH_AUTHORITY_VERSION,
            "tool_version": COVERAGE_SEARCH_TOOL_VERSION,
            "endpoint_ids": COVERAGE_SEARCH_ENDPOINTS,
            "source_search_module_sha256": hashlib.sha256(
                Path(source_search_receipt_module.__file__).read_bytes()
            ).hexdigest(),
        }
    )


def _source_search_receipt_id(receipt: SourceSearchReceipt) -> str:
    receipt_identity = canonical_sha256(
        [
            receipt.request_fingerprint,
            receipt.completed_at,
            sorted(receipt.result_document_ids),
            receipt.status,
        ]
    )
    return f"source-search:{receipt.issuer_id}:{receipt_identity}"


def _candidate_evidence_object_ids(candidate: AnalyticalClaimCandidate) -> set[str]:
    result: set[str] = set()
    for binding in (*candidate.supporting_evidence_bindings, *candidate.counterevidence_bindings):
        for field_name in ("fact_id", "calculation_result_id", "context_observation_id"):
            identifier = binding[field_name]
            if identifier is not None:
                result.add(str(identifier))
    return result


def _direct_binding_fact_ids(bindings: tuple[Any, ...], label: str) -> tuple[str, ...]:
    binding_ids: set[str] = set()
    fact_ids: list[str] = []
    for binding in bindings:
        binding_id = str(binding["binding_id"])
        _nonempty(binding_id, f"{label} binding ID")
        if binding_id in binding_ids:
            raise ValueError(f"{label} contains duplicate binding IDs")
        binding_ids.add(binding_id)
        fact_id = binding["fact_id"]
        if (
            fact_id is None
            or binding["calculation_result_id"] is not None
            or binding["context_observation_id"] is not None
        ):
            raise ValueError(f"{label} must contain direct Fact-only evidence")
        fact_ids.append(str(fact_id))
    if len(fact_ids) != len(set(fact_ids)):
        raise ValueError(f"{label} repeats a direct Fact")
    return tuple(sorted(fact_ids))


def _issuer_wide_analytical_scope() -> dict[str, Any]:
    return {
        "scope_type": "issuer_wide",
        "segment_definition_ids": [],
        "business_unit": None,
        "product_service": None,
        "geography": None,
        "customer_group": None,
        "channel": None,
    }


def _coverage_not_applicable_statement(category: str, security_id: str) -> str:
    return f"Share activity category {category} is not applicable to security {security_id}."


def _replay_security_identity_compilation(
    *,
    graph: ContractGraph,
    result: SecurityIdentityCompilationResult,
) -> None:
    proposal = result.proposal
    decision = result.decision
    closure = result.evidence_closure
    if (
        (result.policy_id, result.policy_version)
        != (SECURITY_EVIDENCE_POLICY_ID, SECURITY_EVIDENCE_POLICY_VERSION)
        or result.status != "eligible"
        or result.issue_codes
        or decision is None
        or closure is None
    ):
        raise ValueError("current-share security compilation is not eligible")
    if (
        len(closure.fact_ids) != len(set(closure.fact_ids))
        or len(closure.source_document_ids) != len(set(closure.source_document_ids))
        or len(closure.object_fingerprints)
        != len({item[1] for item in closure.object_fingerprints})
    ):
        raise ValueError("current-share security evidence contains duplicate typed identities")
    facts_by_id = {item.fact_id: item for item in graph.facts}
    claims_by_id = {item.claim_id: item for item in graph.claims}
    candidates_by_id = {item.candidate_id: item for item in graph.analytical_claim_candidates}
    decisions_by_id = {item.decision_id: item for item in graph.analytical_claim_review_decisions}
    documents_by_id = {item.document_id: item for item in graph.documents}
    try:
        by_role = {binding.role: facts_by_id[binding.fact_id] for binding in proposal.fact_bindings}
        claim = claims_by_id[proposal.structure_claim_id]
        candidate = candidates_by_id[proposal.analytical_candidate_id]
        review = decisions_by_id[proposal.analytical_review_decision_id]
        documents = {
            facts_by_id[binding.fact_id].source_document_id: documents_by_id[
                facts_by_id[binding.fact_id].source_document_id
            ]
            for binding in proposal.fact_bindings
        }
    except KeyError as exc:
        raise ValueError("current-share security compilation has dangling evidence") from exc
    fact_ids = {item.fact_id for item in by_role.values()}
    candidate_fact_ids = {
        str(binding["fact_id"])
        for binding in candidate.supporting_evidence_bindings
        if binding["fact_id"] is not None
    }
    expected_closure_objects = {
        *(("SourceDocument", item.document_id, item.fingerprint) for item in documents.values()),
        *(("Fact", item.fact_id, item.fingerprint) for item in by_role.values()),
        ("Claim", claim.claim_id, claim.fingerprint),
        ("AnalyticalClaimCandidate", candidate.candidate_id, candidate.fingerprint),
        (
            "AnalyticalClaimReviewDecision",
            review.decision_id,
            review.fingerprint,
        ),
    }
    cutoff = _date(proposal.data_cutoff_date, "security proposal cutoff")
    if (
        proposal.issuer_id != closure.issuer_id
        or proposal.data_cutoff_date != closure.data_cutoff_date
        or set(closure.fact_ids) != fact_ids
        or set(closure.source_document_ids) != set(documents)
        or closure.claim_id != claim.claim_id
        or closure.candidate_id != candidate.candidate_id
        or closure.review_decision_id != review.decision_id
        or set(closure.object_fingerprints) != expected_closure_objects
        or set(by_role) != set(SECURITY_FACT_CONCEPTS)
        or any(
            fact.issuer_id != proposal.issuer_id
            or fact.concept != SECURITY_FACT_CONCEPTS[role]
            or fact.value_type != "text"
            or not isinstance(fact.value, str)
            or not fact.value.strip()
            or fact.derivation is not None
            or fact.parent_fact_ids
            or fact.period.get("end") is None
            or _date(str(fact.period["end"]), "security Fact date") > cutoff
            for role, fact in by_role.items()
        )
        or any(
            document.issuer_id != proposal.issuer_id
            or document.authority_level not in OFFICIAL_AUTHORITY_LEVELS
            or _date(document.published_date, "security source date") > cutoff
            for document in documents.values()
        )
        or candidate.issuer_id != proposal.issuer_id
        or candidate.validation_status != "ready"
        or candidate.claim_role != "support"
        or candidate.scope["scope_type"] != "issuer_wide"
        or _date(candidate.as_of_date, "security Candidate date") > cutoff
        or candidate_fact_ids != fact_ids
        or claim.issuer_id != proposal.issuer_id
        or set(claim.supporting_fact_ids) != fact_ids
        or not claim.counterevidence_search_note
        or not claim.falsification_condition
        or claim.confidence not in {"high", "medium"}
        or review.issuer_id != proposal.issuer_id
        or review.decision != "confirmed"
        or not _is_named_human(review.reviewer_id)
        or review.candidate_id != candidate.candidate_id
        or review.candidate_fingerprint != candidate.fingerprint
        or review.evidence_graph_sha256 != candidate.evidence_graph_sha256
        or review.output_claim_id != claim.claim_id
    ):
        raise ValueError("current-share security evidence does not replay")
    ticker = str(by_role["ticker"].value).upper()
    mic = str(by_role["mic"].value).upper()
    share_class = str(by_role["share_class"].value).casefold()
    structure = str(by_role["security_structure"].value)
    quote_currency = SUPPORTED_MIC_CURRENCY.get(mic)
    expected_security_id = f"security:{proposal.issuer_id}:{mic}:{ticker}:{share_class}"
    expected_decision_id = (
        "security-decision:"
        + canonical_sha256({"proposal": proposal.fingerprint, "closure": closure.closure_sha256})[
            :24
        ]
    )
    if (
        structure != "single_primary_common"
        or share_class != "common"
        or quote_currency is None
        or decision.decision_id != expected_decision_id
        or decision.issuer_id != proposal.issuer_id
        or decision.security_id != expected_security_id
        or decision.ticker != ticker
        or decision.exchange != mic
        or decision.share_class != share_class
        or decision.security_structure != structure
        or decision.quote_currency != quote_currency
        or decision.reporting_currency != quote_currency
        or decision.disposition != "eligible"
        or decision.reason_codes
    ):
        raise ValueError("current-share security identity does not replay its evidence")


def current_share_integration_contract_sha256() -> str:
    """Return the closed semantic identity of this contract-only boundary."""

    return canonical_sha256(
        {
            "policy_id": CURRENT_SHARE_INTEGRATION_POLICY_ID,
            "policy_version": CURRENT_SHARE_INTEGRATION_POLICY_VERSION,
            "grouping_policy_id": SHARE_EVENT_GROUPING_POLICY_ID,
            "grouping_policy_version": SHARE_EVENT_GROUPING_POLICY_VERSION,
            "canonical_event_derivation": CANONICAL_EVENT_DERIVATION,
            "rollforward_derivation": CURRENT_SHARE_ROLLFORWARD_DERIVATION,
            "official_occurrence_collision_domain": (
                "issuer_security_official_legal_event_id_legal_effective_date"
            ),
            "economic_event_key_drift": "blocked_before_canonical_grouping",
            "generated_fact_id_reservations": (
                "canonical_conflicting_bytes_blocked_output_any_occupancy_blocked"
            ),
            "opening_share_root": "raw_official_primary_high_confidence",
            "output_share_source": "same_official_primary_source_as_opening",
            "output_share_confidence": "high_only",
            "extension_policy": (
                CURRENT_SHARE_EXTENSION_POLICY_ID,
                CURRENT_SHARE_EXTENSION_POLICY_VERSION,
            ),
            "coverage_search_authority_sha256": coverage_search_authority_sha256(),
            "event_signs": {
                key: format(value, "f")
                for key, value in sorted(COMPLETED_SHARE_EVENT_SIGNS.items())
            },
            "coverage_categories": CORPORATE_ACTION_COVERAGE_CATEGORIES,
            "coverage_entry_cardinality": "exactly_one_entry_per_registered_category",
            "coverage_not_applicable_statement_template": (
                "Share activity category {category} is not applicable to security {security_id}."
            ),
            "coverage_not_applicable_evidence": (
                "direct_fact_only_unique_binding_ids_candidate_safe_and_graph_byte_bound"
            ),
            "coverage_not_applicable_review_time": "candidate_through_data_cutoff_inclusive",
            "coverage_typed_graph_binding": "exact_object_id_and_fingerprint",
            "source_families": tuple(sorted(SOURCE_FAMILIES)),
            "standard_claim_transition_event_concepts": tuple(
                sorted(STANDARD_CLAIM_TRANSITION_EVENT_CONCEPTS)
            ),
            "specialist_required_claim_transition_event_concepts": tuple(
                sorted(SPECIALIST_REQUIRED_CLAIM_TRANSITION_EVENT_CONCEPTS)
            ),
            "claim_transition_review": (
                "exactly_one_candidate_decision_claim_projection_cutoff_safe_and_graph_byte_bound"
            ),
            "multi_root_economic_claim": (
                "blocked_without_graph_owned_aggregate_opening_balance"
            ),
            "dilution_claim_authority_policy": (
                GROUP_BOUND_DILUTION_AUTHORITY_POLICY_ID,
                GROUP_BOUND_DILUTION_AUTHORITY_POLICY_VERSION,
            ),
            "integration_policy_sha256": current_share_integration_policy_sha256(),
        }
    )


def current_share_integration_code_sha256() -> str:
    """Return the exact source-byte identity of this validation boundary."""

    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def current_share_integration_policy_sha256() -> str:
    """Return the exact byte identity of the closed integration policy resource."""

    return hashlib.sha256(CURRENT_SHARE_INTEGRATION_POLICY_PATH.read_bytes()).hexdigest()


def _nonempty(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty")


def _is_named_human(value: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("human:")
        and bool(value[len("human:") :].strip())
    )


def _cik(value: str, label: str) -> None:
    if not isinstance(value, str) or len(value) != 10 or not value.isdigit():
        raise ValueError(f"{label} must be a ten-digit CIK")


def _sha(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _ids(values: tuple[str, ...], label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} must contain non-empty strings")
    normalized = tuple(sorted(values))
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{label} contains duplicate values")
    if not allow_empty and not normalized:
        raise ValueError(f"{label} must not be empty")
    return normalized


def _bindings(
    values: tuple[tuple[str, str], ...],
    label: str,
    *,
    allow_empty: bool = True,
) -> tuple[tuple[str, str], ...]:
    normalized: list[tuple[str, str]] = []
    identifiers: set[str] = set()
    for identifier, fingerprint in values:
        _nonempty(identifier, f"{label} ID")
        _sha(fingerprint, f"{label} fingerprint")
        if identifier in identifiers:
            raise ValueError(f"{label} contains duplicate IDs")
        identifiers.add(identifier)
        normalized.append((identifier, fingerprint))
    result = tuple(sorted(normalized))
    if not allow_empty and not result:
        raise ValueError(f"{label} must not be empty")
    return result


def _objects(
    values: tuple[tuple[str, str, str], ...], label: str
) -> tuple[tuple[str, str, str], ...]:
    normalized: list[tuple[str, str, str]] = []
    object_ids: set[str] = set()
    for contract_type, object_id, fingerprint in values:
        _nonempty(contract_type, f"{label} contract type")
        _nonempty(object_id, f"{label} object ID")
        _sha(fingerprint, f"{label} object SHA")
        if object_id in object_ids:
            raise ValueError(f"{label} contains duplicate object IDs")
        object_ids.add(object_id)
        normalized.append((contract_type, object_id, fingerprint))
    return tuple(sorted(normalized))


_CANONICAL_SHARE_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z")


def _integer_decimal(
    value: str,
    label: str,
    *,
    positive: bool = False,
) -> Decimal:
    if not isinstance(value, str) or _CANONICAL_SHARE_INTEGER.fullmatch(value) is None:
        qualifier = "positive " if positive else "non-negative "
        raise ValueError(f"{label} must be a canonical {qualifier}integer string")
    try:
        parsed = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} must be an exact decimal string") from exc
    if (
        not parsed.is_finite()
        or parsed != parsed.to_integral()
        or (parsed <= 0 if positive else parsed < 0)
    ):
        qualifier = "positive " if positive else "non-negative "
        raise ValueError(f"{label} must be a canonical {qualifier}integer")
    return parsed


def _fact_share_integer(value: Any, label: str, *, positive: bool = False) -> Decimal:
    if type(value) is not int:
        raise ValueError(f"{label} must be represented as an exact JSON integer")
    return _integer_decimal(str(value), label, positive=positive)


def _date(value: str, label: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO date") from exc


def _utc_datetime(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO datetime") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{label} must be timezone-aware UTC")
    return parsed.astimezone(UTC)


def _price_blind_authorization_is_current(
    graph: ContractGraph,
    freeze: PriceBlindFreezeCompilationResult,
) -> bool:
    authorization = freeze.handoffs[-1]
    handoffs = {item.handoff_id: item for item in graph.valuation_handoffs}
    relevant = tuple(
        item
        for item in graph.valuation_handoffs
        if item.issuer_id == authorization.issuer_id
        and item.data_cutoff_date == authorization.data_cutoff_date
    )
    roots = tuple(item for item in relevant if item.predecessor_handoff_id is None)
    superseded_runs = {
        handoffs[item.supersedes_handoff_id].handoff_run_id
        for item in roots
        if item.supersedes_handoff_id in handoffs
    }
    active_runs = {item.handoff_run_id for item in roots} - superseded_runs
    if active_runs != {authorization.handoff_run_id}:
        return False
    active = tuple(
        sorted(
            (
                item
                for item in relevant
                if item.handoff_run_id == authorization.handoff_run_id
            ),
            key=lambda item: item.handoff_version,
        )
    )
    return bool(active) and active[-1] == authorization


def _graph_registry(graph: ContractGraph) -> dict[tuple[str, str], Any]:
    registry: dict[tuple[str, str], Any] = {}
    for field_name, contract_type in GRAPH_DOMAIN_TYPES.items():
        for item in getattr(graph, field_name):
            identifier = getattr(item, GRAPH_OBJECT_ID_ATTRIBUTE[contract_type])
            key = (contract_type, identifier)
            if key in registry:
                raise ValueError("ContractGraph contains duplicate typed object identity")
            registry[key] = item
    return registry


def _typed_extension_edges(contract_type: str, item: Any) -> tuple[tuple[str, str], ...]:
    """Return the closed, target-typed dependency edges for one extension object."""

    edges: set[tuple[str, str]] = set()

    def add(target_type: str, identifier: str | None) -> None:
        if identifier is not None:
            edges.add((target_type, str(identifier)))

    def add_many(target_type: str, identifiers: Any) -> None:
        for identifier in identifiers:
            add(target_type, str(identifier))

    if contract_type == "SourceDocument":
        pass
    elif contract_type == "Fact":
        add("SourceDocument", item.source_document_id)
        add_many("Fact", item.parent_fact_ids)
    elif contract_type == "Claim":
        add_many("Fact", item.supporting_fact_ids)
        add_many("Fact", item.counterevidence_fact_ids)
    elif contract_type == "AnalyticalClaimCandidate":
        add_many("SegmentDefinition", item.scope["segment_definition_ids"])
        for binding in (*item.supporting_evidence_bindings, *item.counterevidence_bindings):
            targets = tuple(
                (target_type, binding[field_name])
                for target_type, field_name in (
                    ("Fact", "fact_id"),
                    ("CalculationResult", "calculation_result_id"),
                    ("ContextObservation", "context_observation_id"),
                )
                if binding[field_name] is not None
            )
            if len(targets) != 1:
                raise ValueError("analytical evidence binding is not exactly one typed object")
            add(*targets[0])
    elif contract_type == "AnalyticalClaimReviewDecision":
        add("AnalyticalClaimCandidate", item.candidate_id)
        add("Claim", item.output_claim_id)
    elif contract_type == "SourceSearchReceipt":
        add_many("SourceDocument", item.result_document_ids)
    elif contract_type == "FilingArtifact":
        add("SourceDocument", item.source_document_id)
    elif contract_type == "CapitalAllocationEventCandidate":
        add("SourceDocument", item.source_document_id)
        add_many("SegmentDefinition", item.proposed_scope["segment_definition_ids"])
        add_many(
            "Fact",
            (binding["fact_id"] for binding in item.proposed_fact_bindings),
        )
        add_many("ManagementStatement", item.proposed_rationale_statement_ids)
        add_many("ManagementCommitment", item.proposed_related_commitment_ids)
        add_many("CapitalAllocationEventCandidate", item.potential_duplicate_candidate_ids)
        add_many("CapitalAllocationEventCandidate", item.supersedes_candidate_ids)
    elif contract_type == "CapitalAllocationEventReviewDecision":
        add("CapitalAllocationEventCandidate", item.candidate_id)
        add("CapitalAllocationEvent", item.output_event_id)
        add_many("CapitalAllocationEventReviewDecision", item.supersedes_decision_ids)
    elif contract_type == "CapitalAllocationEvent":
        add("CapitalAllocationEvent", item.predecessor_event_id)
        add_many("CapitalAllocationEvent", item.supersedes_event_ids)
        add_many("SegmentDefinition", item.scope["segment_definition_ids"])
        for binding in item.source_bindings:
            add("CapitalAllocationEventCandidate", binding["candidate_id"])
            add("CapitalAllocationEventReviewDecision", binding["decision_id"])
            add("SourceDocument", binding["source_document_id"])
        for binding in item.fact_bindings:
            add("CapitalAllocationEventCandidate", binding["candidate_id"])
            add("CapitalAllocationEventReviewDecision", binding["decision_id"])
            add("Fact", binding["fact_id"])
        for binding in item.claim_bindings:
            add("Claim", binding["claim_id"])
            add("AnalyticalClaimReviewDecision", binding["review_decision_id"])
        add_many("ManagementStatement", item.rationale_statement_ids)
        add_many("ManagementCommitment", item.related_commitment_ids)
    elif contract_type == "CalculationResult":
        add_many("Fact", item.input_fact_ids)
        add_many("Assumption", item.input_assumption_ids)
        add_many("CalculationResult", item.input_calculation_ids)
        add_many("FiscalPeriod", item.input_period_ids)
    elif contract_type == "Assumption":
        add_many("Fact", item.supporting_fact_ids)
        add_many("Claim", item.supporting_claim_ids)
    elif contract_type == "FiscalPeriod":
        add("FiscalPeriod", item.comparative_period_id)
        add_many("SourceDocument", item.source_document_ids)
    elif contract_type == "ContextObservation":
        add("SourceDocument", item.source_document_id)
        add_many("SegmentDefinition", item.scope["segment_definition_ids"])
    elif contract_type == "SegmentDefinition":
        add_many("SourceDocument", item.source_document_ids)
        add_many("SegmentDefinition", item.predecessor_segment_ids)
        add("Claim", item.mapping_claim_id)
    elif contract_type == "ManagementStatement":
        add("SourceDocument", item.source_document_id)
        add_many("ManagementStatement", item.predecessor_statement_ids)
        add_many("Fact", item.kpi_definition_fact_ids)
        add_many("Fact", (binding["fact_id"] for binding in item.metric_bindings))
    elif contract_type == "ManagementCommitment":
        add("ManagementStatement", item.statement_id)
        add_many("Fact", (binding["fact_id"] for binding in item.baseline_bindings))
        add_many("Fact", (binding["fact_id"] for binding in item.target_bindings))
        if item.scope["scope_type"] == "segment":
            add("SegmentDefinition", item.scope["scope_id"])
        add_many("Claim", item.condition_claim_ids)
        add_many("CalculationResult", item.definition_reconciliation_calculation_ids)
        add("ManagementStatement", item.withdrawal_statement_id)
        add("ManagementCommitment", item.superseded_by_commitment_id)
    else:
        raise ValueError(
            f"unsupported current-share extension contract type: {contract_type}"
        )
    return tuple(sorted(edges))


def _typed_extension_dependency_closure(
    graph: ContractGraph,
    roots: tuple[str, ...],
) -> dict[str, tuple[str, Any]]:
    """Replay the post-Bundle extension graph through typed contract references only."""

    registry = _graph_registry(graph)
    pending: list[tuple[str, str]] = []
    for root in roots:
        matches = tuple(key for key in registry if key[1] == root)
        if len(matches) != 1:
            raise ResearchBundleValidationError(
                f"current-share extension root is missing or type-ambiguous: {root}"
            )
        pending.append(matches[0])
    closure: dict[str, tuple[str, Any]] = {}
    while pending:
        contract_type, identifier = pending.pop()
        existing = closure.get(identifier)
        if existing is not None:
            if existing[0] != contract_type:
                raise ResearchBundleValidationError(
                    f"current-share extension repeats a cross-type ID: {identifier}"
                )
            continue
        resolved = registry.get((contract_type, identifier))
        if resolved is None:
            raise ResearchBundleValidationError(
                "current-share extension has a dangling or wrong-type dependency: "
                f"{contract_type}:{identifier}"
            )
        item = resolved
        if contract_type == "RunManifest":
            continue
        closure[identifier] = (contract_type, item)
        pending.extend(_typed_extension_edges(contract_type, item))
    return closure


def _scoped_contract_graph_fingerprint(
    graph: ContractGraph,
    object_fingerprints: tuple[tuple[str, str, str], ...],
) -> str:
    objects = _objects(object_fingerprints, "scoped ContractGraph evidence")
    registry = _graph_registry(graph)
    graph_field_by_type = {
        contract_type: field_name for field_name, contract_type in GRAPH_DOMAIN_TYPES.items()
    }
    for contract_type, object_id, fingerprint in objects:
        item = registry.get((contract_type, object_id))
        if item is None:
            # The frozen public ResearchBundle closure predates the target-typed extension
            # registry and uses its historical ID precedence.  Accept that identifier only
            # when it resolves uniquely inside the declared contract type; extension roots
            # never use this fallback.
            legacy_matches = tuple(
                candidate
                for candidate in getattr(graph, graph_field_by_type[contract_type])
                if _object_id(candidate) == object_id
            )
            if len(legacy_matches) != 1:
                raise ValueError(
                    "scoped ContractGraph evidence does not resolve byte-identically"
                )
            item = legacy_matches[0]
        if item.fingerprint != fingerprint:
            raise ValueError("scoped ContractGraph evidence does not resolve byte-identically")
    return canonical_sha256(
        {
            "objects": objects,
            "component_lock_sha256": file_sha256(graph.component_lock_path),
        }
    )


def _primary_member_source_id(
    members: tuple[CanonicalShareEventMemberBinding, ...],
) -> str:
    authority_rank = {"primary_regulatory": 0, "company_primary": 1}
    document_rank = {
        "8-K": 0,
        "10-Q": 1,
        "10-K": 2,
        "registration-statement": 3,
        "prospectus": 4,
        "earnings-release": 5,
        "investor-day": 6,
        "company-transcript": 7,
    }
    selected = min(
        members,
        key=lambda item: (
            authority_rank.get(item.source_document.authority_level, 99),
            document_rank.get(item.source_document.document_type, 99),
            item.source_document.published_date,
            item.source_document.content_sha256,
            item.fact.source_locator,
            item.source_document.document_id,
        ),
    )
    return selected.source_document.document_id


@dataclass(frozen=True, slots=True)
class CanonicalShareEventMemberBinding:
    issuer_id: str
    security_id: str
    data_cutoff_date: str
    member: ShareEventEvidenceMember
    fact: Fact
    source_document: SourceDocument
    capital_allocation_event: CapitalAllocationEvent
    candidates: tuple[CapitalAllocationEventCandidate, ...]
    review_decisions: tuple[CapitalAllocationEventReviewDecision, ...]
    member_id: str
    member_fingerprint: str
    fact_id: str
    fact_fingerprint: str
    source_document_id: str
    source_document_fingerprint: str
    capital_allocation_event_id: str
    capital_allocation_event_fingerprint: str
    candidate_bindings: tuple[tuple[str, str], ...]
    review_decision_bindings: tuple[tuple[str, str], ...]
    binding_fingerprint: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.issuer_id, "member issuer ID"),
            (self.security_id, "member security ID"),
            (self.member_id, "member ID"),
            (self.fact_id, "member Fact ID"),
            (self.source_document_id, "member SourceDocument ID"),
            (self.capital_allocation_event_id, "member CapitalAllocationEvent ID"),
        ):
            _nonempty(value, label)
        for value, label in (
            (self.member_fingerprint, "member fingerprint"),
            (self.fact_fingerprint, "member Fact fingerprint"),
            (self.source_document_fingerprint, "member SourceDocument fingerprint"),
            (
                self.capital_allocation_event_fingerprint,
                "member CapitalAllocationEvent fingerprint",
            ),
        ):
            _sha(value, label)
        cutoff = _date(self.data_cutoff_date, "member data cutoff")
        fact = self.fact
        source = self.source_document
        event = self.capital_allocation_event
        candidates = tuple(sorted(self.candidates, key=lambda item: item.candidate_id))
        decisions = tuple(sorted(self.review_decisions, key=lambda item: item.decision_id))
        if not candidates or not decisions:
            raise ValueError("member binding lacks its reviewed capital-event objects")
        candidate_by_id = {item.candidate_id: item for item in candidates}
        decision_by_id = {item.decision_id: item for item in decisions}
        if len(candidate_by_id) != len(candidates) or len(decision_by_id) != len(decisions):
            raise ValueError("member binding repeats a reviewed capital-event object")
        if (
            self.member_id != self.member.member_id
            or self.member_fingerprint != self.member.member_fingerprint
            or self.fact_id != self.member.fact_id
            or self.fact_fingerprint != self.member.fact_fingerprint
            or self.source_document_id != self.member.source_document_id
            or self.source_document_fingerprint != self.member.source_document_fingerprint
            or self.capital_allocation_event_id != self.member.capital_allocation_event_id
            or self.capital_allocation_event_fingerprint
            != self.member.capital_allocation_event_fingerprint
            or self.data_cutoff_date != self.member.data_cutoff_date
            or fact.fact_id != self.fact_id
            or fact.fingerprint != self.fact_fingerprint
            or source.document_id != self.source_document_id
            or source.fingerprint != self.source_document_fingerprint
            or event.event_id != self.capital_allocation_event_id
            or event.fingerprint != self.capital_allocation_event_fingerprint
            or fact.issuer_id != self.issuer_id
            or source.issuer_id != self.issuer_id
            or event.issuer_id != self.issuer_id
            or fact.source_document_id != source.document_id
            or fact.source_locator != self.member.source_locator
            or fact.concept not in COMPLETED_SHARE_EVENT_SIGNS
            or fact.value_type != "number"
            or fact.unit != "shares"
            or fact.currency is not None
            or fact.period.get("start") is not None
            or fact.period.get("end") != self.member.fact_measurement_date
            or fact.derivation is not None
            or fact.parent_fact_ids
            or fact.confidence != "high"
            or source.authority_level not in OFFICIAL_AUTHORITY_LEVELS
            or source.authority_level != self.member.source_authority_level
            or source.published_date != self.member.source_published_date
            or event.lifecycle_status != "completed"
            or _date(self.member.fact_measurement_date, "member measurement date") > cutoff
            or _date(self.member.source_published_date, "member published date") > cutoff
        ):
            raise ValueError("member binding does not replay the reviewed grouping member")
        candidate_bindings = _bindings(
            self.candidate_bindings,
            "member Candidate bindings",
            allow_empty=False,
        )
        decision_bindings = _bindings(
            self.review_decision_bindings,
            "member ReviewDecision bindings",
            allow_empty=False,
        )
        if candidate_bindings != tuple(
            sorted((item.candidate_id, item.fingerprint) for item in candidates)
        ) or decision_bindings != tuple(
            sorted((item.decision_id, item.fingerprint) for item in decisions)
        ):
            raise ValueError("member reviewed-object bindings do not match typed objects")
        if {item.candidate_id for item in candidates} != set(self.member.candidate_ids) or {
            item.decision_id for item in decisions
        } != set(self.member.review_decision_ids):
            raise ValueError("member reviewed-object set does not match grouping evidence")
        matching_pairs = 0
        policy = SHARE_EVENT_CONCEPT_POLICIES[fact.concept]
        for decision in decisions:
            candidate = candidate_by_id.get(decision.candidate_id)
            if candidate is None:
                raise ValueError("member ReviewDecision lacks its typed Candidate")
            source_bindings = tuple(
                item
                for item in event.source_bindings
                if item["candidate_id"] == candidate.candidate_id
                and item["decision_id"] == decision.decision_id
                and item["source_document_id"] == source.document_id
            )
            fact_bindings = tuple(
                item
                for item in event.fact_bindings
                if item["candidate_id"] == candidate.candidate_id
                and item["decision_id"] == decision.decision_id
                and item["fact_id"] == fact.fact_id
                and item["role_id"] in policy["fact_roles"]
            )
            candidate_fact_bindings = tuple(
                item
                for item in candidate.proposed_fact_bindings
                if item["fact_id"] == fact.fact_id and item["role_id"] in policy["fact_roles"]
            )
            if (
                candidate.issuer_id != self.issuer_id
                or candidate.source_document_id != source.document_id
                or candidate.validation_status != "ready"
                or candidate.proposed_event_type != event.event_type
                or candidate.proposed_event_subtype != event.event_subtype
                or tuple(candidate.proposed_identity_components) != tuple(event.identity_components)
                or candidate.proposed_execution_period.get("start")
                != self.member.fact_measurement_date
                or candidate.proposed_execution_period.get("end")
                != self.member.fact_measurement_date
                or decision.issuer_id != self.issuer_id
                or decision.decision != "confirmed"
                or not _is_named_human(decision.reviewer_id)
                or decision.candidate_fingerprint != candidate.fingerprint
                or decision.output_event_id != event.event_id
                or decision.output_economic_event_key != event.economic_event_key
                or _utc_datetime(decision.reviewed_at, "capital-event review time").date() > cutoff
                or len(source_bindings) != 1
                or len(fact_bindings) != 1
                or len(candidate_fact_bindings) != 1
            ):
                raise ValueError("member capital-event review chain is not authoritative")
            matching_pairs += 1
        if matching_pairs != len(candidates):
            raise ValueError("member capital-event review chain is incomplete")
        if _fact_share_integer(fact.value, "member Fact value", positive=True) <= 0:
            raise ValueError("member Fact value is invalid")
        _utc_datetime(source.retrieved_at, "member source retrieval time")
        object.__setattr__(self, "candidates", candidates)
        object.__setattr__(self, "review_decisions", decisions)
        object.__setattr__(self, "candidate_bindings", candidate_bindings)
        object.__setattr__(self, "review_decision_bindings", decision_bindings)
        _sha(self.binding_fingerprint, "member binding fingerprint")
        if self.binding_fingerprint != self.expected_fingerprint():
            raise ValueError("member binding fingerprint mismatch")

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("binding_fingerprint")
        return payload

    def expected_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class CanonicalShareEventFactMaterialization:
    policy_id: str
    policy_version: str
    materialization_code_sha256: str
    issuer_id: str
    security_id: str
    opening_date: str
    quote_date: str
    data_cutoff_date: str
    grouping_result: ShareEventGroupingResult
    group: ShareEventEvidenceGroup
    canonical_event_fact: Fact
    grouping_result_fingerprint: str
    group_id: str
    group_fingerprint: str
    identity_fingerprint: str
    canonical_event_fact_id: str
    canonical_event_fact_fingerprint: str
    event_concept: str
    legal_effective_date: str
    canonical_share_magnitude: str
    primary_source_document_id: str
    members: tuple[CanonicalShareEventMemberBinding, ...]
    materialization_fingerprint: str

    def __post_init__(self) -> None:
        if (self.policy_id, self.policy_version) != (
            CURRENT_SHARE_INTEGRATION_POLICY_ID,
            CURRENT_SHARE_INTEGRATION_POLICY_VERSION,
        ):
            raise ValueError("canonical-event materialization policy mismatch")
        for value, label in (
            (self.materialization_code_sha256, "materialization code SHA"),
            (self.grouping_result_fingerprint, "grouping-result fingerprint"),
            (self.group_fingerprint, "group fingerprint"),
            (self.identity_fingerprint, "identity fingerprint"),
            (self.canonical_event_fact_fingerprint, "canonical event Fact fingerprint"),
        ):
            _sha(value, label)
        if self.materialization_code_sha256 != current_share_integration_code_sha256():
            raise ValueError("canonical-event materialization code SHA mismatch")
        if self.grouping_result.grouping_code_sha256 != _grouping_code_sha256():
            raise ValueError("grouping result code SHA does not match the frozen implementation")
        for value, label in (
            (self.issuer_id, "materialization issuer ID"),
            (self.security_id, "materialization security ID"),
        ):
            _nonempty(value, label)
        opening = _date(self.opening_date, "materialization opening date")
        quote = _date(self.quote_date, "materialization quote date")
        cutoff = _date(self.data_cutoff_date, "materialization data cutoff")
        effective = _date(self.legal_effective_date, "canonical-event effective date")
        if not opening < effective <= quote <= cutoff:
            raise ValueError("canonical event falls outside the governed materialization window")
        _nonempty(self.group_id, "canonical group ID")
        _nonempty(self.primary_source_document_id, "primary SourceDocument ID")
        if self.event_concept not in COMPLETED_SHARE_EVENT_SIGNS:
            raise ValueError("canonical-event concept is not registered")
        _integer_decimal(
            self.canonical_share_magnitude,
            "canonical share magnitude",
            positive=True,
        )
        expected_fact_id = f"derived:share-event:{self.identity_fingerprint[:24]}"
        if self.canonical_event_fact_id != expected_fact_id:
            raise ValueError("canonical event Fact does not match the reserved identity")
        members = tuple(sorted(self.members, key=lambda item: item.member_id))
        if not members:
            raise ValueError("canonical-event materialization has no member evidence")
        for attribute, label in (
            ("member_id", "member"),
            ("fact_id", "member Fact"),
            ("source_document_id", "member SourceDocument"),
        ):
            values = [getattr(item, attribute) for item in members]
            if len(values) != len(set(values)):
                raise ValueError(f"canonical-event materialization contains duplicate {label}")
        if self.primary_source_document_id != _primary_member_source_id(members):
            raise ValueError("canonical-event primary source is not deterministically selected")
        grouped_members = {item.member_id: item for item in self.grouping_result.members}
        matching_groups = tuple(
            item for item in self.grouping_result.groups if item.group_id == self.group_id
        )
        if (
            self.grouping_result.status != "grouped"
            or self.grouping_result_fingerprint != self.grouping_result.grouping_fingerprint
            or self.grouping_result.issuer_id != self.issuer_id
            or self.grouping_result.security_id != self.security_id
            or self.grouping_result.opening_date != self.opening_date
            or self.grouping_result.quote_date != self.quote_date
            or len(matching_groups) != 1
            or matching_groups[0] != self.group
            or self.group.status != "canonical"
            or self.group.group_fingerprint != self.group_fingerprint
            or self.group.identity.identity_fingerprint != self.identity_fingerprint
            or self.group.identity.issuer_id != self.issuer_id
            or self.group.identity.security_id != self.security_id
            or self.group.identity.event_concept != self.event_concept
            or self.group.identity.legal_effective_date != self.legal_effective_date
            or self.group.identity.canonical_share_magnitude != self.canonical_share_magnitude
            or self.group.canonical_event_fact_id != self.canonical_event_fact_id
            or set(self.group.member_ids) != {item.member_id for item in members}
        ):
            raise ValueError("materialization does not replay the accepted grouping result")
        for member in members:
            grouped = grouped_members.get(member.member_id)
            if (
                grouped is None
                or grouped != member.member
                or member.issuer_id != self.issuer_id
                or member.security_id != self.security_id
                or member.data_cutoff_date != self.data_cutoff_date
                or member.member.legal_event_key != self.group.identity.legal_event_key
                or member.capital_allocation_event.economic_event_key
                != self.group.identity.economic_event_key
                or member.fact.concept != self.event_concept
                or _fact_share_integer(member.fact.value, "member Fact value", positive=True)
                != _integer_decimal(
                    self.canonical_share_magnitude,
                    "canonical share magnitude",
                    positive=True,
                )
                or member.member.fact_measurement_date != self.legal_effective_date
                or {identifier for identifier, _ in member.candidate_bindings}
                != set(member.member.candidate_ids)
                or {identifier for identifier, _ in member.review_decision_bindings}
                != set(member.member.review_decision_ids)
            ):
                raise ValueError("materialization member does not match its reviewed group")
        canonical = self.canonical_event_fact
        if (
            canonical.fact_id != self.canonical_event_fact_id
            or canonical.fingerprint != self.canonical_event_fact_fingerprint
            or canonical.issuer_id != self.issuer_id
            or canonical.concept != self.event_concept
            or canonical.value_type != "number"
            or _fact_share_integer(
                canonical.value,
                "canonical event Fact value",
                positive=True,
            )
            != _integer_decimal(
                self.canonical_share_magnitude,
                "canonical share magnitude",
                positive=True,
            )
            or canonical.unit != "shares"
            or canonical.currency is not None
            or canonical.period.get("start") is not None
            or canonical.period.get("end") != self.legal_effective_date
            or canonical.source_document_id != self.primary_source_document_id
            or canonical.source_locator
            != _canonical_event_source_locator(self.canonical_event_fact_id)
            or canonical.derivation != CANONICAL_EVENT_DERIVATION
            or canonical.parent_fact_ids
            != tuple(sorted(item.fact_id for item in members))
            or canonical.confidence != "high"
        ):
            raise ValueError("canonical event Fact does not exactly materialize the reviewed group")
        object.__setattr__(self, "members", members)
        _sha(self.materialization_fingerprint, "materialization fingerprint")
        if self.materialization_fingerprint != self.expected_fingerprint():
            raise ValueError("canonical-event materialization fingerprint mismatch")

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("materialization_fingerprint")
        return payload

    def expected_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class ShareEventNumericConsumption:
    group_id: str
    group_fingerprint: str
    identity_fingerprint: str
    canonical_event_fact_id: str
    canonical_event_fact_fingerprint: str
    event_concept: str
    sign: str
    channel: str
    window_start: str
    window_end: str
    consumption_fingerprint: str

    def __post_init__(self) -> None:
        _nonempty(self.group_id, "consumed canonical group ID")
        for value, label in (
            (self.group_fingerprint, "consumed group fingerprint"),
            (self.identity_fingerprint, "consumed identity fingerprint"),
            (self.canonical_event_fact_fingerprint, "consumed canonical Fact fingerprint"),
        ):
            _sha(value, label)
        if self.event_concept not in COMPLETED_SHARE_EVENT_SIGNS:
            raise ValueError("numeric-consumption event concept is not registered")
        expected_sign = format(COMPLETED_SHARE_EVENT_SIGNS[self.event_concept], "f")
        if self.sign != expected_sign:
            raise ValueError("numeric-consumption sign does not match the registered event concept")
        if self.channel != CURRENT_SHARE_ROLLFORWARD_CHANNEL:
            raise ValueError("numeric-consumption channel is not registered")
        if _date(self.window_start, "consumption window start") >= _date(
            self.window_end, "consumption window end"
        ):
            raise ValueError("numeric-consumption window is invalid")
        expected_fact_id = f"derived:share-event:{self.identity_fingerprint[:24]}"
        if self.canonical_event_fact_id != expected_fact_id:
            raise ValueError("numeric consumption is not bound to the reserved canonical Fact")
        _sha(self.consumption_fingerprint, "numeric-consumption fingerprint")
        if self.consumption_fingerprint != self.expected_fingerprint():
            raise ValueError("numeric-consumption fingerprint mismatch")

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("consumption_fingerprint")
        return payload

    def expected_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class CorporateActionCoverageEntryV2:
    category: str
    status: str
    group_ids: tuple[str, ...]
    canonical_event_fact_ids: tuple[str, ...]
    member_event_fact_ids: tuple[str, ...]
    observed_member_facts: tuple[Fact, ...]
    observed_member_source_documents: tuple[SourceDocument, ...]
    zero_fact_id: str | None
    zero_fact: Fact | None
    not_applicable_claim_id: str | None
    not_applicable_claim: Claim | None
    not_applicable_candidate: AnalyticalClaimCandidate | None
    review_decision_id: str | None
    review_decision: AnalyticalClaimReviewDecision | None
    not_applicable_supporting_facts: tuple[Fact, ...]
    not_applicable_counterevidence_facts: tuple[Fact, ...]
    source_search_receipt_ids: tuple[str, ...]
    entry_fingerprint: str

    def __post_init__(self) -> None:
        if self.category not in CORPORATE_ACTION_COVERAGE_CATEGORIES:
            raise ValueError("group-bound coverage category is not registered")
        if self.status not in {
            "observed",
            "official_zero_or_no_activity",
            "not_applicable_with_reviewed_proof",
        }:
            raise ValueError("group-bound coverage status is not closed")
        groups = _ids(self.group_ids, "coverage canonical groups")
        canonical_facts = _ids(
            self.canonical_event_fact_ids,
            "coverage canonical event Facts",
        )
        member_facts = _ids(self.member_event_fact_ids, "coverage member event Facts")
        observed_facts = tuple(sorted(self.observed_member_facts, key=lambda item: item.fact_id))
        observed_sources = tuple(
            sorted(self.observed_member_source_documents, key=lambda item: item.document_id)
        )
        observed_fact_by_id = {item.fact_id: item for item in observed_facts}
        observed_source_by_id = {item.document_id: item for item in observed_sources}
        if len(observed_fact_by_id) != len(observed_facts) or len(observed_source_by_id) != len(
            observed_sources
        ):
            raise ValueError("observed coverage repeats a typed evidence object")
        receipts = _ids(
            self.source_search_receipt_ids,
            "coverage SourceSearchReceipts",
            allow_empty=False,
        )
        if self.status == "observed":
            if (
                not groups
                or len(groups) != len(canonical_facts)
                or not member_facts
                or any(
                    item is not None
                    for item in (
                        self.zero_fact_id,
                        self.zero_fact,
                        self.not_applicable_claim_id,
                        self.not_applicable_claim,
                        self.not_applicable_candidate,
                        self.review_decision_id,
                        self.review_decision,
                    )
                )
                or self.not_applicable_supporting_facts
                or self.not_applicable_counterevidence_facts
                or set(observed_fact_by_id) != set(member_facts)
                or {item.source_document_id for item in observed_facts}
                != set(observed_source_by_id)
                or any(
                    item.issuer_id != observed_facts[0].issuer_id
                    or item.concept not in COMPLETED_SHARE_EVENT_SIGNS
                    or item.value_type != "number"
                    or _fact_share_integer(
                        item.value,
                        "observed coverage event share value",
                        positive=True,
                    )
                    <= 0
                    or item.unit != "shares"
                    or item.currency is not None
                    or item.derivation is not None
                    or item.parent_fact_ids
                    or item.confidence != "high"
                    or item.period.get("start") is not None
                    or item.period.get("end") is None
                    or item.source_document_id not in observed_source_by_id
                    for item in observed_facts
                )
                or any(
                    item.issuer_id != observed_facts[0].issuer_id
                    or item.authority_level not in OFFICIAL_AUTHORITY_LEVELS
                    for item in observed_sources
                )
            ):
                raise ValueError("observed coverage lacks canonical group evidence")
        elif self.status == "official_zero_or_no_activity":
            if (
                self.zero_fact_id is None
                or self.zero_fact is None
                or self.zero_fact.fact_id != self.zero_fact_id
                or groups
                or canonical_facts
                or member_facts
                or self.not_applicable_claim_id is not None
                or self.not_applicable_claim is not None
                or self.not_applicable_candidate is not None
                or self.review_decision_id is not None
                or self.review_decision is not None
                or self.not_applicable_supporting_facts
                or self.not_applicable_counterevidence_facts
                or observed_facts
                or observed_sources
            ):
                raise ValueError("official-zero coverage contains canonical event evidence")
        elif (
            self.not_applicable_claim_id is None
            or self.not_applicable_claim is None
            or self.not_applicable_candidate is None
            or self.review_decision_id is None
            or self.review_decision is None
            or self.not_applicable_claim.claim_id != self.not_applicable_claim_id
            or self.review_decision.decision_id != self.review_decision_id
            or self.review_decision.candidate_id != self.not_applicable_candidate.candidate_id
            or self.review_decision.output_claim_id != self.not_applicable_claim_id
            or self.zero_fact_id is not None
            or self.zero_fact is not None
            or groups
            or canonical_facts
            or member_facts
            or observed_facts
            or observed_sources
        ):
            raise ValueError("not-applicable coverage lacks reviewed proof")
        supporting_facts = tuple(
            sorted(self.not_applicable_supporting_facts, key=lambda item: item.fact_id)
        )
        counterevidence_facts = tuple(
            sorted(self.not_applicable_counterevidence_facts, key=lambda item: item.fact_id)
        )
        if self.status == "not_applicable_with_reviewed_proof":
            assert self.not_applicable_claim is not None
            assert self.not_applicable_candidate is not None
            assert self.review_decision is not None
            claim = self.not_applicable_claim
            candidate = self.not_applicable_candidate
            decision = self.review_decision
            supporting_ids = _direct_binding_fact_ids(
                candidate.supporting_evidence_bindings,
                "coverage N/A supporting evidence",
            )
            counterevidence_ids = _direct_binding_fact_ids(
                candidate.counterevidence_bindings,
                "coverage N/A counterevidence",
            )
            all_binding_ids = tuple(
                str(binding["binding_id"])
                for binding in (
                    *candidate.supporting_evidence_bindings,
                    *candidate.counterevidence_bindings,
                )
            )
            expected_evidence_sha = canonical_sha256(
                {
                    "supporting_evidence_bindings": candidate.supporting_evidence_bindings,
                    "counterevidence_bindings": candidate.counterevidence_bindings,
                }
            )
            if (
                not supporting_facts
                or len(all_binding_ids) != len(set(all_binding_ids))
                or len(supporting_facts)
                != len({item.fact_id for item in supporting_facts})
                or len(counterevidence_facts)
                != len({item.fact_id for item in counterevidence_facts})
                or tuple(item.fact_id for item in supporting_facts)
                != tuple(sorted(claim.supporting_fact_ids))
                or tuple(item.fact_id for item in counterevidence_facts)
                != tuple(sorted(claim.counterevidence_fact_ids))
                or supporting_ids != tuple(sorted(claim.supporting_fact_ids))
                or counterevidence_ids != tuple(sorted(claim.counterevidence_fact_ids))
                or candidate.claim_role != "not_applicable"
                or candidate.validation_status != "ready"
                or candidate.validation_issues
                or candidate.business_attribute_role is not None
                or candidate.business_component_type is not None
                or to_json_value(candidate.scope) != _issuer_wide_analytical_scope()
                or candidate.evidence_graph_sha256 != expected_evidence_sha
                or decision.decision != "confirmed"
                or decision.issues
                or not decision.reviewer_id.startswith("human:")
                or not decision.reviewer_id[len("human:") :].strip()
                or decision.candidate_id != candidate.candidate_id
                or decision.candidate_fingerprint != candidate.fingerprint
                or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
                or decision.output_claim_id != claim.claim_id
                or claim.issuer_id != candidate.issuer_id
                or claim.statement != candidate.proposed_statement
                or claim.as_of_date != candidate.as_of_date
                or claim.counterevidence_search_note
                != candidate.counterevidence_search_note
                or claim.confidence != candidate.proposed_confidence
                or claim.falsification_condition != candidate.falsification_condition
                or not claim.counterevidence_search_note
                or not claim.falsification_condition
            ):
                raise ValueError("not-applicable coverage lacks exact reviewed proof")
        object.__setattr__(self, "not_applicable_supporting_facts", supporting_facts)
        object.__setattr__(
            self,
            "not_applicable_counterevidence_facts",
            counterevidence_facts,
        )
        object.__setattr__(self, "group_ids", groups)
        object.__setattr__(self, "canonical_event_fact_ids", canonical_facts)
        object.__setattr__(self, "member_event_fact_ids", member_facts)
        object.__setattr__(self, "observed_member_facts", observed_facts)
        object.__setattr__(self, "observed_member_source_documents", observed_sources)
        object.__setattr__(self, "source_search_receipt_ids", receipts)
        _sha(self.entry_fingerprint, "coverage-entry fingerprint")
        if self.entry_fingerprint != self.expected_fingerprint():
            raise ValueError("coverage-entry fingerprint mismatch")

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("entry_fingerprint")
        return payload

    def expected_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class CorporateActionCoverageLedgerV2:
    issuer_id: str
    issuer_cik: str
    security_id: str
    period_start: str
    period_end: str
    data_cutoff_date: str
    expected_group_ids: tuple[str, ...]
    entries: tuple[CorporateActionCoverageEntryV2, ...]
    receipts: tuple[SourceSearchReceipt, ...]
    result_source_documents: tuple[SourceDocument, ...]
    receipt_ids: tuple[str, ...]
    search_authority_id: str
    search_authority_version: str
    search_authority_code_sha256: str
    ledger_sha256: str

    _REQUIRED_CATEGORIES: ClassVar[tuple[str, ...]] = CORPORATE_ACTION_COVERAGE_CATEGORIES

    @classmethod
    def required_categories(cls) -> tuple[str, ...]:
        return cls._REQUIRED_CATEGORIES

    def __post_init__(self) -> None:
        _nonempty(self.issuer_id, "coverage issuer ID")
        _cik(self.issuer_cik, "coverage issuer CIK")
        _nonempty(self.security_id, "coverage security ID")
        period_start = _date(self.period_start, "coverage period start")
        period_end = _date(self.period_end, "coverage period end")
        cutoff = _date(self.data_cutoff_date, "coverage data cutoff")
        if period_start >= period_end or period_end > cutoff:
            raise ValueError("group-bound coverage period is invalid")
        if (
            self.search_authority_id != COVERAGE_SEARCH_AUTHORITY_ID
            or self.search_authority_version != COVERAGE_SEARCH_AUTHORITY_VERSION
            or self.search_authority_code_sha256 != coverage_search_authority_sha256()
        ):
            raise ValueError("coverage search authority is not the closed repository authority")
        expected = _ids(self.expected_group_ids, "expected canonical groups")
        entries = tuple(sorted(self.entries, key=lambda item: item.category))
        entry_categories = [item.category for item in entries]
        if (
            len(entries) != len(self._REQUIRED_CATEGORIES)
            or len(entry_categories) != len(set(entry_categories))
            or set(entry_categories) != set(self._REQUIRED_CATEGORIES)
        ):
            raise ValueError(
                "group-bound coverage requires exactly one entry per registered category"
            )
        not_applicable_entries = tuple(
            item for item in entries if item.status == "not_applicable_with_reviewed_proof"
        )
        for field_name, label in (
            ("not_applicable_claim_id", "Claim"),
            ("review_decision_id", "ReviewDecision"),
        ):
            identifiers = tuple(getattr(item, field_name) for item in not_applicable_entries)
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"coverage N/A {label} review chain is reused across categories")
        candidate_ids = tuple(
            item.not_applicable_candidate.candidate_id
            for item in not_applicable_entries
            if item.not_applicable_candidate is not None
        )
        if len(candidate_ids) != len(not_applicable_entries) or len(candidate_ids) != len(
            set(candidate_ids)
        ):
            raise ValueError("coverage N/A Candidate review chain is reused across categories")
        receipt_objects = tuple(sorted(self.receipts, key=lambda item: item.source_family))
        result_sources = tuple(
            sorted(self.result_source_documents, key=lambda item: item.document_id)
        )
        result_source_by_id = {item.document_id: item for item in result_sources}
        if len(result_source_by_id) != len(result_sources):
            raise ValueError("coverage result SourceDocuments are duplicated")
        if len(receipt_objects) != len(SOURCE_FAMILIES) or {
            item.source_family for item in receipt_objects
        } != set(SOURCE_FAMILIES):
            raise ValueError("coverage ledger lacks exactly one receipt per source family")
        receipts = _ids(self.receipt_ids, "coverage ledger receipts", allow_empty=False)
        if receipts != tuple(sorted(item.receipt_id for item in receipt_objects)):
            raise ValueError("coverage receipt IDs do not match the typed receipt set")
        for receipt in receipt_objects:
            completed = _utc_datetime(
                receipt.completed_at,
                "coverage receipt completion time",
            )
            if (
                receipt.issuer_id != self.issuer_id
                or receipt.query_scope["cik"] != self.issuer_cik
                or receipt.status != "completed"
                or receipt.issues
                or receipt.cutoff_date != self.data_cutoff_date
                or _date(str(receipt.period["start"]), "receipt period start") > period_start
                or _date(str(receipt.period["end"]), "receipt period end") < period_end
                or not set(SHARE_COVERAGE_SEARCH_EVENT_TYPES).issubset(
                    set(receipt.query_scope["event_types"])
                )
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
                or receipt.searched_endpoints != COVERAGE_SEARCH_ENDPOINTS[receipt.source_family]
                or receipt.tool_version != COVERAGE_SEARCH_TOOL_VERSION
                or receipt.receipt_id != _source_search_receipt_id(receipt)
                or completed.date() < _date(str(receipt.period["end"]), "receipt period end")
            ):
                raise ValueError("coverage SourceSearchReceipt does not replay")
            for document_id in receipt.result_document_ids:
                document = result_source_by_id.get(document_id)
                retrieved = (
                    _utc_datetime(document.retrieved_at, "coverage result retrieval time")
                    if document is not None
                    else None
                )
                published = (
                    datetime.combine(
                        _date(document.published_date, "coverage result published date"),
                        datetime.min.time(),
                        tzinfo=UTC,
                    )
                    if document is not None
                    else None
                )
                if (
                    document is None
                    or document.issuer_id != self.issuer_id
                    or document.authority_level not in OFFICIAL_AUTHORITY_LEVELS
                    or source_family(document) != receipt.source_family
                    or _date(document.published_date, "coverage result published date") > cutoff
                    or retrieved is None
                    or published is None
                    or completed < retrieved
                    or completed < published
                ):
                    raise ValueError(
                        "coverage receipt result does not match its official source family"
                    )
        if any(item.source_search_receipt_ids != receipts for item in entries):
            raise ValueError("coverage entries do not share the closed receipt set")
        searched_document_ids = {
            document_id
            for receipt in receipt_objects
            for document_id in receipt.result_document_ids
        }
        if searched_document_ids != set(result_source_by_id):
            raise ValueError("coverage result SourceDocument set is not exact")
        receipt_sources_by_family = {
            receipt.source_family: set(receipt.result_document_ids) for receipt in receipt_objects
        }
        for entry in entries:
            if entry.status == "observed":
                for fact in entry.observed_member_facts:
                    fact_end = _date(
                        str(fact.period["end"]),
                        "observed coverage event date",
                    )
                    source = result_source_by_id.get(fact.source_document_id)
                    if source is None:
                        raise ValueError(
                            "observed share-event source is absent from its governed receipt"
                        )
                    if (
                        fact.issuer_id != self.issuer_id
                        or fact_end <= period_start
                        or fact_end > period_end
                        or fact_end > cutoff
                        or _date(
                            source.published_date,
                            "observed coverage source published date",
                        )
                        > cutoff
                    ):
                        raise ValueError(
                            "observed share-event evidence is outside the closed activity window"
                        )
                for source in entry.observed_member_source_documents:
                    family = source_family(source)
                    if source.document_id not in receipt_sources_by_family.get(family, set()):
                        raise ValueError(
                            "observed share-event source is absent from its governed receipt"
                        )
            if entry.status == "official_zero_or_no_activity":
                assert entry.zero_fact is not None
                zero = entry.zero_fact
                if (
                    zero.issuer_id != self.issuer_id
                    or zero.concept != f"share_activity_{entry.category}_count"
                    or zero.value_type != "number"
                    or _fact_share_integer(zero.value, "coverage zero Fact value") != 0
                    or zero.unit != "count"
                    or zero.currency is not None
                    or zero.period.get("start") != self.period_start
                    or zero.period.get("end") != self.period_end
                    or zero.derivation is not None
                    or zero.parent_fact_ids
                    or zero.confidence != "high"
                    or zero.source_document_id not in searched_document_ids
                ):
                    raise ValueError("coverage official-zero Fact is not governed evidence")
            if entry.status == "not_applicable_with_reviewed_proof":
                assert entry.not_applicable_claim is not None
                assert entry.not_applicable_candidate is not None
                assert entry.review_decision is not None
                claim = entry.not_applicable_claim
                candidate = entry.not_applicable_candidate
                decision = entry.review_decision
                expected_statement = _coverage_not_applicable_statement(
                    entry.category,
                    self.security_id,
                )
                candidate_date = _date(
                    candidate.as_of_date,
                    "coverage N/A Candidate date",
                )
                claim_date = _date(claim.as_of_date, "coverage N/A Claim date")
                reviewed_at = _utc_datetime(
                    decision.reviewed_at,
                    "coverage N/A review time",
                )
                if (
                    claim.issuer_id != self.issuer_id
                    or candidate.issuer_id != self.issuer_id
                    or decision.issuer_id != self.issuer_id
                    or candidate.proposed_statement != expected_statement
                    or claim.statement != expected_statement
                    or candidate_date < period_end
                    or candidate_date > cutoff
                    or claim_date != candidate_date
                    or reviewed_at.date() < candidate_date
                    or reviewed_at.date() > cutoff
                    or candidate.claim_role != "not_applicable"
                    or candidate.validation_status != "ready"
                    or decision.decision != "confirmed"
                    or not decision.reviewer_id.startswith("human:")
                    or not decision.reviewer_id[len("human:") :].strip()
                    or decision.candidate_fingerprint != candidate.fingerprint
                    or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
                    or decision.output_claim_id != claim.claim_id
                    or claim.statement != candidate.proposed_statement
                    or not claim.supporting_fact_ids
                    or not claim.counterevidence_search_note
                    or not claim.falsification_condition
                    or any(
                        fact.issuer_id != self.issuer_id
                        or fact.source_document_id not in searched_document_ids
                        or fact.confidence not in {"high", "medium"}
                        or fact.derivation is not None
                        or fact.parent_fact_ids
                        or fact.period.get("end") is None
                        or _date(
                            str(fact.period["end"]),
                            "coverage N/A supporting Fact date",
                        )
                        > candidate_date
                        or _date(
                            result_source_by_id[fact.source_document_id].published_date,
                            "coverage N/A supporting source published date",
                        )
                        > candidate_date
                        for fact in (
                            *entry.not_applicable_supporting_facts,
                            *entry.not_applicable_counterevidence_facts,
                        )
                    )
                ):
                    raise ValueError(
                        "coverage not-applicable proof is not category-specific, period-safe, "
                        "and human reviewed"
                    )
        consumed = [
            group_id
            for entry in entries
            if entry.status == "observed"
            for group_id in entry.group_ids
        ]
        if sorted(consumed) != list(expected) or len(consumed) != len(set(consumed)):
            raise ValueError("canonical groups are not covered exactly once")
        object.__setattr__(self, "expected_group_ids", expected)
        object.__setattr__(self, "entries", entries)
        object.__setattr__(self, "receipts", receipt_objects)
        object.__setattr__(self, "result_source_documents", result_sources)
        object.__setattr__(self, "receipt_ids", receipts)
        _sha(self.ledger_sha256, "coverage-ledger SHA")
        if self.ledger_sha256 != self.expected_sha256():
            raise ValueError("coverage-ledger SHA mismatch")

    def hash_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("ledger_sha256")
        return payload

    def expected_sha256(self) -> str:
        return canonical_sha256(self.hash_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class GroupBoundClaimTransition:
    claim_lineage_id: str
    economic_claim_key: str
    initial_claim_root_fact_id: str
    group_id: str
    group_fingerprint: str
    identity_fingerprint: str
    canonical_event_fact_id: str
    canonical_event_fact_fingerprint: str
    event_concept: str
    legal_effective_date: str
    canonical_share_magnitude: str
    affected_claim_root_fact_id: str
    affected_claim_root_fact_fingerprint: str
    affected_claim_value: str
    affected_claim_root_fact: Fact
    affected_claim_source_document: SourceDocument
    remaining_claim_fact_id: str
    remaining_claim_fact_fingerprint: str
    remaining_claim_value: str
    remaining_claim_fact: Fact
    remaining_claim_source_document: SourceDocument
    evidence_facts: tuple[Fact, ...]
    evidence_source_documents: tuple[SourceDocument, ...]
    claims: tuple[Claim, ...]
    candidates: tuple[AnalyticalClaimCandidate, ...]
    review_decisions: tuple[AnalyticalClaimReviewDecision, ...]
    claim_bindings: tuple[tuple[str, str], ...]
    candidate_bindings: tuple[tuple[str, str], ...]
    review_decision_bindings: tuple[tuple[str, str], ...]
    disposition: str
    transition_fingerprint: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.claim_lineage_id, "claim lineage ID"),
            (self.economic_claim_key, "economic claim key"),
            (self.initial_claim_root_fact_id, "initial claim root Fact ID"),
            (self.group_id, "transition group ID"),
            (self.affected_claim_root_fact_id, "affected claim Fact ID"),
            (self.remaining_claim_fact_id, "remaining claim Fact ID"),
        ):
            _nonempty(value, label)
        _sha(self.economic_claim_key, "economic claim key")
        for value, label in (
            (self.group_fingerprint, "transition group fingerprint"),
            (self.identity_fingerprint, "transition identity fingerprint"),
            (self.canonical_event_fact_fingerprint, "transition canonical Fact fingerprint"),
            (self.affected_claim_root_fact_fingerprint, "affected claim Fact fingerprint"),
            (self.remaining_claim_fact_fingerprint, "remaining claim Fact fingerprint"),
        ):
            _sha(value, label)
        if self.event_concept in SPECIALIST_REQUIRED_CLAIM_TRANSITION_EVENT_CONCEPTS:
            raise ValueError(
                "claim-transition event requires specialist authority outside frozen Phase 5C"
            )
        if self.event_concept not in STANDARD_CLAIM_TRANSITION_EVENT_CONCEPTS:
            raise ValueError("group-bound transition event is not claim-sensitive")
        effective = _date(self.legal_effective_date, "claim-transition effective date")
        canonical = _integer_decimal(
            self.canonical_share_magnitude,
            "transition canonical share magnitude",
            positive=True,
        )
        affected = _integer_decimal(self.affected_claim_value, "affected claim value")
        remaining = _integer_decimal(self.remaining_claim_value, "remaining claim value")
        if affected - remaining != canonical:
            raise ValueError("group-bound claim-transition arithmetic does not replay")
        if self.disposition == "extinguished":
            if remaining != 0:
                raise ValueError("extinguished claim transition retains a claim")
        elif self.disposition == "remaining_claim_rebound":
            if remaining <= 0:
                raise ValueError("remaining-claim transition has no remaining claim")
        else:
            raise ValueError("group-bound claim-transition disposition is invalid")
        expected_fact_id = f"derived:share-event:{self.identity_fingerprint[:24]}"
        if self.canonical_event_fact_id != expected_fact_id:
            raise ValueError("claim transition is not bound to the reserved canonical Fact")
        expected_remaining_fact_id = _remaining_claim_fact_id(
            issuer_id=self.affected_claim_root_fact.issuer_id,
            economic_claim_key=self.economic_claim_key,
            group_id=self.group_id,
            affected_claim_root_fact_id=self.affected_claim_root_fact_id,
            legal_effective_date=self.legal_effective_date,
        )
        if self.remaining_claim_fact_id != expected_remaining_fact_id:
            raise ValueError("remaining claim Fact ID is not deterministic")
        expected_lineage_id = (
            "claim-lineage:"
            + canonical_sha256(
                {
                    "issuer_id": self.affected_claim_root_fact.issuer_id,
                    "security_root_fact_id": self.initial_claim_root_fact_id,
                }
            )[:24]
        )
        if self.claim_lineage_id != expected_lineage_id:
            raise ValueError("claim-transition lineage ID is not deterministic")
        affected_fact = self.affected_claim_root_fact
        remaining_fact = self.remaining_claim_fact
        affected_source = self.affected_claim_source_document
        remaining_source = self.remaining_claim_source_document
        is_initial_transition = affected_fact.fact_id == self.initial_claim_root_fact_id
        expected_affected_concept = (
            CLAIM_ROOT_CONCEPT_BY_EVENT[self.event_concept]
            if is_initial_transition
            else CLAIM_SENSITIVE_EVENT_CONCEPTS[self.event_concept]
        )
        affected_derivation_is_valid = (
            affected_fact.derivation is None and not affected_fact.parent_fact_ids
            if is_initial_transition
            else affected_fact.derivation == CLAIM_TRANSITION_DERIVATION
            and len(affected_fact.parent_fact_ids) == 2
        )
        if (
            affected_fact.fact_id != self.affected_claim_root_fact_id
            or affected_fact.fingerprint != self.affected_claim_root_fact_fingerprint
            or remaining_fact.fact_id != self.remaining_claim_fact_id
            or remaining_fact.fingerprint != self.remaining_claim_fact_fingerprint
            or affected_fact.issuer_id != remaining_fact.issuer_id
            or affected_fact.value_type != "number"
            or remaining_fact.value_type != "number"
            or affected_fact.concept != expected_affected_concept
            or remaining_fact.concept != CLAIM_SENSITIVE_EVENT_CONCEPTS[self.event_concept]
            or affected_fact.unit != "shares"
            or remaining_fact.unit != "shares"
            or affected_fact.currency is not None
            or remaining_fact.currency is not None
            or affected_fact.source_document_id != affected_source.document_id
            or remaining_fact.source_document_id != remaining_source.document_id
            or remaining_fact.source_document_id != affected_fact.source_document_id
            or remaining_source != affected_source
            or affected_source.issuer_id != affected_fact.issuer_id
            or remaining_source.issuer_id != affected_fact.issuer_id
            or affected_source.authority_level not in OFFICIAL_AUTHORITY_LEVELS
            or remaining_source.authority_level not in OFFICIAL_AUTHORITY_LEVELS
            or affected_fact.confidence != "high"
            or remaining_fact.confidence != "high"
            or _fact_share_integer(affected_fact.value, "affected claim Fact value") != affected
            or _fact_share_integer(remaining_fact.value, "remaining claim Fact value")
            != remaining
            or affected_fact.period.get("end") is None
            or affected_fact.period.get("start") is not None
            or remaining_fact.period.get("start") is not None
            or remaining_fact.period.get("end") != self.legal_effective_date
            or _date(str(affected_fact.period["end"]), "affected claim Fact date") > effective
            or not affected_derivation_is_valid
            or remaining_fact.derivation != CLAIM_TRANSITION_DERIVATION
            or remaining_fact.source_locator
            != _claim_transition_source_locator(self.remaining_claim_fact_id)
            or remaining_fact.parent_fact_ids
            != tuple(
                sorted(
                    (
                        self.affected_claim_root_fact_id,
                        self.canonical_event_fact_id,
                    )
                )
            )
        ):
            raise ValueError("claim transition does not bind authoritative claim Facts")
        claims = tuple(sorted(self.claims, key=lambda item: item.claim_id))
        candidates = tuple(sorted(self.candidates, key=lambda item: item.candidate_id))
        decisions = tuple(sorted(self.review_decisions, key=lambda item: item.decision_id))
        evidence_facts = tuple(sorted(self.evidence_facts, key=lambda item: item.fact_id))
        evidence_sources = tuple(
            sorted(self.evidence_source_documents, key=lambda item: item.document_id)
        )
        if len(claims) != 1 or len(candidates) != 1 or len(decisions) != 1:
            raise ValueError(
                "claim transition requires exactly one Candidate, Decision, and Claim"
            )
        claim_by_id = {item.claim_id: item for item in claims}
        candidate_by_id = {item.candidate_id: item for item in candidates}
        decision_by_id = {item.decision_id: item for item in decisions}
        evidence_fact_by_id = {item.fact_id: item for item in evidence_facts}
        evidence_source_by_id = {item.document_id: item for item in evidence_sources}
        if (
            len(claim_by_id) != len(claims)
            or len(candidate_by_id) != len(candidates)
            or len(decision_by_id) != len(decisions)
            or len(evidence_fact_by_id) != len(evidence_facts)
            or len(evidence_source_by_id) != len(evidence_sources)
        ):
            raise ValueError("claim transition repeats a reviewed analytical object")
        object.__setattr__(
            self,
            "claim_bindings",
            _bindings(self.claim_bindings, "transition Claims", allow_empty=False),
        )
        object.__setattr__(
            self,
            "candidate_bindings",
            _bindings(self.candidate_bindings, "transition Candidates", allow_empty=False),
        )
        object.__setattr__(
            self,
            "review_decision_bindings",
            _bindings(
                self.review_decision_bindings,
                "transition ReviewDecisions",
                allow_empty=False,
            ),
        )
        if (
            self.claim_bindings
            != tuple(sorted((item.claim_id, item.fingerprint) for item in claims))
            or self.candidate_bindings
            != tuple(sorted((item.candidate_id, item.fingerprint) for item in candidates))
            or self.review_decision_bindings
            != tuple(sorted((item.decision_id, item.fingerprint) for item in decisions))
        ):
            raise ValueError("claim transition reviewed bindings do not match typed objects")
        if (
            {item.candidate_id for item in decisions} != set(candidate_by_id)
            or {str(item.output_claim_id) for item in decisions} != set(claim_by_id)
            or len(decisions) != len(candidates)
            or len(decisions) != len(claims)
        ):
            raise ValueError("claim transition review chain is not one-to-one")
        required_support = {
            self.affected_claim_root_fact_id,
            self.remaining_claim_fact_id,
        }
        for decision in decisions:
            candidate = candidate_by_id.get(decision.candidate_id)
            if candidate is None or decision.output_claim_id not in claim_by_id:
                raise ValueError("claim transition Decision lacks its Candidate or Claim")
            claim = claim_by_id[str(decision.output_claim_id)]
            candidate_support = set(
                _direct_binding_fact_ids(
                    candidate.supporting_evidence_bindings,
                    "claim-transition supporting evidence",
                )
            )
            candidate_counterevidence = set(
                _direct_binding_fact_ids(
                    candidate.counterevidence_bindings,
                    "claim-transition counterevidence",
                )
            )
            all_binding_ids = tuple(
                str(binding["binding_id"])
                for binding in (
                    *candidate.supporting_evidence_bindings,
                    *candidate.counterevidence_bindings,
                )
            )
            expected_evidence_sha = canonical_sha256(
                {
                    "supporting_evidence_bindings": candidate.supporting_evidence_bindings,
                    "counterevidence_bindings": candidate.counterevidence_bindings,
                }
            )
            candidate_date = _date(
                candidate.as_of_date,
                "claim-transition Candidate date",
            )
            claim_date = _date(claim.as_of_date, "claim-transition Claim date")
            reviewed_at = _utc_datetime(
                decision.reviewed_at,
                "claim-transition review time",
            )
            candidate_evidence_ids = candidate_support | candidate_counterevidence
            candidate_evidence_facts = tuple(
                evidence_fact_by_id.get(identifier) for identifier in candidate_evidence_ids
            )
            if any(item is None for item in candidate_evidence_facts):
                raise ValueError("claim transition analytical evidence Fact is missing")
            typed_candidate_evidence_facts = tuple(
                item for item in candidate_evidence_facts if item is not None
            )
            if (
                candidate.issuer_id != affected_fact.issuer_id
                or candidate.claim_role != "support"
                or candidate.business_attribute_role is not None
                or candidate.business_component_type is not None
                or to_json_value(candidate.scope) != _issuer_wide_analytical_scope()
                or candidate.validation_status != "ready"
                or candidate.validation_issues
                or candidate.evidence_graph_sha256 != expected_evidence_sha
                or len(all_binding_ids) != len(set(all_binding_ids))
                or candidate_date < effective
                or decision.issuer_id != affected_fact.issuer_id
                or decision.decision != "confirmed"
                or decision.issues
                or not _is_named_human(decision.reviewer_id)
                or decision.candidate_id != candidate.candidate_id
                or decision.candidate_fingerprint != candidate.fingerprint
                or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
                or reviewed_at.date() < candidate_date
                or claim.issuer_id != affected_fact.issuer_id
                or decision.output_claim_id != claim.claim_id
                or claim.statement != candidate.proposed_statement
                or claim_date != candidate_date
                or self.economic_claim_key not in claim.statement
                or set(claim.supporting_fact_ids) != candidate_support
                or set(claim.counterevidence_fact_ids) != candidate_counterevidence
                or not required_support.issubset(candidate_support)
                or claim.counterevidence_search_note
                != candidate.counterevidence_search_note
                or claim.confidence != candidate.proposed_confidence
                or claim.falsification_condition != candidate.falsification_condition
                or not candidate.counterevidence_search_note
                or not candidate.falsification_condition
                or any(
                    fact.issuer_id != affected_fact.issuer_id
                    or fact.confidence != "high"
                    or fact.period.get("end") is None
                    or _date(
                        str(fact.period["end"]),
                        "claim-transition evidence Fact date",
                    )
                    > candidate_date
                    or fact.source_document_id not in evidence_source_by_id
                    or evidence_source_by_id[fact.source_document_id].issuer_id
                    != affected_fact.issuer_id
                    or evidence_source_by_id[fact.source_document_id].authority_level
                    not in OFFICIAL_AUTHORITY_LEVELS
                    or _date(
                        evidence_source_by_id[fact.source_document_id].published_date,
                        "claim-transition evidence source date",
                    )
                    > candidate_date
                    for fact in typed_candidate_evidence_facts
                )
            ):
                raise ValueError("claim transition analytical review chain is invalid")
        expected_evidence_ids = {
            identifier
            for candidate in candidates
            for identifier in (
                *_direct_binding_fact_ids(
                    candidate.supporting_evidence_bindings,
                    "claim-transition supporting evidence",
                ),
                *_direct_binding_fact_ids(
                    candidate.counterevidence_bindings,
                    "claim-transition counterevidence",
                ),
            )
        }
        expected_source_ids = {
            evidence_fact_by_id[identifier].source_document_id
            for identifier in expected_evidence_ids
        }
        if (
            set(evidence_fact_by_id) != expected_evidence_ids
            or set(evidence_source_by_id) != expected_source_ids
        ):
            raise ValueError("claim transition analytical evidence closure is not exact")
        object.__setattr__(self, "evidence_facts", evidence_facts)
        object.__setattr__(self, "evidence_source_documents", evidence_sources)
        object.__setattr__(self, "claims", claims)
        object.__setattr__(self, "candidates", candidates)
        object.__setattr__(self, "review_decisions", decisions)
        _sha(self.transition_fingerprint, "claim-transition fingerprint")
        if self.transition_fingerprint != self.expected_fingerprint():
            raise ValueError("claim-transition fingerprint mismatch")

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("transition_fingerprint")
        return payload

    def expected_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


def _phase5c_economic_claim_key(*, issuer_id: str, binding: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "policy_id": PHASE5C_POLICY_ID,
            "policy_version": PHASE5C_POLICY_VERSION,
            "issuer_id": issuer_id,
            "identity_kind": binding["identity_kind"],
            "identity_value": binding["identity_value"],
            "scope_id": binding["scope_id"],
            "measurement_end": binding["measurement_end"],
            "security_class": binding["security_class"],
        }
    )


def _phase5c_economic_claim_statement(binding: dict[str, Any]) -> str:
    semantic_sha = canonical_sha256(
        {
            "economic_identity": binding["economic_identity"],
            "identity_kind": binding["identity_kind"],
            "identity_value": binding["identity_value"],
            "scope_id": binding["scope_id"],
            "measurement_end": binding["measurement_end"],
            "security_class": binding["security_class"],
            "root_fact_ids": binding["root_fact_ids"],
            "identity_evidence_fact_ids": binding["identity_evidence_fact_ids"],
            "diluted_share_treatment": binding["diluted_share_treatment"],
            "diluted_share_fact_ids": binding["diluted_share_fact_ids"],
        }
    )
    return f"Reviewed Phase 5C economic-claim identity {semantic_sha}."


def _artifact_phase5c_claim_records(
    artifact: PriceBlindInputArtifact,
) -> tuple[dict[str, Any], list[Any], dict[str, list[dict[str, Any]]]]:
    artifact_payload = artifact.to_dict()
    readiness = artifact_payload.get("phase5c_readiness")
    bridge = readiness.get("equity_bridge_result") if isinstance(readiness, dict) else None
    method_view = bridge.get("method_view_result") if isinstance(bridge, dict) else None
    reconciliation = (
        method_view.get("reconciliation_result") if isinstance(method_view, dict) else None
    )
    bindings = (
        reconciliation.get("economic_claim_bindings")
        if isinstance(reconciliation, dict)
        else None
    )
    records = bridge.get("consumption_records") if isinstance(bridge, dict) else None
    typed = {
        field: reconciliation.get(field)
        for field in (
            "economic_claim_candidates",
            "economic_claim_review_decisions",
            "economic_claims",
        )
    } if isinstance(reconciliation, dict) else {}
    if (
        not isinstance(bridge, dict)
        or not isinstance(bindings, list)
        or not isinstance(records, list)
        or any(not isinstance(value, list) for value in typed.values())
    ):
        raise ValueError("frozen reviewed economic-claim evidence is unavailable")
    if any(not isinstance(item, dict) or not item.get("binding_id") for item in bindings):
        raise ValueError("Phase 5C economic-claim bindings are not closed")
    binding_ids = [str(item["binding_id"]) for item in bindings]
    if len(binding_ids) != len(set(binding_ids)):
        raise ValueError("Phase 5C economic-claim binding IDs are duplicated")
    bound_root_ids = [
        str(root_id)
        for binding in bindings
        for root_id in binding.get("root_fact_ids", ())
    ]
    if len(bound_root_ids) != len(set(bound_root_ids)):
        raise ValueError("Phase 5C economic-claim roots are bound more than once")
    typed_id_fields = {
        "economic_claim_candidates": "candidate_id",
        "economic_claim_review_decisions": "decision_id",
        "economic_claims": "claim_id",
    }
    typed_ids: dict[str, set[str]] = {}
    for field, id_field in typed_id_fields.items():
        values = typed[field]
        if any(not isinstance(item, dict) or not item.get(id_field) for item in values):
            raise ValueError(f"Phase 5C {field} payload is not closed")
        identifiers = [str(item[id_field]) for item in values]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError(f"Phase 5C {field} contains duplicate IDs")
        typed_ids[field] = set(identifiers)
    binding_reference_fields = {
        "economic_claim_candidates": "candidate_id",
        "economic_claim_review_decisions": "review_decision_id",
        "economic_claims": "claim_id",
    }
    for binding in bindings:
        status = binding.get("status")
        candidate_id = binding.get("candidate_id")
        decision_id = binding.get("review_decision_id")
        claim_id = binding.get("claim_id")
        if (
            not isinstance(candidate_id, str)
            or not candidate_id
            or not isinstance(decision_id, str)
            or not decision_id
            or (
                status == "confirmed"
                and (
                    not isinstance(claim_id, str)
                    or not claim_id
                    or binding.get("economic_claim_key")
                    != _phase5c_economic_claim_key(
                        issuer_id=str(artifact_payload["issuer_id"]),
                        binding=binding,
                    )
                    or bool(binding.get("missing_evidence"))
                    or bool(binding.get("reason_codes"))
                )
            )
            or (
                status == "blocked"
                and (
                    claim_id is not None
                    or binding.get("economic_claim_key") is not None
                    or not binding.get("missing_evidence")
                    or "economic_claim_identity_unresolved"
                    not in binding.get("reason_codes", ())
                )
            )
            or status not in {"confirmed", "blocked"}
        ):
            raise ValueError("Phase 5C binding must preserve its review chain")
    referenced_ids: dict[str, set[str]] = {}
    for field, reference_field in binding_reference_fields.items():
        raw_identifiers = [
            item.get(reference_field)
            for item in bindings
            if item.get(reference_field) is not None
        ]
        if any(
            not isinstance(identifier, str) or not identifier
            for identifier in raw_identifiers
        ):
            raise ValueError("Phase 5C review binding references are not closed")
        identifiers = [str(identifier) for identifier in raw_identifiers]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Phase 5C review binding references are duplicated")
        referenced_ids[field] = set(identifiers)
    if typed_ids != referenced_ids:
        raise ValueError("Phase 5C review objects do not exactly match economic-claim bindings")
    root_claim_bindings: dict[str, tuple[str, str]] = {}
    confirmed_claim_keys: set[str] = set()
    for binding in bindings:
        roots = binding.get("root_fact_ids")
        claim_key = binding.get("economic_claim_key")
        economic_identity = binding.get("economic_identity")
        if (
            not isinstance(roots, list)
            or not roots
            or len(roots) != len(set(roots))
            or any(not isinstance(root_id, str) or not root_id for root_id in roots)
            or binding.get("status") not in {"confirmed", "blocked"}
        ):
            raise ValueError("Phase 5C economic-claim root bindings are not closed")
        if binding["status"] != "confirmed":
            if claim_key is not None:
                raise ValueError("blocked Phase 5C binding cannot authorize consumption")
            continue
        if (
            not isinstance(claim_key, str)
            or not claim_key
            or not isinstance(economic_identity, str)
            or not economic_identity
            or claim_key in confirmed_claim_keys
        ):
            raise ValueError("Phase 5C confirmed economic-claim identity is ambiguous")
        confirmed_claim_keys.add(claim_key)
        for root_id in roots:
            if root_id in root_claim_bindings:
                raise ValueError("Phase 5C economic-claim root is bound more than once")
            root_claim_bindings[root_id] = (claim_key, economic_identity)
    consumption_fields = {
        "root_fact_id",
        "economic_claim_key",
        "economic_identity",
        "channel",
        "method",
        "group_id",
        "consumption_kind",
    }
    if any(
        not isinstance(item, dict)
        or set(item) != consumption_fields
        or any(not item[field] for field in consumption_fields)
        for item in records
    ):
        raise ValueError("Phase 5C consumption record fields are not closed")
    consumption_keys = [
        tuple(item[field] for field in sorted(consumption_fields)) for item in records
    ]
    if len(consumption_keys) != len(set(consumption_keys)):
        raise ValueError("Phase 5C consumption records contain duplicate economic treatment")
    nonvalidation_treatments: dict[tuple[str, str], set[tuple[str, str, str]]] = {}
    for item in records:
        if item["method"] not in {"mckinsey", "penman"} or item[
            "consumption_kind"
        ] not in {"validation", "economic_deduction", "method_base"}:
            raise ValueError("Phase 5C consumption record semantics are invalid")
        if item["consumption_kind"] != "validation":
            nonvalidation_treatments.setdefault(
                (str(item["method"]), str(item["economic_claim_key"])),
                set(),
            ).add(
                (
                    str(item["channel"]),
                    str(item["group_id"]),
                    str(item["consumption_kind"]),
                )
            )
        expected_claim = root_claim_bindings.get(str(item["root_fact_id"]))
        if expected_claim != (
            str(item["economic_claim_key"]),
            str(item["economic_identity"]),
        ):
            raise ValueError("Phase 5C consumption record lacks its exact reviewed binding")
    if any(len(treatments) > 1 for treatments in nonvalidation_treatments.values()):
        raise ValueError("Phase 5C economic claim is consumed more than once by one method")
    return bridge, bindings, typed


def _phase5c_review_object_bindings(
    *,
    artifact: PriceBlindInputArtifact,
    graph: ContractGraph,
) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str, str], ...]]:
    bridge, bindings, artifact_typed = _artifact_phase5c_claim_records(artifact)
    facts = {item.fact_id: item for item in graph.facts}
    documents = {item.document_id: item for item in graph.documents}
    candidates = {item.candidate_id: item for item in graph.analytical_claim_candidates}
    decisions = {
        item.decision_id: item for item in graph.analytical_claim_review_decisions
    }
    claims = {item.claim_id: item for item in graph.claims}
    artifact_candidates = {
        str(item["candidate_id"]): item
        for item in artifact_typed["economic_claim_candidates"]
    }
    artifact_decisions = {
        str(item["decision_id"]): item
        for item in artifact_typed["economic_claim_review_decisions"]
    }
    artifact_claims = {
        str(item["claim_id"]): item for item in artifact_typed["economic_claims"]
    }
    cutoff = _date(artifact.to_dict()["data_cutoff_date"], "price-blind cutoff")
    issuer_id = str(artifact.to_dict()["issuer_id"])
    root_bindings: dict[str, str] = {}
    bound_objects: dict[tuple[str, str], Any] = {}

    def bind(contract_type: str, object_id: str, item: Any) -> None:
        prior = bound_objects.setdefault((contract_type, object_id), item)
        if prior != item:
            raise ValueError("Phase 5C authority object identity is ambiguous")

    for identifier, payload in artifact_candidates.items():
        item = candidates.get(identifier)
        if item is None or item.to_dict() != payload:
            raise ValueError("Phase 5C Candidate payload is not graph-owned")
        bind("AnalyticalClaimCandidate", identifier, item)
    for identifier, payload in artifact_decisions.items():
        item = decisions.get(identifier)
        if item is None or item.to_dict() != payload:
            raise ValueError("Phase 5C Decision payload is not graph-owned")
        bind("AnalyticalClaimReviewDecision", identifier, item)
    for identifier, payload in artifact_claims.items():
        item = claims.get(identifier)
        if item is None or item.to_dict() != payload:
            raise ValueError("Phase 5C Claim payload is not graph-owned")
        bind("Claim", identifier, item)

    issuer_scope = {
        "scope_type": "issuer_wide",
        "segment_definition_ids": [],
        "business_unit": None,
        "product_service": None,
        "geography": None,
        "customer_group": None,
        "channel": None,
    }
    for binding in bindings:
        required_fact_ids = {
            *binding["root_fact_ids"],
            *binding["identity_evidence_fact_ids"],
            *binding["diluted_share_fact_ids"],
        }
        if not required_fact_ids.issubset(facts):
            raise ValueError("Phase 5C binding evidence is outside ContractGraph")
        root_facts = [facts[root_id] for root_id in binding["root_fact_ids"]]
        root_policies = [ACCOUNT_CONCEPT_POLICIES.get(fact.concept) for fact in root_facts]
        if any(policy is None for policy in root_policies):
            raise ValueError("Phase 5C binding root concept is not registered")
        expected_identities = {
            policy.bridge_role or "method_base" for policy in root_policies if policy is not None
        }
        permitted_identity_kinds = PHASE5C_ECONOMIC_IDENTITY_KINDS.get(
            binding["economic_identity"]
        )
        if (
            expected_identities != {binding["economic_identity"]}
            or permitted_identity_kinds is None
            or binding["identity_kind"] not in permitted_identity_kinds
            or any(fact.period.get("start") is not None for fact in root_facts)
            or {fact.period.get("end") for fact in root_facts}
            != {binding["measurement_end"]}
        ):
            raise ValueError("Phase 5C binding identity conflicts with its root Facts")
        treatment = binding["diluted_share_treatment"]
        if binding["economic_identity"] == "option_or_dilution_claim":
            if treatment in {"included", "excluded"}:
                if len(binding["diluted_share_fact_ids"]) != 1:
                    raise ValueError("option claim requires reviewed diluted-share evidence")
            elif treatment == "not_applicable":
                if binding["diluted_share_fact_ids"]:
                    raise ValueError(
                        "not-applicable dilution treatment cannot cite share Facts"
                    )
            elif treatment != "blocked" or not binding["missing_evidence"]:
                raise ValueError("option claim dilution treatment is not closed")
        elif treatment != "not_applicable" or binding["diluted_share_fact_ids"]:
            raise ValueError("ordinary economic claims cannot carry dilution treatment")
        candidate = candidates[str(binding["candidate_id"])]
        decision = decisions[str(binding["review_decision_id"])]
        expected_support = required_fact_ids
        candidate_support = {
            str(item["fact_id"])
            for item in candidate.supporting_evidence_bindings
            if item["fact_id"] is not None
        }
        counterevidence_fact_ids = {
            str(item["fact_id"])
            for item in candidate.counterevidence_bindings
            if item["fact_id"] is not None
        }
        if not counterevidence_fact_ids.issubset(facts):
            raise ValueError("Phase 5C counterevidence is outside ContractGraph")
        required_facts = [facts[fact_id] for fact_id in required_fact_ids]
        counterevidence_facts = [facts[fact_id] for fact_id in counterevidence_fact_ids]
        try:
            required_sources = {
                fact.source_document_id: documents[fact.source_document_id]
                for fact in required_facts
            }
            counterevidence_sources = {
                fact.source_document_id: documents[fact.source_document_id]
                for fact in counterevidence_facts
            }
        except KeyError as exc:
            raise ValueError("Phase 5C binding source is outside ContractGraph") from exc
        if (
            candidate.issuer_id != issuer_id
            or to_json_value(candidate.scope) != issuer_scope
            or candidate.claim_role != "support"
            or candidate.proposed_statement != _phase5c_economic_claim_statement(binding)
            or candidate.business_attribute_role is not None
            or candidate.business_component_type is not None
            or candidate.validation_status != "ready"
            or candidate.validation_issues
            or candidate_support != expected_support
            or any(
                item["calculation_result_id"] is not None
                or item["context_observation_id"] is not None
                for item in candidate.supporting_evidence_bindings
            )
            or _date(candidate.as_of_date, "economic-claim Candidate as-of") > cutoff
            or not candidate.counterevidence_search_note
            or not candidate.falsification_condition
            or any(fact.issuer_id != issuer_id for fact in required_facts)
            or any(
                document.issuer_id != issuer_id
                or document.authority_level not in OFFICIAL_AUTHORITY_LEVELS
                or _date(document.published_date, "Phase 5C source date") > cutoff
                for document in required_sources.values()
            )
            or any(fact.issuer_id != issuer_id for fact in counterevidence_facts)
            or any(
                document.issuer_id != issuer_id
                or _date(document.published_date, "Phase 5C counterevidence source date")
                > cutoff
                for document in counterevidence_sources.values()
            )
            or decision.issuer_id != issuer_id
            or decision.candidate_id != candidate.candidate_id
            or decision.candidate_fingerprint != candidate.fingerprint
            or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
            or not _is_named_human(decision.reviewer_id)
            or _utc_datetime(decision.reviewed_at, "economic-claim reviewed_at").date()
            > cutoff
        ):
            raise ValueError("Phase 5C binding review chain does not replay current graph")
        if binding["status"] == "confirmed":
            claim = claims[str(binding["claim_id"])]
            if (
                decision.decision != "confirmed"
                or decision.output_claim_id != claim.claim_id
                or claim.issuer_id != issuer_id
                or claim.statement != candidate.proposed_statement
                or claim.as_of_date != candidate.as_of_date
                or set(claim.supporting_fact_ids) != expected_support
                or set(claim.counterevidence_fact_ids) != counterevidence_fact_ids
                or claim.counterevidence_search_note != candidate.counterevidence_search_note
                or claim.confidence != candidate.proposed_confidence
                or claim.falsification_condition != candidate.falsification_condition
            ):
                raise ValueError("Phase 5C confirmed binding Claim does not replay review chain")
        else:
            if decision.decision != "blocked" or decision.output_claim_id is not None:
                raise ValueError("Phase 5C blocked binding requires a blocked human Decision")
            raise ValueError("blocked Phase 5C binding cannot authorize the standard path")

        for document in (*required_sources.values(), *counterevidence_sources.values()):
            bind("SourceDocument", document.document_id, document)
        for fact in (*required_facts, *counterevidence_facts):
            bind("Fact", fact.fact_id, fact)

        if binding["economic_identity"] == "option_or_dilution_claim":
            option_value = sum(
                (Decimal(str(facts[root_id].value)) for root_id in binding["root_fact_ids"]),
                start=Decimal(0),
            )
            if (
                binding["diluted_share_treatment"] == "not_applicable"
                and option_value != 0
            ):
                raise ValueError(
                    "a positive option claim requires an included or excluded treatment"
                )

    for binding in bindings:
        if (
            not isinstance(binding, dict)
            or binding.get("economic_identity") != "option_or_dilution_claim"
            or binding.get("diluted_share_treatment") != "excluded"
        ):
            continue
        required_fields = {
            "binding_id",
            "economic_identity",
            "identity_kind",
            "identity_value",
            "scope_id",
            "measurement_end",
            "security_class",
            "economic_claim_key",
            "status",
            "root_fact_ids",
            "identity_evidence_fact_ids",
            "diluted_share_treatment",
            "diluted_share_fact_ids",
            "candidate_id",
            "review_decision_id",
            "claim_id",
            "missing_evidence",
            "reason_codes",
        }
        if set(binding) != required_fields:
            raise ValueError("reviewed dilution binding fields are not closed")
        root_ids = binding["root_fact_ids"]
        identity_ids = binding["identity_evidence_fact_ids"]
        diluted_ids = binding["diluted_share_fact_ids"]
        if (
            binding["status"] != "confirmed"
            or binding["identity_kind"] not in {"plan", "program", "aggregate_perimeter"}
            or binding["scope_id"] != f"scope:{issuer_id}:issuer-wide"
            or binding["security_class"] != "common"
            or binding["economic_claim_key"]
            != _phase5c_economic_claim_key(issuer_id=issuer_id, binding=binding)
            or not isinstance(root_ids, list)
            or not root_ids
            or not isinstance(identity_ids, list)
            or not identity_ids
            or not isinstance(diluted_ids, list)
            or len(diluted_ids) != 1
            or binding["missing_evidence"]
            or binding["reason_codes"]
        ):
            raise ValueError("reviewed dilution binding does not replay Phase 5C identity")
        measurement_end = _date(binding["measurement_end"], "economic-claim measurement end")
        required_fact_ids = set(root_ids) | set(identity_ids) | set(diluted_ids)
        try:
            evidence_facts = {identifier: facts[identifier] for identifier in required_fact_ids}
            candidate = candidates[binding["candidate_id"]]
            decision = decisions[binding["review_decision_id"]]
            claim = claims[binding["claim_id"]]
            evidence_sources = {
                fact.source_document_id: documents[fact.source_document_id]
                for fact in evidence_facts.values()
            }
        except KeyError as exc:
            raise ValueError(
                "reviewed Phase 5C authority evidence is outside ContractGraph"
            ) from exc
        if (
            any(
                fact.issuer_id != issuer_id
                or fact.value_type != "number"
                or fact.unit != "shares"
                or fact.currency is not None
                or fact.confidence not in {"high", "medium"}
                or fact.period.get("start") is not None
                or fact.period.get("end") != binding["measurement_end"]
                for fact in evidence_facts.values()
            )
            or any(
                facts[identifier].concept != "option_or_dilution_claim"
                for identifier in root_ids
            )
            or any(facts[identifier].concept != "diluted_shares" for identifier in diluted_ids)
            or any(
                document.issuer_id != issuer_id
                or document.authority_level not in OFFICIAL_AUTHORITY_LEVELS
                or _date(document.published_date, "Phase 5C source date") > cutoff
                for document in evidence_sources.values()
            )
            or measurement_end > cutoff
        ):
            raise ValueError("reviewed Phase 5C Fact or source authority is invalid")
        supporting_fact_ids = {
            str(item["fact_id"])
            for item in candidate.supporting_evidence_bindings
            if item["fact_id"] is not None
        }
        counterevidence_fact_ids = {
            str(item["fact_id"])
            for item in candidate.counterevidence_bindings
            if item["fact_id"] is not None
        }
        if (
            artifact_candidates.get(candidate.candidate_id) != candidate.to_dict()
            or artifact_decisions.get(decision.decision_id) != decision.to_dict()
            or artifact_claims.get(claim.claim_id) != claim.to_dict()
            or candidate.issuer_id != issuer_id
            or candidate.scope["scope_type"] != "issuer_wide"
            or candidate.claim_role != "support"
            or candidate.business_attribute_role is not None
            or candidate.business_component_type is not None
            or candidate.proposed_statement != _phase5c_economic_claim_statement(binding)
            or candidate.validation_status != "ready"
            or candidate.validation_issues
            or supporting_fact_ids != required_fact_ids
            or any(
                item["calculation_result_id"] is not None
                or item["context_observation_id"] is not None
                for item in candidate.supporting_evidence_bindings
            )
            or _date(candidate.as_of_date, "economic-claim Candidate as-of") > cutoff
            or not candidate.counterevidence_search_note
            or not candidate.falsification_condition
            or decision.issuer_id != issuer_id
            or decision.candidate_id != candidate.candidate_id
            or decision.candidate_fingerprint != candidate.fingerprint
            or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
            or decision.decision != "confirmed"
            or decision.output_claim_id != claim.claim_id
            or not _is_named_human(decision.reviewer_id)
            or decision.issues
            or _utc_datetime(decision.reviewed_at, "economic-claim reviewed_at").date() > cutoff
            or claim.issuer_id != issuer_id
            or claim.statement != candidate.proposed_statement
            or claim.as_of_date != candidate.as_of_date
            or set(claim.supporting_fact_ids) != required_fact_ids
            or set(claim.counterevidence_fact_ids) != counterevidence_fact_ids
            or claim.counterevidence_search_note != candidate.counterevidence_search_note
            or claim.confidence != candidate.proposed_confidence
            or claim.falsification_condition != candidate.falsification_condition
        ):
            raise ValueError(
                "reviewed Phase 5C Candidate-to-human-Decision-to-Claim chain is invalid"
            )
        for root_id in root_ids:
            prior_key = root_bindings.setdefault(root_id, binding["economic_claim_key"])
            if prior_key != binding["economic_claim_key"]:
                raise ValueError("one Phase 5C root has multiple reviewed economic identities")
        for document in evidence_sources.values():
            bind("SourceDocument", document.document_id, document)
        for fact in evidence_facts.values():
            bind("Fact", fact.fact_id, fact)
        for identifier in counterevidence_fact_ids:
            try:
                fact = facts[identifier]
                document = documents[fact.source_document_id]
            except KeyError as exc:
                raise ValueError("Phase 5C counterevidence is outside ContractGraph") from exc
            if (
                fact.issuer_id != issuer_id
                or _date(document.published_date, "counterevidence source date") > cutoff
            ):
                raise ValueError("Phase 5C counterevidence crosses issuer or cutoff")
            bind("SourceDocument", document.document_id, document)
            bind("Fact", fact.fact_id, fact)
        bind("AnalyticalClaimCandidate", candidate.candidate_id, candidate)
        bind("AnalyticalClaimReviewDecision", decision.decision_id, decision)
        bind("Claim", claim.claim_id, claim)

    records = bridge["consumption_records"]
    option_role_decisions = [
        item
        for item in bridge.get("role_decisions", [])
        if isinstance(item, dict) and item.get("role") == "option_or_dilution_claim"
    ]
    option_role_root_ids = (
        option_role_decisions[0].get("root_fact_ids")
        if len(option_role_decisions) == 1
        else None
    )
    if (
        len(option_role_decisions) != 1
        or option_role_decisions[0].get("status") != "modeled"
        or not isinstance(option_role_root_ids, list)
        or len(option_role_root_ids) != len(set(option_role_root_ids))
        or set(option_role_root_ids) != set(root_bindings)
    ):
        raise ValueError("Phase 5C option bridge role does not replay reviewed roots")
    for root_id, economic_claim_key in root_bindings.items():
        root_records = [record for record in records if record.get("root_fact_id") == root_id]
        expected_record = {
            "root_fact_id": root_id,
            "economic_claim_key": economic_claim_key,
            "economic_identity": "option_or_dilution_claim",
            "channel": "mckinsey_equity_bridge",
            "method": "mckinsey",
            "group_id": "equity-bridge:option_or_dilution_claim",
            "consumption_kind": "economic_deduction",
        }
        if root_records != [expected_record]:
            raise ValueError("Phase 5C option bridge consumption records do not replay")
    object_bindings = tuple(
        sorted(
            (contract_type, object_id, item.fingerprint)
            for (contract_type, object_id), item in bound_objects.items()
        )
    )
    return tuple(sorted(root_bindings.items())), object_bindings


@dataclass(frozen=True, slots=True)
class GroupBoundDilutionClaimAuthority:
    """Graph-owned full-freeze Phase 5C authority for group-bound transitions."""

    policy_id: str
    policy_version: str
    price_blind_freeze: PriceBlindFreezeCompilationResult
    price_blind_freeze_fingerprint: str
    price_blind_input_fingerprint: str
    component_lock_sha256: str
    research_bundle_id: str
    research_bundle_fingerprint: str
    research_bundle_dependency_sha256: str
    run_manifest_id: str
    handoff_bindings: tuple[tuple[str, str], ...]
    freeze_candidate_bindings: tuple[tuple[str, str], ...]
    freeze_decision_bindings: tuple[tuple[str, str], ...]
    phase5c_authority: Phase5CDilutionClaimAuthority
    phase5c_authority_fingerprint: str
    root_economic_claim_bindings: tuple[tuple[str, str], ...]
    phase5c_review_object_fingerprints: tuple[tuple[str, str, str], ...]
    authority_evidence_closure_sha256: str
    authority_fingerprint: str
    validation_graph: InitVar[ContractGraph]

    def __post_init__(self, validation_graph: ContractGraph) -> None:
        if (self.policy_id, self.policy_version) != (
            GROUP_BOUND_DILUTION_AUTHORITY_POLICY_ID,
            GROUP_BOUND_DILUTION_AUTHORITY_POLICY_VERSION,
        ):
            raise ValueError("group-bound dilution authority policy mismatch")
        if type(self.price_blind_freeze) is not PriceBlindFreezeCompilationResult:
            raise TypeError("group-bound dilution authority requires the exact full freeze")
        if not isinstance(validation_graph, ContractGraph):
            raise TypeError("group-bound dilution authority requires the current ContractGraph")
        try:
            validation_graph.validate()
        except ContractGraphError as exc:
            raise ValueError("group-bound dilution authority ContractGraph is invalid") from exc
        freeze = self.price_blind_freeze
        artifact = freeze.artifact
        if (
            self.price_blind_freeze_fingerprint != freeze.fingerprint
            or self.price_blind_input_fingerprint != artifact.fingerprint
            or self.component_lock_sha256 != file_sha256(validation_graph.component_lock_path)
            or artifact.payload["component_lock_sha256"] != self.component_lock_sha256
        ):
            raise ValueError("group-bound dilution authority changed the current freeze or lock")
        research = artifact.to_dict()["research_bundle"]
        bundles = [
            item
            for item in validation_graph.research_bundles
            if item.bundle_id == research["bundle_id"]
        ]
        manifests = [
            item
            for item in validation_graph.manifests
            if item.run_id == research["run_manifest_id"]
        ]
        if (
            len(bundles) != 1
            or len(manifests) != 1
            or self.research_bundle_id != research["bundle_id"]
            or self.research_bundle_fingerprint != research["bundle_fingerprint"]
            or self.research_bundle_dependency_sha256 != research["dependency_closure_sha256"]
            or self.run_manifest_id != research["run_manifest_id"]
            or bundles[0].bundle_fingerprint != self.research_bundle_fingerprint
            or bundles[0].dependency_closure_sha256 != self.research_bundle_dependency_sha256
            or bundles[0].run_id != self.run_manifest_id
            or manifests[0].issuer_id != artifact.payload["issuer_id"]
            or manifests[0].data_cutoff_date != artifact.payload["data_cutoff_date"]
            or manifests[0].component_lock_sha256 != self.component_lock_sha256
        ):
            raise ValueError("group-bound dilution authority lacks graph-owned Bundle artifacts")
        handoffs = {item.handoff_id: item for item in validation_graph.valuation_handoffs}
        expected_handoff_bindings = tuple(
            sorted((item.handoff_id, item.fingerprint) for item in freeze.handoffs)
        )
        matching_run = tuple(
            item
            for item in validation_graph.valuation_handoffs
            if item.handoff_run_id == freeze.handoffs[0].handoff_run_id
        )
        consumed_authorizations = {
            item.authorization_handoff_id for item in validation_graph.market_reference_snapshots
        }
        if (
            _bindings(self.handoff_bindings, "price-blind Handoff bindings")
            != expected_handoff_bindings
            or any(handoffs.get(item.handoff_id) != item for item in freeze.handoffs)
            or tuple(sorted(matching_run, key=lambda item: item.handoff_version))
            != freeze.handoffs
            or freeze.handoffs[-1].state != "market_reference_allowed"
            or freeze.handoffs[-1].handoff_id in consumed_authorizations
            or not _price_blind_authorization_is_current(validation_graph, freeze)
        ):
            raise ValueError("price-blind Handoff chain is not current and graph-owned")
        graph_candidates = {
            item.candidate_id: item for item in validation_graph.valuation_assumption_candidates
        }
        graph_decisions = {
            item.decision_id: item
            for item in validation_graph.valuation_assumption_review_decisions
        }
        expected_candidate_bindings = tuple(
            sorted((item.candidate_id, item.fingerprint) for item in freeze.candidates)
        )
        expected_decision_bindings = tuple(
            sorted((item.decision_id, item.fingerprint) for item in freeze.decisions)
        )
        if (
            _bindings(self.freeze_candidate_bindings, "freeze Candidate bindings")
            != expected_candidate_bindings
            or _bindings(self.freeze_decision_bindings, "freeze Decision bindings")
            != expected_decision_bindings
            or any(graph_candidates.get(item.candidate_id) != item for item in freeze.candidates)
            or any(graph_decisions.get(item.decision_id) != item for item in freeze.decisions)
        ):
            raise ValueError("price-blind freeze review objects are not graph-owned")
        replayed = Phase5CDilutionClaimAuthority.from_price_blind_artifact(artifact)
        if (
            type(self.phase5c_authority) is not Phase5CDilutionClaimAuthority
            or self.phase5c_authority != replayed
            or self.phase5c_authority_fingerprint != replayed.fingerprint
            or replayed.standard_path_disposition != "eligible"
            or replayed.included_option_root_fact_ids
            or replayed.blocked_option_root_fact_ids
        ):
            raise ValueError("group-bound dilution authority does not replay Phase 5C")
        expected_roots, expected_review_objects = _phase5c_review_object_bindings(
            artifact=artifact,
            graph=validation_graph,
        )
        normalized_roots = tuple(sorted(self.root_economic_claim_bindings))
        reviewed_claim_keys = tuple(claim_key for _, claim_key in normalized_roots)
        if len(reviewed_claim_keys) != len(set(reviewed_claim_keys)):
            # Phase 5C permits one reviewed economic Claim to contain several root Facts, but this
            # validation-only contract has no graph-owned aggregate-balance Fact.  Consuming one
            # component would silently understate the remaining Claim, so the alpha path blocks
            # until a later policy explicitly materializes the complete aggregate lineage.
            raise ValueError(
                "multi-root economic claim lacks one graph-owned aggregate opening balance"
            )
        normalized_review_objects = _objects(
            self.phase5c_review_object_fingerprints,
            "Phase 5C authority review closure",
        )
        if (
            normalized_roots != expected_roots
            or set(dict(normalized_roots)) != set(replayed.excluded_option_root_fact_ids)
            or normalized_review_objects != expected_review_objects
        ):
            raise ValueError("graph-owned Phase 5C authority evidence does not replay")
        object.__setattr__(self, "handoff_bindings", expected_handoff_bindings)
        object.__setattr__(self, "freeze_candidate_bindings", expected_candidate_bindings)
        object.__setattr__(self, "freeze_decision_bindings", expected_decision_bindings)
        object.__setattr__(self, "root_economic_claim_bindings", normalized_roots)
        object.__setattr__(
            self,
            "phase5c_review_object_fingerprints",
            normalized_review_objects,
        )
        expected_closure = self.expected_evidence_closure_sha256()
        _sha(self.authority_evidence_closure_sha256, "Phase 5C authority closure SHA")
        if self.authority_evidence_closure_sha256 != expected_closure:
            raise ValueError("Phase 5C authority evidence closure mismatch")
        _sha(self.authority_fingerprint, "group-bound dilution authority fingerprint")
        if self.authority_fingerprint != self.expected_fingerprint():
            raise ValueError("group-bound dilution authority fingerprint mismatch")

    @classmethod
    def from_price_blind_freeze(
        cls,
        *,
        freeze: PriceBlindFreezeCompilationResult,
        validation_graph: ContractGraph,
    ) -> GroupBoundDilutionClaimAuthority:
        if type(freeze) is not PriceBlindFreezeCompilationResult:
            raise TypeError("group-bound dilution authority requires the exact full freeze")
        artifact = freeze.artifact
        replayed = Phase5CDilutionClaimAuthority.from_price_blind_artifact(artifact)
        root_bindings, review_objects = _phase5c_review_object_bindings(
            artifact=artifact,
            graph=validation_graph,
        )
        research = artifact.to_dict()["research_bundle"]
        values = {
            "policy_id": GROUP_BOUND_DILUTION_AUTHORITY_POLICY_ID,
            "policy_version": GROUP_BOUND_DILUTION_AUTHORITY_POLICY_VERSION,
            "price_blind_freeze": freeze,
            "price_blind_freeze_fingerprint": freeze.fingerprint,
            "price_blind_input_fingerprint": artifact.fingerprint,
            "component_lock_sha256": file_sha256(validation_graph.component_lock_path),
            "research_bundle_id": research["bundle_id"],
            "research_bundle_fingerprint": research["bundle_fingerprint"],
            "research_bundle_dependency_sha256": research["dependency_closure_sha256"],
            "run_manifest_id": research["run_manifest_id"],
            "handoff_bindings": tuple(
                sorted((item.handoff_id, item.fingerprint) for item in freeze.handoffs)
            ),
            "freeze_candidate_bindings": tuple(
                sorted((item.candidate_id, item.fingerprint) for item in freeze.candidates)
            ),
            "freeze_decision_bindings": tuple(
                sorted((item.decision_id, item.fingerprint) for item in freeze.decisions)
            ),
            "phase5c_authority": replayed,
            "phase5c_authority_fingerprint": replayed.fingerprint,
            "root_economic_claim_bindings": root_bindings,
            "phase5c_review_object_fingerprints": review_objects,
        }
        closure_payload = {
            key: to_json_value(value)
            for key, value in values.items()
            if key not in {"policy_id", "policy_version"}
        }
        values["authority_evidence_closure_sha256"] = canonical_sha256(closure_payload)
        fingerprint_payload = {
            **values,
            "authority_evidence_closure_sha256": values[
                "authority_evidence_closure_sha256"
            ],
        }
        return cls(
            **values,
            authority_fingerprint=canonical_sha256(fingerprint_payload),
            validation_graph=validation_graph,
        )

    def expected_evidence_closure_sha256(self) -> str:
        payload = self.fingerprint_payload()
        payload.pop("policy_id")
        payload.pop("policy_version")
        payload.pop("authority_evidence_closure_sha256")
        return canonical_sha256(payload)

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("authority_fingerprint")
        return payload

    def expected_fingerprint(self) -> str:
        return canonical_sha256(self.fingerprint_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class GroupBoundClaimTransitionReconciliation:
    issuer_id: str
    security_id: str
    opening_date: str
    quote_date: str
    data_cutoff_date: str
    claim_control_authority: GroupBoundDilutionClaimAuthority | None
    claim_control_authority_fingerprint: str | None
    expected_claim_sensitive_group_ids: tuple[str, ...]
    records: tuple[GroupBoundClaimTransition, ...]
    reconciliation_sha256: str

    def __post_init__(self) -> None:
        _nonempty(self.issuer_id, "transition issuer ID")
        _nonempty(self.security_id, "transition security ID")
        opening = _date(self.opening_date, "transition opening date")
        quote = _date(self.quote_date, "transition quote date")
        cutoff = _date(self.data_cutoff_date, "transition data cutoff")
        if opening >= quote or quote > cutoff:
            raise ValueError("claim-transition reconciliation window is invalid")
        expected = _ids(
            self.expected_claim_sensitive_group_ids,
            "expected claim-sensitive groups",
        )
        records = tuple(
            sorted(
                self.records,
                key=lambda item: (
                    item.claim_lineage_id,
                    item.legal_effective_date,
                    item.group_id,
                ),
            )
        )
        groups = [item.group_id for item in records]
        if sorted(groups) != list(expected) or len(groups) != len(set(groups)):
            raise ValueError("claim-sensitive groups are not transitioned exactly once")
        if not records:
            if self.claim_control_authority is not None or self.claim_control_authority_fingerprint:
                raise ValueError("empty transition reconciliation cannot carry claim authority")
            authority_bindings: dict[str, str] = {}
        else:
            if (
                type(self.claim_control_authority) is not GroupBoundDilutionClaimAuthority
                or self.claim_control_authority_fingerprint
                != self.claim_control_authority.authority_fingerprint
            ):
                raise ValueError(
                    "claim-transition reconciliation lacks graph-owned full-freeze "
                    "Phase 5C authority"
                )
            authority_bindings = dict(self.claim_control_authority.root_economic_claim_bindings)
        by_lineage: dict[str, list[GroupBoundClaimTransition]] = {}
        affected_roots: set[str] = set()
        remaining_nodes: set[str] = set()
        economic_claim_lineages: dict[str, str] = {}
        transition_edges: list[tuple[str, str]] = []
        for item in records:
            effective = _date(item.legal_effective_date, "claim-transition effective date")
            if not opening < effective <= quote:
                raise ValueError("claim transition falls outside the governed window")
            candidate_by_id = {candidate.candidate_id: candidate for candidate in item.candidates}
            claim_by_id = {claim.claim_id: claim for claim in item.claims}
            if any(
                _date(candidate.as_of_date, "claim-transition Candidate date") > cutoff
                or _date(
                    claim_by_id[str(decision.output_claim_id)].as_of_date,
                    "claim-transition Claim date",
                )
                > cutoff
                or _utc_datetime(
                    decision.reviewed_at,
                    "claim-transition review time",
                ).date()
                > cutoff
                for decision in item.review_decisions
                for candidate in (candidate_by_id[decision.candidate_id],)
            ):
                raise ValueError("claim-transition review chain crosses the data cutoff")
            if item.affected_claim_root_fact_id in affected_roots:
                raise ValueError("claim-transition root is consumed more than once")
            if item.remaining_claim_fact_id in remaining_nodes:
                raise ValueError("claim-transition remaining node has multiple predecessors")
            prior_lineage = economic_claim_lineages.get(item.economic_claim_key)
            if prior_lineage is not None and prior_lineage != item.claim_lineage_id:
                raise ValueError("economic claim is transitioned through more than one lineage")
            if item.initial_claim_root_fact_id not in authority_bindings:
                raise ValueError("claim-transition root is outside Phase 5C dilution authority")
            expected_economic_key = authority_bindings[item.initial_claim_root_fact_id]
            if item.economic_claim_key != expected_economic_key:
                raise ValueError("claim-transition economic claim key does not replay")
            affected_roots.add(item.affected_claim_root_fact_id)
            remaining_nodes.add(item.remaining_claim_fact_id)
            economic_claim_lineages[item.economic_claim_key] = item.claim_lineage_id
            transition_edges.append(
                (item.affected_claim_root_fact_id, item.remaining_claim_fact_id)
            )
            for source in (
                item.affected_claim_source_document,
                item.remaining_claim_source_document,
            ):
                if (
                    source.issuer_id != self.issuer_id
                    or _date(source.published_date, "claim source published date") > cutoff
                ):
                    raise ValueError("claim-transition source crosses issuer or cutoff")
                _utc_datetime(source.retrieved_at, "claim source retrieval time")
            by_lineage.setdefault(item.claim_lineage_id, []).append(item)
        for lineage in by_lineage.values():
            if lineage[0].affected_claim_root_fact_id != lineage[0].initial_claim_root_fact_id:
                raise ValueError("claim-transition lineage does not start at its initial root")
            if any(
                item.initial_claim_root_fact_id != lineage[0].initial_claim_root_fact_id
                for item in lineage
            ):
                raise ValueError("claim-transition lineage changes its initial root")
            dates = [item.legal_effective_date for item in lineage]
            if len(dates) != len(set(dates)):
                raise ValueError("claim-transition ordering is ambiguous")
            for prior, current in zip(lineage, lineage[1:], strict=False):
                if (
                    current.affected_claim_root_fact_id != prior.remaining_claim_fact_id
                    or current.affected_claim_root_fact_fingerprint
                    != prior.remaining_claim_fact_fingerprint
                    or current.affected_claim_value != prior.remaining_claim_value
                ):
                    raise ValueError("claim-transition lineage branches instead of chaining")
        adjacency = {parent: child for parent, child in transition_edges}
        for root in adjacency:
            seen: set[str] = set()
            current = root
            while current in adjacency:
                if current in seen:
                    raise ValueError("claim-transition graph contains a cycle")
                seen.add(current)
                current = adjacency[current]
        object.__setattr__(self, "expected_claim_sensitive_group_ids", expected)
        object.__setattr__(self, "records", records)
        _sha(self.reconciliation_sha256, "claim-transition reconciliation SHA")
        if self.reconciliation_sha256 != self.expected_sha256():
            raise ValueError("claim-transition reconciliation SHA mismatch")

    def hash_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("reconciliation_sha256")
        return payload

    def expected_sha256(self) -> str:
        return canonical_sha256(self.hash_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class CurrentShareBundleEvidenceClosure:
    research_bundle: ResearchBundle
    run_manifest: RunManifest
    research_bundle_id: str
    research_bundle_fingerprint: str
    issuer_id: str
    issuer_cik: str
    data_cutoff_date: str
    component_lock_sha256: str
    dependency_closure_sha256: str
    current_share_dependency_closure_sha256: str
    extension_policy_id: str
    extension_policy_version: str
    integration_contract_sha256: str
    integration_policy_sha256: str
    integration_code_sha256: str
    run_manifest_id: str
    security_compilation_result: SecurityIdentityCompilationResult
    security_compilation_fingerprint: str
    grouping_result: ShareEventGroupingResult
    grouping_result_fingerprint: str
    opening_share_fact: Fact
    canonical_event_materializations: tuple[CanonicalShareEventFactMaterialization, ...]
    canonical_event_fact_bindings: tuple[tuple[str, str], ...]
    reserved_output_share_fact_id: str
    claim_control_authority: GroupBoundDilutionClaimAuthority | None
    claim_control_authority_fingerprint: str | None
    source_documents: tuple[SourceDocument, ...]
    base_dependency_object_fingerprints: tuple[tuple[str, str, str], ...]
    extension_root_ids: tuple[str, ...]
    extension_object_fingerprints: tuple[tuple[str, str, str], ...]
    object_fingerprints: tuple[tuple[str, str, str], ...]
    contract_graph_fingerprint: str
    closure_sha256: str
    validation_graph: InitVar[ContractGraph]

    def __post_init__(self, validation_graph: ContractGraph) -> None:
        _nonempty(self.research_bundle_id, "ResearchBundle ID")
        _nonempty(self.run_manifest_id, "RunManifest ID")
        _nonempty(self.issuer_id, "ResearchBundle closure issuer ID")
        _cik(self.issuer_cik, "ResearchBundle closure issuer CIK")
        _date(self.data_cutoff_date, "ResearchBundle closure data cutoff")
        _sha(self.research_bundle_fingerprint, "ResearchBundle fingerprint")
        _sha(self.component_lock_sha256, "ResearchBundle closure component-lock SHA")
        _sha(self.dependency_closure_sha256, "ResearchBundle dependency SHA")
        _sha(
            self.current_share_dependency_closure_sha256,
            "current-share dependency SHA",
        )
        _sha(self.contract_graph_fingerprint, "ContractGraph fingerprint")
        _sha(self.security_compilation_fingerprint, "security compilation fingerprint")
        _sha(self.grouping_result_fingerprint, "grouping result fingerprint")
        _validate_official_occurrence_collision_domain(self.grouping_result.groups)
        materials = tuple(
            sorted(self.canonical_event_materializations, key=lambda item: item.group_id)
        )
        if any(type(item) is not CanonicalShareEventFactMaterialization for item in materials):
            raise ValueError("canonical-event materialization authority is malformed")
        if len(materials) != len({item.group_id for item in materials}):
            raise ValueError("canonical-event materialization authority repeats a group")
        expected_group_ids = tuple(
            sorted(
                group.group_id
                for group in self.grouping_result.groups
                if group.status == "canonical"
            )
        )
        if (
            tuple(item.group_id for item in materials) != expected_group_ids
            or any(item.grouping_result != self.grouping_result for item in materials)
        ):
            raise ValueError("canonical-event materializations do not match grouping")
        canonical_bindings = _bindings(
            self.canonical_event_fact_bindings,
            "reserved canonical-event Facts",
        )
        expected_canonical_bindings = tuple(
            sorted(
                (
                    item.canonical_event_fact_id,
                    item.canonical_event_fact_fingerprint,
                )
                for item in materials
            )
        )
        if canonical_bindings != expected_canonical_bindings:
            raise ValueError(
                "reserved canonical-event Fact bindings do not match deterministic materialization"
            )
        object.__setattr__(self, "canonical_event_materializations", materials)
        object.__setattr__(self, "canonical_event_fact_bindings", canonical_bindings)
        _nonempty(self.reserved_output_share_fact_id, "reserved output-share Fact ID")
        expected_output_fact_id = _reserved_output_share_fact_id(
            issuer_id=self.issuer_id,
            security_id=self.grouping_result.security_id,
            quote_date=self.grouping_result.quote_date,
            opening_share_fact_id=self.opening_share_fact.fact_id,
            grouping_result_fingerprint=self.grouping_result_fingerprint,
        )
        if self.reserved_output_share_fact_id != expected_output_fact_id:
            raise ValueError("reserved output-share Fact ID is not deterministically derived")
        if (
            self.extension_policy_id != CURRENT_SHARE_EXTENSION_POLICY_ID
            or self.extension_policy_version != CURRENT_SHARE_EXTENSION_POLICY_VERSION
        ):
            raise ValueError("current-share extension policy mismatch")
        if (
            self.integration_contract_sha256 != current_share_integration_contract_sha256()
            or self.integration_policy_sha256 != current_share_integration_policy_sha256()
            or self.integration_code_sha256 != current_share_integration_code_sha256()
        ):
            raise ValueError("current-share integration policy or code identity drifted")
        if (
            type(self.security_compilation_result) is not SecurityIdentityCompilationResult
            or self.security_compilation_result.fingerprint != self.security_compilation_fingerprint
            or self.security_compilation_result.status != "eligible"
            or self.security_compilation_result.decision is None
            or self.security_compilation_result.decision.security_id
            != self.grouping_result.security_id
            or self.grouping_result.grouping_fingerprint != self.grouping_result_fingerprint
        ):
            raise ValueError("current-share extension security or grouping identity is invalid")
        if not isinstance(validation_graph, ContractGraph):
            raise ValueError("current-share Bundle closure requires a ContractGraph")
        try:
            validation_graph.validate()
            validate_research_bundle(validation_graph, self.research_bundle)
        except (ContractGraphError, ResearchBundleValidationError) as exc:
            raise ValueError("current-share Bundle closure ContractGraph is invalid") from exc
        _replay_security_identity_compilation(
            graph=validation_graph,
            result=self.security_compilation_result,
        )
        authority = self.claim_control_authority
        if authority is None:
            if self.claim_control_authority_fingerprint is not None:
                raise ValueError("empty Bundle claim authority cannot carry a fingerprint")
        else:
            if (
                type(authority) is not GroupBoundDilutionClaimAuthority
                or self.claim_control_authority_fingerprint != authority.authority_fingerprint
            ):
                raise ValueError("Bundle claim authority identity is invalid")
            replayed_authority = GroupBoundDilutionClaimAuthority.from_price_blind_freeze(
                freeze=authority.price_blind_freeze,
                validation_graph=validation_graph,
            )
            if replayed_authority != authority:
                raise ValueError("Bundle claim authority does not replay its current ContractGraph")
        bundle = self.research_bundle
        manifest = self.run_manifest
        if (
            bundle.bundle_id != self.research_bundle_id
            or bundle.bundle_fingerprint != self.research_bundle_fingerprint
            or bundle.bundle_fingerprint != bundle_payload_sha256(bundle.to_dict())
            or bundle.issuer_id != self.issuer_id
            or bundle.data_cutoff_date != self.data_cutoff_date
            or bundle.component_lock_sha256 != self.component_lock_sha256
            or bundle.dependency_closure_sha256 != self.dependency_closure_sha256
            or bundle.run_id != self.run_manifest_id
            or manifest.run_id != self.run_manifest_id
            or manifest.issuer_id != self.issuer_id
            or manifest.data_cutoff_date != self.data_cutoff_date
            or manifest.component_lock_sha256 != self.component_lock_sha256
            or manifest.output_artifact_hashes.get("research-bundle.json")
            != self.research_bundle_fingerprint
        ):
            raise ValueError("ResearchBundle or RunManifest does not replay")
        base_objects = _objects(
            self.base_dependency_object_fingerprints,
            "ResearchBundle base dependency closure",
        )
        extension_objects = _objects(
            self.extension_object_fingerprints,
            "current-share extension closure",
        )
        objects = _objects(self.object_fingerprints, "current-share Bundle closure")
        extension_roots = _ids(
            self.extension_root_ids,
            "current-share extension roots",
            allow_empty=False,
        )
        if not objects:
            raise ValueError("current-share Bundle closure is empty")
        if set(base_objects).intersection(extension_objects):
            raise ValueError("current-share extension duplicates a ResearchBundle dependency")
        if set(objects) != set(base_objects) | set(extension_objects):
            raise ValueError("current-share closure is not base plus governed extension")
        expected_graph_fingerprint = _scoped_contract_graph_fingerprint(
            validation_graph,
            objects,
        )
        if self.contract_graph_fingerprint != expected_graph_fingerprint:
            raise ValueError("current-share scoped ContractGraph fingerprint mismatch")
        expected_dependency = dependency_closure_sha256(list(objects))
        if self.current_share_dependency_closure_sha256 != expected_dependency:
            raise ValueError("current-share dependency SHA does not bind the exact object set")
        registry = _graph_registry(validation_graph)
        closure_filing_artifacts = tuple(
            registry[(contract_type, object_id)]
            for contract_type, object_id, _fingerprint in objects
            if contract_type == "FilingArtifact"
        )
        if (
            not closure_filing_artifacts
            or {item.cik for item in closure_filing_artifacts} != {self.issuer_cik}
            or any(
                item.issuer_id != self.issuer_id
                or _date(item.filing_date, "issuer FilingArtifact date")
                > _date(self.data_cutoff_date, "ResearchBundle closure cutoff")
                or _date(item.report_period, "issuer FilingArtifact report period")
                > _date(self.data_cutoff_date, "ResearchBundle closure cutoff")
                for item in closure_filing_artifacts
            )
        ):
            raise ValueError(
                "current-share Bundle closure lacks one cutoff-safe issuer CIK authority"
            )
        graph_facts = {item.fact_id: item for item in validation_graph.facts}
        graph_opening = graph_facts.get(self.opening_share_fact.fact_id)
        if graph_opening != self.opening_share_fact:
            raise ValueError("opening-share Fact is not byte-bound to the ContractGraph")
        graph_sources = {item.document_id: item for item in validation_graph.documents}
        opening_source = graph_sources.get(self.opening_share_fact.source_document_id)
        if (
            self.opening_share_fact.issuer_id != self.issuer_id
            or self.opening_share_fact.concept != "common_shares_outstanding"
            or self.opening_share_fact.value_type != "number"
            or _fact_share_integer(
                self.opening_share_fact.value,
                "Bundle opening-share Fact value",
                positive=True,
            )
            <= 0
            or self.opening_share_fact.unit != "shares"
            or self.opening_share_fact.currency is not None
            or self.opening_share_fact.period.get("start") is not None
            or self.opening_share_fact.period.get("end") != self.grouping_result.opening_date
            or self.opening_share_fact.derivation is not None
            or self.opening_share_fact.parent_fact_ids
            or self.opening_share_fact.confidence != "high"
            or opening_source is None
            or opening_source.issuer_id != self.issuer_id
            or opening_source.authority_level not in OFFICIAL_AUTHORITY_LEVELS
        ):
            raise ValueError("opening-share Fact is not official high-confidence raw evidence")
        output_id_occupants = tuple(
            (contract_type, item)
            for (contract_type, object_id), item in registry.items()
            if object_id == self.reserved_output_share_fact_id
        )
        if output_id_occupants:
            raise ValueError("reserved output-share Fact ID is already occupied")
        material_by_fact_id = {
            item.canonical_event_fact_id: item for item in materials
        }
        for canonical_fact_id, _canonical_fingerprint in canonical_bindings:
            occupants = tuple(
                (contract_type, item)
                for (contract_type, object_id), item in registry.items()
                if object_id == canonical_fact_id
            )
            if occupants and (
                len(occupants) != 1
                or occupants[0][0] != "Fact"
                or occupants[0][1]
                != material_by_fact_id[canonical_fact_id].canonical_event_fact
            ):
                raise ValueError(
                    "reserved canonical-event Fact ID contains noncanonical graph bytes"
                )
        graph_field_by_type = {
            contract_type: field_name
            for field_name, contract_type in GRAPH_DOMAIN_TYPES.items()
        }
        for contract_type, object_id, fingerprint in base_objects:
            item = registry.get((contract_type, object_id))
            if item is None:
                legacy_matches = tuple(
                    candidate
                    for candidate in getattr(
                        validation_graph,
                        graph_field_by_type[contract_type],
                    )
                    if _object_id(candidate) == object_id
                )
                item = legacy_matches[0] if len(legacy_matches) == 1 else None
            if item is None or item.fingerprint != fingerprint:
                raise ValueError(
                    "current-share Bundle closure object does not resolve in ContractGraph"
                )
        for contract_type, object_id, fingerprint in extension_objects:
            item = registry.get((contract_type, object_id))
            if item is None or item.fingerprint != fingerprint:
                raise ValueError(
                    "current-share extension object does not resolve by its typed identity"
                )
        if authority is not None:
            authority_review_objects = set(authority.phase5c_review_object_fingerprints)
            if (
                authority.component_lock_sha256 != self.component_lock_sha256
                or authority.research_bundle_id != self.research_bundle_id
                or authority.research_bundle_fingerprint != self.research_bundle_fingerprint
                or authority.research_bundle_dependency_sha256 != self.dependency_closure_sha256
                or authority.run_manifest_id != self.run_manifest_id
                or not authority_review_objects.issubset(set(objects))
            ):
                raise ValueError(
                    "Bundle claim authority is outside the exact scoped evidence closure"
                )
        matching_bundles = tuple(
            item
            for item in validation_graph.research_bundles
            if item.bundle_id == self.research_bundle_id
        )
        matching_manifests = tuple(
            item for item in validation_graph.manifests if item.run_id == self.run_manifest_id
        )
        if (
            len(matching_bundles) != 1
            or matching_bundles[0] != self.research_bundle
            or len(matching_manifests) != 1
            or matching_manifests[0] != self.run_manifest
        ):
            raise ValueError("current-share Bundle closure does not use graph-owned artifacts")
        sources = tuple(sorted(self.source_documents, key=lambda item: item.document_id))
        source_bindings = {
            ("SourceDocument", item.document_id, item.fingerprint) for item in sources
        }
        if len(sources) != len({item.document_id for item in sources}):
            raise ValueError("current-share extension SourceDocuments are duplicated")
        if any(
            item.issuer_id != self.issuer_id
            or _date(item.published_date, "Bundle source published date")
            > _date(self.data_cutoff_date, "ResearchBundle closure data cutoff")
            for item in sources
        ):
            raise ValueError("ResearchBundle source crosses issuer or cutoff")
        if not source_bindings.issubset(set(objects)):
            raise ValueError("ResearchBundle source set is not bound by the object closure")
        public_roots = tuple(
            str(object_id)
            for reference in bundle.module_references
            for object_id in reference["object_ids"]
        )
        public_closure = dependency_closure(validation_graph, public_roots)
        expected_base_objects = tuple(
            sorted(
                (contract_type, object_id, item.fingerprint)
                for object_id, (contract_type, item) in public_closure.items()
            )
        )
        if bundle.dependency_closure_sha256 != dependency_closure_sha256(
            list(expected_base_objects)
        ):
            raise ValueError("ResearchBundle public dependency closure does not replay")
        if base_objects != expected_base_objects:
            raise ValueError("ResearchBundle base dependency bindings do not replay")
        extension_closure = _typed_extension_dependency_closure(
            validation_graph,
            extension_roots,
        )
        expected_extension_objects = tuple(
            sorted(
                (contract_type, object_id, item.fingerprint)
                for object_id, (contract_type, item) in extension_closure.items()
                if object_id not in public_closure
            )
        )
        if extension_objects != expected_extension_objects:
            raise ValueError("current-share extension dependency closure does not replay")
        expected_current_source_bindings = {
            ("SourceDocument", object_id, item.fingerprint)
            for object_id, (contract_type, item) in extension_closure.items()
            if contract_type == "SourceDocument"
        }
        if source_bindings != expected_current_source_bindings:
            raise ValueError("current-share extension source closure is not exact")
        replayed_grouping = group_governed_completed_share_events(
            graph=validation_graph,
            issuer_id=self.issuer_id,
            security_compilation_result=self.security_compilation_result,
            opening_date=self.grouping_result.opening_date,
            quote_date=self.grouping_result.quote_date,
            data_cutoff_date=self.data_cutoff_date,
        )
        if replayed_grouping != self.grouping_result:
            raise ValueError("current-share grouping does not replay the current governed graph")
        object.__setattr__(self, "source_documents", sources)
        object.__setattr__(self, "base_dependency_object_fingerprints", base_objects)
        object.__setattr__(self, "extension_root_ids", extension_roots)
        object.__setattr__(self, "extension_object_fingerprints", extension_objects)
        object.__setattr__(self, "object_fingerprints", objects)
        _sha(self.closure_sha256, "current-share Bundle closure SHA")
        if self.closure_sha256 != self.expected_sha256():
            raise ValueError("current-share Bundle closure SHA mismatch")

    def hash_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("closure_sha256")
        return payload

    def expected_sha256(self) -> str:
        return canonical_sha256(self.hash_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


def _reject_fact_cycle(edges: tuple[tuple[str, str], ...]) -> None:
    parents: dict[str, set[str]] = {}
    for child, parent in edges:
        parents.setdefault(child, set()).add(parent)
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise ValueError("current-share Fact parent graph contains a cycle")
        if node in visited:
            return
        visiting.add(node)
        for parent in parents.get(node, set()):
            visit(parent)
        visiting.remove(node)
        visited.add(node)

    for node in tuple(parents):
        visit(node)


@dataclass(frozen=True, slots=True)
class CurrentShareEvidenceClosureV2:
    closure_id: str
    issuer_id: str
    security_id: str
    quote_date: str
    data_cutoff_date: str
    grouping_result: ShareEventGroupingResult
    opening_share_fact: Fact
    output_share_fact: Fact
    output_share_fact_id: str
    output_share_fact_fingerprint: str
    opening_share_fact_id: str
    rollforward_parent_fact_ids: tuple[str, ...]
    ultimate_numeric_root_fact_ids: tuple[str, ...]
    materializations: tuple[CanonicalShareEventFactMaterialization, ...]
    numeric_consumptions: tuple[ShareEventNumericConsumption, ...]
    bundle_evidence_closure: CurrentShareBundleEvidenceClosure
    coverage_ledger: CorporateActionCoverageLedgerV2
    claim_transition_reconciliation: GroupBoundClaimTransitionReconciliation
    fact_parent_edges: tuple[tuple[str, str], ...]
    object_fingerprints: tuple[tuple[str, str, str], ...]
    grouping_policy_id: str
    grouping_policy_version: str
    grouping_code_sha256: str
    integration_contract_sha256: str
    integration_policy_sha256: str
    integration_code_sha256: str
    grouping_result_fingerprint: str
    numeric_lineage_sha256: str
    coverage_closure_sha256: str
    claim_transition_sha256: str
    source_closure_sha256: str
    temporal_closure_sha256: str
    closure_sha256: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.closure_id, "current-share v2 closure ID"),
            (self.issuer_id, "current-share v2 issuer ID"),
            (self.security_id, "current-share v2 security ID"),
            (self.output_share_fact_id, "current-share output Fact ID"),
            (self.opening_share_fact_id, "opening-share Fact ID"),
        ):
            _nonempty(value, label)
        expected_closure_id = _current_share_v2_closure_id(
            issuer_id=self.issuer_id,
            security_id=self.security_id,
            quote_date=self.quote_date,
            opening_share_fact_id=self.opening_share_fact_id,
            output_share_fact_id=self.output_share_fact_id,
            grouping_result_fingerprint=self.grouping_result_fingerprint,
        )
        if self.closure_id != expected_closure_id:
            raise ValueError("current-share v2 closure ID is not deterministic")
        quote = _date(self.quote_date, "current-share v2 quote date")
        cutoff = _date(self.data_cutoff_date, "current-share v2 data cutoff")
        if quote > cutoff:
            raise ValueError("current-share quote date exceeds its data cutoff")
        _sha(self.output_share_fact_fingerprint, "current-share output fingerprint")
        opening_fact = self.opening_share_fact
        output_fact = self.output_share_fact
        if (
            opening_fact.fact_id != self.opening_share_fact_id
            or opening_fact.issuer_id != self.issuer_id
            or opening_fact.concept != "common_shares_outstanding"
            or opening_fact.value_type != "number"
            or opening_fact.unit != "shares"
            or opening_fact.currency is not None
            or opening_fact.period.get("start") is not None
            or opening_fact.derivation is not None
            or opening_fact.parent_fact_ids
            or opening_fact.confidence != "high"
        ):
            raise ValueError("opening-share Fact is not a governed raw stock Fact")
        opening_date = _date(str(opening_fact.period.get("end")), "opening-share measurement date")
        if opening_date >= quote:
            raise ValueError("opening-share Fact does not precede the quote date")
        if (
            output_fact.fact_id != self.output_share_fact_id
            or output_fact.fingerprint != self.output_share_fact_fingerprint
            or output_fact.issuer_id != self.issuer_id
            or output_fact.concept != "common_shares_outstanding"
            or output_fact.value_type != "number"
            or output_fact.unit != "shares"
            or output_fact.currency is not None
            or output_fact.period.get("start") is not None
            or output_fact.period.get("end") != self.quote_date
            or output_fact.source_document_id != opening_fact.source_document_id
            or output_fact.source_locator
            != _output_share_source_locator(self.output_share_fact_id)
            or output_fact.derivation != CURRENT_SHARE_ROLLFORWARD_DERIVATION
            or output_fact.confidence != "high"
        ):
            raise ValueError("output-share Fact is not the governed roll-forward result")
        if (self.grouping_policy_id, self.grouping_policy_version) != (
            SHARE_EVENT_GROUPING_POLICY_ID,
            SHARE_EVENT_GROUPING_POLICY_VERSION,
        ):
            raise ValueError("recursive closure grouping policy mismatch")
        for value, label in (
            (self.grouping_code_sha256, "grouping code SHA"),
            (self.integration_contract_sha256, "integration contract SHA"),
            (self.integration_policy_sha256, "integration policy SHA"),
            (self.integration_code_sha256, "integration code SHA"),
            (self.grouping_result_fingerprint, "grouping-result fingerprint"),
            (self.numeric_lineage_sha256, "numeric-lineage SHA"),
            (self.coverage_closure_sha256, "coverage-closure SHA"),
            (self.claim_transition_sha256, "claim-transition SHA"),
            (self.source_closure_sha256, "source-closure SHA"),
            (self.temporal_closure_sha256, "temporal-closure SHA"),
        ):
            _sha(value, label)
        if (
            self.integration_contract_sha256 != current_share_integration_contract_sha256()
            or self.integration_policy_sha256 != current_share_integration_policy_sha256()
            or self.integration_code_sha256 != current_share_integration_code_sha256()
            or self.bundle_evidence_closure.integration_contract_sha256
            != self.integration_contract_sha256
            or self.bundle_evidence_closure.integration_policy_sha256
            != self.integration_policy_sha256
            or self.bundle_evidence_closure.integration_code_sha256
            != self.integration_code_sha256
            or self.grouping_result.issuer_id != self.issuer_id
            or self.grouping_result.security_id != self.security_id
            or self.grouping_result.opening_date != opening_fact.period.get("end")
            or self.grouping_result.quote_date != self.quote_date
            or self.grouping_result.status != "grouped"
            or self.grouping_result.grouping_fingerprint != self.grouping_result_fingerprint
            or self.grouping_result.grouping_code_sha256 != self.grouping_code_sha256
            or self.grouping_code_sha256 != _grouping_code_sha256()
            or self.bundle_evidence_closure.grouping_result != self.grouping_result
            or self.bundle_evidence_closure.grouping_result_fingerprint
            != self.grouping_result_fingerprint
            or self.bundle_evidence_closure.security_compilation_result.decision is None
            or self.bundle_evidence_closure.security_compilation_result.decision.security_id
            != self.security_id
        ):
            raise ValueError("recursive closure does not bind the accepted grouping result")
        materials = tuple(sorted(self.materializations, key=lambda item: item.group_id))
        consumptions = tuple(sorted(self.numeric_consumptions, key=lambda item: item.group_id))
        material_groups = tuple(item.group_id for item in materials)
        consumption_groups = tuple(item.group_id for item in consumptions)
        if len(material_groups) != len(set(material_groups)):
            raise ValueError("recursive closure contains duplicate canonical groups")
        if material_groups != consumption_groups:
            raise ValueError("canonical groups are not consumed exactly once")
        material_by_group = {item.group_id: item for item in materials}
        expected_canonical_bindings = tuple(
            sorted(
                (
                    item.canonical_event_fact_id,
                    item.canonical_event_fact_fingerprint,
                )
                for item in materials
            )
        )
        if (
            self.bundle_evidence_closure.opening_share_fact != opening_fact
            or self.bundle_evidence_closure.canonical_event_materializations != materials
            or self.bundle_evidence_closure.canonical_event_fact_bindings
            != expected_canonical_bindings
            or self.bundle_evidence_closure.reserved_output_share_fact_id
            != self.output_share_fact_id
        ):
            raise ValueError("recursive closure generated Fact reservations do not replay")
        grouping_results = {item.grouping_result_fingerprint for item in materials}
        grouping_codes = {item.grouping_result.grouping_code_sha256 for item in materials}
        if (
            grouping_results != ({self.grouping_result_fingerprint} if materials else set())
            or grouping_codes != ({self.grouping_code_sha256} if materials else set())
            or any(item.grouping_result != self.grouping_result for item in materials)
            or {item.group_id for item in materials}
            != {item.group_id for item in self.grouping_result.groups}
        ):
            raise ValueError("recursive closure does not bind one accepted grouping result")
        for consumption in consumptions:
            material = material_by_group[consumption.group_id]
            if (
                consumption.group_fingerprint != material.group_fingerprint
                or consumption.identity_fingerprint != material.identity_fingerprint
                or consumption.canonical_event_fact_id != material.canonical_event_fact_id
                or consumption.canonical_event_fact_fingerprint
                != material.canonical_event_fact_fingerprint
                or consumption.event_concept != material.event_concept
                or consumption.window_start != opening_fact.period.get("end")
                or consumption.window_end != self.quote_date
                or material.issuer_id != self.issuer_id
                or material.security_id != self.security_id
                or material.opening_date != opening_fact.period.get("end")
                or material.quote_date != self.quote_date
                or material.data_cutoff_date != self.data_cutoff_date
            ):
                raise ValueError("numeric consumption does not match its canonical materialization")
        parents = _ids(self.rollforward_parent_fact_ids, "roll-forward parent Facts")
        expected_parents = tuple(
            sorted(
                {
                    self.opening_share_fact_id,
                    *(item.canonical_event_fact_id for item in materials),
                }
            )
        )
        if parents != expected_parents:
            raise ValueError("roll-forward parents are not exactly opening plus canonical Facts")
        if output_fact.parent_fact_ids != expected_parents:
            raise ValueError("output-share Fact does not bind the exact roll-forward parents")
        opening_value = _fact_share_integer(
            opening_fact.value,
            "opening-share Fact value",
            positive=True,
        )
        expected_output = opening_value + sum(
            (
                COMPLETED_SHARE_EVENT_SIGNS[item.event_concept]
                * _integer_decimal(
                    item.canonical_share_magnitude,
                    "canonical share magnitude",
                    positive=True,
                )
            )
            for item in materials
        )
        output_value = _fact_share_integer(
            output_fact.value,
            "output-share Fact value",
            positive=True,
        )
        if output_value != expected_output:
            raise ValueError("current-share roll-forward arithmetic does not replay")
        confidence_rank = {"low": 0, "medium": 1, "high": 2}
        expected_confidence = min(
            (
                opening_fact.confidence,
                *(material.canonical_event_fact.confidence for material in materials),
            ),
            key=confidence_rank.__getitem__,
        )
        if output_fact.confidence != expected_confidence:
            raise ValueError("output-share confidence does not preserve the weakest parent")
        roots = _ids(
            self.ultimate_numeric_root_fact_ids,
            "ultimate numeric root Facts",
            allow_empty=False,
        )
        edges = tuple(sorted(self.fact_parent_edges))
        if len(edges) != len(set(edges)):
            raise ValueError("recursive closure contains duplicate Fact parent edges")
        expected_edges = tuple(
            sorted(
                {
                    *((self.output_share_fact_id, parent) for parent in expected_parents),
                    *(
                        (material.canonical_event_fact_id, member.fact_id)
                        for material in materials
                        for member in material.members
                    ),
                }
            )
        )
        if edges != expected_edges:
            raise ValueError("recursive closure does not contain the exact Fact parent edges")
        object_bindings = _objects(self.object_fingerprints, "recursive object closure")
        fact_ids = {
            object_id for contract_type, object_id, _ in object_bindings if contract_type == "Fact"
        }
        if any(child not in fact_ids or parent not in fact_ids for child, parent in edges):
            raise ValueError("recursive closure contains a dangling Fact parent edge")
        _reject_fact_cycle(edges)
        parent_map: dict[str, set[str]] = {}
        for child, parent in edges:
            parent_map.setdefault(child, set()).add(parent)
        if parent_map.get(self.output_share_fact_id, set()) != set(expected_parents):
            raise ValueError(
                "roll-forward Fact parents are not exactly opening plus canonical Facts"
            )
        for material in materials:
            expected_member_parents = {member.fact_id for member in material.members}
            if parent_map.get(material.canonical_event_fact_id, set()) != (expected_member_parents):
                raise ValueError(
                    "canonical event Fact parents are not exactly all corroborating raw Facts"
                )
        raw_numeric_roots = {
            self.opening_share_fact_id,
            *(member.fact_id for material in materials for member in material.members),
        }
        if any(parent_map.get(root) for root in raw_numeric_roots):
            raise ValueError("raw current-share numeric root unexpectedly has parents")
        reachable: set[str] = set()

        def walk(node: str) -> None:
            if node in reachable:
                return
            reachable.add(node)
            for parent in parent_map.get(node, set()):
                walk(parent)

        walk(self.output_share_fact_id)
        numeric_leaves = tuple(sorted(node for node in reachable if node not in parent_map))
        if numeric_leaves != roots or set(roots) != raw_numeric_roots:
            raise ValueError("ultimate numeric roots do not replay the Fact parent graph")
        member_fact_ids = {member.fact_id for material in materials for member in material.members}
        if not member_fact_ids.issubset(reachable):
            raise ValueError("canonical member Facts are outside the numeric lineage")
        bundle_objects = self.bundle_evidence_closure.object_fingerprints
        bundle_object_set = set(bundle_objects)
        coverage_typed_bindings: set[tuple[str, str, str]] = {
            *(
                ("SourceDocument", item.document_id, item.fingerprint)
                for item in self.coverage_ledger.result_source_documents
            ),
            *(
                ("SourceSearchReceipt", item.receipt_id, item.fingerprint)
                for item in self.coverage_ledger.receipts
            ),
        }
        for entry in self.coverage_ledger.entries:
            coverage_typed_bindings.update(
                ("Fact", item.fact_id, item.fingerprint)
                for item in entry.observed_member_facts
            )
            coverage_typed_bindings.update(
                ("SourceDocument", item.document_id, item.fingerprint)
                for item in entry.observed_member_source_documents
            )
            coverage_typed_bindings.update(
                ("Fact", item.fact_id, item.fingerprint)
                for item in entry.not_applicable_supporting_facts
            )
            coverage_typed_bindings.update(
                ("Fact", item.fact_id, item.fingerprint)
                for item in entry.not_applicable_counterevidence_facts
            )
            if entry.zero_fact is not None:
                coverage_typed_bindings.add(
                    ("Fact", entry.zero_fact.fact_id, entry.zero_fact.fingerprint)
                )
            if entry.not_applicable_claim is not None:
                coverage_typed_bindings.add(
                    (
                        "Claim",
                        entry.not_applicable_claim.claim_id,
                        entry.not_applicable_claim.fingerprint,
                    )
                )
            if entry.not_applicable_candidate is not None:
                coverage_typed_bindings.add(
                    (
                        "AnalyticalClaimCandidate",
                        entry.not_applicable_candidate.candidate_id,
                        entry.not_applicable_candidate.fingerprint,
                    )
                )
            if entry.review_decision is not None:
                coverage_typed_bindings.add(
                    (
                        "AnalyticalClaimReviewDecision",
                        entry.review_decision.decision_id,
                        entry.review_decision.fingerprint,
                    )
                )
        transition_typed_bindings: set[tuple[str, str, str]] = set()
        for transition in self.claim_transition_reconciliation.records:
            transition_typed_bindings.update(
                {
                    (
                        "Fact",
                        transition.affected_claim_root_fact.fact_id,
                        transition.affected_claim_root_fact.fingerprint,
                    ),
                    (
                        "Fact",
                        transition.remaining_claim_fact.fact_id,
                        transition.remaining_claim_fact.fingerprint,
                    ),
                    (
                        "SourceDocument",
                        transition.affected_claim_source_document.document_id,
                        transition.affected_claim_source_document.fingerprint,
                    ),
                    (
                        "SourceDocument",
                        transition.remaining_claim_source_document.document_id,
                        transition.remaining_claim_source_document.fingerprint,
                    ),
                }
            )
            transition_typed_bindings.update(
                ("Fact", item.fact_id, item.fingerprint)
                for item in transition.evidence_facts
            )
            transition_typed_bindings.update(
                ("SourceDocument", item.document_id, item.fingerprint)
                for item in transition.evidence_source_documents
            )
            transition_typed_bindings.update(
                ("Claim", item.claim_id, item.fingerprint)
                for item in transition.claims
            )
            transition_typed_bindings.update(
                ("AnalyticalClaimCandidate", item.candidate_id, item.fingerprint)
                for item in transition.candidates
            )
            transition_typed_bindings.update(
                (
                    "AnalyticalClaimReviewDecision",
                    item.decision_id,
                    item.fingerprint,
                )
                for item in transition.review_decisions
            )
        if not coverage_typed_bindings.issubset(bundle_object_set):
            raise ValueError(
                "coverage typed evidence is not byte-bound to the graph-owned Bundle closure"
            )
        if not transition_typed_bindings.issubset(bundle_object_set):
            raise ValueError(
                "claim-transition typed evidence is not byte-bound to the graph-owned "
                "Bundle closure"
            )
        generated_objects = {
            ("Fact", self.output_share_fact_id, self.output_share_fact_fingerprint),
            *(
                (
                    "Fact",
                    item.canonical_event_fact_id,
                    item.canonical_event_fact_fingerprint,
                )
                for item in materials
            ),
        }
        if set(object_bindings) != set(bundle_objects) | generated_objects:
            raise ValueError("recursive object closure is not the exact governed evidence set")
        base_bundle_ids = {
            object_id
            for _, object_id, _ in self.bundle_evidence_closure.base_dependency_object_fingerprints
        }
        required_extension_roots = {
            self.opening_share_fact_id,
            *member_fact_ids,
            *(
                member.capital_allocation_event_id
                for material in materials
                for member in material.members
            ),
            *(
                identifier
                for material in materials
                for member in material.members
                for identifier, _ in (
                    *member.candidate_bindings,
                    *member.review_decision_bindings,
                )
            ),
            *self.coverage_ledger.receipt_ids,
            *(
                object_id
                for contract_type, object_id, _fingerprint in (
                    self.bundle_evidence_closure.extension_object_fingerprints
                )
                if contract_type == "FilingArtifact"
            ),
        }
        for entry in self.coverage_ledger.entries:
            required_extension_roots.update(entry.member_event_fact_ids)
            if entry.zero_fact_id is not None:
                required_extension_roots.add(entry.zero_fact_id)
            if entry.not_applicable_claim_id is not None:
                required_extension_roots.add(entry.not_applicable_claim_id)
            if entry.not_applicable_candidate is not None:
                required_extension_roots.add(entry.not_applicable_candidate.candidate_id)
                required_extension_roots.update(
                    _candidate_evidence_object_ids(entry.not_applicable_candidate)
                )
            if entry.review_decision_id is not None:
                required_extension_roots.add(entry.review_decision_id)
        for transition in self.claim_transition_reconciliation.records:
            required_extension_roots.update(
                {
                    transition.affected_claim_root_fact_id,
                    transition.remaining_claim_fact_id,
                }
            )
            required_extension_roots.update(
                identifier for identifier, _ in transition.claim_bindings
            )
            required_extension_roots.update(
                identifier for identifier, _ in transition.candidate_bindings
            )
            for candidate in transition.candidates:
                required_extension_roots.update(_candidate_evidence_object_ids(candidate))
            required_extension_roots.update(
                identifier for identifier, _ in transition.review_decision_bindings
            )
        claim_authority = self.claim_transition_reconciliation.claim_control_authority
        if claim_authority is not None:
            required_extension_roots.update(
                object_id
                for contract_type, object_id, _ in (
                    claim_authority.phase5c_review_object_fingerprints
                )
                if contract_type != "SourceDocument"
            )
        security = self.bundle_evidence_closure.security_compilation_result
        security_closure = security.evidence_closure
        if security_closure is None:
            raise ValueError("current-share security evidence closure is unavailable")
        required_extension_roots.update(
            {
                *security_closure.fact_ids,
                security_closure.claim_id,
                security_closure.candidate_id,
                security_closure.review_decision_id,
            }
        )
        if (
            tuple(sorted(required_extension_roots))
            != self.bundle_evidence_closure.extension_root_ids
        ):
            raise ValueError("current-share post-Bundle extension roots are not exact")
        if not required_extension_roots.difference(base_bundle_ids):
            raise ValueError(
                "current-share post-Bundle extension unexpectedly contains no new evidence"
            )
        if (
            self.bundle_evidence_closure.issuer_id != self.issuer_id
            or self.bundle_evidence_closure.data_cutoff_date != self.data_cutoff_date
            or self.coverage_ledger.issuer_id != self.issuer_id
            or self.coverage_ledger.issuer_cik
            != self.bundle_evidence_closure.issuer_cik
            or self.coverage_ledger.security_id != self.security_id
            or self.coverage_ledger.period_start != opening_fact.period.get("end")
            or self.coverage_ledger.period_end != self.quote_date
            or self.coverage_ledger.data_cutoff_date != self.data_cutoff_date
            or self.claim_transition_reconciliation.issuer_id != self.issuer_id
            or self.claim_transition_reconciliation.security_id != self.security_id
            or self.claim_transition_reconciliation.opening_date != opening_fact.period.get("end")
            or self.claim_transition_reconciliation.quote_date != self.quote_date
            or self.claim_transition_reconciliation.data_cutoff_date != self.data_cutoff_date
        ):
            raise ValueError("recursive closure crosses its governed issuer, security, or period")
        if claim_authority is not None and (
            self.bundle_evidence_closure.claim_control_authority != claim_authority
            or self.bundle_evidence_closure.claim_control_authority_fingerprint
            != claim_authority.authority_fingerprint
            or
            claim_authority.component_lock_sha256
            != self.bundle_evidence_closure.component_lock_sha256
            or claim_authority.research_bundle_id
            != self.bundle_evidence_closure.research_bundle_id
            or claim_authority.research_bundle_fingerprint
            != self.bundle_evidence_closure.research_bundle_fingerprint
            or claim_authority.research_bundle_dependency_sha256
            != self.bundle_evidence_closure.dependency_closure_sha256
            or claim_authority.run_manifest_id
            != self.bundle_evidence_closure.run_manifest_id
            or not set(claim_authority.phase5c_review_object_fingerprints).issubset(
                set(self.bundle_evidence_closure.object_fingerprints)
            )
        ):
            raise ValueError(
                "claim authority is not bound to the current graph-owned evidence closure"
            )
        if claim_authority is None and (
            self.bundle_evidence_closure.claim_control_authority is not None
            or self.bundle_evidence_closure.claim_control_authority_fingerprint is not None
        ):
            raise ValueError("Bundle claim authority exists without a transition reconciliation")
        if self.coverage_ledger.expected_group_ids != tuple(sorted(material_groups)):
            raise ValueError("coverage ledger does not close the canonical group set")
        material_by_group = {item.group_id: item for item in materials}
        for entry in self.coverage_ledger.entries:
            if entry.status != "observed":
                continue
            entry_materials = tuple(material_by_group[group_id] for group_id in entry.group_ids)
            if any(
                EVENT_CONCEPT_TO_COVERAGE_CATEGORY[item.event_concept] != entry.category
                for item in entry_materials
            ):
                raise ValueError("coverage category does not match its canonical event concept")
            if set(entry.canonical_event_fact_ids) != {
                item.canonical_event_fact_id for item in entry_materials
            }:
                raise ValueError("coverage canonical Facts do not match their groups")
            if set(entry.member_event_fact_ids) != {
                member.fact_id for item in entry_materials for member in item.members
            }:
                raise ValueError("coverage raw members do not match their canonical groups")
            if {(item.fact_id, item.fingerprint) for item in entry.observed_member_facts} != {
                (member.fact_id, member.fact_fingerprint)
                for item in entry_materials
                for member in item.members
            } or {
                (item.document_id, item.fingerprint)
                for item in entry.observed_member_source_documents
            } != {
                (member.source_document_id, member.source_document_fingerprint)
                for item in entry_materials
                for member in item.members
            }:
                raise ValueError("coverage typed evidence does not match its canonical groups")
        claim_sensitive = tuple(
            sorted(
                item.group_id
                for item in materials
                if item.event_concept in STANDARD_CLAIM_TRANSITION_EVENT_CONCEPTS
            )
        )
        if any(
            item.event_concept in SPECIALIST_REQUIRED_CLAIM_TRANSITION_EVENT_CONCEPTS
            for item in materials
        ):
            raise ValueError(
                "current-share closure requires specialist claim-transition authority"
            )
        if (
            self.claim_transition_reconciliation.expected_claim_sensitive_group_ids
            != claim_sensitive
        ):
            raise ValueError("claim-transition reconciliation does not close sensitive groups")
        for transition in self.claim_transition_reconciliation.records:
            material = material_by_group[transition.group_id]
            reviewed_support = {
                fact_id for claim in transition.claims for fact_id in claim.supporting_fact_ids
            }
            if (
                transition.group_fingerprint != material.group_fingerprint
                or transition.identity_fingerprint != material.identity_fingerprint
                or transition.canonical_event_fact_id != material.canonical_event_fact_id
                or transition.canonical_event_fact_fingerprint
                != material.canonical_event_fact_fingerprint
                or transition.event_concept != material.event_concept
                or transition.legal_effective_date != material.legal_effective_date
                or transition.canonical_share_magnitude != material.canonical_share_magnitude
                or not {member.fact_id for member in material.members}.issubset(reviewed_support)
            ):
                raise ValueError(
                    "claim transition does not match its canonical event materialization"
                )
        if self.coverage_closure_sha256 != self.coverage_ledger.ledger_sha256:
            raise ValueError("coverage closure SHA does not bind the coverage ledger")
        if (
            self.claim_transition_sha256
            != self.claim_transition_reconciliation.reconciliation_sha256
        ):
            raise ValueError("claim-transition SHA does not bind the reconciliation")
        expected_numeric_lineage = canonical_sha256(
            {
                "opening_fact": opening_fact.to_dict(),
                "output_fact": output_fact.to_dict(),
                "materialization_fingerprints": [
                    item.materialization_fingerprint for item in materials
                ],
                "consumption_fingerprints": [item.consumption_fingerprint for item in consumptions],
                "fact_parent_edges": edges,
            }
        )
        extension_sources = {
            item.document_id: item for item in self.bundle_evidence_closure.source_documents
        }
        opening_source = extension_sources.get(opening_fact.source_document_id)
        if (
            opening_source is None
            or opening_source.authority_level not in OFFICIAL_AUTHORITY_LEVELS
        ):
            raise ValueError(
                "opening-share source is absent or not an official primary source"
            )
        security_source_ids = set(
            self.bundle_evidence_closure.security_compilation_result.evidence_closure.source_document_ids
            if self.bundle_evidence_closure.security_compilation_result.evidence_closure is not None
            else ()
        )
        expected_source_closure = canonical_sha256(
            {
                "member_sources": sorted(
                    {
                        (member.source_document_id, member.source_document_fingerprint)
                        for material in materials
                        for member in material.members
                    }
                ),
                "receipt_fingerprints": sorted(
                    (receipt.receipt_id, receipt.fingerprint)
                    for receipt in self.coverage_ledger.receipts
                ),
                "opening_source": (opening_source.document_id, opening_source.fingerprint),
                "coverage_zero_sources": sorted(
                    (
                        extension_sources[entry.zero_fact.source_document_id].document_id,
                        extension_sources[entry.zero_fact.source_document_id].fingerprint,
                    )
                    for entry in self.coverage_ledger.entries
                    if entry.zero_fact is not None
                ),
                "claim_transition_sources": sorted(
                    {
                        (source.document_id, source.fingerprint)
                        for transition in self.claim_transition_reconciliation.records
                        for source in transition.evidence_source_documents
                    }
                ),
                "security_sources": sorted(
                    (identifier, extension_sources[identifier].fingerprint)
                    for identifier in security_source_ids
                ),
                "extension_sources": sorted(
                    (item.document_id, item.fingerprint) for item in extension_sources.values()
                ),
            }
        )
        expected_temporal_closure = canonical_sha256(
            {
                "issuer_id": self.issuer_id,
                "security_id": self.security_id,
                "opening_date": opening_fact.period.get("end"),
                "quote_date": self.quote_date,
                "data_cutoff_date": self.data_cutoff_date,
                "event_effective_dates": sorted(item.legal_effective_date for item in materials),
                "member_dates": sorted(
                    (
                        member.member.fact_measurement_date,
                        member.member.source_published_date,
                        member.member.data_cutoff_date,
                    )
                    for material in materials
                    for member in material.members
                ),
                "receipt_periods": sorted(
                    (
                        receipt.source_family,
                        receipt.period["start"],
                        receipt.period["end"],
                        receipt.cutoff_date,
                    )
                    for receipt in self.coverage_ledger.receipts
                ),
                "claim_transition_evidence_dates": sorted(
                    (
                        fact.fact_id,
                        fact.period["end"],
                        extension_sources[fact.source_document_id].published_date,
                    )
                    for transition in self.claim_transition_reconciliation.records
                    for fact in transition.evidence_facts
                ),
            }
        )
        if self.numeric_lineage_sha256 != expected_numeric_lineage:
            raise ValueError("numeric-lineage SHA is not derived from the governed Facts")
        if self.source_closure_sha256 != expected_source_closure:
            raise ValueError("source-closure SHA is not derived from the governed evidence")
        if self.temporal_closure_sha256 != expected_temporal_closure:
            raise ValueError("temporal-closure SHA is not derived from the governed window")
        object.__setattr__(self, "materializations", materials)
        object.__setattr__(self, "numeric_consumptions", consumptions)
        object.__setattr__(self, "rollforward_parent_fact_ids", parents)
        object.__setattr__(self, "ultimate_numeric_root_fact_ids", roots)
        object.__setattr__(self, "fact_parent_edges", edges)
        object.__setattr__(self, "object_fingerprints", object_bindings)
        _sha(self.closure_sha256, "recursive current-share closure SHA")
        if self.closure_sha256 != self.expected_sha256():
            raise ValueError("recursive current-share closure SHA mismatch")

    def hash_payload(self) -> dict[str, Any]:
        payload = to_json_value(self)
        payload.pop("closure_sha256")
        return payload

    def expected_sha256(self) -> str:
        return canonical_sha256(self.hash_payload())

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


__all__: tuple[str, ...] = ()
