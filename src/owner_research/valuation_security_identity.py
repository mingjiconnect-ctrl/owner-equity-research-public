"""Evidence-bound security identity compiler for Phase 5E-1.1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from .component_lock import file_sha256
from .contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    Claim,
    Fact,
    SourceDocument,
)
from .fingerprints import canonical_sha256, to_json_value
from .validation import ContractGraph, ContractGraphError
from .valuation_market_execution_policies import (
    SECURITY_IDENTITY_POLICY_ID,
    SECURITY_IDENTITY_POLICY_VERSION,
)
from .valuation_market_execution_types import SecurityIdentityDecision
from .valuation_price_blind_freeze import PriceBlindFreezeCompilationResult

SECURITY_EVIDENCE_POLICY_ID = "market-security-identity-evidence"
SECURITY_EVIDENCE_POLICY_VERSION = "1.0.0"
SECURITY_FACT_CONCEPTS = {
    "ticker": "security_ticker",
    "mic": "security_mic",
    "share_class": "security_share_class",
    "security_structure": "security_structure",
}
SUPPORTED_MIC_CURRENCY = {"XNAS": "USD", "XNYS": "USD"}
SECURITY_COMPILATION_STATUSES = ("eligible", "specialist_required", "blocked")
SECURITY_COMPILATION_ISSUES = frozenset(
    {
        "component_lock_mismatch",
        "contract_graph_invalid",
        "security_evidence_missing",
        "security_evidence_not_formal",
        "security_evidence_future",
        "security_evidence_cross_issuer",
        "security_fact_role_mismatch",
        "security_claim_unreviewed",
        "security_claim_incomplete",
        "security_scope_mismatch",
        "security_identity_unresolved",
        "cross_currency_security",
        "cross_listing_unsupported",
        "dual_class_security_unsupported",
        "multi_security_aggregation_unsupported",
    }
)


@dataclass(frozen=True, slots=True)
class SecurityFactBinding:
    role: str
    fact_id: str

    def __post_init__(self) -> None:
        if self.role not in SECURITY_FACT_CONCEPTS or not self.fact_id.strip():
            raise ValueError("security Fact binding is not registered")

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class SecurityAccessProposal:
    proposal_id: str
    issuer_id: str
    data_cutoff_date: str
    fact_bindings: tuple[SecurityFactBinding, ...]
    structure_claim_id: str
    analytical_candidate_id: str
    analytical_review_decision_id: str

    def __post_init__(self) -> None:
        date.fromisoformat(self.data_cutoff_date)
        if not self.proposal_id.strip() or not self.issuer_id.strip():
            raise ValueError("security access proposal identity is required")
        ordered = tuple(sorted(self.fact_bindings, key=lambda item: item.role))
        roles = tuple(item.role for item in ordered)
        if set(roles) != set(SECURITY_FACT_CONCEPTS) or len(roles) != len(set(roles)):
            raise ValueError("security proposal must bind every registered Fact role exactly once")
        if not all(
            item.strip()
            for item in (
                self.structure_claim_id,
                self.analytical_candidate_id,
                self.analytical_review_decision_id,
            )
        ):
            raise ValueError("security proposal requires the reviewed analytical Claim chain")
        object.__setattr__(self, "fact_bindings", ordered)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class SecurityIdentityEvidenceClosure:
    issuer_id: str
    data_cutoff_date: str
    source_document_ids: tuple[str, ...]
    fact_ids: tuple[str, ...]
    claim_id: str
    candidate_id: str
    review_decision_id: str
    object_fingerprints: tuple[tuple[str, str, str], ...]
    closure_sha256: str

    def __post_init__(self) -> None:
        payload = {
            "issuer_id": self.issuer_id,
            "data_cutoff_date": self.data_cutoff_date,
            "source_document_ids": tuple(sorted(self.source_document_ids)),
            "fact_ids": tuple(sorted(self.fact_ids)),
            "claim_id": self.claim_id,
            "candidate_id": self.candidate_id,
            "review_decision_id": self.review_decision_id,
            "object_fingerprints": tuple(sorted(self.object_fingerprints)),
        }
        if self.closure_sha256 != canonical_sha256(payload):
            raise ValueError("security evidence closure SHA mismatch")
        object.__setattr__(self, "source_document_ids", payload["source_document_ids"])
        object.__setattr__(self, "fact_ids", payload["fact_ids"])
        object.__setattr__(self, "object_fingerprints", payload["object_fingerprints"])

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)


@dataclass(frozen=True, slots=True)
class SecurityIdentityCompilationResult:
    policy_id: str
    policy_version: str
    proposal: SecurityAccessProposal
    status: str
    decision: SecurityIdentityDecision | None
    evidence_closure: SecurityIdentityEvidenceClosure | None
    issue_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if (self.policy_id, self.policy_version) != (
            SECURITY_EVIDENCE_POLICY_ID,
            SECURITY_EVIDENCE_POLICY_VERSION,
        ):
            raise ValueError("security compilation policy mismatch")
        if self.status not in SECURITY_COMPILATION_STATUSES:
            raise ValueError("security compilation status is not registered")
        issues = tuple(sorted(self.issue_codes))
        if len(issues) != len(set(issues)) or not set(issues).issubset(
            SECURITY_COMPILATION_ISSUES
        ):
            raise ValueError("security compilation issues are not registered")
        if self.status == "eligible":
            if self.decision is None or self.evidence_closure is None or issues:
                raise ValueError("eligible security compilation lacks its evidence closure")
        elif not issues:
            raise ValueError("non-eligible security compilation requires issues")
        object.__setattr__(self, "issue_codes", issues)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


def _blocked(
    proposal: SecurityAccessProposal,
    *issues: str,
    status: str = "blocked",
    decision: SecurityIdentityDecision | None = None,
    closure: SecurityIdentityEvidenceClosure | None = None,
) -> SecurityIdentityCompilationResult:
    return SecurityIdentityCompilationResult(
        policy_id=SECURITY_EVIDENCE_POLICY_ID,
        policy_version=SECURITY_EVIDENCE_POLICY_VERSION,
        proposal=proposal,
        status=status,
        decision=decision,
        evidence_closure=closure,
        issue_codes=tuple(issues),
    )


def _evidence_objects(
    graph: ContractGraph,
    proposal: SecurityAccessProposal,
) -> tuple[
    tuple[Fact, ...],
    Claim | None,
    AnalyticalClaimCandidate | None,
    AnalyticalClaimReviewDecision | None,
    tuple[SourceDocument, ...],
]:
    facts_by_id = {item.fact_id: item for item in graph.facts}
    facts = tuple(
        facts_by_id[item.fact_id]
        for item in proposal.fact_bindings
        if item.fact_id in facts_by_id
    )
    claim = next(
        (item for item in graph.claims if item.claim_id == proposal.structure_claim_id),
        None,
    )
    candidate = next(
        (
            item
            for item in graph.analytical_claim_candidates
            if item.candidate_id == proposal.analytical_candidate_id
        ),
        None,
    )
    review = next(
        (
            item
            for item in graph.analytical_claim_review_decisions
            if item.decision_id == proposal.analytical_review_decision_id
        ),
        None,
    )
    document_ids = {item.source_document_id for item in facts}
    documents = tuple(item for item in graph.documents if item.document_id in document_ids)
    return facts, claim, candidate, review, documents


def _closure(
    proposal: SecurityAccessProposal,
    facts: tuple[Fact, ...],
    claim: Claim,
    candidate: AnalyticalClaimCandidate,
    review: AnalyticalClaimReviewDecision,
    documents: tuple[SourceDocument, ...],
) -> SecurityIdentityEvidenceClosure:
    fingerprints = tuple(
        sorted(
            (
                *(("SourceDocument", item.document_id, item.fingerprint) for item in documents),
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
    )
    payload = {
        "issuer_id": proposal.issuer_id,
        "data_cutoff_date": proposal.data_cutoff_date,
        "source_document_ids": tuple(sorted(item.document_id for item in documents)),
        "fact_ids": tuple(sorted(item.fact_id for item in facts)),
        "claim_id": claim.claim_id,
        "candidate_id": candidate.candidate_id,
        "review_decision_id": review.decision_id,
        "object_fingerprints": fingerprints,
    }
    return SecurityIdentityEvidenceClosure(**payload, closure_sha256=canonical_sha256(payload))


def compile_security_identity(
    *,
    graph: ContractGraph,
    expected_freeze: PriceBlindFreezeCompilationResult,
    proposal: SecurityAccessProposal,
) -> SecurityIdentityCompilationResult:
    artifact = expected_freeze.artifact.to_dict()
    if artifact["component_lock_sha256"] != file_sha256(graph.component_lock_path):
        return _blocked(proposal, "component_lock_mismatch")
    if (
        proposal.issuer_id != artifact["issuer_id"]
        or proposal.data_cutoff_date != artifact["data_cutoff_date"]
    ):
        return _blocked(proposal, "security_evidence_cross_issuer")
    try:
        graph.validate()
    except ContractGraphError:
        return _blocked(proposal, "contract_graph_invalid")
    facts, claim, candidate, review, documents = _evidence_objects(graph, proposal)
    if (
        len(facts) != len(SECURITY_FACT_CONCEPTS)
        or claim is None
        or candidate is None
        or review is None
        or len(documents) != len({item.source_document_id for item in facts})
    ):
        return _blocked(proposal, "security_evidence_missing")
    cutoff = date.fromisoformat(proposal.data_cutoff_date)
    if any(
        item.issuer_id != proposal.issuer_id
        for item in (*facts, claim, candidate, review, *documents)
    ):
        return _blocked(proposal, "security_evidence_cross_issuer")
    if any(
        item.authority_level not in {"primary_regulatory", "company_primary"}
        for item in documents
    ):
        return _blocked(proposal, "security_evidence_not_formal")
    if any(date.fromisoformat(item.published_date) > cutoff for item in documents) or any(
        item.period["end"] is None or date.fromisoformat(str(item.period["end"])) > cutoff
        for item in facts
    ):
        return _blocked(proposal, "security_evidence_future")
    by_role = {
        binding.role: next(item for item in facts if item.fact_id == binding.fact_id)
        for binding in proposal.fact_bindings
    }
    if any(
        fact.concept != SECURITY_FACT_CONCEPTS[role]
        or fact.value_type != "text"
        or not isinstance(fact.value, str)
        or not fact.value.strip()
        or fact.derivation is not None
        or fact.parent_fact_ids
        for role, fact in by_role.items()
    ):
        return _blocked(proposal, "security_fact_role_mismatch")
    if (
        review.decision != "confirmed"
        or review.candidate_id != candidate.candidate_id
        or review.candidate_fingerprint != candidate.fingerprint
        or review.evidence_graph_sha256 != candidate.evidence_graph_sha256
        or review.output_claim_id != claim.claim_id
        or not review.reviewer_id.startswith("human:")
        or len(review.reviewer_id) <= len("human:")
    ):
        return _blocked(proposal, "security_claim_unreviewed")
    candidate_fact_ids = {
        str(binding["fact_id"])
        for binding in candidate.supporting_evidence_bindings
        if binding["fact_id"] is not None
    }
    fact_ids = {item.fact_id for item in facts}
    if (
        candidate.validation_status != "ready"
        or candidate.claim_role != "support"
        or candidate.scope["scope_type"] != "issuer_wide"
        or candidate.as_of_date > proposal.data_cutoff_date
        or candidate_fact_ids != fact_ids
        or set(claim.supporting_fact_ids) != fact_ids
        or not claim.counterevidence_search_note
        or not claim.falsification_condition.strip()
        or claim.confidence not in {"high", "medium"}
    ):
        return _blocked(proposal, "security_claim_incomplete")
    closure = _closure(proposal, facts, claim, candidate, review, documents)
    ticker = str(by_role["ticker"].value).upper()
    mic = str(by_role["mic"].value).upper()
    share_class = str(by_role["share_class"].value).casefold()
    structure = str(by_role["security_structure"].value)
    reporting_currency = artifact["reviewed_assumptions"]["augmented_fact_ledger_payload"][
        "reporting_currency"
    ]
    quote_currency = SUPPORTED_MIC_CURRENCY.get(mic)
    security_id = f"security:{proposal.issuer_id}:{mic}:{ticker}:{share_class}"
    if (
        structure != "single_primary_common"
        or share_class != "common"
        or mic not in SUPPORTED_MIC_CURRENCY
    ):
        reason = {
            "adr_or_depositary_receipt": "security_identity_unresolved",
            "dual_or_multi_class_different_prices": "dual_class_security_unsupported",
            "cross_listed_or_multi_venue": "cross_listing_unsupported",
            "multi_security_aggregation": "multi_security_aggregation_unsupported",
        }.get(structure, "security_identity_unresolved")
        decision_identity = canonical_sha256(
            {"proposal": proposal.fingerprint, "closure": closure.closure_sha256}
        )
        decision = SecurityIdentityDecision(
            decision_id=f"security-decision:{decision_identity[:24]}",
            policy_id=SECURITY_IDENTITY_POLICY_ID,
            policy_version=SECURITY_IDENTITY_POLICY_VERSION,
            issuer_id=proposal.issuer_id,
            security_id=security_id,
            ticker=ticker,
            exchange=mic,
            share_class=share_class,
            security_structure=structure if structure in {
                "adr_or_depositary_receipt",
                "dual_or_multi_class_different_prices",
                "cross_listed_or_multi_venue",
                "multi_security_aggregation",
                "unresolved",
            } else "unresolved",
            quote_currency=quote_currency or reporting_currency,
            reporting_currency=reporting_currency,
            disposition="specialist_required",
            reason_codes=(reason,),
        )
        return _blocked(
            proposal,
            reason,
            status="specialist_required",
            decision=decision,
            closure=closure,
        )
    if quote_currency != reporting_currency:
        return _blocked(proposal, "cross_currency_security", closure=closure)
    decision_identity = canonical_sha256(
        {"proposal": proposal.fingerprint, "closure": closure.closure_sha256}
    )
    decision = SecurityIdentityDecision(
        decision_id=f"security-decision:{decision_identity[:24]}",
        policy_id=SECURITY_IDENTITY_POLICY_ID,
        policy_version=SECURITY_IDENTITY_POLICY_VERSION,
        issuer_id=proposal.issuer_id,
        security_id=security_id,
        ticker=ticker,
        exchange=mic,
        share_class=share_class,
        security_structure=structure,
        quote_currency=quote_currency,
        reporting_currency=reporting_currency,
        disposition="eligible",
        reason_codes=(),
    )
    return SecurityIdentityCompilationResult(
        policy_id=SECURITY_EVIDENCE_POLICY_ID,
        policy_version=SECURITY_EVIDENCE_POLICY_VERSION,
        proposal=proposal,
        status="eligible",
        decision=decision,
        evidence_closure=closure,
        issue_codes=(),
    )


__all__ = ()
