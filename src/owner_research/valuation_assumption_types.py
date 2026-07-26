"""Internal immutable Phase 5D price-blind reference types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from .contracts import Fact, SourceDocument
from .fingerprints import FrozenMap, canonical_sha256, freeze, to_json_value
from .valuation_handoff_policies import (
    SUPPLEMENTAL_REFERENCE_POLICY_ID,
    SUPPLEMENTAL_REFERENCE_POLICY_VERSION,
)


@dataclass(frozen=True, slots=True)
class PriceBlindReferenceClosure:
    """A non-public, separately hashed closure of non-target price-blind references."""

    closure_id: str
    policy_id: str
    policy_version: str
    target_issuer_id: str
    data_cutoff_date: str
    documents: tuple[SourceDocument, ...]
    facts: tuple[Fact, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "documents", tuple(self.documents))
        object.__setattr__(self, "facts", tuple(self.facts))
        if (self.policy_id, self.policy_version) != (
            SUPPLEMENTAL_REFERENCE_POLICY_ID,
            SUPPLEMENTAL_REFERENCE_POLICY_VERSION,
        ):
            raise ValueError("PriceBlindReferenceClosure policy mismatch")
        cutoff = date.fromisoformat(self.data_cutoff_date)
        documents = {item.document_id: item for item in self.documents}
        if len(documents) != len(self.documents):
            raise ValueError("PriceBlindReferenceClosure repeats SourceDocument IDs")
        if len({item.fact_id for item in self.facts}) != len(self.facts):
            raise ValueError("PriceBlindReferenceClosure repeats Fact IDs")
        for document in self.documents:
            if document.issuer_id == self.target_issuer_id:
                raise ValueError("target-issuer evidence cannot enter the supplemental closure")
            if date.fromisoformat(document.published_date) > cutoff:
                raise ValueError("supplemental SourceDocument follows the data cutoff")
        for fact in self.facts:
            source = documents.get(fact.source_document_id)
            if source is None:
                raise ValueError("supplemental Fact has a dangling SourceDocument")
            if fact.issuer_id != source.issuer_id:
                raise ValueError("supplemental Fact and SourceDocument issuer mismatch")
            if fact.issuer_id == self.target_issuer_id:
                raise ValueError("target-issuer Fact cannot enter the supplemental closure")
            if fact.value_type != "number" or fact.confidence not in {"high", "medium"}:
                raise ValueError("supplemental Fact must be numeric and high/medium confidence")
            if fact.derivation is not None or fact.parent_fact_ids:
                raise ValueError("supplemental Fact must preserve raw single-source lineage")
            if date.fromisoformat(fact.period["end"]) > cutoff:
                raise ValueError("supplemental Fact period follows the data cutoff")

    def to_dict(self) -> dict[str, Any]:
        return {
            "closure_id": self.closure_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "target_issuer_id": self.target_issuer_id,
            "data_cutoff_date": self.data_cutoff_date,
            "documents": [
                item.to_dict()
                for item in sorted(self.documents, key=lambda value: value.document_id)
            ],
            "facts": [
                item.to_dict()
                for item in sorted(self.facts, key=lambda value: value.fact_id)
            ],
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class AssumptionEvidenceRequest:
    """Caller proposal for one typed evidence edge; the compiler owns its binding ID."""

    role: str
    slot_evidence_role: str
    evidence_domain: str
    contract_type: str
    object_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "slot_evidence_role": self.slot_evidence_role,
            "evidence_domain": self.evidence_domain,
            "contract_type": self.contract_type,
            "object_id": self.object_id,
        }


@dataclass(frozen=True, slots=True)
class AssumptionCandidateProposal:
    """Unreviewed numeric proposal consumed by the Phase 5D-1 compiler."""

    assumption_slot_id: str
    value: float | int
    unit: str
    currency: str | None
    horizon: FrozenMap
    scenario: str | None
    rationale: str
    generation_method: str
    evidence: tuple[AssumptionEvidenceRequest, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "horizon", freeze(self.horizon))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        if not self.rationale.strip():
            raise ValueError("AssumptionCandidateProposal rationale is required")
        if self.generation_method not in {"deterministic", "human", "llm"}:
            raise ValueError("AssumptionCandidateProposal generation method is invalid")
        if not self.evidence:
            raise ValueError("AssumptionCandidateProposal requires typed evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "assumption_slot_id": self.assumption_slot_id,
            "value": self.value,
            "unit": self.unit,
            "currency": self.currency,
            "horizon": to_json_value(self.horizon),
            "scenario": self.scenario,
            "rationale": self.rationale,
            "generation_method": self.generation_method,
            "evidence": [
                item.to_dict()
                for item in sorted(
                    self.evidence,
                    key=lambda value: (
                        value.evidence_domain,
                        value.contract_type,
                        value.object_id,
                        value.slot_evidence_role,
                        value.role,
                    ),
                )
            ],
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class AssumptionCandidateCompilationResult:
    """In-memory, price-blind output of deterministic Candidate compilation."""

    issuer_id: str
    data_cutoff_date: str
    research_bundle_id: str
    research_bundle_fingerprint: str
    research_bundle_dependency_sha256: str
    phase5c_readiness_fingerprint: str
    supplemental_reference_closure_sha256: str
    assumption_slot_policy_sha256: str
    assumption_evidence_policy_sha256: str
    candidates: tuple[Any, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "candidates",
            tuple(sorted(self.candidates, key=lambda item: item.assumption_slot_id)),
        )
        slots = [item.assumption_slot_id for item in self.candidates]
        if len(slots) != len(set(slots)):
            raise ValueError("Candidate compilation repeats an assumption slot")
        if any(
            item.issuer_id != self.issuer_id
            or item.data_cutoff_date != self.data_cutoff_date
            or item.research_bundle_id != self.research_bundle_id
            or item.research_bundle_fingerprint != self.research_bundle_fingerprint
            or item.research_bundle_dependency_sha256
            != self.research_bundle_dependency_sha256
            or item.supplemental_reference_closure_sha256
            != self.supplemental_reference_closure_sha256
            for item in self.candidates
        ):
            raise ValueError("Candidate compilation context does not replay")

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer_id": self.issuer_id,
            "data_cutoff_date": self.data_cutoff_date,
            "research_bundle_id": self.research_bundle_id,
            "research_bundle_fingerprint": self.research_bundle_fingerprint,
            "research_bundle_dependency_sha256": self.research_bundle_dependency_sha256,
            "phase5c_readiness_fingerprint": self.phase5c_readiness_fingerprint,
            "supplemental_reference_closure_sha256": (
                self.supplemental_reference_closure_sha256
            ),
            "assumption_slot_policy_sha256": self.assumption_slot_policy_sha256,
            "assumption_evidence_policy_sha256": self.assumption_evidence_policy_sha256,
            "candidates": [item.to_dict() for item in self.candidates],
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class AssumptionReviewRequest:
    """Named-human review input; the resolver owns Decision and assumption IDs."""

    candidate_id: str
    candidate_fingerprint: str
    evidence_graph_sha256: str
    decision: str
    reviewer_id: str
    reviewed_at: str
    rationale: str
    issues: tuple[str, ...] = ()
    supersedes_decision_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "issues", tuple(sorted(set(self.issues))))
        if self.decision not in {"confirmed", "blocked", "rejected", "superseded"}:
            raise ValueError("AssumptionReviewRequest decision is invalid")
        if not self.reviewer_id.startswith("human:") or not self.reviewer_id[6:].strip():
            raise ValueError("AssumptionReviewRequest requires a named human reviewer")
        if not self.rationale.strip():
            raise ValueError("AssumptionReviewRequest rationale is required")
        if self.decision in {"blocked", "rejected", "superseded"} and not self.issues:
            raise ValueError("non-confirmed review decisions require issues")
        if self.decision == "superseded" and self.supersedes_decision_id is None:
            raise ValueError("superseded review requires its predecessor Decision")
        if self.decision != "superseded" and self.supersedes_decision_id is not None:
            raise ValueError("only superseded review may cite a predecessor Decision")

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_fingerprint": self.candidate_fingerprint,
            "evidence_graph_sha256": self.evidence_graph_sha256,
            "decision": self.decision,
            "reviewer_id": self.reviewer_id,
            "reviewed_at": self.reviewed_at,
            "rationale": self.rationale,
            "issues": list(self.issues),
            "supersedes_decision_id": self.supersedes_decision_id,
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class AssumptionLedgerCompilationResult:
    """In-memory Phase 5D-2 Decisions plus a pinned-kernel-compatible ledger."""

    issuer_id: str
    data_cutoff_date: str
    research_bundle_id: str
    research_bundle_fingerprint: str
    research_bundle_dependency_sha256: str
    phase5c_readiness_fingerprint: str
    candidate_compilation_fingerprint: str
    supplemental_reference_closure_sha256: str
    decisions: tuple[Any, ...]
    augmented_fact_ledger_payload: FrozenMap
    assumption_ledger_payload: FrozenMap
    assumption_entries_sha256: str
    kernel_assumption_schema_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "decisions",
            tuple(sorted(self.decisions, key=lambda item: item.decision_id)),
        )
        object.__setattr__(
            self,
            "augmented_fact_ledger_payload",
            freeze(self.augmented_fact_ledger_payload),
        )
        object.__setattr__(
            self,
            "assumption_ledger_payload",
            freeze(self.assumption_ledger_payload),
        )
        if len({item.decision_id for item in self.decisions}) != len(self.decisions):
            raise ValueError("Assumption ledger result repeats a Decision ID")
        if self.assumption_entries_sha256 != canonical_sha256(
            to_json_value(self.assumption_ledger_payload)["assumptions"]
        ):
            raise ValueError("Assumption ledger entry hash does not replay")

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer_id": self.issuer_id,
            "data_cutoff_date": self.data_cutoff_date,
            "research_bundle_id": self.research_bundle_id,
            "research_bundle_fingerprint": self.research_bundle_fingerprint,
            "research_bundle_dependency_sha256": self.research_bundle_dependency_sha256,
            "phase5c_readiness_fingerprint": self.phase5c_readiness_fingerprint,
            "candidate_compilation_fingerprint": self.candidate_compilation_fingerprint,
            "supplemental_reference_closure_sha256": (
                self.supplemental_reference_closure_sha256
            ),
            "decisions": [item.to_dict() for item in self.decisions],
            "augmented_fact_ledger_payload": to_json_value(
                self.augmented_fact_ledger_payload
            ),
            "assumption_ledger_payload": to_json_value(self.assumption_ledger_payload),
            "assumption_entries_sha256": self.assumption_entries_sha256,
            "kernel_assumption_schema_sha256": self.kernel_assumption_schema_sha256,
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())
