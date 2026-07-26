from __future__ import annotations

from collections.abc import Mapping

from .contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    Claim,
)
from .fingerprints import canonical_sha256


class AnalyticalClaimReviewError(ValueError):
    pass


def _direct_fact_ids(bindings: tuple[Mapping[str, object], ...]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(binding["fact_id"])
                for binding in bindings
                if binding["fact_id"] is not None
            }
        )
    )


def review_analytical_claim_candidate(
    candidate: AnalyticalClaimCandidate,
    *,
    decision: str,
    reviewer_id: str,
    reviewed_at: str,
    rationale: str,
    issues: tuple[str, ...] = (),
) -> tuple[Claim | None, AnalyticalClaimReviewDecision]:
    """Apply a named human decision; a language model can only author the Candidate."""
    if decision not in {"confirmed", "blocked", "rejected"}:
        raise AnalyticalClaimReviewError("unsupported analytical review decision")
    if not reviewer_id.strip() or not rationale.strip():
        raise AnalyticalClaimReviewError(
            "analytical review requires a named reviewer and rationale"
        )
    expected_graph = canonical_sha256(
        {
            "supporting_evidence_bindings": candidate.supporting_evidence_bindings,
            "counterevidence_bindings": candidate.counterevidence_bindings,
        }
    )
    if candidate.evidence_graph_sha256 != expected_graph:
        raise AnalyticalClaimReviewError("Candidate evidence graph hash mismatch")
    if decision == "confirmed" and candidate.validation_status != "ready":
        raise AnalyticalClaimReviewError("only a ready Candidate can be confirmed")
    if decision != "confirmed" and not issues:
        raise AnalyticalClaimReviewError("blocked or rejected review requires issues")

    claim: Claim | None = None
    output_claim_id: str | None = None
    if decision == "confirmed":
        supporting_fact_ids = _direct_fact_ids(candidate.supporting_evidence_bindings)
        if not supporting_fact_ids:
            raise AnalyticalClaimReviewError(
                "confirmed analytical Claim requires direct target-company Fact support"
            )
        counterevidence_fact_ids = _direct_fact_ids(candidate.counterevidence_bindings)
        identity = canonical_sha256(
            {
                "candidate_id": candidate.candidate_id,
                "candidate_fingerprint": candidate.fingerprint,
                "evidence_graph_sha256": candidate.evidence_graph_sha256,
            }
        )[:20]
        output_claim_id = f"claim:{candidate.issuer_id}:analytical:{identity}"
        claim = Claim(
            schema_version="1.0.0",
            claim_id=output_claim_id,
            issuer_id=candidate.issuer_id,
            statement=candidate.proposed_statement,
            as_of_date=candidate.as_of_date,
            supporting_fact_ids=supporting_fact_ids,
            counterevidence_fact_ids=counterevidence_fact_ids,
            counterevidence_search_note=candidate.counterevidence_search_note,
            confidence=candidate.proposed_confidence,
            falsification_condition=candidate.falsification_condition,
        )
    decision_identity = canonical_sha256(
        {
            "candidate_fingerprint": candidate.fingerprint,
            "decision": decision,
            "reviewer_id": reviewer_id,
            "reviewed_at": reviewed_at,
        }
    )[:20]
    review = AnalyticalClaimReviewDecision(
        schema_version="1.0.0",
        decision_id=f"analytical-review:{candidate.issuer_id}:{decision_identity}",
        issuer_id=candidate.issuer_id,
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=candidate.fingerprint,
        evidence_graph_sha256=candidate.evidence_graph_sha256,
        decision=decision,
        output_claim_id=output_claim_id,
        reviewer_id=reviewer_id,
        reviewed_at=reviewed_at,
        rationale=rationale,
        issues=issues,
    )
    return claim, review
