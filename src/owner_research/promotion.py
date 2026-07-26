from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .contracts import EvidencePromotion, ExtractionCandidate, Fact, FilingArtifact, SourceDocument
from .fingerprints import canonical_sha256
from .units import UnitError, validate_unit_currency

POLICY_ID = "owner-research-evidence-promotion"
POLICY_VERSION = "2.0.0"
AUTO_METHODS = frozenset({"deterministic_table", "deterministic_ixbrl"})
PRIMARY_FORMS = frozenset({"10-K", "10-K/A", "10-Q", "10-Q/A"})
CHECK_NAMES = (
    "primary_regulatory",
    "locator_resolved",
    "hash_resolved",
    "value_resolved",
    "unit_resolved",
    "currency_resolved",
    "period_resolved",
    "duplicates_resolved",
    "reconciliation_resolved",
)


class PromotionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PromotionOutcome:
    promotion: EvidencePromotion
    fact: Fact | None = None


def _checks(
    candidate: ExtractionCandidate,
    source: SourceDocument,
    artifact: FilingArtifact,
    *,
    duplicates_resolved: bool,
    reconciliation_resolved: bool,
) -> dict[str, bool]:
    period = dict(candidate.period)
    unit_resolved = candidate.value_type != "number" or bool(candidate.unit)
    currency_resolved = candidate.value_type != "number"
    if candidate.value_type == "number":
        try:
            validate_unit_currency(candidate.unit, candidate.currency)
            currency_resolved = True
        except UnitError:
            currency_resolved = False
    return {
        "primary_regulatory": source.authority_level == "primary_regulatory"
        and artifact.form in PRIMARY_FORMS,
        "locator_resolved": bool(candidate.locator["value"]),
        "hash_resolved": bool(candidate.locator["excerpt_sha256"])
        and bool(artifact.raw_sha256)
        and bool(artifact.normalized_sha256),
        "value_resolved": candidate.value is not None,
        "unit_resolved": unit_resolved,
        "currency_resolved": currency_resolved,
        "period_resolved": bool(period.get("end")),
        "duplicates_resolved": duplicates_resolved,
        "reconciliation_resolved": reconciliation_resolved,
    }


def evaluate_candidate(
    candidate: ExtractionCandidate,
    *,
    source: SourceDocument,
    artifact: FilingArtifact,
    reviewed_at: str,
    duplicates_resolved: bool = False,
    reconciliation_resolved: bool = False,
    fact_id: str | None = None,
) -> PromotionOutcome:
    if candidate.source_document_id != source.document_id:
        raise PromotionError("candidate/source mismatch")
    if (
        candidate.artifact_id != artifact.artifact_id
        or artifact.source_document_id != source.document_id
    ):
        raise PromotionError("candidate/artifact mismatch")
    checks = _checks(
        candidate,
        source,
        artifact,
        duplicates_resolved=duplicates_resolved,
        reconciliation_resolved=reconciliation_resolved,
    )
    automatic = (
        candidate.candidate_kind == "numeric_fact"
        and candidate.extraction_method in AUTO_METHODS
        and candidate.validation_status == "validated"
        and not candidate.high_impact
        and all(checks.values())
    )
    issues = [name for name, passed in checks.items() if not passed]
    if candidate.extraction_method == "language_model":
        issues.append("language_model_cannot_auto_promote")
    if candidate.high_impact:
        issues.append("high_impact_requires_human_confirmation")
    decision = "auto_fact" if automatic else "blocked"
    resolved_fact_id = (
        fact_id or f"fact:{candidate.issuer_id}:{candidate.candidate_id.split(':')[-1]}"
    )
    promotion = EvidencePromotion(
        schema_version="1.0.0",
        promotion_id=f"promotion:{candidate.issuer_id}:{candidate.candidate_id.split(':')[-1]}",
        issuer_id=candidate.issuer_id,
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=candidate.fingerprint,
        decision=decision,
        output_fact_id=resolved_fact_id if automatic else None,
        output_claim_id=None,
        approval_kind="deterministic_program",
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        checks=checks,
        reviewed_at=reviewed_at,
        reviewer_id=None,
        rationale=(
            "All automatic promotion gates passed."
            if automatic
            else "Candidate remains blocked until every promotion gate is resolved."
        ),
        issues=tuple(sorted(set(issues + list(candidate.validation_issues)))),
    )
    fact = None
    if automatic:
        fact = Fact(
            schema_version="2.0.0",
            fact_id=resolved_fact_id,
            issuer_id=candidate.issuer_id,
            concept=candidate.concept,
            value_type=candidate.value_type,
            value=candidate.value,
            unit=candidate.unit,
            currency=candidate.currency,
            period=candidate.period,
            source_document_id=source.document_id,
            source_locator=f"{candidate.locator['kind']}:{candidate.locator['value']}",
            derivation=(
                f"Promoted by {POLICY_ID} {POLICY_VERSION}; "
                f"candidate fingerprint {candidate.fingerprint}."
            ),
            parent_fact_ids=(),
            confidence="high",
        )
    return PromotionOutcome(promotion=promotion, fact=fact)


def human_disposition(
    candidate: ExtractionCandidate,
    *,
    decision: str,
    output_id: str | None,
    reviewer_id: str,
    reviewed_at: str,
    rationale: str,
    checks: Mapping[str, bool],
    issues: tuple[str, ...] = (),
) -> EvidencePromotion:
    allowed = {"human_confirmed_fact", "human_confirmed_claim", "blocked", "rejected"}
    if decision not in allowed:
        raise PromotionError("human disposition decision is invalid")
    if set(checks) != set(CHECK_NAMES):
        raise PromotionError("human disposition must record every policy check")
    if decision.startswith("human_confirmed") and not output_id:
        raise PromotionError("confirmed human disposition requires an output identifier")
    if decision == "human_confirmed_fact" and candidate.extraction_method == "language_model":
        raise PromotionError("language-model candidates cannot be confirmed as Facts")
    if decision == "human_confirmed_claim" and candidate.candidate_kind not in {
        "claim_draft",
        "narrative_fact",
    }:
        raise PromotionError("numeric Fact candidates must remain Facts, not Claim output")
    if decision in {"blocked", "rejected"} and output_id is not None:
        raise PromotionError("blocked or rejected disposition cannot emit an output")
    promotion_id = (
        f"promotion:{candidate.issuer_id}:"
        f"{canonical_sha256([candidate.candidate_id, reviewed_at])[:20]}"
    )
    return EvidencePromotion(
        schema_version="1.0.0",
        promotion_id=promotion_id,
        issuer_id=candidate.issuer_id,
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=candidate.fingerprint,
        decision=decision,
        output_fact_id=output_id if decision == "human_confirmed_fact" else None,
        output_claim_id=output_id if decision == "human_confirmed_claim" else None,
        approval_kind="human",
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        checks=dict(checks),
        reviewed_at=reviewed_at,
        reviewer_id=reviewer_id,
        rationale=rationale,
        issues=issues,
    )
