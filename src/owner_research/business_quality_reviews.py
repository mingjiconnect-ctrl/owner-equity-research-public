from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date

from .business_quality_policies import MECHANISM_POLICIES
from .contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    BusinessModelSnapshot,
    BusinessQualityReview,
    CalculationResult,
    Claim,
    CompetitiveAdvantageHypothesis,
    CompetitiveContextSnapshot,
    ContextObservation,
)
from .fingerprints import canonical_sha256


class BusinessQualityReviewError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MechanismNotApplicableInput:
    mechanism: str
    claim_id: str


def _same_scope(left: Mapping[str, object], right: Mapping[str, object]) -> bool:
    return canonical_sha256(left) == canonical_sha256(right)


def _hypothesis_claim_ids(hypothesis: CompetitiveAdvantageHypothesis) -> set[str]:
    return {
        *(
            item
            for item in (
                hypothesis.hypothesis_claim_id,
                hypothesis.durability_claim_id,
                hypothesis.reinvestment_claim_id,
                hypothesis.trend_claim_id,
            )
            if item is not None
        ),
        *hypothesis.counterevidence_claim_ids,
        *(
            item["resolution_claim_id"]
            for item in hypothesis.counterevidence_resolutions
            if item["resolution_claim_id"] is not None
        ),
    }


def _business_model_claim_ids(
    business_model: BusinessModelSnapshot, scope_id: str
) -> set[str]:
    claim_ids: set[str] = set()
    component_ids = {
        item["component_id"]
        for item in business_model.components
        if item["scope_id"] == scope_id
    }
    for relation in business_model.shared_scope_relations:
        if scope_id in relation["covered_scope_ids"]:
            component_ids.add(relation["component_id"])
            claim_ids.add(relation["claim_id"])
    for component in business_model.components:
        if component["component_id"] in component_ids:
            claim_ids.update(component["claim_ids"])
    for coverage in business_model.component_coverage:
        if coverage["scope_id"] == scope_id:
            claim_ids.update(coverage["claim_ids"])
    for material_scope in business_model.material_scopes:
        if material_scope["scope_id"] == scope_id and (
            material_scope["materiality_claim_id"] is not None
        ):
            claim_ids.add(material_scope["materiality_claim_id"])
    return claim_ids


def build_business_quality_review(
    *,
    issuer_id: str,
    review_period: Mapping[str, str],
    as_of_date: str,
    scope: Mapping[str, object],
    business_models: tuple[BusinessModelSnapshot, ...],
    competitive_contexts: tuple[CompetitiveContextSnapshot, ...],
    hypotheses: tuple[CompetitiveAdvantageHypothesis, ...],
    claims: tuple[Claim, ...],
    analytical_candidates: tuple[AnalyticalClaimCandidate, ...],
    claim_review_decisions: tuple[AnalyticalClaimReviewDecision, ...],
    observations: tuple[ContextObservation, ...],
    calculations: tuple[CalculationResult, ...],
    not_applicable_inputs: tuple[MechanismNotApplicableInput, ...] = (),
    explicit_missing_evidence: tuple[str, ...] = (),
) -> BusinessQualityReview:
    review_start = date.fromisoformat(review_period["start"])
    review_end = date.fromisoformat(review_period["end"])
    cutoff = date.fromisoformat(as_of_date)
    if review_start > review_end or review_end > cutoff:
        raise BusinessQualityReviewError("invalid BusinessQualityReview period or cutoff")

    eligible_contexts = [
        item
        for item in competitive_contexts
        if item.issuer_id == issuer_id
        and date.fromisoformat(item.as_of_date) <= cutoff
        and _same_scope(item.scope, scope)
    ]
    if not eligible_contexts:
        raise BusinessQualityReviewError("no eligible competitive-context snapshot")
    competitive_context = max(
        eligible_contexts, key=lambda item: (item.as_of_date, item.context_snapshot_id)
    )

    eligible_models: list[tuple[BusinessModelSnapshot, str]] = []
    for model in business_models:
        if model.issuer_id != issuer_id or date.fromisoformat(model.as_of_date) > cutoff:
            continue
        matching_scope_ids = [
            item["scope_id"]
            for item in model.material_scopes
            if _same_scope(item["scope"], scope)
        ]
        if len(matching_scope_ids) == 1:
            eligible_models.append((model, matching_scope_ids[0]))
    if not eligible_models:
        raise BusinessQualityReviewError("no eligible business-model snapshot")
    business_model, scope_id = max(
        eligible_models, key=lambda item: (item[0].as_of_date, item[0].snapshot_id)
    )

    eligible_hypotheses = [
        item
        for item in hypotheses
        if item.issuer_id == issuer_id
        and item.business_model_snapshot_id == business_model.snapshot_id
        and item.competitive_context_snapshot_id == competitive_context.context_snapshot_id
        and _same_scope(item.scope, scope)
        and date.fromisoformat(item.as_of_date) <= cutoff
        and date.fromisoformat(item.assessment_period["start"]) <= review_end
        and date.fromisoformat(item.assessment_period["end"]) >= review_start
    ]
    latest_hypotheses: dict[str, CompetitiveAdvantageHypothesis] = {}
    for hypothesis in eligible_hypotheses:
        current = latest_hypotheses.get(hypothesis.mechanism)
        if current is None or (
            hypothesis.as_of_date,
            hypothesis.assessment_period["end"],
            hypothesis.hypothesis_id,
        ) > (
            current.as_of_date,
            current.assessment_period["end"],
            current.hypothesis_id,
        ):
            latest_hypotheses[hypothesis.mechanism] = hypothesis

    claims_by_id = {item.claim_id: item for item in claims if item.issuer_id == issuer_id}
    candidates_by_id = {
        item.candidate_id: item
        for item in analytical_candidates
        if item.issuer_id == issuer_id
    }
    decisions_by_claim = {
        item.output_claim_id: item
        for item in claim_review_decisions
        if item.issuer_id == issuer_id
        and item.decision == "confirmed"
        and item.output_claim_id is not None
    }

    def reviewed_candidate(claim_id: str) -> AnalyticalClaimCandidate:
        try:
            claim = claims_by_id[claim_id]
            decision = decisions_by_claim[claim_id]
            candidate = candidates_by_id[decision.candidate_id]
        except KeyError as exc:
            raise BusinessQualityReviewError(
                "review Claim lacks a confirmed analytical decision"
            ) from exc
        if (
            decision.candidate_fingerprint != candidate.fingerprint
            or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
            or date.fromisoformat(claim.as_of_date) > cutoff
        ):
            raise BusinessQualityReviewError(
                "review Claim no longer matches its analytical decision"
            )
        return candidate

    not_applicable_by_mechanism: dict[str, str] = {}
    for item in not_applicable_inputs:
        if item.mechanism not in MECHANISM_POLICIES:
            raise BusinessQualityReviewError("unknown not-applicable mechanism")
        if item.mechanism in not_applicable_by_mechanism:
            raise BusinessQualityReviewError("duplicate not-applicable mechanism")
        candidate = reviewed_candidate(item.claim_id)
        if (
            candidate.claim_role != "not_applicable"
            or not _same_scope(candidate.scope, scope)
            or candidate.business_attribute_role is not None
            or candidate.business_component_type is not None
        ):
            raise BusinessQualityReviewError(
                "not-applicable mechanism Claim role or scope mismatch"
            )
        not_applicable_by_mechanism[item.mechanism] = item.claim_id

    missing = set(explicit_missing_evidence)
    mechanism_coverage = []
    selected_claim_ids = _business_model_claim_ids(business_model, scope_id)
    selected_claim_ids.update(competitive_context.competitor_selection_claim_ids)
    for item in competitive_context.coverage:
        selected_claim_ids.update(item["claim_ids"])
    for mechanism in sorted(MECHANISM_POLICIES):
        hypothesis = latest_hypotheses.get(mechanism)
        not_applicable_claim_id = not_applicable_by_mechanism.get(mechanism)
        if hypothesis is not None and not_applicable_claim_id is not None:
            raise BusinessQualityReviewError(
                "mechanism cannot be both hypothesized and not-applicable"
            )
        if hypothesis is not None:
            mechanism_claim_ids = _hypothesis_claim_ids(hypothesis)
            selected_claim_ids.update(mechanism_claim_ids)
            if hypothesis.status == "blocked":
                status = "blocked"
                mechanism_missing = hypothesis.missing_evidence or (
                    f"{mechanism} hypothesis is blocked",
                )
                missing.update(mechanism_missing)
            else:
                status = "reviewed"
                mechanism_missing = ()
            hypothesis_ids = (hypothesis.hypothesis_id,)
            coverage_claim_ids = tuple(sorted(mechanism_claim_ids))
        elif not_applicable_claim_id is not None:
            status = "not_applicable"
            hypothesis_ids = ()
            coverage_claim_ids = (not_applicable_claim_id,)
            mechanism_missing = ()
            selected_claim_ids.add(not_applicable_claim_id)
        else:
            status = "blocked"
            hypothesis_ids = ()
            coverage_claim_ids = ()
            mechanism_missing = (f"{mechanism} review is missing",)
            missing.update(mechanism_missing)
        mechanism_coverage.append(
            {
                "mechanism": mechanism,
                "status": status,
                "hypothesis_ids": hypothesis_ids,
                "claim_ids": coverage_claim_ids,
                "missing_evidence": mechanism_missing,
            }
        )

    for claim_id in selected_claim_ids:
        reviewed_candidate(claim_id)
    decision_ids = tuple(
        sorted(decisions_by_claim[claim_id].decision_id for claim_id in selected_claim_ids)
    )

    observations_by_id = {
        item.observation_id: item
        for item in observations
        if item.target_issuer_id == issuer_id
    }
    selected_observation_ids = set(competitive_context.observation_ids)
    selected_calculation_ids: set[str] = set()
    for hypothesis in latest_hypotheses.values():
        for binding in hypothesis.evidence_bindings:
            if binding["context_observation_id"] is not None:
                selected_observation_ids.add(binding["context_observation_id"])
            if binding["calculation_result_id"] is not None:
                selected_calculation_ids.add(binding["calculation_result_id"])
    if not selected_observation_ids.issubset(observations_by_id):
        raise BusinessQualityReviewError("review ContextObservation is missing")
    calculations_by_id = {
        item.calculation_id: item
        for item in calculations
        if item.issuer_id == issuer_id
    }
    if not selected_calculation_ids.issubset(calculations_by_id):
        raise BusinessQualityReviewError("review CalculationResult is missing")

    scope_component_coverage = [
        item for item in business_model.component_coverage if item["scope_id"] == scope_id
    ]
    selected_hypotheses = tuple(
        sorted(latest_hypotheses.values(), key=lambda item: item.hypothesis_id)
    )
    coverage = {
        "reviewed_component_count": sum(
            item["status"] == "reviewed" for item in scope_component_coverage
        ),
        "not_applicable_component_count": sum(
            item["status"] == "not_applicable" for item in scope_component_coverage
        ),
        "blocked_component_count": sum(
            item["status"] == "blocked" for item in scope_component_coverage
        ),
        **{
            f"{status}_hypothesis_count": sum(
                item.status == status for item in selected_hypotheses
            )
            for status in ("proposed", "supported", "contested", "falsified", "blocked")
        },
        **{
            f"{trend}_count": sum(item.trend == trend for item in selected_hypotheses)
            for trend in ("strengthening", "stable", "eroding")
        },
        "unknown_trend_count": sum(
            item.trend == "unknown" for item in selected_hypotheses
        ),
        "confirmed_claim_count": len(selected_claim_ids),
        "unresolved_counterevidence_count": sum(
            item["status"] in {"unresolved", "blocked"}
            for hypothesis in selected_hypotheses
            for item in hypothesis.counterevidence_resolutions
        ),
    }

    if business_model.status != "complete":
        missing.update(business_model.missing_evidence or ("business model incomplete",))
    if competitive_context.status != "complete":
        missing.update(
            competitive_context.missing_evidence or ("competitive context incomplete",)
        )
    critical = (
        business_model.status == "blocked"
        or competitive_context.status == "blocked"
        or not selected_claim_ids
    )
    partial = (
        business_model.status != "complete"
        or competitive_context.status != "complete"
        or any(item["status"] == "blocked" for item in scope_component_coverage)
        or any(item["status"] == "blocked" for item in competitive_context.coverage)
        or any(item["status"] == "blocked" for item in mechanism_coverage)
        or bool(missing)
    )
    if critical:
        status = "blocked"
        missing.add("business-quality review has a critical evidence gap")
    elif partial:
        status = "partial"
    else:
        status = "complete"

    identity = canonical_sha256(
        {
            "issuer_id": issuer_id,
            "review_period": review_period,
            "as_of_date": as_of_date,
            "scope": scope,
            "business_model_snapshot_id": business_model.snapshot_id,
            "competitive_context_snapshot_id": competitive_context.context_snapshot_id,
            "hypothesis_ids": [item.hypothesis_id for item in selected_hypotheses],
        }
    )[:20]
    return BusinessQualityReview(
        schema_version="2.0.0",
        review_id=f"business-quality-review:{issuer_id}:{identity}",
        issuer_id=issuer_id,
        review_period=dict(review_period),
        as_of_date=as_of_date,
        status=status,
        business_model_snapshot_id=business_model.snapshot_id,
        competitive_context_snapshot_id=competitive_context.context_snapshot_id,
        hypothesis_ids=tuple(item.hypothesis_id for item in selected_hypotheses),
        mechanism_coverage=tuple(mechanism_coverage),
        claim_ids=tuple(sorted(selected_claim_ids)),
        analytical_claim_review_decision_ids=decision_ids,
        context_observation_ids=tuple(sorted(selected_observation_ids)),
        calculation_result_ids=tuple(sorted(selected_calculation_ids)),
        coverage=coverage,
        missing_evidence=tuple(sorted(missing)),
    )
