from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date

from .business_quality_policies import POLICY_VERSION, mechanism_policy
from .contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    BusinessModelSnapshot,
    CalculationResult,
    Claim,
    CompetitiveAdvantageHypothesis,
    CompetitiveContextSnapshot,
    ContextObservation,
    Fact,
    SegmentSnapshot,
    SourceDocument,
)
from .fingerprints import canonical_sha256

OFFICIAL_AUTHORITY_LEVELS = frozenset({"primary_regulatory", "company_primary"})


class CompetitiveAdvantageResolutionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CounterevidenceResolutionInput:
    counterevidence_claim_id: str
    status: str
    resolution_claim_id: str | None = None


def _binding_reference(binding: Mapping[str, object]) -> tuple[str, str]:
    references = [
        (kind, str(binding[field]))
        for kind, field in (
            ("fact", "fact_id"),
            ("calculation", "calculation_result_id"),
            ("observation", "context_observation_id"),
        )
        if binding[field] is not None
    ]
    if len(references) != 1:
        raise CompetitiveAdvantageResolutionError(
            "evidence binding must reference exactly one evidence object"
        )
    return references[0]


def _candidate_references(candidate: AnalyticalClaimCandidate) -> set[tuple[str, str]]:
    return {
        _binding_reference(binding)
        for binding in (
            *candidate.supporting_evidence_bindings,
            *candidate.counterevidence_bindings,
        )
    }


def _calculation_fact_ids(
    calculation_id: str,
    calculations: Mapping[str, CalculationResult],
    seen: set[str] | None = None,
) -> set[str]:
    visited = set() if seen is None else seen
    if calculation_id in visited:
        raise CompetitiveAdvantageResolutionError("calculation dependency cycle")
    try:
        calculation = calculations[calculation_id]
    except KeyError as exc:
        raise CompetitiveAdvantageResolutionError("calculation evidence is missing") from exc
    visited.add(calculation_id)
    fact_ids = set(calculation.input_fact_ids)
    for dependency in calculation.input_calculation_ids:
        fact_ids.update(_calculation_fact_ids(dependency, calculations, visited))
    visited.remove(calculation_id)
    return fact_ids


def _confirmed_decisions(
    candidates: Mapping[str, AnalyticalClaimCandidate],
    decisions: tuple[AnalyticalClaimReviewDecision, ...],
    claims: Mapping[str, Claim],
) -> dict[str, AnalyticalClaimReviewDecision]:
    confirmed: dict[str, AnalyticalClaimReviewDecision] = {}
    for decision in decisions:
        if decision.decision != "confirmed" or decision.output_claim_id is None:
            continue
        try:
            candidate = candidates[decision.candidate_id]
            claim = claims[decision.output_claim_id]
        except KeyError as exc:
            raise CompetitiveAdvantageResolutionError(
                "confirmed analytical review references missing evidence"
            ) from exc
        if (
            candidate.validation_status != "ready"
            or decision.issuer_id != candidate.issuer_id
            or decision.candidate_fingerprint != candidate.fingerprint
            or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
            or claim.issuer_id != candidate.issuer_id
        ):
            raise CompetitiveAdvantageResolutionError(
                "confirmed analytical review no longer matches its evidence graph"
            )
        expected_graph = canonical_sha256(
            {
                "supporting_evidence_bindings": candidate.supporting_evidence_bindings,
                "counterevidence_bindings": candidate.counterevidence_bindings,
            }
        )
        supporting_facts = {
            str(item["fact_id"])
            for item in candidate.supporting_evidence_bindings
            if item["fact_id"] is not None
        }
        counter_facts = {
            str(item["fact_id"])
            for item in candidate.counterevidence_bindings
            if item["fact_id"] is not None
        }
        if (
            candidate.evidence_graph_sha256 != expected_graph
            or not supporting_facts
            or set(claim.supporting_fact_ids) != supporting_facts
            or set(claim.counterevidence_fact_ids) != counter_facts
            or claim.statement != candidate.proposed_statement
            or claim.as_of_date != candidate.as_of_date
            or claim.confidence != candidate.proposed_confidence
            or claim.falsification_condition != candidate.falsification_condition
            or claim.counterevidence_search_note != candidate.counterevidence_search_note
        ):
            raise CompetitiveAdvantageResolutionError(
                "confirmed analytical Claim does not reproduce its reviewed Candidate"
            )
        if claim.claim_id in confirmed:
            raise CompetitiveAdvantageResolutionError(
                "one analytical Claim has multiple confirmed decisions"
            )
        confirmed[claim.claim_id] = decision
    return confirmed


def _scope_is_material(
    business_model: BusinessModelSnapshot, scope: Mapping[str, object]
) -> bool:
    return any(_same_scope(item["scope"], scope) for item in business_model.material_scopes)


def _same_scope(left: Mapping[str, object], right: Mapping[str, object]) -> bool:
    return canonical_sha256(left) == canonical_sha256(right)


def _require_fact_scope(
    fact_ids: set[str],
    *,
    issuer_id: str,
    scope: Mapping[str, object],
    business_model: BusinessModelSnapshot,
    segment_snapshots: tuple[SegmentSnapshot, ...],
) -> None:
    scope_type = scope["scope_type"]
    if scope_type == "issuer_wide":
        return
    if scope_type == "product_market":
        raise CompetitiveAdvantageResolutionError(
            "product-market Facts lack a deterministic scope mapping"
        )
    segment_ids = set(scope["segment_definition_ids"])
    eligible_snapshots = {
        snapshot.snapshot_id: snapshot
        for snapshot in segment_snapshots
        if snapshot.snapshot_id in business_model.segment_snapshot_ids
        and snapshot.issuer_id == issuer_id
    }
    assigned_fact_ids = {
        str(assignment["fact_id"])
        for snapshot in eligible_snapshots.values()
        for assignment in snapshot.metric_assignments
        if assignment["segment_id"] in segment_ids
    }
    if not segment_ids or not fact_ids.issubset(assigned_fact_ids):
        raise CompetitiveAdvantageResolutionError(
            "Fact evidence is not assigned to the declared segment scope"
        )


def resolve_competitive_advantage_hypothesis(
    *,
    issuer_id: str,
    as_of_date: str,
    assessment_period: Mapping[str, str],
    mechanism: str,
    scope: Mapping[str, object],
    business_model: BusinessModelSnapshot,
    competitive_context: CompetitiveContextSnapshot,
    documents: tuple[SourceDocument, ...],
    facts: tuple[Fact, ...],
    calculations: tuple[CalculationResult, ...],
    observations: tuple[ContextObservation, ...],
    segment_snapshots: tuple[SegmentSnapshot, ...],
    claims: tuple[Claim, ...],
    analytical_candidates: tuple[AnalyticalClaimCandidate, ...],
    claim_review_decisions: tuple[AnalyticalClaimReviewDecision, ...],
    evidence_bindings: tuple[Mapping[str, object], ...],
    hypothesis_claim_id: str | None,
    durability_claim_id: str | None,
    reinvestment_claim_id: str | None,
    reinvestment_relevance: str,
    counterevidence_resolutions: tuple[CounterevidenceResolutionInput, ...] = (),
    predecessor: CompetitiveAdvantageHypothesis | None = None,
    trend_claim_id: str | None = None,
) -> CompetitiveAdvantageHypothesis:
    """Resolve status and trend from reviewed evidence; neither is caller supplied."""
    try:
        policy = mechanism_policy(mechanism)
    except KeyError as exc:
        raise CompetitiveAdvantageResolutionError("unregistered mechanism policy") from exc
    cutoff = date.fromisoformat(as_of_date)
    if date.fromisoformat(assessment_period["end"]) > cutoff:
        raise CompetitiveAdvantageResolutionError("assessment period follows cutoff")
    if business_model.issuer_id != issuer_id or competitive_context.issuer_id != issuer_id:
        raise CompetitiveAdvantageResolutionError("business-quality issuer mismatch")
    if (
        date.fromisoformat(business_model.as_of_date) > cutoff
        or date.fromisoformat(competitive_context.as_of_date) > cutoff
    ):
        raise CompetitiveAdvantageResolutionError("business-quality input follows cutoff")
    if not _same_scope(competitive_context.scope, scope):
        raise CompetitiveAdvantageResolutionError("competitive-context scope mismatch")
    if len({str(binding["binding_id"]) for binding in evidence_bindings}) != len(
        evidence_bindings
    ):
        raise CompetitiveAdvantageResolutionError("duplicate evidence binding id")

    documents_by_id = {item.document_id: item for item in documents}
    facts_by_id = {item.fact_id: item for item in facts}
    calculations_by_id = {item.calculation_id: item for item in calculations}
    observations_by_id = {item.observation_id: item for item in observations}
    claims_by_id = {item.claim_id: item for item in claims}
    candidates_by_id = {item.candidate_id: item for item in analytical_candidates}
    decisions_by_claim = _confirmed_decisions(
        candidates_by_id, claim_review_decisions, claims_by_id
    )

    role_polarities: dict[str, set[str]] = {"support": set(), "counterevidence": set()}
    binding_references: dict[str, tuple[str, str]] = {}
    evidence_document_ids: set[str] = set()
    forbidden_matches: set[str] = set()
    for binding in evidence_bindings:
        binding_id = str(binding["binding_id"])
        role_id = str(binding["role_id"])
        polarity = str(binding["polarity"])
        if role_id not in policy.allowed_roles:
            raise CompetitiveAdvantageResolutionError("unregistered mechanism evidence role")
        expected_polarity = (
            "support" if role_id in policy.support_roles else "counterevidence"
        )
        if polarity != expected_polarity:
            raise CompetitiveAdvantageResolutionError("mechanism evidence polarity mismatch")
        kind, reference = _binding_reference(binding)
        binding_references[binding_id] = (kind, reference)
        role_polarities[polarity].add(role_id)
        if kind == "fact":
            try:
                fact = facts_by_id[reference]
                document = documents_by_id[fact.source_document_id]
            except KeyError as exc:
                raise CompetitiveAdvantageResolutionError("Fact evidence is missing") from exc
            if fact.issuer_id != issuer_id or document.issuer_id != issuer_id:
                raise CompetitiveAdvantageResolutionError("Fact evidence issuer mismatch")
            _require_fact_scope(
                {fact.fact_id},
                issuer_id=issuer_id,
                scope=scope,
                business_model=business_model,
                segment_snapshots=segment_snapshots,
            )
            if date.fromisoformat(document.published_date) > cutoff:
                raise CompetitiveAdvantageResolutionError("Fact evidence follows cutoff")
            evidence_document_ids.add(document.document_id)
            forbidden_matches.update(
                item for item in policy.forbidden_single_indicators if item in fact.concept.lower()
            )
        elif kind == "calculation":
            try:
                calculation = calculations_by_id[reference]
            except KeyError as exc:
                raise CompetitiveAdvantageResolutionError(
                    "CalculationResult evidence is missing"
                ) from exc
            if calculation.issuer_id != issuer_id or calculation.input_assumption_ids:
                raise CompetitiveAdvantageResolutionError(
                    "mechanism calculation is cross-issuer or assumption-based"
                )
            forbidden_matches.update(
                item
                for item in policy.forbidden_single_indicators
                if item in calculation.concept.lower()
            )
            calculation_fact_ids = _calculation_fact_ids(reference, calculations_by_id)
            _require_fact_scope(
                calculation_fact_ids,
                issuer_id=issuer_id,
                scope=scope,
                business_model=business_model,
                segment_snapshots=segment_snapshots,
            )
            for fact_id in calculation_fact_ids:
                try:
                    fact = facts_by_id[fact_id]
                    document = documents_by_id[fact.source_document_id]
                except KeyError as exc:
                    raise CompetitiveAdvantageResolutionError(
                        "CalculationResult source Fact is missing"
                    ) from exc
                if fact.issuer_id != issuer_id or document.issuer_id != issuer_id:
                    raise CompetitiveAdvantageResolutionError(
                        "CalculationResult source Fact issuer mismatch"
                    )
                if date.fromisoformat(document.published_date) > cutoff:
                    raise CompetitiveAdvantageResolutionError(
                        "CalculationResult evidence follows cutoff"
                    )
                evidence_document_ids.add(document.document_id)
        else:
            try:
                observation = observations_by_id[reference]
                document = documents_by_id[observation.source_document_id]
            except KeyError as exc:
                raise CompetitiveAdvantageResolutionError(
                    "ContextObservation evidence is missing"
                ) from exc
            if observation.target_issuer_id != issuer_id:
                raise CompetitiveAdvantageResolutionError(
                    "ContextObservation target issuer mismatch"
                )
            if not _same_scope(observation.scope, scope):
                raise CompetitiveAdvantageResolutionError(
                    "ContextObservation scope mismatch"
                )
            if (
                date.fromisoformat(observation.as_of_date) > cutoff
                or date.fromisoformat(document.published_date) > cutoff
            ):
                raise CompetitiveAdvantageResolutionError(
                    "ContextObservation evidence follows cutoff"
                )
            evidence_document_ids.add(document.document_id)
    if forbidden_matches:
        raise CompetitiveAdvantageResolutionError("forbidden single-indicator shortcut")

    positive_claim_ids = tuple(
        item
        for item in (hypothesis_claim_id, durability_claim_id, reinvestment_claim_id)
        if item is not None
    )
    all_evidence_references = set(binding_references.values())
    for claim_id in positive_claim_ids:
        if claim_id not in claims_by_id or claim_id not in decisions_by_claim:
            raise CompetitiveAdvantageResolutionError(
                "positive hypothesis Claim lacks confirmed analytical review"
            )
        if claims_by_id[claim_id].issuer_id != issuer_id:
            raise CompetitiveAdvantageResolutionError("positive hypothesis Claim issuer mismatch")
        decision = decisions_by_claim[claim_id]
        candidate = candidates_by_id[decision.candidate_id]
        if (
            date.fromisoformat(claims_by_id[claim_id].as_of_date) > cutoff
            or not _same_scope(candidate.scope, scope)
            or not _candidate_references(candidate).issubset(all_evidence_references)
            or candidate.claim_role != "support"
        ):
            raise CompetitiveAdvantageResolutionError(
                "positive hypothesis Claim evidence, cutoff, or scope mismatch"
            )
    if len(positive_claim_ids) != len(set(positive_claim_ids)):
        raise CompetitiveAdvantageResolutionError("positive hypothesis Claims must be distinct")

    counter_references = {
        reference
        for binding_id, reference in binding_references.items()
        if next(
            str(item["polarity"])
            for item in evidence_bindings
            if str(item["binding_id"]) == binding_id
        )
        == "counterevidence"
    }
    counterevidence_claim_ids: set[str] = set()
    counter_claim_roles: dict[str, str] = {}
    reviewed_counter_references: set[tuple[str, str]] = set()
    for claim_id, decision in decisions_by_claim.items():
        candidate = candidates_by_id[decision.candidate_id]
        if (
            candidate.issuer_id == issuer_id
            and _same_scope(candidate.scope, scope)
            and candidate.claim_role in {"counterevidence", "falsification"}
        ):
            references = _candidate_references(candidate)
            if references and references.issubset(counter_references):
                if date.fromisoformat(candidate.as_of_date) > cutoff:
                    raise CompetitiveAdvantageResolutionError(
                        "counterevidence Claim follows cutoff"
                    )
                counterevidence_claim_ids.add(claim_id)
                counter_claim_roles[claim_id] = candidate.claim_role
                reviewed_counter_references.update(references)
    missing_counter_review = bool(counter_references - reviewed_counter_references)

    resolutions = {item.counterevidence_claim_id: item for item in counterevidence_resolutions}
    if len(resolutions) != len(counterevidence_resolutions):
        raise CompetitiveAdvantageResolutionError("duplicate counterevidence resolution")
    if set(resolutions) != counterevidence_claim_ids:
        raise CompetitiveAdvantageResolutionError(
            "counterevidence resolutions must preserve every reviewed counter Claim"
        )
    resolution_payloads = []
    for claim_id in sorted(resolutions):
        item = resolutions[claim_id]
        if item.status not in {"unresolved", "resolved", "falsifying", "blocked"}:
            raise CompetitiveAdvantageResolutionError("invalid counterevidence resolution status")
        if item.status == "falsifying" and counter_claim_roles[claim_id] != "falsification":
            raise CompetitiveAdvantageResolutionError(
                "falsifying status requires a reviewed falsification Claim"
            )
        if item.status == "resolved" and item.resolution_claim_id is None:
            raise CompetitiveAdvantageResolutionError(
                "resolved counterevidence requires a reviewed resolution Claim"
            )
        if item.resolution_claim_id is not None and (
            item.resolution_claim_id not in claims_by_id
            or item.resolution_claim_id not in decisions_by_claim
        ):
            raise CompetitiveAdvantageResolutionError(
                "counterevidence resolution Claim lacks confirmed review"
            )
        if item.resolution_claim_id is not None:
            resolution_decision = decisions_by_claim[item.resolution_claim_id]
            resolution_candidate = candidates_by_id[resolution_decision.candidate_id]
            if not _same_scope(resolution_candidate.scope, scope):
                raise CompetitiveAdvantageResolutionError(
                    "counterevidence resolution Claim scope mismatch"
                )
            if date.fromisoformat(resolution_candidate.as_of_date) > cutoff:
                raise CompetitiveAdvantageResolutionError(
                    "counterevidence resolution Claim follows cutoff"
                )
        resolution_payloads.append(
            {
                "counterevidence_claim_id": claim_id,
                "status": item.status,
                "resolution_claim_id": item.resolution_claim_id,
            }
        )

    if predecessor is not None:
        if (
            predecessor.issuer_id != issuer_id
            or predecessor.mechanism != mechanism
            or not _same_scope(predecessor.scope, scope)
            or date.fromisoformat(predecessor.assessment_period["end"])
            >= date.fromisoformat(assessment_period["start"])
        ):
            raise CompetitiveAdvantageResolutionError("predecessor is not comparable")
        prior_counter_bindings = {
            str(item["binding_id"])
            for item in predecessor.evidence_bindings
            if item["polarity"] == "counterevidence"
        }
        current_counter_bindings = {
            str(item["binding_id"])
            for item in evidence_bindings
            if item["polarity"] == "counterevidence"
        }
        if not prior_counter_bindings.issubset(current_counter_bindings) or not set(
            predecessor.counterevidence_claim_ids
        ).issubset(counterevidence_claim_ids):
            raise CompetitiveAdvantageResolutionError(
                "predecessor counterevidence cannot be deleted"
            )

    missing: list[str] = []
    scope_closed = (
        business_model.status == "complete"
        and competitive_context.status == "complete"
        and _scope_is_material(business_model, scope)
    )
    if not scope_closed:
        missing.append("Business-model or competitive-context scope is incomplete")
    if hypothesis_claim_id is None:
        missing.append("Core hypothesis Claim is missing")
    if missing_counter_review:
        missing.append("Counterevidence binding lacks a reviewed counter Claim")
    if any(item.status == "blocked" for item in counterevidence_resolutions):
        missing.append("Counterevidence resolution is blocked")

    has_three_positive_claims = len(positive_claim_ids) == 3
    falsifying = any(item.status == "falsifying" for item in counterevidence_resolutions)
    unresolved = any(item.status == "unresolved" for item in counterevidence_resolutions)
    selected_documents = [documents_by_id[item] for item in evidence_document_ids]
    source_diverse = any(
        item.issuer_id == issuer_id and item.authority_level in OFFICIAL_AUTHORITY_LEVELS
        for item in selected_documents
    ) and any(
        item.issuer_id != issuer_id
        and item.authority_level in {*OFFICIAL_AUTHORITY_LEVELS, "audited_secondary"}
        for item in selected_documents
    )
    policy_roles_complete = (
        role_polarities["support"] == policy.support_roles
        and role_polarities["counterevidence"] == policy.counterevidence_roles
    )
    if missing:
        status = "blocked"
    elif falsifying and has_three_positive_claims:
        status = "falsified"
    elif unresolved and has_three_positive_claims:
        status = "contested"
    elif (
        has_three_positive_claims
        and policy_roles_complete
        and source_diverse
        and all(item.status == "resolved" for item in counterevidence_resolutions)
        and reinvestment_relevance in {"direct", "indirect"}
    ):
        status = "supported"
    else:
        status = "proposed"

    trend = "unknown"
    validated_trend_claim_id: str | None = None
    if trend_claim_id is not None:
        if predecessor is None or trend_claim_id not in decisions_by_claim:
            raise CompetitiveAdvantageResolutionError(
                "trend Claim lacks a comparable predecessor or confirmed review"
            )
        trend_decision = decisions_by_claim[trend_claim_id]
        trend_candidate = candidates_by_id[trend_decision.candidate_id]
        if (
            trend_candidate.claim_role not in {"strengthening", "stable", "eroding"}
            or not _same_scope(trend_candidate.scope, scope)
            or date.fromisoformat(trend_candidate.as_of_date) > cutoff
        ):
            raise CompetitiveAdvantageResolutionError("trend Claim role or scope mismatch")
        trend = trend_candidate.claim_role
        validated_trend_claim_id = trend_claim_id

    used_claim_ids = {
        *positive_claim_ids,
        *counterevidence_claim_ids,
        *(
            item.resolution_claim_id
            for item in counterevidence_resolutions
            if item.resolution_claim_id is not None
        ),
        *([validated_trend_claim_id] if validated_trend_claim_id is not None else []),
    }
    decision_ids = tuple(
        sorted(decisions_by_claim[claim_id].decision_id for claim_id in used_claim_ids)
    )
    identity = canonical_sha256(
        {
            "issuer_id": issuer_id,
            "as_of_date": as_of_date,
            "assessment_period": assessment_period,
            "mechanism": mechanism,
            "scope": scope,
            "business_model_snapshot_id": business_model.snapshot_id,
            "competitive_context_snapshot_id": competitive_context.context_snapshot_id,
            "evidence_bindings": evidence_bindings,
        }
    )[:20]
    return CompetitiveAdvantageHypothesis(
        schema_version="2.0.0",
        hypothesis_id=f"hypothesis:{issuer_id}:{mechanism}:{identity}",
        issuer_id=issuer_id,
        as_of_date=as_of_date,
        assessment_period=dict(assessment_period),
        mechanism=mechanism,
        mechanism_policy_id=mechanism,
        mechanism_policy_version=POLICY_VERSION,
        scope=dict(scope),
        status=status,
        business_model_snapshot_id=business_model.snapshot_id,
        competitive_context_snapshot_id=competitive_context.context_snapshot_id,
        hypothesis_claim_id=hypothesis_claim_id,
        durability_claim_id=durability_claim_id,
        reinvestment_claim_id=reinvestment_claim_id,
        counterevidence_claim_ids=tuple(sorted(counterevidence_claim_ids)),
        claim_review_decision_ids=decision_ids,
        evidence_bindings=evidence_bindings,
        counterevidence_resolutions=tuple(resolution_payloads),
        reinvestment_relevance=reinvestment_relevance,
        predecessor_hypothesis_id=(predecessor.hypothesis_id if predecessor else None),
        trend=trend,
        trend_claim_id=validated_trend_claim_id,
        missing_evidence=tuple(sorted(set(missing))),
    )
