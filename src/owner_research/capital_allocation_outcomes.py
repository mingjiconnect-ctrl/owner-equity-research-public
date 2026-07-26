from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date

from .calculation_integrity import expected_input_fingerprint, expected_output_fingerprint
from .capital_allocation_policies import (
    OFFICIAL_AUTHORITY_LEVELS,
    OUTCOME_CLAIM_ROLES,
    OUTCOME_POLICY_VERSION,
    policy_for,
    role_accepts_unit,
)
from .contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    CalculationResult,
    CapitalAllocationEvent,
    CapitalAllocationOutcome,
    Claim,
    Fact,
    FiscalPeriod,
    SourceDocument,
)
from .fingerprints import canonical_sha256
from .units import unit_spec


class CapitalAllocationOutcomeError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CapitalOutcomeClaimEvidence:
    claim_id: str
    review_decision_id: str
    role_id: str


@dataclass(frozen=True, slots=True)
class CapitalOutcomeRoleEvidence:
    role_id: str
    coverage_status: str
    fact_id: str | None = None
    calculation_result_id: str | None = None
    claim_ids: tuple[str, ...] = ()
    search_source_document_ids: tuple[str, ...] = ()
    search_note: str | None = None
    missing_evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CapitalOutcomeEvaluationRequest:
    assessed_at: str
    observation_period: Mapping[str, str]
    role_evidence: tuple[CapitalOutcomeRoleEvidence, ...] = ()
    claim_evidence: tuple[CapitalOutcomeClaimEvidence, ...] = ()
    missing_evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CapitalOutcomeEvaluation:
    outcome: CapitalAllocationOutcome
    no_change: bool


def _binding_id(*values: str) -> str:
    return f"capital-outcome-binding:{canonical_sha256(values)}"


def _calculation_fact_ids(
    calculation_id: str,
    *,
    calculations: Mapping[str, CalculationResult],
    facts: Mapping[str, Fact],
    periods: Mapping[str, FiscalPeriod],
    stack: set[str] | None = None,
) -> set[str]:
    trail = set() if stack is None else set(stack)
    if calculation_id in trail:
        raise CapitalAllocationOutcomeError("Outcome calculation dependency cycle")
    trail.add(calculation_id)
    try:
        calculation = calculations[calculation_id]
    except KeyError as exc:
        raise CapitalAllocationOutcomeError("Outcome calculation is unavailable") from exc
    if calculation.input_assumption_ids:
        raise CapitalAllocationOutcomeError("Outcome calculation cannot use Assumptions")
    if calculation.input_fingerprint != expected_input_fingerprint(
        calculation,
        facts=facts,
        assumptions={},
        calculations=calculations,
        periods=periods,
    ):
        raise CapitalAllocationOutcomeError("Outcome calculation input fingerprint mismatch")
    if calculation.output_fingerprint != expected_output_fingerprint(calculation):
        raise CapitalAllocationOutcomeError("Outcome calculation output fingerprint mismatch")
    result = set(calculation.input_fact_ids)
    for child_id in calculation.input_calculation_ids:
        result.update(
            _calculation_fact_ids(
                child_id,
                calculations=calculations,
                facts=facts,
                periods=periods,
                stack=trail,
            )
        )
    return result


def _validated_claim_bindings(
    *,
    event: CapitalAllocationEvent,
    request: CapitalOutcomeEvaluationRequest,
    claims: Mapping[str, Claim],
    candidates: Mapping[str, AnalyticalClaimCandidate],
    decisions: Mapping[str, AnalyticalClaimReviewDecision],
    facts: Mapping[str, Fact],
    documents: Mapping[str, SourceDocument],
    assessed_at: date,
) -> tuple[tuple[dict[str, str], ...], dict[str, Claim]]:
    bindings: list[dict[str, str]] = []
    reviewed: dict[str, Claim] = {}
    seen_claim_ids: set[str] = set()
    for evidence in request.claim_evidence:
        if evidence.claim_id in seen_claim_ids:
            raise CapitalAllocationOutcomeError("Outcome repeats an analytical Claim")
        seen_claim_ids.add(evidence.claim_id)
        if evidence.role_id not in OUTCOME_CLAIM_ROLES:
            raise CapitalAllocationOutcomeError("Outcome uses an unregistered Claim role")
        try:
            claim = claims[evidence.claim_id]
            decision = decisions[evidence.review_decision_id]
            candidate = candidates[decision.candidate_id]
        except KeyError as exc:
            raise CapitalAllocationOutcomeError("Outcome Claim review chain is incomplete") from exc
        if (
            claim.issuer_id != event.issuer_id
            or decision.issuer_id != event.issuer_id
            or candidate.issuer_id != event.issuer_id
        ):
            raise CapitalAllocationOutcomeError("Outcome Claim issuer mismatch")
        if canonical_sha256(dict(candidate.scope)) != canonical_sha256(dict(event.scope)):
            raise CapitalAllocationOutcomeError("Outcome Claim scope mismatch")
        if (
            decision.decision != "confirmed"
            or decision.output_claim_id != claim.claim_id
            or decision.candidate_fingerprint != candidate.fingerprint
            or decision.evidence_graph_sha256 != candidate.evidence_graph_sha256
            or candidate.validation_status != "ready"
        ):
            raise CapitalAllocationOutcomeError("Outcome Claim lacks valid human review")
        expected_evidence_graph = canonical_sha256(
            {
                "supporting_evidence_bindings": candidate.supporting_evidence_bindings,
                "counterevidence_bindings": candidate.counterevidence_bindings,
            }
        )
        candidate_supporting_fact_ids = {
            item["fact_id"]
            for item in candidate.supporting_evidence_bindings
            if item["fact_id"] is not None
        }
        if (
            candidate.evidence_graph_sha256 != expected_evidence_graph
            or set(claim.supporting_fact_ids) != candidate_supporting_fact_ids
        ):
            raise CapitalAllocationOutcomeError("Outcome Claim evidence graph is invalid")
        if (
            claim.statement != candidate.proposed_statement
            or claim.counterevidence_search_note != candidate.counterevidence_search_note
            or claim.falsification_condition != candidate.falsification_condition
        ):
            raise CapitalAllocationOutcomeError("Outcome Claim differs from its reviewed Candidate")
        if date.fromisoformat(claim.as_of_date) > assessed_at:
            raise CapitalAllocationOutcomeError("Outcome Claim follows the assessment cutoff")
        for fact_id in (*claim.supporting_fact_ids, *claim.counterevidence_fact_ids):
            try:
                fact = facts[fact_id]
                document = documents[fact.source_document_id]
            except KeyError as exc:
                raise CapitalAllocationOutcomeError(
                    "Outcome Claim Fact chain is incomplete"
                ) from exc
            if (
                fact.issuer_id != event.issuer_id
                or document.issuer_id != event.issuer_id
                or document.authority_level not in OFFICIAL_AUTHORITY_LEVELS
                or date.fromisoformat(document.published_date) > assessed_at
            ):
                raise CapitalAllocationOutcomeError(
                    "Outcome Claim requires official cutoff-safe issuer Facts"
                )
        binding_id = _binding_id(claim.claim_id, evidence.role_id)
        bindings.append(
            {
                "binding_id": binding_id,
                "claim_id": claim.claim_id,
                "review_decision_id": decision.decision_id,
                "role_id": evidence.role_id,
            }
        )
        reviewed[claim.claim_id] = claim
    return tuple(sorted(bindings, key=lambda item: item["binding_id"])), reviewed


def _validate_result_fact(
    fact: Fact,
    *,
    event: CapitalAllocationEvent,
    role_id: str,
    documents: Mapping[str, SourceDocument],
    assessed_at: date,
    observation_start: date,
    observation_end: date,
) -> set[str]:
    if fact.issuer_id != event.issuer_id:
        raise CapitalAllocationOutcomeError("Outcome result Fact issuer mismatch")
    try:
        document = documents[fact.source_document_id]
    except KeyError as exc:
        raise CapitalAllocationOutcomeError("Outcome result Fact source is unavailable") from exc
    if (
        document.issuer_id != event.issuer_id
        or document.authority_level not in OFFICIAL_AUTHORITY_LEVELS
    ):
        raise CapitalAllocationOutcomeError("Outcome result Fact requires an official source")
    if date.fromisoformat(document.published_date) > assessed_at:
        raise CapitalAllocationOutcomeError("Outcome result Fact uses future evidence")
    period_end = fact.period["end"]
    if period_end is None:
        raise CapitalAllocationOutcomeError("Outcome result Fact lacks a period end")
    parsed_end = date.fromisoformat(period_end)
    if parsed_end < observation_start or parsed_end > observation_end:
        raise CapitalAllocationOutcomeError("Outcome result Fact is outside the observation window")
    unit_family = unit_spec(fact.unit or "").family
    if (
        fact.value_type != "number"
        or not role_accepts_unit(role_id, unit_family)
        or unit_family.startswith("per_unit:")
    ):
        raise CapitalAllocationOutcomeError("Outcome result Fact role or unit mismatch")
    return {fact.fact_id}


def _validate_result_calculation(
    calculation: CalculationResult,
    *,
    event: CapitalAllocationEvent,
    role_id: str,
    calculations: Mapping[str, CalculationResult],
    facts: Mapping[str, Fact],
    periods: Mapping[str, FiscalPeriod],
    documents: Mapping[str, SourceDocument],
    assessed_at: date,
    observation_start: date,
    observation_end: date,
) -> set[str]:
    if calculation.issuer_id != event.issuer_id:
        raise CapitalAllocationOutcomeError("Outcome calculation issuer mismatch")
    unit_family = unit_spec(calculation.unit or "").family
    if (
        calculation.value_type != "number"
        or not role_accepts_unit(role_id, unit_family)
        or unit_family.startswith("per_unit:")
    ):
        raise CapitalAllocationOutcomeError("Outcome calculation role or unit mismatch")
    period_end = calculation.period["end"]
    if period_end is None:
        raise CapitalAllocationOutcomeError("Outcome calculation lacks a period end")
    parsed_end = date.fromisoformat(period_end)
    if parsed_end < observation_start or parsed_end > observation_end:
        raise CapitalAllocationOutcomeError("Outcome calculation is outside the observation window")
    input_fact_ids = _calculation_fact_ids(
        calculation.calculation_id,
        calculations=calculations,
        facts=facts,
        periods=periods,
    )
    for fact_id in input_fact_ids:
        try:
            fact = facts[fact_id]
        except KeyError as exc:
            raise CapitalAllocationOutcomeError("Outcome calculation Fact is unavailable") from exc
        if fact.issuer_id != event.issuer_id:
            raise CapitalAllocationOutcomeError("Outcome calculation Fact issuer mismatch")
        try:
            document = documents[fact.source_document_id]
        except KeyError as exc:
            raise CapitalAllocationOutcomeError(
                "Outcome calculation source is unavailable"
            ) from exc
        if (
            document.issuer_id != event.issuer_id
            or document.authority_level not in OFFICIAL_AUTHORITY_LEVELS
            or date.fromisoformat(document.published_date) > assessed_at
        ):
            raise CapitalAllocationOutcomeError(
                "Outcome calculation requires official cutoff-safe Facts"
            )
    return input_fact_ids


def _lifecycle_outcome(
    *,
    event: CapitalAllocationEvent,
    request: CapitalOutcomeEvaluationRequest,
    status: str,
    predecessor_outcome_id: str | None,
) -> CapitalAllocationOutcome:
    policy = policy_for(event.event_type)
    coverage = tuple(
        {
            "role_id": role,
            "status": "not_due",
            "binding_ids": [],
            "claim_binding_ids": [],
            "missing_evidence": [],
        }
        for role in sorted(policy.outcome_roles)
    )
    identity = canonical_sha256(
        {
            "event_id": event.event_id,
            "assessed_at": request.assessed_at,
            "observation_period": dict(request.observation_period),
        }
    )[:20]
    return CapitalAllocationOutcome(
        schema_version="2.0.0",
        outcome_id=f"capital-outcome:{event.issuer_id}:{identity}",
        issuer_id=event.issuer_id,
        outcome_policy_id=policy.outcome_policy_id,
        outcome_policy_version=OUTCOME_POLICY_VERSION,
        event_id=event.event_id,
        predecessor_outcome_id=predecessor_outcome_id,
        assessed_at=request.assessed_at,
        observation_period=dict(request.observation_period),
        status=status,
        result_bindings=(),
        result_role_coverage=coverage,
        claim_bindings=(),
        missing_evidence=(),
    )


def evaluate_capital_allocation_outcome(
    *,
    event: CapitalAllocationEvent,
    event_versions: Sequence[CapitalAllocationEvent],
    facts: Sequence[Fact],
    calculations: Sequence[CalculationResult],
    fiscal_periods: Sequence[FiscalPeriod],
    source_documents: Sequence[SourceDocument],
    claims: Sequence[Claim],
    analytical_candidates: Sequence[AnalyticalClaimCandidate],
    analytical_decisions: Sequence[AnalyticalClaimReviewDecision],
    request: CapitalOutcomeEvaluationRequest,
    existing_outcomes: Sequence[CapitalAllocationOutcome] = (),
) -> CapitalOutcomeEvaluation:
    assessed_at = date.fromisoformat(request.assessed_at)
    observation_start = date.fromisoformat(request.observation_period["start"])
    observation_end = date.fromisoformat(request.observation_period["end"])
    if (
        observation_start > observation_end
        or observation_end > assessed_at
        or observation_start < date.fromisoformat(event.announcement_date)
    ):
        raise CapitalAllocationOutcomeError("invalid capital-allocation observation period")
    prior_same_event = [
        item
        for item in existing_outcomes
        if item.event_id == event.event_id
        and date.fromisoformat(item.assessed_at) < assessed_at
    ]
    predecessor = max(prior_same_event, key=lambda item: item.assessed_at, default=None)
    predecessor_id = predecessor.outcome_id if predecessor is not None else None
    latest_event_version = max(
        (
            item.event_version
            for item in event_versions
            if item.economic_event_key == event.economic_event_key
        ),
        default=event.event_version,
    )
    if event.event_version < latest_event_version:
        outcome = _lifecycle_outcome(
            event=event,
            request=request,
            status="superseded",
            predecessor_outcome_id=predecessor_id,
        )
        return CapitalOutcomeEvaluation(outcome, False)
    if event.lifecycle_status == "cancelled":
        outcome = _lifecycle_outcome(
            event=event,
            request=request,
            status="cancelled",
            predecessor_outcome_id=predecessor_id,
        )
        return CapitalOutcomeEvaluation(outcome, False)
    if event.lifecycle_status == "announced" and not request.role_evidence:
        outcome = _lifecycle_outcome(
            event=event,
            request=request,
            status="not_due",
            predecessor_outcome_id=predecessor_id,
        )
        return CapitalOutcomeEvaluation(outcome, False)

    policy = policy_for(event.event_type)
    if event.lifecycle_status == "blocked":
        role_evidence = tuple(
            CapitalOutcomeRoleEvidence(
                role_id=role,
                coverage_status="blocked",
                missing_evidence=tuple(event.missing_evidence) or ("event_blocked",),
            )
            for role in sorted(policy.outcome_roles)
        )
        request = CapitalOutcomeEvaluationRequest(
            assessed_at=request.assessed_at,
            observation_period=request.observation_period,
            role_evidence=role_evidence,
            missing_evidence=tuple(event.missing_evidence) or ("event_blocked",),
        )
    if not request.role_evidence and event.lifecycle_status == "in_progress":
        outcome = _lifecycle_outcome(
            event=event,
            request=request,
            status="not_due",
            predecessor_outcome_id=predecessor_id,
        )
        return CapitalOutcomeEvaluation(outcome, False)

    role_evidence = {item.role_id: item for item in request.role_evidence}
    if len(role_evidence) != len(request.role_evidence) or set(role_evidence) != set(
        policy.outcome_roles
    ):
        raise CapitalAllocationOutcomeError("Outcome role evidence does not match policy")
    fact_map = {item.fact_id: item for item in facts}
    calculation_map = {item.calculation_id: item for item in calculations}
    period_map = {item.period_id: item for item in fiscal_periods}
    document_map = {item.document_id: item for item in source_documents}
    claim_map = {item.claim_id: item for item in claims}
    candidate_map = {item.candidate_id: item for item in analytical_candidates}
    decision_map = {item.decision_id: item for item in analytical_decisions}
    claim_bindings, reviewed_claims = _validated_claim_bindings(
        event=event,
        request=request,
        claims=claim_map,
        candidates=candidate_map,
        decisions=decision_map,
        facts=fact_map,
        documents=document_map,
        assessed_at=assessed_at,
    )
    claim_binding_by_claim = {item["claim_id"]: item["binding_id"] for item in claim_bindings}
    used_claim_ids: set[str] = set()
    used_result_ids: set[str] = set()
    result_bindings: list[dict[str, str | None]] = []
    coverage: list[dict[str, object]] = []
    missing: set[str] = set(request.missing_evidence)
    statuses: set[str] = set()

    for role in sorted(policy.outcome_roles):
        evidence = role_evidence[role]
        status = evidence.coverage_status
        if status not in {
            "observed",
            "none_recognized_after_review",
            "not_disclosed",
            "not_applicable",
            "blocked",
        }:
            raise CapitalAllocationOutcomeError("unsupported Outcome role coverage status")
        statuses.add(status)
        binding_ids: list[str] = []
        if status == "observed":
            if (evidence.fact_id is None) == (evidence.calculation_result_id is None):
                raise CapitalAllocationOutcomeError(
                    "observed Outcome role requires exactly one result"
                )
            result_id = evidence.fact_id or evidence.calculation_result_id
            if result_id in used_result_ids:
                raise CapitalAllocationOutcomeError("Outcome reuses result evidence across roles")
            used_result_ids.add(result_id)
            if evidence.fact_id is not None:
                try:
                    fact = fact_map[evidence.fact_id]
                except KeyError as exc:
                    raise CapitalAllocationOutcomeError(
                        "Outcome result Fact is unavailable"
                    ) from exc
                result_fact_ids = _validate_result_fact(
                    fact,
                    event=event,
                    role_id=role,
                    documents=document_map,
                    assessed_at=assessed_at,
                    observation_start=observation_start,
                    observation_end=observation_end,
                )
            else:
                try:
                    calculation = calculation_map[evidence.calculation_result_id]
                except KeyError as exc:
                    raise CapitalAllocationOutcomeError(
                        "Outcome result calculation is unavailable"
                    ) from exc
                result_fact_ids = _validate_result_calculation(
                    calculation,
                    event=event,
                    role_id=role,
                    calculations=calculation_map,
                    facts=fact_map,
                    periods=period_map,
                    documents=document_map,
                    assessed_at=assessed_at,
                    observation_start=observation_start,
                    observation_end=observation_end,
                )
            binding_id = _binding_id(event.event_id, role, result_id)
            binding_ids.append(binding_id)
            result_bindings.append(
                {
                    "binding_id": binding_id,
                    "role_id": role,
                    "fact_id": evidence.fact_id,
                    "calculation_result_id": evidence.calculation_result_id,
                }
            )
        elif evidence.fact_id is not None or evidence.calculation_result_id is not None:
            raise CapitalAllocationOutcomeError("non-observed Outcome role contains a result")

        role_claim_ids = set(evidence.claim_ids)
        if not role_claim_ids.issubset(reviewed_claims):
            raise CapitalAllocationOutcomeError("Outcome role uses an unreviewed Claim")
        if status in {"none_recognized_after_review", "not_applicable"} and not role_claim_ids:
            raise CapitalAllocationOutcomeError("reviewed absence requires an analytical Claim")
        if status == "not_applicable" and any(
            candidate_map[decision_map[
                next(
                    item.review_decision_id
                    for item in request.claim_evidence
                    if item.claim_id == claim_id
                )
            ].candidate_id].claim_role
            != "not_applicable"
            for claim_id in role_claim_ids
        ):
            raise CapitalAllocationOutcomeError("not-applicable role requires not-applicable Claim")
        if status == "observed":
            covered = set().union(
                *(set(reviewed_claims[claim_id].supporting_fact_ids) for claim_id in role_claim_ids)
            ) if role_claim_ids else set()
            if not result_fact_ids.issubset(covered):
                raise CapitalAllocationOutcomeError(
                    "observed Outcome role Claim does not cover its result evidence"
                )
        if status == "not_disclosed":
            if not evidence.search_note or not evidence.search_source_document_ids:
                raise CapitalAllocationOutcomeError(
                    "not-disclosed Outcome role lacks a completed official search"
                )
            for document_id in evidence.search_source_document_ids:
                try:
                    document = document_map[document_id]
                except KeyError as exc:
                    raise CapitalAllocationOutcomeError(
                        "Outcome disclosure-search source is unavailable"
                    ) from exc
                if (
                    document.issuer_id != event.issuer_id
                    or document.authority_level not in OFFICIAL_AUTHORITY_LEVELS
                    or date.fromisoformat(document.published_date) > assessed_at
                ):
                    raise CapitalAllocationOutcomeError(
                        "Outcome disclosure search requires official cutoff-safe sources"
                    )
            if not evidence.missing_evidence:
                raise CapitalAllocationOutcomeError(
                    "not-disclosed Outcome role requires missing evidence"
                )
        if status == "blocked" and not evidence.missing_evidence:
            raise CapitalAllocationOutcomeError("blocked Outcome role requires missing evidence")
        used_claim_ids.update(role_claim_ids)
        missing.update(evidence.missing_evidence)
        coverage.append(
            {
                "role_id": role,
                "status": status,
                "binding_ids": binding_ids,
                "claim_binding_ids": sorted(
                    claim_binding_by_claim[claim_id] for claim_id in role_claim_ids
                ),
                "missing_evidence": sorted(set(evidence.missing_evidence)),
            }
        )

    if set(reviewed_claims) != used_claim_ids:
        raise CapitalAllocationOutcomeError("Outcome includes an unused analytical Claim")
    if "blocked" in statuses:
        outcome_status = "blocked"
    elif "observed" in statuses and statuses.intersection({"not_disclosed"}):
        outcome_status = "partial"
    elif "observed" in statuses:
        outcome_status = "observed"
    elif "not_disclosed" in statuses:
        outcome_status = "unverifiable"
    else:
        raise CapitalAllocationOutcomeError("Outcome has no observable or undisclosed result role")
    if outcome_status in {"observed", "partial"} and not claim_bindings:
        raise CapitalAllocationOutcomeError("interpreted Outcome requires an analytical Claim")
    if outcome_status in {"partial", "unverifiable", "blocked"} and not missing:
        missing.add("outcome_evidence_incomplete")

    identity = canonical_sha256(
        {
            "event_id": event.event_id,
            "assessed_at": request.assessed_at,
            "observation_period": dict(request.observation_period),
        }
    )[:20]
    outcome = CapitalAllocationOutcome(
        schema_version="2.0.0",
        outcome_id=f"capital-outcome:{event.issuer_id}:{identity}",
        issuer_id=event.issuer_id,
        outcome_policy_id=policy.outcome_policy_id,
        outcome_policy_version=OUTCOME_POLICY_VERSION,
        event_id=event.event_id,
        predecessor_outcome_id=predecessor_id,
        assessed_at=request.assessed_at,
        observation_period=dict(request.observation_period),
        status=outcome_status,
        result_bindings=tuple(sorted(result_bindings, key=lambda item: item["binding_id"])),
        result_role_coverage=tuple(coverage),
        claim_bindings=claim_bindings,
        missing_evidence=tuple(sorted(missing)),
    )
    same_window = [
        item
        for item in existing_outcomes
        if item.event_id == event.event_id
        and item.assessed_at == outcome.assessed_at
        and dict(item.observation_period) == dict(outcome.observation_period)
    ]
    if same_window:
        if len(same_window) != 1 or same_window[0].fingerprint != outcome.fingerprint:
            raise CapitalAllocationOutcomeError(
                "Outcome observation window already has other evidence"
            )
        return CapitalOutcomeEvaluation(same_window[0], True)
    return CapitalOutcomeEvaluation(outcome, False)
