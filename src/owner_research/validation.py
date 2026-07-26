from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, fields
from datetime import date, datetime
from math import isclose
from pathlib import Path
from typing import Any

from .business_models import BUSINESS_ATTRIBUTE_ROLES
from .business_quality_policies import POLICY_VERSION, mechanism_policy
from .calculation_integrity import (
    expected_input_fingerprint,
    expected_output_fingerprint,
)
from .capital_allocation_policies import (
    CLAIM_ROLES,
    EVENT_POLICY_VERSION,
    EVENT_TYPES,
    OFFICIAL_AUTHORITY_LEVELS,
    OUTCOME_CLAIM_ROLES,
    OUTCOME_POLICY_VERSION,
    REVIEW_CLAIM_ROLES,
    REVIEW_POLICY_ID,
    REVIEW_POLICY_VERSION,
    SOURCE_FAMILIES,
    SOURCE_ROLES,
    economic_event_key,
    policy_for,
    role_accepts_unit,
)
from .capital_allocation_reviews import (
    CapitalReviewClaimEvidence,
    build_capital_allocation_review,
)
from .component_lock import default_component_lock_path, file_sha256
from .contracts import (
    AccountingQualityFinding,
    AccountingQualityReview,
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    Assumption,
    BusinessModelSnapshot,
    BusinessQualityReview,
    CalculationResult,
    CapitalAllocationEvent,
    CapitalAllocationEventCandidate,
    CapitalAllocationEventReviewDecision,
    CapitalAllocationOutcome,
    CapitalAllocationReview,
    Claim,
    CompetitiveAdvantageHypothesis,
    CompetitiveContextSnapshot,
    ContextObservation,
    EvidencePromotion,
    ExtractionCandidate,
    Fact,
    FilingArtifact,
    FiscalPeriod,
    FootnoteReview,
    ManagementCommitment,
    ManagementOutcome,
    ManagementReview,
    ManagementStatement,
    ManagementStatementCandidate,
    ManagementStatementReviewDecision,
    MarketReferenceSnapshot,
    QuarterlyReconciliation,
    QuarterlyUpdate,
    ResearchBundle,
    RunManifest,
    Score,
    SegmentDefinition,
    SegmentSnapshot,
    SourceDocument,
    SourceSearchReceipt,
    ValuationAssumptionCandidate,
    ValuationAssumptionReviewDecision,
    ValuationHandoff,
)
from .fingerprints import canonical_sha256
from .footnotes import REQUIRED_TOPICS
from .management_outcomes import OutcomeEvaluationError, recompute_outcome_status
from .management_policies import policy as management_policy
from .quarterly import (
    COMPARABILITY_EVIDENCE_CONCEPTS,
    QuarterlyComputationError,
    assess_comparability,
    validate_fiscal_period,
)
from .units import UnitError, compatible_units, unit_spec, validate_unit_currency
from .valuation_assumption_types import PriceBlindReferenceClosure


class ContractGraphError(ValueError):
    pass


PHASE4_MECHANISMS = frozenset(
    {
        "switching_cost",
        "network_effect",
        "scale_cost_advantage",
        "brand_pricing_power",
        "intellectual_property",
        "regulatory_license",
        "distribution",
        "data_learning",
        "efficient_scale",
        "process_execution",
    }
)
PHASE4_EVENT_TYPES = EVENT_TYPES
BUSINESS_COMPONENT_TYPES = frozenset(
    {
        "customer",
        "value_proposition",
        "revenue_model",
        "cost_structure",
        "distribution",
        "key_resource",
        "key_partner",
        "regulatory_dependency",
    }
)
CONTEXT_TOPICS = frozenset(
    {
        "product_service",
        "customer_group",
        "geography",
        "channel",
        "competitor_set",
        "substitutes",
        "entry_barriers",
        "buyer_power",
        "supplier_power",
        "rivalry",
        "regulatory_change",
        "technology_change",
        "market_growth",
    }
)


@dataclass(frozen=True, slots=True)
class ContractGraph:
    documents: tuple[SourceDocument, ...] = ()
    facts: tuple[Fact, ...] = ()
    claims: tuple[Claim, ...] = ()
    assumptions: tuple[Assumption, ...] = ()
    calculations: tuple[CalculationResult, ...] = ()
    periods: tuple[FiscalPeriod, ...] = ()
    reconciliations: tuple[QuarterlyReconciliation, ...] = ()
    quarterly_updates: tuple[QuarterlyUpdate, ...] = ()
    filing_artifacts: tuple[FilingArtifact, ...] = ()
    extraction_candidates: tuple[ExtractionCandidate, ...] = ()
    evidence_promotions: tuple[EvidencePromotion, ...] = ()
    segment_definitions: tuple[SegmentDefinition, ...] = ()
    segment_snapshots: tuple[SegmentSnapshot, ...] = ()
    footnote_reviews: tuple[FootnoteReview, ...] = ()
    accounting_quality_findings: tuple[AccountingQualityFinding, ...] = ()
    accounting_quality_reviews: tuple[AccountingQualityReview, ...] = ()
    context_observations: tuple[ContextObservation, ...] = ()
    competitive_context_snapshots: tuple[CompetitiveContextSnapshot, ...] = ()
    analytical_claim_candidates: tuple[AnalyticalClaimCandidate, ...] = ()
    analytical_claim_review_decisions: tuple[AnalyticalClaimReviewDecision, ...] = ()
    business_model_snapshots: tuple[BusinessModelSnapshot, ...] = ()
    competitive_advantage_hypotheses: tuple[CompetitiveAdvantageHypothesis, ...] = ()
    business_quality_reviews: tuple[BusinessQualityReview, ...] = ()
    management_statements: tuple[ManagementStatement, ...] = ()
    management_statement_candidates: tuple[ManagementStatementCandidate, ...] = ()
    management_statement_review_decisions: tuple[ManagementStatementReviewDecision, ...] = ()
    management_commitments: tuple[ManagementCommitment, ...] = ()
    management_outcomes: tuple[ManagementOutcome, ...] = ()
    capital_allocation_event_candidates: tuple[CapitalAllocationEventCandidate, ...] = ()
    capital_allocation_event_review_decisions: tuple[
        CapitalAllocationEventReviewDecision, ...
    ] = ()
    capital_allocation_events: tuple[CapitalAllocationEvent, ...] = ()
    capital_allocation_outcomes: tuple[CapitalAllocationOutcome, ...] = ()
    source_search_receipts: tuple[SourceSearchReceipt, ...] = ()
    management_reviews: tuple[ManagementReview, ...] = ()
    capital_allocation_reviews: tuple[CapitalAllocationReview, ...] = ()
    scores: tuple[Score, ...] = ()
    manifests: tuple[RunManifest, ...] = ()
    research_bundles: tuple[ResearchBundle, ...] = ()
    valuation_assumption_candidates: tuple[ValuationAssumptionCandidate, ...] = ()
    valuation_assumption_review_decisions: tuple[
        ValuationAssumptionReviewDecision, ...
    ] = ()
    market_reference_snapshots: tuple[MarketReferenceSnapshot, ...] = ()
    valuation_handoffs: tuple[ValuationHandoff, ...] = ()
    price_blind_reference_closures: tuple[PriceBlindReferenceClosure, ...] = ()
    market_reference_validation_contexts: tuple[Any, ...] = ()
    component_lock_path: Path | None = None

    def __post_init__(self) -> None:
        for field in fields(self):
            if field.name == "component_lock_path":
                continue
            value = getattr(self, field.name)
            if not isinstance(value, Sequence):
                raise ContractGraphError(f"{field.name} must be a sequence")
            object.__setattr__(self, field.name, tuple(value))
        path = self.component_lock_path or default_component_lock_path()
        object.__setattr__(self, "component_lock_path", Path(path))

    def validate(self) -> None:
        self._validate_collection_types()
        sequences = {
            "SourceDocument": [item.document_id for item in self.documents],
            "Fact": [item.fact_id for item in self.facts],
            "Claim": [item.claim_id for item in self.claims],
            "Assumption": [item.assumption_id for item in self.assumptions],
            "CalculationResult": [item.calculation_id for item in self.calculations],
            "FiscalPeriod": [item.period_id for item in self.periods],
            "QuarterlyReconciliation": [item.reconciliation_id for item in self.reconciliations],
            "QuarterlyUpdate": [item.update_id for item in self.quarterly_updates],
            "FilingArtifact": [item.artifact_id for item in self.filing_artifacts],
            "ExtractionCandidate": [item.candidate_id for item in self.extraction_candidates],
            "EvidencePromotion": [item.promotion_id for item in self.evidence_promotions],
            "SegmentDefinition": [item.segment_id for item in self.segment_definitions],
            "SegmentSnapshot": [item.snapshot_id for item in self.segment_snapshots],
            "FootnoteReview": [item.review_id for item in self.footnote_reviews],
            "AccountingQualityFinding": [
                item.finding_id for item in self.accounting_quality_findings
            ],
            "AccountingQualityReview": [item.review_id for item in self.accounting_quality_reviews],
            "ContextObservation": [item.observation_id for item in self.context_observations],
            "CompetitiveContextSnapshot": [
                item.context_snapshot_id for item in self.competitive_context_snapshots
            ],
            "AnalyticalClaimCandidate": [
                item.candidate_id for item in self.analytical_claim_candidates
            ],
            "AnalyticalClaimReviewDecision": [
                item.decision_id for item in self.analytical_claim_review_decisions
            ],
            "BusinessModelSnapshot": [item.snapshot_id for item in self.business_model_snapshots],
            "CompetitiveAdvantageHypothesis": [
                item.hypothesis_id for item in self.competitive_advantage_hypotheses
            ],
            "BusinessQualityReview": [item.review_id for item in self.business_quality_reviews],
            "ManagementStatement": [item.statement_id for item in self.management_statements],
            "ManagementStatementCandidate": [
                item.candidate_id for item in self.management_statement_candidates
            ],
            "ManagementStatementReviewDecision": [
                item.decision_id for item in self.management_statement_review_decisions
            ],
            "ManagementCommitment": [item.commitment_id for item in self.management_commitments],
            "ManagementOutcome": [item.outcome_id for item in self.management_outcomes],
            "CapitalAllocationEventCandidate": [
                item.candidate_id for item in self.capital_allocation_event_candidates
            ],
            "CapitalAllocationEventReviewDecision": [
                item.decision_id for item in self.capital_allocation_event_review_decisions
            ],
            "CapitalAllocationEvent": [item.event_id for item in self.capital_allocation_events],
            "CapitalAllocationOutcome": [
                item.outcome_id for item in self.capital_allocation_outcomes
            ],
            "SourceSearchReceipt": [
                item.receipt_id for item in self.source_search_receipts
            ],
            "ManagementReview": [item.review_id for item in self.management_reviews],
            "CapitalAllocationReview": [item.review_id for item in self.capital_allocation_reviews],
            "Score": [item.score_id for item in self.scores],
            "RunManifest": [item.run_id for item in self.manifests],
            "ResearchBundle": [item.bundle_id for item in self.research_bundles],
            "ValuationAssumptionCandidate": [
                item.candidate_id for item in self.valuation_assumption_candidates
            ],
            "ValuationAssumptionReviewDecision": [
                item.decision_id for item in self.valuation_assumption_review_decisions
            ],
            "MarketReferenceSnapshot": [
                item.snapshot_id for item in self.market_reference_snapshots
            ],
            "ValuationHandoff": [item.handoff_id for item in self.valuation_handoffs],
            "PriceBlindReferenceClosure": [
                item.closure_id for item in self.price_blind_reference_closures
            ],
            "MarketReferenceValidationContext": [
                item.context_id for item in self.market_reference_validation_contexts
            ],
        }
        domains = {domain: set(identifiers) for domain, identifiers in sequences.items()}
        self._reject_duplicates(sequences)
        self._reject_cross_domain_ids(domains)
        self._require_single_issuer()

        documents = {item.document_id: item for item in self.documents}
        facts = {item.fact_id: item for item in self.facts}
        claims = {item.claim_id: item for item in self.claims}
        assumptions = {item.assumption_id: item for item in self.assumptions}
        calculations = {item.calculation_id: item for item in self.calculations}
        periods = {item.period_id: item for item in self.periods}
        reconciliations = {item.reconciliation_id: item for item in self.reconciliations}
        artifacts = {item.artifact_id: item for item in self.filing_artifacts}
        candidates = {item.candidate_id: item for item in self.extraction_candidates}
        segments = {item.segment_id: item for item in self.segment_definitions}
        segment_snapshots = {item.snapshot_id: item for item in self.segment_snapshots}
        footnotes = {item.review_id: item for item in self.footnote_reviews}
        findings = {item.finding_id: item for item in self.accounting_quality_findings}
        observations = {item.observation_id: item for item in self.context_observations}
        competitive_contexts = {
            item.context_snapshot_id: item for item in self.competitive_context_snapshots
        }
        analytical_candidates = {
            item.candidate_id: item for item in self.analytical_claim_candidates
        }
        analytical_decisions = {
            item.decision_id: item for item in self.analytical_claim_review_decisions
        }
        business_models = {item.snapshot_id: item for item in self.business_model_snapshots}
        hypotheses = {item.hypothesis_id: item for item in self.competitive_advantage_hypotheses}
        statements = {item.statement_id: item for item in self.management_statements}
        statement_candidates = {
            item.candidate_id: item for item in self.management_statement_candidates
        }
        commitments = {item.commitment_id: item for item in self.management_commitments}
        management_outcomes = {item.outcome_id: item for item in self.management_outcomes}
        capital_candidates = {
            item.candidate_id: item for item in self.capital_allocation_event_candidates
        }
        capital_decisions = {
            item.decision_id: item for item in self.capital_allocation_event_review_decisions
        }
        capital_events = {item.event_id: item for item in self.capital_allocation_events}
        capital_outcomes = {item.outcome_id: item for item in self.capital_allocation_outcomes}

        def require_claim(
            reference: str,
            context: str,
            *,
            official: bool = False,
            cutoff: date | None = None,
        ) -> Claim:
            self._require(reference, set(claims), context)
            claim = claims[reference]
            if not claim.supporting_fact_ids:
                raise ContractGraphError(f"{context} Claim lacks supporting evidence")
            if not claim.falsification_condition.strip():
                raise ContractGraphError(f"{context} Claim lacks falsification condition")
            if not claim.counterevidence_fact_ids and not (
                claim.counterevidence_search_note and claim.counterevidence_search_note.strip()
            ):
                raise ContractGraphError(f"{context} Claim lacks counterevidence search")
            if cutoff is not None and date.fromisoformat(claim.as_of_date) > cutoff:
                raise ContractGraphError(f"{context} Claim follows the review cutoff")
            for fact_id in (*claim.supporting_fact_ids, *claim.counterevidence_fact_ids):
                self._require(fact_id, set(facts), f"{context} evidence Fact IDs")
                document = documents[facts[fact_id].source_document_id]
                if cutoff is not None and date.fromisoformat(document.published_date) > cutoff:
                    raise ContractGraphError(f"{context} uses evidence published after cutoff")
                if official and fact_id in claim.supporting_fact_ids:
                    if document.authority_level not in OFFICIAL_AUTHORITY_LEVELS:
                        raise ContractGraphError(
                            f"{context} cannot rely on third-party supporting evidence"
                        )
            return claim

        def require_phase4_calculation(
            reference: str,
            context: str,
            *,
            official: bool = False,
            cutoff: date | None = None,
        ) -> CalculationResult:
            self._require(reference, set(calculations), context)
            visiting: set[str] = set()

            def reject_assumptions(calculation_id: str) -> None:
                if calculation_id in visiting:
                    return
                visiting.add(calculation_id)
                calculation = calculations[calculation_id]
                if calculation.input_assumption_ids:
                    raise ContractGraphError(
                        f"{context} depends on an Assumption through {calculation_id}"
                    )
                for fact_id in calculation.input_fact_ids:
                    document = documents[facts[fact_id].source_document_id]
                    if official and document.authority_level not in OFFICIAL_AUTHORITY_LEVELS:
                        raise ContractGraphError(
                            f"{context} calculation uses third-party supporting evidence"
                        )
                    if cutoff is not None and (
                        date.fromisoformat(document.published_date) > cutoff
                    ):
                        raise ContractGraphError(
                            f"{context} calculation uses evidence published after cutoff"
                        )
                for dependency_id in calculation.input_calculation_ids:
                    reject_assumptions(dependency_id)

            reject_assumptions(reference)
            return calculations[reference]

        def calculation_fact_ids(reference: str) -> set[str]:
            collected: set[str] = set()
            visited: set[str] = set()

            def collect(calculation_id: str) -> None:
                if calculation_id in visited:
                    return
                visited.add(calculation_id)
                calculation = calculations[calculation_id]
                collected.update(calculation.input_fact_ids)
                for dependency_id in calculation.input_calculation_ids:
                    collect(dependency_id)

            collect(reference)
            return collected

        def validate_period(period: Any, as_of_date: str, context: str) -> tuple[date, date]:
            start = date.fromisoformat(period["start"])
            end = date.fromisoformat(period["end"])
            as_of = date.fromisoformat(as_of_date)
            if start > end:
                raise ContractGraphError(f"{context} period starts after it ends")
            if end > as_of:
                raise ContractGraphError(f"{context} period ends after as-of date")
            return start, end

        for fact in self.facts:
            self._require(fact.source_document_id, set(documents), "Fact source_document_id")
            if facts[fact.fact_id].issuer_id != documents[fact.source_document_id].issuer_id:
                raise ContractGraphError("Fact issuer must match its SourceDocument issuer")
            for reference in fact.parent_fact_ids:
                self._require(reference, set(facts), "Fact parent_fact_ids")

        for claim in self.claims:
            for reference in claim.supporting_fact_ids:
                self._require(reference, set(facts), "Claim supporting_fact_ids")
            for reference in claim.counterevidence_fact_ids:
                self._require(reference, set(facts), "Claim counterevidence_fact_ids")
            if not claim.counterevidence_fact_ids and not (
                claim.counterevidence_search_note and claim.counterevidence_search_note.strip()
            ):
                raise ContractGraphError(
                    f"Claim {claim.claim_id} lacks counterevidence search note"
                )

        for assumption in self.assumptions:
            for reference in assumption.supporting_fact_ids:
                self._require(reference, set(facts), "Assumption supporting_fact_ids")
            for reference in assumption.supporting_claim_ids:
                self._require(reference, set(claims), "Assumption supporting_claim_ids")

        for calculation in self.calculations:
            if calculation.generator != "deterministic_program":
                raise ContractGraphError(
                    f"Calculation {calculation.calculation_id} is not deterministic"
                )
            for reference in calculation.input_fact_ids:
                self._require(reference, set(facts), "CalculationResult input_fact_ids")
            for reference in calculation.input_assumption_ids:
                self._require(reference, set(assumptions), "CalculationResult input_assumption_ids")
            for reference in calculation.input_calculation_ids:
                self._require(
                    reference, set(calculations), "CalculationResult input_calculation_ids"
                )
            for reference in calculation.input_period_ids:
                self._require(reference, set(periods), "CalculationResult input_period_ids")
            declared_inputs = {
                *calculation.input_fact_ids,
                *calculation.input_assumption_ids,
                *calculation.input_calculation_ids,
                *calculation.input_period_ids,
            }
            if not set(calculation.input_bindings.values()).issubset(declared_inputs):
                raise ContractGraphError(
                    f"Calculation {calculation.calculation_id} has an undeclared input binding"
                )

        for period in self.periods:
            try:
                validate_fiscal_period(period)
            except QuarterlyComputationError as exc:
                raise ContractGraphError(
                    f"FiscalPeriod {period.period_id} is invalid: {exc}"
                ) from exc
            for reference in period.source_document_ids:
                self._require(reference, set(documents), "FiscalPeriod source_document_ids")
            if period.comparative_period_id is not None:
                self._require(
                    period.comparative_period_id,
                    set(periods),
                    "FiscalPeriod comparative_period_id",
                )
                if period.comparative_period_id == period.period_id:
                    raise ContractGraphError(f"FiscalPeriod {period.period_id} references itself")
                comparison = periods[period.comparative_period_id]
                if (
                    comparison.fiscal_year != period.fiscal_year - 1
                    or comparison.fiscal_quarter != period.fiscal_quarter
                ):
                    raise ContractGraphError(
                        "FiscalPeriod comparison must be the prior fiscal year same quarter"
                    )

        for reconciliation in self.reconciliations:
            self._require(
                reconciliation.period_id,
                set(periods),
                "QuarterlyReconciliation period_id",
            )
            reconciliation_period = periods[reconciliation.period_id]
            first_candidate: Fact | None = None
            expected_fact_period = (
                {
                    "start": reconciliation_period.quarter_start,
                    "end": reconciliation_period.quarter_end,
                }
                if reconciliation.basis == "single_quarter"
                else {
                    "start": reconciliation_period.cumulative_start,
                    "end": reconciliation_period.cumulative_end,
                }
            )
            for reference in reconciliation.candidate_fact_ids:
                self._require(reference, set(facts), "QuarterlyReconciliation candidate_fact_ids")
                candidate = facts[reference]
                if first_candidate is None:
                    first_candidate = candidate
                if candidate.concept != reconciliation.concept:
                    raise ContractGraphError("QuarterlyReconciliation candidate concept mismatch")
                if (
                    candidate.value_type != "number"
                    or candidate.unit != first_candidate.unit
                    or candidate.currency != first_candidate.currency
                ):
                    raise ContractGraphError(
                        "QuarterlyReconciliation candidate unit or currency mismatch"
                    )
                if dict(facts[reference].period) != expected_fact_period:
                    raise ContractGraphError("QuarterlyReconciliation candidate period mismatch")
            if first_candidate is None:
                raise ContractGraphError("QuarterlyReconciliation requires candidate Facts")
            if reconciliation.authoritative_fact_id is not None:
                self._require(
                    reconciliation.authoritative_fact_id,
                    set(facts),
                    "QuarterlyReconciliation authoritative_fact_id",
                )
                if reconciliation.authoritative_fact_id not in reconciliation.candidate_fact_ids:
                    raise ContractGraphError(
                        "QuarterlyReconciliation authority is not a candidate Fact"
                    )
            if reconciliation.delta_calculation_id is not None:
                self._require(
                    reconciliation.delta_calculation_id,
                    set(calculations),
                    "QuarterlyReconciliation delta_calculation_id",
                )
                delta = calculations[reconciliation.delta_calculation_id]
                if delta.concept != (f"{reconciliation.concept}.reconciliation_max_absolute_delta"):
                    raise ContractGraphError(
                        "QuarterlyReconciliation delta calculation concept mismatch"
                    )
                if dict(delta.period) != expected_fact_period:
                    raise ContractGraphError(
                        "QuarterlyReconciliation delta calculation period mismatch"
                    )
                if delta.unit != first_candidate.unit or delta.currency != first_candidate.currency:
                    raise ContractGraphError(
                        "QuarterlyReconciliation delta unit or currency mismatch"
                    )
                if set(delta.input_fact_ids) != set(reconciliation.candidate_fact_ids):
                    raise ContractGraphError(
                        "QuarterlyReconciliation delta must cover every candidate Fact"
                    )
                if reconciliation.period_id not in delta.input_period_ids:
                    raise ContractGraphError(
                        "QuarterlyReconciliation delta lacks FiscalPeriod input"
                    )
                if (
                    reconciliation.authoritative_fact_id is not None
                    and delta.input_bindings.get("authoritative")
                    != reconciliation.authoritative_fact_id
                ):
                    raise ContractGraphError(
                        "QuarterlyReconciliation delta authority binding mismatch"
                    )
                if (
                    delta.value_type != "number"
                    or isinstance(delta.value, bool)
                    or not isinstance(delta.value, (int, float))
                ):
                    raise ContractGraphError("QuarterlyReconciliation delta is not numeric")
            regulatory_candidates = [
                reference
                for reference in reconciliation.candidate_fact_ids
                if documents[facts[reference].source_document_id].authority_level
                == "primary_regulatory"
            ]
            if reconciliation.selection_rule == "no_regulatory_authority":
                if regulatory_candidates:
                    raise ContractGraphError(
                        "QuarterlyReconciliation ignored available regulatory authority"
                    )
            else:
                if not regulatory_candidates:
                    raise ContractGraphError("QuarterlyReconciliation lacks regulatory authority")
                authority_id = reconciliation.authoritative_fact_id
                if authority_id is None:
                    raise ContractGraphError("QuarterlyReconciliation lacks authoritative Fact")
                authority_document = documents[facts[authority_id].source_document_id]
                if authority_document.authority_level != "primary_regulatory":
                    raise ContractGraphError("QuarterlyReconciliation authority is not regulatory")
                expected_authority_id = max(
                    regulatory_candidates,
                    key=lambda reference: (
                        documents[facts[reference].source_document_id].document_type.endswith("/A"),
                        documents[facts[reference].source_document_id].published_date,
                        reference,
                    ),
                )
                if authority_id != expected_authority_id:
                    raise ContractGraphError(
                        "QuarterlyReconciliation did not select latest regulatory authority"
                    )
                amended = authority_document.document_type.endswith("/A")
                expected_rule = (
                    "latest_regulatory_amendment" if amended else "regulatory_over_company_release"
                )
                if reconciliation.selection_rule != expected_rule:
                    raise ContractGraphError(
                        "QuarterlyReconciliation authority selection rule mismatch"
                    )
                if reconciliation.delta_calculation_id is None:
                    raise ContractGraphError(
                        "QuarterlyReconciliation authority lacks a delta calculation"
                    )
                delta = calculations[reconciliation.delta_calculation_id]
                authority_value = facts[authority_id].value
                other_values = [
                    facts[identifier].value
                    for identifier in reconciliation.candidate_fact_ids
                    if identifier != authority_id
                ]
                if (
                    isinstance(authority_value, bool)
                    or not isinstance(authority_value, (int, float))
                    or any(
                        isinstance(value, bool) or not isinstance(value, (int, float))
                        for value in other_values
                    )
                ):
                    raise ContractGraphError("QuarterlyReconciliation candidates are not numeric")
                expected_delta = max(
                    abs(float(authority_value) - float(value)) for value in other_values
                )
                if not isclose(float(delta.value), expected_delta, abs_tol=1e-12):
                    raise ContractGraphError("QuarterlyReconciliation maximum delta mismatch")
                expected_status = (
                    "restated_authority"
                    if amended
                    else (
                        "exact_match"
                        if expected_delta == 0
                        else (
                            "tolerance_match"
                            if expected_delta <= reconciliation.tolerance
                            else "conflict"
                        )
                    )
                )
                if reconciliation.status != expected_status:
                    raise ContractGraphError(
                        "QuarterlyReconciliation status contradicts its evidence"
                    )
        claim_groups = (
            "what_changed_claim_ids",
            "why_it_changed_claim_ids",
            "temporary_or_structural_claim_ids",
            "guidance_change_claim_ids",
            "long_term_thesis_impact_claim_ids",
            "impact_on_valuation_assumptions_claim_ids",
        )
        for update in self.quarterly_updates:
            self._require(
                update.current_period_id, set(periods), "QuarterlyUpdate current_period_id"
            )
            self._require(
                update.comparison_period_id,
                set(periods),
                "QuarterlyUpdate comparison_period_id",
            )
            current_period = periods[update.current_period_id]
            comparison_period = periods[update.comparison_period_id]
            if current_period.comparative_period_id != update.comparison_period_id:
                raise ContractGraphError(
                    "QuarterlyUpdate comparison does not match FiscalPeriod metadata"
                )
            for reference in update.fact_ids:
                self._require(reference, set(facts), "QuarterlyUpdate fact_ids")
            comparability_facts = [
                facts[reference]
                for reference in update.fact_ids
                if facts[reference].concept in COMPARABILITY_EVIDENCE_CONCEPTS
            ]
            try:
                evidence_assessment = assess_comparability(
                    current_period,
                    comparison_period,
                    comparability_facts,
                )
            except QuarterlyComputationError as exc:
                raise ContractGraphError(
                    f"QuarterlyUpdate comparability evidence is invalid: {exc}"
                ) from exc
            if evidence_assessment.status != update.comparability[
                "status"
            ] or evidence_assessment.reasons != tuple(update.comparability["reasons"]):
                raise ContractGraphError(
                    "QuarterlyUpdate comparability does not match referenced evidence"
                )
            for reference in update.calculation_result_ids:
                self._require(
                    reference, set(calculations), "QuarterlyUpdate calculation_result_ids"
                )
            for reference in update.reconciliation_ids:
                self._require(reference, set(reconciliations), "QuarterlyUpdate reconciliation_ids")
                reconciliation = reconciliations[reference]
                if reconciliation.period_id != update.current_period_id:
                    raise ContractGraphError(
                        "QuarterlyUpdate reconciliation belongs to another period"
                    )
                if reconciliation.blocked and update.status != "blocked":
                    raise ContractGraphError(
                        "Blocked reconciliation requires a blocked QuarterlyUpdate"
                    )
            if update.comparability["status"] in {"not_comparable", "unknown"} and (
                update.status != "blocked"
            ):
                raise ContractGraphError(
                    "Unresolved comparability requires a blocked QuarterlyUpdate"
                )
            for group in claim_groups:
                for reference in getattr(update, group):
                    self._require(reference, set(claims), f"QuarterlyUpdate {group}")

        for artifact in self.filing_artifacts:
            self._require(
                artifact.source_document_id, set(documents), "FilingArtifact source_document_id"
            )
            document = documents[artifact.source_document_id]
            if artifact.issuer_id != document.issuer_id:
                raise ContractGraphError("FilingArtifact issuer conflicts with SourceDocument")
            if document.document_type != artifact.form:
                raise ContractGraphError("FilingArtifact form conflicts with SourceDocument")
            if document.published_date != artifact.filing_date:
                raise ContractGraphError("FilingArtifact filing date conflicts with SourceDocument")
            if artifact.report_period != document.period["end"]:
                raise ContractGraphError(
                    "FilingArtifact report period conflicts with SourceDocument"
                )
            if document.authority_level != "primary_regulatory":
                raise ContractGraphError("FilingArtifact source is not primary regulatory")
            if (
                not artifact.source_url.startswith("https://")
                or "sec.gov/" not in artifact.source_url
            ):
                raise ContractGraphError("FilingArtifact source URL is not SEC")

        for candidate in self.extraction_candidates:
            self._require(
                candidate.source_document_id,
                set(documents),
                "ExtractionCandidate source_document_id",
            )
            self._require(candidate.artifact_id, set(artifacts), "ExtractionCandidate artifact_id")
            artifact = artifacts[candidate.artifact_id]
            if candidate.issuer_id != artifact.issuer_id:
                raise ContractGraphError("ExtractionCandidate issuer conflicts with FilingArtifact")
            if artifact.source_document_id != candidate.source_document_id:
                raise ContractGraphError("ExtractionCandidate source and artifact disagree")
            if candidate.value_type == "number" and (not candidate.unit or not candidate.currency):
                raise ContractGraphError("numeric ExtractionCandidate lacks unit or currency")

        # A candidate may not silently disappear between extraction and review.  Exactly one
        # promotion record is required even when the decision is blocked or rejected.
        promoted_candidate_ids = [item.candidate_id for item in self.evidence_promotions]
        if len(promoted_candidate_ids) != len(candidates) or set(promoted_candidate_ids) != set(
            candidates
        ):
            raise ContractGraphError(
                "every ExtractionCandidate must have exactly one EvidencePromotion"
            )

        for promotion in self.evidence_promotions:
            self._require(promotion.candidate_id, set(candidates), "EvidencePromotion candidate_id")
            candidate = candidates[promotion.candidate_id]
            if promotion.issuer_id != candidate.issuer_id:
                raise ContractGraphError("EvidencePromotion issuer conflicts with candidate")
            if promotion.candidate_fingerprint != candidate.fingerprint:
                raise ContractGraphError("EvidencePromotion candidate fingerprint mismatch")
            if promotion.decision in {"auto_fact", "human_confirmed_fact"} and (
                promotion.output_fact_id is None or promotion.output_claim_id is not None
            ):
                raise ContractGraphError("Fact promotion must identify only an output Fact")
            if promotion.decision == "human_confirmed_claim" and (
                promotion.output_claim_id is None or promotion.output_fact_id is not None
            ):
                raise ContractGraphError("Claim promotion must identify only an output Claim")
            if promotion.decision in {"blocked", "rejected"} and (
                promotion.output_fact_id is not None or promotion.output_claim_id is not None
            ):
                raise ContractGraphError("blocked or rejected promotion cannot emit an output")
            if promotion.approval_kind == "deterministic_program" and promotion.reviewer_id:
                raise ContractGraphError("deterministic promotion cannot carry a human reviewer")
            if promotion.approval_kind == "human" and promotion.reviewer_id is None:
                raise ContractGraphError("human promotion requires a reviewer")
            if promotion.decision == "auto_fact":
                if (
                    candidate.extraction_method
                    not in {"deterministic_table", "deterministic_ixbrl"}
                    or candidate.candidate_kind != "numeric_fact"
                    or candidate.validation_status != "validated"
                    or candidate.high_impact
                    or not all(promotion.checks.values())
                    or promotion.approval_kind != "deterministic_program"
                ):
                    raise ContractGraphError(
                        "EvidencePromotion violated automatic promotion policy"
                    )
            if candidate.extraction_method == "language_model" and promotion.decision in {
                "auto_fact",
                "human_confirmed_fact",
            }:
                raise ContractGraphError("language-model candidate cannot create a Fact")
            if promotion.output_fact_id is not None:
                self._require(
                    promotion.output_fact_id, set(facts), "EvidencePromotion output_fact_id"
                )
            if promotion.output_claim_id is not None:
                self._require(
                    promotion.output_claim_id, set(claims), "EvidencePromotion output_claim_id"
                )
            if promotion.output_fact_id is not None:
                output_fact = facts[promotion.output_fact_id]
                if (
                    output_fact.issuer_id != candidate.issuer_id
                    or output_fact.concept != candidate.concept
                    or output_fact.value_type != candidate.value_type
                    or output_fact.value != candidate.value
                    or output_fact.unit != candidate.unit
                    or output_fact.currency != candidate.currency
                    or dict(output_fact.period) != dict(candidate.period)
                    or output_fact.source_document_id != candidate.source_document_id
                ):
                    raise ContractGraphError(
                        "EvidencePromotion output Fact does not preserve candidate evidence"
                    )
            if promotion.output_claim_id is not None:
                output_claim = claims[promotion.output_claim_id]
                if output_claim.issuer_id != candidate.issuer_id:
                    raise ContractGraphError("EvidencePromotion output Claim issuer mismatch")

        for segment in self.segment_definitions:
            for reference in segment.source_document_ids:
                self._require(reference, set(documents), "SegmentDefinition source_document_ids")
            for reference in segment.predecessor_segment_ids:
                self._require(reference, set(segments), "SegmentDefinition predecessor_segment_ids")
                if reference == segment.segment_id:
                    raise ContractGraphError("SegmentDefinition cannot be its own predecessor")
            if segment.mapping_status in {"partial", "not_comparable"}:
                if segment.mapping_claim_id is None:
                    raise ContractGraphError("non-exact SegmentDefinition requires a mapping Claim")
                self._require(
                    segment.mapping_claim_id, set(claims), "SegmentDefinition mapping_claim_id"
                )
            elif segment.mapping_claim_id is not None:
                self._require(
                    segment.mapping_claim_id, set(claims), "SegmentDefinition mapping_claim_id"
                )

        for snapshot in self.segment_snapshots:
            self._require(
                snapshot.fiscal_period_id, set(periods), "SegmentSnapshot fiscal_period_id"
            )
            snapshot_period = periods[snapshot.fiscal_period_id]
            if snapshot.issuer_id != snapshot_period.issuer_id:
                raise ContractGraphError("SegmentSnapshot issuer conflicts with FiscalPeriod")
            for reference in snapshot.segment_definition_ids:
                self._require(reference, set(segments), "SegmentSnapshot segment_definition_ids")
            assignment_ids = set()
            for assignment in snapshot.metric_assignments:
                segment_id = assignment["segment_id"]
                fact_id = assignment["fact_id"]
                self._require(segment_id, set(segments), "SegmentSnapshot metric segment_id")
                self._require(fact_id, set(facts), "SegmentSnapshot metric fact_id")
                if segment_id not in snapshot.segment_definition_ids:
                    raise ContractGraphError("SegmentSnapshot assignment segment is not declared")
                if segments[segment_id].segment_type in {"geographic", "customer_concentration"}:
                    raise ContractGraphError(
                        "geography or customer concentration used as reportable segment"
                    )
                fact = facts[fact_id]
                if fact.issuer_id != snapshot.issuer_id:
                    raise ContractGraphError("SegmentSnapshot Fact issuer mismatch")
                cumulative_period = {
                    "start": snapshot_period.cumulative_start,
                    "end": snapshot_period.cumulative_end,
                }
                quarter_period = {
                    "start": snapshot_period.quarter_start,
                    "end": snapshot_period.quarter_end,
                }
                if dict(fact.period) not in (cumulative_period, quarter_period):
                    raise ContractGraphError(
                        "SegmentSnapshot Fact period does not match FiscalPeriod"
                    )
                if (
                    fact.unit != snapshot.display_precision["unit"]
                    or fact.currency != snapshot.display_precision["currency"]
                ):
                    raise ContractGraphError(
                        "SegmentSnapshot Fact conflicts with display precision"
                    )
                pair = (segment_id, fact_id, assignment["metric_role"])
                if pair in assignment_ids:
                    raise ContractGraphError("SegmentSnapshot has a duplicate metric assignment")
                assignment_ids.add(pair)
            for reference in snapshot.consolidated_fact_ids:
                self._require(reference, set(facts), "SegmentSnapshot consolidated_fact_ids")
            for reference in snapshot.reconciliation_calculation_ids:
                self._require(
                    reference, set(calculations), "SegmentSnapshot reconciliation_calculation_ids"
                )
                if not calculations[reference].concept.endswith(".segment_reconciliation_delta"):
                    raise ContractGraphError("SegmentSnapshot has a non-reconciliation calculation")
            for reference in snapshot.comparability_claim_ids:
                self._require(reference, set(claims), "SegmentSnapshot comparability_claim_ids")
            if (
                any(
                    segments[reference].mapping_status != "exact"
                    for reference in snapshot.segment_definition_ids
                )
                and not snapshot.comparability_claim_ids
            ):
                raise ContractGraphError("non-exact segment mapping requires comparability Claim")
            if snapshot.status == "blocked" and not snapshot.missing_evidence:
                raise ContractGraphError("blocked SegmentSnapshot requires missing evidence")
            if snapshot.status == "complete":
                if snapshot.missing_evidence:
                    raise ContractGraphError(
                        "complete SegmentSnapshot cannot have missing evidence"
                    )
                if not snapshot.reconciliation_calculation_ids:
                    raise ContractGraphError(
                        "complete SegmentSnapshot requires reconciliation calculations"
                    )
                consolidated_ids = set(snapshot.consolidated_fact_ids)
                for calculation_id in snapshot.reconciliation_calculation_ids:
                    calculation = calculations[calculation_id]
                    if calculation.unit != snapshot.display_precision["unit"] or (
                        calculation.currency != snapshot.display_precision["currency"]
                    ):
                        raise ContractGraphError(
                            "segment reconciliation conflicts with display precision"
                        )
                    if dict(calculation.period) not in (cumulative_period, quarter_period):
                        raise ContractGraphError(
                            "segment reconciliation period does not match FiscalPeriod"
                        )
                    base_concept = calculation.concept.removesuffix(".segment_reconciliation_delta")
                    segment_ids = {
                        assignment["fact_id"]
                        for assignment in snapshot.metric_assignments
                        if facts[assignment["fact_id"]].concept == base_concept
                    }
                    consolidated_for_metric = {
                        fact_id
                        for fact_id in consolidated_ids
                        if facts[fact_id].concept == base_concept
                    }
                    expected_ids = segment_ids.union(consolidated_for_metric)
                    if not expected_ids or set(calculation.input_fact_ids) != expected_ids:
                        raise ContractGraphError(
                            "segment reconciliation does not consume exactly the metric Facts"
                        )
                    if any(
                        facts[fact_id].value_type != "number"
                        or isinstance(facts[fact_id].value, bool)
                        or not isinstance(facts[fact_id].value, (int, float))
                        for fact_id in expected_ids
                    ):
                        raise ContractGraphError(
                            "segment reconciliation requires numeric metric Facts"
                        )
                    expected_delta = sum(
                        float(facts[fact_id].value) for fact_id in segment_ids
                    ) - sum(float(facts[fact_id].value) for fact_id in consolidated_for_metric)
                    tolerance = (
                        snapshot.display_precision["rounding_increment"] * len(expected_ids) / 2
                    )
                    if abs(expected_delta) > tolerance:
                        raise ContractGraphError(
                            "segment reconciliation exceeds disclosed display precision"
                        )
                    if (
                        not isinstance(calculation.value, (int, float))
                        or isinstance(calculation.value, bool)
                        or not isclose(float(calculation.value), expected_delta, abs_tol=tolerance)
                    ):
                        raise ContractGraphError(
                            "segment reconciliation exceeds disclosed display precision"
                        )

        for review in self.footnote_reviews:
            self._require(review.fiscal_period_id, set(periods), "FootnoteReview fiscal_period_id")
            if review.issuer_id != periods[review.fiscal_period_id].issuer_id:
                raise ContractGraphError("FootnoteReview issuer conflicts with FiscalPeriod")
            for reference in review.source_document_ids:
                self._require(reference, set(documents), "FootnoteReview source_document_ids")
            for reference in review.candidate_ids:
                self._require(reference, set(candidates), "FootnoteReview candidate_ids")
            for reference in review.fact_ids:
                self._require(reference, set(facts), "FootnoteReview fact_ids")
            for reference in review.claim_ids:
                self._require(reference, set(claims), "FootnoteReview claim_ids")
            for reference in review.calculation_result_ids:
                self._require(reference, set(calculations), "FootnoteReview calculation_result_ids")
            evidence_count = sum(
                len(group)
                for group in (
                    review.source_document_ids,
                    review.candidate_ids,
                    review.fact_ids,
                    review.claim_ids,
                    review.calculation_result_ids,
                )
            )
            if review.status == "reviewed" and evidence_count == 0:
                raise ContractGraphError("reviewed FootnoteReview requires evidence")
            if review.status == "not_disclosed" and not review.source_document_ids:
                raise ContractGraphError(
                    "not-disclosed FootnoteReview requires a reviewed SourceDocument"
                )
            if review.status == "not_applicable" and not review.claim_ids:
                raise ContractGraphError("not-applicable FootnoteReview requires a Claim")
            if review.status == "not_applicable":
                for claim_id in review.claim_ids:
                    claim = claims[claim_id]
                    if not claim.supporting_fact_ids or not claim.falsification_condition.strip():
                        raise ContractGraphError(
                            "not-applicable FootnoteReview Claim lacks evidence or falsification"
                        )
            if review.status == "blocked" and not review.missing_evidence:
                raise ContractGraphError("blocked FootnoteReview requires missing evidence")

        for finding in self.accounting_quality_findings:
            if finding.issuer_id not in {
                item.issuer_id for item in (*self.facts, *self.claims, *self.calculations)
            }:
                raise ContractGraphError("AccountingQualityFinding issuer has no graph evidence")
            for reference in finding.fact_ids:
                self._require(reference, set(facts), "AccountingQualityFinding fact_ids")
            for reference in finding.calculation_result_ids:
                self._require(
                    reference, set(calculations), "AccountingQualityFinding calculation_result_ids"
                )
            for reference in finding.claim_ids:
                self._require(reference, set(claims), "AccountingQualityFinding claim_ids")
            if finding.status != "blocked" and not finding.claim_ids:
                raise ContractGraphError("final AccountingQualityFinding requires a Claim")
            if finding.status == "blocked" and finding.final_severity != "informational":
                raise ContractGraphError("blocked AccountingQualityFinding cannot be a red flag")
            for claim_id in finding.claim_ids:
                claim = claims[claim_id]
                if claim.issuer_id != finding.issuer_id:
                    raise ContractGraphError("AccountingQualityFinding Claim issuer mismatch")
                if not claim.falsification_condition.strip():
                    raise ContractGraphError("AccountingQualityFinding Claim lacks falsification")
            if finding.final_severity != finding.suggested_severity:
                if finding.override_claim_id is None:
                    raise ContractGraphError("severity override requires a Claim")
                self._require(
                    finding.override_claim_id,
                    set(claims),
                    "AccountingQualityFinding override_claim_id",
                )
            if finding.status == "blocked" and not finding.missing_evidence:
                raise ContractGraphError(
                    "blocked AccountingQualityFinding requires missing evidence"
                )

        for review in self.accounting_quality_reviews:
            self._require(
                review.fiscal_period_id, set(periods), "AccountingQualityReview fiscal_period_id"
            )
            if review.issuer_id != periods[review.fiscal_period_id].issuer_id:
                raise ContractGraphError(
                    "AccountingQualityReview issuer conflicts with FiscalPeriod"
                )
            if set(review.required_topic_codes) != set(REQUIRED_TOPICS):
                raise ContractGraphError("AccountingQualityReview mandatory topic set mismatch")
            selected: list[FootnoteReview] = []
            for reference in review.footnote_review_ids:
                self._require(reference, set(footnotes), "AccountingQualityReview footnote IDs")
                selected.append(footnotes[reference])
            mandatory_selected = [item for item in selected if item.topic_code != "dynamic"]
            if len(mandatory_selected) != len(REQUIRED_TOPICS) or {
                item.topic_code for item in mandatory_selected
            } != set(REQUIRED_TOPICS):
                raise ContractGraphError(
                    "AccountingQualityReview does not cover every mandatory topic"
                )
            expected_coverage = {
                "required_count": len(REQUIRED_TOPICS),
                "reviewed_count": sum(item.status == "reviewed" for item in mandatory_selected),
                "not_disclosed_count": sum(
                    item.status == "not_disclosed" for item in mandatory_selected
                ),
                "not_applicable_count": sum(
                    item.status == "not_applicable" for item in mandatory_selected
                ),
                "blocked_count": sum(item.status == "blocked" for item in mandatory_selected),
            }
            if dict(review.coverage) != expected_coverage:
                raise ContractGraphError("AccountingQualityReview coverage counts mismatch")
            for reference in review.finding_ids:
                self._require(reference, set(findings), "AccountingQualityReview finding_ids")
            if review.status == "complete" and expected_coverage["blocked_count"]:
                raise ContractGraphError(
                    "complete AccountingQualityReview cannot contain blocked topics"
                )
            if review.status == "blocked" and not review.missing_evidence:
                raise ContractGraphError(
                    "blocked AccountingQualityReview requires missing evidence"
                )

        def validate_business_scope(scope: Any, issuer_id: str, context: str) -> None:
            segment_ids = tuple(scope["segment_definition_ids"])
            for reference in segment_ids:
                self._require(reference, set(segments), f"{context} segment_definition_ids")
                if segments[reference].issuer_id != issuer_id:
                    raise ContractGraphError(f"{context} segment issuer mismatch")
            if scope["scope_type"] == "segment_specific" and not segment_ids:
                raise ContractGraphError(f"segment-specific {context} lacks a segment")
            if scope["scope_type"] == "issuer_wide" and segment_ids:
                raise ContractGraphError(f"issuer-wide {context} cannot bind segments")
            if scope["scope_type"] == "product_market" and not any(
                scope[key]
                for key in (
                    "business_unit",
                    "product_service",
                    "geography",
                    "customer_group",
                    "channel",
                )
            ):
                raise ContractGraphError(f"product-market {context} lacks a scope dimension")

        def validate_typed_binding(binding: Any, context: str) -> tuple[str, str]:
            references = {
                "fact": binding["fact_id"],
                "calculation": binding["calculation_result_id"],
                "observation": binding["context_observation_id"],
            }
            present = [(kind, value) for kind, value in references.items() if value is not None]
            if len(present) != 1:
                raise ContractGraphError(f"{context} must bind exactly one evidence object")
            kind, reference = present[0]
            if kind == "fact":
                self._require(reference, set(facts), context)
            elif kind == "calculation":
                require_phase4_calculation(reference, context)
            else:
                self._require(reference, set(observations), context)
            return kind, reference

        for observation in self.context_observations:
            self._require(
                observation.source_document_id,
                set(documents),
                "ContextObservation source_document_id",
            )
            document = documents[observation.source_document_id]
            if date.fromisoformat(document.published_date) > date.fromisoformat(
                observation.as_of_date
            ):
                raise ContractGraphError("ContextObservation uses future source evidence")
            role = observation.subject["role"]
            expected_subject = (
                observation.target_issuer_id
                if role == "target_issuer"
                else observation.subject["entity_id"]
            )
            if document.issuer_id != expected_subject:
                raise ContractGraphError("ContextObservation source subject mismatch")
            validate_business_scope(
                observation.scope,
                observation.target_issuer_id,
                "ContextObservation scope",
            )
            if observation.verification_status == "human_confirmed" and (
                observation.extraction_method == "language_model"
            ):
                raise ContractGraphError(
                    "language-model ContextObservation cannot be human-confirmed"
                )

        for candidate in self.analytical_claim_candidates:
            validate_business_scope(
                candidate.scope,
                candidate.issuer_id,
                "AnalyticalClaimCandidate scope",
            )
            for binding in (
                *candidate.supporting_evidence_bindings,
                *candidate.counterevidence_bindings,
            ):
                kind, reference = validate_typed_binding(
                    binding, "AnalyticalClaimCandidate evidence binding"
                )
                if kind == "fact" and facts[reference].issuer_id != candidate.issuer_id:
                    raise ContractGraphError("AnalyticalClaimCandidate Fact issuer mismatch")
                if (
                    kind == "calculation"
                    and calculations[reference].issuer_id != candidate.issuer_id
                ):
                    raise ContractGraphError(
                        "AnalyticalClaimCandidate CalculationResult issuer mismatch"
                    )
                if kind == "observation" and (
                    observations[reference].target_issuer_id != candidate.issuer_id
                ):
                    raise ContractGraphError(
                        "AnalyticalClaimCandidate ContextObservation target mismatch"
                    )
            expected_graph_hash = canonical_sha256(
                {
                    "supporting_evidence_bindings": candidate.supporting_evidence_bindings,
                    "counterevidence_bindings": candidate.counterevidence_bindings,
                }
            )
            if candidate.evidence_graph_sha256 != expected_graph_hash:
                raise ContractGraphError("AnalyticalClaimCandidate evidence graph hash mismatch")

        analytical_decision_by_claim: dict[str, AnalyticalClaimReviewDecision] = {}
        for decision in self.analytical_claim_review_decisions:
            self._require(
                decision.candidate_id,
                set(analytical_candidates),
                "AnalyticalClaimReviewDecision candidate_id",
            )
            candidate = analytical_candidates[decision.candidate_id]
            if decision.issuer_id != candidate.issuer_id:
                raise ContractGraphError("AnalyticalClaimReviewDecision issuer mismatch")
            if decision.candidate_fingerprint != candidate.fingerprint:
                raise ContractGraphError(
                    "AnalyticalClaimReviewDecision candidate fingerprint mismatch"
                )
            if decision.evidence_graph_sha256 != candidate.evidence_graph_sha256:
                raise ContractGraphError(
                    "AnalyticalClaimReviewDecision evidence graph hash mismatch"
                )
            if decision.decision == "confirmed":
                if candidate.validation_status != "ready":
                    raise ContractGraphError("non-ready AnalyticalClaimCandidate cannot confirm")
                assert decision.output_claim_id is not None
                self._require(
                    decision.output_claim_id,
                    set(claims),
                    "AnalyticalClaimReviewDecision output_claim_id",
                )
                if decision.output_claim_id in analytical_decision_by_claim:
                    raise ContractGraphError("confirmed Claim has multiple review decisions")
                claim = claims[decision.output_claim_id]
                if claim.issuer_id != decision.issuer_id:
                    raise ContractGraphError("confirmed analytical Claim issuer mismatch")
                supporting_fact_ids = {
                    binding["fact_id"]
                    for binding in candidate.supporting_evidence_bindings
                    if binding["fact_id"] is not None
                }
                counter_fact_ids = {
                    binding["fact_id"]
                    for binding in candidate.counterevidence_bindings
                    if binding["fact_id"] is not None
                }
                if not supporting_fact_ids or set(claim.supporting_fact_ids) != supporting_fact_ids:
                    raise ContractGraphError(
                        "confirmed analytical Claim must preserve target Fact support"
                    )
                if set(claim.counterevidence_fact_ids) != counter_fact_ids:
                    raise ContractGraphError("confirmed analytical Claim counterevidence mismatch")
                if (
                    claim.statement != candidate.proposed_statement
                    or claim.as_of_date != candidate.as_of_date
                    or claim.confidence != candidate.proposed_confidence
                    or claim.falsification_condition != candidate.falsification_condition
                    or claim.counterevidence_search_note != candidate.counterevidence_search_note
                ):
                    raise ContractGraphError(
                        "confirmed analytical Claim does not reproduce reviewed Candidate"
                    )
                analytical_decision_by_claim[claim.claim_id] = decision

        def require_analytical_claim(
            reference: str,
            context: str,
            *,
            cutoff: date | None = None,
        ) -> Claim:
            claim = require_claim(reference, context, cutoff=cutoff)
            if reference not in analytical_decision_by_claim:
                raise ContractGraphError(f"{context} Claim lacks analytical human review")
            return claim

        for context_snapshot in self.competitive_context_snapshots:
            as_of = date.fromisoformat(context_snapshot.as_of_date)
            validate_business_scope(
                context_snapshot.scope,
                context_snapshot.issuer_id,
                "CompetitiveContextSnapshot scope",
            )
            for reference in context_snapshot.source_document_ids:
                self._require(
                    reference,
                    set(documents),
                    "CompetitiveContextSnapshot source_document_ids",
                )
                if date.fromisoformat(documents[reference].published_date) > as_of:
                    raise ContractGraphError(
                        "CompetitiveContextSnapshot uses future source evidence"
                    )
            for reference in context_snapshot.observation_ids:
                self._require(
                    reference,
                    set(observations),
                    "CompetitiveContextSnapshot observation_ids",
                )
                observation = observations[reference]
                if observation.target_issuer_id != context_snapshot.issuer_id:
                    raise ContractGraphError("CompetitiveContextSnapshot target issuer mismatch")
                if observation.verification_status != "human_confirmed":
                    raise ContractGraphError(
                        "CompetitiveContextSnapshot requires confirmed observations"
                    )
                if observation.source_document_id not in context_snapshot.source_document_ids:
                    raise ContractGraphError(
                        "CompetitiveContextSnapshot omits an observation SourceDocument"
                    )
            for reference in context_snapshot.competitor_selection_claim_ids:
                require_analytical_claim(
                    reference,
                    "CompetitiveContextSnapshot competitor selection",
                    cutoff=as_of,
                )
            if not context_snapshot.competitor_selection_claim_ids and (
                context_snapshot.status != "blocked"
            ):
                raise ContractGraphError(
                    "CompetitiveContextSnapshot without competitor selection must be blocked"
                )
            topics = [item["topic"] for item in context_snapshot.coverage]
            if len(topics) != len(set(topics)) or set(topics) != CONTEXT_TOPICS:
                raise ContractGraphError("CompetitiveContextSnapshot topic coverage mismatch")
            for item in context_snapshot.coverage:
                if not set(item["observation_ids"]).issubset(set(context_snapshot.observation_ids)):
                    raise ContractGraphError(
                        "CompetitiveContextSnapshot coverage uses undeclared observation"
                    )
                for reference in item["claim_ids"]:
                    require_analytical_claim(
                        reference,
                        "CompetitiveContextSnapshot coverage Claim",
                        cutoff=as_of,
                    )
                if item["status"] == "reviewed" and not item["observation_ids"]:
                    raise ContractGraphError(
                        "reviewed CompetitiveContextSnapshot topic lacks observation"
                    )
                if item["status"] == "not_applicable" and not item["claim_ids"]:
                    raise ContractGraphError(
                        "not-applicable CompetitiveContextSnapshot topic lacks Claim"
                    )
                if item["status"] == "blocked" and not item["missing_evidence"]:
                    raise ContractGraphError(
                        "blocked CompetitiveContextSnapshot topic lacks missing evidence"
                    )
            if context_snapshot.status == "complete":
                if any(item["status"] == "blocked" for item in context_snapshot.coverage):
                    raise ContractGraphError(
                        "complete CompetitiveContextSnapshot cannot contain blocked topics"
                    )
                selected_documents = [
                    documents[reference] for reference in context_snapshot.source_document_ids
                ]
                has_target_primary = any(
                    item.issuer_id == context_snapshot.issuer_id
                    and item.authority_level in OFFICIAL_AUTHORITY_LEVELS
                    for item in selected_documents
                )
                has_independent = any(
                    item.issuer_id != context_snapshot.issuer_id
                    and item.authority_level in {*OFFICIAL_AUTHORITY_LEVELS, "audited_secondary"}
                    for item in selected_documents
                )
                if not (has_target_primary and has_independent):
                    raise ContractGraphError(
                        "complete CompetitiveContextSnapshot lacks independent source diversity"
                    )

        for snapshot in self.business_model_snapshots:
            as_of = date.fromisoformat(snapshot.as_of_date)
            for reference in snapshot.source_document_ids:
                self._require(
                    reference,
                    set(documents),
                    "BusinessModelSnapshot source_document_ids",
                )
                if date.fromisoformat(documents[reference].published_date) > as_of:
                    raise ContractGraphError("BusinessModelSnapshot uses future source evidence")
            for reference in snapshot.segment_snapshot_ids:
                self._require(
                    reference,
                    {item.snapshot_id for item in self.segment_snapshots},
                    "BusinessModelSnapshot segment_snapshot_ids",
                )
            material_scopes = {item["scope_id"]: item for item in snapshot.material_scopes}
            if len(material_scopes) != len(snapshot.material_scopes):
                raise ContractGraphError("BusinessModelSnapshot has duplicate material scope")
            for scope_id, item in material_scopes.items():
                validate_business_scope(item["scope"], snapshot.issuer_id, "material scope")
                expected_scope_id = (
                    f"business-scope:{snapshot.issuer_id}:"
                    f"{canonical_sha256(dict(item['scope']))[:20]}"
                )
                if scope_id != expected_scope_id:
                    raise ContractGraphError("BusinessModelSnapshot material scope ID mismatch")
                if item["segment_snapshot_id"] is not None:
                    self._require(
                        item["segment_snapshot_id"],
                        set(segment_snapshots),
                        "BusinessModelSnapshot material scope segment_snapshot_id",
                    )
                    if item["segment_snapshot_id"] not in snapshot.segment_snapshot_ids:
                        raise ContractGraphError(
                            "material scope uses an undeclared segment snapshot"
                        )
                for segment_id in item["segment_definition_ids"]:
                    self._require(
                        segment_id,
                        set(segments),
                        "BusinessModelSnapshot material scope segment_definition_ids",
                    )
                    if segments[segment_id].segment_type != "reportable":
                        raise ContractGraphError("material scope uses a non-reportable segment")
                if item["derivation"] == "confirmed_product_market":
                    if item["materiality_claim_id"] is None:
                        raise ContractGraphError("product-market scope lacks materiality Claim")
                    claim_id = item["materiality_claim_id"]
                    require_analytical_claim(claim_id, "product-market materiality", cutoff=as_of)
                    decision = analytical_decision_by_claim[claim_id]
                    candidate = analytical_candidates[decision.candidate_id]
                    if candidate.claim_role != "support" or canonical_sha256(
                        dict(candidate.scope)
                    ) != canonical_sha256(dict(item["scope"])):
                        raise ContractGraphError("product-market materiality Claim scope mismatch")
                elif item["materiality_claim_id"] is not None:
                    raise ContractGraphError("segment-derived scope cannot carry materiality Claim")
            component_ids: set[str] = set()
            evidence_documents: set[str] = set()
            by_component: dict[str, Any] = {}
            for component in snapshot.components:
                component_id = component["component_id"]
                if component_id in component_ids:
                    raise ContractGraphError("BusinessModelSnapshot has duplicate component_id")
                component_ids.add(component_id)
                by_component[component_id] = component
                roles = set(component["attribute_roles"])
                if not roles or roles - BUSINESS_ATTRIBUTE_ROLES[component["component_type"]]:
                    raise ContractGraphError(
                        "BusinessModelSnapshot has invalid business attribute role"
                    )
                validate_business_scope(
                    component["scope"], snapshot.issuer_id, "business component"
                )
                scope_id = (
                    f"business-scope:{snapshot.issuer_id}:"
                    f"{canonical_sha256(dict(component['scope']))[:20]}"
                )
                if component["scope_id"] != scope_id:
                    raise ContractGraphError("BusinessModelSnapshot component scope ID mismatch")
                binding_facts: set[str] = set()
                binding_claims: set[str] = set()
                binding_roles: set[str] = set()
                seen_claim_roles: dict[str, str] = {}
                for binding in component["attribute_evidence_bindings"]:
                    role = binding["role"]
                    if role not in BUSINESS_ATTRIBUTE_ROLES[component["component_type"]]:
                        raise ContractGraphError("BusinessModelSnapshot attribute role mismatch")
                    binding_roles.add(role)
                    for fact_id in binding["fact_ids"]:
                        self._require(fact_id, set(facts), "attribute binding fact_ids")
                        if facts[fact_id].issuer_id != snapshot.issuer_id:
                            raise ContractGraphError("BusinessModelSnapshot Fact issuer mismatch")
                        evidence_documents.add(facts[fact_id].source_document_id)
                    for claim_id in binding["claim_ids"]:
                        require_analytical_claim(claim_id, "attribute binding Claim", cutoff=as_of)
                        decision = analytical_decision_by_claim[claim_id]
                        if decision.decision_id not in binding["review_decision_ids"]:
                            raise ContractGraphError("attribute binding omits Claim ReviewDecision")
                        candidate = analytical_candidates[decision.candidate_id]
                        if (
                            candidate.claim_role != "support"
                            or candidate.business_attribute_role != role
                            or candidate.business_component_type != component["component_type"]
                            or canonical_sha256(dict(candidate.scope))
                            != canonical_sha256(dict(component["scope"]))
                        ):
                            raise ContractGraphError(
                                "attribute Claim semantic role or scope mismatch"
                            )
                        claim = claims[claim_id]
                        if not set(binding["fact_ids"]).issubset(claim.supporting_fact_ids):
                            raise ContractGraphError("attribute Claim lacks bound Fact support")
                        if claim_id in seen_claim_roles and seen_claim_roles[claim_id] != role:
                            raise ContractGraphError(
                                "one Claim supports multiple business attributes"
                            )
                        seen_claim_roles[claim_id] = role
                        evidence_documents.update(
                            facts[fact_id].source_document_id
                            for fact_id in (
                                *claim.supporting_fact_ids,
                                *claim.counterevidence_fact_ids,
                            )
                        )
                    binding_facts.update(binding["fact_ids"])
                    binding_claims.update(binding["claim_ids"])
                if binding_roles != roles:
                    raise ContractGraphError(
                        "component attribute roles differ from evidence bindings"
                    )
                if binding_facts != set(component["fact_ids"]) or binding_claims != set(
                    component["claim_ids"]
                ):
                    raise ContractGraphError("component aggregate evidence differs from bindings")
            if not evidence_documents.issubset(set(snapshot.source_document_ids)):
                raise ContractGraphError("BusinessModelSnapshot omits an evidence SourceDocument")
            coverage_keys = [
                (item["scope_id"], item["component_type"])
                for item in snapshot.component_coverage
            ]
            expected_coverage = {
                (scope_id, component_type)
                for scope_id in material_scopes
                for component_type in BUSINESS_COMPONENT_TYPES
            }
            if (
                len(coverage_keys) != len(set(coverage_keys))
                or set(coverage_keys) != expected_coverage
            ):
                raise ContractGraphError("BusinessModelSnapshot component coverage mismatch")
            shared_pairs: set[tuple[str, str]] = set()
            for relation in snapshot.shared_scope_relations:
                self._require(relation["component_id"], component_ids, "shared-scope component_id")
                component = by_component[relation["component_id"]]
                if component["component_type"] not in {
                    "key_resource", "key_partner", "regulatory_dependency"
                } or component["scope"]["scope_type"] != "issuer_wide":
                    raise ContractGraphError("invalid shared-scope component")
                claim_id = relation["claim_id"]
                require_analytical_claim(claim_id, "shared-scope Claim", cutoff=as_of)
                decision = analytical_decision_by_claim[claim_id]
                if decision.decision_id != relation["review_decision_id"]:
                    raise ContractGraphError("shared-scope Claim Decision mismatch")
                candidate = analytical_candidates[decision.candidate_id]
                if (
                    candidate.claim_role != "support"
                    or candidate.scope["scope_type"] != "issuer_wide"
                ):
                    raise ContractGraphError("shared-scope Claim is not issuer-wide support")
                for scope_id in relation["covered_scope_ids"]:
                    self._require(scope_id, set(material_scopes), "shared-scope covered_scope_ids")
                    shared_pairs.add((scope_id, component["component_type"]))
            for item in snapshot.component_coverage:
                if not set(item["component_ids"]).issubset(component_ids):
                    raise ContractGraphError(
                        "BusinessModelSnapshot coverage uses undeclared component"
                    )
                if any(
                    by_component[reference]["component_type"] != item["component_type"]
                    for reference in item["component_ids"]
                ):
                    raise ContractGraphError(
                        "BusinessModelSnapshot coverage component type mismatch"
                    )
                if item["component_ids"]:
                    for reference in item["component_ids"]:
                        component = by_component[reference]
                        if component["scope_id"] != item["scope_id"] and (
                            item["scope_id"], item["component_type"]
                        ) not in shared_pairs:
                            raise ContractGraphError("coverage combines evidence across scopes")
                for reference in item["claim_ids"]:
                    require_analytical_claim(
                        reference,
                        "BusinessModelSnapshot coverage Claim",
                        cutoff=as_of,
                    )
                if item["status"] == "reviewed" and not item["component_ids"]:
                    raise ContractGraphError(
                        "reviewed BusinessModelSnapshot component lacks real component"
                    )
                if item["status"] == "reviewed":
                    roles = {
                        role
                        for component_id in item["component_ids"]
                        for role in by_component[component_id]["attribute_roles"]
                    }
                    if roles != BUSINESS_ATTRIBUTE_ROLES[item["component_type"]]:
                        raise ContractGraphError(
                            "BusinessModelSnapshot attribute coverage incomplete"
                        )
                if item["status"] == "not_applicable" and not item["claim_ids"]:
                    raise ContractGraphError(
                        "not-applicable BusinessModelSnapshot component lacks Claim"
                    )
                if item["status"] == "not_applicable":
                    if item["component_type"] not in {"key_partner", "regulatory_dependency"}:
                        raise ContractGraphError("component type cannot be not-applicable")
                    for claim_id in item["claim_ids"]:
                        decision = analytical_decision_by_claim[claim_id]
                        if decision.decision_id not in item["review_decision_ids"]:
                            raise ContractGraphError("not-applicable coverage omits Decision")
                        candidate = analytical_candidates[decision.candidate_id]
                        if (
                            candidate.claim_role != "not_applicable"
                            or candidate.business_component_type != item["component_type"]
                            or candidate.business_attribute_role is not None
                            or canonical_sha256(dict(candidate.scope))
                            != canonical_sha256(
                                dict(material_scopes[item["scope_id"]]["scope"])
                            )
                        ):
                            raise ContractGraphError("not-applicable Claim role or scope mismatch")
                if item["status"] == "blocked" and not item["missing_evidence"]:
                    raise ContractGraphError(
                        "blocked BusinessModelSnapshot component lacks missing evidence"
                    )
            if snapshot.status == "complete":
                if any(item["status"] == "blocked" for item in snapshot.component_coverage):
                    raise ContractGraphError(
                        "complete BusinessModelSnapshot cannot contain blocked components"
                    )
                if any(
                    segment_snapshots[reference].status != "complete"
                    for reference in snapshot.segment_snapshot_ids
                ):
                    raise ContractGraphError(
                        "complete BusinessModelSnapshot uses unresolved segments"
                    )
                if snapshot.missing_evidence:
                    raise ContractGraphError(
                        "complete BusinessModelSnapshot cannot contain missing evidence"
                    )
                if any(
                    documents[document_id].authority_level not in OFFICIAL_AUTHORITY_LEVELS
                    for document_id in evidence_documents
                ):
                    raise ContractGraphError(
                        "complete BusinessModelSnapshot cannot rely on third-party evidence"
                    )
            if snapshot.status == "blocked" and not snapshot.missing_evidence:
                raise ContractGraphError("blocked BusinessModelSnapshot requires missing evidence")

        for hypothesis in self.competitive_advantage_hypotheses:
            self._require(
                hypothesis.business_model_snapshot_id,
                set(business_models),
                "CompetitiveAdvantageHypothesis business_model_snapshot_id",
            )
            business_model = business_models[hypothesis.business_model_snapshot_id]
            if business_model.issuer_id != hypothesis.issuer_id:
                raise ContractGraphError("CompetitiveAdvantageHypothesis issuer mismatch")
            self._require(
                hypothesis.competitive_context_snapshot_id,
                set(competitive_contexts),
                "CompetitiveAdvantageHypothesis competitive_context_snapshot_id",
            )
            context_snapshot = competitive_contexts[hypothesis.competitive_context_snapshot_id]
            if context_snapshot.issuer_id != hypothesis.issuer_id:
                raise ContractGraphError("CompetitiveAdvantageHypothesis context issuer mismatch")
            validate_business_scope(
                hypothesis.scope,
                hypothesis.issuer_id,
                "CompetitiveAdvantageHypothesis scope",
            )
            if dict(hypothesis.scope) != dict(context_snapshot.scope):
                raise ContractGraphError("CompetitiveAdvantageHypothesis context scope mismatch")
            policy = mechanism_policy(
                hypothesis.mechanism_policy_id, hypothesis.mechanism_policy_version
            )
            if hypothesis.mechanism_policy_id != hypothesis.mechanism:
                raise ContractGraphError("CompetitiveAdvantageHypothesis policy mismatch")
            if hypothesis.mechanism_policy_version != POLICY_VERSION:
                raise ContractGraphError("CompetitiveAdvantageHypothesis policy version mismatch")
            role_polarities: dict[str, set[str]] = {"support": set(), "counterevidence": set()}
            evidence_references: set[tuple[str, str]] = set()
            counterevidence_references: set[tuple[str, str]] = set()
            evidence_document_ids: set[str] = set()
            for binding in hypothesis.evidence_bindings:
                if binding["role_id"] not in policy.allowed_roles:
                    raise ContractGraphError(
                        "CompetitiveAdvantageHypothesis uses an unregistered evidence role"
                    )
                kind, reference = validate_typed_binding(
                    binding, "CompetitiveAdvantageHypothesis evidence binding"
                )
                polarity = binding["polarity"]
                evidence_references.add((kind, reference))
                if polarity == "counterevidence":
                    counterevidence_references.add((kind, reference))
                role_polarities[polarity].add(binding["role_id"])
                expected_polarity = (
                    "support" if binding["role_id"] in policy.support_roles else "counterevidence"
                )
                if polarity != expected_polarity:
                    raise ContractGraphError(
                        "CompetitiveAdvantageHypothesis evidence role polarity mismatch"
                    )
                if kind == "fact":
                    if facts[reference].issuer_id != hypothesis.issuer_id:
                        raise ContractGraphError(
                            "CompetitiveAdvantageHypothesis Fact issuer mismatch"
                        )
                    evidence_document_ids.add(facts[reference].source_document_id)
                    if any(
                        shortcut in facts[reference].concept.lower()
                        for shortcut in policy.forbidden_single_indicators
                    ):
                        raise ContractGraphError(
                            "CompetitiveAdvantageHypothesis uses a forbidden shortcut"
                        )
                elif kind == "calculation":
                    if calculations[reference].issuer_id != hypothesis.issuer_id:
                        raise ContractGraphError(
                            "CompetitiveAdvantageHypothesis calculation issuer mismatch"
                        )
                    evidence_document_ids.update(
                        facts[fact_id].source_document_id
                        for fact_id in calculation_fact_ids(reference)
                    )
                    if any(
                        shortcut in calculations[reference].concept.lower()
                        for shortcut in policy.forbidden_single_indicators
                    ):
                        raise ContractGraphError(
                            "CompetitiveAdvantageHypothesis uses a forbidden shortcut"
                        )
                else:
                    observation = observations[reference]
                    if observation.target_issuer_id != hypothesis.issuer_id:
                        raise ContractGraphError(
                            "CompetitiveAdvantageHypothesis observation target mismatch"
                        )
                    evidence_document_ids.add(observation.source_document_id)
            positive_claim_ids = {
                reference
                for reference in (
                    hypothesis.hypothesis_claim_id,
                    hypothesis.durability_claim_id,
                    hypothesis.reinvestment_claim_id,
                )
                if reference is not None
            }
            all_hypothesis_claim_ids = {
                *positive_claim_ids,
                *hypothesis.counterevidence_claim_ids,
                *([hypothesis.trend_claim_id] if hypothesis.trend_claim_id else []),
            }
            declared_review_ids = set(hypothesis.claim_review_decision_ids)
            for reference in declared_review_ids:
                self._require(
                    reference,
                    set(analytical_decisions),
                    "CompetitiveAdvantageHypothesis claim_review_decision_ids",
                )
            reviewed_claim_ids = {
                analytical_decisions[reference].output_claim_id
                for reference in declared_review_ids
                if analytical_decisions[reference].decision == "confirmed"
            }
            if all_hypothesis_claim_ids != reviewed_claim_ids:
                raise ContractGraphError(
                    "CompetitiveAdvantageHypothesis analytical Claim review coverage mismatch"
                )
            if positive_claim_ids.intersection(hypothesis.counterevidence_claim_ids):
                raise ContractGraphError(
                    "CompetitiveAdvantageHypothesis mixes support and counterevidence Claims"
                )
            if hypothesis.status != "blocked":
                if hypothesis.hypothesis_claim_id is None:
                    raise ContractGraphError(
                        "non-blocked CompetitiveAdvantageHypothesis requires a core Claim"
                    )
                require_analytical_claim(
                    hypothesis.hypothesis_claim_id,
                    "CompetitiveAdvantageHypothesis hypothesis_claim_id",
                    cutoff=date.fromisoformat(hypothesis.as_of_date),
                )
            for reference in positive_claim_ids:
                decision = analytical_decision_by_claim[reference]
                candidate = analytical_candidates[decision.candidate_id]
                candidate_references = {
                    validate_typed_binding(
                        binding, "positive analytical Claim evidence binding"
                    )
                    for binding in (
                        *candidate.supporting_evidence_bindings,
                        *candidate.counterevidence_bindings,
                    )
                }
                if candidate.claim_role != "support" or not candidate_references.issubset(
                    evidence_references
                ):
                    raise ContractGraphError(
                        "CompetitiveAdvantageHypothesis positive Claim role or evidence mismatch"
                    )
            if hypothesis.status in {"supported", "contested", "falsified"}:
                for role, reference in (
                    ("durability_claim_id", hypothesis.durability_claim_id),
                    ("reinvestment_claim_id", hypothesis.reinvestment_claim_id),
                ):
                    if reference is None:
                        raise ContractGraphError(
                            f"{hypothesis.status} CompetitiveAdvantageHypothesis lacks {role}"
                        )
                    require_analytical_claim(
                        reference,
                        f"CompetitiveAdvantageHypothesis {role}",
                        cutoff=date.fromisoformat(hypothesis.as_of_date),
                    )
                positive_role_ids = (
                    hypothesis.hypothesis_claim_id,
                    hypothesis.durability_claim_id,
                    hypothesis.reinvestment_claim_id,
                )
                if len(set(positive_role_ids)) != 3:
                    raise ContractGraphError(
                        "CompetitiveAdvantageHypothesis positive role Claims must be distinct"
                    )
            if hypothesis.status in {"contested", "falsified"} and not (
                hypothesis.counterevidence_claim_ids
            ):
                raise ContractGraphError(
                    f"{hypothesis.status} CompetitiveAdvantageHypothesis lacks counterevidence"
                )
            reviewed_counterevidence_references: set[tuple[str, str]] = set()
            for reference in hypothesis.counterevidence_claim_ids:
                require_analytical_claim(
                    reference,
                    "CompetitiveAdvantageHypothesis counterevidence",
                    cutoff=date.fromisoformat(hypothesis.as_of_date),
                )
                decision = analytical_decision_by_claim[reference]
                counter_candidate = analytical_candidates[decision.candidate_id]
                if counter_candidate.claim_role not in {
                    "counterevidence",
                    "falsification",
                }:
                    raise ContractGraphError(
                        "CompetitiveAdvantageHypothesis counter Claim role mismatch"
                    )
                reviewed_counterevidence_references.update(
                    validate_typed_binding(
                        binding, "counter analytical Claim evidence binding"
                    )
                    for binding in (
                        *counter_candidate.supporting_evidence_bindings,
                        *counter_candidate.counterevidence_bindings,
                    )
                )
            resolution_claims = {
                item["counterevidence_claim_id"] for item in hypothesis.counterevidence_resolutions
            }
            if resolution_claims != set(hypothesis.counterevidence_claim_ids):
                raise ContractGraphError(
                    "CompetitiveAdvantageHypothesis counterevidence resolution mismatch"
                )
            for item in hypothesis.counterevidence_resolutions:
                counter_decision = analytical_decision_by_claim[
                    item["counterevidence_claim_id"]
                ]
                counter_candidate = analytical_candidates[counter_decision.candidate_id]
                if item["status"] == "falsifying" and (
                    counter_candidate.claim_role != "falsification"
                ):
                    raise ContractGraphError(
                        "falsifying resolution requires a reviewed falsification Claim"
                    )
                if item["status"] == "resolved" and item["resolution_claim_id"] is None:
                    raise ContractGraphError("resolved counterevidence requires a resolution Claim")
                if item["resolution_claim_id"] is not None:
                    require_analytical_claim(
                        item["resolution_claim_id"],
                        "CompetitiveAdvantageHypothesis resolution Claim",
                        cutoff=date.fromisoformat(hypothesis.as_of_date),
                    )
            if hypothesis.status == "supported":
                if role_polarities["support"] != policy.support_roles or (
                    role_polarities["counterevidence"] != policy.counterevidence_roles
                ):
                    raise ContractGraphError(
                        "supported CompetitiveAdvantageHypothesis lacks policy evidence roles"
                    )
                if any(
                    item["status"] != "resolved" for item in hypothesis.counterevidence_resolutions
                ):
                    raise ContractGraphError(
                        "supported CompetitiveAdvantageHypothesis retains unresolved "
                        "counterevidence"
                    )
                selected_documents = [documents[item] for item in evidence_document_ids]
                if not any(
                    item.issuer_id == hypothesis.issuer_id
                    and item.authority_level in OFFICIAL_AUTHORITY_LEVELS
                    for item in selected_documents
                ) or not any(
                    item.issuer_id != hypothesis.issuer_id
                    and item.authority_level in {*OFFICIAL_AUTHORITY_LEVELS, "audited_secondary"}
                    for item in selected_documents
                ):
                    raise ContractGraphError(
                        "supported CompetitiveAdvantageHypothesis lacks independent "
                        "source diversity"
                    )
            if hypothesis.status == "contested" and not any(
                item["status"] == "unresolved" for item in hypothesis.counterevidence_resolutions
            ):
                raise ContractGraphError(
                    "contested CompetitiveAdvantageHypothesis lacks unresolved counterevidence"
                )
            if hypothesis.status == "falsified" and not any(
                item["status"] == "falsifying" for item in hypothesis.counterevidence_resolutions
            ):
                raise ContractGraphError(
                    "falsified CompetitiveAdvantageHypothesis lacks falsifying evidence"
                )
            selected_documents = [documents[item] for item in evidence_document_ids]
            source_diverse = any(
                item.issuer_id == hypothesis.issuer_id
                and item.authority_level in OFFICIAL_AUTHORITY_LEVELS
                for item in selected_documents
            ) and any(
                item.issuer_id != hypothesis.issuer_id
                and item.authority_level
                in {*OFFICIAL_AUTHORITY_LEVELS, "audited_secondary"}
                for item in selected_documents
            )
            material_scope_closed = any(
                canonical_sha256(item["scope"]) == canonical_sha256(hypothesis.scope)
                for item in business_model.material_scopes
            )
            critical_missing = (
                business_model.status != "complete"
                or context_snapshot.status != "complete"
                or not material_scope_closed
                or hypothesis.hypothesis_claim_id is None
                or any(
                    item["status"] == "blocked"
                    for item in hypothesis.counterevidence_resolutions
                )
                or (
                    bool(counterevidence_references)
                    and not counterevidence_references.issubset(
                        reviewed_counterevidence_references
                    )
                )
            )
            has_three_positive_claims = len(positive_claim_ids) == 3
            has_falsifying = any(
                item["status"] == "falsifying"
                for item in hypothesis.counterevidence_resolutions
            )
            has_unresolved = any(
                item["status"] == "unresolved"
                for item in hypothesis.counterevidence_resolutions
            )
            policy_roles_complete = (
                role_polarities["support"] == policy.support_roles
                and role_polarities["counterevidence"] == policy.counterevidence_roles
            )
            if critical_missing:
                expected_status = "blocked"
            elif has_falsifying and has_three_positive_claims:
                expected_status = "falsified"
            elif has_unresolved and has_three_positive_claims:
                expected_status = "contested"
            elif (
                has_three_positive_claims
                and policy_roles_complete
                and source_diverse
                and all(
                    item["status"] == "resolved"
                    for item in hypothesis.counterevidence_resolutions
                )
                and hypothesis.reinvestment_relevance in {"direct", "indirect"}
            ):
                expected_status = "supported"
            else:
                expected_status = "proposed"
            if hypothesis.status != expected_status:
                raise ContractGraphError(
                    "CompetitiveAdvantageHypothesis status was not deterministically resolved"
                )
            assessment_start, assessment_end = validate_period(
                hypothesis.assessment_period,
                hypothesis.as_of_date,
                "CompetitiveAdvantageHypothesis",
            )
            if hypothesis.predecessor_hypothesis_id is not None:
                self._require(
                    hypothesis.predecessor_hypothesis_id,
                    set(hypotheses),
                    "CompetitiveAdvantageHypothesis predecessor_hypothesis_id",
                )
                predecessor = hypotheses[hypothesis.predecessor_hypothesis_id]
                if (
                    predecessor.issuer_id != hypothesis.issuer_id
                    or predecessor.mechanism != hypothesis.mechanism
                    or dict(predecessor.scope) != dict(hypothesis.scope)
                    or date.fromisoformat(predecessor.assessment_period["end"]) >= assessment_start
                ):
                    raise ContractGraphError(
                        "CompetitiveAdvantageHypothesis predecessor is not comparable"
                    )
                prior_counter_bindings = {
                    item["binding_id"]
                    for item in predecessor.evidence_bindings
                    if item["polarity"] == "counterevidence"
                }
                current_counter_bindings = {
                    item["binding_id"]
                    for item in hypothesis.evidence_bindings
                    if item["polarity"] == "counterevidence"
                }
                if not prior_counter_bindings.issubset(current_counter_bindings) or not set(
                    predecessor.counterevidence_claim_ids
                ).issubset(set(hypothesis.counterevidence_claim_ids)):
                    raise ContractGraphError(
                        "CompetitiveAdvantageHypothesis deleted predecessor counterevidence"
                    )
            if hypothesis.trend != "unknown":
                if (
                    hypothesis.predecessor_hypothesis_id is None
                    or hypothesis.trend_claim_id is None
                ):
                    raise ContractGraphError(
                        "CompetitiveAdvantageHypothesis trend lacks comparable evidence"
                    )
                decision = analytical_decision_by_claim[hypothesis.trend_claim_id]
                candidate = analytical_candidates[decision.candidate_id]
                if candidate.claim_role != hypothesis.trend:
                    raise ContractGraphError(
                        "CompetitiveAdvantageHypothesis trend Claim role mismatch"
                    )
            elif hypothesis.trend_claim_id is not None:
                raise ContractGraphError("unknown trend cannot bind a trend Claim")
            if hypothesis.status == "blocked" and not hypothesis.missing_evidence:
                raise ContractGraphError(
                    "blocked CompetitiveAdvantageHypothesis requires missing evidence"
                )

        for review in self.business_quality_reviews:
            review_start, review_end = validate_period(
                review.review_period, review.as_of_date, "BusinessQualityReview"
            )
            self._require(
                review.business_model_snapshot_id,
                set(business_models),
                "BusinessQualityReview business_model_snapshot_id",
            )
            business_model = business_models[review.business_model_snapshot_id]
            review_cutoff = date.fromisoformat(review.as_of_date)
            if date.fromisoformat(business_model.as_of_date) > review_cutoff:
                raise ContractGraphError("BusinessQualityReview uses a future business model")
            self._require(
                review.competitive_context_snapshot_id,
                set(competitive_contexts),
                "BusinessQualityReview competitive_context_snapshot_id",
            )
            selected_context = competitive_contexts[review.competitive_context_snapshot_id]
            if selected_context.issuer_id != review.issuer_id:
                raise ContractGraphError("BusinessQualityReview context issuer mismatch")
            eligible_contexts = [
                item
                for item in self.competitive_context_snapshots
                if item.issuer_id == review.issuer_id
                and date.fromisoformat(item.as_of_date) <= review_cutoff
                and canonical_sha256(item.scope) == canonical_sha256(selected_context.scope)
            ]
            latest_context = max(
                eligible_contexts,
                key=lambda item: (item.as_of_date, item.context_snapshot_id),
            )
            if latest_context.context_snapshot_id != selected_context.context_snapshot_id:
                raise ContractGraphError(
                    "BusinessQualityReview did not select the latest competitive context"
                )
            eligible_models = [
                item
                for item in self.business_model_snapshots
                if item.issuer_id == review.issuer_id
                and date.fromisoformat(item.as_of_date) <= review_cutoff
                and any(
                    canonical_sha256(scope_item["scope"])
                    == canonical_sha256(selected_context.scope)
                    for scope_item in item.material_scopes
                )
            ]
            latest_model = max(
                eligible_models, key=lambda item: (item.as_of_date, item.snapshot_id)
            )
            if latest_model.snapshot_id != business_model.snapshot_id:
                raise ContractGraphError(
                    "BusinessQualityReview did not select the latest business model"
                )
            matching_scope_ids = [
                item["scope_id"]
                for item in business_model.material_scopes
                if canonical_sha256(item["scope"])
                == canonical_sha256(selected_context.scope)
            ]
            if len(matching_scope_ids) != 1:
                raise ContractGraphError(
                    "BusinessQualityReview material scope is ambiguous"
                )
            scope_id = matching_scope_ids[0]
            for reference in review.hypothesis_ids:
                self._require(
                    reference,
                    set(hypotheses),
                    "BusinessQualityReview hypothesis_ids",
                )
                if date.fromisoformat(hypotheses[reference].as_of_date) > review_cutoff:
                    raise ContractGraphError(
                        "BusinessQualityReview uses a future hypothesis"
                    )
            eligible_review_hypotheses = [
                item
                for item in self.competitive_advantage_hypotheses
                if item.issuer_id == review.issuer_id
                and item.business_model_snapshot_id == business_model.snapshot_id
                and item.competitive_context_snapshot_id
                == selected_context.context_snapshot_id
                and canonical_sha256(item.scope) == canonical_sha256(selected_context.scope)
                and date.fromisoformat(item.as_of_date) <= review_cutoff
                and date.fromisoformat(item.assessment_period["start"]) <= review_end
                and date.fromisoformat(item.assessment_period["end"]) >= review_start
            ]
            latest_hypothesis_by_mechanism: dict[
                str, CompetitiveAdvantageHypothesis
            ] = {}
            for hypothesis in eligible_review_hypotheses:
                current = latest_hypothesis_by_mechanism.get(hypothesis.mechanism)
                if current is None or (
                    hypothesis.as_of_date,
                    hypothesis.assessment_period["end"],
                    hypothesis.hypothesis_id,
                ) > (
                    current.as_of_date,
                    current.assessment_period["end"],
                    current.hypothesis_id,
                ):
                    latest_hypothesis_by_mechanism[hypothesis.mechanism] = hypothesis
            expected_hypothesis_ids = {
                item.hypothesis_id for item in latest_hypothesis_by_mechanism.values()
            }
            if set(review.hypothesis_ids) != expected_hypothesis_ids:
                raise ContractGraphError(
                    "BusinessQualityReview did not select latest hypotheses"
                )
            selected_hypotheses: list[CompetitiveAdvantageHypothesis] = []
            for reference in review.hypothesis_ids:
                selected_hypotheses.append(hypotheses[reference])
            mechanisms = [item["mechanism"] for item in review.mechanism_coverage]
            if len(mechanisms) != len(set(mechanisms)) or set(mechanisms) != PHASE4_MECHANISMS:
                raise ContractGraphError("BusinessQualityReview mechanism coverage mismatch")
            for item in review.mechanism_coverage:
                if not set(item["hypothesis_ids"]).issubset(set(review.hypothesis_ids)):
                    raise ContractGraphError(
                        "BusinessQualityReview mechanism references an unselected hypothesis"
                    )
                for reference in item["hypothesis_ids"]:
                    if hypotheses[reference].mechanism != item["mechanism"]:
                        raise ContractGraphError(
                            "BusinessQualityReview mechanism and hypothesis mismatch"
                        )
                expected_hypothesis = latest_hypothesis_by_mechanism.get(item["mechanism"])
                expected_item_hypotheses = (
                    {expected_hypothesis.hypothesis_id}
                    if expected_hypothesis is not None
                    else set()
                )
                if set(item["hypothesis_ids"]) != expected_item_hypotheses:
                    raise ContractGraphError(
                        "BusinessQualityReview mechanism did not select latest hypothesis"
                    )
                for reference in item["claim_ids"]:
                    require_analytical_claim(
                        reference,
                        "BusinessQualityReview mechanism Claim",
                        cutoff=date.fromisoformat(review.as_of_date),
                    )
                    if reference not in review.claim_ids:
                        raise ContractGraphError(
                            "BusinessQualityReview mechanism Claim is not declared by review"
                        )
                if item["status"] == "reviewed" and not item["hypothesis_ids"]:
                    raise ContractGraphError(
                        "reviewed BusinessQualityReview mechanism requires a hypothesis"
                    )
                if item["status"] == "reviewed" and (
                    expected_hypothesis is None or expected_hypothesis.status == "blocked"
                ):
                    raise ContractGraphError(
                        "reviewed BusinessQualityReview mechanism uses a blocked hypothesis"
                    )
                if item["status"] == "not_applicable" and not item["claim_ids"]:
                    raise ContractGraphError(
                        "not-applicable BusinessQualityReview mechanism requires a Claim"
                    )
                if item["status"] == "not_applicable":
                    if item["hypothesis_ids"]:
                        raise ContractGraphError(
                            "not-applicable BusinessQualityReview mechanism has a hypothesis"
                        )
                    for reference in item["claim_ids"]:
                        decision = analytical_decision_by_claim[reference]
                        candidate = analytical_candidates[decision.candidate_id]
                        if (
                            candidate.claim_role != "not_applicable"
                            or canonical_sha256(candidate.scope)
                            != canonical_sha256(selected_context.scope)
                        ):
                            raise ContractGraphError(
                                "not-applicable mechanism Claim role or scope mismatch"
                            )
                if item["status"] == "blocked" and not item["missing_evidence"]:
                    raise ContractGraphError(
                        "blocked BusinessQualityReview mechanism requires missing evidence"
                    )
                expected_item_status = (
                    "blocked"
                    if expected_hypothesis is None or expected_hypothesis.status == "blocked"
                    else "reviewed"
                )
                if item["status"] != "not_applicable" and (
                    item["status"] != expected_item_status
                ):
                    raise ContractGraphError(
                        "BusinessQualityReview mechanism status was not recomputed"
                    )
            for reference in review.claim_ids:
                require_analytical_claim(
                    reference,
                    "BusinessQualityReview claim_ids",
                    cutoff=date.fromisoformat(review.as_of_date),
                )
            for reference in review.analytical_claim_review_decision_ids:
                self._require(
                    reference,
                    set(analytical_decisions),
                    "BusinessQualityReview analytical_claim_review_decision_ids",
                )
            reviewed_claim_ids = {
                analytical_decisions[reference].output_claim_id
                for reference in review.analytical_claim_review_decision_ids
                if analytical_decisions[reference].decision == "confirmed"
            }
            if set(review.claim_ids) != reviewed_claim_ids:
                raise ContractGraphError("BusinessQualityReview Claim review coverage mismatch")
            for reference in review.context_observation_ids:
                self._require(
                    reference,
                    set(observations),
                    "BusinessQualityReview context_observation_ids",
                )
                if observations[reference].target_issuer_id != review.issuer_id:
                    raise ContractGraphError("BusinessQualityReview observation target mismatch")
            if not set(selected_context.observation_ids).issubset(
                set(review.context_observation_ids)
            ):
                raise ContractGraphError(
                    "BusinessQualityReview omits competitive-context observations"
                )
            for reference in review.calculation_result_ids:
                require_phase4_calculation(
                    reference,
                    "BusinessQualityReview calculation_result_ids",
                    official=review.status == "complete",
                    cutoff=date.fromisoformat(review.as_of_date),
                )
            if review.status != "blocked" and not review.claim_ids:
                raise ContractGraphError("non-blocked BusinessQualityReview requires a Claim")
            scope_component_coverage = [
                item
                for item in business_model.component_coverage
                if item["scope_id"] == scope_id
            ]
            expected_coverage = {
                "reviewed_component_count": sum(
                    item["status"] == "reviewed" for item in scope_component_coverage
                ),
                "not_applicable_component_count": sum(
                    item["status"] == "not_applicable" for item in scope_component_coverage
                ),
                "blocked_component_count": sum(
                    item["status"] == "blocked" for item in scope_component_coverage
                ),
                "proposed_hypothesis_count": sum(
                    item.status == "proposed" for item in selected_hypotheses
                ),
                "supported_hypothesis_count": sum(
                    item.status == "supported" for item in selected_hypotheses
                ),
                "contested_hypothesis_count": sum(
                    item.status == "contested" for item in selected_hypotheses
                ),
                "falsified_hypothesis_count": sum(
                    item.status == "falsified" for item in selected_hypotheses
                ),
                "blocked_hypothesis_count": sum(
                    item.status == "blocked" for item in selected_hypotheses
                ),
                "strengthening_count": sum(
                    item.trend == "strengthening" for item in selected_hypotheses
                ),
                "stable_count": sum(item.trend == "stable" for item in selected_hypotheses),
                "eroding_count": sum(item.trend == "eroding" for item in selected_hypotheses),
                "unknown_trend_count": sum(item.trend == "unknown" for item in selected_hypotheses),
                "confirmed_claim_count": len(review.claim_ids),
                "unresolved_counterevidence_count": sum(
                    item["status"] in {"unresolved", "blocked"}
                    for hypothesis in selected_hypotheses
                    for item in hypothesis.counterevidence_resolutions
                ),
            }
            if dict(review.coverage) != expected_coverage:
                raise ContractGraphError("BusinessQualityReview coverage counts mismatch")
            critical_review_gap = (
                business_model.status == "blocked"
                or selected_context.status == "blocked"
                or not review.claim_ids
            )
            partial_review_gap = (
                business_model.status != "complete"
                or selected_context.status != "complete"
                or any(item["status"] == "blocked" for item in scope_component_coverage)
                or any(item["status"] == "blocked" for item in selected_context.coverage)
                or any(item["status"] == "blocked" for item in review.mechanism_coverage)
                or bool(review.missing_evidence)
            )
            expected_review_status = (
                "blocked"
                if critical_review_gap
                else ("partial" if partial_review_gap else "complete")
            )
            if review.status != expected_review_status:
                raise ContractGraphError(
                    "BusinessQualityReview status was not deterministically recomputed"
                )
            if review.status == "blocked" and not review.missing_evidence:
                raise ContractGraphError("blocked BusinessQualityReview requires missing evidence")

        candidate_locations: set[tuple[str, str]] = set()
        for candidate in self.management_statement_candidates:
            self._require(
                candidate.source_document_id,
                set(documents),
                "ManagementStatementCandidate source_document_id",
            )
            document = documents[candidate.source_document_id]
            if candidate.issuer_id != document.issuer_id:
                raise ContractGraphError("ManagementStatementCandidate issuer mismatch")
            if document.authority_level not in OFFICIAL_AUTHORITY_LEVELS:
                raise ContractGraphError("ManagementStatementCandidate requires an official source")
            location_key = (candidate.source_document_id, candidate.source_locator)
            if location_key in candidate_locations:
                raise ContractGraphError("duplicate ManagementStatementCandidate source locator")
            candidate_locations.add(location_key)
            expected_text_hash = hashlib.sha256(candidate.statement_text.encode()).hexdigest()
            if candidate.statement_sha256 != expected_text_hash or (
                candidate.excerpt_sha256 != expected_text_hash
            ):
                raise ContractGraphError("ManagementStatementCandidate text hash mismatch")
            if date.fromisoformat(candidate.statement_date) > date.fromisoformat(
                document.published_date
            ):
                raise ContractGraphError(
                    "ManagementStatementCandidate date follows source publication"
                )

        statement_locations: set[tuple[str, str]] = set()
        for statement in self.management_statements:
            self._require(
                statement.source_document_id,
                set(documents),
                "ManagementStatement source_document_id",
            )
            document = documents[statement.source_document_id]
            location_key = (statement.source_document_id, statement.source_locator)
            if location_key in statement_locations:
                raise ContractGraphError("duplicate ManagementStatement source locator")
            statement_locations.add(location_key)
            if (
                statement.statement_sha256
                != hashlib.sha256(statement.statement_text.encode("utf-8")).hexdigest()
            ):
                raise ContractGraphError("ManagementStatement text hash mismatch")
            if date.fromisoformat(statement.statement_date) > date.fromisoformat(
                document.published_date
            ):
                raise ContractGraphError("ManagementStatement date follows source publication")
            for reference in statement.predecessor_statement_ids:
                self._require(
                    reference, set(statements), "ManagementStatement predecessor_statement_ids"
                )
                predecessor = statements[reference]
                if date.fromisoformat(predecessor.statement_date) >= date.fromisoformat(
                    statement.statement_date
                ):
                    raise ContractGraphError("ManagementStatement predecessor is not earlier")
            for reference in statement.kpi_definition_fact_ids:
                self._require(reference, set(facts), "ManagementStatement kpi_definition_fact_ids")
            binding_keys: set[tuple[str, str, str]] = set()
            for binding in statement.metric_bindings:
                fact_id = binding["fact_id"]
                self._require(fact_id, set(facts), "ManagementStatement metric_bindings")
                metric_fact = facts[fact_id]
                if metric_fact.issuer_id != statement.issuer_id:
                    raise ContractGraphError("ManagementStatement metric Fact issuer mismatch")
                if metric_fact.source_document_id != statement.source_document_id:
                    raise ContractGraphError(
                        "ManagementStatement metric Fact is not sourced to its Statement"
                    )
                if metric_fact.concept != binding["metric_concept"]:
                    raise ContractGraphError("ManagementStatement metric binding concept mismatch")
                key = (binding["component_id"], binding["metric_concept"], binding["role"])
                if key in binding_keys:
                    raise ContractGraphError("duplicate ManagementStatement metric binding role")
                binding_keys.add(key)
            if statement.commitment_eligibility == "measurable" and not (statement.metric_bindings):
                raise ContractGraphError("measurable ManagementStatement requires metric bindings")
            if statement.commitment_eligibility == "narrative_only" and (statement.metric_bindings):
                raise ContractGraphError("narrative-only Statement cannot bind target metrics")
            if statement.statement_type == "kpi_definition":
                if statement.kpi_concept is None or not statement.kpi_definition_fact_ids:
                    raise ContractGraphError("KPI ManagementStatement lacks definition evidence")
            elif statement.definition_change != "not_applicable":
                raise ContractGraphError("non-KPI ManagementStatement has KPI definition change")
            if statement.definition_change in {"renamed", "redefined", "discontinued"} and not (
                statement.predecessor_statement_ids
            ):
                raise ContractGraphError("KPI definition change lacks predecessor Statement")
            if statement.verification_status == "human_confirmed":
                if document.authority_level not in OFFICIAL_AUTHORITY_LEVELS:
                    raise ContractGraphError(
                        "confirmed ManagementStatement requires official source evidence"
                    )
                if statement.reviewer_id is None or statement.reviewed_at is None:
                    raise ContractGraphError(
                        "confirmed ManagementStatement lacks reviewer provenance"
                    )
                if self._parse_datetime(statement.reviewed_at).date() < date.fromisoformat(
                    document.published_date
                ):
                    raise ContractGraphError(
                        "ManagementStatement review predates source publication"
                    )
            elif statement.verification_status in {"pending", "blocked"} and (
                statement.reviewer_id is not None or statement.reviewed_at is not None
            ):
                raise ContractGraphError(
                    "unconfirmed ManagementStatement cannot claim human review"
                )
            if statement.verification_status == "blocked" and not statement.missing_evidence:
                raise ContractGraphError("blocked ManagementStatement requires missing evidence")

        confirmed_outputs: set[str] = set()
        for decision in self.management_statement_review_decisions:
            self._require(
                decision.candidate_id,
                set(statement_candidates),
                "ManagementStatementReviewDecision candidate_id",
            )
            candidate = statement_candidates[decision.candidate_id]
            if decision.issuer_id != candidate.issuer_id:
                raise ContractGraphError("ManagementStatementReviewDecision issuer mismatch")
            if decision.candidate_fingerprint != candidate.fingerprint:
                raise ContractGraphError(
                    "ManagementStatementReviewDecision candidate fingerprint mismatch"
                )
            document = documents[candidate.source_document_id]
            if self._parse_datetime(decision.reviewed_at).date() < date.fromisoformat(
                document.published_date
            ):
                raise ContractGraphError(
                    "ManagementStatementReviewDecision predates source publication"
                )
            if decision.decision == "confirmed":
                if candidate.validation_status in {"blocked", "rejected"}:
                    raise ContractGraphError("blocked Statement candidate cannot be confirmed")
                self._require(
                    decision.output_statement_id,
                    set(statements),
                    "ManagementStatementReviewDecision output_statement_id",
                )
                statement = statements[decision.output_statement_id]
                if statement.verification_status != "human_confirmed":
                    raise ContractGraphError(
                        "ManagementStatementReviewDecision requires a human-confirmed Statement"
                    )
                if statement.statement_id in confirmed_outputs:
                    raise ContractGraphError("Statement has duplicate confirmation decisions")
                confirmed_outputs.add(statement.statement_id)
                if (
                    statement.statement_text != candidate.statement_text
                    or statement.source_document_id != candidate.source_document_id
                    or statement.source_locator != candidate.source_locator
                    or statement.speaker_name != candidate.speaker_name
                    or statement.speaker_role != candidate.speaker_role
                    or statement.statement_date != candidate.statement_date
                    or statement.statement_type != candidate.statement_type
                    or statement.kpi_concept != candidate.kpi_concept
                    or statement.reviewer_id != decision.reviewer_id
                    or statement.reviewed_at != decision.reviewed_at
                ):
                    raise ContractGraphError(
                        "confirmed Statement differs from its reviewed candidate"
                    )
                bound_fact_ids = {item["fact_id"] for item in statement.metric_bindings}
                if bound_fact_ids != set(decision.output_fact_ids):
                    raise ContractGraphError(
                        "Statement decision output Facts differ from metric bindings"
                    )
                if len(candidate.metric_mentions) != len(statement.metric_bindings):
                    raise ContractGraphError("confirmed Statement omits candidate metric mentions")
                mentions = {
                    (item["component_id"], item["metric_concept"], item["role"]): item
                    for item in candidate.metric_mentions
                }
                for binding in statement.metric_bindings:
                    key = (
                        binding["component_id"],
                        binding["metric_concept"],
                        binding["role"],
                    )
                    mention = mentions.get(key)
                    metric_fact = facts[binding["fact_id"]]
                    if mention is None or any(
                        (
                            metric_fact.value_type != mention["value_type"],
                            metric_fact.value != mention["value"],
                            metric_fact.unit != mention["unit"],
                            metric_fact.currency != mention["currency"],
                            dict(metric_fact.period) != dict(mention["period"]),
                        )
                    ):
                        raise ContractGraphError(
                            "confirmed management Fact differs from candidate metric mention"
                        )
                for fact_id in decision.output_fact_ids:
                    self._require(
                        fact_id,
                        set(facts),
                        "ManagementStatementReviewDecision output_fact_ids",
                    )
                    if facts[fact_id].source_locator != candidate.source_locator:
                        raise ContractGraphError(
                            "confirmed management Fact locator differs from candidate"
                        )
            elif decision.output_statement_id is not None or decision.output_fact_ids:
                raise ContractGraphError("non-confirmed Statement decision emits output")
        missing_decisions = {
            item.statement_id
            for item in self.management_statements
            if item.verification_status == "human_confirmed"
        }.difference(confirmed_outputs)
        if missing_decisions:
            raise ContractGraphError("human-confirmed Statement lacks a review decision")

        for commitment in self.management_commitments:
            self._require(
                commitment.statement_id, set(statements), "ManagementCommitment statement_id"
            )
            statement = statements[commitment.statement_id]
            if statement.verification_status != "human_confirmed":
                raise ContractGraphError(
                    "ManagementCommitment requires a human-confirmed Statement"
                )
            if statement.commitment_eligibility != "measurable":
                raise ContractGraphError("ManagementCommitment requires a measurable Statement")
            if (
                statement.statement_type == "kpi_definition"
                and statement.definition_change in {"renamed", "redefined"}
                and not commitment.definition_reconciliation_calculation_ids
            ):
                raise ContractGraphError("KPI definition change lacks deterministic bridge")
            if commitment.issuer_id != statement.issuer_id:
                raise ContractGraphError("ManagementCommitment issuer mismatch")
            if date.fromisoformat(commitment.start_date) > date.fromisoformat(commitment.due_date):
                raise ContractGraphError("ManagementCommitment starts after due date")
            baseline_fact_ids = tuple(item["fact_id"] for item in commitment.baseline_bindings)
            target_fact_ids = tuple(item["fact_id"] for item in commitment.target_bindings)
            if set(baseline_fact_ids).intersection(target_fact_ids):
                raise ContractGraphError("ManagementCommitment reuses baseline Fact as target")
            if len({item["component_id"] for item in commitment.baseline_bindings}) != len(
                commitment.baseline_bindings
            ):
                raise ContractGraphError("duplicate ManagementCommitment baseline component")
            target_keys = {
                (item["component_id"], item["role"]) for item in commitment.target_bindings
            }
            if len(target_keys) != len(commitment.target_bindings):
                raise ContractGraphError("duplicate ManagementCommitment target component role")
            registered = management_policy(
                commitment.evaluation_policy_id, commitment.evaluation_policy_version
            )
            actual_roles = {item["role"] for item in commitment.target_bindings}
            if actual_roles != set(registered.target_roles):
                raise ContractGraphError("ManagementCommitment target roles violate policy")
            if registered.requires_baseline and not commitment.baseline_bindings:
                raise ContractGraphError("ManagementCommitment policy requires a baseline")
            if commitment.comparison_direction not in registered.allowed_directions:
                raise ContractGraphError(
                    "ManagementCommitment comparison direction violates policy"
                )
            if commitment.scope["scope_type"] == "issuer" and (
                commitment.scope["scope_id"] != commitment.issuer_id
            ):
                raise ContractGraphError("issuer-scoped ManagementCommitment scope_id mismatch")
            if commitment.scope["scope_type"] == "segment":
                self._require(
                    commitment.scope["scope_id"], set(segments), "ManagementCommitment scope"
                )
                if segments[commitment.scope["scope_id"]].issuer_id != commitment.issuer_id:
                    raise ContractGraphError("ManagementCommitment Segment issuer mismatch")
            for reference in (*baseline_fact_ids, *target_fact_ids):
                self._require(reference, set(facts), "ManagementCommitment Fact reference")
                if facts[reference].issuer_id != commitment.issuer_id:
                    raise ContractGraphError("ManagementCommitment Fact issuer mismatch")
                if (
                    documents[facts[reference].source_document_id].authority_level
                    not in OFFICIAL_AUTHORITY_LEVELS
                ):
                    raise ContractGraphError("ManagementCommitment requires official Fact evidence")
                if date.fromisoformat(
                    documents[facts[reference].source_document_id].published_date
                ) > date.fromisoformat(documents[statement.source_document_id].published_date):
                    raise ContractGraphError(
                        "ManagementCommitment uses Fact evidence disclosed after its Statement"
                    )
            for reference in baseline_fact_ids:
                period_end = facts[reference].period["end"]
                if period_end is not None and date.fromisoformat(period_end) > date.fromisoformat(
                    statement.statement_date
                ):
                    raise ContractGraphError(
                        "ManagementCommitment baseline Fact follows its Statement"
                    )
            statement_target_bindings = {
                (item["component_id"], item["role"], item["fact_id"])
                for item in statement.metric_bindings
                if item["metric_concept"] == commitment.metric_concept
            }
            for binding in commitment.target_bindings:
                reference = binding["fact_id"]
                if facts[reference].source_document_id != statement.source_document_id:
                    raise ContractGraphError(
                        "ManagementCommitment target Fact is not sourced to its Statement"
                    )
                if facts[reference].concept != commitment.metric_concept:
                    raise ContractGraphError("ManagementCommitment target metric concept mismatch")
                if (binding["component_id"], binding["role"], reference) not in (
                    statement_target_bindings
                ):
                    raise ContractGraphError(
                        "ManagementCommitment target is not confirmed by its Statement"
                    )
            for reference in commitment.condition_claim_ids:
                require_claim(
                    reference,
                    "ManagementCommitment condition_claim_ids",
                    official=True,
                    cutoff=date.fromisoformat(statement.statement_date),
                )
            if commitment.commitment_strength == "conditional" and not (
                commitment.condition_claim_ids
            ):
                raise ContractGraphError("conditional ManagementCommitment lacks conditions")
            for reference in commitment.definition_reconciliation_calculation_ids:
                bridge = require_phase4_calculation(
                    reference,
                    "ManagementCommitment definition_reconciliation_calculation_ids",
                )
                required_definition_facts = set(statement.kpi_definition_fact_ids)
                for predecessor_id in statement.predecessor_statement_ids:
                    required_definition_facts.update(
                        statements[predecessor_id].kpi_definition_fact_ids
                    )
                if not required_definition_facts.issubset(set(bridge.input_fact_ids)):
                    raise ContractGraphError(
                        "ManagementCommitment KPI bridge omits definition Facts"
                    )
            if (
                statement.statement_type == "kpi_definition"
                and statement.definition_change
                in {
                    "renamed",
                    "redefined",
                }
                and not commitment.definition_reconciliation_calculation_ids
            ):
                raise ContractGraphError("KPI definition change lacks deterministic bridge")
            if commitment.status == "withdrawn":
                if commitment.withdrawal_statement_id is None:
                    raise ContractGraphError("withdrawn commitment lacks withdrawal Statement")
                self._require(
                    commitment.withdrawal_statement_id,
                    set(statements),
                    "ManagementCommitment withdrawal_statement_id",
                )
                if statements[commitment.withdrawal_statement_id].verification_status != (
                    "human_confirmed"
                ):
                    raise ContractGraphError(
                        "withdrawn commitment requires confirmed withdrawal Statement"
                    )
            if commitment.status == "superseded":
                if commitment.superseded_by_commitment_id is None:
                    raise ContractGraphError("superseded commitment lacks successor")
                self._require(
                    commitment.superseded_by_commitment_id,
                    set(commitments),
                    "ManagementCommitment superseded_by_commitment_id",
                )
                successor = commitments[commitment.superseded_by_commitment_id]
                if successor.metric_concept != commitment.metric_concept:
                    raise ContractGraphError(
                        "superseded ManagementCommitment successor changes metric concept"
                    )
                if date.fromisoformat(successor.start_date) <= date.fromisoformat(
                    commitment.start_date
                ):
                    raise ContractGraphError(
                        "superseded ManagementCommitment successor is not later"
                    )
            if commitment.status == "blocked" and not commitment.missing_evidence:
                raise ContractGraphError("blocked ManagementCommitment requires missing evidence")

        management_windows: set[tuple[str, str, str]] = set()
        for outcome in self.management_outcomes:
            self._require(
                outcome.commitment_id,
                set(commitments),
                "ManagementOutcome commitment_id",
            )
            commitment = commitments[outcome.commitment_id]
            if outcome.predecessor_outcome_id is not None:
                self._require(
                    outcome.predecessor_outcome_id,
                    set(management_outcomes),
                    "ManagementOutcome predecessor_outcome_id",
                )
                predecessor = management_outcomes[outcome.predecessor_outcome_id]
                if predecessor.commitment_id != outcome.commitment_id:
                    raise ContractGraphError(
                        "ManagementOutcome predecessor belongs to another Commitment"
                    )
                if date.fromisoformat(predecessor.assessed_at) >= date.fromisoformat(
                    outcome.assessed_at
                ):
                    raise ContractGraphError("ManagementOutcome predecessor is not earlier")
            start, end = validate_period(
                outcome.evaluation_period, outcome.assessed_at, "ManagementOutcome"
            )
            window = (outcome.commitment_id, start.isoformat(), end.isoformat())
            if window in management_windows:
                raise ContractGraphError("duplicate ManagementOutcome evaluation window")
            management_windows.add(window)
            due_date = date.fromisoformat(commitment.due_date)
            assessed_at = date.fromisoformat(outcome.assessed_at)
            if start < date.fromisoformat(commitment.start_date):
                raise ContractGraphError(
                    "ManagementOutcome evaluation starts before its Commitment"
                )
            if assessed_at < due_date and outcome.status not in {
                "pending",
                "blocked",
                "withdrawn",
                "superseded",
            }:
                raise ContractGraphError("unexpired ManagementCommitment cannot be evaluated")
            if assessed_at >= due_date and outcome.status == "pending":
                raise ContractGraphError("expired ManagementCommitment cannot remain pending")
            if outcome.status == "withdrawn" and commitment.status != "withdrawn":
                raise ContractGraphError("withdrawn Outcome requires withdrawn Commitment")
            if outcome.status == "superseded" and commitment.status != "superseded":
                raise ContractGraphError("superseded Outcome requires superseded Commitment")
            if commitment.status in {"withdrawn", "superseded"} and outcome.status not in {
                commitment.status,
                "blocked",
            }:
                raise ContractGraphError("lifecycle Commitment cannot receive an operating Outcome")
            if outcome.status in {"withdrawn", "superseded"} and outcome.result_bindings:
                raise ContractGraphError(
                    "lifecycle ManagementOutcome cannot contain result evidence"
                )
            if outcome.status in {"met", "partially_met", "missed"} and end < due_date:
                raise ContractGraphError(
                    "evaluated ManagementOutcome window does not reach the due date"
                )
            if outcome.status in {"met", "partially_met", "missed"}:
                commitment_statement = statements[commitment.statement_id]
                definition_changes = [
                    item
                    for item in self.management_statements
                    if item.verification_status == "human_confirmed"
                    and item.statement_type == "kpi_definition"
                    and item.kpi_concept == commitment.metric_concept
                    and date.fromisoformat(item.statement_date)
                    > date.fromisoformat(commitment_statement.statement_date)
                    and date.fromisoformat(item.statement_date) <= assessed_at
                    and item.definition_change in {"renamed", "redefined"}
                ]
                if definition_changes:
                    if not commitment.definition_reconciliation_calculation_ids:
                        raise ContractGraphError(
                            "evaluated ManagementOutcome crosses a KPI definition change "
                            "without a deterministic bridge"
                        )
                    required_definition_fact_ids = set(commitment_statement.kpi_definition_fact_ids)
                    for changed_statement in definition_changes:
                        required_definition_fact_ids.update(
                            changed_statement.kpi_definition_fact_ids
                        )
                        for predecessor_id in changed_statement.predecessor_statement_ids:
                            required_definition_fact_ids.update(
                                statements[predecessor_id].kpi_definition_fact_ids
                            )
                    bridge_inputs: set[str] = set()
                    bridge_bindings: set[str] = set()
                    for calculation_id in commitment.definition_reconciliation_calculation_ids:
                        bridge = require_phase4_calculation(
                            calculation_id,
                            "ManagementOutcome KPI definition bridge",
                        )
                        bridge_inputs.update(bridge.input_fact_ids)
                        bridge_bindings.update(bridge.input_bindings.values())
                    if not required_definition_fact_ids.issubset(bridge_inputs) or not (
                        required_definition_fact_ids.issubset(bridge_bindings)
                    ):
                        raise ContractGraphError(
                            "ManagementOutcome KPI bridge lacks definition Fact role bindings"
                        )
            if dict(outcome.result_scope) != dict(commitment.scope):
                raise ContractGraphError("ManagementOutcome result scope differs from Commitment")
            if dict(outcome.result_measurement_basis) != dict(commitment.measurement_basis):
                raise ContractGraphError(
                    "ManagementOutcome measurement basis differs from Commitment"
                )
            target_components = {item["component_id"] for item in commitment.target_bindings}
            if commitment.evaluation_policy_id == "maintain_or_improve":
                target_components.update(
                    item["component_id"] for item in commitment.baseline_bindings
                )
            if outcome.status == "partially_met" and len(target_components) < 2:
                raise ContractGraphError(
                    "partially met requires a multi-component ManagementCommitment"
                )
            result_keys = {(item["component_id"], item["role"]) for item in outcome.result_bindings}
            if len(result_keys) != len(outcome.result_bindings):
                raise ContractGraphError("duplicate ManagementOutcome result component role")
            if not {item["component_id"] for item in outcome.result_bindings}.issubset(
                target_components
            ):
                raise ContractGraphError("ManagementOutcome result component lacks a target")
            outcome_result_fact_ids: set[str] = set()
            outcome_calculation_fact_ids: set[str] = set()
            for binding in outcome.result_bindings:
                fact_id = binding["fact_id"]
                calculation_id = binding["calculation_result_id"]
                result_value: Fact | CalculationResult
                if fact_id is not None:
                    self._require(fact_id, set(facts), "ManagementOutcome result_bindings")
                    result_value = facts[fact_id]
                    outcome_result_fact_ids.add(fact_id)
                    if (
                        date.fromisoformat(
                            documents[result_value.source_document_id].published_date
                        )
                        > assessed_at
                    ):
                        raise ContractGraphError(
                            "ManagementOutcome uses result evidence published after assessment"
                        )
                    if outcome.status in {"met", "partially_met", "missed"} and (
                        documents[result_value.source_document_id].authority_level
                        not in OFFICIAL_AUTHORITY_LEVELS
                    ):
                        raise ContractGraphError(
                            "evaluated ManagementOutcome requires official result Facts"
                        )
                else:
                    result_value = require_phase4_calculation(
                        calculation_id,
                        "ManagementOutcome result_bindings",
                        official=outcome.status in {"met", "partially_met", "missed"},
                        cutoff=assessed_at,
                    )
                    outcome_calculation_fact_ids.update(calculation_fact_ids(calculation_id))
                if result_value.concept != commitment.metric_concept:
                    raise ContractGraphError("ManagementOutcome result metric concept mismatch")
                matching_targets = [
                    facts[item["fact_id"]]
                    for item in commitment.target_bindings
                    if item["component_id"] == binding["component_id"]
                ]
                if commitment.evaluation_policy_id == "maintain_or_improve":
                    matching_targets = [
                        facts[item["fact_id"]]
                        for item in commitment.baseline_bindings
                        if item["component_id"] == binding["component_id"]
                    ]
                for target in matching_targets:
                    if result_value.value_type != target.value_type:
                        raise ContractGraphError("ManagementOutcome result value type mismatch")
                    if result_value.value_type == "number":
                        try:
                            if not compatible_units(result_value.unit, target.unit):
                                raise ContractGraphError(
                                    "ManagementOutcome result unit is not comparable"
                                )
                            validate_unit_currency(result_value.unit, result_value.currency)
                        except UnitError as exc:
                            raise ContractGraphError(str(exc)) from exc
                        if result_value.currency != target.currency:
                            raise ContractGraphError("ManagementOutcome result currency mismatch")
            management_evidence_fact_ids = {
                *outcome_result_fact_ids,
                *outcome_calculation_fact_ids,
                *(item["fact_id"] for item in commitment.baseline_bindings),
                *(item["fact_id"] for item in commitment.target_bindings),
            }
            claim_supporting_fact_ids: set[str] = set()
            for reference in outcome.claim_ids:
                outcome_claim = require_claim(
                    reference,
                    "ManagementOutcome claim_ids",
                    official=outcome.status not in {"blocked", "pending"},
                    cutoff=assessed_at,
                )
                claim_supporting_fact_ids.update(outcome_claim.supporting_fact_ids)
                if not set(outcome_claim.supporting_fact_ids).intersection(
                    management_evidence_fact_ids
                ):
                    raise ContractGraphError(
                        "ManagementOutcome Claim is disconnected from commitment or result Facts"
                    )
            if outcome.status != "blocked" and not outcome.claim_ids:
                raise ContractGraphError("non-blocked ManagementOutcome requires a Claim")
            if outcome.status in {"met", "partially_met", "missed"} and not (
                outcome.result_bindings
            ):
                raise ContractGraphError("evaluated ManagementOutcome lacks result evidence")
            formal_result_fact_ids = {
                *outcome_result_fact_ids,
                *outcome_calculation_fact_ids,
            }
            if outcome.status in {"met", "partially_met", "missed"} and not (
                formal_result_fact_ids.issubset(claim_supporting_fact_ids)
            ):
                raise ContractGraphError(
                    "evaluated ManagementOutcome Claim does not cover all result evidence"
                )
            if outcome.status in {"met", "partially_met", "missed"}:
                try:
                    expected_status = recompute_outcome_status(
                        commitment=commitment,
                        outcome=outcome,
                        facts=facts,
                        calculations=calculations,
                    )
                except (KeyError, OutcomeEvaluationError) as exc:
                    raise ContractGraphError(
                        "ManagementOutcome arithmetic status cannot be recomputed"
                    ) from exc
                if outcome.status != expected_status:
                    raise ContractGraphError(
                        "ManagementOutcome status differs from registered policy arithmetic"
                    )
            if outcome.status in {"unverifiable", "blocked"} and not outcome.missing_evidence:
                raise ContractGraphError(
                    f"{outcome.status} ManagementOutcome requires missing evidence"
                )

        for candidate in self.capital_allocation_event_candidates:
            self._require(
                candidate.source_document_id,
                set(documents),
                "CapitalAllocationEventCandidate source_document_id",
            )
            source = documents[candidate.source_document_id]
            if date.fromisoformat(source.published_date) > date.fromisoformat(
                candidate.as_of_date
            ):
                raise ContractGraphError(
                    "CapitalAllocationEventCandidate uses future source evidence"
                )
            candidate_as_of = date.fromisoformat(candidate.as_of_date)
            candidate_announcement = date.fromisoformat(
                candidate.proposed_announcement_date
            )
            if candidate_announcement > date.fromisoformat(source.published_date):
                raise ContractGraphError(
                    "CapitalAllocationEventCandidate announcement follows its source"
                )
            candidate_start = candidate.proposed_execution_period["start"]
            candidate_end = candidate.proposed_execution_period["end"]
            if candidate_end is not None and candidate_start is None:
                raise ContractGraphError(
                    "CapitalAllocationEventCandidate execution end lacks a start"
                )
            if candidate_start is not None:
                parsed_start = date.fromisoformat(candidate_start)
                if parsed_start < candidate_announcement or parsed_start > candidate_as_of:
                    raise ContractGraphError(
                        "CapitalAllocationEventCandidate execution start is invalid"
                    )
            if candidate_end is not None:
                parsed_end = date.fromisoformat(candidate_end)
                if parsed_end < date.fromisoformat(candidate_start) or parsed_end > candidate_as_of:
                    raise ContractGraphError(
                        "CapitalAllocationEventCandidate execution end is invalid"
                    )
            if candidate.proposed_source_role == "completion" and candidate_end is None:
                raise ContractGraphError(
                    "completion CapitalAllocationEventCandidate lacks an execution end"
                )
            if (
                candidate.proposed_source_role == "execution_update"
                and candidate_start is None
            ):
                raise ContractGraphError(
                    "execution-update CapitalAllocationEventCandidate lacks a start"
                )
            if (
                candidate.proposed_event_type == "acquisition"
                and candidate.proposed_growth_classification == "organic"
            ):
                raise ContractGraphError(
                    "acquisition Candidate cannot be classified as organic"
                )
            try:
                policy = policy_for(candidate.proposed_event_type)
                economic_event_key(
                    issuer_id=candidate.issuer_id,
                    event_type=candidate.proposed_event_type,
                    event_subtype=candidate.proposed_event_subtype,
                    identity_components=candidate.proposed_identity_components,
                )
            except ValueError as exc:
                raise ContractGraphError(str(exc)) from exc
            if candidate.proposed_source_role not in SOURCE_ROLES:
                raise ContractGraphError("CapitalAllocationEventCandidate uses a free source role")
            candidate_binding_ids: set[str] = set()
            candidate_fact_ids: set[str] = set()
            for binding in candidate.proposed_fact_bindings:
                if binding["binding_id"] in candidate_binding_ids:
                    raise ContractGraphError(
                        "duplicate CapitalAllocationEventCandidate fact binding ID"
                    )
                candidate_binding_ids.add(binding["binding_id"])
                if binding["role_id"] not in policy.fact_roles:
                    raise ContractGraphError(
                        "CapitalAllocationEventCandidate uses a free fact role"
                    )
                self._require(
                    binding["fact_id"],
                    set(facts),
                    "CapitalAllocationEventCandidate fact binding",
                )
                candidate_fact = facts[binding["fact_id"]]
                if candidate_fact.source_document_id != candidate.source_document_id:
                    raise ContractGraphError(
                        "CapitalAllocationEventCandidate Fact belongs to another source"
                    )
                if candidate_fact.value_type != "number" or not role_accepts_unit(
                    binding["role_id"], unit_spec(candidate_fact.unit).family
                ):
                    raise ContractGraphError(
                        "CapitalAllocationEventCandidate fact role unit mismatch"
                    )
                if binding["fact_id"] in candidate_fact_ids:
                    raise ContractGraphError(
                        "CapitalAllocationEventCandidate reuses a Fact across roles"
                    )
                candidate_fact_ids.add(binding["fact_id"])
            for reference in candidate.proposed_rationale_statement_ids:
                self._require(
                    reference,
                    set(statements),
                    "CapitalAllocationEventCandidate rationale Statement",
                )
            for reference in candidate.proposed_related_commitment_ids:
                self._require(
                    reference,
                    set(commitments),
                    "CapitalAllocationEventCandidate related Commitment",
                )
            for reference in candidate.potential_duplicate_candidate_ids:
                self._require(
                    reference,
                    set(capital_candidates),
                    "CapitalAllocationEventCandidate potential duplicate",
                )
                if reference == candidate.candidate_id:
                    raise ContractGraphError(
                        "CapitalAllocationEventCandidate cannot duplicate itself"
                    )
                if capital_candidates[reference].issuer_id != candidate.issuer_id:
                    raise ContractGraphError(
                        "CapitalAllocationEventCandidate duplicate issuer mismatch"
                    )
            for reference in candidate.supersedes_candidate_ids:
                self._require(
                    reference,
                    set(capital_candidates),
                    "CapitalAllocationEventCandidate supersedes",
                )
                if reference == candidate.candidate_id:
                    raise ContractGraphError(
                        "CapitalAllocationEventCandidate cannot supersede itself"
                    )
                if capital_candidates[reference].issuer_id != candidate.issuer_id:
                    raise ContractGraphError(
                        "CapitalAllocationEventCandidate supersession issuer mismatch"
                    )

        superseded_capital_decisions = {
            reference
            for decision in self.capital_allocation_event_review_decisions
            for reference in decision.supersedes_decision_ids
        }
        for decision in self.capital_allocation_event_review_decisions:
            self._require(
                decision.candidate_id,
                set(capital_candidates),
                "CapitalAllocationEventReviewDecision candidate_id",
            )
            candidate = capital_candidates[decision.candidate_id]
            if decision.issuer_id != candidate.issuer_id:
                raise ContractGraphError("CapitalAllocationEventReviewDecision issuer mismatch")
            if decision.candidate_fingerprint != candidate.fingerprint:
                raise ContractGraphError(
                    "CapitalAllocationEventReviewDecision fingerprint mismatch"
                )
            for reference in decision.supersedes_decision_ids:
                self._require(
                    reference,
                    set(capital_decisions),
                    "CapitalAllocationEventReviewDecision supersedes_decision_ids",
                )
                prior_decision = capital_decisions[reference]
                if prior_decision.issuer_id != decision.issuer_id:
                    raise ContractGraphError(
                        "CapitalAllocationEventReviewDecision supersession issuer mismatch"
                    )
                if self._parse_datetime(prior_decision.reviewed_at) >= self._parse_datetime(
                    decision.reviewed_at
                ):
                    raise ContractGraphError(
                        "CapitalAllocationEventReviewDecision supersession is not later"
                    )
            if decision.decision == "confirmed":
                source = documents[candidate.source_document_id]
                if source.authority_level not in OFFICIAL_AUTHORITY_LEVELS:
                    raise ContractGraphError(
                        "confirmed Event Decision requires an official source"
                    )
                if candidate.validation_status != "ready":
                    raise ContractGraphError("confirmed Event Decision uses a blocked Candidate")
                try:
                    expected_key = economic_event_key(
                        issuer_id=candidate.issuer_id,
                        event_type=candidate.proposed_event_type,
                        event_subtype=candidate.proposed_event_subtype,
                        identity_components=candidate.proposed_identity_components,
                    )
                except ValueError as exc:
                    raise ContractGraphError(str(exc)) from exc
                if decision.output_economic_event_key != expected_key:
                    raise ContractGraphError(
                        "CapitalAllocationEventReviewDecision economic key mismatch"
                    )
        active_capital_decisions = {
            item.decision_id: item
            for item in self.capital_allocation_event_review_decisions
            if item.decision == "confirmed"
            and item.decision_id not in superseded_capital_decisions
        }
        active_confirmed_candidates = [
            item.candidate_id for item in active_capital_decisions.values()
        ]
        if len(active_confirmed_candidates) != len(set(active_confirmed_candidates)):
            raise ContractGraphError("Candidate has multiple active confirmed Decisions")
        for decision in active_capital_decisions.values():
            self._require(
                decision.output_event_id,
                set(capital_events),
                "CapitalAllocationEventReviewDecision output Event",
            )

        event_versions: set[tuple[str, str, int]] = set()
        for event in self.capital_allocation_events:
            policy = policy_for(event.event_type)
            if (
                event.event_policy_id != policy.event_policy_id
                or event.event_policy_version != EVENT_POLICY_VERSION
            ):
                raise ContractGraphError("CapitalAllocationEvent event policy mismatch")
            try:
                expected_key = economic_event_key(
                    issuer_id=event.issuer_id,
                    event_type=event.event_type,
                    event_subtype=event.event_subtype,
                    identity_components=event.identity_components,
                )
            except ValueError as exc:
                raise ContractGraphError(str(exc)) from exc
            if event.economic_event_key != expected_key:
                raise ContractGraphError("CapitalAllocationEvent economic key mismatch")
            version_key = (event.issuer_id, event.economic_event_key, event.event_version)
            if version_key in event_versions:
                raise ContractGraphError("duplicate CapitalAllocationEvent version chain entry")
            event_versions.add(version_key)
            if event.event_version == 1 and event.predecessor_event_id is not None:
                raise ContractGraphError("CapitalAllocationEvent version chain starts with v1")
            if event.event_version > 1:
                if event.predecessor_event_id is None:
                    raise ContractGraphError(
                        "CapitalAllocationEvent version chain lacks predecessor"
                    )
                self._require(
                    event.predecessor_event_id,
                    set(capital_events),
                    "CapitalAllocationEvent predecessor_event_id",
                )
                predecessor = capital_events[event.predecessor_event_id]
                if (
                    predecessor.economic_event_key != event.economic_event_key
                    or predecessor.event_version + 1 != event.event_version
                ):
                    raise ContractGraphError(
                        "CapitalAllocationEvent version chain is not contiguous"
                    )
                predecessor_decisions = {
                    item["decision_id"] for item in predecessor.source_bindings
                }.union(item["decision_id"] for item in predecessor.fact_bindings)
                current_decisions = {
                    item["decision_id"] for item in event.source_bindings
                }.union(item["decision_id"] for item in event.fact_bindings)
                removed = predecessor_decisions - current_decisions
                if removed and not removed.issubset(superseded_capital_decisions):
                    raise ContractGraphError(
                        "CapitalAllocationEvent silently deletes predecessor evidence"
                    )
            for reference in event.supersedes_event_ids:
                self._require(reference, set(capital_events), "CapitalAllocationEvent supersedes")
                if capital_events[reference].issuer_id != event.issuer_id:
                    raise ContractGraphError("CapitalAllocationEvent supersession issuer mismatch")
                if capital_events[reference].economic_event_key == event.economic_event_key:
                    raise ContractGraphError(
                        "same-key CapitalAllocationEvent versions must use predecessor_event_id"
                    )
            start_value = event.execution_period["start"]
            end_value = event.execution_period["end"]
            if start_value is None:
                if end_value is not None:
                    raise ContractGraphError(
                        "CapitalAllocationEvent execution end requires a start"
                    )
                if event.lifecycle_status in {"in_progress", "completed"}:
                    raise ContractGraphError(
                        f"{event.lifecycle_status} CapitalAllocationEvent requires "
                        "an execution start"
                    )
            else:
                start = date.fromisoformat(start_value)
                if end_value is not None and start > date.fromisoformat(end_value):
                    raise ContractGraphError("CapitalAllocationEvent execution period is invalid")
                if start < date.fromisoformat(event.announcement_date):
                    raise ContractGraphError(
                        "CapitalAllocationEvent execution predates announcement"
                    )
            if event.lifecycle_status == "completed" and end_value is None:
                raise ContractGraphError(
                    "completed CapitalAllocationEvent requires an execution end"
                )
            decision_ids: set[str] = set()
            source_document_ids: set[str] = set()
            binding_ids: set[str] = set()
            bound_event_candidates: dict[str, CapitalAllocationEventCandidate] = {}
            allowable_decision_event_ids = {event.event_id}
            ancestor_id = event.predecessor_event_id
            while ancestor_id is not None:
                allowable_decision_event_ids.add(ancestor_id)
                ancestor_id = capital_events[ancestor_id].predecessor_event_id
            for binding in event.source_bindings:
                if binding["binding_id"] in binding_ids:
                    raise ContractGraphError("duplicate CapitalAllocationEvent binding ID")
                binding_ids.add(binding["binding_id"])
                if binding["role_id"] not in SOURCE_ROLES:
                    raise ContractGraphError("CapitalAllocationEvent uses a free source role")
                self._require(
                    binding["decision_id"],
                    set(active_capital_decisions),
                    "CapitalAllocationEvent confirmed Event Decision",
                )
                decision = active_capital_decisions[binding["decision_id"]]
                self._require(
                    binding["candidate_id"],
                    set(capital_candidates),
                    "CapitalAllocationEvent source Candidate",
                )
                candidate = capital_candidates[binding["candidate_id"]]
                bound_event_candidates[candidate.candidate_id] = candidate
                if (
                    decision.candidate_id != candidate.candidate_id
                    or decision.output_event_id not in allowable_decision_event_ids
                    or decision.output_economic_event_key != event.economic_event_key
                    or candidate.source_document_id != binding["source_document_id"]
                    or candidate.proposed_source_role != binding["role_id"]
                    or candidate.proposed_event_type != event.event_type
                    or candidate.proposed_event_subtype != event.event_subtype
                    or dict(candidate.proposed_scope) != dict(event.scope)
                    or tuple(candidate.proposed_identity_components)
                    != tuple(event.identity_components)
                    or candidate.proposed_announcement_date != event.announcement_date
                ):
                    raise ContractGraphError("CapitalAllocationEvent source binding mismatch")
                source_document_ids.add(binding["source_document_id"])
                decision_ids.add(binding["decision_id"])
            seen_facts: set[str] = set()
            monetary_currencies: set[str] = set()
            declared_fact_ids = [item["fact_id"] for item in event.fact_bindings]
            if len(declared_fact_ids) != len(set(declared_fact_ids)):
                raise ContractGraphError("CapitalAllocationEvent reuses a Fact across roles")
            for binding in event.fact_bindings:
                if binding["binding_id"] in binding_ids:
                    raise ContractGraphError("duplicate CapitalAllocationEvent binding ID")
                binding_ids.add(binding["binding_id"])
                if binding["role_id"] not in policy.fact_roles:
                    raise ContractGraphError("CapitalAllocationEvent uses a free fact role")
                seen_facts.add(binding["fact_id"])
                self._require(binding["fact_id"], set(facts), "CapitalAllocationEvent fact binding")
                self._require(
                    binding["decision_id"],
                    set(active_capital_decisions),
                    "CapitalAllocationEvent confirmed Event Decision",
                )
                self._require(
                    binding["candidate_id"],
                    set(capital_candidates),
                    "CapitalAllocationEvent fact Candidate",
                )
                candidate = capital_candidates[binding["candidate_id"]]
                bound_event_candidates[candidate.candidate_id] = candidate
                proposed = {
                    (item["binding_id"], item["role_id"], item["fact_id"])
                    for item in candidate.proposed_fact_bindings
                }
                if (
                    (binding["binding_id"], binding["role_id"], binding["fact_id"])
                    not in proposed
                    or active_capital_decisions[binding["decision_id"]].candidate_id
                    != candidate.candidate_id
                ):
                    raise ContractGraphError("CapitalAllocationEvent fact binding was not reviewed")
                fact = facts[binding["fact_id"]]
                if fact.source_document_id != candidate.source_document_id:
                    raise ContractGraphError(
                        "CapitalAllocationEvent Fact belongs to another Candidate source"
                    )
                if fact.value_type != "number" or not role_accepts_unit(
                    binding["role_id"], unit_spec(fact.unit).family
                ):
                    raise ContractGraphError("CapitalAllocationEvent fact role unit mismatch")
                source_document_ids.add(fact.source_document_id)
                if fact.value_type == "number" and unit_spec(fact.unit).currency_required:
                    monetary_currencies.add(fact.currency)
            if len(monetary_currencies) > 1:
                raise ContractGraphError("CapitalAllocationEvent mixes currencies")
            reviewed_growth = {
                item.proposed_growth_classification
                for item in bound_event_candidates.values()
                if item.proposed_growth_classification != "unknown"
            }
            if len(reviewed_growth) > 1 or (
                reviewed_growth and event.growth_classification not in reviewed_growth
            ):
                raise ContractGraphError(
                    "CapitalAllocationEvent growth classification was not consistently reviewed"
                )
            reviewed_starts = sorted(
                item.proposed_execution_period["start"]
                for item in bound_event_candidates.values()
                if item.proposed_execution_period["start"] is not None
            )
            reviewed_ends = sorted(
                item.proposed_execution_period["end"]
                for item in bound_event_candidates.values()
                if item.proposed_execution_period["end"] is not None
            )
            expected_execution_period = {
                "start": reviewed_starts[0] if reviewed_starts else None,
                "end": reviewed_ends[-1] if reviewed_ends else None,
            }
            if dict(event.execution_period) != expected_execution_period:
                raise ContractGraphError(
                    "CapitalAllocationEvent execution period was not consistently reviewed"
                )
            for binding in event.claim_bindings:
                if binding["role_id"] not in CLAIM_ROLES:
                    raise ContractGraphError("CapitalAllocationEvent uses a free Claim role")
                require_analytical_claim(
                    binding["claim_id"],
                    "CapitalAllocationEvent Claim",
                    cutoff=date.fromisoformat(event.announcement_date),
                )
                self._require(
                    binding["review_decision_id"],
                    set(analytical_decisions),
                    "CapitalAllocationEvent analytical review Decision",
                )
                decision = analytical_decisions[binding["review_decision_id"]]
                if decision.output_claim_id != binding["claim_id"]:
                    raise ContractGraphError("CapitalAllocationEvent Claim review mismatch")
            for reference in event.rationale_statement_ids:
                self._require(
                    reference, set(statements), "CapitalAllocationEvent rationale_statement_ids"
                )
                if statements[reference].verification_status != "human_confirmed":
                    raise ContractGraphError(
                        "CapitalAllocationEvent rationale requires confirmed Statement"
                    )
            for reference in event.related_commitment_ids:
                self._require(
                    reference, set(commitments), "CapitalAllocationEvent related_commitment_ids"
                )
            if event.event_type == "acquisition" and event.growth_classification == "organic":
                raise ContractGraphError("acquisition revenue cannot be classified as organic")
            bound_roles = {item["role_id"] for item in event.fact_bindings}
            source_roles = {item["role_id"] for item in event.source_bindings}
            if event.lifecycle_status == "announced" and not source_roles.intersection(
                {"authorization", "announcement", "terms"}
            ):
                raise ContractGraphError(
                    "announced CapitalAllocationEvent lacks announcement evidence"
                )
            if event.lifecycle_status in {"in_progress", "completed"} and not (
                bound_roles.intersection(policy.execution_roles)
            ):
                raise ContractGraphError(
                    f"{event.lifecycle_status} CapitalAllocationEvent lacks execution evidence"
                )
            if event.lifecycle_status == "in_progress" and not source_roles.intersection(
                {"execution_update", "completion"}
            ):
                raise ContractGraphError(
                    "in-progress CapitalAllocationEvent lacks an execution source"
                )
            if event.lifecycle_status == "completed" and not (
                bound_roles.intersection(policy.completion_roles)
            ):
                raise ContractGraphError(
                    "completed CapitalAllocationEvent lacks completion evidence"
                )
            if event.lifecycle_status == "completed" and "completion" not in source_roles:
                raise ContractGraphError(
                    "completed CapitalAllocationEvent lacks a completion source"
                )
            if (
                event.event_type == "debt_issuance"
                and event.event_subtype == "refinancing"
                and event.lifecycle_status in {"in_progress", "completed"}
                and "debt_refinanced" not in bound_roles
            ):
                raise ContractGraphError(
                    "debt refinancing cannot be represented as new debt without a refinance bridge"
                )
            if event.lifecycle_status == "cancelled" and not any(
                item["role_id"] == "cancellation" for item in event.source_bindings
            ):
                raise ContractGraphError(
                    "cancelled CapitalAllocationEvent lacks cancellation source"
                )
            if event.lifecycle_status == "blocked" and not event.missing_evidence:
                raise ContractGraphError("blocked CapitalAllocationEvent requires missing evidence")

        superseded_event_version_ids = {
            item.predecessor_event_id
            for item in self.capital_allocation_events
            if item.predecessor_event_id is not None
        }

        capital_windows: set[tuple[str, str, str]] = set()
        for outcome in self.capital_allocation_outcomes:
            self._require(
                outcome.event_id,
                set(capital_events),
                "CapitalAllocationOutcome event_id",
            )
            event = capital_events[outcome.event_id]
            if outcome.predecessor_outcome_id is not None:
                self._require(
                    outcome.predecessor_outcome_id,
                    set(capital_outcomes),
                    "CapitalAllocationOutcome predecessor_outcome_id",
                )
                predecessor = capital_outcomes[outcome.predecessor_outcome_id]
                if predecessor.event_id != outcome.event_id:
                    raise ContractGraphError(
                        "CapitalAllocationOutcome predecessor belongs to another Event"
                    )
                if date.fromisoformat(predecessor.assessed_at) >= date.fromisoformat(
                    outcome.assessed_at
                ):
                    raise ContractGraphError("CapitalAllocationOutcome predecessor is not earlier")
            start, end = validate_period(
                outcome.observation_period, outcome.assessed_at, "CapitalAllocationOutcome"
            )
            if start < date.fromisoformat(event.announcement_date):
                raise ContractGraphError("CapitalAllocationOutcome observation predates its Event")
            window = (outcome.event_id, start.isoformat(), end.isoformat())
            if window in capital_windows:
                raise ContractGraphError("duplicate CapitalAllocationOutcome observation window")
            capital_windows.add(window)
            policy = policy_for(event.event_type)
            if (
                outcome.outcome_policy_id != policy.outcome_policy_id
                or outcome.outcome_policy_version != OUTCOME_POLICY_VERSION
            ):
                raise ContractGraphError("CapitalAllocationOutcome outcome policy mismatch")
            if event.lifecycle_status == "cancelled" and outcome.status not in {
                "cancelled",
                "blocked",
            }:
                raise ContractGraphError(
                    "cancelled CapitalAllocationEvent cannot receive an ordinary Outcome"
                )
            if event.event_id in superseded_event_version_ids and outcome.status not in {
                "superseded",
                "blocked",
            }:
                raise ContractGraphError(
                    "superseded CapitalAllocationEvent version cannot receive an ordinary Outcome"
                )
            result_bindings = {item["binding_id"]: item for item in outcome.result_bindings}
            if len(result_bindings) != len(outcome.result_bindings):
                raise ContractGraphError("duplicate CapitalAllocationOutcome binding ID")
            seen_role_facts: set[str] = set()
            outcome_calculation_fact_ids: set[str] = set()
            for binding in outcome.result_bindings:
                if binding["role_id"] not in policy.outcome_roles:
                    raise ContractGraphError("CapitalAllocationOutcome uses a free result role")
                if binding["fact_id"] is not None:
                    reference = binding["fact_id"]
                    self._require(reference, set(facts), "CapitalAllocationOutcome result binding")
                    if reference in seen_role_facts:
                        raise ContractGraphError(
                            "CapitalAllocationOutcome reuses a Fact across evidence roles"
                        )
                    seen_role_facts.add(reference)
                    if facts[reference].value_type != "number" or not role_accepts_unit(
                        binding["role_id"], unit_spec(facts[reference].unit).family
                    ):
                        raise ContractGraphError(
                            "CapitalAllocationOutcome result role unit mismatch"
                        )
                    document = documents[facts[reference].source_document_id]
                    if date.fromisoformat(document.published_date) > date.fromisoformat(
                        outcome.assessed_at
                    ):
                        raise ContractGraphError(
                            "CapitalAllocationOutcome result binding uses future evidence"
                        )
                    if (
                        outcome.status in {"observed", "partial"}
                        and document.authority_level not in OFFICIAL_AUTHORITY_LEVELS
                    ):
                        raise ContractGraphError(
                            "CapitalAllocationOutcome requires official result Facts"
                        )
                else:
                    reference = binding["calculation_result_id"]
                    require_phase4_calculation(
                        reference,
                        "CapitalAllocationOutcome result binding",
                        official=outcome.status in {"observed", "partial"},
                        cutoff=date.fromisoformat(outcome.assessed_at),
                    )
                    outcome_calculation_fact_ids.update(calculation_fact_ids(reference))
                    calculation = calculations[reference]
                    if calculation.value_type != "number" or not role_accepts_unit(
                        binding["role_id"], unit_spec(calculation.unit).family
                    ):
                        raise ContractGraphError(
                            "CapitalAllocationOutcome result role unit mismatch"
                        )
            claim_binding_ids = {item["binding_id"] for item in outcome.claim_bindings}
            if len(claim_binding_ids) != len(outcome.claim_bindings):
                raise ContractGraphError("duplicate CapitalAllocationOutcome Claim binding")
            claim_supporting_fact_ids: set[str] = set()
            for binding in outcome.claim_bindings:
                if binding["role_id"] not in OUTCOME_CLAIM_ROLES:
                    raise ContractGraphError("CapitalAllocationOutcome uses a free Claim role")
                claim = require_analytical_claim(
                    binding["claim_id"],
                    "CapitalAllocationOutcome Claim",
                    cutoff=date.fromisoformat(outcome.assessed_at),
                )
                self._require(
                    binding["review_decision_id"],
                    set(analytical_decisions),
                    "CapitalAllocationOutcome analytical review Decision",
                )
                decision = analytical_decisions[binding["review_decision_id"]]
                if decision.output_claim_id != binding["claim_id"]:
                    raise ContractGraphError("CapitalAllocationOutcome Claim review mismatch")
                claim_supporting_fact_ids.update(claim.supporting_fact_ids)
            coverage_roles = [item["role_id"] for item in outcome.result_role_coverage]
            if len(coverage_roles) != len(set(coverage_roles)) or set(coverage_roles) != set(
                policy.outcome_roles
            ):
                raise ContractGraphError("CapitalAllocationOutcome role coverage mismatch")
            for item in outcome.result_role_coverage:
                if not set(item["binding_ids"]).issubset(result_bindings):
                    raise ContractGraphError(
                        "CapitalAllocationOutcome role coverage binding missing"
                    )
                if any(
                    result_bindings[reference]["role_id"] != item["role_id"]
                    for reference in item["binding_ids"]
                ):
                    raise ContractGraphError("CapitalAllocationOutcome role coverage mismatch")
                if not set(item["claim_binding_ids"]).issubset(claim_binding_ids):
                    raise ContractGraphError("CapitalAllocationOutcome role Claim binding missing")
                if item["status"] == "observed" and not item["binding_ids"]:
                    raise ContractGraphError("observed role coverage requires result evidence")
                if item["status"] in {
                    "none_recognized_after_review",
                    "not_applicable",
                } and not item["claim_binding_ids"]:
                    raise ContractGraphError("absence role coverage requires a reviewed Claim")
                if item["status"] == "blocked" and not item["missing_evidence"]:
                    raise ContractGraphError("blocked role coverage requires missing evidence")
            if outcome.status == "observed" and any(
                item["status"] not in {
                    "observed",
                    "none_recognized_after_review",
                    "not_applicable",
                }
                for item in outcome.result_role_coverage
            ):
                raise ContractGraphError(
                    "observed CapitalAllocationOutcome has incomplete role coverage"
                )
            if outcome.status == "not_due" and any(
                item["status"] != "not_due" for item in outcome.result_role_coverage
            ):
                raise ContractGraphError("not-due Outcome has non-pending role coverage")
            if outcome.status == "partial":
                coverage_states = {item["status"] for item in outcome.result_role_coverage}
                if "observed" not in coverage_states or not coverage_states.intersection(
                    {"not_disclosed", "blocked"}
                ):
                    raise ContractGraphError(
                        "partial CapitalAllocationOutcome lacks mixed result coverage"
                    )
            if outcome.status == "unverifiable" and not any(
                item["status"] == "not_disclosed" for item in outcome.result_role_coverage
            ):
                raise ContractGraphError(
                    "unverifiable CapitalAllocationOutcome lacks undisclosed result coverage"
                )
            if outcome.status == "blocked" and not any(
                item["status"] == "blocked" for item in outcome.result_role_coverage
            ):
                raise ContractGraphError(
                    "blocked CapitalAllocationOutcome lacks blocked result coverage"
                )
            if outcome.status in {"cancelled", "superseded"} and outcome.result_bindings:
                raise ContractGraphError("lifecycle CapitalAllocationOutcome contains results")
            if outcome.status in {"observed", "partial"} and not outcome.claim_bindings:
                raise ContractGraphError("interpreted CapitalAllocationOutcome requires a Claim")
            if outcome.status == "observed" and not outcome.result_bindings:
                raise ContractGraphError(
                    "observed CapitalAllocationOutcome requires result evidence"
                )
            if outcome.status == "observed":
                announcement_date = date.fromisoformat(event.announcement_date)
                for fact_id in seen_role_facts:
                    fact = facts[fact_id]
                    document = documents[fact.source_document_id]
                    period_end = fact.period["end"]
                    if date.fromisoformat(document.published_date) < announcement_date or (
                        period_end is not None
                        and date.fromisoformat(period_end) < announcement_date
                    ):
                        raise ContractGraphError(
                            "observed CapitalAllocationOutcome uses pre-Event result evidence"
                        )
                for calculation_id in {
                    item["calculation_result_id"]
                    for item in outcome.result_bindings
                    if item["calculation_result_id"] is not None
                }:
                    calculation = calculations[calculation_id]
                    calculation_end = calculation.period["end"]
                    if (
                        calculation_end is None
                        or date.fromisoformat(calculation_end) < announcement_date
                    ):
                        raise ContractGraphError(
                            "observed CapitalAllocationOutcome calculation predates its Event"
                        )
                    if not any(
                        date.fromisoformat(
                            documents[facts[fact_id].source_document_id].published_date
                        )
                        >= announcement_date
                        for fact_id in calculation_fact_ids(calculation_id)
                    ):
                        raise ContractGraphError(
                            "observed CapitalAllocationOutcome calculation lacks post-Event input"
                        )
            if event.event_type in {
                "acquisition",
                "buyback",
                "debt_issuance",
                "debt_repayment",
            } and (outcome.status == "observed"):
                supporting_concepts = {
                    facts[fact_id].concept.lower()
                    for binding in outcome.claim_bindings
                    for fact_id in claims[binding["claim_id"]].supporting_fact_ids
                }
                if supporting_concepts and all(
                    "eps" in concept or "earnings_per_share" in concept
                    for concept in supporting_concepts
                ):
                    raise ContractGraphError(
                        "capital allocation Outcome cannot rely on EPS accretion alone"
                    )
            formal_result_fact_ids = seen_role_facts.union(outcome_calculation_fact_ids)
            if outcome.status == "observed" and not formal_result_fact_ids.issubset(
                claim_supporting_fact_ids
            ):
                raise ContractGraphError(
                    "observed CapitalAllocationOutcome Claim does not cover all result roles"
                )
            if outcome.status in {"partial", "unverifiable", "blocked"} and not (
                outcome.missing_evidence
            ):
                raise ContractGraphError(
                    f"{outcome.status} CapitalAllocationOutcome requires missing evidence"
                )

        for review in self.management_reviews:
            review_start, review_end = validate_period(
                review.review_period, review.as_of_date, "ManagementReview"
            )
            selected_statements: list[ManagementStatement] = []
            selected_commitments: list[ManagementCommitment] = []
            selected_outcomes: list[ManagementOutcome] = []
            for reference in review.statement_ids:
                self._require(reference, set(statements), "ManagementReview statement_ids")
                selected_statements.append(statements[reference])
                if statements[reference].verification_status != "human_confirmed":
                    raise ContractGraphError(
                        "ManagementReview cannot consume unconfirmed Statements"
                    )
                if date.fromisoformat(statements[reference].statement_date) > date.fromisoformat(
                    review.as_of_date
                ):
                    raise ContractGraphError("ManagementReview uses a future Statement")
                statement_document = documents[statements[reference].source_document_id]
                if date.fromisoformat(statement_document.published_date) > date.fromisoformat(
                    review.as_of_date
                ):
                    raise ContractGraphError(
                        "ManagementReview uses Statement evidence published after cutoff"
                    )
                reviewed_at = statements[reference].reviewed_at
                if reviewed_at is not None and self._parse_datetime(reviewed_at).date() > (
                    date.fromisoformat(review.as_of_date)
                ):
                    raise ContractGraphError(
                        "ManagementReview uses a Statement confirmed after cutoff"
                    )
            for reference in review.commitment_ids:
                self._require(reference, set(commitments), "ManagementReview commitment_ids")
                selected_commitments.append(commitments[reference])
                if commitments[reference].statement_id not in review.statement_ids:
                    raise ContractGraphError(
                        "ManagementReview Commitment lacks its source Statement"
                    )
                if date.fromisoformat(commitments[reference].start_date) > date.fromisoformat(
                    review.as_of_date
                ):
                    raise ContractGraphError("ManagementReview uses a future Commitment")
                for fact_id in (
                    *(item["fact_id"] for item in commitments[reference].baseline_bindings),
                    *(item["fact_id"] for item in commitments[reference].target_bindings),
                ):
                    if date.fromisoformat(
                        documents[facts[fact_id].source_document_id].published_date
                    ) > date.fromisoformat(review.as_of_date):
                        raise ContractGraphError(
                            "ManagementReview uses Commitment evidence published after cutoff"
                        )
            for reference in review.outcome_ids:
                self._require(reference, set(management_outcomes), "ManagementReview outcome_ids")
                selected_outcomes.append(management_outcomes[reference])
                if management_outcomes[reference].commitment_id not in review.commitment_ids:
                    raise ContractGraphError("ManagementReview Outcome lacks its Commitment")
                if date.fromisoformat(
                    management_outcomes[reference].assessed_at
                ) > date.fromisoformat(review.as_of_date):
                    raise ContractGraphError("ManagementReview uses a future Outcome")
            for reference in review.claim_ids:
                require_claim(
                    reference,
                    "ManagementReview claim_ids",
                    official=review.status == "complete",
                    cutoff=date.fromisoformat(review.as_of_date),
                )
            for reference in review.calculation_result_ids:
                require_phase4_calculation(
                    reference,
                    "ManagementReview calculation_result_ids",
                    official=review.status == "complete",
                    cutoff=date.fromisoformat(review.as_of_date),
                )
            due = [
                item
                for item in selected_commitments
                if item.status == "open"
                and date.fromisoformat(item.due_date) <= date.fromisoformat(review.as_of_date)
            ]
            not_due = [
                item
                for item in selected_commitments
                if item.status == "open"
                and date.fromisoformat(item.due_date) > date.fromisoformat(review.as_of_date)
            ]
            expected_coverage = {
                "statement_count": len(selected_statements),
                "confirmed_count": sum(
                    item.verification_status == "human_confirmed" for item in selected_statements
                ),
                "open_count": sum(item.status == "open" for item in selected_commitments),
                "not_due_count": len(not_due),
                "due_count": len(due),
                "evaluated_due_count": len(
                    {
                        item.commitment_id
                        for item in selected_outcomes
                        if item.status in {"met", "partially_met", "missed", "unverifiable"}
                    }.intersection({item.commitment_id for item in due})
                ),
                "pending_count": sum(item.status == "pending" for item in selected_outcomes),
                "met_count": sum(item.status == "met" for item in selected_outcomes),
                "partially_met_count": sum(
                    item.status == "partially_met" for item in selected_outcomes
                ),
                "missed_count": sum(item.status == "missed" for item in selected_outcomes),
                "unverifiable_count": sum(
                    item.status == "unverifiable" for item in selected_outcomes
                ),
                "blocked_count": sum(item.status == "blocked" for item in selected_outcomes),
                "withdrawn_count": sum(item.status == "withdrawn" for item in selected_commitments),
                "superseded_count": sum(
                    item.status == "superseded" for item in selected_commitments
                ),
            }
            if dict(review.coverage) != expected_coverage:
                raise ContractGraphError("ManagementReview coverage counts mismatch")
            if review.status != "blocked" and not review.claim_ids:
                raise ContractGraphError("non-blocked ManagementReview requires a Claim")
            if review.status == "complete":
                expected_commitment_ids = {
                    item.commitment_id
                    for item in self.management_commitments
                    if (
                        review_start <= date.fromisoformat(item.due_date) <= review_end
                        or (
                            item.status == "open"
                            and date.fromisoformat(item.start_date) <= review_end
                            and date.fromisoformat(item.due_date) >= review_start
                        )
                    )
                }
                if not expected_commitment_ids.issubset(set(review.commitment_ids)):
                    raise ContractGraphError(
                        "complete ManagementReview omits an in-period Commitment"
                    )
                expected_statement_ids = {
                    item.statement_id
                    for item in self.management_statements
                    if item.verification_status == "human_confirmed"
                    and review_start <= date.fromisoformat(item.statement_date) <= review_end
                }
                expected_statement_ids.update(
                    commitments[commitment_id].statement_id
                    for commitment_id in expected_commitment_ids
                )
                if not expected_statement_ids.issubset(set(review.statement_ids)):
                    raise ContractGraphError(
                        "complete ManagementReview omits an in-period or linked Statement"
                    )
                if expected_coverage["evaluated_due_count"] != expected_coverage["due_count"]:
                    raise ContractGraphError("complete ManagementReview omits a due Outcome")
                lifecycle_outcomes = {
                    (item.commitment_id, item.status) for item in selected_outcomes
                }
                for item in selected_commitments:
                    if (
                        item.status in {"withdrawn", "superseded"}
                        and (
                            item.commitment_id,
                            item.status,
                        )
                        not in lifecycle_outcomes
                    ):
                        raise ContractGraphError(
                            "complete ManagementReview omits a lifecycle Outcome"
                        )
                if expected_coverage["blocked_count"] or expected_coverage["unverifiable_count"]:
                    raise ContractGraphError(
                        "complete ManagementReview contains blocked or unverifiable Outcomes"
                    )
            if review.status == "blocked" and not review.missing_evidence:
                raise ContractGraphError("blocked ManagementReview requires missing evidence")

        for review in self.capital_allocation_reviews:
            for outcome_id in review.outcome_ids:
                self._require(
                    outcome_id,
                    set(capital_outcomes),
                    "CapitalAllocationReview outcome_ids",
                )
                assessed_at = date.fromisoformat(capital_outcomes[outcome_id].assessed_at)
                if assessed_at > date.fromisoformat(review.as_of_date):
                    raise ContractGraphError("CapitalAllocationReview uses a future Outcome")
            rebuilt = build_capital_allocation_review(
                issuer_id=review.issuer_id,
                review_period=dict(review.review_period),
                as_of_date=review.as_of_date,
                source_documents=tuple(
                    item for item in self.documents if item.issuer_id == review.issuer_id
                ),
                source_search_receipts=tuple(
                    item
                    for item in self.source_search_receipts
                    if item.issuer_id == review.issuer_id
                ),
                events=tuple(
                    item
                    for item in self.capital_allocation_events
                    if item.issuer_id == review.issuer_id
                ),
                outcomes=tuple(
                    item
                    for item in self.capital_allocation_outcomes
                    if item.issuer_id == review.issuer_id
                ),
                calculations=tuple(
                    item for item in self.calculations if item.issuer_id == review.issuer_id
                ),
                claims=tuple(
                    item for item in self.claims if item.issuer_id == review.issuer_id
                ),
                analytical_candidates=tuple(
                    item
                    for item in self.analytical_claim_candidates
                    if item.issuer_id == review.issuer_id
                ),
                analytical_decisions=tuple(
                    item
                    for item in self.analytical_claim_review_decisions
                    if item.issuer_id == review.issuer_id
                ),
                claim_evidence=tuple(
                    CapitalReviewClaimEvidence(
                        claim_id=item["claim_id"],
                        review_decision_id=item["review_decision_id"],
                        role_id=item["role_id"],
                    )
                    for item in review.claim_bindings
                ),
            )
            if rebuilt.fingerprint != review.fingerprint:
                raise ContractGraphError(
                    "CapitalAllocationReview does not match deterministic replay"
                )
            continue
            review_start, review_end = validate_period(
                review.review_period, review.as_of_date, "CapitalAllocationReview"
            )
            review_cutoff = date.fromisoformat(review.as_of_date)
            if (
                review.review_policy_id != REVIEW_POLICY_ID
                or review.review_policy_version != REVIEW_POLICY_VERSION
            ):
                raise ContractGraphError("CapitalAllocationReview review policy mismatch")

            source_rows = {item["source_family"]: item for item in review.source_coverage}
            if len(source_rows) != len(review.source_coverage) or set(source_rows) != set(
                SOURCE_FAMILIES
            ):
                raise ContractGraphError("CapitalAllocationReview source coverage mismatch")
            for row in review.source_coverage:
                for source_document_id in row["source_document_ids"]:
                    self._require(
                        source_document_id,
                        set(documents),
                        "CapitalAllocationReview source coverage",
                    )
                    source = documents[source_document_id]
                    if source.authority_level not in OFFICIAL_AUTHORITY_LEVELS:
                        raise ContractGraphError(
                            "CapitalAllocationReview source coverage requires official evidence"
                        )
                    if date.fromisoformat(source.published_date) > review_cutoff:
                        raise ContractGraphError(
                            "CapitalAllocationReview source coverage uses future evidence"
                        )
                    normalized_type = source.document_type.upper().replace(" ", "")
                    family = row["source_family"]
                    exact_families = {
                        "10-K": "10-K",
                        "10-Q": "10-Q",
                        "8-K": "8-K",
                        "DEF14A": "DEF14A",
                    }
                    if family in exact_families and normalized_type != exact_families[family]:
                        raise ContractGraphError(
                            "CapitalAllocationReview source family does not match document type"
                        )
                    if family == "official_ir" and source.authority_level != "company_primary":
                        raise ContractGraphError(
                            "CapitalAllocationReview official IR coverage is not company-primary"
                        )
                if row["status"] == "reviewed" and not row["source_document_ids"]:
                    raise ContractGraphError(
                        "reviewed CapitalAllocationReview source family lacks documents"
                    )
                if row["status"] == "blocked" and not row["missing_evidence"]:
                    raise ContractGraphError(
                        "blocked CapitalAllocationReview source family lacks missing evidence"
                    )
                if row["status"] != "blocked" and row["missing_evidence"]:
                    raise ContractGraphError(
                        "resolved CapitalAllocationReview source family has missing evidence"
                    )

            review_claim_bindings = {
                item["binding_id"]: item for item in review.claim_bindings
            }
            if len(review_claim_bindings) != len(review.claim_bindings):
                raise ContractGraphError("duplicate CapitalAllocationReview Claim binding")
            for binding in review.claim_bindings:
                if binding["role_id"] not in REVIEW_CLAIM_ROLES:
                    raise ContractGraphError("CapitalAllocationReview uses a free Claim role")
                require_analytical_claim(
                    binding["claim_id"],
                    "CapitalAllocationReview Claim",
                    cutoff=review_cutoff,
                )
                self._require(
                    binding["review_decision_id"],
                    set(analytical_decisions),
                    "CapitalAllocationReview analytical review Decision",
                )
                claim_decision = analytical_decisions[binding["review_decision_id"]]
                if claim_decision.output_claim_id != binding["claim_id"]:
                    raise ContractGraphError("CapitalAllocationReview Claim review mismatch")

            eligible_events = [
                item
                for item in self.capital_allocation_events
                if date.fromisoformat(item.announcement_date) <= review_cutoff
            ]
            latest_events_by_key: dict[str, CapitalAllocationEvent] = {}
            for event in eligible_events:
                current = latest_events_by_key.get(event.economic_event_key)
                if current is None or event.event_version > current.event_version:
                    latest_events_by_key[event.economic_event_key] = event
            latest_event_ids = {item.event_id for item in latest_events_by_key.values()}
            selected_events: list[CapitalAllocationEvent] = []
            selected_outcomes: list[CapitalAllocationOutcome] = []
            for reference in review.event_ids:
                self._require(reference, set(capital_events), "CapitalAllocationReview event_ids")
                selected_events.append(capital_events[reference])
                if reference not in latest_event_ids:
                    raise ContractGraphError(
                        "CapitalAllocationReview must select the latest logical Event version"
                    )
                if date.fromisoformat(capital_events[reference].announcement_date) > review_cutoff:
                    raise ContractGraphError("CapitalAllocationReview uses a future Event")
                for binding in capital_events[reference].source_bindings:
                    source_document_id = binding["source_document_id"]
                    if (
                        date.fromisoformat(documents[source_document_id].published_date)
                        > review_cutoff
                    ):
                        raise ContractGraphError(
                            "CapitalAllocationReview uses Event evidence published after cutoff"
                        )
            if len({item.economic_event_key for item in selected_events}) != len(selected_events):
                raise ContractGraphError(
                    "CapitalAllocationReview double-counts an economic Event"
                )

            eligible_outcomes = [
                item
                for item in self.capital_allocation_outcomes
                if date.fromisoformat(item.assessed_at) <= review_cutoff
            ]
            latest_outcome_by_event: dict[str, CapitalAllocationOutcome] = {}
            for outcome in eligible_outcomes:
                current = latest_outcome_by_event.get(outcome.event_id)
                if current is None or date.fromisoformat(outcome.assessed_at) > date.fromisoformat(
                    current.assessed_at
                ):
                    latest_outcome_by_event[outcome.event_id] = outcome
            latest_outcome_ids = {item.outcome_id for item in latest_outcome_by_event.values()}
            for reference in review.outcome_ids:
                self._require(
                    reference, set(capital_outcomes), "CapitalAllocationReview outcome_ids"
                )
                selected_outcomes.append(capital_outcomes[reference])
                if date.fromisoformat(capital_outcomes[reference].assessed_at) > review_cutoff:
                    raise ContractGraphError("CapitalAllocationReview uses a future Outcome")
                if reference not in latest_outcome_ids:
                    raise ContractGraphError(
                        "CapitalAllocationReview must select the latest available Outcome"
                    )
                if capital_outcomes[reference].event_id not in review.event_ids:
                    raise ContractGraphError(
                        "CapitalAllocationReview Outcome belongs to an unselected Event"
                    )

            event_type_rows = [item["event_type"] for item in review.event_type_coverage]
            if len(event_type_rows) != len(set(event_type_rows)) or set(event_type_rows) != (
                PHASE4_EVENT_TYPES
            ):
                raise ContractGraphError("CapitalAllocationReview event type coverage mismatch")
            selected_event_ids = {item.event_id for item in selected_events}
            for row in review.event_type_coverage:
                row_event_ids = set(row["event_ids"])
                if not row_event_ids.issubset(selected_event_ids):
                    raise ContractGraphError(
                        "CapitalAllocationReview event coverage references an unselected Event"
                    )
                if any(
                    capital_events[item].event_type != row["event_type"]
                    for item in row_event_ids
                ):
                    raise ContractGraphError(
                        "CapitalAllocationReview event coverage type mismatch"
                    )
                for source_document_id in row["source_document_ids"]:
                    self._require(
                        source_document_id,
                        set(documents),
                        "CapitalAllocationReview event coverage source",
                    )
                    source = documents[source_document_id]
                    if (
                        source.authority_level not in OFFICIAL_AUTHORITY_LEVELS
                        or date.fromisoformat(source.published_date) > review_cutoff
                    ):
                        raise ContractGraphError(
                            "CapitalAllocationReview event coverage requires "
                            "current official sources"
                        )
                if not set(row["claim_binding_ids"]).issubset(review_claim_bindings):
                    raise ContractGraphError(
                        "CapitalAllocationReview event coverage Claim binding missing"
                    )
                if row["status"] == "reviewed":
                    if not row_event_ids or not row["source_document_ids"]:
                        raise ContractGraphError(
                            "reviewed CapitalAllocationReview event type lacks evidence"
                        )
                elif row["status"] == "not_found":
                    if row_event_ids or not row["source_document_ids"] or not row["search_note"]:
                        raise ContractGraphError(
                            "not-found CapitalAllocationReview event type lacks completed search"
                        )
                elif row["status"] == "not_applicable":
                    if row_event_ids or not row["claim_binding_ids"]:
                        raise ContractGraphError(
                            "not-applicable CapitalAllocationReview event type lacks a Claim"
                        )
                    if any(
                        review_claim_bindings[item]["role_id"] != "not_applicable"
                        for item in row["claim_binding_ids"]
                    ):
                        raise ContractGraphError(
                            "CapitalAllocationReview not-applicable coverage uses "
                            "the wrong Claim role"
                        )
                elif not row["missing_evidence"]:
                    raise ContractGraphError(
                        "blocked CapitalAllocationReview event type lacks missing evidence"
                    )
                if row["status"] != "blocked" and row["missing_evidence"]:
                    raise ContractGraphError(
                        "resolved CapitalAllocationReview event type has missing evidence"
                    )

            selected_keys = {item.economic_event_key for item in selected_events}
            version_count = sum(
                item.economic_event_key in selected_keys for item in eligible_events
            )
            expected_coverage = {
                "logical_event_count": len(selected_keys),
                "event_version_count": version_count,
                "outcome_count": len(selected_outcomes),
                "not_due_count": sum(item.status == "not_due" for item in selected_outcomes),
                "observed_count": sum(item.status == "observed" for item in selected_outcomes),
                "partial_count": sum(item.status == "partial" for item in selected_outcomes),
                "unverifiable_count": sum(
                    item.status == "unverifiable" for item in selected_outcomes
                ),
                "blocked_count": sum(item.status == "blocked" for item in selected_outcomes),
                "cancelled_count": sum(item.status == "cancelled" for item in selected_outcomes),
                "superseded_count": sum(
                    item.status == "superseded" for item in selected_outcomes
                ),
                "reviewed_type_count": sum(
                    item["status"] == "reviewed" for item in review.event_type_coverage
                ),
                "not_found_type_count": sum(
                    item["status"] == "not_found" for item in review.event_type_coverage
                ),
                "not_applicable_type_count": sum(
                    item["status"] == "not_applicable"
                    for item in review.event_type_coverage
                ),
                "blocked_type_count": sum(
                    item["status"] == "blocked" for item in review.event_type_coverage
                ),
            }
            if dict(review.coverage) != expected_coverage:
                raise ContractGraphError("CapitalAllocationReview coverage counts mismatch")
            for reference in review.calculation_result_ids:
                require_phase4_calculation(
                    reference,
                    "CapitalAllocationReview calculation_result_ids",
                    official=review.status == "complete",
                    cutoff=review_cutoff,
                )
            if review.status == "complete":
                in_period_keys = {
                    item.economic_event_key
                    for item in eligible_events
                    if review_start <= date.fromisoformat(item.announcement_date) <= review_end
                }
                expected_event_ids = {
                    latest_events_by_key[item].event_id for item in in_period_keys
                }
                if not expected_event_ids.issubset(selected_event_ids):
                    raise ContractGraphError(
                        "complete CapitalAllocationReview omits an in-period Event"
                    )
                expected_outcome_ids = {
                    latest_outcome_by_event[event_id].outcome_id
                    for event_id in selected_event_ids
                    if event_id in latest_outcome_by_event
                }
                if expected_outcome_ids != set(review.outcome_ids):
                    raise ContractGraphError(
                        "complete CapitalAllocationReview omits an available Outcome"
                    )
                if (
                    expected_coverage["partial_count"]
                    or expected_coverage["unverifiable_count"]
                    or expected_coverage["blocked_count"]
                    or expected_coverage["blocked_type_count"]
                    or any(item["status"] == "blocked" for item in review.source_coverage)
                    or review.missing_evidence
                ):
                    raise ContractGraphError(
                        "complete CapitalAllocationReview contains unresolved coverage"
                    )
            if review.status == "partial" and any(
                item["status"] == "blocked" for item in review.source_coverage
            ):
                raise ContractGraphError(
                    "CapitalAllocationReview with blocked source coverage cannot be partial"
                )
            if review.status == "blocked" and not review.missing_evidence:
                raise ContractGraphError(
                    "blocked CapitalAllocationReview requires missing evidence"
                )

        self._reject_cycles(
            {item.fact_id: tuple(item.parent_fact_ids) for item in self.facts},
            "Fact",
        )
        self._reject_cycles(
            {item.calculation_id: tuple(item.input_calculation_ids) for item in self.calculations},
            "CalculationResult",
        )
        self._reject_cycles(
            {
                item.period_id: (
                    (item.comparative_period_id,) if item.comparative_period_id is not None else ()
                )
                for item in self.periods
            },
            "FiscalPeriod",
        )
        self._reject_cycles(
            {
                item.segment_id: tuple(item.predecessor_segment_ids)
                for item in self.segment_definitions
            },
            "SegmentDefinition",
        )
        self._reject_cycles(
            {
                item.hypothesis_id: (
                    (item.predecessor_hypothesis_id,)
                    if item.predecessor_hypothesis_id is not None
                    else ()
                )
                for item in self.competitive_advantage_hypotheses
            },
            "CompetitiveAdvantageHypothesis",
        )
        self._reject_cycles(
            {
                item.statement_id: tuple(item.predecessor_statement_ids)
                for item in self.management_statements
            },
            "ManagementStatement",
        )
        self._reject_cycles(
            {
                item.commitment_id: (
                    (item.superseded_by_commitment_id,)
                    if item.superseded_by_commitment_id is not None
                    else ()
                )
                for item in self.management_commitments
            },
            "ManagementCommitment",
        )
        self._reject_cycles(
            {
                item.outcome_id: (
                    (item.predecessor_outcome_id,)
                    if item.predecessor_outcome_id is not None
                    else ()
                )
                for item in self.management_outcomes
            },
            "ManagementOutcome",
        )
        self._reject_cycles(
            {
                item.candidate_id: tuple(item.supersedes_candidate_ids)
                for item in self.capital_allocation_event_candidates
            },
            "CapitalAllocationEventCandidate",
        )
        self._reject_cycles(
            {
                item.decision_id: tuple(item.supersedes_decision_ids)
                for item in self.capital_allocation_event_review_decisions
            },
            "CapitalAllocationEventReviewDecision",
        )
        self._reject_cycles(
            {
                item.event_id: (
                    *((item.predecessor_event_id,) if item.predecessor_event_id else ()),
                    *item.supersedes_event_ids,
                )
                for item in self.capital_allocation_events
            },
            "CapitalAllocationEvent",
        )
        self._reject_cycles(
            {
                item.outcome_id: (
                    (item.predecessor_outcome_id,)
                    if item.predecessor_outcome_id is not None
                    else ()
                )
                for item in self.capital_allocation_outcomes
            },
            "CapitalAllocationOutcome",
        )

        for calculation in self.calculations:
            expected_input = expected_input_fingerprint(
                calculation,
                facts=facts,
                assumptions=assumptions,
                calculations=calculations,
                periods=periods,
            )
            if calculation.input_fingerprint != expected_input:
                raise ContractGraphError(
                    f"Calculation {calculation.calculation_id} input_fingerprint mismatch"
                )
            expected_output = expected_output_fingerprint(calculation)
            if calculation.output_fingerprint != expected_output:
                raise ContractGraphError(
                    f"Calculation {calculation.calculation_id} output_fingerprint mismatch"
                )

        for score in self.scores:
            if score.score > score.max_score:
                raise ContractGraphError(f"Score {score.score_id} exceeds its maximum")
            for reference in score.fact_ids:
                self._require(reference, set(facts), "Score fact_ids")
            for reference in score.claim_ids:
                self._require(reference, set(claims), "Score claim_ids")
            for reference in score.calculation_result_ids:
                self._require(reference, set(calculations), "Score calculation_result_ids")

        for manifest in self.manifests:
            self._validate_manifest(manifest, documents)

        from .research_bundle_validation import (
            ResearchBundleValidationError,
            validate_research_bundle,
        )

        for bundle in self.research_bundles:
            try:
                validate_research_bundle(self, bundle)
            except ResearchBundleValidationError as exc:
                raise ContractGraphError(str(exc)) from exc

        from .valuation_handoff_validation import (
            ValuationHandoffValidationError,
            validate_valuation_handoff_contracts,
        )

        try:
            validate_valuation_handoff_contracts(self)
        except ValuationHandoffValidationError as exc:
            raise ContractGraphError(str(exc)) from exc

    def _validate_collection_types(self) -> None:
        from .valuation_market_reference_types import MarketReferenceValidationContext

        expected: dict[str, type[Any]] = {
            "documents": SourceDocument,
            "facts": Fact,
            "claims": Claim,
            "assumptions": Assumption,
            "calculations": CalculationResult,
            "periods": FiscalPeriod,
            "reconciliations": QuarterlyReconciliation,
            "quarterly_updates": QuarterlyUpdate,
            "filing_artifacts": FilingArtifact,
            "extraction_candidates": ExtractionCandidate,
            "evidence_promotions": EvidencePromotion,
            "segment_definitions": SegmentDefinition,
            "segment_snapshots": SegmentSnapshot,
            "footnote_reviews": FootnoteReview,
            "accounting_quality_findings": AccountingQualityFinding,
            "accounting_quality_reviews": AccountingQualityReview,
            "context_observations": ContextObservation,
            "competitive_context_snapshots": CompetitiveContextSnapshot,
            "analytical_claim_candidates": AnalyticalClaimCandidate,
            "analytical_claim_review_decisions": AnalyticalClaimReviewDecision,
            "business_model_snapshots": BusinessModelSnapshot,
            "competitive_advantage_hypotheses": CompetitiveAdvantageHypothesis,
            "business_quality_reviews": BusinessQualityReview,
            "management_statements": ManagementStatement,
            "management_statement_candidates": ManagementStatementCandidate,
            "management_statement_review_decisions": ManagementStatementReviewDecision,
            "management_commitments": ManagementCommitment,
            "management_outcomes": ManagementOutcome,
            "capital_allocation_event_candidates": CapitalAllocationEventCandidate,
            "capital_allocation_event_review_decisions": CapitalAllocationEventReviewDecision,
            "capital_allocation_events": CapitalAllocationEvent,
            "capital_allocation_outcomes": CapitalAllocationOutcome,
            "source_search_receipts": SourceSearchReceipt,
            "management_reviews": ManagementReview,
            "capital_allocation_reviews": CapitalAllocationReview,
            "scores": Score,
            "manifests": RunManifest,
            "research_bundles": ResearchBundle,
            "valuation_assumption_candidates": ValuationAssumptionCandidate,
            "valuation_assumption_review_decisions": ValuationAssumptionReviewDecision,
            "market_reference_snapshots": MarketReferenceSnapshot,
            "valuation_handoffs": ValuationHandoff,
            "price_blind_reference_closures": PriceBlindReferenceClosure,
            "market_reference_validation_contexts": MarketReferenceValidationContext,
        }
        domain_names = {
            "documents": "SourceDocument",
            "facts": "Fact",
            "claims": "Claim",
            "assumptions": "Assumption",
            "calculations": "CalculationResult",
            "periods": "FiscalPeriod",
            "reconciliations": "QuarterlyReconciliation",
            "quarterly_updates": "QuarterlyUpdate",
            "filing_artifacts": "FilingArtifact",
            "extraction_candidates": "ExtractionCandidate",
            "evidence_promotions": "EvidencePromotion",
            "segment_definitions": "SegmentDefinition",
            "segment_snapshots": "SegmentSnapshot",
            "footnote_reviews": "FootnoteReview",
            "accounting_quality_findings": "AccountingQualityFinding",
            "accounting_quality_reviews": "AccountingQualityReview",
            "context_observations": "ContextObservation",
            "competitive_context_snapshots": "CompetitiveContextSnapshot",
            "analytical_claim_candidates": "AnalyticalClaimCandidate",
            "analytical_claim_review_decisions": "AnalyticalClaimReviewDecision",
            "business_model_snapshots": "BusinessModelSnapshot",
            "competitive_advantage_hypotheses": "CompetitiveAdvantageHypothesis",
            "business_quality_reviews": "BusinessQualityReview",
            "management_statements": "ManagementStatement",
            "management_statement_candidates": "ManagementStatementCandidate",
            "management_statement_review_decisions": "ManagementStatementReviewDecision",
            "management_commitments": "ManagementCommitment",
            "management_outcomes": "ManagementOutcome",
            "capital_allocation_event_candidates": "CapitalAllocationEventCandidate",
            "capital_allocation_event_review_decisions": "CapitalAllocationEventReviewDecision",
            "capital_allocation_events": "CapitalAllocationEvent",
            "capital_allocation_outcomes": "CapitalAllocationOutcome",
            "source_search_receipts": "SourceSearchReceipt",
            "management_reviews": "ManagementReview",
            "capital_allocation_reviews": "CapitalAllocationReview",
            "scores": "Score",
            "manifests": "RunManifest",
            "research_bundles": "ResearchBundle",
            "valuation_assumption_candidates": "ValuationAssumptionCandidate",
            "valuation_assumption_review_decisions": "ValuationAssumptionReviewDecision",
            "market_reference_snapshots": "MarketReferenceSnapshot",
            "valuation_handoffs": "ValuationHandoff",
            "price_blind_reference_closures": "PriceBlindReferenceClosure",
            "market_reference_validation_contexts": "MarketReferenceValidationContext",
        }
        for field_name, expected_type in expected.items():
            for item in getattr(self, field_name):
                if type(item) is not expected_type:
                    raise ContractGraphError(
                        f"{domain_names[field_name]} domain contains {type(item).__name__}"
                    )

    def _require_single_issuer(self) -> None:
        items = (
            *self.facts,
            *self.claims,
            *self.assumptions,
            *self.calculations,
            *self.periods,
            *self.reconciliations,
            *self.quarterly_updates,
            *self.filing_artifacts,
            *self.extraction_candidates,
            *self.evidence_promotions,
            *self.segment_definitions,
            *self.segment_snapshots,
            *self.footnote_reviews,
            *self.accounting_quality_findings,
            *self.accounting_quality_reviews,
            *self.competitive_context_snapshots,
            *self.analytical_claim_candidates,
            *self.analytical_claim_review_decisions,
            *self.business_model_snapshots,
            *self.competitive_advantage_hypotheses,
            *self.business_quality_reviews,
            *self.management_statements,
            *self.management_statement_candidates,
            *self.management_statement_review_decisions,
            *self.management_commitments,
            *self.management_outcomes,
            *self.capital_allocation_event_candidates,
            *self.capital_allocation_event_review_decisions,
            *self.capital_allocation_events,
            *self.capital_allocation_outcomes,
            *self.source_search_receipts,
            *self.management_reviews,
            *self.capital_allocation_reviews,
            *self.scores,
            *self.manifests,
            *self.research_bundles,
            *self.valuation_assumption_candidates,
            *self.valuation_assumption_review_decisions,
            *self.market_reference_snapshots,
            *self.valuation_handoffs,
            *self.market_reference_validation_contexts,
        )
        issuers = {item.issuer_id for item in items}
        issuers.update(item.target_issuer_id for item in self.context_observations)
        if len(issuers) > 1:
            raise ContractGraphError("ContractGraph contains multiple issuers")

    def _validate_manifest(
        self,
        manifest: RunManifest,
        documents: dict[str, SourceDocument],
    ) -> None:
        declared_hashes = dict(manifest.input_document_hashes)
        expected_hashes = {
            identifier: document.content_sha256
            for identifier, document in documents.items()
            if document.authority_level != "market_reference"
        }
        if declared_hashes != expected_hashes:
            raise ContractGraphError(
                f"RunManifest {manifest.run_id} input_document_hashes do not match graph inputs"
            )

        cutoff = date.fromisoformat(manifest.data_cutoff_date)
        for document in documents.values():
            if date.fromisoformat(document.published_date) > cutoff:
                raise ContractGraphError(
                    f"SourceDocument {document.document_id} was published after data cutoff"
                )
        for artifact in self.filing_artifacts:
            if date.fromisoformat(artifact.filing_date) > cutoff:
                raise ContractGraphError(
                    f"FilingArtifact {artifact.artifact_id} was filed after data cutoff"
                )
            if date.fromisoformat(artifact.report_period) > cutoff:
                raise ContractGraphError(
                    f"FilingArtifact {artifact.artifact_id} report period follows data cutoff"
                )

        lock_path = self.component_lock_path
        if lock_path is None or not lock_path.is_file():
            raise ContractGraphError("RunManifest component lock file is unavailable")
        if manifest.component_lock_sha256 != file_sha256(lock_path):
            raise ContractGraphError(
                f"RunManifest {manifest.run_id} component_lock_sha256 mismatch"
            )

        started = self._parse_datetime(manifest.started_at)
        if cutoff > started.date():
            raise ContractGraphError(f"RunManifest {manifest.run_id} cutoff follows run start")
        completed = self._parse_datetime(manifest.completed_at) if manifest.completed_at else None
        if completed and completed < started:
            raise ContractGraphError(f"RunManifest {manifest.run_id} completed before start")

        anti = manifest.anti_anchoring
        state = anti["state"]
        accessed = anti["prior_materials_accessed"]
        if state != "comparison" and accessed:
            raise ContractGraphError(
                f"RunManifest {manifest.run_id} accessed prior material before conclusion freeze"
            )
        if state == "comparison" and (
            anti["conclusion_frozen_at"] is None or anti["current_conclusion_sha256"] is None
        ):
            raise ContractGraphError(
                f"RunManifest {manifest.run_id} comparison lacks frozen conclusion"
            )
        if anti["conclusion_frozen_at"]:
            frozen = self._parse_datetime(anti["conclusion_frozen_at"])
            if frozen < started or (completed and frozen > completed):
                raise ContractGraphError(
                    f"RunManifest {manifest.run_id} conclusion freeze is outside run lifecycle"
                )

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _require(reference: str, valid_ids: set[str], context: str) -> None:
        if reference not in valid_ids:
            raise ContractGraphError(f"{context} has dangling reference: {reference}")

    @staticmethod
    def _reject_duplicates(domains: dict[str, list[str]]) -> None:
        for domain, identifiers in domains.items():
            if len(identifiers) != len(set(identifiers)):
                raise ContractGraphError(f"Duplicate identifier inside {domain} domain")

    @staticmethod
    def _reject_cross_domain_ids(domains: dict[str, set[str]]) -> None:
        owners: dict[str, str] = {}
        for domain, identifiers in domains.items():
            for identifier in identifiers:
                previous = owners.setdefault(identifier, domain)
                if previous != domain:
                    raise ContractGraphError(
                        f"Identifier {identifier} appears in multiple contract domains: "
                        f"{previous}, {domain}"
                    )

    @staticmethod
    def _reject_cycles(edges: dict[str, tuple[str, ...]], domain: str) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(identifier: str) -> None:
            if identifier in visiting:
                raise ContractGraphError(f"{domain} dependency cycle includes {identifier}")
            if identifier in visited:
                return
            visiting.add(identifier)
            for dependency in edges.get(identifier, ()):
                visit(dependency)
            visiting.remove(identifier)
            visited.add(identifier)

        for identifier in edges:
            visit(identifier)
