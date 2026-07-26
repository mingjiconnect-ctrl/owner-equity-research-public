from __future__ import annotations

import re
from dataclasses import dataclass, fields
from decimal import Decimal, InvalidOperation
from typing import Any, ClassVar

from .fingerprints import FrozenMap, canonical_sha256, freeze, to_json_value
from .schema_store import validate_payload
from .units import validate_unit_currency

Scalar = float | int | str | bool | None

_MARKET_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")


def _positive_market_decimal(value: str, label: str) -> Decimal:
    if not isinstance(value, str) or _MARKET_DECIMAL.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{label} must be a canonical decimal string") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ValueError(f"{label} must be finite and positive")
    return parsed


@dataclass(frozen=True, slots=True)
class Contract:
    SCHEMA_NAME: ClassVar[str]

    def __post_init__(self) -> None:
        payload = {field.name: to_json_value(getattr(self, field.name)) for field in fields(self)}
        validate_payload(self.SCHEMA_NAME, payload)
        for field in fields(self):
            object.__setattr__(self, field.name, freeze(getattr(self, field.name)))

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {field.name: to_json_value(getattr(self, field.name)) for field in fields(self)}


@dataclass(frozen=True, slots=True)
class SourceDocument(Contract):
    SCHEMA_NAME: ClassVar[str] = "source-document"
    schema_version: str
    document_id: str
    issuer_id: str
    document_type: str
    period: FrozenMap
    published_date: str
    retrieved_at: str
    source_url: str
    authority_level: str
    content_sha256: str


@dataclass(frozen=True, slots=True)
class Fact(Contract):
    SCHEMA_NAME: ClassVar[str] = "fact"
    schema_version: str
    fact_id: str
    issuer_id: str
    concept: str
    value_type: str
    value: Scalar
    unit: str | None
    currency: str | None
    period: FrozenMap
    source_document_id: str
    source_locator: str
    derivation: str | None
    parent_fact_ids: tuple[str, ...]
    confidence: str

    def __post_init__(self) -> None:
        Contract.__post_init__(self)
        if self.value_type == "number":
            validate_unit_currency(self.unit, self.currency)


@dataclass(frozen=True, slots=True)
class Claim(Contract):
    SCHEMA_NAME: ClassVar[str] = "claim"
    schema_version: str
    claim_id: str
    issuer_id: str
    statement: str
    as_of_date: str
    supporting_fact_ids: tuple[str, ...]
    counterevidence_fact_ids: tuple[str, ...]
    counterevidence_search_note: str | None
    confidence: str
    falsification_condition: str


@dataclass(frozen=True, slots=True)
class Assumption(Contract):
    SCHEMA_NAME: ClassVar[str] = "assumption"
    schema_version: str
    assumption_id: str
    issuer_id: str
    concept: str
    value_type: str
    value: Scalar
    unit: str | None
    currency: str | None
    horizon: FrozenMap
    scenario: str
    rationale: str
    supporting_fact_ids: tuple[str, ...]
    supporting_claim_ids: tuple[str, ...]
    confidence: str


@dataclass(frozen=True, slots=True)
class CalculationResult(Contract):
    SCHEMA_NAME: ClassVar[str] = "calculation-result"
    schema_version: str
    calculation_id: str
    issuer_id: str
    concept: str
    value_type: str
    value: Scalar
    unit: str | None
    currency: str | None
    period: FrozenMap
    generator: str
    calculator_id: str
    calculator_version: str
    code_sha256: str
    input_fact_ids: tuple[str, ...]
    input_assumption_ids: tuple[str, ...]
    input_calculation_ids: tuple[str, ...]
    input_period_ids: tuple[str, ...]
    input_bindings: FrozenMap
    input_fingerprint: str
    output_fingerprint: str
    generated_at: str


@dataclass(frozen=True, slots=True)
class Score(Contract):
    SCHEMA_NAME: ClassVar[str] = "score"
    schema_version: str
    score_id: str
    issuer_id: str
    extension_label: str
    framework: str
    component: str
    score: float
    max_score: float
    rationale: str
    fact_ids: tuple[str, ...]
    claim_ids: tuple[str, ...]
    calculation_result_ids: tuple[str, ...]
    confidence: str
    missing_evidence: tuple[str, ...]
    red_flags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReportSpec(Contract):
    SCHEMA_NAME: ClassVar[str] = "report-spec"
    schema_version: str
    report_spec_id: str
    language: str
    audience: str
    sections: tuple[FrozenMap, ...]
    output_formats: tuple[str, ...]
    partial_and_blocked_states_required: bool


@dataclass(frozen=True, slots=True)
class RunManifest(Contract):
    SCHEMA_NAME: ClassVar[str] = "run-manifest"
    schema_version: str
    run_id: str
    issuer_id: str
    data_cutoff_date: str
    started_at: str
    completed_at: str | None
    component_lock_sha256: str
    component_versions: FrozenMap
    input_document_hashes: FrozenMap
    output_artifact_hashes: FrozenMap
    missing_evidence: tuple[str, ...]
    anti_anchoring: FrozenMap


@dataclass(frozen=True, slots=True)
class ResearchBundle(Contract):
    SCHEMA_NAME: ClassVar[str] = "research-bundle"
    schema_version: str
    bundle_id: str
    issuer_id: str
    data_cutoff_date: str
    bundle_policy_id: str
    bundle_policy_version: str
    status: str
    module_references: tuple[FrozenMap, ...]
    source_document_ids: tuple[str, ...]
    fiscal_period_ids: tuple[str, ...]
    segment_definition_ids: tuple[str, ...]
    source_graph_sha256: str
    dependency_closure_sha256: str
    component_lock_sha256: str
    bundle_fingerprint: str
    run_id: str
    missing_evidence: tuple[str, ...]

    @property
    def fingerprint(self) -> str:
        return self.bundle_fingerprint


@dataclass(frozen=True, slots=True)
class ValuationAssumptionCandidate(Contract):
    SCHEMA_NAME: ClassVar[str] = "valuation-assumption-candidate"
    schema_version: str
    candidate_id: str
    issuer_id: str
    data_cutoff_date: str
    candidate_policy_id: str
    candidate_policy_version: str
    research_bundle_id: str
    research_bundle_fingerprint: str
    research_bundle_dependency_sha256: str
    supplemental_reference_closure_sha256: str
    assumption_slot_id: str
    method_scope: str
    kernel_concept: str
    value: float | int
    unit: str
    currency: str | None
    horizon: FrozenMap
    scenario: str | None
    rationale: str
    evidence_bindings: tuple[FrozenMap, ...]
    generation_method: str
    evidence_graph_sha256: str
    validation_status: str
    validation_issues: tuple[str, ...]

    def __post_init__(self) -> None:
        Contract.__post_init__(self)
        validate_unit_currency(self.unit, self.currency)


@dataclass(frozen=True, slots=True)
class ValuationAssumptionReviewDecision(Contract):
    SCHEMA_NAME: ClassVar[str] = "valuation-assumption-review-decision"
    schema_version: str
    decision_id: str
    issuer_id: str
    candidate_id: str
    candidate_fingerprint: str
    evidence_graph_sha256: str
    decision: str
    reserved_kernel_assumption_id: str | None
    supersedes_decision_id: str | None
    reviewer_type: str
    reviewer_id: str
    reviewed_at: str
    rationale: str
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MarketReferenceSnapshot(Contract):
    SCHEMA_NAME: ClassVar[str] = "market-reference-snapshot"
    schema_version: str
    snapshot_id: str
    issuer_id: str
    data_cutoff_date: str
    status: str
    market_policy_id: str
    market_policy_version: str
    authorization_handoff_id: str
    authorization_handoff_fingerprint: str
    component_lock_sha256: str
    market_access_result_fingerprint: str
    market_quote_request: FrozenMap
    governed_market_quote_receipt: FrozenMap
    authority_lineage: FrozenMap
    security: FrozenMap
    trading_date: str
    quote_timestamp: str
    quote_retrieved_at: str
    quote_price_decimal: str
    quote_unit: str
    quote_currency: str
    evidence_mode: str
    usage_scope: str
    raw_evidence: FrozenMap
    quote_source_document_id: str
    quote_source_locator: str
    quote_fact_id: str
    share_basis: FrozenMap
    market_equity: FrozenMap
    price_blind_input_fingerprint: str
    protected_mckinsey_sha256: str
    protected_penman_assumptions_sha256: str
    future_kernel_request_v2: FrozenMap
    market_evidence_closure_sha256: str
    snapshot_fingerprint: str

    def __post_init__(self) -> None:
        Contract.__post_init__(self)
        validate_unit_currency(self.quote_unit, self.quote_currency)
        validate_unit_currency(self.share_basis["share_unit"], None)
        validate_unit_currency(self.market_equity["unit"], self.market_equity["currency"])
        _positive_market_decimal(self.quote_price_decimal, "quote price")
        _positive_market_decimal(
            self.share_basis["current_common_shares_outstanding_decimal"],
            "current common shares outstanding",
        )
        if self.share_basis["split_factor_decimal"] != "1":
            raise ValueError("v0.5 alpha requires split factor one")
        _positive_market_decimal(self.market_equity["value_decimal"], "market equity")
        if (
            self.future_kernel_request_v2["share_denominator_fact_id"]
            != self.share_basis["shares_outstanding_fact_id"]
            or self.future_kernel_request_v2["share_denominator_evidence_kind"]
            != self.share_basis["evidence_kind"]
        ):
            raise ValueError("future kernel request-v2 witness does not match current shares")
        payload = self.to_dict()
        fingerprint = payload.pop("snapshot_fingerprint")
        if fingerprint != canonical_sha256(payload):
            raise ValueError("MarketReferenceSnapshot fingerprint mismatch")

    @property
    def fingerprint(self) -> str:
        return self.snapshot_fingerprint


@dataclass(frozen=True, slots=True)
class ValuationHandoff(Contract):
    SCHEMA_NAME: ClassVar[str] = "valuation-handoff"
    schema_version: str
    handoff_id: str
    handoff_policy_id: str
    handoff_policy_version: str
    handoff_run_id: str
    handoff_version: int
    transitioned_at: str
    issuer_id: str
    data_cutoff_date: str
    state: str
    predecessor_handoff_id: str | None
    supersedes_handoff_id: str | None
    research_bundle_id: str
    research_bundle_fingerprint: str
    research_bundle_dependency_sha256: str
    research_run_manifest_id: str
    supplemental_reference_closure_sha256: str
    mapping_policy_id: str
    mapping_policy_version: str
    assumption_slot_policy_id: str
    assumption_slot_policy_version: str
    assumption_slot_policy_sha256: str
    assumption_evidence_policy_id: str
    assumption_evidence_policy_version: str
    assumption_evidence_policy_sha256: str
    price_blind_freeze_policy_id: str
    price_blind_freeze_policy_version: str
    price_blind_freeze_policy_sha256: str
    component_lock_sha256: str
    kernel_identity: FrozenMap
    assumption_candidate_ids: tuple[str, ...]
    assumption_review_decision_ids: tuple[str, ...]
    price_blind_input_fingerprint: str | None
    protected_mckinsey_sha256: str | None
    protected_penman_assumptions_sha256: str | None
    market_reference_snapshot_id: str | None
    valuation_request_sha256: str | None
    valuation_result_sha256: str | None
    quarantined_market_reference_snapshot_ids: tuple[str, ...]
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FiscalPeriod(Contract):
    SCHEMA_NAME: ClassVar[str] = "fiscal-period"
    schema_version: str
    period_id: str
    issuer_id: str
    fiscal_year: int
    fiscal_quarter: int
    calendar_type: str
    quarter_start: str
    quarter_end: str
    cumulative_start: str
    cumulative_end: str
    ttm_start: str
    weeks: int
    comparative_period_id: str | None
    restatement_version: int
    status: str
    source_document_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class QuarterlyReconciliation(Contract):
    SCHEMA_NAME: ClassVar[str] = "quarterly-reconciliation"
    schema_version: str
    reconciliation_id: str
    issuer_id: str
    period_id: str
    basis: str
    concept: str
    candidate_fact_ids: tuple[str, ...]
    authoritative_fact_id: str | None
    delta_calculation_id: str | None
    tolerance: float
    status: str
    selection_rule: str
    blocked: bool
    notes: str


@dataclass(frozen=True, slots=True)
class QuarterlyUpdate(Contract):
    SCHEMA_NAME: ClassVar[str] = "quarterly-update"
    schema_version: str
    update_id: str
    issuer_id: str
    as_of_date: str
    current_period_id: str
    comparison_period_id: str
    status: str
    comparability: FrozenMap
    fact_ids: tuple[str, ...]
    calculation_result_ids: tuple[str, ...]
    reconciliation_ids: tuple[str, ...]
    what_changed_claim_ids: tuple[str, ...]
    why_it_changed_claim_ids: tuple[str, ...]
    temporary_or_structural_claim_ids: tuple[str, ...]
    guidance_change_claim_ids: tuple[str, ...]
    long_term_thesis_impact_claim_ids: tuple[str, ...]
    impact_on_valuation_assumptions_claim_ids: tuple[str, ...]
    valuation_assumption_review_required: bool
    confidence: str
    missing_evidence: tuple[str, ...]
    red_flags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FilingArtifact(Contract):
    SCHEMA_NAME: ClassVar[str] = "filing-artifact"
    schema_version: str
    artifact_id: str
    issuer_id: str
    source_document_id: str
    cik: str
    accession: str
    form: str
    filing_date: str
    report_period: str
    primary_document: str
    source_url: str
    raw_sha256: str
    normalized_sha256: str
    parser_id: str
    parser_version: str
    retrieved_at: str


@dataclass(frozen=True, slots=True)
class ExtractionCandidate(Contract):
    SCHEMA_NAME: ClassVar[str] = "extraction-candidate"
    schema_version: str
    candidate_id: str
    issuer_id: str
    source_document_id: str
    artifact_id: str
    candidate_kind: str
    concept: str
    value_type: str
    value: Scalar
    unit: str | None
    currency: str | None
    period: FrozenMap
    dimensions: FrozenMap
    locator: FrozenMap
    extraction_method: str
    extractor_id: str
    extractor_version: str
    validation_status: str
    validation_issues: tuple[str, ...]
    high_impact: bool


@dataclass(frozen=True, slots=True)
class EvidencePromotion(Contract):
    SCHEMA_NAME: ClassVar[str] = "evidence-promotion"
    schema_version: str
    promotion_id: str
    issuer_id: str
    candidate_id: str
    candidate_fingerprint: str
    decision: str
    output_fact_id: str | None
    output_claim_id: str | None
    approval_kind: str
    policy_id: str
    policy_version: str
    checks: FrozenMap
    reviewed_at: str
    reviewer_id: str | None
    rationale: str
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SegmentDefinition(Contract):
    SCHEMA_NAME: ClassVar[str] = "segment-definition"
    schema_version: str
    segment_id: str
    issuer_id: str
    disclosed_name: str
    normalized_name: str
    segment_type: str
    effective_period: FrozenMap
    source_document_ids: tuple[str, ...]
    predecessor_segment_ids: tuple[str, ...]
    mapping_status: str
    mapping_claim_id: str | None


@dataclass(frozen=True, slots=True)
class SegmentSnapshot(Contract):
    SCHEMA_NAME: ClassVar[str] = "segment-snapshot"
    schema_version: str
    snapshot_id: str
    issuer_id: str
    fiscal_period_id: str
    status: str
    segment_definition_ids: tuple[str, ...]
    metric_assignments: tuple[FrozenMap, ...]
    consolidated_fact_ids: tuple[str, ...]
    reconciliation_calculation_ids: tuple[str, ...]
    display_precision: FrozenMap
    comparability_claim_ids: tuple[str, ...]
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FootnoteReview(Contract):
    SCHEMA_NAME: ClassVar[str] = "footnote-review"
    schema_version: str
    review_id: str
    issuer_id: str
    fiscal_period_id: str
    topic_code: str
    dynamic_topic_label: str | None
    status: str
    source_document_ids: tuple[str, ...]
    candidate_ids: tuple[str, ...]
    fact_ids: tuple[str, ...]
    claim_ids: tuple[str, ...]
    calculation_result_ids: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    counterevidence_search_note: str


@dataclass(frozen=True, slots=True)
class AccountingQualityFinding(Contract):
    SCHEMA_NAME: ClassVar[str] = "accounting-quality-finding"
    schema_version: str
    finding_id: str
    issuer_id: str
    rule_id: str
    rule_version: str
    category: str
    suggested_severity: str
    final_severity: str
    classification: str
    status: str
    fact_ids: tuple[str, ...]
    calculation_result_ids: tuple[str, ...]
    claim_ids: tuple[str, ...]
    override_claim_id: str | None
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AccountingQualityReview(Contract):
    SCHEMA_NAME: ClassVar[str] = "accounting-quality-review"
    schema_version: str
    review_id: str
    issuer_id: str
    fiscal_period_id: str
    status: str
    rule_set_version: str
    required_topic_codes: tuple[str, ...]
    footnote_review_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]
    coverage: FrozenMap
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ContextObservation(Contract):
    SCHEMA_NAME: ClassVar[str] = "context-observation"
    schema_version: str
    observation_id: str
    target_issuer_id: str
    subject: FrozenMap
    as_of_date: str
    scope: FrozenMap
    observation_type: str
    statement: str
    value_type: str
    value: Scalar
    unit: str | None
    currency: str | None
    period: FrozenMap
    source_document_id: str
    source_locator: str
    extraction_method: str
    verification_status: str
    reviewer_id: str | None
    reviewed_at: str | None
    confidence: str
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        Contract.__post_init__(self)
        if self.value_type == "number":
            validate_unit_currency(self.unit, self.currency)


@dataclass(frozen=True, slots=True)
class CompetitiveContextSnapshot(Contract):
    SCHEMA_NAME: ClassVar[str] = "competitive-context-snapshot"
    schema_version: str
    context_snapshot_id: str
    issuer_id: str
    as_of_date: str
    status: str
    scope: FrozenMap
    source_document_ids: tuple[str, ...]
    observation_ids: tuple[str, ...]
    competitor_selection_claim_ids: tuple[str, ...]
    coverage: tuple[FrozenMap, ...]
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AnalyticalClaimCandidate(Contract):
    SCHEMA_NAME: ClassVar[str] = "analytical-claim-candidate"
    schema_version: str
    candidate_id: str
    issuer_id: str
    as_of_date: str
    proposed_statement: str
    scope: FrozenMap
    claim_role: str
    business_attribute_role: str | None
    business_component_type: str | None
    supporting_evidence_bindings: tuple[FrozenMap, ...]
    counterevidence_bindings: tuple[FrozenMap, ...]
    counterevidence_search_note: str
    proposed_confidence: str
    falsification_condition: str
    generation_method: str
    evidence_graph_sha256: str
    validation_status: str
    validation_issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AnalyticalClaimReviewDecision(Contract):
    SCHEMA_NAME: ClassVar[str] = "analytical-claim-review-decision"
    schema_version: str
    decision_id: str
    issuer_id: str
    candidate_id: str
    candidate_fingerprint: str
    evidence_graph_sha256: str
    decision: str
    output_claim_id: str | None
    reviewer_id: str
    reviewed_at: str
    rationale: str
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BusinessModelSnapshot(Contract):
    SCHEMA_NAME: ClassVar[str] = "business-model-snapshot"
    schema_version: str
    snapshot_id: str
    issuer_id: str
    as_of_date: str
    status: str
    source_document_ids: tuple[str, ...]
    segment_snapshot_ids: tuple[str, ...]
    material_scopes: tuple[FrozenMap, ...]
    components: tuple[FrozenMap, ...]
    component_coverage: tuple[FrozenMap, ...]
    shared_scope_relations: tuple[FrozenMap, ...]
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CompetitiveAdvantageHypothesis(Contract):
    SCHEMA_NAME: ClassVar[str] = "competitive-advantage-hypothesis"
    schema_version: str
    hypothesis_id: str
    issuer_id: str
    as_of_date: str
    assessment_period: FrozenMap
    mechanism: str
    mechanism_policy_id: str
    mechanism_policy_version: str
    scope: FrozenMap
    status: str
    business_model_snapshot_id: str
    competitive_context_snapshot_id: str
    hypothesis_claim_id: str | None
    durability_claim_id: str | None
    reinvestment_claim_id: str | None
    counterevidence_claim_ids: tuple[str, ...]
    claim_review_decision_ids: tuple[str, ...]
    evidence_bindings: tuple[FrozenMap, ...]
    counterevidence_resolutions: tuple[FrozenMap, ...]
    reinvestment_relevance: str
    predecessor_hypothesis_id: str | None
    trend: str
    trend_claim_id: str | None
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BusinessQualityReview(Contract):
    SCHEMA_NAME: ClassVar[str] = "business-quality-review"
    schema_version: str
    review_id: str
    issuer_id: str
    review_period: FrozenMap
    as_of_date: str
    status: str
    business_model_snapshot_id: str
    competitive_context_snapshot_id: str
    hypothesis_ids: tuple[str, ...]
    mechanism_coverage: tuple[FrozenMap, ...]
    claim_ids: tuple[str, ...]
    analytical_claim_review_decision_ids: tuple[str, ...]
    context_observation_ids: tuple[str, ...]
    calculation_result_ids: tuple[str, ...]
    coverage: FrozenMap
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ManagementStatement(Contract):
    SCHEMA_NAME: ClassVar[str] = "management-statement"
    schema_version: str
    statement_id: str
    issuer_id: str
    speaker_name: str
    speaker_role: str
    statement_date: str
    statement_type: str
    kpi_concept: str | None
    definition_change: str
    source_document_id: str
    source_locator: str
    statement_text: str
    statement_sha256: str
    extraction_method: str
    verification_status: str
    reviewer_id: str | None
    reviewed_at: str | None
    lifecycle_status: str
    predecessor_statement_ids: tuple[str, ...]
    kpi_definition_fact_ids: tuple[str, ...]
    commitment_eligibility: str
    metric_bindings: tuple[FrozenMap, ...]
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ManagementStatementCandidate(Contract):
    SCHEMA_NAME: ClassVar[str] = "management-statement-candidate"
    schema_version: str
    candidate_id: str
    issuer_id: str
    source_document_id: str
    source_locator: str
    excerpt_sha256: str
    statement_text: str
    statement_sha256: str
    speaker_name: str
    speaker_role: str
    statement_date: str
    statement_type: str
    kpi_concept: str | None
    extraction_method: str
    metric_mentions: tuple[FrozenMap, ...]
    validation_status: str
    validation_issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ManagementStatementReviewDecision(Contract):
    SCHEMA_NAME: ClassVar[str] = "management-statement-review-decision"
    schema_version: str
    decision_id: str
    issuer_id: str
    candidate_id: str
    candidate_fingerprint: str
    decision: str
    output_statement_id: str | None
    output_fact_ids: tuple[str, ...]
    reviewer_id: str
    reviewed_at: str
    rationale: str
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ManagementCommitment(Contract):
    SCHEMA_NAME: ClassVar[str] = "management-commitment"
    schema_version: str
    commitment_id: str
    issuer_id: str
    statement_id: str
    commitment_type: str
    commitment_strength: str
    metric_concept: str
    baseline_bindings: tuple[FrozenMap, ...]
    target_bindings: tuple[FrozenMap, ...]
    scope: FrozenMap
    measurement_basis: FrozenMap
    comparison_direction: str
    start_date: str
    due_date: str
    evaluation_policy_id: str
    evaluation_policy_version: str
    condition_claim_ids: tuple[str, ...]
    definition_reconciliation_calculation_ids: tuple[str, ...]
    status: str
    withdrawal_statement_id: str | None
    superseded_by_commitment_id: str | None
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ManagementOutcome(Contract):
    SCHEMA_NAME: ClassVar[str] = "management-outcome"
    schema_version: str
    outcome_id: str
    issuer_id: str
    commitment_id: str
    predecessor_outcome_id: str | None
    assessed_at: str
    evaluation_period: FrozenMap
    status: str
    result_bindings: tuple[FrozenMap, ...]
    result_scope: FrozenMap
    result_measurement_basis: FrozenMap
    claim_ids: tuple[str, ...]
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CapitalAllocationEventCandidate(Contract):
    SCHEMA_NAME: ClassVar[str] = "capital-allocation-event-candidate"
    schema_version: str
    candidate_id: str
    issuer_id: str
    as_of_date: str
    source_document_id: str
    source_locator: str
    excerpt_sha256: str
    proposed_event_type: str
    proposed_event_subtype: str
    proposed_scope: FrozenMap
    proposed_identity_components: tuple[FrozenMap, ...]
    proposed_announcement_date: str
    proposed_execution_period: FrozenMap
    proposed_growth_classification: str
    proposed_source_role: str
    proposed_fact_bindings: tuple[FrozenMap, ...]
    proposed_rationale_statement_ids: tuple[str, ...]
    proposed_related_commitment_ids: tuple[str, ...]
    potential_duplicate_candidate_ids: tuple[str, ...]
    supersedes_candidate_ids: tuple[str, ...]
    extraction_method: str
    validation_status: str
    validation_issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CapitalAllocationEventReviewDecision(Contract):
    SCHEMA_NAME: ClassVar[str] = "capital-allocation-event-review-decision"
    schema_version: str
    decision_id: str
    issuer_id: str
    candidate_id: str
    candidate_fingerprint: str
    decision: str
    output_event_id: str | None
    output_economic_event_key: str | None
    supersedes_decision_ids: tuple[str, ...]
    reviewer_id: str
    reviewed_at: str
    rationale: str
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CapitalAllocationEvent(Contract):
    SCHEMA_NAME: ClassVar[str] = "capital-allocation-event"
    schema_version: str
    event_id: str
    issuer_id: str
    event_policy_id: str
    event_policy_version: str
    economic_event_key: str
    event_version: int
    predecessor_event_id: str | None
    supersedes_event_ids: tuple[str, ...]
    event_type: str
    event_subtype: str
    scope: FrozenMap
    identity_components: tuple[FrozenMap, ...]
    announcement_date: str
    execution_period: FrozenMap
    lifecycle_status: str
    source_bindings: tuple[FrozenMap, ...]
    fact_bindings: tuple[FrozenMap, ...]
    claim_bindings: tuple[FrozenMap, ...]
    rationale_statement_ids: tuple[str, ...]
    related_commitment_ids: tuple[str, ...]
    growth_classification: str
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CapitalAllocationOutcome(Contract):
    SCHEMA_NAME: ClassVar[str] = "capital-allocation-outcome"
    schema_version: str
    outcome_id: str
    issuer_id: str
    outcome_policy_id: str
    outcome_policy_version: str
    event_id: str
    predecessor_outcome_id: str | None
    assessed_at: str
    observation_period: FrozenMap
    status: str
    result_bindings: tuple[FrozenMap, ...]
    result_role_coverage: tuple[FrozenMap, ...]
    claim_bindings: tuple[FrozenMap, ...]
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SourceSearchReceipt(Contract):
    SCHEMA_NAME: ClassVar[str] = "source-search-receipt"
    schema_version: str
    receipt_id: str
    issuer_id: str
    source_family: str
    query_scope: FrozenMap
    period: FrozenMap
    cutoff_date: str
    searched_endpoints: tuple[str, ...]
    result_document_ids: tuple[str, ...]
    completed_at: str
    tool_version: str
    request_fingerprint: str
    status: str
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ManagementReview(Contract):
    SCHEMA_NAME: ClassVar[str] = "management-review"
    schema_version: str
    review_id: str
    issuer_id: str
    review_period: FrozenMap
    as_of_date: str
    status: str
    statement_ids: tuple[str, ...]
    commitment_ids: tuple[str, ...]
    outcome_ids: tuple[str, ...]
    coverage: FrozenMap
    claim_ids: tuple[str, ...]
    calculation_result_ids: tuple[str, ...]
    missing_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CapitalAllocationReview(Contract):
    SCHEMA_NAME: ClassVar[str] = "capital-allocation-review"
    schema_version: str
    review_id: str
    issuer_id: str
    review_policy_id: str
    review_policy_version: str
    review_period: FrozenMap
    as_of_date: str
    status: str
    source_coverage: tuple[FrozenMap, ...]
    event_type_coverage: tuple[FrozenMap, ...]
    event_ids: tuple[str, ...]
    outcome_ids: tuple[str, ...]
    coverage: FrozenMap
    claim_bindings: tuple[FrozenMap, ...]
    calculation_result_ids: tuple[str, ...]
    missing_evidence: tuple[str, ...]


CONTRACT_TYPES: dict[str, type[Contract]] = {
    contract_type.SCHEMA_NAME: contract_type
    for contract_type in (
        SourceDocument,
        Fact,
        Claim,
        Assumption,
        CalculationResult,
        Score,
        ReportSpec,
        RunManifest,
        ResearchBundle,
        ValuationAssumptionCandidate,
        ValuationAssumptionReviewDecision,
        MarketReferenceSnapshot,
        ValuationHandoff,
        FiscalPeriod,
        QuarterlyReconciliation,
        QuarterlyUpdate,
        FilingArtifact,
        ExtractionCandidate,
        EvidencePromotion,
        SegmentDefinition,
        SegmentSnapshot,
        FootnoteReview,
        AccountingQualityFinding,
        AccountingQualityReview,
        ContextObservation,
        CompetitiveContextSnapshot,
        AnalyticalClaimCandidate,
        AnalyticalClaimReviewDecision,
        BusinessModelSnapshot,
        CompetitiveAdvantageHypothesis,
        BusinessQualityReview,
        ManagementStatement,
        ManagementStatementCandidate,
        ManagementStatementReviewDecision,
        ManagementCommitment,
        ManagementOutcome,
        CapitalAllocationEventCandidate,
        CapitalAllocationEventReviewDecision,
        CapitalAllocationEvent,
        CapitalAllocationOutcome,
        SourceSearchReceipt,
        ManagementReview,
        CapitalAllocationReview,
    )
}


def contract_from_dict(name: str, payload: dict[str, Any]) -> Contract:
    validate_payload(name, payload)
    contract_type = CONTRACT_TYPES[name]
    field_names = {field.name for field in fields(contract_type)}
    frozen_payload = {key: freeze(value) for key, value in payload.items() if key in field_names}
    return contract_type(**frozen_payload)
