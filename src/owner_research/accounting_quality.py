from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .contracts import (
    AccountingQualityFinding,
    AccountingQualityReview,
    CalculationResult,
    Claim,
    Fact,
    FiscalPeriod,
    FootnoteReview,
)
from .footnotes import REQUIRED_TOPICS, coverage_counts
from .segments import ratio_metric

RULE_SET_VERSION = "1.0.0"


class AccountingQualityError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RuleSpec:
    rule_id: str
    category: str
    concept: str
    watch_threshold: float
    red_flag_threshold: float
    higher_is_worse: bool = True


@dataclass(frozen=True, slots=True)
class RuleSuggestion:
    rule: RuleSpec
    severity: str
    calculation: CalculationResult


RATIO_RULES: dict[str, RuleSpec] = {
    "cash-conversion": RuleSpec(
        "cash-conversion", "cash_conversion", "operating_cash_flow_to_net_income", 0.9, 0.7, False
    ),
    "accruals": RuleSpec("accruals", "accruals", "accrual_ratio", 0.08, 0.15),
    "sbc-dilution": RuleSpec("sbc-dilution", "sbc_dilution", "sbc_to_revenue", 0.05, 0.10),
    "goodwill-intangibles": RuleSpec(
        "goodwill-intangibles", "goodwill_intangibles", "goodwill_intangibles_to_assets", 0.35, 0.60
    ),
    "lease-commitments": RuleSpec(
        "lease-commitments", "lease_commitments", "lease_liabilities_to_assets", 0.20, 0.40
    ),
    "segment-elimination": RuleSpec(
        "segment-elimination", "segment_elimination", "segment_eliminations_to_revenue", 0.05, 0.10
    ),
    "acquisition-reconciliation": RuleSpec(
        "acquisition-reconciliation",
        "acquisition_reconciliation",
        "acquisition_adjustments_to_assets",
        0.05,
        0.10,
    ),
    "tax-anomaly": RuleSpec(
        "tax-anomaly", "tax_anomaly", "effective_tax_rate_deviation", 0.10, 0.20
    ),
    "impairment": RuleSpec("impairment", "impairment", "impairment_to_assets", 0.02, 0.05),
    "restructuring-recurrence": RuleSpec(
        "restructuring-recurrence",
        "restructuring_recurrence",
        "restructuring_period_share",
        0.50,
        0.75,
    ),
    "off-balance-sheet": RuleSpec(
        "off-balance-sheet", "off_balance_sheet", "off_balance_commitments_to_assets", 0.15, 0.30
    ),
}


def _suggest(rule: RuleSpec, value: float) -> str:
    if rule.higher_is_worse:
        if value >= rule.red_flag_threshold:
            return "red_flag"
        if value >= rule.watch_threshold:
            return "watch"
    else:
        if value <= rule.red_flag_threshold:
            return "red_flag"
        if value <= rule.watch_threshold:
            return "watch"
    return "informational"


def evaluate_ratio_rule(
    rule_id: str,
    numerator: Fact,
    denominator: Fact,
    fiscal_period: FiscalPeriod,
    *,
    generated_at: str,
) -> RuleSuggestion:
    try:
        rule = RATIO_RULES[rule_id]
    except KeyError as exc:
        raise AccountingQualityError(f"unknown accounting-quality rule: {rule_id}") from exc
    calculation = ratio_metric(
        numerator,
        denominator,
        fiscal_period,
        concept=rule.concept,
        generated_at=generated_at,
    )
    return RuleSuggestion(rule, _suggest(rule, float(calculation.value)), calculation)


def confirm_finding(
    suggestion: RuleSuggestion,
    *,
    claim: Claim,
    classification: str,
    final_severity: str | None = None,
    status: str = "confirmed",
    missing_evidence: Sequence[str] = (),
) -> AccountingQualityFinding:
    if claim.issuer_id != suggestion.calculation.issuer_id:
        raise AccountingQualityError("finding Claim and calculation issuer mismatch")
    if not claim.supporting_fact_ids:
        raise AccountingQualityError("final finding Claim requires supporting evidence")
    if not set(suggestion.calculation.input_fact_ids).issubset(
        set(claim.supporting_fact_ids)
    ):
        raise AccountingQualityError(
            "finding Claim must support every Fact consumed by the rule calculation"
        )
    if not claim.counterevidence_fact_ids and not (
        claim.counterevidence_search_note and claim.counterevidence_search_note.strip()
    ):
        raise AccountingQualityError("final finding Claim requires counterevidence search")
    if not claim.falsification_condition.strip():
        raise AccountingQualityError("final finding Claim requires a falsification condition")
    resolved_severity = final_severity or suggestion.severity
    override = claim.claim_id if resolved_severity != suggestion.severity else None
    if status == "blocked" and not missing_evidence:
        raise AccountingQualityError("blocked finding requires missing evidence")
    return AccountingQualityFinding(
        schema_version="1.0.0",
        finding_id=f"finding:{claim.issuer_id}:{suggestion.rule.rule_id}:{claim.claim_id.split(':')[-1]}",
        issuer_id=claim.issuer_id,
        rule_id=suggestion.rule.rule_id,
        rule_version=RULE_SET_VERSION,
        category=suggestion.rule.category,
        suggested_severity=suggestion.severity,
        final_severity=resolved_severity,
        classification=classification,
        status=status,
        fact_ids=tuple(suggestion.calculation.input_fact_ids),
        calculation_result_ids=(suggestion.calculation.calculation_id,),
        claim_ids=(claim.claim_id,),
        override_claim_id=override,
        missing_evidence=tuple(missing_evidence),
    )


def blocked_finding(
    *,
    issuer_id: str,
    rule_id: str,
    missing_evidence: Sequence[str],
) -> AccountingQualityFinding:
    if not missing_evidence:
        raise AccountingQualityError("blocked finding requires missing evidence")
    try:
        rule = RATIO_RULES[rule_id]
    except KeyError as exc:
        raise AccountingQualityError(f"unknown accounting-quality rule: {rule_id}") from exc
    return AccountingQualityFinding(
        schema_version="1.0.0",
        finding_id=f"finding:{issuer_id}:{rule_id}:blocked",
        issuer_id=issuer_id,
        rule_id=rule.rule_id,
        rule_version=RULE_SET_VERSION,
        category=rule.category,
        suggested_severity="informational",
        final_severity="informational",
        classification="uncertain",
        status="blocked",
        fact_ids=(),
        calculation_result_ids=(),
        claim_ids=(),
        override_claim_id=None,
        missing_evidence=tuple(missing_evidence),
    )


def build_review(
    *,
    issuer_id: str,
    fiscal_period_id: str,
    reviews: Sequence[FootnoteReview],
    findings: Sequence[AccountingQualityFinding],
    missing_evidence: Sequence[str] = (),
) -> AccountingQualityReview:
    by_topic = {review.topic_code: review for review in reviews if review.topic_code != "dynamic"}
    if set(by_topic) != set(REQUIRED_TOPICS):
        missing = set(REQUIRED_TOPICS).difference(by_topic)
        extra = set(by_topic).difference(REQUIRED_TOPICS)
        raise AccountingQualityError(
            "mandatory footnote coverage mismatch; "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )
    if any(review.issuer_id != issuer_id for review in reviews) or any(
        finding.issuer_id != issuer_id for finding in findings
    ):
        raise AccountingQualityError("accounting-quality review contains another issuer")
    # Dynamic notes are retained in the review but never change the mandatory
    # topic coverage denominator or its counts.
    coverage = coverage_counts(by_topic.values())
    blocked = coverage["blocked_count"]
    status = (
        "blocked"
        if blocked and blocked == len(REQUIRED_TOPICS)
        else ("partial" if blocked or missing_evidence else "complete")
    )
    missing = tuple(missing_evidence)
    if blocked and not missing:
        missing = tuple(
            item
            for review in reviews
            if review.status == "blocked"
            for item in review.missing_evidence
        )
    return AccountingQualityReview(
        schema_version="1.0.0",
        review_id=f"accounting-quality-review:{issuer_id}:{fiscal_period_id}",
        issuer_id=issuer_id,
        fiscal_period_id=fiscal_period_id,
        status=status,
        rule_set_version=RULE_SET_VERSION,
        required_topic_codes=REQUIRED_TOPICS,
        footnote_review_ids=tuple(review.review_id for review in reviews),
        finding_ids=tuple(finding.finding_id for finding in findings),
        coverage=coverage,
        missing_evidence=missing,
    )


def validate_rule_registry() -> None:
    expected = {
        "cash_conversion",
        "accruals",
        "sbc_dilution",
        "restructuring_recurrence",
        "goodwill_intangibles",
        "impairment",
        "tax_anomaly",
        "lease_commitments",
        "acquisition_reconciliation",
        "segment_elimination",
        "off_balance_sheet",
    }
    actual = {rule.category for rule in RATIO_RULES.values()}
    if actual != expected:
        raise AccountingQualityError("accounting-quality rule registry is incomplete")
