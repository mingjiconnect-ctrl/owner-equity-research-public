"""Deterministic Phase 5B company classification and method readiness.

This module consumes a validated, price-blind mapping result. It does not create
Facts, assumptions, routing booleans for callers, valuation requests, or valuation
results, and it never imports or executes the valuation kernel.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .component_lock import file_sha256
from .contracts import (
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    BusinessModelSnapshot,
    Claim,
    Fact,
    ResearchBundle,
)
from .fingerprints import to_json_value
from .research_bundle_validation import dependency_closure
from .validation import ContractGraph, ContractGraphError
from .valuation_fact_mapping_policies import (
    CLASSIFICATION_POLICY_ID,
    CLASSIFICATION_POLICY_VERSION,
    MAPPING_POLICY_ID,
    MAPPING_POLICY_VERSION,
    METHOD_READINESS_ROLES,
    PINNED_FACT_LEDGER_SCHEMA_SHA256,
    READINESS_POLICY_ID,
    READINESS_POLICY_VERSION,
    ROUTING_ASSESSMENT_IDS,
    SEC_SIC_COMPANY_TYPES,
    SEC_SIC_UNSUPPORTED_FINANCIAL_RANGE,
    SPECIALIST_CLASSIFICATION_CLAIMS,
    mapping_policy_sha256,
    readiness_policy_sha256,
)
from .valuation_fact_mapping_types import (
    CompanyClassificationResult,
    FactLedgerMappingResult,
    MethodReadiness,
    ValuationReadinessResult,
)


class ValuationReadinessError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _Classification:
    company_type: str
    specialist_route: str
    research_evidence_ids: tuple[str, ...]
    mapped_fact_ids: tuple[str, ...]
    rationale: str
    reason_codes: tuple[str, ...] = ()


def _bundle_roots(bundle: ResearchBundle) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                identifier
                for reference in bundle.module_references
                for identifier in reference["object_ids"]
            }
        )
    )


def _validated_closure(
    graph: ContractGraph,
    mapping_result: FactLedgerMappingResult,
) -> tuple[ResearchBundle, dict[str, tuple[str, Any]]]:
    try:
        graph.validate()
    except ContractGraphError as exc:
        raise ValuationReadinessError("ContractGraph does not replay") from exc
    matches = [
        item
        for item in graph.research_bundles
        if item.bundle_id == mapping_result.research_bundle_id
    ]
    if len(matches) != 1:
        raise ValuationReadinessError("mapping result requires one bound ResearchBundle")
    bundle = matches[0]
    if (
        bundle.bundle_fingerprint != mapping_result.research_bundle_fingerprint
        or bundle.dependency_closure_sha256 != mapping_result.dependency_closure_sha256
        or bundle.component_lock_sha256 != mapping_result.component_lock_sha256
        or bundle.issuer_id != mapping_result.issuer_id
        or bundle.data_cutoff_date != mapping_result.data_cutoff_date
    ):
        raise ValuationReadinessError("mapping result and ResearchBundle differ")
    if (
        mapping_result.mapping_policy_id != MAPPING_POLICY_ID
        or mapping_result.mapping_policy_version != MAPPING_POLICY_VERSION
        or mapping_result.mapping_policy_sha256 != mapping_policy_sha256()
        or mapping_result.kernel_fact_ledger_schema_sha256
        != PINNED_FACT_LEDGER_SCHEMA_SHA256
    ):
        raise ValuationReadinessError("mapping result policy or kernel Schema drifted")
    if file_sha256(graph.component_lock_path) != mapping_result.component_lock_sha256:
        raise ValuationReadinessError("mapping result component lock drifted")
    ledger = to_json_value(mapping_result.ledger_payload)
    if (
        ledger["entity_id"] != mapping_result.issuer_id
        or ledger["valuation_date"] != mapping_result.data_cutoff_date
    ):
        raise ValuationReadinessError("mapping ledger identity differs from its envelope")
    return bundle, dependency_closure(graph, _bundle_roots(bundle))


def _ledger_facts(mapping_result: FactLedgerMappingResult) -> tuple[dict[str, Any], ...]:
    payload = to_json_value(mapping_result.ledger_payload)
    return tuple(dict(item) for item in payload["facts"])


def _facts_for_concepts(
    ledger_facts: tuple[dict[str, Any], ...], concepts: set[str]
) -> tuple[str, ...]:
    selected: list[dict[str, Any]] = [
        item for item in ledger_facts if item["concept"] in concepts
    ]
    if not selected:
        return ()
    latest_by_concept: dict[str, dict[str, Any]] = {}
    for item in selected:
        key = (item["period_end"] or "", item["as_of_date"], item["fact_id"])
        current = latest_by_concept.get(item["concept"])
        if current is None or key > (
            current["period_end"] or "",
            current["as_of_date"],
            current["fact_id"],
        ):
            latest_by_concept[item["concept"]] = item
    return tuple(sorted(item["fact_id"] for item in latest_by_concept.values()))


def _concepts(ledger_facts: tuple[dict[str, Any], ...]) -> set[str]:
    return {str(item["concept"]) for item in ledger_facts}


def _official_sic(
    *,
    closure: dict[str, tuple[str, Any]],
    issuer_id: str,
    cutoff: str,
) -> tuple[str | None, tuple[str, ...], str | None]:
    documents = {
        identifier: item
        for identifier, (kind, item) in closure.items()
        if kind == "SourceDocument"
    }
    eligible: list[Fact] = []
    for _, (kind, item) in closure.items():
        if kind != "Fact" or item.concept != "sec_sic_code":
            continue
        document = documents.get(item.source_document_id)
        if (
            document is None
            or document.issuer_id != issuer_id
            or document.authority_level != "primary_regulatory"
            or document.published_date > cutoff
            or item.issuer_id != issuer_id
            or item.value_type != "number"
            or item.unit != "count"
            or item.currency is not None
            or item.confidence not in {"high", "medium"}
            or item.period["end"] is None
            or item.period["end"] > cutoff
            or isinstance(item.value, bool)
            or int(item.value) != item.value
        ):
            continue
        eligible.append(item)
    if not eligible:
        return None, (), "official_classification_missing"
    latest_end = max(str(item.period["end"]) for item in eligible)
    current = [item for item in eligible if item.period["end"] == latest_end]
    codes = {int(item.value) for item in current}
    evidence = tuple(sorted(item.fact_id for item in current))
    if len(codes) != 1:
        return None, evidence, "official_classification_conflict"
    code = next(iter(codes))
    for company_type, ranges in SEC_SIC_COMPANY_TYPES.items():
        if any(start <= code <= end for start, end in ranges):
            return company_type, evidence, None
    if SEC_SIC_UNSUPPORTED_FINANCIAL_RANGE[0] <= code <= (
        SEC_SIC_UNSUPPORTED_FINANCIAL_RANGE[1]
    ):
        return None, evidence, "company_classification_unresolved"
    return "nonfinancial_operating_company", evidence, None


def _latest_business_model(
    closure: dict[str, tuple[str, Any]], cutoff: str
) -> BusinessModelSnapshot | None:
    candidates = [
        item
        for _, (kind, item) in closure.items()
        if kind == "BusinessModelSnapshot" and item.as_of_date <= cutoff
    ]
    if not candidates:
        return None
    latest = max(item.as_of_date for item in candidates)
    winners = [item for item in candidates if item.as_of_date == latest]
    return winners[0] if len(winners) == 1 else None


def _reviewed_specialist_claims(
    *,
    closure: dict[str, tuple[str, Any]],
    mapped_fact_ids: set[str],
    cutoff: str,
) -> tuple[tuple[str, str, str, tuple[str, ...]], ...]:
    claims: dict[str, Claim] = {
        identifier: item
        for identifier, (kind, item) in closure.items()
        if kind == "Claim"
    }
    candidates: dict[str, AnalyticalClaimCandidate] = {
        identifier: item
        for identifier, (kind, item) in closure.items()
        if kind == "AnalyticalClaimCandidate"
    }
    decisions: tuple[AnalyticalClaimReviewDecision, ...] = tuple(
        item
        for _, (kind, item) in closure.items()
        if kind == "AnalyticalClaimReviewDecision" and item.decision == "confirmed"
    )
    reviewed: list[tuple[str, str, str, tuple[str, ...]]] = []
    for decision in decisions:
        claim = claims.get(decision.output_claim_id or "")
        candidate = candidates.get(decision.candidate_id)
        if (
            claim is None
            or candidate is None
            or claim.statement not in SPECIALIST_CLASSIFICATION_CLAIMS
            or candidate.claim_role != "support"
            or candidate.scope["scope_type"] != "issuer_wide"
            or candidate.business_attribute_role is not None
            or candidate.business_component_type is not None
            or claim.as_of_date > cutoff
            or not set(claim.supporting_fact_ids).intersection(mapped_fact_ids)
        ):
            continue
        company_type, route = SPECIALIST_CLASSIFICATION_CLAIMS[claim.statement]
        reviewed.append(
            (
                company_type,
                route,
                claim.claim_id,
                tuple(
                    sorted(
                        {
                            candidate.candidate_id,
                            decision.decision_id,
                            claim.claim_id,
                            *claim.supporting_fact_ids,
                        }
                    )
                ),
            )
        )
    return tuple(sorted(reviewed))


def _classification(
    *,
    closure: dict[str, tuple[str, Any]],
    ledger_facts: tuple[dict[str, Any], ...],
    issuer_id: str,
    cutoff: str,
) -> _Classification:
    mapped_ids = {str(item["fact_id"]) for item in ledger_facts}
    context_ids = _facts_for_concepts(
        ledger_facts,
        {
            "revenue",
            "operating_income",
            "net_income",
            "total_assets",
            "common_equity",
            "interest_bearing_debt",
        },
    )
    official_type, official_ids, official_issue = _official_sic(
        closure=closure,
        issuer_id=issuer_id,
        cutoff=cutoff,
    )
    if official_issue is not None:
        return _Classification(
            "unresolved",
            "unresolved",
            official_ids,
            context_ids,
            "Official company classification is missing or conflicting.",
            (official_issue,),
        )
    if official_type in {"bank", "insurer"}:
        return _Classification(
            official_type,
            "financial_institution",
            official_ids,
            context_ids,
            "Current SEC industry identity requires the financial-institution route.",
        )
    business_model = _latest_business_model(closure, cutoff)
    if business_model is None or business_model.status == "blocked":
        return _Classification(
            "unresolved",
            "unresolved",
            official_ids,
            context_ids,
            "Current material business scope is unresolved.",
            ("business_scope_unresolved",),
        )
    segment_scopes = {
        item["scope_id"]
        for item in business_model.material_scopes
        if item["scope"]["scope_type"] == "segment_specific"
    }
    if len(segment_scopes) > 1:
        return _Classification(
            "conglomerate",
            "sum_of_parts",
            tuple(sorted({*official_ids, business_model.snapshot_id})),
            context_ids,
            "Multiple current material reportable-segment scopes require SOTP routing.",
        )
    specialist = _reviewed_specialist_claims(
        closure=closure,
        mapped_fact_ids=mapped_ids,
        cutoff=cutoff,
    )
    if len(specialist) > 1:
        return _Classification(
            "unresolved",
            "unresolved",
            tuple(sorted({*official_ids, *(item for row in specialist for item in row[3])})),
            context_ids,
            "Conflicting reviewed specialist classifications remain unresolved.",
            ("official_classification_conflict",),
        )
    if specialist:
        company_type, route, _, evidence = specialist[0]
        return _Classification(
            company_type,
            route,
            tuple(sorted({*official_ids, *evidence})),
            context_ids,
            "A current human-confirmed specialist classification requires a dedicated route.",
        )
    return _Classification(
        "nonfinancial_operating_company",
        "none",
        tuple(sorted({*official_ids, business_model.snapshot_id})),
        context_ids,
        "Current SEC identity and reviewed material scope support the core nonfinancial route.",
    )


def _role_evidence(
    method: str,
    *,
    ledger_facts: tuple[dict[str, Any], ...],
    closure: dict[str, tuple[str, Any]],
) -> dict[str, tuple[bool, tuple[str, ...], tuple[str, ...]]]:
    present = _concepts(ledger_facts)

    def concepts(*required: str) -> tuple[bool, tuple[str, ...], tuple[str, ...]]:
        missing = tuple(sorted(set(required) - present))
        return (
            not missing,
            _facts_for_concepts(ledger_facts, set(required)),
            missing,
        )

    def any_complete(*alternatives: tuple[str, ...]):
        for alternative in alternatives:
            result = concepts(*alternative)
            if result[0]:
                return result
        required = min(alternatives, key=lambda item: len(set(item) - present))
        return concepts(*required)

    operating_tax = any_complete(
        ("nopat",),
        ("operating_income", "effective_tax_rate"),
        ("operating_income", "pretax_income", "income_tax_expense"),
    )
    balance_roots = any_complete(
        ("total_assets", "total_liabilities", "common_equity"),
        ("total_assets", "total_liabilities", "ending_common_equity"),
    )
    capital_roots = any_complete(
        ("invested_capital",),
        (
            "total_assets",
            "total_liabilities",
            "cash_and_cash_equivalents",
            "interest_bearing_debt",
            "common_equity",
        ),
    )
    noa_roots = any_complete(
        ("net_operating_assets", "net_financial_obligations"),
        (
            "total_assets",
            "total_liabilities",
            "cash_and_cash_equivalents",
            "interest_bearing_debt",
            "common_equity",
        ),
    )
    quality_reviews = [
        item
        for _, (kind, item) in closure.items()
        if kind == "AccountingQualityReview"
    ]
    quality_complete = (
        len(quality_reviews) == 1
        and quality_reviews[0].status == "complete"
        and not quality_reviews[0].missing_evidence
    )
    quality_ids = (
        (quality_reviews[0].review_id,) if len(quality_reviews) == 1 else ()
    )
    roles = {
        "mckinsey": {
            "revenue": concepts("revenue"),
            "operating_profit_and_tax": operating_tax,
            "invested_capital_or_roots": capital_roots,
            "balance_sheet_roots": balance_roots,
            "diluted_shares": concepts("diluted_shares"),
        },
        "penman": {
            "sales": concepts("revenue"),
            "after_tax_operating_profit_roots": operating_tax,
            "noa_nfo_or_roots": noa_roots,
            "near_term_earnings": concepts("net_income"),
            "equity_stock_flow_stock_roots": concepts(
                "beginning_common_equity",
                "ending_common_equity",
                "comprehensive_income",
            ),
            "accounting_quality_coverage": (
                quality_complete,
                (),
                (() if quality_complete else ("accounting_quality_review",)),
            ),
        },
    }
    selected = roles[method]
    return {
        role: (passed, fact_ids, quality_ids if role == "accounting_quality_coverage" else ())
        for role, (passed, fact_ids, _) in selected.items()
    }


def _method_readiness(
    method: str,
    *,
    classification: _Classification,
    ledger_facts: tuple[dict[str, Any], ...],
    closure: dict[str, tuple[str, Any]],
) -> tuple[MethodReadiness, tuple[str, ...]]:
    roles = _role_evidence(method, ledger_facts=ledger_facts, closure=closure)
    satisfied = tuple(sorted(role for role, (ok, _, _) in roles.items() if ok))
    missing = tuple(sorted(set(METHOD_READINESS_ROLES[method]) - set(satisfied)))
    evidence = tuple(
        sorted(
            {
                fact_id
                for ok, fact_ids, _ in roles.values()
                if ok
                for fact_id in fact_ids
            }
        )
    )
    research_evidence = tuple(
        sorted(
            {
                evidence_id
                for ok, _, evidence_ids in roles.values()
                if ok
                for evidence_id in evidence_ids
            }
        )
    )
    if classification.specialist_route == "unresolved":
        status = "blocked"
        reasons = ("company_classification_unresolved", *classification.reason_codes)
    elif classification.specialist_route != "none":
        status = "specialist_required"
        reasons = ("specialist_route_required",)
    elif missing:
        status = "partial"
        reasons = ("required_role_missing",)
        if "accounting_quality_coverage" in missing:
            reasons = (*reasons, "accounting_quality_incomplete")
    else:
        status = "ready"
        reasons = ()
    return (
        MethodReadiness(
            method=method,
            status=status,
            required_roles=METHOD_READINESS_ROLES[method],
            satisfied_roles=satisfied,
            missing_roles=missing,
            evidence_fact_ids=evidence,
            research_evidence_ids=research_evidence,
            reason_codes=tuple(sorted(set(reasons))),
        ),
        research_evidence,
    )


def _assessment(
    *,
    status: str,
    value: bool | None,
    rationale: str,
    research_ids: tuple[str, ...] = (),
    mapped_ids: tuple[str, ...] = (),
    reason_codes: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "status": status,
        "value": value,
        "rationale": rationale,
        "research_evidence_ids": sorted(research_ids),
        "mapped_fact_ids": sorted(mapped_ids),
        "reason_codes": sorted(reason_codes),
    }


def _routing_assessments(
    *,
    classification: _Classification,
    mckinsey: MethodReadiness,
    penman: MethodReadiness,
    ledger_facts: tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    present = _concepts(ledger_facts)
    mapped = tuple(sorted({*mckinsey.evidence_fact_ids, *penman.evidence_fact_ids}))
    separable: tuple[str, bool | None]
    if classification.company_type in {"bank", "insurer", "unresolved"}:
        separable = (
            "blocked" if classification.company_type == "unresolved" else "unsatisfied",
            None if classification.company_type == "unresolved" else False,
        )
    else:
        separable = ("satisfied", True)
    credible_noa = bool(
        {"net_operating_assets", "net_financial_obligations"}.issubset(present)
        or {
            "total_assets",
            "total_liabilities",
            "cash_and_cash_equivalents",
            "interest_bearing_debt",
            "common_equity",
        }.issubset(present)
    )
    credible_earnings = "net_income" in present
    capital_ids = _facts_for_concepts(
        ledger_facts,
        {"interest_bearing_debt", "common_equity", "cash_and_cash_equivalents"},
    )
    capital_dates = {
        item["period_end"]
        for item in ledger_facts
        if item["concept"]
        in {"interest_bearing_debt", "common_equity", "cash_and_cash_equivalents"}
    }
    stable_capital = len(capital_dates) >= 2 and bool(capital_ids)
    return {
        "required_data_complete": _assessment(
            status="unsatisfied",
            value=False,
            rationale=(
                "Phase 5B role coverage does not complete Phase 5C accounting and "
                "equity-bridge controls."
            ),
            research_ids=classification.research_evidence_ids,
            mapped_ids=mapped,
            reason_codes=("phase5c_confirmation_pending",),
        ),
        "stable_capital_structure": _assessment(
            status="satisfied" if stable_capital else "blocked",
            value=True if stable_capital else None,
            rationale=(
                "At least two cutoff-safe capital-structure measurement dates are present."
                if stable_capital
                else "Capital-structure stability lacks two comparable measurement dates."
            ),
            mapped_ids=capital_ids,
            reason_codes=(() if stable_capital else ("phase5c_confirmation_pending",)),
        ),
        "operating_financing_separable": _assessment(
            status=separable[0],
            value=separable[1],
            rationale=(
                "The company route determines whether operating and financing evidence "
                "is separable."
            ),
            research_ids=classification.research_evidence_ids,
            mapped_ids=classification.mapped_fact_ids,
            reason_codes=(
                ("company_classification_unresolved",)
                if separable[0] == "blocked"
                else ()
            ),
        ),
        "credible_noa": _assessment(
            status="satisfied" if credible_noa else "blocked",
            value=True if credible_noa else None,
            rationale=(
                "Mapped NOA/NFO or complete accounting roots are present."
                if credible_noa
                else "Mapped NOA/NFO and complete accounting roots are absent."
            ),
            mapped_ids=_facts_for_concepts(
                ledger_facts,
                {
                    "net_operating_assets",
                    "net_financial_obligations",
                    "total_assets",
                    "total_liabilities",
                    "cash_and_cash_equivalents",
                    "interest_bearing_debt",
                    "common_equity",
                },
            ),
            reason_codes=(() if credible_noa else ("required_role_missing",)),
        ),
        "credible_near_term_earnings": _assessment(
            status="satisfied" if credible_earnings else "blocked",
            value=True if credible_earnings else None,
            rationale=(
                "Mapped near-term earnings evidence is present."
                if credible_earnings
                else "Mapped near-term earnings evidence is absent."
            ),
            mapped_ids=_facts_for_concepts(ledger_facts, {"net_income"}),
            reason_codes=(() if credible_earnings else ("required_role_missing",)),
        ),
        "equity_bridge_complete": _assessment(
            status="blocked",
            value=None,
            rationale="Nine-role equity-bridge review is reserved for Phase 5C.",
            mapped_ids=mapped,
            reason_codes=("phase5c_confirmation_pending",),
        ),
    }


def assess_method_readiness(
    *,
    graph: ContractGraph,
    mapping_result: FactLedgerMappingResult,
) -> ValuationReadinessResult:
    """Recompute company routing and independent price-blind method readiness."""

    bundle, closure = _validated_closure(graph, mapping_result)
    ledger_facts = _ledger_facts(mapping_result)
    classification_data = _classification(
        closure=closure,
        ledger_facts=ledger_facts,
        issuer_id=bundle.issuer_id,
        cutoff=bundle.data_cutoff_date,
    )
    mckinsey, mckinsey_research = _method_readiness(
        "mckinsey",
        classification=classification_data,
        ledger_facts=ledger_facts,
        closure=closure,
    )
    penman, penman_research = _method_readiness(
        "penman",
        classification=classification_data,
        ledger_facts=ledger_facts,
        closure=closure,
    )
    assessments = _routing_assessments(
        classification=classification_data,
        mckinsey=mckinsey,
        penman=penman,
        ledger_facts=ledger_facts,
    )
    if set(assessments) != set(ROUTING_ASSESSMENT_IDS):
        raise ValuationReadinessError("routing assessment registry coverage drifted")
    classification = CompanyClassificationResult(
        policy_id=CLASSIFICATION_POLICY_ID,
        policy_version=CLASSIFICATION_POLICY_VERSION,
        policy_sha256=readiness_policy_sha256(),
        company_type=classification_data.company_type,
        specialist_route=classification_data.specialist_route,
        research_evidence_ids=tuple(
            sorted(
                {
                    *classification_data.research_evidence_ids,
                    *mckinsey_research,
                    *penman_research,
                }
            )
        ),
        mapped_fact_ids=classification_data.mapped_fact_ids,
        routing_assessments=assessments,
        rationale=classification_data.rationale,
    )
    return ValuationReadinessResult(
        issuer_id=bundle.issuer_id,
        data_cutoff_date=bundle.data_cutoff_date,
        mapping_result_fingerprint=mapping_result.fingerprint,
        readiness_policy_id=READINESS_POLICY_ID,
        readiness_policy_version=READINESS_POLICY_VERSION,
        readiness_policy_sha256=readiness_policy_sha256(),
        classification=classification,
        mckinsey=mckinsey,
        penman=penman,
        specialist_route=classification.specialist_route,
    )
