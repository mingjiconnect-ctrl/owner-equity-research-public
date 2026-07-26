from __future__ import annotations

import json
import os
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from tempfile import TemporaryDirectory, gettempdir

import pytest

import owner_research
from owner_research.business_models import BUSINESS_COMPONENT_TYPES
from owner_research.business_quality_reviews import build_business_quality_review
from owner_research.capital_allocation_policies import EVENT_TYPES, SOURCE_FAMILIES
from owner_research.capital_allocation_reviews import build_capital_allocation_review
from owner_research.component_lock import file_sha256
from owner_research.contracts import (
    AccountingQualityFinding,
    AccountingQualityReview,
    AnalyticalClaimCandidate,
    AnalyticalClaimReviewDecision,
    BusinessModelSnapshot,
    CapitalAllocationReview,
    Claim,
    CompetitiveContextSnapshot,
    Fact,
    FiscalPeriod,
    FootnoteReview,
    RunManifest,
    SourceDocument,
)
from owner_research.fingerprints import canonical_sha256, to_json_value
from owner_research.footnotes import REQUIRED_TOPICS
from owner_research.research_bundle_artifacts import write_research_bundle_artifacts
from owner_research.research_bundle_builder import ResearchBundleBuildResult, build_research_bundle
from owner_research.schema_store import SCHEMA_NAMES
from owner_research.source_search_receipts import build_source_search_receipt
from owner_research.validation import CONTEXT_TOPICS, ContractGraph
from owner_research.valuation_accounting_policies import (
    ACCOUNT_CONCEPT_POLICIES,
    ACCOUNT_ROLES,
    ACCOUNTING_FORMULA_DERIVATIONS,
    BRIDGE_AGGREGATE_DERIVATIONS,
    BRIDGE_ROLE_POLICIES,
    BRIDGE_ROLES,
    BRIDGE_STATES,
    COMMON_EQUITY_ALIAS_DERIVATIONS,
    CROSS_CHANNEL_POLICIES,
    FORMULA_POLICIES,
    KERNEL_FORBIDDEN_SURFACES,
    KERNEL_METHOD_VIEW_TARGET_ALLOWLIST,
    KERNEL_VALIDATION_ALLOWLIST,
    METHOD_ADJUSTMENT_CALCULATOR_POLICY,
    METHOD_ADJUSTMENT_CATEGORIES,
    METHOD_ADJUSTMENT_CATEGORY_POLICIES,
    METHOD_SUCCESSOR_REQUIRED_ROLES,
    METHOD_TARGET_POLICIES,
    OWNER_TRANSACTION_CONCEPTS,
    PERIOD_ALIGNMENT_POLICIES,
    PHASE5C_POLICY_ID,
    PHASE5C_POLICY_VERSION,
    PHASE5C_REASON_CODES,
    QUALITY_MAPPING_POLICIES,
    ROUTING_ASSESSMENT_IDS,
    ROUTING_ASSESSMENT_REQUIRED_EVIDENCE,
    STABLE_CAPITAL_MINIMUM_ANNUAL_SNAPSHOTS,
    account_concept_policy,
    bridge_role_policy,
    method_target_policy,
    phase5c_policy_sha256,
)
from owner_research.valuation_accounting_types import (
    AccountClassificationDecision,
    AccountingFactDecision,
    AccountingQualityCompilationResult,
    AccountingReconciliationResult,
    EquityBridgeCompilationResult,
    EquityBridgeRoleDecision,
    MethodAdjustmentDecision,
    MethodViewCompilationResult,
    Phase5CReadinessResult,
    _economic_claim_key,
    _economic_claim_review_statement,
    _expected_annual_capital_bindings,
    _validate_phase5b_mapping_replay,
    _validate_phase5b_readiness_replay,
    _validate_research_context,
)
from owner_research.valuation_fact_mapping import compile_price_blind_fact_ledger
from owner_research.valuation_fact_mapping_policies import (
    CLASSIFICATION_POLICY_ID,
    CLASSIFICATION_POLICY_VERSION,
    MAPPING_POLICY_ID,
    MAPPING_POLICY_VERSION,
    PINNED_FACT_LEDGER_SCHEMA_SHA256,
    READINESS_POLICY_ID,
    READINESS_POLICY_VERSION,
    mapping_policy_sha256,
    readiness_policy_sha256,
)
from owner_research.valuation_fact_mapping_policies import (
    CONCEPT_POLICIES as PHASE5B_CONCEPT_POLICIES,
)
from owner_research.valuation_fact_mapping_policies import (
    METHOD_READINESS_ROLES as PHASE5B_METHOD_READINESS_ROLES,
)
from owner_research.valuation_fact_mapping_policies import (
    ROUTING_ASSESSMENT_IDS as PHASE5B_ROUTING_ASSESSMENT_IDS,
)
from owner_research.valuation_fact_mapping_types import (
    CompanyClassificationResult,
    FactLedgerMappingResult,
    FactMappingDecision,
    MethodReadiness,
    ValuationReadinessResult,
)
from owner_research.valuation_readiness import assess_method_readiness

ROOT = Path(__file__).parents[1]
KERNEL = Path(
    os.environ.get(
        "OWNER_VALUATION_REPO",
        str(ROOT.parent / "owner-valuation-kernel"),
    )
)


def _identity() -> dict[str, str]:
    return {
        "issuer_id": "issuer:fixture",
        "data_cutoff_date": "2026-07-11",
        "research_bundle_id": "research-bundle:fixture",
        "research_bundle_fingerprint": "a" * 64,
        "dependency_closure_sha256": "b" * 64,
        "component_lock_sha256": "c" * 64,
        "phase5b_mapping_fingerprint": "d" * 64,
        "phase5b_readiness_fingerprint": "e" * 64,
    }


def _calculator_fields(adjustment_id: str) -> dict[str, object]:
    policy = METHOD_ADJUSTMENT_CALCULATOR_POLICY
    return {
        "calculation_id": f"calculation:{adjustment_id}",
        "calculator_id": policy.calculator_id,
        "calculator_version": policy.calculator_version,
        "calculator_code_sha256": policy.calculator_code_sha256,
        "assumption_ids": (),
    }


def _economic_claim_contracts(
    ledger_payload: dict[str, object],
    fact_decisions: tuple[AccountingFactDecision, ...] | None = None,
) -> dict[str, tuple[object, ...]]:
    ledger_facts = {item["fact_id"]: item for item in ledger_payload["facts"]}
    required_roots = {
        root_id
        for decision in (fact_decisions or _fact_decisions())
        if decision.purpose
        in {"invested_capital", "net_operating_assets", "net_financial_obligations"}
        for root_id in decision.root_fact_ids
    }
    if not required_roots.issubset(ledger_facts):
        return {
            "economic_claim_bindings": (),
            "economic_claim_candidates": (),
            "economic_claim_review_decisions": (),
            "economic_claims": (),
        }
    groups: list[tuple[str, ...]] = []
    debt_roots = tuple(
        sorted(
            root_id
            for root_id in required_roots
            if ledger_facts[root_id]["concept"] == "interest_bearing_debt"
        )
    )
    if debt_roots:
        groups.append(debt_roots)
    groups.extend((root_id,) for root_id in sorted(required_roots.difference(debt_roots)))
    bindings: list[dict[str, object]] = []
    candidates: list[AnalyticalClaimCandidate] = []
    decisions: list[AnalyticalClaimReviewDecision] = []
    claims: list[Claim] = []
    for index, roots in enumerate(groups):
        first = ledger_facts[roots[0]]
        concept_policy = ACCOUNT_CONCEPT_POLICIES[first["concept"]]
        economic_identity = concept_policy.bridge_role or "method_base"
        slug = f"economic-{index:02d}"
        identity_kind = (
            "instrument"
            if economic_identity in {"debt", "debt_equivalent", "lease_liability"}
            else "plan"
            if economic_identity in {"option_or_dilution_claim", "unfunded_pension"}
            else "security_class"
            if economic_identity
            in {"preferred_stock", "noncontrolling_interest", "other_senior_claim"}
            else "aggregate_perimeter"
        )
        identity_value = (
            "fixture-debt-instrument"
            if economic_identity == "debt"
            else f"fixture-{economic_identity}-{index:02d}"
        )
        security_class = (
            f"fixture-{economic_identity}-class"
            if identity_kind == "security_class"
            else "common"
            if economic_identity == "option_or_dilution_claim"
            else None
        )
        candidate_id = f"analytical-candidate:{slug}"
        decision_id = f"analytical-decision:{slug}"
        claim_id = f"claim:{slug}"
        binding = {
            "binding_id": f"economic-claim-binding:{slug}",
            "economic_identity": economic_identity,
            "identity_kind": identity_kind,
            "identity_value": identity_value,
            "scope_id": "scope:issuer:fixture:issuer-wide",
            "measurement_end": first["as_of_date"],
            "security_class": security_class,
            "economic_claim_key": _economic_claim_key(
                issuer_id="issuer:fixture",
                identity_kind=identity_kind,
                identity_value=identity_value,
                scope_id="scope:issuer:fixture:issuer-wide",
                measurement_end=first["as_of_date"],
                security_class=security_class,
            ),
            "status": "confirmed",
            "root_fact_ids": list(roots),
            "identity_evidence_fact_ids": list(roots),
            "diluted_share_treatment": "not_applicable",
            "diluted_share_fact_ids": [],
            "candidate_id": candidate_id,
            "review_decision_id": decision_id,
            "claim_id": claim_id,
            "missing_evidence": [],
            "reason_codes": [],
        }
        supporting = tuple(
            {
                "binding_id": f"binding:{slug}:{fact_id}",
                "fact_id": fact_id,
                "calculation_result_id": None,
                "context_observation_id": None,
            }
            for fact_id in roots
        )
        evidence_sha = canonical_sha256(
            {
                "supporting_evidence_bindings": list(supporting),
                "counterevidence_bindings": [],
            }
        )
        statement = _economic_claim_review_statement(binding)
        candidate = AnalyticalClaimCandidate(
            schema_version="2.0.0",
            candidate_id=candidate_id,
            issuer_id="issuer:fixture",
            as_of_date="2026-07-11",
            proposed_statement=statement,
            scope={
                "scope_type": "issuer_wide",
                "segment_definition_ids": [],
                "business_unit": None,
                "product_service": None,
                "geography": None,
                "customer_group": None,
                "channel": None,
            },
            claim_role="support",
            business_attribute_role=None,
            business_component_type=None,
            supporting_evidence_bindings=supporting,
            counterevidence_bindings=(),
            counterevidence_search_note=(
                "Reviewed duplicate disclosures, replacement identities, and share-plan coverage."
            ),
            proposed_confidence="high",
            falsification_condition=(
                "A conflicting formal instrument, plan, or perimeter identity "
                "falsifies this binding."
            ),
            generation_method="manual",
            evidence_graph_sha256=evidence_sha,
            validation_status="ready",
            validation_issues=(),
        )
        claim = Claim(
            schema_version="1.0.0",
            claim_id=claim_id,
            issuer_id="issuer:fixture",
            statement=statement,
            as_of_date=candidate.as_of_date,
            supporting_fact_ids=roots,
            counterevidence_fact_ids=(),
            counterevidence_search_note=candidate.counterevidence_search_note,
            confidence="high",
            falsification_condition=candidate.falsification_condition,
        )
        decision = AnalyticalClaimReviewDecision(
            schema_version="1.0.0",
            decision_id=decision_id,
            issuer_id="issuer:fixture",
            candidate_id=candidate.candidate_id,
            candidate_fingerprint=candidate.fingerprint,
            evidence_graph_sha256=evidence_sha,
            decision="confirmed",
            output_claim_id=claim.claim_id,
            reviewer_id="human:phase5c-economic-identity-reviewer",
            reviewed_at="2026-07-11T00:00:00+00:00",
            rationale="Named human reviewer confirmed the economic identity.",
            issues=(),
        )
        bindings.append(binding)
        candidates.append(candidate)
        decisions.append(decision)
        claims.append(claim)
    return {
        "economic_claim_bindings": tuple(bindings),
        "economic_claim_candidates": tuple(candidates),
        "economic_claim_review_decisions": tuple(decisions),
        "economic_claims": tuple(claims),
    }


def _kernel_fact(
    fact_id: str,
    *,
    concept: str = "fixture_evidence",
    value: float = 1.0,
    category: str = "evidence",
    currency: str | None = "USD",
    unit: str = "USD millions",
    raw: bool = True,
    parent_fact_ids: tuple[str, ...] = (),
    equity_bridge_role: str | None = None,
    period_start: str | None = None,
    period_end: str = "2025-12-31",
    derivation: str | None = None,
) -> dict[str, object]:
    return {
        "fact_id": fact_id,
        "concept": concept,
        "value": value,
        "unit": unit,
        "category": category,
        "source_id": "doc:10k",
        "source_location": f"fixture:{fact_id}",
        "as_of_date": period_end,
        "currency": currency,
        "period_start": period_start,
        "period_end": period_end,
        "confidence": "high",
        "raw": raw,
        "parent_fact_ids": list(parent_fact_ids),
        "derivation": None if raw else derivation or "phase5c-policy-fixture",
        "equity_bridge_role": equity_bridge_role,
    }


def _ledger_payload(facts: tuple[dict[str, object], ...]) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "entity_id": "issuer:fixture",
        "valuation_date": "2026-07-11",
        "reporting_currency": "USD",
        "sources": [
            {
                "source_id": "doc:10k",
                "title": "issuer:fixture 10-K filed 2026-02-01",
                "publisher": "U.S. Securities and Exchange Commission",
                "published_date": "2026-02-01",
                "retrieved_at": "2026-07-11T00:00:00+00:00",
                "locator": f"document_id=doc:10k;content_sha256={'1' * 64}",
                "url": "https://www.sec.gov/Archives/edgar/data/1/fixture10-k.htm",
                "local_path": None,
                "primary": True,
            }
        ],
        "facts": list(facts),
    }


def _phase5b_pair(
    enriched_ledger: dict[str, object],
    *,
    specialist_route: str = "none",
    bundle_identity: dict[str, str] | None = None,
) -> tuple[FactLedgerMappingResult, ValuationReadinessResult]:
    identity = bundle_identity or {
        "research_bundle_id": "research-bundle:fixture",
        "research_bundle_fingerprint": "a" * 64,
        "dependency_closure_sha256": "b" * 64,
        "component_lock_sha256": "c" * 64,
    }
    source = dict(enriched_ledger["sources"][0])
    base_facts = sorted(
        [
            dict(item)
            for item in enriched_ledger["facts"]
            if item["concept"] in PHASE5B_CONCEPT_POLICIES
            and (item["raw"] is True or item["concept"] in {"effective_tax_rate", "nopat"})
        ],
        key=lambda item: item["fact_id"],
    )
    base_ledger = {
        **{
            key: enriched_ledger[key]
            for key in (
                "schema_version",
                "entity_id",
                "valuation_date",
                "reporting_currency",
            )
        },
        "sources": [source],
        "facts": base_facts,
    }
    mapping = FactLedgerMappingResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        research_bundle_id=identity["research_bundle_id"],
        research_bundle_fingerprint=identity["research_bundle_fingerprint"],
        dependency_closure_sha256=identity["dependency_closure_sha256"],
        component_lock_sha256=identity["component_lock_sha256"],
        mapping_policy_id=MAPPING_POLICY_ID,
        mapping_policy_version=MAPPING_POLICY_VERSION,
        mapping_policy_sha256=mapping_policy_sha256(),
        kernel_fact_ledger_schema_sha256=PINNED_FACT_LEDGER_SCHEMA_SHA256,
        ledger_payload=base_ledger,
        decisions=(
            FactMappingDecision(
                object_type="SourceDocument",
                object_id=source["source_id"],
                disposition="mapped",
                reason_codes=(),
                output_id=source["source_id"],
            ),
            *(
                FactMappingDecision(
                    object_type="Fact",
                    object_id=item["fact_id"],
                    disposition="mapped",
                    reason_codes=(),
                    output_id=item["fact_id"],
                )
                for item in base_facts
            ),
        ),
    )
    classification = CompanyClassificationResult(
        policy_id=CLASSIFICATION_POLICY_ID,
        policy_version=CLASSIFICATION_POLICY_VERSION,
        policy_sha256=readiness_policy_sha256(),
        company_type=(
            "bank"
            if specialist_route == "financial_institution"
            else "unresolved"
            if specialist_route == "unresolved"
            else "nonfinancial_operating_company"
        ),
        specialist_route=specialist_route,
        research_evidence_ids=("source-document:fixture",),
        mapped_fact_ids=tuple(sorted(item["fact_id"] for item in base_facts)),
        routing_assessments={
            assessment_id: {
                "status": "unsatisfied",
                "value": False,
                "rationale": "Synthetic Phase 5B routing evidence remains incomplete.",
                "research_evidence_ids": ["source-document:fixture"],
                "mapped_fact_ids": sorted(item["fact_id"] for item in base_facts),
                "reason_codes": [],
            }
            for assessment_id in PHASE5B_ROUTING_ASSESSMENT_IDS
        },
        rationale="Synthetic core-route classification.",
    )
    panel_status = (
        "partial"
        if specialist_route == "none"
        else "blocked"
        if specialist_route == "unresolved"
        else "specialist_required"
    )
    panel_reason = (
        "required_role_missing"
        if panel_status == "partial"
        else "company_classification_unresolved"
        if panel_status == "blocked"
        else "specialist_route_required"
    )
    panels = {
        method: MethodReadiness(
            method=method,
            status=panel_status,
            required_roles=PHASE5B_METHOD_READINESS_ROLES[method],
            satisfied_roles=(),
            missing_roles=PHASE5B_METHOD_READINESS_ROLES[method],
            evidence_fact_ids=tuple(sorted(item["fact_id"] for item in base_facts)),
            research_evidence_ids=("source-document:fixture",),
            reason_codes=(panel_reason,),
        )
        for method in ("mckinsey", "penman")
    }
    readiness = ValuationReadinessResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        mapping_result_fingerprint=mapping.fingerprint,
        readiness_policy_id=READINESS_POLICY_ID,
        readiness_policy_version=READINESS_POLICY_VERSION,
        readiness_policy_sha256=readiness_policy_sha256(),
        classification=classification,
        mckinsey=panels["mckinsey"],
        penman=panels["penman"],
        specialist_route=specialist_route,
    )
    return mapping, readiness


def _check(check_id: str, status: str = "reconciles_independently") -> dict[str, object]:
    policy = PERIOD_ALIGNMENT_POLICIES[check_id]
    role_fact_ids = {
        "balance_sheet": {
            "total_assets": "fact:total-assets",
            "adjusted_total_liabilities": "derived:adjusted_total_liabilities",
            "common_equity": "derived:common_equity",
        },
        "clean_surplus": {
            "beginning_common_equity": "fact:beginning-common-equity",
            "ending_common_equity": "fact:ending-common-equity",
            "comprehensive_income_attributable_to_common": "fact:comprehensive-income",
            "net_distributions_to_owners": "derived:net_distributions_to_owners",
        },
        "noa_nfo_common_equity": {
            "net_operating_assets": "derived:net_operating_assets",
            "net_financial_obligations": "derived:net_financial_obligations",
            "common_equity": "derived:common_equity",
        },
    }[check_id]
    if check_id == "clean_surplus":
        period = {"start": "2025-01-01", "end": "2025-12-31"}
        stock_dates = {
            "beginning_common_equity": "2024-12-31",
            "ending_common_equity": "2025-12-31",
        }
    else:
        period = {"start": None, "end": "2025-12-31"}
        stock_dates = {role: "2025-12-31" for role in policy.stock_roles}
    roots_by_role = {
        "total_assets": ["fact:total-assets"],
        "adjusted_total_liabilities": [
            "fact:total-liabilities",
            "fact:noncontrolling_interest:zero",
            "fact:preferred_stock:zero",
        ],
        "common_equity": ["fact:total-equity"],
        "beginning_common_equity": ["fact:beginning-common-equity-root"],
        "ending_common_equity": ["fact:total-equity"],
        "comprehensive_income_attributable_to_common": ["fact:comprehensive-income"],
        "net_distributions_to_owners": [
            f"fact:{concept}" for concept in OWNER_TRANSACTION_CONCEPTS
        ],
        "net_operating_assets": ["fact:operating-assets", "fact:operating-liabilities"],
        "net_financial_obligations": [
            "fact:debt:current",
            "fact:debt:noncurrent",
            "fact:debt_equivalent:zero",
            "fact:lease_liability:zero",
            "fact:cash:2025",
            "fact:marketable-securities",
            "fact:noncontrolling_interest:zero",
            "fact:nonoperating_asset:zero",
            "fact:option_or_dilution_claim:zero",
            "fact:other_senior_claim:zero",
            "fact:preferred_stock:zero",
            "fact:unfunded_pension:zero",
        ],
    }
    stock_roots = {role: roots_by_role[role] for role in policy.stock_roles}
    all_roots = sorted({root for role in role_fact_ids for root in roots_by_role[role]})
    reason_codes = []
    if status == "reconciles_by_construction":
        reason_codes = [
            "clean_surplus_by_construction"
            if check_id == "clean_surplus"
            else "balance_sheet_by_construction"
        ]
    elif status == "blocked":
        reason_codes = [
            "clean_surplus_reconciliation_failed"
            if check_id == "clean_surplus"
            else "balance_sheet_reconciliation_failed"
        ]
    return {
        "status": status,
        "role_fact_ids": role_fact_ids,
        "fact_ids": sorted(role_fact_ids.values()),
        "root_fact_ids": all_roots,
        "measurement_period": period,
        "stock_measurement_dates": stock_dates,
        "stock_root_fact_ids": stock_roots,
        "currency": "USD",
        "unit": "USD millions",
        "common_equity_perimeter_id": "common-equity-perimeter:fixture",
        "difference": 0.0,
        "tolerance": {
            "balance_sheet": 1.8e-6,
            "clean_surplus": 1.0e-6,
            "noa_nfo_common_equity": 1.5e-6,
        }[check_id],
        "reason_codes": reason_codes,
    }


def _owner_coverage() -> dict[str, object]:
    return {
        concept: {
            "status": "observed",
            "fact_id": f"fact:{concept}",
            "claim_id": None,
            "review_decision_id": None,
            "missing_evidence": [],
            "reason_codes": [],
        }
        for concept in OWNER_TRANSACTION_CONCEPTS
    }


def _fact_decisions() -> tuple[AccountingFactDecision, ...]:
    facts_by_purpose = {
        "common_equity": {
            "total_equity": ("fact:total-equity",),
            "included_non_common_equity_claims": (),
        },
        "adjusted_total_liabilities": {
            "total_liabilities": ("fact:total-liabilities",),
            "equity_classified_non_common_claims": (
                "fact:noncontrolling_interest:zero",
                "fact:preferred_stock:zero",
            ),
        },
        "net_operating_assets": {
            "operating_asset_components": ("fact:operating-assets",),
            "operating_liability_components": ("fact:operating-liabilities",),
        },
        "net_financial_obligations": {
            "financial_obligation_components": (
                "fact:debt:current",
                "fact:debt:noncurrent",
                "fact:debt_equivalent:zero",
                "fact:lease_liability:zero",
                "fact:option_or_dilution_claim:zero",
                "fact:other_senior_claim:zero",
                "fact:unfunded_pension:zero",
            ),
            "nfo_non_common_equity_claims": (
                "fact:noncontrolling_interest:zero",
                "fact:preferred_stock:zero",
            ),
            "financial_asset_components": (
                "fact:marketable-securities",
                "fact:cash:2025",
                "fact:nonoperating_asset:zero",
            ),
        },
        "invested_capital": {
            "net_operating_assets": ("derived:net_operating_assets",),
        },
        "net_distributions_to_owners": {
            "distributions": (
                "fact:common_dividends",
                "fact:common_share_repurchases",
                "fact:other_common_owner_distributions",
            ),
            "contributions": (
                "fact:common_equity_issuance_proceeds",
                "fact:equity_settled_sbc_owner_contribution",
                "fact:other_common_owner_contributions",
            ),
        },
    }
    decisions = []
    for purpose in (
        "common_equity",
        "adjusted_total_liabilities",
        "net_operating_assets",
        "net_financial_obligations",
        "invested_capital",
        "net_distributions_to_owners",
    ):
        inputs = tuple(
            fact_id for fact_ids in facts_by_purpose[purpose].values() for fact_id in fact_ids
        )
        roots = (
            ("fact:operating-assets", "fact:operating-liabilities")
            if purpose == "invested_capital"
            else (
                "fact:total-liabilities",
                "fact:noncontrolling_interest:zero",
                "fact:preferred_stock:zero",
            )
            if purpose == "adjusted_total_liabilities"
            else inputs
        )
        term_bindings = tuple(
            {
                "input_role": term.input_role,
                "fact_ids": list(facts_by_purpose[purpose][term.input_role]),
                "inclusion_status": (
                    term.required_inclusion_status
                    if facts_by_purpose[purpose][term.input_role]
                    and term.required_inclusion_status != "not_required"
                    else "none_identified_after_review"
                    if term.required_inclusion_status != "not_required"
                    else "not_required"
                ),
                "claim_id": (
                    f"claim:{purpose}:{term.input_role}"
                    if term.required_inclusion_status != "not_required"
                    else None
                ),
                "review_decision_id": (
                    f"decision:{purpose}:{term.input_role}"
                    if term.required_inclusion_status != "not_required"
                    else None
                ),
                "missing_evidence": [],
                "reason_codes": [],
            }
            for term in FORMULA_POLICIES[purpose].terms
        )
        decisions.append(
            AccountingFactDecision(
                purpose=purpose,
                disposition="emitted",
                output_fact_id=f"derived:{purpose}",
                calculation_id=f"calculation:{purpose}",
                input_fact_ids=inputs,
                root_fact_ids=roots,
                term_bindings=term_bindings,
                lineage_status=(
                    "dependent_inputs" if purpose == "invested_capital" else "independent_inputs"
                ),
                reason_codes=(),
            )
        )
    return tuple(decisions)


def _reconciliation_ledger() -> dict[str, object]:
    raw_facts = (
        ("fact:total-assets", "total_assets", 180.0, "accounting"),
        ("fact:total-equity", "total_equity", 100.0, "accounting"),
        ("fact:beginning-common-equity-root", "common_equity", 90.0, "accounting"),
        ("fact:total-liabilities", "total_liabilities", 80.0, "accounting"),
        ("fact:operating-assets", "operating_assets", 200.0, "operating"),
        ("fact:operating-liabilities", "operating_liabilities", 50.0, "operating"),
        ("fact:debt:current", "interest_bearing_debt", 30.0, "financing"),
        ("fact:debt:noncurrent", "interest_bearing_debt", 30.0, "financing"),
        ("fact:debt_equivalent:zero", "debt_equivalent", 0.0, "financing"),
        ("fact:lease_liability:zero", "operating_lease_liability", 0.0, "financing"),
        ("fact:unfunded_pension:zero", "unfunded_pension", 0.0, "financing"),
        ("fact:preferred_stock:zero", "preferred_stock", 0.0, "financing"),
        (
            "fact:noncontrolling_interest:zero",
            "noncontrolling_interest",
            0.0,
            "financing",
        ),
        (
            "fact:option_or_dilution_claim:zero",
            "option_or_dilution_claim",
            0.0,
            "financing",
        ),
        ("fact:other_senior_claim:zero", "other_senior_claim", 0.0, "financing"),
        (
            "fact:nonoperating_asset:zero",
            "cash_and_nonoperating_investments",
            0.0,
            "nonoperating",
        ),
        ("fact:marketable-securities", "marketable_securities", 10.0, "nonoperating"),
        ("fact:cash:2025", "cash_and_cash_equivalents", 0.0, "nonoperating"),
        ("fact:debt:2024", "interest_bearing_debt", 50.0, "financing"),
        ("fact:cash:2024", "cash_and_cash_equivalents", 8.0, "nonoperating"),
        ("fact:debt:2023", "interest_bearing_debt", 45.0, "financing"),
        ("fact:cash:2023", "cash_and_cash_equivalents", 7.0, "nonoperating"),
        ("fact:common-equity:2023", "common_equity", 82.0, "accounting"),
    )
    facts: dict[str, dict[str, object]] = {
        fact_id: _kernel_fact(
            fact_id,
            concept=concept,
            value=value,
            category=category,
        )
        for fact_id, concept, value, category in raw_facts
    }
    facts["fact:beginning-common-equity-root"]["period_end"] = "2024-12-31"
    facts["fact:beginning-common-equity-root"]["as_of_date"] = "2024-12-31"
    for fact_id, period_end in (
        ("fact:debt:2024", "2024-12-31"),
        ("fact:cash:2024", "2024-12-31"),
        ("fact:debt:2023", "2023-12-31"),
        ("fact:cash:2023", "2023-12-31"),
        ("fact:common-equity:2023", "2023-12-31"),
    ):
        facts[fact_id]["period_end"] = period_end
        facts[fact_id]["as_of_date"] = period_end
    facts["fact:beginning-common-equity"] = _kernel_fact(
        "fact:beginning-common-equity",
        concept="beginning_common_equity",
        value=90.0,
        category="accounting",
        raw=False,
        parent_fact_ids=("fact:beginning-common-equity-root",),
        period_end="2024-12-31",
        derivation=COMMON_EQUITY_ALIAS_DERIVATIONS["beginning_common_equity"],
    )
    facts["fact:ending-common-equity"] = _kernel_fact(
        "fact:ending-common-equity",
        concept="ending_common_equity",
        value=100.0,
        category="accounting",
        raw=False,
        parent_fact_ids=("derived:common_equity",),
        derivation=COMMON_EQUITY_ALIAS_DERIVATIONS["ending_common_equity"],
    )
    facts["fact:comprehensive-income"] = _kernel_fact(
        "fact:comprehensive-income",
        concept="comprehensive_income_attributable_to_common",
        value=10.0,
        category="accounting",
        period_start="2025-01-01",
    )
    facts["fact:diluted-shares"] = _kernel_fact(
        "fact:diluted-shares",
        concept="diluted_shares",
        value=100,
        category="share_count",
        currency=None,
        unit="millions shares",
        period_start="2025-01-01",
    )
    for concept in OWNER_TRANSACTION_CONCEPTS:
        fact_id = f"fact:{concept}"
        facts[fact_id] = _kernel_fact(
            fact_id,
            concept=concept,
            category="accounting",
            period_start="2025-01-01",
        )
    for decision in _fact_decisions():
        input_facts = [facts[fact_id] for fact_id in decision.input_fact_ids]
        binding_by_role = {item["input_role"]: item for item in decision.term_bindings}
        value = sum(
            term.sign
            * sum(
                float(facts[fact_id]["value"])
                for fact_id in binding_by_role[term.input_role]["fact_ids"]
            )
            for term in FORMULA_POLICIES[decision.purpose].terms
        )
        period_start = input_facts[0]["period_start"]
        output_concept = FORMULA_POLICIES[decision.purpose].output_concept
        facts[decision.output_fact_id] = _kernel_fact(
            decision.output_fact_id,
            concept=output_concept,
            value=value,
            category=ACCOUNT_CONCEPT_POLICIES[output_concept].kernel_category,
            raw=False,
            parent_fact_ids=decision.input_fact_ids,
            period_start=period_start,
            derivation=ACCOUNTING_FORMULA_DERIVATIONS[decision.purpose],
        )
    for check_id in PERIOD_ALIGNMENT_POLICIES:
        check = _check(check_id)
        for fact_id in (*check["fact_ids"], *check["root_fact_ids"]):
            facts.setdefault(fact_id, _kernel_fact(fact_id))
    return _ledger_payload(tuple(facts.values()))


def _account_decision() -> AccountClassificationDecision:
    return AccountClassificationDecision(
        fact_id="fact:marketable-securities",
        concept="marketable_securities",
        status="classified",
        account_role="financial_asset",
        classification_basis="registered_concept",
        classification_claim_id=None,
        review_decision_id=None,
        aggregation_set_id="financial_asset:fixture",
        aggregation_level="component",
        root_fact_ids=("fact:marketable-securities",),
        reason_codes=(),
        rationale="Registered financial-asset aggregate.",
    )


def _account_decisions(
    ledger_payload: dict[str, object] | None = None,
) -> tuple[AccountClassificationDecision, ...]:
    selected_ledger = ledger_payload or _reconciliation_ledger()
    decisions = []
    for fact in selected_ledger["facts"]:
        policy = ACCOUNT_CONCEPT_POLICIES.get(fact["concept"])
        if (
            fact["raw"] is not True
            or fact["as_of_date"] != "2025-12-31"
            or policy is None
            or policy.period_kind != "stock"
            or (policy.account_role == "unresolved" and not policy.classification_requires_review)
        ):
            continue
        role = (
            policy.account_role
            if policy.account_role != "unresolved"
            else policy.classification_roles[-1]
        )
        perimeter = None
        if fact["concept"] in {
            "noncontrolling_interest",
            "preferred_stock",
            "other_non_common_equity_claim",
        }:
            perimeter = {
                "total_equity": "excluded",
                "reported_liabilities": "excluded",
                "financial_obligations": "excluded",
            }
        decisions.append(
            AccountClassificationDecision(
                fact_id=fact["fact_id"],
                concept=fact["concept"],
                status="classified",
                account_role=role,
                classification_basis=(
                    "reviewed_claim"
                    if policy.classification_requires_review
                    else "registered_concept"
                ),
                classification_claim_id=(
                    f"claim:classification:{fact['fact_id']}"
                    if policy.classification_requires_review
                    else None
                ),
                review_decision_id=(
                    f"decision:classification:{fact['fact_id']}"
                    if policy.classification_requires_review
                    else None
                ),
                aggregation_set_id=(
                    f"{role}:fixture"
                    if role
                    in {
                        "operating_asset",
                        "operating_liability",
                        "financial_asset",
                        "financial_obligation",
                    }
                    else None
                ),
                aggregation_level=(
                    "aggregate"
                    if fact["concept"]
                    in {
                        "operating_assets",
                        "operating_liabilities",
                        "financial_assets",
                        "financial_obligations",
                    }
                    else "component"
                    if role
                    in {
                        "operating_asset",
                        "operating_liability",
                        "financial_asset",
                        "financial_obligation",
                    }
                    else "not_applicable"
                ),
                root_fact_ids=(fact["fact_id"],),
                reason_codes=(),
                rationale=f"Registered {role} aggregate.",
                perimeter_disposition=perimeter,
            )
        )
    return tuple(decisions)


def _reconciliation(
    *,
    ledger_payload: object | None = None,
    account_decisions: tuple[AccountClassificationDecision, ...] | None = None,
    fact_decisions: tuple[AccountingFactDecision, ...] | None = None,
    owner_transaction_coverage: object | None = None,
    checks: object | None = None,
    economic_claim_contracts: dict[str, tuple[object, ...]] | None = None,
    status: str = "pass",
    reason_codes: tuple[str, ...] = (),
    specialist_route: str = "none",
    bundle_identity: dict[str, str] | None = None,
    phase5b_pair: tuple[FactLedgerMappingResult, ValuationReadinessResult] | None = None,
) -> AccountingReconciliationResult:
    selected_ledger = ledger_payload if ledger_payload is not None else _reconciliation_ledger()
    mapping, readiness = (
        phase5b_pair
        if phase5b_pair is not None
        else _phase5b_pair(
            selected_ledger,
            specialist_route=specialist_route,
            bundle_identity=bundle_identity,
        )
    )
    normalized_base_ledger = {
        "schema_version": mapping.ledger_payload["schema_version"],
        "entity_id": mapping.ledger_payload["entity_id"],
        "valuation_date": mapping.ledger_payload["valuation_date"],
        "reporting_currency": mapping.ledger_payload["reporting_currency"],
        "sources": sorted(mapping.ledger_payload["sources"], key=lambda item: item["source_id"]),
        "facts": sorted(mapping.ledger_payload["facts"], key=lambda item: item["fact_id"]),
    }
    base_fact_ids = {item["fact_id"] for item in mapping.ledger_payload["facts"]}
    selected_input_facts = [
        item
        for item in selected_ledger["facts"]
        if item["fact_id"] not in base_fact_ids and item["raw"] is True
    ]
    selected_fact_decisions = fact_decisions if fact_decisions is not None else _fact_decisions()
    return AccountingReconciliationResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        research_bundle_id=mapping.research_bundle_id,
        research_bundle_fingerprint=mapping.research_bundle_fingerprint,
        dependency_closure_sha256=mapping.dependency_closure_sha256,
        component_lock_sha256=mapping.component_lock_sha256,
        phase5b_mapping_fingerprint=mapping.fingerprint,
        phase5b_mapping_result=mapping,
        phase5b_readiness_fingerprint=readiness.fingerprint,
        phase5b_readiness_result=readiness,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        base_ledger_fingerprint=canonical_sha256(normalized_base_ledger),
        selected_input_fact_ids=tuple(sorted(item["fact_id"] for item in selected_input_facts)),
        selected_input_source_ids=tuple(
            sorted({item["source_id"] for item in selected_input_facts})
        ),
        ledger_payload=selected_ledger,
        account_decisions=(
            account_decisions
            if account_decisions is not None
            else _account_decisions(selected_ledger)
        ),
        fact_decisions=selected_fact_decisions,
        **(
            economic_claim_contracts
            if economic_claim_contracts is not None
            else _economic_claim_contracts(selected_ledger, selected_fact_decisions)
        ),
        owner_transaction_coverage=(
            owner_transaction_coverage
            if owner_transaction_coverage is not None
            else _owner_coverage()
        ),
        checks=(
            checks
            if checks is not None
            else {
                "balance_sheet": _check("balance_sheet"),
                "clean_surplus": _check("clean_surplus"),
                "noa_nfo_common_equity": _check("noa_nfo_common_equity"),
            }
        ),
        status=status,
        reason_codes=reason_codes,
    )


def _quality_contracts(
    decisions: tuple[dict[str, object], ...],
    *,
    review_status: str = "complete",
) -> tuple[AccountingQualityReview, tuple[AccountingQualityFinding, ...]]:
    findings = tuple(
        AccountingQualityFinding(
            schema_version="1.0.0",
            finding_id=str(item["finding_id"]),
            issuer_id="issuer:fixture",
            rule_id=f"rule:{item['finding_id']}",
            rule_version="1.0.0",
            category=str(item["category"]),
            suggested_severity=str(item["final_severity"]),
            final_severity=str(item["final_severity"]),
            classification="uncertain",
            status=str(item["finding_status"]),
            fact_ids=tuple(item["evidence_fact_ids"]),
            calculation_result_ids=(),
            claim_ids=(
                (str(item["claim_id"]),)
                if item["claim_id"] is not None
                else (f"claim:{item['finding_id']}",)
                if item["finding_status"] != "blocked"
                else ()
            ),
            override_claim_id=None,
            missing_evidence=(
                (f"missing:{item['finding_id']}",) if item["finding_status"] == "blocked" else ()
            ),
        )
        for item in decisions
    )
    required_topics = tuple(sorted(REQUIRED_TOPICS))
    review = AccountingQualityReview(
        schema_version="1.0.0",
        review_id="accounting-quality-review:fixture",
        issuer_id="issuer:fixture",
        fiscal_period_id="fiscal-period:2025",
        status=review_status,
        rule_set_version="1.0.0",
        required_topic_codes=required_topics,
        footnote_review_ids=tuple(f"footnote:{topic}" for topic in sorted(REQUIRED_TOPICS)),
        finding_ids=tuple(item.finding_id for item in findings),
        coverage={
            "required_count": 15,
            "reviewed_count": 15 if review_status == "complete" else 14,
            "not_disclosed_count": 0,
            "not_applicable_count": 0,
            "blocked_count": 0 if review_status == "complete" else 1,
        },
        missing_evidence=() if review_status == "complete" else ("footnote:blocked",),
    )
    return review, findings


def _quality_result(
    reconciliation: AccountingReconciliationResult | None = None,
    *,
    ledger_payload: object | None = None,
    adjustment_decisions: tuple[MethodAdjustmentDecision, ...] = (),
) -> AccountingQualityCompilationResult:
    selected_reconciliation = reconciliation or _reconciliation()
    decisions = (
        {
            "finding_id": "finding:watch",
            "finding_fingerprint": "placeholder",
            "finding_status": "confirmed",
            "final_severity": "watch",
            "evidence_state": "watch",
            "category": "accruals",
            "disposition": "nonmaterial",
            "material": False,
            "resolved": False,
            "evidence_fact_ids": ["fact:marketable-securities"],
            "claim_id": "claim:watch",
            "review_decision_id": "decision:watch",
            "reason_codes": [],
        },
    )
    review, findings = _quality_contracts(decisions)
    replayed_decisions = ({**decisions[0], "finding_fingerprint": findings[0].fingerprint},)
    return AccountingQualityCompilationResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        reconciliation_fingerprint=selected_reconciliation.fingerprint,
        reconciliation_result=selected_reconciliation,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        accounting_quality_review_id=review.review_id,
        accounting_quality_review_fingerprint=review.fingerprint,
        accounting_quality_review_status=review.status,
        accounting_quality_review=review,
        accounting_quality_findings=findings,
        ledger_payload=(
            ledger_payload if ledger_payload is not None else selected_reconciliation.ledger_payload
        ),
        adjustment_decisions=adjustment_decisions,
        expected_finding_ids=review.finding_ids,
        issue_decisions=replayed_decisions,
        kernel_quality_issues=(
            {
                "issue_id": "finding:watch",
                "category": "accruals",
                "material": False,
                "resolved": False,
                "evidence_fact_ids": ["fact:marketable-securities"],
            },
        ),
        kernel_gate_status="pass",
        **_kernel_quality_compatibility(
            kernel_gate_status="pass",
            status_by_method={"mckinsey": "pass", "penman": "pass"},
        ),
        unresolved_material_issue_ids=(),
        status="pass",
        status_by_method={"mckinsey": "pass", "penman": "pass"},
        missing_evidence=(),
        reason_codes=(),
    )


def _kernel_quality_compatibility(
    *,
    kernel_gate_status: str,
    status_by_method: dict[str, str],
) -> dict[str, object]:
    route_effect = {
        "mckinsey": "not_blocked_by_quality_gate",
        "penman": (
            "blocked_by_quality_gate"
            if kernel_gate_status == "blocked"
            else "not_blocked_by_quality_gate"
        ),
    }
    compatibility = {
        method: (
            (status_by_method[method] == "blocked")
            == (route_effect[method] == "blocked_by_quality_gate")
        )
        for method in ("mckinsey", "penman")
    }
    reasons = {
        "mckinsey": (
            ["pinned_kernel_quality_gate_underblocks_mckinsey"]
            if not compatibility["mckinsey"]
            else []
        ),
        "penman": (
            ["pinned_kernel_global_gate_overblocks_penman"] if not compatibility["penman"] else []
        ),
    }
    return {
        "kernel_gate_scope": "global",
        "kernel_route_effect_by_method": route_effect,
        "kernel_execution_compatibility_by_method": compatibility,
        "kernel_incompatibility_reason_codes": reasons,
    }


def _quality_predecessor_fields(
    reconciliation: AccountingReconciliationResult,
) -> dict[str, object]:
    return {
        "ledger_payload": reconciliation.ledger_payload,
        "adjustment_decisions": (),
        "status_by_method": {"mckinsey": "pass", "penman": "pass"},
    }


def _method_predecessor_fields(
    decisions: tuple[MethodAdjustmentDecision, ...] = (),
) -> dict[str, object]:
    full_ledger = _method_ledger(decisions)
    amount_fact_ids = {
        item.amount_fact_id
        for item in decisions
        if item.disposition == "compiled" and item.amount_fact_id is not None
    }
    reconciliation_ledger = {
        **full_ledger,
        "facts": [item for item in full_ledger["facts"] if item["fact_id"] not in amount_fact_ids],
    }
    reconciliation = _reconciliation(ledger_payload=reconciliation_ledger)
    quality = _quality_result(
        reconciliation,
        ledger_payload=full_ledger,
        adjustment_decisions=decisions,
    )
    return {
        "reconciliation_fingerprint": reconciliation.fingerprint,
        "reconciliation_result": reconciliation,
        "quality_fingerprint": quality.fingerprint,
        "quality_result": quality,
    }


def _role_decisions() -> tuple[EquityBridgeRoleDecision, ...]:
    items = []
    for role in BRIDGE_ROLES:
        if role == "debt":
            items.append(
                EquityBridgeRoleDecision(
                    role=role,
                    status="modeled",
                    fact_id="fact:debt:aggregate",
                    evidence_fact_ids=(
                        "fact:debt:aggregate",
                        "fact:debt:current",
                        "fact:debt:noncurrent",
                    ),
                    root_fact_ids=("fact:debt:current", "fact:debt:noncurrent"),
                    claim_id=None,
                    review_decision_id=None,
                    rationale="Official debt components were aggregated without overlap.",
                    missing_evidence=(),
                    reason_codes=(),
                )
            )
        else:
            items.append(
                EquityBridgeRoleDecision(
                    role=role,
                    status="explicitly_absent",
                    fact_id=None,
                    evidence_fact_ids=(f"fact:{role}:zero",),
                    root_fact_ids=(f"fact:{role}:zero",),
                    claim_id=None,
                    review_decision_id=None,
                    rationale="Official filing reports a numeric zero.",
                    missing_evidence=(),
                    reason_codes=(),
                )
            )
    return tuple(items)


def _bridge_ledger(
    decisions: tuple[EquityBridgeRoleDecision, ...],
) -> dict[str, object]:
    concept_by_role = {
        "nonoperating_asset": "cash_and_nonoperating_investments",
        "debt": "interest_bearing_debt",
        "debt_equivalent": "debt_equivalent",
        "lease_liability": "operating_lease_liability",
        "unfunded_pension": "unfunded_pension",
        "preferred_stock": "preferred_stock",
        "noncontrolling_interest": "noncontrolling_interest",
        "option_or_dilution_claim": "option_or_dilution_claim",
        "other_senior_claim": "other_senior_claim",
    }
    base = _reconciliation_ledger()
    facts: dict[str, dict[str, object]] = {item["fact_id"]: dict(item) for item in base["facts"]}
    facts.update(
        {
            "fact:diluted-shares": _kernel_fact(
                "fact:diluted-shares",
                concept="diluted_shares",
                value=100,
                category="share_count",
                currency=None,
                unit="millions shares",
                period_start="2025-01-01",
            )
        }
    )
    for decision in decisions:
        for fact_id in decision.evidence_fact_ids:
            if decision.status == "modeled" and fact_id == decision.fact_id:
                continue
            facts.setdefault(
                fact_id,
                _kernel_fact(
                    fact_id,
                    concept=concept_by_role[decision.role],
                    value=0,
                    category=bridge_role_policy(decision.role).kernel_category,
                ),
            )
        if decision.status == "modeled":
            for root_id in decision.root_fact_ids:
                facts.setdefault(
                    root_id,
                    _kernel_fact(
                        root_id,
                        concept=concept_by_role[decision.role],
                        value=0,
                        category=bridge_role_policy(decision.role).kernel_category,
                    ),
                )
            facts[decision.fact_id] = _kernel_fact(
                decision.fact_id,
                concept=concept_by_role[decision.role],
                value=sum(float(facts[root_id]["value"]) for root_id in decision.root_fact_ids),
                category=bridge_role_policy(decision.role).kernel_category,
                raw=False,
                parent_fact_ids=decision.root_fact_ids,
                equity_bridge_role=decision.role,
                derivation=BRIDGE_AGGREGATE_DERIVATIONS[decision.role],
            )
    return _ledger_payload(tuple(facts.values()))


def _method_consumption_records(
    reconciliation: AccountingReconciliationResult,
    decisions: tuple[MethodAdjustmentDecision, ...] = (),
) -> tuple[dict[str, object], ...]:
    binding_by_root = {
        root_id: binding
        for binding in reconciliation.economic_claim_bindings
        for root_id in binding["root_fact_ids"]
    }
    facts_by_purpose = {item.purpose: item for item in reconciliation.fact_decisions}
    records: list[dict[str, object]] = []
    for method, channel, group_id, purposes in (
        (
            "mckinsey",
            "mckinsey_invested_capital",
            "method-base:mckinsey:invested-capital",
            ("invested_capital",),
        ),
        (
            "penman",
            "penman_noa_nfo",
            "method-base:penman:noa-nfo",
            ("net_operating_assets", "net_financial_obligations"),
        ),
    ):
        roots = {
            root_id
            for purpose in purposes
            for root_id in facts_by_purpose[purpose].root_fact_ids
        }
        for root_id in sorted(roots):
            binding = binding_by_root[root_id]
            effective_channel = (
                "penman_nfo"
                if method == "penman" and binding["economic_identity"] != "method_base"
                else channel
            )
            records.append(
                {
                    "root_fact_id": root_id,
                    "economic_claim_key": binding["economic_claim_key"],
                    "economic_identity": binding["economic_identity"],
                    "channel": effective_channel,
                    "method": method,
                    "group_id": group_id,
                    "consumption_kind": "method_base",
                }
            )
    for decision in decisions:
        if decision.disposition != "compiled":
            continue
        for root_id in decision.root_fact_ids:
            binding = binding_by_root[root_id]
            identity = binding["economic_identity"]
            channel = (
                "mckinsey_equity_bridge"
                if decision.method == "mckinsey" and identity != "method_base"
                else "mckinsey_invested_capital"
                if decision.method == "mckinsey"
                else "penman_nfo"
                if identity != "method_base"
                else "penman_noa_nfo"
            )
            records.append(
                {
                    "root_fact_id": root_id,
                    "economic_claim_key": binding["economic_claim_key"],
                    "economic_identity": identity,
                    "channel": channel,
                    "method": decision.method,
                    "group_id": decision.adjustment_group_id,
                    "consumption_kind": "economic_deduction",
                }
            )
    return tuple(records)


def _bridge_consumption_records(
    method_view: MethodViewCompilationResult,
    decisions: tuple[EquityBridgeRoleDecision, ...],
) -> tuple[dict[str, object], ...]:
    records = [dict(item) for item in method_view.consumption_records]
    bindings = method_view.reconciliation_result.economic_claim_bindings
    binding_by_root = {
        root_id: binding for binding in bindings for root_id in binding["root_fact_ids"]
    }
    for decision in decisions:
        if decision.status != "modeled":
            continue
        for root_id in decision.root_fact_ids:
            binding = binding_by_root.get(root_id)
            if binding is None:
                continue
            records.append(
                {
                    "root_fact_id": root_id,
                    "economic_claim_key": binding["economic_claim_key"],
                    "economic_identity": binding["economic_identity"],
                    "channel": "mckinsey_equity_bridge",
                    "method": "mckinsey",
                    "group_id": f"equity-bridge:{decision.role}",
                    "consumption_kind": "economic_deduction",
                }
            )
    for binding in bindings:
        if binding["diluted_share_treatment"] != "included":
            continue
        for method in ("mckinsey", "penman"):
            for root_id in binding["root_fact_ids"]:
                records.append(
                    {
                        "root_fact_id": root_id,
                        "economic_claim_key": binding["economic_claim_key"],
                        "economic_identity": binding["economic_identity"],
                        "channel": f"{method}_diluted_shares",
                        "method": method,
                        "group_id": f"diluted-shares:{binding['binding_id']}",
                        "consumption_kind": "economic_deduction",
                    }
                )
    return tuple(records)


def _empty_method_view(
    ledger_payload: object,
    *,
    reconciliation_result: AccountingReconciliationResult | None = None,
    quality_result: AccountingQualityCompilationResult | None = None,
) -> MethodViewCompilationResult:
    reconciliation = reconciliation_result or _reconciliation()
    quality = quality_result or _quality_result(reconciliation)
    return MethodViewCompilationResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        reconciliation_fingerprint=reconciliation.fingerprint,
        reconciliation_result=reconciliation,
        quality_fingerprint=quality.fingerprint,
        quality_result=quality,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        ledger_payload=ledger_payload,
        adjustment_decisions=(),
        method_views={"mckinsey": [], "penman": []},
        consumption_records=_method_consumption_records(reconciliation),
        status_by_method={"mckinsey": "pass", "penman": "pass"},
        reason_codes=(),
    )


def _bridge_result(
    *,
    decisions: tuple[EquityBridgeRoleDecision, ...] | None = None,
    ledger_payload: object | None = None,
    bridge_items: tuple[object, ...] | None = None,
    role_assertions: tuple[object, ...] | None = None,
    diluted_share_roots: tuple[str, ...] = ("fact:diluted-shares",),
    status: str = "complete",
    compatible: bool = True,
    reason_codes: tuple[str, ...] = (),
    method_view_result: MethodViewCompilationResult | None = None,
) -> EquityBridgeCompilationResult:
    selected = decisions if decisions is not None else _role_decisions()
    selected_ledger = ledger_payload if ledger_payload is not None else _bridge_ledger(selected)
    selected_method_view = method_view_result or _empty_method_view(_reconciliation_ledger())
    items = (
        bridge_items
        if bridge_items is not None
        else ({"item_id": "bridge:debt", "fact_id": "fact:debt:aggregate"},)
    )
    assertions = (
        role_assertions
        if role_assertions is not None
        else tuple(
            {
                "role": item.role,
                "status": item.status,
                "fact_id": item.fact_id,
                "source_fact_ids": list(item.evidence_fact_ids),
                "rationale": item.rationale,
            }
            for item in selected
        )
    )
    return EquityBridgeCompilationResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        reconciliation_fingerprint=selected_method_view.reconciliation_fingerprint,
        method_view_fingerprint=selected_method_view.fingerprint,
        method_view_result=selected_method_view,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        ledger_payload=selected_ledger,
        diluted_shares_fact_id="fact:diluted-shares",
        diluted_share_root_fact_ids=diluted_share_roots,
        role_decisions=selected,
        bridge_items=items,
        role_assertions=assertions,
        consumption_records=_bridge_consumption_records(selected_method_view, selected),
        status=status,
        kernel_request_compatible=compatible,
        reason_codes=reason_codes,
    )


def _stable_snapshot_fact_ids() -> tuple[str, ...]:
    return tuple(
        sorted(
            (
                "fact:debt:2023",
                "fact:cash:2023",
                "fact:common-equity:2023",
                "fact:debt:2024",
                "fact:cash:2024",
                "fact:beginning-common-equity-root",
                "fact:debt:current",
                "fact:debt:noncurrent",
                "fact:cash:2025",
                "derived:common_equity",
            )
        )
    )


def _stable_raw_root_ids() -> tuple[str, ...]:
    ledger = {item["fact_id"]: item for item in _reconciliation_ledger()["facts"]}

    def roots(fact_id: str) -> set[str]:
        fact = ledger[fact_id]
        if fact["raw"] is True:
            return {fact_id}
        return {root_id for parent_id in fact["parent_fact_ids"] for root_id in roots(parent_id)}

    return tuple(
        sorted({root_id for fact_id in _stable_snapshot_fact_ids() for root_id in roots(fact_id)})
    )


def _capital_search_objects() -> tuple[tuple[object, ...], CapitalAllocationReview]:
    receipts = tuple(
        build_source_search_receipt(
            issuer_id="issuer:fixture",
            source_family_id=family,
            query_scope={"cik": "0000000001", "event_types": sorted(EVENT_TYPES)},
            period={"start": "2023-01-01", "end": "2026-07-11"},
            cutoff_date="2026-07-11",
            searched_endpoints=(f"https://www.sec.gov/fixture/{family}",),
            result_documents=(),
            completed_at="2026-07-11T12:00:00+00:00",
            tool_version="phase5c-test/1.0.0",
        )
        for family in sorted(SOURCE_FAMILIES)
    )
    review = build_capital_allocation_review(
        issuer_id="issuer:fixture",
        review_period={"start": "2023-01-01", "end": "2026-07-11"},
        as_of_date="2026-07-11",
        source_documents=(),
        source_search_receipts=receipts,
        events=(),
        outcomes=(),
        calculations=(),
    )
    return receipts, review


def _stable_capital_contracts(
    reconciliation: AccountingReconciliationResult | None = None,
) -> dict[str, object]:
    raw_root_ids = _stable_raw_root_ids()
    reviewed_fact_ids = {
        *raw_root_ids,
        *(
            item["fact_id"]
            for item in (
                reconciliation.phase5b_mapping_result.ledger_payload["facts"]
                if reconciliation
                else ()
            )
            if item["raw"] is True
        ),
        *(
            fact_id
            for candidate in (reconciliation.economic_claim_candidates if reconciliation else ())
            for binding in (
                *candidate.supporting_evidence_bindings,
                *candidate.counterevidence_bindings,
            )
            if (fact_id := binding["fact_id"]) is not None
        ),
    }
    footnote = FootnoteReview(
        schema_version="1.0.0",
        review_id="footnote:debt_liquidity_covenants",
        issuer_id="issuer:fixture",
        fiscal_period_id="fiscal-period:2025",
        topic_code="debt_liquidity_covenants",
        dynamic_topic_label=None,
        status="reviewed",
        source_document_ids=("doc:10k",),
        candidate_ids=(),
        fact_ids=tuple(sorted(reviewed_fact_ids)),
        claim_ids=(),
        calculation_result_ids=(),
        missing_evidence=(),
        counterevidence_search_note="Reviewed debt, liquidity, and covenant disclosures.",
    )
    _, allocation_review = _capital_search_objects()
    evidence_bindings = tuple(
        {
            "binding_id": f"binding:{fact_id}",
            "fact_id": fact_id,
            "calculation_result_id": None,
            "context_observation_id": None,
        }
        for fact_id in raw_root_ids
    )
    evidence_graph_sha256 = canonical_sha256(
        {
            "supporting_evidence_bindings": evidence_bindings,
            "counterevidence_bindings": [],
        }
    )
    candidate = AnalyticalClaimCandidate(
        schema_version="2.0.0",
        candidate_id="analytical-candidate:stable-capital",
        issuer_id="issuer:fixture",
        as_of_date="2026-07-11",
        proposed_statement="Capital structure was stable across the reviewed annual periods.",
        scope={
            "scope_type": "issuer_wide",
            "segment_definition_ids": [],
            "business_unit": None,
            "product_service": None,
            "geography": None,
            "customer_group": None,
            "channel": None,
        },
        claim_role="stable",
        business_attribute_role=None,
        business_component_type=None,
        supporting_evidence_bindings=evidence_bindings,
        counterevidence_bindings=(),
        counterevidence_search_note="Reviewed debt, cash, equity, covenants, and capital events.",
        proposed_confidence="high",
        falsification_condition=(
            "A material financing shock or covenant breach would falsify stability."
        ),
        generation_method="manual",
        evidence_graph_sha256=evidence_graph_sha256,
        validation_status="ready",
        validation_issues=(),
    )
    claim = Claim(
        schema_version="1.0.0",
        claim_id="claim:stable-capital",
        issuer_id="issuer:fixture",
        statement=candidate.proposed_statement,
        as_of_date="2026-07-11",
        supporting_fact_ids=raw_root_ids,
        counterevidence_fact_ids=(),
        counterevidence_search_note=candidate.counterevidence_search_note,
        confidence="high",
        falsification_condition=candidate.falsification_condition,
    )
    decision = AnalyticalClaimReviewDecision(
        schema_version="1.0.0",
        decision_id="analytical-decision:stable-capital",
        issuer_id="issuer:fixture",
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=candidate.fingerprint,
        evidence_graph_sha256=candidate.evidence_graph_sha256,
        decision="confirmed",
        output_claim_id=claim.claim_id,
        reviewer_id="human:phase5c-reviewer",
        reviewed_at="2026-07-11T00:00:00+00:00",
        rationale="Named human reviewer confirmed the closed evidence package.",
        issues=(),
    )
    return {
        "stable_capital_footnote_review": footnote,
        "stable_capital_allocation_review": allocation_review,
        "stable_capital_claim": claim,
        "stable_capital_claim_candidate": candidate,
        "stable_capital_claim_review_decision": decision,
    }


def _readiness_predecessor_fields(
    *,
    specialist_route: str = "none",
    bundle_identity: dict[str, str] | None = None,
    phase5b_pair: tuple[FactLedgerMappingResult, ValuationReadinessResult] | None = None,
) -> dict[str, object]:
    reconciliation = _reconciliation(
        specialist_route=specialist_route,
        bundle_identity=bundle_identity,
        phase5b_pair=phase5b_pair,
    )
    quality = _quality_result(reconciliation)
    decisions = _role_decisions()
    ledger = _bridge_ledger(decisions)
    method_view = _empty_method_view(
        reconciliation.ledger_payload,
        reconciliation_result=reconciliation,
        quality_result=quality,
    )
    bridge = _bridge_result(
        decisions=decisions,
        ledger_payload=ledger,
        method_view_result=method_view,
    )
    return {
        "phase5b_mapping_fingerprint": reconciliation.phase5b_mapping_fingerprint,
        "phase5b_readiness_fingerprint": reconciliation.phase5b_readiness_fingerprint,
        "reconciliation_fingerprint": reconciliation.fingerprint,
        "reconciliation_result": reconciliation,
        "quality_fingerprint": quality.fingerprint,
        "quality_result": quality,
        "method_view_fingerprint": method_view.fingerprint,
        "method_view_result": method_view,
        "equity_bridge_fingerprint": bridge.fingerprint,
        "equity_bridge_result": bridge,
        **_stable_capital_contracts(reconciliation),
    }


def _phase5c_research_graph(
    predecessor_fields: dict[str, object],
    *,
    calendar_type: str = "calendar",
) -> ContractGraph:
    reconciliation = predecessor_fields["reconciliation_result"]
    quality = predecessor_fields["quality_result"]
    assert isinstance(reconciliation, AccountingReconciliationResult)
    assert isinstance(quality, AccountingQualityCompilationResult)
    source = SourceDocument(
        schema_version="1.0.0",
        document_id="doc:10k",
        issuer_id="issuer:fixture",
        document_type="10-K",
        period={"start": "2025-01-01", "end": "2025-12-31"},
        published_date="2026-02-01",
        retrieved_at="2026-07-11T00:00:00+00:00",
        source_url="https://www.sec.gov/Archives/edgar/data/1/fixture10-k.htm",
        authority_level="primary_regulatory",
        content_sha256="1" * 64,
    )
    ledger_facts = {item["fact_id"]: item for item in reconciliation.ledger_payload["facts"]}
    stable = _stable_capital_contracts(reconciliation)
    stable_claim = stable["stable_capital_claim"]
    stable_candidate = stable["stable_capital_claim_candidate"]
    stable_decision = stable["stable_capital_claim_review_decision"]
    stable_footnote = stable["stable_capital_footnote_review"]
    allocation_review = stable["stable_capital_allocation_review"]
    assert isinstance(stable_claim, Claim)
    assert isinstance(stable_candidate, AnalyticalClaimCandidate)
    assert isinstance(stable_decision, AnalyticalClaimReviewDecision)
    assert isinstance(stable_footnote, FootnoteReview)
    assert isinstance(allocation_review, CapitalAllocationReview)
    watch_claim = Claim(
        schema_version="1.0.0",
        claim_id="claim:watch",
        issuer_id="issuer:fixture",
        statement="The reviewed accrual indicator is nonmaterial for this fixture.",
        as_of_date="2026-07-11",
        supporting_fact_ids=("fact:marketable-securities",),
        counterevidence_fact_ids=(),
        counterevidence_search_note="Reviewed the current official filing for contrary evidence.",
        confidence="high",
        falsification_condition=(
            "A material unresolved accrual exception falsifies this conclusion."
        ),
    )
    graph_claims = (
        *reconciliation.economic_claims,
        stable_claim,
        watch_claim,
    )
    required_fact_ids = {
        fact_id
        for claim in graph_claims
        for fact_id in (*claim.supporting_fact_ids, *claim.counterevidence_fact_ids)
    } | set(stable_footnote.fact_ids)
    research_fact_rows: list[Fact] = []
    for fact_id in sorted(required_fact_ids):
        ledger_fact = ledger_facts[fact_id]
        if ledger_fact["unit"] == "millions shares":
            research_unit = "shares"
            research_value = float(ledger_fact["value"]) * 1_000_000
            research_currency = None
        elif ledger_fact["unit"] == "decimal":
            research_unit = "ratio"
            research_value = ledger_fact["value"]
            research_currency = None
        else:
            research_unit = "currency_millions"
            research_value = ledger_fact["value"]
            research_currency = "USD"
        research_fact_rows.append(
            Fact(
                schema_version="2.0.0",
                fact_id=fact_id,
                issuer_id="issuer:fixture",
                concept=ledger_fact["concept"],
                value_type="number",
                value=research_value,
                unit=research_unit,
                currency=research_currency,
                period={
                    "start": ledger_fact["period_start"],
                    "end": ledger_fact["period_end"],
                },
                source_document_id="doc:10k",
                source_locator=f"fixture:{fact_id}",
                derivation=None,
                parent_fact_ids=(),
                confidence="high",
            )
        )
    research_facts = tuple(research_fact_rows)
    requested_route = reconciliation.phase5b_readiness_result.specialist_route
    sic_by_route = {
        "none": 7372,
        "financial_institution": 6021,
    }
    sic = sic_by_route.get(requested_route)
    if sic is not None:
        research_facts = (
            *research_facts,
            Fact(
                schema_version="2.0.0",
                fact_id="fact:sec-sic-code",
                issuer_id="issuer:fixture",
                concept="sec_sic_code",
                value_type="number",
                value=sic,
                unit="count",
                currency=None,
                period={"start": None, "end": "2025-12-31"},
                source_document_id="doc:10k",
                source_locator="cover:SEC industrial classification",
                derivation=None,
                parent_fact_ids=(),
                confidence="high",
            ),
        )
    if calendar_type == "52_53_week":
        annual_windows = (
            (2023, "2022-01-30", "2023-01-28", "2022-10-30", 13),
            (2024, "2023-01-29", "2024-02-03", "2023-10-29", 14),
            (2025, "2024-02-04", "2025-02-01", "2024-11-03", 13),
        )
    else:
        annual_windows = (
            (2023, "2023-01-01", "2023-12-31", "2023-10-01", 13),
            (2024, "2024-01-01", "2024-12-31", "2024-10-01", 13),
            (2025, "2025-01-01", "2025-12-31", "2025-10-01", 13),
        )
    periods: list[FiscalPeriod] = []
    for index, (year, start, end, quarter_start, weeks) in enumerate(annual_windows):
        periods.append(
            FiscalPeriod(
                schema_version="1.0.0",
                period_id=f"fiscal-period:{year}",
                issuer_id="issuer:fixture",
                fiscal_year=year,
                fiscal_quarter=4,
                calendar_type=calendar_type,
                quarter_start=quarter_start,
                quarter_end=end,
                cumulative_start=start,
                cumulative_end=end,
                ttm_start=start,
                weeks=weeks,
                comparative_period_id=(None if index == 0 else f"fiscal-period:{year - 1}"),
                restatement_version=0,
                status="reported",
                source_document_ids=("doc:10k",),
            )
        )
    if calendar_type == "52_53_week":
        period_end_by_year = {2023: "2023-01-28", 2024: "2024-02-03", 2025: "2025-02-01"}
        adjusted_facts = []
        source_ledger = {item.fact_id: item for item in research_facts}
        root_years = {
            "fact:debt:2023": 2023,
            "fact:cash:2023": 2023,
            "fact:common-equity:2023": 2023,
            "fact:debt:2024": 2024,
            "fact:cash:2024": 2024,
            "fact:beginning-common-equity-root": 2024,
            "fact:debt:current": 2025,
            "fact:debt:noncurrent": 2025,
            "fact:cash:2025": 2025,
            "fact:total-equity": 2025,
        }
        for fact in research_facts:
            year = root_years.get(fact.fact_id)
            adjusted_facts.append(
                replace(
                    fact,
                    period={"start": None, "end": period_end_by_year[year]},
                )
                if year is not None
                else fact
            )
        research_facts = tuple(adjusted_facts)
        del source_ledger
    generic_footnotes = tuple(
        FootnoteReview(
            schema_version="1.0.0",
            review_id=f"footnote:{topic}",
            issuer_id="issuer:fixture",
            fiscal_period_id="fiscal-period:2025",
            topic_code=topic,
            dynamic_topic_label=None,
            status="reviewed",
            source_document_ids=("doc:10k",),
            candidate_ids=(),
            fact_ids=("fact:marketable-securities",),
            claim_ids=(),
            calculation_result_ids=(),
            missing_evidence=(),
            counterevidence_search_note=f"Reviewed official evidence for {topic}.",
        )
        for topic in sorted(REQUIRED_TOPICS)
        if topic != "debt_liquidity_covenants"
    )
    classification_footnote = (
        FootnoteReview(
            schema_version="1.0.0",
            review_id="footnote:sec-industry-classification",
            issuer_id="issuer:fixture",
            fiscal_period_id="fiscal-period:2025",
            topic_code="dynamic",
            dynamic_topic_label="SEC industry classification",
            status="reviewed",
            source_document_ids=("doc:10k",),
            candidate_ids=(),
            fact_ids=("fact:sec-sic-code",),
            claim_ids=(),
            calculation_result_ids=(),
            missing_evidence=(),
            counterevidence_search_note=(
                "Reviewed the current official filing for the issuer SIC identity."
            ),
        )
        if sic is not None
        else None
    )
    business_scope = {
        "scope_type": "issuer_wide",
        "segment_definition_ids": [],
        "business_unit": None,
        "product_service": None,
        "geography": None,
        "customer_group": None,
        "channel": None,
    }
    business_scope_id = f"business-scope:issuer:fixture:{canonical_sha256(business_scope)[:20]}"
    classification_candidate = None
    classification_claim = None
    classification_decision = None
    classification_component = None
    if sic is not None:
        classification_evidence = (
            {
                "binding_id": "binding:sec-sic-code",
                "fact_id": "fact:sec-sic-code",
                "calculation_result_id": None,
                "context_observation_id": None,
            },
        )
        classification_candidate = AnalyticalClaimCandidate(
            schema_version="2.0.0",
            candidate_id="analytical-candidate:sec-industry-classification",
            issuer_id="issuer:fixture",
            as_of_date="2026-02-01",
            proposed_statement=(f"The current SEC filing identifies the issuer under SIC {sic}."),
            scope=business_scope,
            claim_role="support",
            business_attribute_role="regulatory_dependencies",
            business_component_type="regulatory_dependency",
            supporting_evidence_bindings=classification_evidence,
            counterevidence_bindings=(),
            counterevidence_search_note=(
                "Reviewed the current official filing for conflicting SIC identities."
            ),
            proposed_confidence="high",
            falsification_condition=(
                "A later official filing with a different current SIC identity would "
                "falsify this classification evidence."
            ),
            generation_method="manual",
            evidence_graph_sha256=canonical_sha256(
                {
                    "supporting_evidence_bindings": classification_evidence,
                    "counterevidence_bindings": [],
                }
            ),
            validation_status="ready",
            validation_issues=(),
        )
        classification_claim = Claim(
            schema_version="1.0.0",
            claim_id="claim:sec-industry-classification",
            issuer_id="issuer:fixture",
            statement=classification_candidate.proposed_statement,
            as_of_date="2026-02-01",
            supporting_fact_ids=("fact:sec-sic-code",),
            counterevidence_fact_ids=(),
            counterevidence_search_note=(classification_candidate.counterevidence_search_note),
            confidence="high",
            falsification_condition=classification_candidate.falsification_condition,
        )
        classification_decision = AnalyticalClaimReviewDecision(
            schema_version="1.0.0",
            decision_id="analytical-decision:sec-industry-classification",
            issuer_id="issuer:fixture",
            candidate_id=classification_candidate.candidate_id,
            candidate_fingerprint=classification_candidate.fingerprint,
            evidence_graph_sha256=classification_candidate.evidence_graph_sha256,
            decision="confirmed",
            output_claim_id=classification_claim.claim_id,
            reviewer_id="human:phase5c-classification-reviewer",
            reviewed_at="2026-02-01T00:00:00+00:00",
            rationale="Named human reviewer confirmed the official SIC evidence.",
            issues=(),
        )
        classification_component = {
            "component_id": "component:sec-industry-classification",
            "component_type": "regulatory_dependency",
            "scope_id": business_scope_id,
            "scope": business_scope,
            "attribute_roles": ["regulatory_dependencies"],
            "attribute_evidence_bindings": [
                {
                    "binding_id": "attribute-binding:sec-industry-classification",
                    "role": "regulatory_dependencies",
                    "fact_ids": ["fact:sec-sic-code"],
                    "claim_ids": [classification_claim.claim_id],
                    "review_decision_ids": [classification_decision.decision_id],
                }
            ],
            "fact_ids": ["fact:sec-sic-code"],
            "claim_ids": [classification_claim.claim_id],
        }
    business_model = BusinessModelSnapshot(
        schema_version="3.0.0",
        snapshot_id="business-model:fixture:2025",
        issuer_id="issuer:fixture",
        as_of_date="2026-02-01",
        status="partial",
        source_document_ids=("doc:10k",),
        segment_snapshot_ids=(),
        material_scopes=(
            {
                "scope_id": business_scope_id,
                "scope": business_scope,
                "derivation": "single_reportable_segment",
                "segment_snapshot_id": None,
                "segment_definition_ids": [],
                "materiality_claim_id": None,
            },
        ),
        components=((classification_component,) if classification_component is not None else ()),
        component_coverage=tuple(
            {
                "scope_id": business_scope_id,
                "component_type": component_type,
                "status": (
                    "reviewed"
                    if component_type == "regulatory_dependency"
                    and classification_component is not None
                    else "blocked"
                ),
                "component_ids": (
                    [classification_component["component_id"]]
                    if component_type == "regulatory_dependency"
                    and classification_component is not None
                    else []
                ),
                "claim_ids": [],
                "review_decision_ids": [],
                "missing_evidence": (
                    []
                    if component_type == "regulatory_dependency"
                    and classification_component is not None
                    else [f"{component_type} evidence remains outside this policy fixture."]
                ),
            }
            for component_type in sorted(BUSINESS_COMPONENT_TYPES)
        ),
        shared_scope_relations=(),
        missing_evidence=("Business-model evidence remains partial.",),
    )
    competitive_context = CompetitiveContextSnapshot(
        schema_version="1.0.0",
        context_snapshot_id="competitive-context:fixture:2025",
        issuer_id="issuer:fixture",
        as_of_date="2026-02-01",
        status="blocked",
        scope=business_scope,
        source_document_ids=("doc:10k",),
        observation_ids=(),
        competitor_selection_claim_ids=(),
        coverage=tuple(
            {
                "topic": topic,
                "status": "blocked",
                "observation_ids": [],
                "claim_ids": [],
                "missing_evidence": [f"{topic} context remains outside this policy fixture."],
            }
            for topic in sorted(CONTEXT_TOPICS)
        ),
        missing_evidence=("Competitive context remains blocked.",),
    )
    business_quality_review = build_business_quality_review(
        issuer_id="issuer:fixture",
        review_period={"start": "2025-01-01", "end": "2025-12-31"},
        as_of_date="2026-02-01",
        scope=business_scope,
        business_models=(business_model,),
        competitive_contexts=(competitive_context,),
        hypotheses=(),
        claims=((classification_claim,) if classification_claim is not None else ()),
        analytical_candidates=(
            (classification_candidate,) if classification_candidate is not None else ()
        ),
        claim_review_decisions=(
            (classification_decision,) if classification_decision is not None else ()
        ),
        observations=(),
        calculations=(),
    )
    receipts, rebuilt_allocation = _capital_search_objects()
    assert rebuilt_allocation == allocation_review
    lock_hash = file_sha256(ROOT / "component-lock.json")
    manifest = RunManifest(
        schema_version="1.0.0",
        run_id="run:phase5c-fixture",
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        started_at="2026-07-12T00:00:00+00:00",
        completed_at="2026-07-12T01:00:00+00:00",
        component_lock_sha256=lock_hash,
        component_versions={"owner_research": "0.5.0-dev.3"},
        input_document_hashes={source.document_id: source.content_sha256},
        output_artifact_hashes={},
        missing_evidence=(),
        anti_anchoring={
            "state": "pre_conclusion",
            "conclusion_frozen_at": None,
            "current_conclusion_sha256": None,
            "prior_materials_accessed": [],
        },
    )
    base_graph = ContractGraph(
        documents=(source,),
        facts=research_facts,
        claims=(
            *graph_claims,
            *((classification_claim,) if classification_claim is not None else ()),
        ),
        periods=tuple(periods),
        footnote_reviews=(
            *generic_footnotes,
            *((classification_footnote,) if classification_footnote is not None else ()),
            stable_footnote,
        ),
        accounting_quality_findings=quality.accounting_quality_findings,
        accounting_quality_reviews=(quality.accounting_quality_review,),
        analytical_claim_candidates=(
            *reconciliation.economic_claim_candidates,
            stable_candidate,
            *((classification_candidate,) if classification_candidate is not None else ()),
        ),
        analytical_claim_review_decisions=(
            *reconciliation.economic_claim_review_decisions,
            stable_decision,
            *((classification_decision,) if classification_decision is not None else ()),
        ),
        source_search_receipts=receipts,
        capital_allocation_reviews=(allocation_review,),
        business_model_snapshots=(business_model,),
        competitive_context_snapshots=(competitive_context,),
        business_quality_reviews=(business_quality_review,),
        manifests=(manifest,),
        component_lock_path=ROOT / "component-lock.json",
    )
    build = build_research_bundle(base_graph, run_id=manifest.run_id)
    return replace(
        base_graph,
        manifests=(build.run_manifest,),
        research_bundles=(build.bundle,),
    )


def _compiled_phase5b_pair(
    graph: ContractGraph,
) -> tuple[FactLedgerMappingResult, ValuationReadinessResult]:
    result = ResearchBundleBuildResult(
        bundle=graph.research_bundles[0],
        run_manifest=graph.manifests[0],
    )
    with TemporaryDirectory(
        dir=Path(gettempdir()).resolve(),
        prefix="phase5c-phase5b-replay-",
    ) as directory:
        artifacts = Path(directory) / "bundle"
        write_research_bundle_artifacts(
            graph,
            result,
            output_directory=artifacts,
        )
        mapping = compile_price_blind_fact_ledger(
            bundle_artifact_directory=artifacts,
            graph=graph,
            kernel_repository=KERNEL,
        )
    return mapping, assess_method_readiness(graph=graph, mapping_result=mapping)


def _readiness_case(
    *,
    specialist_route: str = "none",
) -> tuple[dict[str, object], ContractGraph]:
    preliminary = _readiness_predecessor_fields(specialist_route=specialist_route)
    graph = _phase5c_research_graph(preliminary)
    bundle = graph.research_bundles[0]
    identity = {
        "research_bundle_id": bundle.bundle_id,
        "research_bundle_fingerprint": bundle.bundle_fingerprint,
        "dependency_closure_sha256": bundle.dependency_closure_sha256,
        "component_lock_sha256": bundle.component_lock_sha256,
    }
    phase5b_pair = _compiled_phase5b_pair(graph)
    fields = _readiness_predecessor_fields(
        specialist_route=specialist_route,
        bundle_identity=identity,
        phase5b_pair=phase5b_pair,
    )
    context_sha, stable_sha, annual_bindings = _validate_research_context(
        graph=graph,
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        reconciliation_result=fields["reconciliation_result"],
        quality_result=fields["quality_result"],
        footnote_review=fields["stable_capital_footnote_review"],
        allocation_review=fields["stable_capital_allocation_review"],
        stable_claim=fields["stable_capital_claim"],
        stable_candidate=fields["stable_capital_claim_candidate"],
        stable_decision=fields["stable_capital_claim_review_decision"],
    )
    fields.update(
        {
            "validated_research_context_sha256": context_sha,
            "stable_capital_evidence_closure_sha256": stable_sha,
            "stable_capital_annual_bindings": annual_bindings,
            "validation_graph": graph,
        }
    )
    return fields, graph


def _context_args(fields: dict[str, object], graph: ContractGraph) -> dict[str, object]:
    return {
        "graph": graph,
        "issuer_id": "issuer:fixture",
        "data_cutoff_date": "2026-07-11",
        "reconciliation_result": fields["reconciliation_result"],
        "quality_result": fields["quality_result"],
        "footnote_review": fields["stable_capital_footnote_review"],
        "allocation_review": fields["stable_capital_allocation_review"],
        "stable_claim": fields["stable_capital_claim"],
        "stable_candidate": fields["stable_capital_claim_candidate"],
        "stable_decision": fields["stable_capital_claim_review_decision"],
    }


def _rebuild_bundle_graph(graph: ContractGraph) -> ContractGraph:
    manifest = replace(graph.manifests[0], output_artifact_hashes={})
    source = replace(graph, manifests=(manifest,), research_bundles=())
    build = build_research_bundle(source, run_id=manifest.run_id)
    return replace(
        source,
        manifests=(build.run_manifest,),
        research_bundles=(build.bundle,),
    )


def _method_ledger(
    decisions: tuple[MethodAdjustmentDecision, ...],
) -> dict[str, object]:
    base = _reconciliation_ledger()
    facts: dict[str, dict[str, object]] = {item["fact_id"]: dict(item) for item in base["facts"]}
    for decision in decisions:
        source_concept = {
            "lease": "operating_lease_liability",
            "pension": "unfunded_pension",
            "sbc": "option_or_dilution_claim",
        }.get(decision.category, "financial_obligations")
        for fact_id in decision.root_fact_ids:
            facts.setdefault(
                fact_id,
                _kernel_fact(
                    fact_id,
                    concept=source_concept,
                    category="financing",
                ),
            )
        category = (
            bridge_role_policy(decision.target_bridge_role).kernel_category
            if decision.target_bridge_role
            else "operating"
            if decision.target_concept in {"invested_capital", "net_operating_assets"}
            else "financing"
        )
        for fact_id in decision.source_fact_ids:
            if fact_id in decision.root_fact_ids:
                facts.setdefault(fact_id, _kernel_fact(fact_id))
            else:
                facts[fact_id] = _kernel_fact(
                    fact_id,
                    concept=(
                        decision.target_concept
                        if fact_id == decision.target_fact_id
                        else source_concept
                    ),
                    category=category if fact_id == decision.target_fact_id else "financing",
                    raw=False,
                    parent_fact_ids=decision.root_fact_ids,
                    equity_bridge_role=(
                        decision.target_bridge_role if fact_id == decision.target_fact_id else None
                    ),
                )
        if decision.target_fact_id not in facts:
            target_policy = ACCOUNT_CONCEPT_POLICIES[decision.target_concept]
            if target_policy.permitted_origins == ("derived",):
                target_root_id = f"root:{decision.target_fact_id}"
                target_root_concept = (
                    "operating_assets" if category == "operating" else "financial_obligations"
                )
                facts[target_root_id] = _kernel_fact(
                    target_root_id,
                    concept=target_root_concept,
                    category=category,
                )
                facts[decision.target_fact_id] = _kernel_fact(
                    decision.target_fact_id,
                    concept=decision.target_concept,
                    category=category,
                    raw=False,
                    parent_fact_ids=(target_root_id,),
                    equity_bridge_role=decision.target_bridge_role,
                )
            else:
                facts[decision.target_fact_id] = _kernel_fact(
                    decision.target_fact_id,
                    concept=decision.target_concept,
                    category=category,
                    equity_bridge_role=decision.target_bridge_role,
                )
        facts[decision.amount_fact_id] = _kernel_fact(
            decision.amount_fact_id,
            concept="method_adjustment_amount",
            value=sum(float(facts[fact_id]["value"]) for fact_id in decision.source_fact_ids),
            category="evidence",
            raw=False,
            parent_fact_ids=decision.root_fact_ids,
            derivation=METHOD_ADJUSTMENT_CALCULATOR_POLICY.derivation_label,
        )
    return _ledger_payload(tuple(facts.values()))


def _assessment(
    assessment_id: str,
    status: str,
    value: bool | None,
    reason_codes=(),
) -> dict[str, object]:
    bindings = {}
    for role in ROUTING_ASSESSMENT_REQUIRED_EVIDENCE[assessment_id]:
        bindings[role] = [f"evidence:{role}"]
    if assessment_id == "stable_capital_structure":
        snapshot_ids = _stable_snapshot_fact_ids()
        bindings["three_comparable_annual_debt_cash_common_equity_snapshots"] = [
            *snapshot_ids,
        ]
        bindings["current_debt_liquidity_covenants_footnote_review"] = [
            "footnote:debt_liquidity_covenants"
        ]
        bindings["current_capital_allocation_review"] = [_capital_search_objects()[1].review_id]
        for role in (
            "named_human_confirmed_analytical_claim",
            "counterevidence_search",
            "falsification_condition",
        ):
            bindings[role] = ["claim:stable-capital"]
        evidence_fact_ids = sorted(
            {
                *snapshot_ids,
                *_stable_capital_contracts(_reconciliation())[
                    "stable_capital_footnote_review"
                ].fact_ids,
            }
        )
        research_evidence_ids = [
            "footnote:debt_liquidity_covenants",
            _capital_search_objects()[1].review_id,
            "claim:stable-capital",
            "analytical-candidate:stable-capital",
            "analytical-decision:stable-capital",
        ]
    else:
        evidence_fact_ids = ["fact:evidence"]
        research_evidence_ids = ["review:evidence"]
    return {
        "status": status,
        "value": value,
        "rationale": "Synthetic reviewed assessment.",
        "evidence_fact_ids": evidence_fact_ids,
        "research_evidence_ids": research_evidence_ids,
        "evidence_role_bindings": bindings,
        "reason_codes": list(reason_codes),
    }


def _panel(method: str, status: str = "ready_for_phase5d") -> dict[str, object]:
    roles = list(METHOD_SUCCESSOR_REQUIRED_ROLES[method])
    ready = status == "ready_for_phase5d"
    return {
        "status": status,
        "satisfied_roles": roles if ready else [],
        "missing_roles": [] if ready else roles,
        "evidence_fact_ids": ["fact:evidence"],
        "research_evidence_ids": ["review:evidence"],
        "reason_codes": [] if ready else ["successor_role_missing"],
    }


def _upstream_statuses() -> dict[str, str]:
    return {
        "accounting_reconciliation": "pass",
        "mckinsey_accounting_quality": "pass",
        "penman_accounting_quality": "pass",
        "mckinsey_method_view": "pass",
        "penman_method_view": "pass",
        "equity_bridge": "complete",
    }


def _readiness_assessments() -> dict[str, object]:
    return {
        "required_data_complete": _assessment(
            "required_data_complete",
            "unsatisfied",
            False,
            ("required_data_incomplete_until_phase5e",),
        ),
        "stable_capital_structure": _assessment("stable_capital_structure", "satisfied", True),
        "operating_financing_separable": _assessment(
            "operating_financing_separable", "satisfied", True
        ),
        "credible_noa": _assessment("credible_noa", "satisfied", True),
        "credible_near_term_earnings": _assessment(
            "credible_near_term_earnings",
            "pending_phase5d",
            None,
            ("phase5d_earnings_pending",),
        ),
        "equity_bridge_complete": _assessment("equity_bridge_complete", "satisfied", True),
    }


def test_phase5c0_keeps_public_surface_closed_and_pins_validation_allowlist() -> None:
    assert len(SCHEMA_NAMES) == 43
    assert (PHASE5C_POLICY_ID, PHASE5C_POLICY_VERSION) == (
        "phase5c-accounting-equity-bridge",
        "1.0.0",
    )
    assert len(phase5c_policy_sha256()) == 64
    assert KERNEL_VALIDATION_ALLOWLIST == (
        "owner_valuation.FactLedger",
        "owner_valuation.MethodAdjustment",
        "owner_valuation.MethodView",
        "owner_valuation.validation.validate_balance_sheet",
        "owner_valuation.validation.validate_clean_surplus",
        "owner_valuation.validation.accounting_quality_gate",
    )
    assert {
        "owner_valuation.run_dual_panel",
        "owner_valuation.AssumptionLedger",
        "owner_valuation.pipeline._build_method_view",
        "owner_valuation.pipeline._accounting_validation",
        "owner_valuation.pipeline._validate_equity_bridge_review",
    }.issubset(KERNEL_FORBIDDEN_SURFACES)
    for name in (
        "AccountClassificationDecision",
        "AccountingReconciliationResult",
        "EquityBridgeCompilationResult",
        "compile_accounting_reformulation",
        "compile_method_views",
        "compile_equity_bridge",
    ):
        assert not hasattr(owner_research, name)


def test_closed_registries_separate_balance_sheet_claims_from_nfo() -> None:
    assert ACCOUNT_ROLES == (
        "operating_asset",
        "operating_liability",
        "financial_asset",
        "financial_obligation",
        "non_common_claim",
        "common_equity",
        "unresolved",
    )
    required = {
        "total_equity",
        "total_liabilities",
        "adjusted_total_liabilities",
        "common_equity",
        "noncontrolling_interest",
        "preferred_stock",
        "comprehensive_income_attributable_to_common",
        "common_dividends",
        "common_share_repurchases",
        "common_equity_issuance_proceeds",
        "equity_settled_sbc_owner_contribution",
        "operating_assets",
        "operating_liabilities",
        "financial_assets",
        "financial_obligations",
    }
    assert required.issubset(ACCOUNT_CONCEPT_POLICIES)
    assert ACCOUNT_CONCEPT_POLICIES["total_liabilities"].nfo_treatment == "prohibited_total"
    assert (
        FORMULA_POLICIES["adjusted_total_liabilities"].output_concept
        == "adjusted_total_liabilities"
    )
    assert ACCOUNT_CONCEPT_POLICIES["total_equity"].account_role == "unresolved"
    assert (
        ACCOUNT_CONCEPT_POLICIES["noncontrolling_interest"].nfo_treatment
        == "non_common_equity_claim"
    )
    assert STABLE_CAPITAL_MINIMUM_ANNUAL_SNAPSHOTS == 3
    assert ACCOUNT_CONCEPT_POLICIES["cash_and_cash_equivalents"].classification_requires_review
    with pytest.raises(KeyError):
        account_concept_policy("liabilities_approximately")


def test_method_and_bridge_registries_are_exact_and_closed() -> None:
    assert METHOD_ADJUSTMENT_CATEGORIES == (
        "r_and_d",
        "brand_investment",
        "lease",
        "pension",
        "sbc",
        "goodwill",
        "deferred_tax",
        "non_recurring",
        "other",
    )
    assert set(METHOD_TARGET_POLICIES) == {"mckinsey", "penman"}
    assert method_target_policy("mckinsey").allowed_concepts == ("invested_capital",)
    assert method_target_policy("mckinsey").allows_modeled_bridge_facts is False
    assert KERNEL_METHOD_VIEW_TARGET_ALLOWLIST["mckinsey"] == (
        "invested_capital",
        *BRIDGE_ROLES,
    )
    assert method_target_policy("penman").allowed_concepts == (
        "net_financial_obligations",
        "net_operating_assets",
    )
    assert BRIDGE_ROLES == (
        "nonoperating_asset",
        "debt",
        "debt_equivalent",
        "lease_liability",
        "unfunded_pension",
        "preferred_stock",
        "noncontrolling_interest",
        "option_or_dilution_claim",
        "other_senior_claim",
    )
    assert set(BRIDGE_ROLE_POLICIES) == set(BRIDGE_ROLES)
    assert BRIDGE_STATES == (
        "modeled",
        "explicitly_absent",
        "not_applicable",
        "unresolved",
    )
    assert bridge_role_policy("nonoperating_asset").kernel_category == "nonoperating"
    assert all(
        bridge_role_policy(role).kernel_category == "financing"
        for role in BRIDGE_ROLES
        if role != "nonoperating_asset"
    )
    with pytest.raises(KeyError):
        method_target_policy("blended")
    with pytest.raises(KeyError):
        bridge_role_policy("net_debt")
    assert all(
        policy.permits_cross_method_base_sharing and policy.consumption_limit_scope == "per_method"
        for role, policy in CROSS_CHANNEL_POLICIES.items()
        if role in BRIDGE_ROLES
    )
    assert (
        bridge_role_policy("option_or_dilution_claim").penman_nfo_treatment
        == "add_if_not_in_diluted_shares"
    )
    assert all(
        bridge_role_policy(role).requires_diluted_share_root_separation for role in BRIDGE_ROLES
    )


def test_internal_decisions_are_frozen_sorted_and_fingerprinted() -> None:
    account = AccountClassificationDecision(
        fact_id="fact:cash",
        concept="financial_assets",
        status="classified",
        account_role="financial_asset",
        classification_basis="registered_concept",
        classification_claim_id=None,
        review_decision_id=None,
        aggregation_set_id="financial_asset:fixture",
        aggregation_level="aggregate",
        root_fact_ids=("fact:cash:b", "fact:cash:a"),
        reason_codes=(),
        rationale="Registered cash classification for the reviewed perimeter.",
    )
    reordered = AccountClassificationDecision(
        fact_id=account.fact_id,
        concept=account.concept,
        status=account.status,
        account_role=account.account_role,
        classification_basis=account.classification_basis,
        classification_claim_id=None,
        review_decision_id=None,
        aggregation_set_id=account.aggregation_set_id,
        aggregation_level=account.aggregation_level,
        root_fact_ids=tuple(reversed(account.root_fact_ids)),
        reason_codes=(),
        rationale=account.rationale,
    )
    assert account.fingerprint == reordered.fingerprint
    assert account.root_fact_ids == ("fact:cash:a", "fact:cash:b")
    with pytest.raises(FrozenInstanceError):
        account.status = "blocked"  # type: ignore[misc]

    fact = next(item for item in _fact_decisions() if item.purpose == "net_distributions_to_owners")
    assert len(fact.fingerprint) == 64


def test_reconciliation_and_quality_results_fail_closed() -> None:
    assert QUALITY_MAPPING_POLICIES["watch"].resolved is False
    assert QUALITY_MAPPING_POLICIES["informational"].resolved is False
    assert QUALITY_MAPPING_POLICIES["cleared"].material is None
    assert QUALITY_MAPPING_POLICIES["cleared"].material_source == "reviewed_final_severity"
    assert METHOD_ADJUSTMENT_CATEGORY_POLICIES["r_and_d"].requires_phase5d_judgment
    assert METHOD_ADJUSTMENT_CATEGORY_POLICIES["lease"].permitted_source_concepts == (
        "operating_lease_liability",
    )
    result = _reconciliation()
    assert len(result.fingerprint) == 64
    with pytest.raises(ValueError, match="status does not replay"):
        _reconciliation(
            checks={
                "balance_sheet": _check("balance_sheet", "reconciles_by_construction"),
                "clean_surplus": _check("clean_surplus"),
                "noa_nfo_common_equity": _check("noa_nfo_common_equity"),
            },
            status="pass",
            reason_codes=(),
        )

    quality = _quality_result(result)
    assert len(quality.fingerprint) == 64


def test_method_view_types_reject_free_or_ineligible_adjustments() -> None:
    decision = MethodAdjustmentDecision(
        method="mckinsey",
        adjustment_id="adjustment:lease",
        adjustment_group_id="group:lease",
        category="lease",
        disposition="compiled",
        target_fact_id="derived:invested_capital",
        target_concept="invested_capital",
        target_bridge_role=None,
        amount_fact_id="derived:method-adjustment:lease",
        source_fact_ids=("fact:lease_liability:zero",),
        root_fact_ids=("fact:lease_liability:zero",),
        evidence_source_ids=("doc:10k",),
        rationale="Official lease amount is assumption-free.",
        reason_codes=(),
        **_calculator_fields("adjustment:lease"),
    )
    predecessors = _method_predecessor_fields((decision,))
    view = MethodViewCompilationResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        **predecessors,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        ledger_payload=_method_ledger((decision,)),
        adjustment_decisions=(decision,),
        method_views={
            "mckinsey": [
                {
                    "adjustment_id": decision.adjustment_id,
                    "target_fact_id": decision.target_fact_id,
                    "target_concept": decision.target_concept,
                    "target_bridge_role": decision.target_bridge_role,
                    "amount_fact_id": decision.amount_fact_id,
                }
            ],
            "penman": [],
        },
        consumption_records=_method_consumption_records(
            predecessors["reconciliation_result"], (decision,)
        ),
        status_by_method={"mckinsey": "pass", "penman": "pass"},
        reason_codes=(),
    )
    assert len(view.fingerprint) == 64
    with pytest.raises(ValueError, match="target"):
        MethodAdjustmentDecision(
            method="mckinsey",
            adjustment_id="adjustment:profit",
            adjustment_group_id="group:profit",
            category="non_recurring",
            disposition="compiled",
            target_fact_id="fact:operating-income",
            target_concept="operating_income",
            target_bridge_role=None,
            amount_fact_id="derived:method-adjustment:profit",
            source_fact_ids=("fact:charge",),
            root_fact_ids=("fact:charge",),
            evidence_source_ids=("doc:10k",),
            rationale="Disallowed historical profit target.",
            reason_codes=(),
            **_calculator_fields("adjustment:profit"),
        )


def test_equity_bridge_requires_exact_roles_and_request_compatibility() -> None:
    decisions = _role_decisions()
    ledger = _bridge_ledger(decisions)
    method_view = _empty_method_view(_reconciliation_ledger())
    result = EquityBridgeCompilationResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        reconciliation_fingerprint=method_view.reconciliation_fingerprint,
        method_view_fingerprint=method_view.fingerprint,
        method_view_result=method_view,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        ledger_payload=ledger,
        diluted_shares_fact_id="fact:diluted-shares",
        diluted_share_root_fact_ids=("fact:diluted-shares",),
        role_decisions=decisions,
        bridge_items=({"item_id": "bridge:debt", "fact_id": "fact:debt:aggregate"},),
        role_assertions=tuple(
            {
                "role": item.role,
                "status": item.status,
                "fact_id": item.fact_id,
                "source_fact_ids": list(item.evidence_fact_ids),
                "rationale": item.rationale,
            }
            for item in decisions
        ),
        consumption_records=_bridge_consumption_records(method_view, decisions),
        status="complete",
        kernel_request_compatible=True,
        reason_codes=(),
    )
    assert len(result.fingerprint) == 64
    with pytest.raises(ValueError, match="exactly nine"):
        EquityBridgeCompilationResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            reconciliation_fingerprint=result.reconciliation_fingerprint,
            method_view_fingerprint=result.method_view_fingerprint,
            method_view_result=result.method_view_result,
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            ledger_payload=result.ledger_payload,
            diluted_shares_fact_id="fact:diluted-shares",
            diluted_share_root_fact_ids=("fact:diluted-shares",),
            role_decisions=decisions[:-1],
            bridge_items=result.bridge_items,
            role_assertions=result.role_assertions[:-1],
            consumption_records=result.consumption_records,
            status="partial",
            kernel_request_compatible=False,
            reason_codes=("bridge_role_coverage_incomplete",),
        )


def test_equity_bridge_replays_prior_method_view_root_consumption() -> None:
    decisions = _role_decisions()
    adjustment = MethodAdjustmentDecision(
        method="mckinsey",
        adjustment_id="adjustment:method-debt",
        adjustment_group_id="group:method-debt",
        category="other",
        disposition="compiled",
        target_fact_id="derived:invested_capital",
        target_concept="invested_capital",
        target_bridge_role=None,
        amount_fact_id="derived:method-debt",
        source_fact_ids=("fact:debt:current", "fact:debt:noncurrent"),
        root_fact_ids=("fact:debt:current", "fact:debt:noncurrent"),
        evidence_source_ids=("doc:10k",),
        rationale="Debt root is first consumed in the McKinsey method view.",
        reason_codes=(),
        **_calculator_fields("adjustment:method-debt"),
    )
    method_ledger = _method_ledger((adjustment,))
    predecessors = _method_predecessor_fields((adjustment,))
    prior_consumption = _method_consumption_records(
        predecessors["reconciliation_result"], (adjustment,)
    )
    method_view = MethodViewCompilationResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        **predecessors,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        ledger_payload=method_ledger,
        adjustment_decisions=(adjustment,),
        method_views={
            "mckinsey": [
                {
                    "adjustment_id": adjustment.adjustment_id,
                    "target_fact_id": adjustment.target_fact_id,
                    "target_concept": adjustment.target_concept,
                    "target_bridge_role": None,
                    "amount_fact_id": adjustment.amount_fact_id,
                }
            ],
            "penman": [],
        },
        consumption_records=prior_consumption,
        status_by_method={"mckinsey": "pass", "penman": "pass"},
        reason_codes=(),
    )
    ledger = _bridge_ledger(decisions)
    amount_fact = next(
        item for item in method_ledger["facts"] if item["fact_id"] == adjustment.amount_fact_id
    )
    ledger["facts"].append(amount_fact)
    with pytest.raises(ValueError, match="consumed more than once"):
        _bridge_result(
            decisions=decisions,
            ledger_payload=ledger,
            method_view_result=method_view,
        )

    absent = tuple(
        EquityBridgeRoleDecision(
            role=role,
            status="unresolved" if role == "debt" else "explicitly_absent",
            fact_id=None,
            evidence_fact_ids=() if role == "debt" else (f"fact:{role}:zero",),
            root_fact_ids=() if role == "debt" else (f"fact:{role}:zero",),
            claim_id=None,
            review_decision_id=None,
            rationale=(
                "Debt evidence is unresolved." if role == "debt" else "Official numeric zero."
            ),
            missing_evidence=("debt evidence",) if role == "debt" else (),
            reason_codes=("bridge_role_coverage_incomplete",) if role == "debt" else (),
        )
        for role in BRIDGE_ROLES
    )
    absent_ledger = _bridge_ledger(absent)
    absent_method_view = _empty_method_view(_reconciliation_ledger())
    with pytest.raises(ValueError, match="kernel_bridge_item_required"):
        EquityBridgeCompilationResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            reconciliation_fingerprint=absent_method_view.reconciliation_fingerprint,
            method_view_fingerprint=absent_method_view.fingerprint,
            method_view_result=absent_method_view,
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            ledger_payload=absent_ledger,
            diluted_shares_fact_id="fact:diluted-shares",
            diluted_share_root_fact_ids=("fact:diluted-shares",),
            role_decisions=absent,
            bridge_items=(),
            role_assertions=tuple(
                {
                    "role": item.role,
                    "status": item.status,
                    "fact_id": None,
                    "source_fact_ids": list(item.evidence_fact_ids),
                    "rationale": item.rationale,
                }
                for item in absent
            ),
            consumption_records=_bridge_consumption_records(absent_method_view, absent),
            status="partial",
            kernel_request_compatible=False,
            reason_codes=("bridge_role_coverage_incomplete",),
        )


def test_successor_readiness_recomputes_six_assessments_without_aggregate() -> None:
    assessments = _readiness_assessments()
    predecessors, graph = _readiness_case()
    result = Phase5CReadinessResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        **predecessors,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        specialist_route="none",
        upstream_statuses=_upstream_statuses(),
        routing_assessments=assessments,
        method_panels={"mckinsey": _panel("mckinsey"), "penman": _panel("penman")},
    )
    assert set(result.routing_assessments) == set(ROUTING_ASSESSMENT_IDS)
    assert set(result.method_panels) == {"mckinsey", "penman"}
    assert "status" not in result.to_dict()
    assert "model_weight" not in json.dumps(result.to_dict())
    with pytest.raises(ValueError, match="pending_phase5d"):
        replace(
            result,
            validation_graph=graph,
            routing_assessments={
                **assessments,
                "credible_near_term_earnings": _assessment(
                    "credible_near_term_earnings", "satisfied", True
                ),
            },
        )


def test_account_classification_requires_registered_concept_role_and_review_basis() -> None:
    with pytest.raises(ValueError, match="concept is not registered"):
        AccountClassificationDecision(
            fact_id="fact:unknown",
            concept="approximately_cash",
            status="classified",
            account_role="financial_asset",
            classification_basis="registered_concept",
            classification_claim_id=None,
            review_decision_id=None,
            aggregation_set_id="financial_asset:fixture",
            aggregation_level="aggregate",
            root_fact_ids=("fact:unknown",),
            reason_codes=(),
            rationale="Unknown concept must fail closed.",
        )
    with pytest.raises(ValueError, match="role does not match"):
        AccountClassificationDecision(
            fact_id="fact:total-equity",
            concept="total_equity",
            status="classified",
            account_role="common_equity",
            classification_basis="registered_concept",
            classification_claim_id=None,
            review_decision_id=None,
            aggregation_set_id=None,
            aggregation_level="not_applicable",
            root_fact_ids=("fact:total-equity",),
            reason_codes=(),
            rationale="Reported total equity is not yet common equity.",
        )
    with pytest.raises(ValueError, match="basis does not match"):
        AccountClassificationDecision(
            fact_id="fact:cash",
            concept="cash_and_cash_equivalents",
            status="classified",
            account_role="financial_asset",
            classification_basis="registered_concept",
            classification_claim_id=None,
            review_decision_id=None,
            aggregation_set_id="financial_asset:fixture",
            aggregation_level="component",
            root_fact_ids=("fact:cash",),
            reason_codes=(),
            rationale="Cash requires reviewed operating-cash classification.",
        )
    reviewed = AccountClassificationDecision(
        fact_id="fact:cash",
        concept="cash_and_cash_equivalents",
        status="classified",
        account_role="financial_asset",
        classification_basis="reviewed_claim",
        classification_claim_id="claim:cash-classification",
        review_decision_id="decision:cash-classification",
        aggregation_set_id="financial_asset:fixture",
        aggregation_level="component",
        root_fact_ids=("fact:cash",),
        reason_codes=(),
        rationale="Named-human review classified excess cash as financial.",
    )
    assert reviewed.account_role == "financial_asset"


def test_clean_surplus_owner_coverage_and_pass_status_fail_closed() -> None:
    bad_clean_surplus = _check("clean_surplus")
    bad_clean_surplus["stock_measurement_dates"]["beginning_common_equity"] = "2025-12-31"
    with pytest.raises(ValueError, match="beginning stock"):
        _reconciliation(
            checks={
                "balance_sheet": _check("balance_sheet"),
                "clean_surplus": bad_clean_surplus,
                "noa_nfo_common_equity": _check("noa_nfo_common_equity"),
            }
        )
    incomplete_coverage = _owner_coverage()
    incomplete_coverage.pop("common_dividends")
    with pytest.raises(ValueError, match="every registered component"):
        _reconciliation(owner_transaction_coverage=incomplete_coverage)
    with pytest.raises(ValueError, match="nonempty ledger"):
        _reconciliation(ledger_payload=_ledger_payload(()))
    with pytest.raises(ValueError, match="cannot retain blocking reasons"):
        _reconciliation(reason_codes=("account_root_role_conflict",))


def test_reconciliation_recomputes_equation_differences_from_bound_facts() -> None:
    ledger = _reconciliation_ledger()
    total_assets = next(item for item in ledger["facts"] if item["fact_id"] == "fact:total-assets")
    total_assets["value"] = 181
    with pytest.raises(ValueError, match="difference does not replay"):
        _reconciliation(ledger_payload=ledger)


def test_accounting_quality_round_trip_preserves_open_and_cleared_materiality() -> None:
    reconciliation = _reconciliation()
    invalid_decision = {
        "finding_id": "finding:watch",
        "finding_fingerprint": "placeholder",
        "finding_status": "confirmed",
        "final_severity": "watch",
        "evidence_state": "watch",
        "category": "accruals",
        "disposition": "nonmaterial",
        "material": False,
        "resolved": True,
        "evidence_fact_ids": ["fact:marketable-securities"],
        "claim_id": "claim:watch",
        "review_decision_id": "decision:watch",
        "reason_codes": [],
    }
    review, findings = _quality_contracts((invalid_decision,))
    invalid_decision["finding_fingerprint"] = findings[0].fingerprint
    with pytest.raises(ValueError, match="disposition does not replay"):
        AccountingQualityCompilationResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            reconciliation_fingerprint=reconciliation.fingerprint,
            reconciliation_result=reconciliation,
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            accounting_quality_review_id=review.review_id,
            accounting_quality_review_fingerprint=review.fingerprint,
            accounting_quality_review_status=review.status,
            accounting_quality_review=review,
            accounting_quality_findings=findings,
            **_quality_predecessor_fields(reconciliation),
            expected_finding_ids=review.finding_ids,
            issue_decisions=(invalid_decision,),
            kernel_quality_issues=(),
            kernel_gate_status="pass",
            **_kernel_quality_compatibility(
                kernel_gate_status="pass",
                status_by_method={"mckinsey": "pass", "penman": "pass"},
            ),
            unresolved_material_issue_ids=(),
            status="pass",
            missing_evidence=(),
            reason_codes=(),
        )


def test_accounting_quality_decision_replays_finding_status_and_severity() -> None:
    reconciliation = _reconciliation()
    invalid_red = {
        "finding_id": "finding:red",
        "finding_fingerprint": "placeholder",
        "finding_status": "confirmed",
        "final_severity": "red_flag",
        "evidence_state": "confirmed_red_flag",
        "category": "tax_anomaly",
        "disposition": "nonmaterial",
        "material": False,
        "resolved": False,
        "evidence_fact_ids": ["fact:total-equity"],
        "claim_id": "claim:red",
        "review_decision_id": "decision:red",
        "reason_codes": [],
    }
    review, findings = _quality_contracts((invalid_red,))
    invalid_red["finding_fingerprint"] = findings[0].fingerprint
    with pytest.raises(ValueError, match="disposition does not replay"):
        AccountingQualityCompilationResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            reconciliation_fingerprint=reconciliation.fingerprint,
            reconciliation_result=reconciliation,
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            accounting_quality_review_id=review.review_id,
            accounting_quality_review_fingerprint=review.fingerprint,
            accounting_quality_review_status=review.status,
            accounting_quality_review=review,
            accounting_quality_findings=findings,
            **_quality_predecessor_fields(reconciliation),
            expected_finding_ids=review.finding_ids,
            issue_decisions=(invalid_red,),
            kernel_quality_issues=(),
            kernel_gate_status="pass",
            **_kernel_quality_compatibility(
                kernel_gate_status="pass",
                status_by_method={"mckinsey": "pass", "penman": "pass"},
            ),
            unresolved_material_issue_ids=(),
            status="pass",
            missing_evidence=(),
            reason_codes=(),
        )
    valid_red = {
        **invalid_red,
        "disposition": "material_unresolved",
        "material": True,
    }
    with pytest.raises(ValueError, match="gate status is inconsistent"):
        AccountingQualityCompilationResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            reconciliation_fingerprint=reconciliation.fingerprint,
            reconciliation_result=reconciliation,
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            accounting_quality_review_id=review.review_id,
            accounting_quality_review_fingerprint=review.fingerprint,
            accounting_quality_review_status=review.status,
            accounting_quality_review=review,
            accounting_quality_findings=findings,
            **_quality_predecessor_fields(reconciliation),
            expected_finding_ids=review.finding_ids,
            issue_decisions=(valid_red,),
            kernel_quality_issues=(
                {
                    "issue_id": "finding:red",
                    "category": "tax_anomaly",
                    "material": True,
                    "resolved": False,
                    "evidence_fact_ids": ["fact:total-equity"],
                },
            ),
            kernel_gate_status="pass",
            **_kernel_quality_compatibility(
                kernel_gate_status="pass",
                status_by_method={"mckinsey": "blocked", "penman": "blocked"},
            ),
            unresolved_material_issue_ids=("finding:red",),
            status="blocked",
            missing_evidence=(),
            reason_codes=("accounting_quality_material_unresolved",),
        )


def test_method_view_uses_real_bridge_concepts_and_per_method_root_conservation() -> None:
    with pytest.raises(ValueError, match="target is not allowed"):
        MethodAdjustmentDecision(
            method="mckinsey",
            adjustment_id="adjustment:debt",
            adjustment_group_id="group:debt",
            category="other",
            disposition="compiled",
            target_fact_id="fact:debt",
            target_concept="interest_bearing_debt",
            target_bridge_role="debt",
            amount_fact_id="derived:debt-adjustment",
            source_fact_ids=("fact:debt-source",),
            root_fact_ids=("fact:shared-root",),
            evidence_source_ids=("doc:10k",),
            rationale="Bridge items are compiled only after MethodView.",
            reason_codes=(),
            **_calculator_fields("adjustment:debt"),
        )
    with pytest.raises(ValueError, match="target is not allowed"):
        MethodAdjustmentDecision(
            method="mckinsey",
            adjustment_id="adjustment:pseudo",
            adjustment_group_id="group:pseudo",
            category="other",
            disposition="compiled",
            target_fact_id="fact:pseudo",
            target_concept="modeled_equity_bridge_fact",
            target_bridge_role="debt",
            amount_fact_id="derived:pseudo",
            source_fact_ids=("fact:debt",),
            root_fact_ids=("fact:shared-root",),
            evidence_source_ids=("doc:10k",),
            rationale="Pseudo concepts cannot enter the ledger.",
            reason_codes=(),
            **_calculator_fields("adjustment:pseudo"),
        )
    mckinsey = MethodAdjustmentDecision(
        method="mckinsey",
        adjustment_id="adjustment:ic",
        adjustment_group_id="group:ic",
        category="other",
        disposition="compiled",
        target_fact_id="derived:invested_capital",
        target_concept="invested_capital",
        target_bridge_role=None,
        amount_fact_id="derived:ic-adjustment",
        source_fact_ids=("fact:debt:current", "fact:debt:noncurrent"),
        root_fact_ids=("fact:debt:current", "fact:debt:noncurrent"),
        evidence_source_ids=("doc:10k",),
        rationale="The registered root may support the McKinsey method once.",
        reason_codes=(),
        **_calculator_fields("adjustment:ic"),
    )
    penman = MethodAdjustmentDecision(
        method="penman",
        adjustment_id="adjustment:nfo",
        adjustment_group_id="group:nfo",
        category="other",
        disposition="compiled",
        target_fact_id="derived:net_financial_obligations",
        target_concept="net_financial_obligations",
        target_bridge_role=None,
        amount_fact_id="derived:nfo-adjustment",
        source_fact_ids=("fact:debt:current", "fact:debt:noncurrent"),
        root_fact_ids=("fact:debt:current", "fact:debt:noncurrent"),
        evidence_source_ids=("doc:10k",),
        rationale="The same root may support the separate Penman method once.",
        reason_codes=(),
        **_calculator_fields("adjustment:nfo"),
    )
    with pytest.raises(ValueError, match="own adjustment roots"):
        _method_predecessor_fields((penman,))
    entries = {
        "mckinsey": [
            {
                "adjustment_id": mckinsey.adjustment_id,
                "target_fact_id": mckinsey.target_fact_id,
                "target_concept": mckinsey.target_concept,
                "target_bridge_role": mckinsey.target_bridge_role,
                "amount_fact_id": mckinsey.amount_fact_id,
            }
        ],
        "penman": [],
    }
    predecessors = _method_predecessor_fields((mckinsey,))
    records = _method_consumption_records(predecessors["reconciliation_result"], (mckinsey,))
    first = MethodViewCompilationResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        **predecessors,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        ledger_payload=_method_ledger((mckinsey,)),
        adjustment_decisions=(mckinsey,),
        method_views=entries,
        consumption_records=records,
        status_by_method={"mckinsey": "pass", "penman": "pass"},
        reason_codes=(),
    )
    second = MethodViewCompilationResult(
        issuer_id=first.issuer_id,
        data_cutoff_date=first.data_cutoff_date,
        reconciliation_fingerprint=first.reconciliation_fingerprint,
        reconciliation_result=first.reconciliation_result,
        quality_fingerprint=first.quality_fingerprint,
        quality_result=first.quality_result,
        policy_id=first.policy_id,
        policy_version=first.policy_version,
        policy_sha256=first.policy_sha256,
        ledger_payload=first.ledger_payload,
        adjustment_decisions=tuple(reversed(first.adjustment_decisions)),
        method_views={
            "penman": list(reversed(entries["penman"])),
            "mckinsey": list(reversed(entries["mckinsey"])),
        },
        consumption_records=tuple(reversed(records)),
        status_by_method={"penman": "pass", "mckinsey": "pass"},
        reason_codes=(),
    )
    assert first.fingerprint == second.fingerprint
    duplicate = {
        **next(item for item in records if item["consumption_kind"] == "economic_deduction"),
        "group_id": "group:duplicate",
    }
    with pytest.raises(ValueError, match="consumed more than once|root consumption"):
        MethodViewCompilationResult(
            issuer_id=first.issuer_id,
            data_cutoff_date=first.data_cutoff_date,
            reconciliation_fingerprint=first.reconciliation_fingerprint,
            reconciliation_result=first.reconciliation_result,
            quality_fingerprint=first.quality_fingerprint,
            quality_result=first.quality_result,
            policy_id=first.policy_id,
            policy_version=first.policy_version,
            policy_sha256=first.policy_sha256,
            ledger_payload=first.ledger_payload,
            adjustment_decisions=first.adjustment_decisions,
            method_views=first.method_views,
            consumption_records=records + (duplicate,),
            status_by_method=first.status_by_method,
            reason_codes=(),
        )
    with pytest.raises(ValueError, match="payload does not match"):
        MethodViewCompilationResult(
            issuer_id=first.issuer_id,
            data_cutoff_date=first.data_cutoff_date,
            reconciliation_fingerprint=first.reconciliation_fingerprint,
            reconciliation_result=first.reconciliation_result,
            quality_fingerprint=first.quality_fingerprint,
            quality_result=first.quality_result,
            policy_id=first.policy_id,
            policy_version=first.policy_version,
            policy_sha256=first.policy_sha256,
            ledger_payload=first.ledger_payload,
            adjustment_decisions=first.adjustment_decisions,
            method_views={"mckinsey": [], "penman": []},
            consumption_records=records,
            status_by_method=first.status_by_method,
            reason_codes=(),
        )


def test_method_view_rejects_self_target_and_kernel_duplicate_targets() -> None:
    self_target = MethodAdjustmentDecision(
        method="penman",
        adjustment_id="adjustment:self-target",
        adjustment_group_id="group:self-target",
        category="other",
        disposition="compiled",
        target_fact_id="derived:net_financial_obligations",
        target_concept="net_financial_obligations",
        target_bridge_role=None,
        amount_fact_id="derived:self-target",
        source_fact_ids=("fact:debt:current",),
        root_fact_ids=("fact:debt:current",),
        evidence_source_ids=("doc:10k",),
        rationale="A target cannot be its own economic adjustment input.",
        reason_codes=(),
        **_calculator_fields("adjustment:self-target"),
    )
    with pytest.raises(ValueError, match="cannot consume its own adjustment roots"):
        _method_predecessor_fields((self_target,))

    def duplicate_decision(
        adjustment_id: str, group_id: str, category: str, root_id: str
    ) -> MethodAdjustmentDecision:
        return MethodAdjustmentDecision(
            method="mckinsey",
            adjustment_id=adjustment_id,
            adjustment_group_id=group_id,
            category=category,
            disposition="compiled",
            target_fact_id="derived:invested_capital",
            target_concept="invested_capital",
            target_bridge_role=None,
            amount_fact_id=f"derived:{adjustment_id}",
            source_fact_ids=(root_id,),
            root_fact_ids=(root_id,),
            evidence_source_ids=("doc:10k",),
            rationale="Synthetic duplicate-target attack fixture.",
            reason_codes=(),
            **_calculator_fields(adjustment_id),
        )

    category_duplicates = (
        duplicate_decision("adjustment:one", "group:one", "other", "fact:debt:current"),
        duplicate_decision("adjustment:two", "group:two", "other", "fact:debt:noncurrent"),
    )
    with pytest.raises(ValueError, match="method category-target pairs"):
        MethodViewCompilationResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            **_method_predecessor_fields(category_duplicates),
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            ledger_payload=_method_ledger(category_duplicates),
            adjustment_decisions=category_duplicates,
            method_views={"mckinsey": [], "penman": []},
            consumption_records=(),
            status_by_method={"mckinsey": "pass", "penman": "pass"},
            reason_codes=(),
        )
    group_duplicates = (
        duplicate_decision("adjustment:three", "group:shared", "other", "fact:debt:current"),
        duplicate_decision(
            "adjustment:four",
            "group:shared",
            "lease",
            "fact:lease_liability:zero",
        ),
    )
    with pytest.raises(ValueError, match="method group-target pairs"):
        MethodViewCompilationResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            **_method_predecessor_fields(group_duplicates),
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            ledger_payload=_method_ledger(group_duplicates),
            adjustment_decisions=group_duplicates,
            method_views={"mckinsey": [], "penman": []},
            consumption_records=(),
            status_by_method={"mckinsey": "pass", "penman": "pass"},
            reason_codes=(),
        )
    judgment_adjustment = MethodAdjustmentDecision(
        method="mckinsey",
        adjustment_id="adjustment:subjective-rd",
        adjustment_group_id="group:subjective-rd",
        category="r_and_d",
        disposition="compiled",
        target_fact_id="derived:invested_capital",
        target_concept="invested_capital",
        target_bridge_role=None,
        amount_fact_id="derived:subjective-rd",
        source_fact_ids=("fact:debt:current",),
        root_fact_ids=("fact:debt:current",),
        evidence_source_ids=("doc:10k",),
        rationale="A monetary Fact cannot establish a judgmental R&D adjustment.",
        reason_codes=(),
        **_calculator_fields("adjustment:subjective-rd"),
    )
    with pytest.raises(ValueError, match="registered category"):
        MethodViewCompilationResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            **_method_predecessor_fields((judgment_adjustment,)),
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            ledger_payload=_method_ledger((judgment_adjustment,)),
            adjustment_decisions=(judgment_adjustment,),
            method_views={
                "mckinsey": [
                    {
                        "adjustment_id": judgment_adjustment.adjustment_id,
                        "target_fact_id": judgment_adjustment.target_fact_id,
                        "target_concept": judgment_adjustment.target_concept,
                        "target_bridge_role": None,
                        "amount_fact_id": judgment_adjustment.amount_fact_id,
                    }
                ],
                "penman": [],
            },
            consumption_records=(
                {
                    "root_fact_id": "fact:debt:current",
                    "economic_identity": "debt",
                    "channel": "mckinsey_equity_bridge",
                    "method": "mckinsey",
                    "group_id": "group:subjective-rd",
                    "consumption_kind": "economic_deduction",
                },
            ),
            status_by_method={"mckinsey": "pass", "penman": "pass"},
            reason_codes=(),
        )


def test_bridge_requires_diluted_lineage_unique_items_and_canonical_assertions() -> None:
    with pytest.raises(ValueError, match="nonempty root lineage"):
        _bridge_result(diluted_share_roots=())
    with pytest.raises(ValueError, match="item Facts"):
        _bridge_result(
            bridge_items=(
                {"item_id": "bridge:debt:a", "fact_id": "fact:debt:aggregate"},
                {"item_id": "bridge:debt:b", "fact_id": "fact:debt:aggregate"},
            )
        )
    first = _bridge_result()
    reordered_assertions = tuple(
        {
            "role": item["role"],
            "status": item["status"],
            "fact_id": item["fact_id"],
            "source_fact_ids": list(reversed(item["source_fact_ids"])),
            "rationale": item["rationale"],
        }
        for item in reversed(first.role_assertions)
    )
    second = _bridge_result(
        decisions=tuple(reversed(first.role_decisions)),
        role_assertions=reordered_assertions,
    )
    assert first.fingerprint == second.fingerprint
    with pytest.raises(ValueError, match="status does not replay"):
        _bridge_result(reason_codes=("bridge_state_not_replayed",))
    with pytest.raises(ValueError, match="cannot retain blocking reasons"):
        EquityBridgeRoleDecision(
            role="debt",
            status="explicitly_absent",
            fact_id=None,
            evidence_fact_ids=("fact:debt:zero",),
            root_fact_ids=("fact:debt:zero",),
            claim_id=None,
            review_decision_id=None,
            rationale="Official zero debt.",
            missing_evidence=(),
            reason_codes=("bridge_state_not_replayed",),
        )


def test_successor_readiness_uses_closed_method_roles_and_specialist_consistency() -> None:
    predecessors, _ = _readiness_case()
    panels = {"mckinsey": _panel("mckinsey"), "penman": _panel("penman")}
    bad_mckinsey = dict(panels["mckinsey"])
    bad_mckinsey["satisfied_roles"] = ["accounting", "bridge"]
    with pytest.raises(ValueError, match="registered closed set"):
        Phase5CReadinessResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            **predecessors,
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            specialist_route="none",
            upstream_statuses=_upstream_statuses(),
            routing_assessments=_readiness_assessments(),
            method_panels={"mckinsey": bad_mckinsey, "penman": panels["penman"]},
        )
    specialist_panels = {
        method: {
            **_panel(method),
            "status": "specialist_required",
            "reason_codes": ["specialist_route_required"],
        }
        for method in ("mckinsey", "penman")
    }
    with pytest.raises(ValueError, match="not deterministic"):
        Phase5CReadinessResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            **predecessors,
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            specialist_route="none",
            upstream_statuses=_upstream_statuses(),
            routing_assessments=_readiness_assessments(),
            method_panels=specialist_panels,
        )
    insufficient = _readiness_assessments()
    insufficient["stable_capital_structure"]["evidence_role_bindings"][
        "three_comparable_annual_debt_cash_common_equity_snapshots"
    ] = ["snapshot:2024", "snapshot:2025"]
    with pytest.raises(ValueError, match="three annual"):
        Phase5CReadinessResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            **predecessors,
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            specialist_route="none",
            upstream_statuses=_upstream_statuses(),
            routing_assessments=insufficient,
            method_panels=panels,
        )


def test_reconciliation_closes_arithmetic_period_perimeter_and_lineage() -> None:
    checks = {
        "balance_sheet": _check("balance_sheet"),
        "clean_surplus": _check("clean_surplus"),
        "noa_nfo_common_equity": _check("noa_nfo_common_equity"),
    }
    checks["balance_sheet"]["difference"] = 1.0
    with pytest.raises(ValueError, match="exceeds tolerance"):
        _reconciliation(checks=checks)

    checks = {
        "balance_sheet": _check("balance_sheet"),
        "clean_surplus": _check("clean_surplus"),
        "noa_nfo_common_equity": _check("noa_nfo_common_equity"),
    }
    checks["clean_surplus"]["measurement_period"] = {
        "start": "2026-01-01",
        "end": "2025-12-31",
    }
    with pytest.raises(ValueError, match="reversed"):
        _reconciliation(checks=checks)

    checks = {
        "balance_sheet": _check("balance_sheet"),
        "clean_surplus": _check("clean_surplus"),
        "noa_nfo_common_equity": _check("noa_nfo_common_equity"),
    }
    checks["clean_surplus"]["currency"] = "EUR"
    with pytest.raises(ValueError, match="currency or unit"):
        _reconciliation(checks=checks)

    ledger = _reconciliation_ledger()
    ledger["facts"].append(
        _kernel_fact(
            "fact:alternate-common-equity-root",
            concept="common_equity",
            category="accounting",
        )
    )
    checks = {
        "balance_sheet": _check("balance_sheet"),
        "clean_surplus": _check("clean_surplus"),
        "noa_nfo_common_equity": _check("noa_nfo_common_equity"),
    }
    checks["clean_surplus"]["stock_root_fact_ids"]["ending_common_equity"] = [
        "fact:alternate-common-equity-root"
    ]
    checks["clean_surplus"]["root_fact_ids"].append("fact:alternate-common-equity-root")
    with pytest.raises(ValueError, match="stock roots do not replay"):
        _reconciliation(ledger_payload=ledger, checks=checks)


def test_reconciliation_closes_account_and_owner_transaction_inputs() -> None:
    decisions = list(_fact_decisions())
    owner_index = next(
        index
        for index, item in enumerate(decisions)
        if item.purpose == "net_distributions_to_owners"
    )
    with pytest.raises(ValueError, match="term bindings do not match"):
        replace(
            decisions[owner_index],
            input_fact_ids=("fact:common_dividends",),
        )

    ledger = _reconciliation_ledger()
    ledger["facts"].append(
        _kernel_fact(
            "fact:operating-assets:extra",
            concept="operating_assets",
            category="operating",
        )
    )
    second = AccountClassificationDecision(
        fact_id="fact:operating-assets:extra",
        concept="operating_assets",
        status="classified",
        account_role="operating_asset",
        classification_basis="registered_concept",
        classification_claim_id=None,
        review_decision_id=None,
        aggregation_set_id="operating_asset:fixture",
        aggregation_level="aggregate",
        root_fact_ids=("fact:marketable-securities",),
        reason_codes=(),
        rationale="Synthetic duplicate-root attack.",
    )
    with pytest.raises(ValueError, match="classification roots"):
        _reconciliation(
            ledger_payload=ledger,
            account_decisions=(*_account_decisions(), second),
        )


def test_internal_ledgers_are_canonical_and_cannot_be_empty() -> None:
    first_ledger = _reconciliation_ledger()
    second_ledger = {
        **first_ledger,
        "sources": list(reversed(first_ledger["sources"])),
        "facts": list(reversed(first_ledger["facts"])),
    }
    assert (
        _reconciliation(ledger_payload=first_ledger).fingerprint
        == _reconciliation(ledger_payload=second_ledger).fingerprint
    )
    with pytest.raises(ValueError, match="nonempty ledger"):
        _reconciliation(ledger_payload=_ledger_payload(()))


def test_quality_compilation_covers_review_and_recomputes_status() -> None:
    reconciliation = _reconciliation()
    expected_decision = {
        "finding_id": "finding:expected",
        "finding_fingerprint": "placeholder",
        "finding_status": "confirmed",
        "final_severity": "watch",
        "evidence_state": "watch",
        "category": "accruals",
        "disposition": "nonmaterial",
        "material": False,
        "resolved": False,
        "evidence_fact_ids": ["fact:marketable-securities"],
        "claim_id": "claim:expected",
        "review_decision_id": "decision:expected",
        "reason_codes": [],
    }
    expected_review, expected_findings = _quality_contracts((expected_decision,))
    common = {
        "issuer_id": "issuer:fixture",
        "data_cutoff_date": "2026-07-11",
        "reconciliation_fingerprint": reconciliation.fingerprint,
        "reconciliation_result": reconciliation,
        "policy_id": PHASE5C_POLICY_ID,
        "policy_version": PHASE5C_POLICY_VERSION,
        "policy_sha256": phase5c_policy_sha256(),
        "accounting_quality_review_id": expected_review.review_id,
        "accounting_quality_review_fingerprint": expected_review.fingerprint,
        "accounting_quality_review_status": expected_review.status,
        "accounting_quality_review": expected_review,
        "accounting_quality_findings": expected_findings,
        "ledger_payload": reconciliation.ledger_payload,
        "adjustment_decisions": (),
        "status_by_method": {"mckinsey": "pass", "penman": "pass"},
        "kernel_quality_issues": (),
        "kernel_gate_status": "pass",
        **_kernel_quality_compatibility(
            kernel_gate_status="pass",
            status_by_method={"mckinsey": "pass", "penman": "pass"},
        ),
        "unresolved_material_issue_ids": (),
        "missing_evidence": (),
    }
    with pytest.raises(ValueError, match="cover the current Review"):
        AccountingQualityCompilationResult(
            **common,
            expected_finding_ids=("finding:expected",),
            issue_decisions=(),
            status="pass",
            reason_codes=(),
        )
    provisional = {
        "finding_id": "finding:provisional",
        "finding_fingerprint": "4" * 64,
        "finding_status": "provisional",
        "final_severity": "informational",
        "evidence_state": "provisional",
        "category": "tax_anomaly",
        "disposition": "provisional",
        "material": None,
        "resolved": None,
        "evidence_fact_ids": [],
        "claim_id": None,
        "review_decision_id": None,
        "reason_codes": ["accounting_quality_evidence_incomplete"],
    }
    provisional_review, provisional_findings = _quality_contracts((provisional,))
    provisional["finding_fingerprint"] = provisional_findings[0].fingerprint
    with pytest.raises(ValueError, match="not deterministic"):
        AccountingQualityCompilationResult(
            **{
                **common,
                "accounting_quality_review_id": provisional_review.review_id,
                "accounting_quality_review_fingerprint": provisional_review.fingerprint,
                "accounting_quality_review_status": provisional_review.status,
                "accounting_quality_review": provisional_review,
                "accounting_quality_findings": provisional_findings,
            },
            expected_finding_ids=provisional_review.finding_ids,
            issue_decisions=(provisional,),
            status="blocked",
            reason_codes=("accounting_quality_evidence_incomplete",),
        )


def test_method_view_requires_registered_consumption_and_ledger_lineage() -> None:
    decision = MethodAdjustmentDecision(
        method="mckinsey",
        adjustment_id="adjustment:lease",
        adjustment_group_id="group:lease",
        category="lease",
        disposition="compiled",
        target_fact_id="derived:invested_capital",
        target_concept="invested_capital",
        target_bridge_role=None,
        amount_fact_id="derived:lease-adjustment",
        source_fact_ids=("fact:lease_liability:zero",),
        root_fact_ids=("fact:lease_liability:zero",),
        evidence_source_ids=("doc:10k",),
        rationale="Synthetic registered adjustment.",
        reason_codes=(),
        **_calculator_fields("adjustment:lease"),
    )
    entries = {
        "mckinsey": [
            {
                "adjustment_id": decision.adjustment_id,
                "target_fact_id": decision.target_fact_id,
                "target_concept": decision.target_concept,
                "target_bridge_role": None,
                "amount_fact_id": decision.amount_fact_id,
            }
        ],
        "penman": [],
    }
    kwargs = {
        "issuer_id": "issuer:fixture",
        "data_cutoff_date": "2026-07-11",
        **_method_predecessor_fields((decision,)),
        "policy_id": PHASE5C_POLICY_ID,
        "policy_version": PHASE5C_POLICY_VERSION,
        "policy_sha256": phase5c_policy_sha256(),
        "ledger_payload": _method_ledger((decision,)),
        "adjustment_decisions": (decision,),
        "method_views": entries,
        "status_by_method": {"mckinsey": "pass", "penman": "pass"},
        "reason_codes": (),
    }
    with pytest.raises(ValueError, match="root consumption"):
        MethodViewCompilationResult(**kwargs, consumption_records=())
    valid_records = _method_consumption_records(kwargs["reconciliation_result"], (decision,))
    invalid_records = tuple(
        {
            **item,
            "channel": (
                "free_channel"
                if item["consumption_kind"] == "economic_deduction"
                else item["channel"]
            ),
        }
        for item in valid_records
    )
    with pytest.raises(ValueError, match="channel is not registered"):
        MethodViewCompilationResult(
            **kwargs,
            consumption_records=invalid_records,
        )


def test_bridge_rejects_duplicate_modeled_fact_and_unresolved_compatibility() -> None:
    decisions = list(_role_decisions())
    lease_index = next(
        index for index, item in enumerate(decisions) if item.role == "lease_liability"
    )
    decisions[lease_index] = EquityBridgeRoleDecision(
        role="lease_liability",
        status="modeled",
        fact_id="fact:debt:aggregate",
        evidence_fact_ids=("fact:debt:aggregate", "fact:lease:root"),
        root_fact_ids=("fact:lease:root",),
        claim_id=None,
        review_decision_id=None,
        rationale="Synthetic duplicate modeled Fact attack.",
        missing_evidence=(),
        reason_codes=(),
    )
    with pytest.raises(ValueError, match="modeled equity-bridge Facts"):
        _bridge_result(decisions=tuple(decisions))

    decisions = list(_role_decisions())
    lease_index = next(
        index for index, item in enumerate(decisions) if item.role == "lease_liability"
    )
    decisions[lease_index] = EquityBridgeRoleDecision(
        role="lease_liability",
        status="unresolved",
        fact_id=None,
        evidence_fact_ids=(),
        root_fact_ids=(),
        claim_id=None,
        review_decision_id=None,
        rationale="Lease evidence is incomplete.",
        missing_evidence=("lease evidence",),
        reason_codes=("bridge_role_coverage_incomplete",),
    )
    with pytest.raises(ValueError, match="cannot be request compatible"):
        _bridge_result(
            decisions=tuple(decisions),
            bridge_items=({"item_id": "bridge:debt", "fact_id": "fact:debt:aggregate"},),
            status="partial",
            compatible=True,
            reason_codes=("bridge_role_coverage_incomplete",),
        )
    partial = _bridge_result(
        decisions=tuple(decisions),
        bridge_items=({"item_id": "bridge:debt", "fact_id": "fact:debt:aggregate"},),
        status="partial",
        compatible=False,
        reason_codes=("bridge_role_coverage_incomplete",),
    )
    assert partial.status == "partial"

    decisions = list(_role_decisions())
    debt_index = next(index for index, item in enumerate(decisions) if item.role == "debt")
    debt = decisions[debt_index]
    decisions[debt_index] = replace(
        debt,
        evidence_fact_ids=("fact:debt:aggregate",),
    )
    with pytest.raises(ValueError, match="roots must be included"):
        _bridge_result(decisions=tuple(decisions))


def test_readiness_panels_replay_blocked_assessment_and_upstream_status() -> None:
    predecessors, _ = _readiness_case()
    assessments = _readiness_assessments()
    assessments["stable_capital_structure"] = _assessment(
        "stable_capital_structure",
        "blocked",
        None,
        ("stable_capital_structure_evidence_missing",),
    )
    with pytest.raises(ValueError, match="cannot retain a partial proof"):
        Phase5CReadinessResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            **predecessors,
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            specialist_route="none",
            upstream_statuses=_upstream_statuses(),
            routing_assessments=assessments,
            method_panels={"mckinsey": _panel("mckinsey"), "penman": _panel("penman")},
        )


def test_ledger_identity_account_and_formula_decisions_replay_exactly() -> None:
    wrong_identity = _reconciliation_ledger()
    wrong_identity["entity_id"] = "issuer:other"
    with pytest.raises(ValueError, match="issuer conflicts"):
        _reconciliation(ledger_payload=wrong_identity)

    wrong_account = _reconciliation_ledger()
    account_fact = next(
        item for item in wrong_account["facts"] if item["fact_id"] == "fact:marketable-securities"
    )
    account_fact["concept"] = "operating_assets"
    with pytest.raises(ValueError, match="registered concept semantics"):
        _reconciliation(ledger_payload=wrong_account)

    wrong_formula = _reconciliation_ledger()
    output = next(
        item for item in wrong_formula["facts"] if item["fact_id"] == "derived:common_equity"
    )
    output["derivation"] = "unregistered common-equity derivation"
    with pytest.raises(ValueError, match="does not replay its formula"):
        _reconciliation(ledger_payload=wrong_formula)


def test_bridge_zero_and_modeled_lineage_replay_registered_role_semantics() -> None:
    decisions = _role_decisions()
    wrong_zero = _bridge_ledger(decisions)
    zero = next(
        item for item in wrong_zero["facts"] if item["fact_id"] == "fact:lease_liability:zero"
    )
    zero.update(
        {
            "concept": "debt_equivalent",
            "category": "financing",
            "equity_bridge_role": None,
        }
    )
    with pytest.raises(ValueError, match="does not preserve MethodView evidence"):
        _bridge_result(decisions=decisions, ledger_payload=wrong_zero)

    wrong_aggregate = _bridge_ledger(decisions)
    aggregate = next(
        item for item in wrong_aggregate["facts"] if item["fact_id"] == "fact:debt:aggregate"
    )
    aggregate["raw"] = True
    aggregate["parent_fact_ids"] = []
    aggregate["derivation"] = None
    with pytest.raises(ValueError, match="reviewed derived aggregate"):
        _bridge_result(decisions=decisions, ledger_payload=wrong_aggregate)


def test_method_view_rejects_cross_source_amount_lineage() -> None:
    decision = MethodAdjustmentDecision(
        method="mckinsey",
        adjustment_id="adjustment:lease-source",
        adjustment_group_id="group:lease-source",
        category="lease",
        disposition="compiled",
        target_fact_id="derived:invested_capital",
        target_concept="invested_capital",
        target_bridge_role=None,
        amount_fact_id="derived:lease-source",
        source_fact_ids=("fact:lease_liability:zero",),
        root_fact_ids=("fact:lease_liability:zero",),
        evidence_source_ids=("doc:10k",),
        rationale="Synthetic source-lineage attack.",
        reason_codes=(),
        **_calculator_fields("adjustment:lease-source"),
    )
    ledger = _method_ledger((decision,))
    ledger["sources"].append(
        {
            **ledger["sources"][0],
            "source_id": "doc:other",
            "local_path": "/fixtures/other.json",
        }
    )
    amount = next(item for item in ledger["facts"] if item["fact_id"] == decision.amount_fact_id)
    amount["source_id"] = "doc:other"
    with pytest.raises(ValueError, match="does not replay accounting quality outputs"):
        MethodViewCompilationResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            **_method_predecessor_fields((decision,)),
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            ledger_payload=ledger,
            adjustment_decisions=(decision,),
            method_views={
                "mckinsey": [
                    {
                        "adjustment_id": decision.adjustment_id,
                        "target_fact_id": decision.target_fact_id,
                        "target_concept": decision.target_concept,
                        "target_bridge_role": None,
                        "amount_fact_id": decision.amount_fact_id,
                    }
                ],
                "penman": [],
            },
            consumption_records=(
                {
                    "root_fact_id": "fact:lease_liability:zero",
                    "economic_identity": "lease_liability",
                    "channel": "mckinsey_equity_bridge",
                    "method": "mckinsey",
                    "group_id": "group:lease-source",
                    "consumption_kind": "economic_deduction",
                },
            ),
            status_by_method={"mckinsey": "pass", "penman": "pass"},
            reason_codes=(),
        )


def test_specialist_readiness_preserves_blocked_priority() -> None:
    upstream = _upstream_statuses()
    panels = {}
    for method in ("mckinsey", "penman"):
        roles = set(METHOD_SUCCESSOR_REQUIRED_ROLES[method])
        panels[method] = {
            "status": "blocked",
            "satisfied_roles": sorted(roles),
            "missing_roles": [],
            "evidence_fact_ids": ["fact:evidence"],
            "research_evidence_ids": ["review:evidence"],
            "reason_codes": ["specialist_route_required"],
        }
    specialist_predecessors, _ = _readiness_case(specialist_route="unresolved")
    result = Phase5CReadinessResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        **specialist_predecessors,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        specialist_route="unresolved",
        upstream_statuses=upstream,
        routing_assessments=_readiness_assessments(),
        method_panels=panels,
    )
    assert {panel["status"] for panel in result.method_panels.values()} == {"blocked"}

    upstream = _upstream_statuses()
    upstream["mckinsey_accounting_quality"] = "blocked"
    upstream["penman_accounting_quality"] = "blocked"
    ordinary_predecessors, _ = _readiness_case()
    with pytest.raises(ValueError, match="upstream statuses do not replay"):
        Phase5CReadinessResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            **ordinary_predecessors,
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            specialist_route="none",
            upstream_statuses=upstream,
            routing_assessments=_readiness_assessments(),
            method_panels={"mckinsey": _panel("mckinsey"), "penman": _panel("penman")},
        )


def test_phase5c_adversarial_fixture_and_failure_matrix_are_closed() -> None:
    fixture = json.loads(
        (ROOT / "tests/fixtures/phase5c/adversarial-cases.json").read_text(encoding="utf-8")
    )
    matrix = json.loads(
        (ROOT / "docs/phase5c-failure-mode-matrix.json").read_text(encoding="utf-8")
    )
    assert fixture["policy_id"] == PHASE5C_POLICY_ID
    assert len(fixture["cases"]) == 94
    assert {item["failure_id"] for item in fixture["cases"]} == {
        f"P5-F{number:03d}" for number in range(15, 22)
    }
    assert {item["reason_code"] for item in fixture["cases"]}.issubset(PHASE5C_REASON_CODES)
    assert [item["case_id"] for item in fixture["cases"]] == [
        item["case_id"] for item in matrix["failure_modes"]
    ]


def test_formula_terms_replay_concepts_and_reviewed_inclusion_proof() -> None:
    common = next(item for item in _fact_decisions() if item.purpose == "common_equity")
    bindings = [dict(item) for item in common.term_bindings]
    inclusion = next(
        item for item in bindings if item["input_role"] == "included_non_common_equity_claims"
    )
    inclusion.update(
        {
            "inclusion_status": "not_required",
            "claim_id": None,
            "review_decision_id": None,
        }
    )
    with pytest.raises(ValueError, match="reviewed inclusion proof"):
        replace(common, term_bindings=tuple(bindings))

    bindings = [dict(item) for item in common.term_bindings]
    inclusion = next(
        item for item in bindings if item["input_role"] == "included_non_common_equity_claims"
    )
    inclusion.update(
        {
            "inclusion_status": "unresolved",
            "claim_id": None,
            "review_decision_id": None,
            "missing_evidence": ["non-common claim inclusion evidence"],
            "reason_codes": ["common_equity_perimeter_ambiguous"],
        }
    )
    blocked = replace(
        common,
        disposition="blocked",
        output_fact_id=None,
        calculation_id=None,
        term_bindings=tuple(bindings),
        reason_codes=("common_equity_perimeter_ambiguous",),
    )
    assert blocked.disposition == "blocked"

    bindings = [dict(item) for item in common.term_bindings]
    total = next(item for item in bindings if item["input_role"] == "total_equity")
    total["fact_ids"] = ["fact:marketable-securities"]
    bad_common = replace(
        common,
        input_fact_ids=("fact:marketable-securities",),
        root_fact_ids=("fact:marketable-securities",),
        term_bindings=tuple(bindings),
    )
    ledger = _reconciliation_ledger()
    output = next(item for item in ledger["facts"] if item["fact_id"] == "derived:common_equity")
    output["parent_fact_ids"] = ["fact:marketable-securities"]
    output["value"] = 10.0
    decisions = tuple(
        bad_common if item.purpose == "common_equity" else item for item in _fact_decisions()
    )
    with pytest.raises(ValueError, match="term Fact concept"):
        _reconciliation(ledger_payload=ledger, fact_decisions=decisions)


def test_method_adjustment_rejects_semantic_cross_source_and_ghost_roots() -> None:
    decision = MethodAdjustmentDecision(
        method="mckinsey",
        adjustment_id="adjustment:semantic",
        adjustment_group_id="group:semantic",
        category="lease",
        disposition="compiled",
        target_fact_id="derived:invested_capital",
        target_concept="invested_capital",
        target_bridge_role=None,
        amount_fact_id="derived:semantic-adjustment",
        source_fact_ids=("fact:lease_liability:zero",),
        root_fact_ids=("fact:lease_liability:zero",),
        evidence_source_ids=("doc:10k",),
        rationale="Registered assumption-free lease adjustment.",
        reason_codes=(),
        **_calculator_fields("adjustment:semantic"),
    )
    entries = {
        "mckinsey": [
            {
                "adjustment_id": decision.adjustment_id,
                "target_fact_id": decision.target_fact_id,
                "target_concept": decision.target_concept,
                "target_bridge_role": None,
                "amount_fact_id": decision.amount_fact_id,
            }
        ],
        "penman": [],
    }
    kwargs = {
        "issuer_id": "issuer:fixture",
        "data_cutoff_date": "2026-07-11",
        **_method_predecessor_fields((decision,)),
        "policy_id": PHASE5C_POLICY_ID,
        "policy_version": PHASE5C_POLICY_VERSION,
        "policy_sha256": phase5c_policy_sha256(),
        "adjustment_decisions": (decision,),
        "method_views": entries,
        "status_by_method": {"mckinsey": "pass", "penman": "pass"},
        "reason_codes": (),
    }
    valid_records = _method_consumption_records(kwargs["reconciliation_result"], (decision,))

    bad_unit = _method_ledger((decision,))
    next(item for item in bad_unit["facts"] if item["fact_id"] == decision.amount_fact_id)[
        "unit"
    ] = "percent"
    with pytest.raises(ValueError, match="monetary Fact unit semantics"):
        MethodViewCompilationResult(
            **kwargs,
            ledger_payload=bad_unit,
            consumption_records=valid_records,
        )

    share_input = _method_ledger((decision,))
    share_fact = next(
        item for item in share_input["facts"] if item["fact_id"] == "fact:lease_liability:zero"
    )
    share_fact.update(
        {
            "concept": "diluted_shares",
            "category": "share_count",
            "currency": None,
            "unit": "millions shares",
            "period_start": "2025-01-01",
        }
    )
    with pytest.raises(ValueError, match="does not replay accounting quality outputs"):
        MethodViewCompilationResult(
            **kwargs,
            ledger_payload=share_input,
            consumption_records=valid_records,
        )

    bad_target = _method_ledger((decision,))
    target_fact = next(
        item for item in bad_target["facts"] if item["fact_id"] == decision.target_fact_id
    )
    target_fact.update(
        {
            "category": "share_count",
            "currency": None,
            "unit": "millions shares",
        }
    )
    with pytest.raises(ValueError, match="registered concept semantics"):
        MethodViewCompilationResult(
            **kwargs,
            ledger_payload=bad_target,
            consumption_records=valid_records,
        )

    with pytest.raises(ValueError, match="calculator identity"):
        replace(decision, calculator_code_sha256="0" * 64)

    cross_source = _method_ledger((decision,))
    cross_source["sources"].append(
        {
            "source_id": "doc:other",
            "title": "Synthetic second 10-K",
            "publisher": "Fixture Issuer",
            "published_date": "2026-02-02",
            "retrieved_at": "2026-07-11T00:00:00+00:00",
            "locator": "fixture://other-10-k",
            "local_path": "/fixtures/other-10-k.json",
            "primary": True,
        }
    )
    next(item for item in cross_source["facts"] if item["fact_id"] == decision.amount_fact_id)[
        "source_id"
    ] = "doc:other"
    cross_source_decision = replace(
        decision,
        evidence_source_ids=("doc:10k", "doc:other"),
    )
    with pytest.raises(ValueError, match="predecessor binding does not replay"):
        MethodViewCompilationResult(
            **{**kwargs, "adjustment_decisions": (cross_source_decision,)},
            ledger_payload=cross_source,
            consumption_records=valid_records,
        )

    ghost_record = {
        "root_fact_id": "fact:ghost",
        "economic_claim_key": "0" * 64,
        "economic_identity": "method_base",
        "channel": "balance_sheet",
        "method": "mckinsey",
        "group_id": "group:validation",
        "consumption_kind": "validation",
    }
    with pytest.raises(ValueError, match="absent from the FactLedger"):
        MethodViewCompilationResult(
            **kwargs,
            ledger_payload=_method_ledger((decision,)),
            consumption_records=valid_records + (ghost_record,),
        )


def test_method_and_bridge_expand_transitive_raw_lineage() -> None:
    first = MethodAdjustmentDecision(
        method="mckinsey",
        adjustment_id="adjustment:first",
        adjustment_group_id="group:first",
        category="other",
        disposition="compiled",
        target_fact_id="fact:first-target",
        target_concept="invested_capital",
        target_bridge_role=None,
        amount_fact_id="derived:first-amount",
        source_fact_ids=("fact:shared-root",),
        root_fact_ids=("fact:shared-root",),
        evidence_source_ids=("doc:10k",),
        rationale="First registered use.",
        reason_codes=(),
        **_calculator_fields("adjustment:first"),
    )
    second = MethodAdjustmentDecision(
        method="mckinsey",
        adjustment_id="adjustment:second",
        adjustment_group_id="group:second",
        category="other",
        disposition="compiled",
        target_fact_id="fact:second-target",
        target_concept="invested_capital",
        target_bridge_role=None,
        amount_fact_id="derived:second-amount",
        source_fact_ids=("fact:alias-root",),
        root_fact_ids=("fact:alias-root",),
        evidence_source_ids=("doc:10k",),
        rationale="Alias must not hide a repeated raw root.",
        reason_codes=(),
        **_calculator_fields("adjustment:second"),
    )
    ledger = _method_ledger((first, second))
    alias = next(item for item in ledger["facts"] if item["fact_id"] == "fact:alias-root")
    alias.update(
        {
            "raw": False,
            "parent_fact_ids": ["fact:shared-root"],
            "derivation": "alias of shared raw root",
        }
    )
    entries = {
        "mckinsey": [
            {
                "adjustment_id": item.adjustment_id,
                "target_fact_id": item.target_fact_id,
                "target_concept": item.target_concept,
                "target_bridge_role": None,
                "amount_fact_id": item.amount_fact_id,
            }
            for item in (first, second)
        ],
        "penman": [],
    }
    records = tuple(
        {
            "root_fact_id": item.root_fact_ids[0],
            "economic_identity": "method_base",
            "channel": "mckinsey_invested_capital",
            "method": "mckinsey",
            "group_id": item.adjustment_group_id,
            "consumption_kind": "economic_deduction",
        }
        for item in (first, second)
    )
    with pytest.raises(ValueError, match="unrelated added Facts"):
        MethodViewCompilationResult(
            issuer_id="issuer:fixture",
            data_cutoff_date="2026-07-11",
            **_method_predecessor_fields((first, second)),
            policy_id=PHASE5C_POLICY_ID,
            policy_version=PHASE5C_POLICY_VERSION,
            policy_sha256=phase5c_policy_sha256(),
            ledger_payload=ledger,
            adjustment_decisions=(first, second),
            method_views=entries,
            consumption_records=records,
            status_by_method={"mckinsey": "pass", "penman": "pass"},
            reason_codes=(),
        )

    decisions = list(_role_decisions())
    index = next(i for i, item in enumerate(decisions) if item.role == "option_or_dilution_claim")
    decisions[index] = EquityBridgeRoleDecision(
        role="option_or_dilution_claim",
        status="modeled",
        fact_id="fact:option:aggregate",
        evidence_fact_ids=("fact:option:aggregate", "fact:option:alias-root"),
        root_fact_ids=("fact:option:alias-root",),
        claim_id=None,
        review_decision_id=None,
        rationale="Alias cannot hide diluted-share overlap.",
        missing_evidence=(),
        reason_codes=(),
    )
    bridge_ledger = _bridge_ledger(tuple(decisions))
    option_alias = next(
        item for item in bridge_ledger["facts"] if item["fact_id"] == "fact:option:alias-root"
    )
    option_alias.update(
        {
            "raw": False,
            "parent_fact_ids": ["fact:diluted-shares"],
            "derivation": "alias of diluted-share evidence",
        }
    )
    with pytest.raises(ValueError, match="may add only"):
        _bridge_result(decisions=tuple(decisions), ledger_payload=bridge_ledger)


def test_bridge_replays_official_zero_and_assertion_rationale() -> None:
    result = _bridge_result()
    assertions = [dict(item) for item in result.role_assertions]
    assertions[0]["rationale"] = "Caller supplied a different rationale."
    with pytest.raises(ValueError, match="does not replay"):
        _bridge_result(role_assertions=tuple(assertions))

    ledger = _bridge_ledger(_role_decisions())
    zero = next(item for item in ledger["facts"] if item["fact_id"] == "fact:lease_liability:zero")
    zero.update(
        {
            "raw": False,
            "parent_fact_ids": ["fact:debt:current"],
            "derivation": "manufactured zero",
        }
    )
    with pytest.raises(ValueError, match="does not preserve MethodView evidence"):
        _bridge_result(ledger_payload=ledger)

    wrong_aggregate = _bridge_ledger(_role_decisions())
    next(item for item in wrong_aggregate["facts"] if item["fact_id"] == "fact:debt:aggregate")[
        "value"
    ] = 999999.0
    with pytest.raises(ValueError, match="does not replay root magnitudes"):
        _bridge_result(ledger_payload=wrong_aggregate)


def test_equity_bridge_cannot_add_late_raw_fact_or_source() -> None:
    late_fact = _bridge_ledger(_role_decisions())
    late_fact["facts"].append(
        _kernel_fact(
            "fact:late-debt-root",
            concept="interest_bearing_debt",
            value=5.0,
            category="financing",
        )
    )
    with pytest.raises(ValueError, match="may add only"):
        _bridge_result(ledger_payload=late_fact)

    late_source = _bridge_ledger(_role_decisions())
    late_source["sources"].append(
        {
            **late_source["sources"][0],
            "source_id": "doc:late-10q",
            "local_path": "/fixtures/late-10q.json",
        }
    )
    with pytest.raises(ValueError, match="late evidence source"):
        _bridge_result(ledger_payload=late_source)


def test_accounting_predecessor_cannot_pre_tag_bridge_fact() -> None:
    ledger = _reconciliation_ledger()
    debt = next(item for item in ledger["facts"] if item["fact_id"] == "fact:debt:current")
    debt["equity_bridge_role"] = "debt"
    with pytest.raises(ValueError, match="cannot pre-tag"):
        _reconciliation(ledger_payload=ledger)


def test_method_view_deduplicates_same_disclosed_claim_across_fact_ids() -> None:
    reconciliation = _reconciliation()
    bindings = [dict(item) for item in reconciliation.economic_claim_bindings]
    lease = next(item for item in bindings if item["economic_identity"] == "lease_liability")
    debt_equivalent = next(
        item for item in bindings if item["economic_identity"] == "debt_equivalent"
    )
    for field in (
        "identity_kind",
        "identity_value",
        "scope_id",
        "measurement_end",
        "security_class",
        "economic_claim_key",
    ):
        debt_equivalent[field] = lease[field]
    with pytest.raises(ValueError, match="does not replay reviewed evidence"):
        replace(reconciliation, economic_claim_bindings=tuple(bindings))


def test_kernel_quality_gate_mismatch_is_explicit_and_fail_closed() -> None:
    reconciliation = _reconciliation()
    decision = {
        "finding_id": "finding:lease-only",
        "finding_fingerprint": "placeholder",
        "finding_status": "confirmed",
        "final_severity": "red_flag",
        "evidence_state": "confirmed_red_flag",
        "category": "lease_commitments",
        "disposition": "material_unresolved",
        "material": True,
        "resolved": False,
        "evidence_fact_ids": ["fact:lease_liability:zero"],
        "claim_id": "claim:lease-only",
        "review_decision_id": "decision:lease-only",
        "reason_codes": [],
    }
    review, findings = _quality_contracts((decision,))
    decision["finding_fingerprint"] = findings[0].fingerprint
    statuses = {"mckinsey": "blocked", "penman": "pass"}
    result = AccountingQualityCompilationResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        reconciliation_fingerprint=reconciliation.fingerprint,
        reconciliation_result=reconciliation,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        accounting_quality_review_id=review.review_id,
        accounting_quality_review_fingerprint=review.fingerprint,
        accounting_quality_review_status=review.status,
        accounting_quality_review=review,
        accounting_quality_findings=findings,
        ledger_payload=reconciliation.ledger_payload,
        adjustment_decisions=(),
        expected_finding_ids=review.finding_ids,
        issue_decisions=(decision,),
        kernel_quality_issues=(
            {
                "issue_id": "finding:lease-only",
                "category": "lease_commitments",
                "material": True,
                "resolved": False,
                "evidence_fact_ids": ["fact:lease_liability:zero"],
            },
        ),
        kernel_gate_status="blocked",
        **_kernel_quality_compatibility(
            kernel_gate_status="blocked",
            status_by_method=statuses,
        ),
        unresolved_material_issue_ids=("finding:lease-only",),
        status="blocked",
        status_by_method=statuses,
        missing_evidence=(),
        reason_codes=("accounting_quality_material_unresolved",),
    )
    assert result.kernel_gate_scope == "global"
    assert result.kernel_execution_compatibility_by_method == {
        "mckinsey": False,
        "penman": False,
    }
    assert result.kernel_incompatibility_reason_codes["mckinsey"] == (
        "pinned_kernel_quality_gate_underblocks_mckinsey",
    )
    assert result.kernel_incompatibility_reason_codes["penman"] == (
        "pinned_kernel_global_gate_overblocks_penman",
    )


def test_stable_capital_structure_rejects_placeholders_and_invalid_review_chain() -> None:
    predecessors, graph = _readiness_case()
    valid = Phase5CReadinessResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        **predecessors,
        policy_id=PHASE5C_POLICY_ID,
        policy_version=PHASE5C_POLICY_VERSION,
        policy_sha256=phase5c_policy_sha256(),
        specialist_route="none",
        upstream_statuses=_upstream_statuses(),
        routing_assessments=_readiness_assessments(),
        method_panels={"mckinsey": _panel("mckinsey"), "penman": _panel("penman")},
    )
    assessments = valid.to_dict()["routing_assessments"]
    assessments["stable_capital_structure"]["evidence_role_bindings"][
        "three_comparable_annual_debt_cash_common_equity_snapshots"
    ] = ["snapshot:2023", "snapshot:2024", "snapshot:2025"]
    with pytest.raises(ValueError, match="snapshot bindings"):
        replace(valid, routing_assessments=assessments, validation_graph=graph)

    with pytest.raises(ValueError, match="FootnoteReview"):
        replace(
            valid,
            validation_graph=graph,
            stable_capital_footnote_review=replace(
                valid.stable_capital_footnote_review,
                topic_code="sbc",
            ),
        )

    with pytest.raises(ValueError, match="Claim review chain"):
        replace(
            valid,
            validation_graph=graph,
            stable_capital_claim_review_decision=replace(
                valid.stable_capital_claim_review_decision,
                candidate_fingerprint="0" * 64,
            ),
        )


def test_phase5c_context_replays_phase5b_fact_bytes_against_bundle_graph() -> None:
    preliminary = _readiness_predecessor_fields()
    graph = _phase5c_research_graph(preliminary)
    tampered_facts = tuple(
        replace(item, value=float(item.value) + 999.0) if item.fact_id == "fact:debt:2023" else item
        for item in graph.facts
    )
    tampered_graph = _rebuild_bundle_graph(replace(graph, facts=tampered_facts))
    bundle = tampered_graph.research_bundles[0]
    old_mapping, _ = _compiled_phase5b_pair(graph)
    stale_mapping = replace(
        old_mapping,
        research_bundle_id=bundle.bundle_id,
        research_bundle_fingerprint=bundle.bundle_fingerprint,
        dependency_closure_sha256=bundle.dependency_closure_sha256,
        component_lock_sha256=bundle.component_lock_sha256,
    )
    stale_readiness = assess_method_readiness(
        graph=tampered_graph,
        mapping_result=stale_mapping,
    )
    fields = _readiness_predecessor_fields(
        phase5b_pair=(stale_mapping, stale_readiness),
    )
    with pytest.raises(ValueError, match="Phase 5B FactLedger mapping"):
        _validate_research_context(**_context_args(fields, tampered_graph))


@pytest.mark.parametrize(
    ("field_name", "tampered_value"),
    (
        ("value", 999999),
        ("concept", "revenue"),
        ("unit", "USD billions"),
        ("category", "accounting"),
        ("source_id", "doc:ghost"),
        ("source_location", "calculation_id=tampered"),
        ("as_of_date", "2025-12-30"),
        ("currency", "EUR"),
        ("period_start", "2025-09-01"),
        ("period_end", "2025-12-30"),
        ("confidence", "medium"),
        ("parent_fact_ids", []),
        ("derivation", "caller-authored"),
        ("equity_bridge_role", "debt"),
        ("raw", True),
    ),
)
def test_phase5c_rejects_every_derived_phase5b_fact_semantic_tamper(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
    field_name: str,
    tampered_value: object,
) -> None:
    from test_phase5b1_raw_fact_compiler import KERNEL, _artifacts
    from test_phase5b2_derived_lineage import _registered_calculation_graph

    from owner_research.research_bundle_validation import dependency_closure
    from owner_research.valuation_fact_mapping import compile_price_blind_fact_ledger

    graph, calculation_id, _ = _registered_calculation_graph(sample_payloads)
    mapping = compile_price_blind_fact_ledger(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )
    build = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    roots = tuple(
        object_id
        for reference in build.bundle.module_references
        for object_id in reference["object_ids"]
    )
    closure = dependency_closure(graph, roots)
    _validate_phase5b_mapping_replay(
        graph=graph,
        bundle_closure=closure,
        mapping_result=mapping,
    )

    payload = to_json_value(mapping.ledger_payload)
    derived = next(
        item for item in payload["facts"] if item["fact_id"] == f"derived:{calculation_id}"
    )
    derived[field_name] = tampered_value
    tampered = replace(mapping, ledger_payload=payload)
    with pytest.raises(ValueError, match="Phase 5B"):
        _validate_phase5b_mapping_replay(
            graph=graph,
            bundle_closure=closure,
            mapping_result=tampered,
        )


@pytest.mark.parametrize(
    "tamper_mode",
    (
        "drop_mapped_fact_and_decision",
        "flip_mapped_decision_to_excluded",
        "add_closure_external_decision",
        "drop_closure_excluded_decision",
        "change_mapped_decision_reason",
    ),
)
def test_phase5c_rejects_phase5b_mapping_decision_or_output_set_tamper(
    sample_payloads: dict[str, dict],
    tmp_path: Path,
    tamper_mode: str,
) -> None:
    from test_phase5b1_raw_fact_compiler import KERNEL, _artifacts
    from test_phase5b2_derived_lineage import _registered_calculation_graph

    from owner_research.research_bundle_validation import dependency_closure

    graph, calculation_id, _ = _registered_calculation_graph(sample_payloads)
    mapping = compile_price_blind_fact_ledger(
        bundle_artifact_directory=_artifacts(graph, tmp_path / "bundle"),
        graph=graph,
        kernel_repository=KERNEL,
    )
    build = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    roots = tuple(
        object_id
        for reference in build.bundle.module_references
        for object_id in reference["object_ids"]
    )
    closure = dependency_closure(graph, roots)
    payload = to_json_value(mapping.ledger_payload)
    decisions = list(mapping.decisions)
    derived_id = f"derived:{calculation_id}"
    mapped_index = next(
        index
        for index, item in enumerate(decisions)
        if item.object_type == "CalculationResult" and item.object_id == calculation_id
    )
    if tamper_mode in {
        "drop_mapped_fact_and_decision",
        "flip_mapped_decision_to_excluded",
    }:
        payload["facts"] = [item for item in payload["facts"] if item["fact_id"] != derived_id]
    if tamper_mode == "drop_mapped_fact_and_decision":
        decisions.pop(mapped_index)
    elif tamper_mode == "flip_mapped_decision_to_excluded":
        decisions[mapped_index] = FactMappingDecision(
            object_type="CalculationResult",
            object_id=calculation_id,
            disposition="excluded",
            reason_codes=("calculation_not_registered",),
        )
    elif tamper_mode == "add_closure_external_decision":
        decisions.append(
            FactMappingDecision(
                object_type="Fact",
                object_id="fact:closure-external-ghost",
                disposition="excluded",
                reason_codes=("concept_not_registered",),
            )
        )
    elif tamper_mode == "drop_closure_excluded_decision":
        excluded_index = next(
            index for index, item in enumerate(decisions) if item.disposition == "excluded"
        )
        decisions.pop(excluded_index)
    elif tamper_mode == "change_mapped_decision_reason":
        current = decisions[mapped_index]
        decisions[mapped_index] = FactMappingDecision(
            object_type=current.object_type,
            object_id=current.object_id,
            disposition=current.disposition,
            reason_codes=("future_evidence",),
            output_id=current.output_id,
        )
    tampered = replace(
        mapping,
        ledger_payload=payload,
        decisions=tuple(decisions),
    )
    with pytest.raises(ValueError, match="Phase 5B"):
        _validate_phase5b_mapping_replay(
            graph=graph,
            bundle_closure=closure,
            mapping_result=tampered,
        )


@pytest.mark.parametrize(
    "tamper_mode",
    (
        "classification_rationale",
        "routing_assessment",
        "method_evidence",
    ),
)
def test_phase5c_rejects_self_consistent_phase5b_readiness_semantic_tamper(
    tamper_mode: str,
) -> None:
    fields, graph = _readiness_case()
    reconciliation = fields["reconciliation_result"]
    assert isinstance(reconciliation, AccountingReconciliationResult)
    mapping = reconciliation.phase5b_mapping_result
    readiness = reconciliation.phase5b_readiness_result
    _validate_phase5b_readiness_replay(
        graph=graph,
        mapping_result=mapping,
        readiness_result=readiness,
    )
    if tamper_mode == "classification_rationale":
        classification = replace(
            readiness.classification,
            rationale="Caller-authored but internally self-consistent classification.",
        )
        tampered = replace(readiness, classification=classification)
    elif tamper_mode == "routing_assessment":
        assessments = to_json_value(readiness.classification.routing_assessments)
        assessments["required_data_complete"]["rationale"] = "Caller-authored routing rationale."
        classification = replace(
            readiness.classification,
            routing_assessments=assessments,
        )
        tampered = replace(readiness, classification=classification)
    else:
        tampered = replace(
            readiness,
            mckinsey=replace(
                readiness.mckinsey,
                evidence_fact_ids=("fact:caller-selected",),
            ),
        )
    with pytest.raises(ValueError, match="method readiness"):
        _validate_phase5b_readiness_replay(
            graph=graph,
            mapping_result=mapping,
            readiness_result=tampered,
        )


def test_phase5c_context_rejects_any_market_reference_in_full_graph() -> None:
    fields, graph = _readiness_case()
    market_document = replace(
        graph.documents[0],
        document_id="doc:market:fixture",
        document_type="market-quote",
        period={"start": "2026-07-10", "end": "2026-07-10"},
        published_date="2026-07-10",
        retrieved_at="2026-07-10T21:00:00+00:00",
        source_url="https://market.example.com/fixture",
        authority_level="market_reference",
        content_sha256="9" * 64,
    )
    with pytest.raises(ValueError, match="entirely price blind"):
        _validate_research_context(
            **_context_args(fields, replace(graph, documents=(*graph.documents, market_document)))
        )


def test_phase5c_context_ignores_unrelated_nonmarket_history() -> None:
    fields, graph = _readiness_case()
    historical_document = replace(
        graph.documents[0],
        document_id="doc:historical-unrelated",
        period={"start": "2010-01-01", "end": "2010-12-31"},
        published_date="2011-02-01",
        retrieved_at="2011-02-02T00:00:00+00:00",
        source_url="https://www.sec.gov/Archives/edgar/data/1/historical.htm",
        content_sha256="8" * 64,
    )
    historical_manifest = replace(
        graph.manifests[0],
        input_document_hashes={
            **dict(graph.manifests[0].input_document_hashes),
            historical_document.document_id: historical_document.content_sha256,
        },
    )
    historical_graph = replace(
        graph,
        documents=(*graph.documents, historical_document),
        manifests=(historical_manifest,),
    )
    replay = _validate_research_context(**_context_args(fields, historical_graph))
    assert replay == (
        fields["validated_research_context_sha256"],
        fields["stable_capital_evidence_closure_sha256"],
        fields["stable_capital_annual_bindings"],
    )


def test_phase5c_context_rejects_missing_source_search_receipts() -> None:
    fields, graph = _readiness_case()
    with pytest.raises(ValueError, match="deterministic replay"):
        _validate_research_context(
            **_context_args(fields, replace(graph, source_search_receipts=()))
        )


def test_phase5c_context_rejects_evidence_outside_frozen_bundle_closure() -> None:
    fields, graph = _readiness_case()
    candidate = fields["stable_capital_claim_candidate"]
    claim = fields["stable_capital_claim"]
    decision = fields["stable_capital_claim_review_decision"]
    assert isinstance(candidate, AnalyticalClaimCandidate)
    assert isinstance(claim, Claim)
    assert isinstance(decision, AnalyticalClaimReviewDecision)
    outside_fact = Fact(
        schema_version="2.0.0",
        fact_id="fact:outside-frozen-bundle",
        issuer_id="issuer:fixture",
        concept="interest_bearing_debt",
        value_type="number",
        value=1.0,
        unit="currency_millions",
        currency="USD",
        period={"start": None, "end": "2025-12-31"},
        source_document_id="doc:10k",
        source_locator="fixture:outside-frozen-bundle",
        derivation=None,
        parent_fact_ids=(),
        confidence="high",
    )
    outside_binding = {
        "binding_id": "binding:outside-frozen-bundle",
        "fact_id": outside_fact.fact_id,
        "calculation_result_id": None,
        "context_observation_id": None,
    }
    bindings = (*candidate.supporting_evidence_bindings, outside_binding)
    evidence_sha = canonical_sha256(
        {
            "supporting_evidence_bindings": bindings,
            "counterevidence_bindings": candidate.counterevidence_bindings,
        }
    )
    changed_candidate = replace(
        candidate,
        supporting_evidence_bindings=bindings,
        evidence_graph_sha256=evidence_sha,
    )
    changed_claim = replace(
        claim,
        supporting_fact_ids=(*claim.supporting_fact_ids, outside_fact.fact_id),
    )
    changed_decision = replace(
        decision,
        candidate_fingerprint=changed_candidate.fingerprint,
        evidence_graph_sha256=evidence_sha,
    )
    changed_graph = replace(
        graph,
        facts=(*graph.facts, outside_fact),
        claims=tuple(
            changed_claim if item.claim_id == claim.claim_id else item for item in graph.claims
        ),
        analytical_claim_candidates=tuple(
            changed_candidate if item.candidate_id == candidate.candidate_id else item
            for item in graph.analytical_claim_candidates
        ),
        analytical_claim_review_decisions=tuple(
            changed_decision if item.decision_id == decision.decision_id else item
            for item in graph.analytical_claim_review_decisions
        ),
    )
    changed_args = _context_args(fields, changed_graph)
    changed_args.update(
        {
            "stable_claim": changed_claim,
            "stable_candidate": changed_candidate,
            "stable_decision": changed_decision,
        }
    )
    with pytest.raises(ValueError, match="outside ResearchBundle closure"):
        _validate_research_context(**changed_args)


def test_equity_bridge_not_applicable_rejects_ghost_review_ids() -> None:
    decisions = list(_role_decisions())
    index = next(index for index, item in enumerate(decisions) if item.role == "nonoperating_asset")
    decisions[index] = replace(
        decisions[index],
        status="not_applicable",
        claim_id="claim:ghost",
        review_decision_id="decision:ghost",
    )
    with pytest.raises(ValueError, match="exactly match one reviewed Claim chain"):
        _bridge_result(decisions=tuple(decisions))


def test_blocked_economic_claim_binding_forces_blocked_reconciliation() -> None:
    reconciliation = _reconciliation()
    bindings = [dict(item) for item in reconciliation.economic_claim_bindings]
    target = next(item for item in bindings if item["economic_identity"] == "lease_liability")
    reviewed_claim_id = target["claim_id"]
    target["status"] = "blocked"
    target["economic_claim_key"] = None
    target["claim_id"] = None
    target["missing_evidence"] = ["instrument identity conflict"]
    target["reason_codes"] = ["economic_claim_identity_unresolved"]
    decisions = tuple(
        replace(item, decision="blocked", output_claim_id=None, issues=("identity conflict",))
        if item.decision_id == target["review_decision_id"]
        else item
        for item in reconciliation.economic_claim_review_decisions
    )
    claims = tuple(
        item for item in reconciliation.economic_claims if item.claim_id != reviewed_claim_id
    )
    with pytest.raises(ValueError, match="status is not deterministic"):
        replace(
            reconciliation,
            economic_claim_bindings=tuple(bindings),
            economic_claim_review_decisions=decisions,
            economic_claims=claims,
        )


def test_stable_capital_accepts_a_consistent_52_53_week_chain() -> None:
    windows = (
        (2023, "2022-01-30", "2023-01-28", "2022-10-30", 13),
        (2024, "2023-01-29", "2024-02-03", "2023-10-29", 14),
        (2025, "2024-02-04", "2025-02-01", "2024-11-03", 13),
    )
    source = SourceDocument(
        schema_version="1.0.0",
        document_id="doc:10k",
        issuer_id="issuer:fixture",
        document_type="10-K",
        period={"start": "2022-01-30", "end": "2025-02-01"},
        published_date="2025-03-01",
        retrieved_at="2025-03-02T00:00:00+00:00",
        source_url="https://www.sec.gov/Archives/edgar/data/1/fixture10-k.htm",
        authority_level="primary_regulatory",
        content_sha256="1" * 64,
    )
    kernel_facts: list[dict[str, object]] = []
    research_facts: list[Fact] = []
    periods: list[FiscalPeriod] = []
    for index, (year, start, end, quarter_start, weeks) in enumerate(windows):
        for role, concept, value in (
            ("debt", "interest_bearing_debt", 40.0 + index),
            ("cash", "cash_and_cash_equivalents", 10.0 + index),
            ("equity", "common_equity", 80.0 + index),
        ):
            fact_id = f"fact:{role}:{year}"
            kernel_facts.append(
                _kernel_fact(
                    fact_id,
                    concept=concept,
                    value=value,
                    category=PHASE5B_CONCEPT_POLICIES[concept].category,
                    period_end=end,
                )
            )
            research_facts.append(
                Fact(
                    schema_version="2.0.0",
                    fact_id=fact_id,
                    issuer_id="issuer:fixture",
                    concept=concept,
                    value_type="number",
                    value=value,
                    unit="currency_millions",
                    currency="USD",
                    period={"start": None, "end": end},
                    source_document_id="doc:10k",
                    source_locator=f"fixture:{fact_id}",
                    derivation=None,
                    parent_fact_ids=(),
                    confidence="high",
                )
            )
        periods.append(
            FiscalPeriod(
                schema_version="1.0.0",
                period_id=f"fiscal-period:{year}",
                issuer_id="issuer:fixture",
                fiscal_year=year,
                fiscal_quarter=4,
                calendar_type="52_53_week",
                quarter_start=quarter_start,
                quarter_end=end,
                cumulative_start=start,
                cumulative_end=end,
                ttm_start=start,
                weeks=weeks,
                comparative_period_id=(None if index == 0 else f"fiscal-period:{year - 1}"),
                restatement_version=0,
                status="reported",
                source_document_ids=("doc:10k",),
            )
        )
    ledger = _ledger_payload(tuple(kernel_facts))
    mapping = FactLedgerMappingResult(
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        research_bundle_id="research-bundle:52-53",
        research_bundle_fingerprint="a" * 64,
        dependency_closure_sha256="b" * 64,
        component_lock_sha256="c" * 64,
        mapping_policy_id=MAPPING_POLICY_ID,
        mapping_policy_version=MAPPING_POLICY_VERSION,
        mapping_policy_sha256=mapping_policy_sha256(),
        kernel_fact_ledger_schema_sha256=PINNED_FACT_LEDGER_SCHEMA_SHA256,
        ledger_payload=ledger,
        decisions=(
            FactMappingDecision("SourceDocument", "doc:10k", "mapped", (), "doc:10k"),
            *(
                FactMappingDecision("Fact", item["fact_id"], "mapped", (), item["fact_id"])
                for item in kernel_facts
            ),
        ),
    )
    graph = ContractGraph(
        documents=(source,),
        facts=tuple(research_facts),
        periods=tuple(periods),
        component_lock_path=ROOT / "component-lock.json",
    )
    bindings = _expected_annual_capital_bindings(
        graph=graph,
        ledger_payload=mapping.ledger_payload,
        issuer_id="issuer:fixture",
        data_cutoff_date="2026-07-11",
        allowed_fiscal_period_ids={item.period_id for item in periods},
        phase5b_mapping_result=mapping,
        selected_phase5c_input_fact_ids=set(),
    )
    assert [item["calendar_type"] for item in bindings] == ["52_53_week"] * 3
    assert [item["period_end"] for item in bindings] == [
        "2023-01-28",
        "2024-02-03",
        "2025-02-01",
    ]


def test_included_option_claim_is_excluded_from_penman_nfo_and_bridge() -> None:
    option_fact_id = "fact:option_or_dilution_claim:zero"
    ledger = _reconciliation_ledger()
    ledger_facts = {item["fact_id"]: dict(item) for item in ledger["facts"]}
    ledger_facts[option_fact_id]["value"] = 12.0

    original_decisions = _fact_decisions()
    decisions: list[AccountingFactDecision] = []
    for decision in original_decisions:
        if decision.purpose != "net_financial_obligations":
            decisions.append(decision)
            continue
        term_bindings = []
        for binding in decision.term_bindings:
            item = dict(binding)
            item["fact_ids"] = tuple(
                fact_id for fact_id in item["fact_ids"] if fact_id != option_fact_id
            )
            term_bindings.append(item)
        decisions.append(
            replace(
                decision,
                input_fact_ids=tuple(
                    fact_id for fact_id in decision.input_fact_ids if fact_id != option_fact_id
                ),
                root_fact_ids=tuple(
                    fact_id for fact_id in decision.root_fact_ids if fact_id != option_fact_id
                ),
                term_bindings=tuple(term_bindings),
            )
        )
    fact_decisions = tuple(decisions)
    nfo_decision = next(
        item for item in fact_decisions if item.purpose == "net_financial_obligations"
    )
    ledger_facts["derived:net_financial_obligations"]["parent_fact_ids"] = list(
        nfo_decision.input_fact_ids
    )
    ledger = _ledger_payload(tuple(ledger_facts.values()))

    contracts = _economic_claim_contracts(ledger, original_decisions)
    bindings = [dict(item) for item in contracts["economic_claim_bindings"]]
    option_binding = next(
        item for item in bindings if item["economic_identity"] == "option_or_dilution_claim"
    )
    option_binding["diluted_share_treatment"] = "included"
    option_binding["diluted_share_fact_ids"] = ["fact:diluted-shares"]

    candidates = list(contracts["economic_claim_candidates"])
    claims = list(contracts["economic_claims"])
    review_decisions = list(contracts["economic_claim_review_decisions"])
    candidate_index = next(
        index
        for index, item in enumerate(candidates)
        if item.candidate_id == option_binding["candidate_id"]
    )
    claim_index = next(
        index for index, item in enumerate(claims) if item.claim_id == option_binding["claim_id"]
    )
    decision_index = next(
        index
        for index, item in enumerate(review_decisions)
        if item.decision_id == option_binding["review_decision_id"]
    )
    candidate = candidates[candidate_index]
    diluted_binding = {
        "binding_id": "binding:economic-option:diluted-shares",
        "fact_id": "fact:diluted-shares",
        "calculation_result_id": None,
        "context_observation_id": None,
    }
    supporting = (*candidate.supporting_evidence_bindings, diluted_binding)
    evidence_sha = canonical_sha256(
        {
            "supporting_evidence_bindings": supporting,
            "counterevidence_bindings": candidate.counterevidence_bindings,
        }
    )
    statement = _economic_claim_review_statement(option_binding)
    candidates[candidate_index] = replace(
        candidate,
        proposed_statement=statement,
        supporting_evidence_bindings=supporting,
        evidence_graph_sha256=evidence_sha,
    )
    claims[claim_index] = replace(
        claims[claim_index],
        statement=statement,
        supporting_fact_ids=tuple(
            sorted(
                {
                    *claims[claim_index].supporting_fact_ids,
                    "fact:diluted-shares",
                }
            )
        ),
    )
    review_decisions[decision_index] = replace(
        review_decisions[decision_index],
        candidate_fingerprint=candidates[candidate_index].fingerprint,
        evidence_graph_sha256=evidence_sha,
    )
    economic_contracts = {
        "economic_claim_bindings": tuple(bindings),
        "economic_claim_candidates": tuple(candidates),
        "economic_claim_review_decisions": tuple(review_decisions),
        "economic_claims": tuple(claims),
    }

    noa_check = _check("noa_nfo_common_equity")
    noa_check["root_fact_ids"].remove(option_fact_id)
    noa_check["stock_root_fact_ids"]["net_financial_obligations"].remove(option_fact_id)
    reconciliation = _reconciliation(
        ledger_payload=ledger,
        fact_decisions=fact_decisions,
        economic_claim_contracts=economic_contracts,
        checks={
            "balance_sheet": _check("balance_sheet"),
            "clean_surplus": _check("clean_surplus"),
            "noa_nfo_common_equity": noa_check,
        },
    )
    assert option_fact_id not in nfo_decision.root_fact_ids

    quality = _quality_result(reconciliation)
    method_view = _empty_method_view(
        ledger,
        reconciliation_result=reconciliation,
        quality_result=quality,
    )
    bridge_decisions = list(_role_decisions())
    option_index = next(
        index
        for index, item in enumerate(bridge_decisions)
        if item.role == "option_or_dilution_claim"
    )
    bridge_decisions[option_index] = EquityBridgeRoleDecision(
        role="option_or_dilution_claim",
        status="not_applicable",
        fact_id=None,
        evidence_fact_ids=(option_fact_id,),
        root_fact_ids=(option_fact_id,),
        claim_id=option_binding["claim_id"],
        review_decision_id=option_binding["review_decision_id"],
        rationale="The reviewed option claim is already included in diluted shares.",
        missing_evidence=(),
        reason_codes=(),
    )
    selected_bridge_decisions = tuple(bridge_decisions)
    bridge_facts = {item["fact_id"]: dict(item) for item in method_view.ledger_payload["facts"]}
    bridge_facts["fact:debt:aggregate"] = _kernel_fact(
        "fact:debt:aggregate",
        concept="interest_bearing_debt",
        value=60.0,
        category="financing",
        raw=False,
        parent_fact_ids=("fact:debt:current", "fact:debt:noncurrent"),
        equity_bridge_role="debt",
        derivation=BRIDGE_AGGREGATE_DERIVATIONS["debt"],
    )
    bridge = _bridge_result(
        decisions=selected_bridge_decisions,
        ledger_payload=_ledger_payload(tuple(bridge_facts.values())),
        method_view_result=method_view,
    )
    assert bridge.status == "complete"
    assert all(
        item["root_fact_id"] != option_fact_id or item["channel"].endswith("_diluted_shares")
        for item in bridge.consumption_records
        if item["method"] == "penman"
    )


def test_blocked_account_role_preserves_confirmed_sibling_role() -> None:
    blocked_account = AccountClassificationDecision(
        fact_id="fact:operating-assets",
        concept="operating_assets",
        status="blocked",
        account_role="unresolved",
        classification_basis="unresolved",
        classification_claim_id=None,
        review_decision_id=None,
        aggregation_set_id=None,
        aggregation_level=None,
        root_fact_ids=(),
        reason_codes=("account_role_evidence_missing",),
        rationale="Operating-asset role evidence is unresolved.",
    )
    assert blocked_account.status == "blocked"
    decision = AccountingFactDecision(
        purpose="net_operating_assets",
        disposition="blocked",
        output_fact_id=None,
        calculation_id=None,
        input_fact_ids=("fact:operating-liabilities",),
        root_fact_ids=("fact:operating-liabilities",),
        term_bindings=(
            {
                "input_role": "operating_asset_components",
                "fact_ids": [],
                "inclusion_status": "unresolved",
                "claim_id": None,
                "review_decision_id": None,
                "missing_evidence": ["operating asset classification"],
                "reason_codes": ["account_role_evidence_missing"],
            },
            {
                "input_role": "operating_liability_components",
                "fact_ids": ["fact:operating-liabilities"],
                "inclusion_status": "not_required",
                "claim_id": None,
                "review_decision_id": None,
                "missing_evidence": [],
                "reason_codes": [],
            },
        ),
        lineage_status="independent_inputs",
        reason_codes=("account_role_evidence_missing",),
    )
    binding_by_role = {item["input_role"]: item for item in decision.term_bindings}
    assert binding_by_role["operating_asset_components"]["inclusion_status"] == ("unresolved")
    assert binding_by_role["operating_liability_components"]["inclusion_status"] == ("not_required")
    assert not binding_by_role["operating_liability_components"]["missing_evidence"]


def test_duplicate_reviewed_economic_claim_key_is_rejected() -> None:
    reconciliation = _reconciliation()
    bindings = [dict(item) for item in reconciliation.economic_claim_bindings]
    method_bindings = [item for item in bindings if item["economic_identity"] == "method_base"]
    assert len(method_bindings) >= 2
    first, duplicate = method_bindings[:2]
    duplicate["identity_value"] = first["identity_value"]
    duplicate["economic_claim_key"] = first["economic_claim_key"]

    candidates = list(reconciliation.economic_claim_candidates)
    claims = list(reconciliation.economic_claims)
    decisions = list(reconciliation.economic_claim_review_decisions)
    candidate_index = next(
        index
        for index, item in enumerate(candidates)
        if item.candidate_id == duplicate["candidate_id"]
    )
    claim_index = next(
        index for index, item in enumerate(claims) if item.claim_id == duplicate["claim_id"]
    )
    decision_index = next(
        index
        for index, item in enumerate(decisions)
        if item.decision_id == duplicate["review_decision_id"]
    )
    statement = _economic_claim_review_statement(duplicate)
    candidates[candidate_index] = replace(candidates[candidate_index], proposed_statement=statement)
    claims[claim_index] = replace(claims[claim_index], statement=statement)
    decisions[decision_index] = replace(
        decisions[decision_index],
        candidate_fingerprint=candidates[candidate_index].fingerprint,
    )
    with pytest.raises(ValueError, match="multiple bindings"):
        replace(
            reconciliation,
            economic_claim_bindings=tuple(bindings),
            economic_claim_candidates=tuple(candidates),
            economic_claim_review_decisions=tuple(decisions),
            economic_claims=tuple(claims),
        )
