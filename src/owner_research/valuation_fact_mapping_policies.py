"""Closed Phase 5B research-to-kernel mapping registries.

These registries describe eligibility only.  They do not select evidence, compile a
FactLedger, create valuation assumptions, access market data, or invoke the valuation
kernel.
"""

from __future__ import annotations

from dataclasses import dataclass

from .fingerprints import canonical_sha256

MAPPING_POLICY_ID = "research-to-kernel-fact-mapping"
MAPPING_POLICY_VERSION = "1.0.0"
PINNED_FACT_LEDGER_SCHEMA_SHA256 = (
    "55be5aadad21629db1cdbe7fce386656eb930b52af8644d1314ba7404e384706"
)

MAPPING_DISPOSITIONS = frozenset({"mapped", "excluded", "blocked"})
READINESS_STATUSES = frozenset(
    {"ready", "partial", "specialist_required", "blocked"}
)
SPECIALIST_ROUTES = frozenset(
    {
        "none",
        "financial_institution",
        "sum_of_parts",
        "nav_or_asset",
        "distress_or_apv",
        "unresolved",
    }
)

REASON_CODES = frozenset(
    {
        "bundle_artifacts_required",
        "bundle_graph_mismatch",
        "component_lock_mismatch",
        "source_not_official",
        "source_identity_incomplete",
        "fact_not_numeric",
        "future_evidence",
        "cross_issuer_evidence",
        "confidence_too_low",
        "concept_not_registered",
        "period_invalid",
        "publication_date_is_not_measurement_date",
        "reporting_currency_unresolved",
        "currency_mismatch",
        "unit_not_registered",
        "unit_semantics_mismatch",
        "segment_scope_not_supported",
        "raw_derivation_not_allowed",
        "duplicate_equivalent",
        "superseded_by_authoritative_fact",
        "conflicting_current_fact",
        "restatement_chain_unresolved",
        "source_unused_by_mapped_fact",
        "calculation_not_registered",
        "calculation_uses_assumption",
        "calculation_fingerprint_mismatch",
        "calculation_source_ambiguous",
        "lineage_incomplete",
        "lineage_cycle",
        "forbidden_evidence_domain",
        "company_classification_unresolved",
        "specialist_route_required",
        "required_role_missing",
        "phase5c_confirmation_pending",
    }
)

CLASSIFICATION_POLICY_ID = "valuation-company-classification"
CLASSIFICATION_POLICY_VERSION = "1.0.0"
READINESS_POLICY_ID = "valuation-method-readiness"
READINESS_POLICY_VERSION = "1.0.0"

ROUTING_ASSESSMENT_IDS = (
    "required_data_complete",
    "stable_capital_structure",
    "operating_financing_separable",
    "credible_noa",
    "credible_near_term_earnings",
    "equity_bridge_complete",
)

READINESS_REASON_CODES = frozenset(
    {
        "official_classification_missing",
        "official_classification_conflict",
        "business_scope_unresolved",
        "reviewed_classification_claim_missing",
        "accounting_quality_incomplete",
    }
)

# Preserve the Phase 5B mapping-policy hash while extending the separate readiness
# policy. Mapping decisions remain governed by the exact registry frozen in 5B-0.
MAPPING_POLICY_REASON_CODES = REASON_CODES
REASON_CODES = REASON_CODES | READINESS_REASON_CODES

SEC_SIC_COMPANY_TYPES = {
    "bank": (
        (6011, 6019),
        (6021, 6029),
        (6035, 6036),
        (6061, 6062),
        (6099, 6099),
        (6712, 6712),
    ),
    "insurer": ((6300, 6499),),
}
SEC_SIC_UNSUPPORTED_FINANCIAL_RANGE = (6000, 6799)

SPECIALIST_CLASSIFICATION_CLAIMS = {
    "Phase 5 routing classification: asset-based company.": (
        "asset_based",
        "nav_or_asset",
    ),
    "Phase 5 routing classification: distressed company.": (
        "distressed",
        "distress_or_apv",
    ),
}

METHOD_READINESS_ROLES = {
    "mckinsey": (
        "revenue",
        "operating_profit_and_tax",
        "invested_capital_or_roots",
        "balance_sheet_roots",
        "diluted_shares",
    ),
    "penman": (
        "sales",
        "after_tax_operating_profit_roots",
        "noa_nfo_or_roots",
        "near_term_earnings",
        "equity_stock_flow_stock_roots",
        "accounting_quality_coverage",
    ),
}


@dataclass(frozen=True, slots=True)
class SourceMappingPolicy:
    authority_level: str
    primary: bool
    permitted_document_types: tuple[str, ...]
    publisher_template: str
    title_template: str


@dataclass(frozen=True, slots=True)
class ConceptMappingPolicy:
    research_concept: str
    kernel_concept: str
    category: str
    period_kind: str
    unit_family: str
    permitted_origins: tuple[str, ...]
    method_scopes: tuple[str, ...]
    scope_policy: str = "issuer_wide"


@dataclass(frozen=True, slots=True)
class UnitMappingPolicy:
    research_unit: str
    unit_family: str
    target_unit_template: str | None
    multiplier: float | None
    price_blind_eligible: bool


@dataclass(frozen=True, slots=True)
class PeriodMappingPolicy:
    period_kind: str
    require_start: bool
    require_end: bool
    target_period_start: str
    target_period_end: str
    target_as_of_date: str


@dataclass(frozen=True, slots=True)
class CalculationMappingPolicy:
    calculator_id: str
    calculator_version: str
    code_sha256: str
    allowed_output_suffixes: tuple[str, ...]
    requires_empty_assumptions: bool
    requires_single_source_lineage: bool


SOURCE_POLICIES = {
    "primary_regulatory": SourceMappingPolicy(
        authority_level="primary_regulatory",
        primary=True,
        permitted_document_types=(
            "10-K",
            "10-K/A",
            "10-Q",
            "10-Q/A",
            "8-K",
            "8-K/A",
            "DEF 14A",
            "DEFA14A",
        ),
        publisher_template="U.S. Securities and Exchange Commission",
        title_template="{issuer_id} {document_type} filed {published_date}",
    ),
    "company_primary": SourceMappingPolicy(
        authority_level="company_primary",
        primary=True,
        permitted_document_types=(
            "earnings-release",
            "official_ir",
            "investor-day",
            "company-transcript",
        ),
        publisher_template="{issuer_id} official investor relations",
        title_template="{issuer_id} {document_type} published {published_date}",
    ),
}


def _concept(
    name: str,
    category: str,
    period_kind: str,
    unit_family: str,
    *,
    origins: tuple[str, ...] = ("raw",),
    methods: tuple[str, ...] = ("mckinsey", "penman"),
) -> ConceptMappingPolicy:
    return ConceptMappingPolicy(
        research_concept=name,
        kernel_concept=name,
        category=category,
        period_kind=period_kind,
        unit_family=unit_family,
        permitted_origins=origins,
        method_scopes=methods,
    )


CONCEPT_POLICIES = {
    item.research_concept: item
    for item in (
        _concept("revenue", "operating", "flow", "currency", origins=("raw", "derived")),
        _concept(
            "operating_income",
            "operating",
            "flow",
            "currency",
            origins=("raw", "derived"),
        ),
        _concept(
            "income_tax_expense",
            "accounting",
            "flow",
            "currency",
            origins=("raw", "derived"),
        ),
        _concept(
            "pretax_income",
            "accounting",
            "flow",
            "currency",
            origins=("raw", "derived"),
        ),
        _concept(
            "net_income",
            "accounting",
            "flow",
            "currency",
            origins=("raw", "derived"),
        ),
        _concept(
            "comprehensive_income",
            "accounting",
            "flow",
            "currency",
            origins=("raw", "derived"),
        ),
        _concept("total_assets", "accounting", "stock", "currency"),
        _concept("total_liabilities", "accounting", "stock", "currency"),
        _concept("beginning_common_equity", "accounting", "stock", "currency"),
        _concept("ending_common_equity", "accounting", "stock", "currency"),
        _concept("common_equity", "accounting", "stock", "currency", origins=("raw", "derived")),
        _concept("cash_and_cash_equivalents", "nonoperating", "stock", "currency"),
        _concept("diluted_shares", "share_count", "flow", "shares"),
        _concept("interest_bearing_debt", "financing", "stock", "currency"),
        _concept("operating_lease_liability", "financing", "stock", "currency"),
        _concept("preferred_stock", "financing", "stock", "currency"),
        _concept("noncontrolling_interest", "financing", "stock", "currency"),
        _concept("unfunded_pension", "financing", "stock", "currency"),
        _concept("debt_equivalent", "financing", "stock", "currency"),
        _concept("option_or_dilution_claim", "financing", "stock", "currency"),
        _concept("other_senior_claim", "financing", "stock", "currency"),
        _concept(
            "effective_tax_rate",
            "accounting",
            "flow",
            "ratio",
            origins=("derived",),
        ),
        _concept("nopat", "operating", "flow", "currency", origins=("derived",)),
        _concept(
            "cash_and_nonoperating_investments",
            "nonoperating",
            "stock",
            "currency",
            origins=("derived",),
        ),
        _concept(
            "net_financial_obligations",
            "financing",
            "stock",
            "currency",
            origins=("derived",),
        ),
        _concept(
            "net_operating_assets",
            "operating",
            "stock",
            "currency",
            origins=("derived",),
        ),
        _concept(
            "invested_capital",
            "operating",
            "stock",
            "currency",
            origins=("derived",),
            methods=("mckinsey",),
        ),
        _concept(
            "net_distributions_to_owners",
            "accounting",
            "flow",
            "currency",
            origins=("derived",),
            methods=("penman",),
        ),
    )
}

UNIT_POLICIES = {
    item.research_unit: item
    for item in (
        UnitMappingPolicy("currency_units", "currency", "{currency} millions", 0.000001, True),
        UnitMappingPolicy("currency_thousands", "currency", "{currency} millions", 0.001, True),
        UnitMappingPolicy("currency_millions", "currency", "{currency} millions", 1.0, True),
        UnitMappingPolicy("currency_billions", "currency", "{currency} millions", 1000.0, True),
        UnitMappingPolicy("currency_per_share", "per_share", None, None, False),
        UnitMappingPolicy("shares", "shares", "millions shares", 0.000001, True),
        UnitMappingPolicy("ratio", "ratio", "decimal", 1.0, True),
        UnitMappingPolicy("percent", "ratio", "decimal", 0.01, True),
        UnitMappingPolicy("percentage_points", "ratio", "decimal", 0.01, True),
        UnitMappingPolicy("basis_points", "ratio", "decimal", 0.0001, True),
    )
}

PERIOD_POLICIES = {
    "stock": PeriodMappingPolicy(
        period_kind="stock",
        require_start=False,
        require_end=True,
        target_period_start="null",
        target_period_end="measurement_end",
        target_as_of_date="measurement_end",
    ),
    "flow": PeriodMappingPolicy(
        period_kind="flow",
        require_start=True,
        require_end=True,
        target_period_start="measurement_start",
        target_period_end="measurement_end",
        target_as_of_date="measurement_end",
    ),
}

CALCULATION_POLICIES = {
    ("owner-research-quarterly", "0.2.0-alpha.1"): CalculationMappingPolicy(
        calculator_id="owner-research-quarterly",
        calculator_version="0.2.0-alpha.1",
        code_sha256="54231c3bb331fd2669f99f9591d66dc8db972f6ba08aa7a4e32e67e51ac26115",
        allowed_output_suffixes=(".single_quarter", ".ttm"),
        requires_empty_assumptions=True,
        requires_single_source_lineage=True,
    )
}


def mapping_policy_sha256() -> str:
    return canonical_sha256(
        {
            "policy_id": MAPPING_POLICY_ID,
            "policy_version": MAPPING_POLICY_VERSION,
            "sources": SOURCE_POLICIES,
            "concepts": CONCEPT_POLICIES,
            "units": UNIT_POLICIES,
            "periods": PERIOD_POLICIES,
            "calculations": CALCULATION_POLICIES,
            "reason_codes": sorted(MAPPING_POLICY_REASON_CODES),
        }
    )


def readiness_policy_sha256() -> str:
    return canonical_sha256(
        {
            "classification_policy_id": CLASSIFICATION_POLICY_ID,
            "classification_policy_version": CLASSIFICATION_POLICY_VERSION,
            "readiness_policy_id": READINESS_POLICY_ID,
            "readiness_policy_version": READINESS_POLICY_VERSION,
            "routing_assessments": ROUTING_ASSESSMENT_IDS,
            "sic_company_types": SEC_SIC_COMPANY_TYPES,
            "unsupported_financial_range": SEC_SIC_UNSUPPORTED_FINANCIAL_RANGE,
            "specialist_claims": SPECIALIST_CLASSIFICATION_CLAIMS,
            "method_roles": METHOD_READINESS_ROLES,
            "reason_codes": sorted(READINESS_REASON_CODES),
        }
    )


def source_policy(authority_level: str) -> SourceMappingPolicy:
    try:
        return SOURCE_POLICIES[authority_level]
    except KeyError as exc:
        raise KeyError(f"unregistered valuation source authority: {authority_level}") from exc


def concept_policy(concept: str) -> ConceptMappingPolicy:
    try:
        return CONCEPT_POLICIES[concept]
    except KeyError as exc:
        raise KeyError(f"unregistered valuation concept: {concept}") from exc


def unit_policy(unit: str) -> UnitMappingPolicy:
    try:
        return UNIT_POLICIES[unit]
    except KeyError as exc:
        raise KeyError(f"unregistered valuation unit: {unit}") from exc


def period_policy(period_kind: str) -> PeriodMappingPolicy:
    try:
        return PERIOD_POLICIES[period_kind]
    except KeyError as exc:
        raise KeyError(f"unregistered valuation period kind: {period_kind}") from exc


def calculation_policy(calculator_id: str, calculator_version: str) -> CalculationMappingPolicy:
    try:
        return CALCULATION_POLICIES[(calculator_id, calculator_version)]
    except KeyError as exc:
        raise KeyError(
            f"unregistered valuation calculator: {calculator_id}@{calculator_version}"
        ) from exc
