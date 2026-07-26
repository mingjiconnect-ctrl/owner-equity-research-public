"""Closed Phase 5C accounting, method-view, bridge, and readiness registries.

The registries define eligibility and fail-closed semantics only.  Phase 5C-0 does
not classify accounts, derive Facts, build method views, compile a bridge, access
market data, or invoke the valuation kernel.
"""

from __future__ import annotations

from dataclasses import dataclass

from .fingerprints import canonical_sha256

PHASE5C_POLICY_ID = "phase5c-accounting-equity-bridge"
PHASE5C_POLICY_VERSION = "1.0.0"

ACCOUNTING_POLICY_ID = "valuation-accounting-reformulation"
ACCOUNTING_POLICY_VERSION = "1.0.0"
ACCOUNTING_QUALITY_POLICY_ID = "valuation-accounting-quality-gate"
ACCOUNTING_QUALITY_POLICY_VERSION = "1.0.0"
METHOD_VIEW_POLICY_ID = "valuation-method-views"
METHOD_VIEW_POLICY_VERSION = "1.0.0"
EQUITY_BRIDGE_POLICY_ID = "valuation-equity-bridge"
EQUITY_BRIDGE_POLICY_VERSION = "1.0.0"
CROSS_CHANNEL_POLICY_ID = "valuation-root-consumption"
CROSS_CHANNEL_POLICY_VERSION = "1.0.0"
ECONOMIC_CLAIM_IDENTITY_POLICY_ID = "valuation-economic-claim-identity"
ECONOMIC_CLAIM_IDENTITY_POLICY_VERSION = "1.0.0"
SUCCESSOR_READINESS_POLICY_ID = "valuation-phase5c-readiness"
SUCCESSOR_READINESS_POLICY_VERSION = "1.0.0"

PINNED_KERNEL_COMMIT = "be9b0773d5a78f5f8a33ba982494512668df85fe"
PINNED_KERNEL_TAG = "v2.0.0-rc.2"
PINNED_FACT_LEDGER_SCHEMA_SHA256 = (
    "55be5aadad21629db1cdbe7fce386656eb930b52af8644d1314ba7404e384706"
)

ACCOUNT_ROLES = (
    "operating_asset",
    "operating_liability",
    "financial_asset",
    "financial_obligation",
    "non_common_claim",
    "common_equity",
    "unresolved",
)
ACCOUNT_CLASSIFICATION_STATUSES = ("classified", "blocked")
ACCOUNT_CLASSIFICATION_BASES = ("registered_concept", "reviewed_claim", "unresolved")
ACCOUNT_AGGREGATION_LEVELS = ("aggregate", "component", "not_applicable")

ACCOUNTING_FACT_PURPOSES = (
    "common_equity",
    "adjusted_total_liabilities",
    "net_operating_assets",
    "net_financial_obligations",
    "invested_capital",
    "net_distributions_to_owners",
)
ACCOUNTING_FACT_DISPOSITIONS = ("emitted", "excluded", "blocked")
LINEAGE_STATUSES = ("independent_inputs", "dependent_inputs", "not_applicable")
FORMULA_TERM_INCLUSION_STATUSES = (
    "not_required",
    "included_in_total_equity",
    "outside_reported_liabilities",
    "not_in_reported_liabilities",
    "none_identified_after_review",
    "unresolved",
)
RECONCILIATION_STATUSES = (
    "reconciles_independently",
    "reconciles_by_construction",
    "blocked",
)
COMPILATION_STATUSES = ("pass", "partial", "blocked")
ACCOUNTING_RECONCILIATION_RELATIVE_TOLERANCE = 1e-8
ACCOUNTING_FORMULA_DERIVATIONS = {
    purpose: f"{PHASE5C_POLICY_ID}/{PHASE5C_POLICY_VERSION}:{purpose}"
    for purpose in ACCOUNTING_FACT_PURPOSES
}
COMMON_EQUITY_ALIAS_DERIVATIONS = {
    "beginning_common_equity": (
        f"{PHASE5C_POLICY_ID}/{PHASE5C_POLICY_VERSION}:beginning_common_equity_alias"
    ),
    "ending_common_equity": (
        f"{PHASE5C_POLICY_ID}/{PHASE5C_POLICY_VERSION}:ending_common_equity_alias"
    ),
}
ACCOUNTING_QUALITY_CATEGORIES = (
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
)
ACCOUNTING_QUALITY_METHOD_APPLICABILITY = {
    "cash_conversion": ("mckinsey",),
    "accruals": ("penman",),
    "sbc_dilution": ("mckinsey", "penman"),
    "restructuring_recurrence": ("mckinsey", "penman"),
    "goodwill_intangibles": ("mckinsey", "penman"),
    "impairment": ("mckinsey", "penman"),
    "tax_anomaly": ("mckinsey", "penman"),
    "lease_commitments": ("mckinsey",),
    "acquisition_reconciliation": ("mckinsey", "penman"),
    "segment_elimination": ("mckinsey",),
    "off_balance_sheet": ("mckinsey", "penman"),
}

METHODS = ("mckinsey", "penman")
METHOD_ADJUSTMENT_DISPOSITIONS = ("compiled", "excluded", "blocked")
METHOD_ADJUSTMENT_CATEGORIES = (
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

BRIDGE_ROLES = (
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
BRIDGE_STATES = ("modeled", "explicitly_absent", "not_applicable", "unresolved")
BRIDGE_COMPILATION_STATUSES = ("complete", "partial", "blocked")
BRIDGE_UNRESOLVED_REASON_SEVERITY = {
    "bridge_components_not_aggregated": "partial",
    "bridge_diluted_share_overlap": "blocked",
    "bridge_fact_category_mismatch": "blocked",
    "bridge_fact_currency_mismatch": "blocked",
    "bridge_fact_not_positive_magnitude": "blocked",
    "bridge_multi_source_aggregation": "blocked",
    "bridge_narrative_absence": "partial",
    "bridge_official_zero_fact_missing": "partial",
    "bridge_role_coverage_incomplete": "partial",
    "bridge_root_overlap": "blocked",
    "bridge_state_not_replayed": "blocked",
    "nonoperating_cash_evidence_missing": "partial",
}
BRIDGE_AGGREGATE_DERIVATIONS = {
    role: f"{PHASE5C_POLICY_ID}/{PHASE5C_POLICY_VERSION}:equity_bridge:{role}"
    for role in BRIDGE_ROLES
}

SUCCESSOR_READINESS_STATUSES = (
    "ready_for_phase5d",
    "partial",
    "specialist_required",
    "blocked",
)
SPECIALIST_ROUTES = (
    "none",
    "financial_institution",
    "sum_of_parts",
    "nav_or_asset",
    "distress_or_apv",
    "unresolved",
)
ROUTING_ASSESSMENT_IDS = (
    "required_data_complete",
    "stable_capital_structure",
    "operating_financing_separable",
    "credible_noa",
    "credible_near_term_earnings",
    "equity_bridge_complete",
)
ROUTING_ASSESSMENT_STATUSES = (
    "satisfied",
    "unsatisfied",
    "pending_phase5d",
    "blocked",
)
OWNER_TRANSACTION_COVERAGE_STATES = (
    "observed",
    "official_zero",
    "not_applicable",
    "blocked",
)
OWNER_TRANSACTION_CONCEPTS = (
    "common_dividends",
    "common_share_repurchases",
    "common_equity_issuance_proceeds",
    "equity_settled_sbc_owner_contribution",
    "other_common_owner_distributions",
    "other_common_owner_contributions",
)
METHOD_SUCCESSOR_REQUIRED_ROLES = {
    "mckinsey": (
        "accounting_reconciliation",
        "accounting_quality",
        "mckinsey_method_view",
        "stable_capital_structure",
        "operating_financing_separable",
        "equity_bridge_complete",
    ),
    "penman": (
        "accounting_reconciliation",
        "accounting_quality",
        "penman_method_view",
        "credible_noa",
        "operating_financing_separable",
    ),
}
STABLE_CAPITAL_MINIMUM_ANNUAL_SNAPSHOTS = 3
STABLE_CAPITAL_REQUIRED_EVIDENCE = (
    "three_comparable_annual_debt_cash_common_equity_snapshots",
    "current_debt_liquidity_covenants_footnote_review",
    "current_capital_allocation_review",
    "named_human_confirmed_analytical_claim",
    "counterevidence_search",
    "falsification_condition",
)
ROUTING_ASSESSMENT_REQUIRED_EVIDENCE = {
    "required_data_complete": (),
    "stable_capital_structure": STABLE_CAPITAL_REQUIRED_EVIDENCE,
    "operating_financing_separable": (
        "closed_account_classification",
        "noa_nfo_common_equity_reconciliation",
    ),
    "credible_noa": ("noa_nfo_common_equity_reconciliation",),
    "credible_near_term_earnings": (),
    "equity_bridge_complete": ("equity_bridge_compilation",),
}

KERNEL_VALIDATION_ALLOWLIST = (
    "owner_valuation.FactLedger",
    "owner_valuation.MethodAdjustment",
    "owner_valuation.MethodView",
    "owner_valuation.validation.validate_balance_sheet",
    "owner_valuation.validation.validate_clean_surplus",
    "owner_valuation.validation.accounting_quality_gate",
)
KERNEL_FORBIDDEN_SURFACES = frozenset(
    {
        "owner_valuation.AssumptionLedger",
        "owner_valuation.build_request",
        "owner_valuation.request_builder",
        "owner_valuation.route_company",
        "owner_valuation.run_dual_panel",
        "owner_valuation.run_equity_bridge",
        "owner_valuation.validate_request",
        "owner_valuation.pipeline._accounting_validation",
        "owner_valuation.pipeline._bridge_items",
        "owner_valuation.pipeline._build_method_view",
        "owner_valuation.pipeline._validate_equity_bridge_review",
    }
)

PHASE5C_REASON_CODES = frozenset(
    {
        "account_root_role_conflict",
        "account_role_evidence_missing",
        "account_role_unregistered",
        "accounting_quality_evidence_incomplete",
        "accounting_quality_material_unresolved",
        "adjustment_amount_fact_required",
        "adjustment_amount_not_derived",
        "adjustment_lineage_incomplete",
        "adjustment_market_lineage",
        "adjustment_multi_source_lineage",
        "adjustment_requires_assumption",
        "adjustment_root_reuse",
        "adjustment_target_not_allowed",
        "balance_sheet_by_construction",
        "balance_sheet_currency_mismatch",
        "balance_sheet_period_mismatch",
        "balance_sheet_reconciliation_failed",
        "bridge_components_not_aggregated",
        "bridge_diluted_share_overlap",
        "bridge_fact_category_mismatch",
        "bridge_fact_currency_mismatch",
        "bridge_fact_not_positive_magnitude",
        "bridge_multi_source_aggregation",
        "bridge_narrative_absence",
        "bridge_official_zero_fact_missing",
        "bridge_role_coverage_incomplete",
        "bridge_root_overlap",
        "bridge_state_not_replayed",
        "clean_surplus_by_construction",
        "clean_surplus_period_mismatch",
        "clean_surplus_reconciliation_failed",
        "clean_surplus_residual_plug",
        "common_equity_perimeter_ambiguous",
        "component_lock_replay_required",
        "comprehensive_income_missing",
        "cross_channel_double_count",
        "diluted_share_plan_coverage_unresolved",
        "economic_claim_duplicate_treatment",
        "economic_claim_identity_unresolved",
        "economic_claim_review_mismatch",
        "finding_cannot_create_adjustment",
        "forbidden_evidence_domain",
        "forbidden_kernel_surface",
        "forbidden_later_phase_surface",
        "kernel_bridge_item_required",
        "kernel_quality_round_trip_failed",
        "pinned_kernel_global_gate_overblocks_penman",
        "pinned_kernel_quality_gate_underblocks_mckinsey",
        "method_view_payload_mismatch",
        "noncanonical_internal_order",
        "nonoperating_cash_evidence_missing",
        "owner_distribution_component_missing",
        "owner_distribution_sign_invalid",
        "owner_transaction_coverage_incomplete",
        "phase5b_routing_replay_required",
        "phase5d_earnings_pending",
        "reported_liabilities_nfo_double_count",
        "required_data_incomplete_until_phase5e",
        "specialist_route_required",
        "stable_capital_structure_capital_review_missing",
        "stable_capital_structure_claim_missing",
        "stable_capital_structure_evidence_missing",
        "stable_capital_structure_footnote_missing",
        "successor_role_missing",
    }
)


@dataclass(frozen=True, slots=True)
class AccountRolePolicy:
    role: str
    permitted_categories: tuple[str, ...]
    balance_sheet_treatment: str
    nfo_treatment: str


@dataclass(frozen=True, slots=True)
class AccountConceptPolicy:
    research_concept: str
    account_role: str
    period_kind: str
    kernel_category: str
    balance_sheet_treatment: str
    nfo_treatment: str
    owner_distribution_sign: int | None = None
    bridge_role: str | None = None
    permitted_origins: tuple[str, ...] = ("raw", "derived")
    classification_roles: tuple[str, ...] = ()
    classification_requires_review: bool = False


@dataclass(frozen=True, slots=True)
class FormulaTermPolicy:
    input_role: str
    permitted_concepts: tuple[str, ...]
    sign: int
    cardinality: str
    required_inclusion_status: str


@dataclass(frozen=True, slots=True)
class AccountingFormulaPolicy:
    purpose: str
    output_concept: str
    terms: tuple[FormulaTermPolicy, ...]
    requires_same_currency: bool
    requires_same_period: bool
    residual_permitted: bool


@dataclass(frozen=True, slots=True)
class PeriodAlignmentPolicy:
    check_id: str
    stock_roles: tuple[str, ...]
    flow_roles: tuple[str, ...]
    same_currency: bool
    same_measurement_end: bool
    consecutive_stock_flow: bool
    date_relationship: str
    requires_same_common_equity_perimeter: bool
    equation_terms: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class QualityMappingPolicy:
    evidence_state: str
    material: bool | None
    resolved: bool | None
    compilation_status: str
    material_source: str


@dataclass(frozen=True, slots=True)
class MethodTargetPolicy:
    method: str
    allowed_concepts: tuple[str, ...]
    allows_modeled_bridge_facts: bool
    allowed_bridge_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MethodAdjustmentCalculatorPolicy:
    calculator_id: str
    calculator_version: str
    calculator_code_sha256: str
    operation: str
    derivation_label: str
    permitted_input_categories: tuple[str, ...]
    requires_reporting_currency_millions: bool
    requires_same_period: bool
    requires_single_source: bool
    requires_zero_assumptions: bool


@dataclass(frozen=True, slots=True)
class MethodAdjustmentCategoryPolicy:
    category: str
    permitted_source_concepts: tuple[str, ...]
    requires_phase5d_judgment: bool


@dataclass(frozen=True, slots=True)
class BridgeRolePolicy:
    role: str
    kernel_category: str
    mckinsey_effect: str
    penman_nfo_treatment: str
    requires_diluted_share_root_separation: bool


@dataclass(frozen=True, slots=True)
class CrossChannelPolicy:
    economic_identity: str
    validation_channels: tuple[str, ...]
    economic_channels: tuple[str, ...]
    maximum_economic_consumptions: int
    permits_cross_method_base_sharing: bool
    consumption_limit_scope: str


ECONOMIC_CLAIM_IDENTITY_KINDS = (
    "instrument",
    "plan",
    "program",
    "security_class",
    "aggregate_perimeter",
)
ECONOMIC_CLAIM_BINDING_STATUSES = ("confirmed", "blocked")
DILUTED_SHARE_TREATMENTS = (
    "included",
    "excluded",
    "not_applicable",
    "blocked",
)


@dataclass(frozen=True, slots=True)
class OwnerTransactionPolicy:
    concept: str
    sign: int
    permitted_coverage_states: tuple[str, ...]
    official_numeric_fact_required: bool


ACCOUNT_ROLE_POLICIES = {
    item.role: item
    for item in (
        AccountRolePolicy("operating_asset", ("operating",), "asset_component", "excluded"),
        AccountRolePolicy(
            "operating_liability", ("operating",), "reported_liability_component", "excluded"
        ),
        AccountRolePolicy("financial_asset", ("nonoperating",), "asset_component", "deduct"),
        AccountRolePolicy(
            "financial_obligation", ("financing",), "reported_liability_component", "add"
        ),
        AccountRolePolicy(
            "non_common_claim",
            ("financing",),
            "equity_classified_non_common_claim",
            "add",
        ),
        AccountRolePolicy("common_equity", ("accounting",), "common_equity", "identity_only"),
        AccountRolePolicy("unresolved", (), "blocked", "blocked"),
    )
}


def _concept(
    name: str,
    role: str,
    period_kind: str,
    category: str,
    *,
    balance_sheet_treatment: str = "not_applicable",
    nfo_treatment: str = "not_applicable",
    owner_distribution_sign: int | None = None,
    bridge_role: str | None = None,
    origins: tuple[str, ...] = ("raw", "derived"),
    classification_roles: tuple[str, ...] | None = None,
    classification_requires_review: bool = False,
) -> AccountConceptPolicy:
    roles = classification_roles
    if roles is None:
        roles = () if role == "unresolved" else (role,)
    return AccountConceptPolicy(
        research_concept=name,
        account_role=role,
        period_kind=period_kind,
        kernel_category=category,
        balance_sheet_treatment=balance_sheet_treatment,
        nfo_treatment=nfo_treatment,
        owner_distribution_sign=owner_distribution_sign,
        bridge_role=bridge_role,
        permitted_origins=origins,
        classification_roles=roles,
        classification_requires_review=classification_requires_review,
    )


ACCOUNT_CONCEPT_POLICIES = {
    item.research_concept: item
    for item in (
        _concept(
            "total_assets",
            "unresolved",
            "stock",
            "accounting",
            balance_sheet_treatment="asset_total",
        ),
        _concept(
            "total_liabilities",
            "unresolved",
            "stock",
            "accounting",
            balance_sheet_treatment="reported_liabilities_base",
            nfo_treatment="prohibited_total",
        ),
        _concept(
            "total_equity",
            "unresolved",
            "stock",
            "accounting",
            balance_sheet_treatment="perimeter_requires_inclusion_proof",
        ),
        _concept(
            "common_equity",
            "common_equity",
            "stock",
            "accounting",
            balance_sheet_treatment="common_equity",
        ),
        _concept("beginning_common_equity", "common_equity", "stock", "accounting"),
        _concept("ending_common_equity", "common_equity", "stock", "accounting"),
        _concept(
            "noncontrolling_interest",
            "non_common_claim",
            "stock",
            "financing",
            balance_sheet_treatment="include_only_if_outside_reported_liabilities",
            nfo_treatment="non_common_equity_claim",
            bridge_role="noncontrolling_interest",
            classification_requires_review=True,
        ),
        _concept(
            "preferred_stock",
            "non_common_claim",
            "stock",
            "financing",
            balance_sheet_treatment="include_only_if_outside_reported_liabilities",
            nfo_treatment="non_common_equity_claim",
            bridge_role="preferred_stock",
            classification_roles=("non_common_claim", "financial_obligation"),
            classification_requires_review=True,
        ),
        _concept(
            "other_non_common_equity_claim",
            "non_common_claim",
            "stock",
            "financing",
            balance_sheet_treatment="include_only_if_outside_reported_liabilities",
            nfo_treatment="non_common_equity_claim",
            classification_roles=("non_common_claim", "financial_obligation"),
            classification_requires_review=True,
        ),
        _concept(
            "comprehensive_income_attributable_to_common",
            "common_equity",
            "flow",
            "accounting",
        ),
        _concept(
            "common_dividends",
            "common_equity",
            "flow",
            "accounting",
            owner_distribution_sign=1,
        ),
        _concept(
            "common_share_repurchases",
            "common_equity",
            "flow",
            "accounting",
            owner_distribution_sign=1,
        ),
        _concept(
            "common_equity_issuance_proceeds",
            "common_equity",
            "flow",
            "accounting",
            owner_distribution_sign=-1,
        ),
        _concept(
            "equity_settled_sbc_owner_contribution",
            "common_equity",
            "flow",
            "accounting",
            owner_distribution_sign=-1,
        ),
        _concept(
            "other_common_owner_distributions",
            "common_equity",
            "flow",
            "accounting",
            owner_distribution_sign=1,
        ),
        _concept(
            "other_common_owner_contributions",
            "common_equity",
            "flow",
            "accounting",
            owner_distribution_sign=-1,
        ),
        _concept("operating_assets", "operating_asset", "stock", "operating"),
        _concept("accounts_receivable", "operating_asset", "stock", "operating"),
        _concept("inventory", "operating_asset", "stock", "operating"),
        _concept("property_plant_equipment", "operating_asset", "stock", "operating"),
        _concept("goodwill", "operating_asset", "stock", "operating"),
        _concept("intangible_assets", "operating_asset", "stock", "operating"),
        _concept(
            "operating_right_of_use_asset", "operating_asset", "stock", "operating"
        ),
        _concept(
            "other_operating_assets",
            "operating_asset",
            "stock",
            "operating",
            classification_requires_review=True,
        ),
        _concept("operating_liabilities", "operating_liability", "stock", "operating"),
        _concept("accounts_payable", "operating_liability", "stock", "operating"),
        _concept(
            "accrued_operating_liabilities", "operating_liability", "stock", "operating"
        ),
        _concept("deferred_revenue", "operating_liability", "stock", "operating"),
        _concept(
            "other_operating_liabilities",
            "operating_liability",
            "stock",
            "operating",
            classification_requires_review=True,
        ),
        _concept(
            "financial_assets",
            "financial_asset",
            "stock",
            "nonoperating",
            nfo_treatment="deduct",
        ),
        _concept(
            "marketable_securities",
            "financial_asset",
            "stock",
            "nonoperating",
            nfo_treatment="deduct",
        ),
        _concept(
            "other_financial_assets",
            "financial_asset",
            "stock",
            "nonoperating",
            nfo_treatment="deduct",
            classification_requires_review=True,
        ),
        _concept(
            "financial_obligations",
            "financial_obligation",
            "stock",
            "financing",
            nfo_treatment="add",
        ),
        _concept(
            "net_operating_assets",
            "operating_asset",
            "stock",
            "operating",
            origins=("derived",),
        ),
        _concept(
            "net_financial_obligations",
            "financial_obligation",
            "stock",
            "financing",
            origins=("derived",),
        ),
        _concept("invested_capital", "operating_asset", "stock", "operating", origins=("derived",)),
        _concept(
            "net_distributions_to_owners",
            "common_equity",
            "flow",
            "accounting",
            origins=("derived",),
        ),
        _concept(
            "adjusted_total_liabilities",
            "non_common_claim",
            "stock",
            "accounting",
            origins=("derived",),
        ),
        _concept(
            "method_adjustment_amount",
            "unresolved",
            "stock_or_flow",
            "evidence",
            origins=("derived",),
        ),
        _concept(
            "cash_and_cash_equivalents",
            "unresolved",
            "stock",
            "nonoperating",
            nfo_treatment="requires_reviewed_operating_cash_classification",
            classification_roles=("operating_asset", "financial_asset"),
            classification_requires_review=True,
        ),
        _concept(
            "cash_and_nonoperating_investments",
            "financial_asset",
            "stock",
            "nonoperating",
            nfo_treatment="deduct",
            bridge_role="nonoperating_asset",
            classification_requires_review=True,
        ),
        _concept(
            "interest_bearing_debt",
            "financial_obligation",
            "stock",
            "financing",
            nfo_treatment="add",
            bridge_role="debt",
        ),
        _concept(
            "debt_equivalent",
            "financial_obligation",
            "stock",
            "financing",
            nfo_treatment="add",
            bridge_role="debt_equivalent",
        ),
        _concept(
            "operating_lease_liability",
            "financial_obligation",
            "stock",
            "financing",
            nfo_treatment="add",
            bridge_role="lease_liability",
        ),
        _concept(
            "unfunded_pension",
            "financial_obligation",
            "stock",
            "financing",
            nfo_treatment="add",
            bridge_role="unfunded_pension",
        ),
        _concept(
            "option_or_dilution_claim",
            "financial_obligation",
            "stock",
            "financing",
            nfo_treatment="add_if_not_in_diluted_shares",
            bridge_role="option_or_dilution_claim",
        ),
        _concept(
            "other_senior_claim",
            "financial_obligation",
            "stock",
            "financing",
            nfo_treatment="add",
            bridge_role="other_senior_claim",
            classification_requires_review=True,
        ),
        _concept("diluted_shares", "unresolved", "flow", "share_count"),
    )
}


def _term(
    role: str,
    concepts: tuple[str, ...],
    sign: int,
    cardinality: str,
    required_inclusion_status: str = "not_required",
) -> FormulaTermPolicy:
    return FormulaTermPolicy(
        role,
        concepts,
        sign,
        cardinality,
        required_inclusion_status,
    )


FORMULA_POLICIES = {
    item.purpose: item
    for item in (
        AccountingFormulaPolicy(
            "common_equity",
            "common_equity",
            (
                _term("total_equity", ("total_equity",), 1, "exactly_one"),
                _term(
                    "included_non_common_equity_claims",
                    ("noncontrolling_interest", "preferred_stock", "other_non_common_equity_claim"),
                    -1,
                    "zero_or_more_with_inclusion_proof",
                    "included_in_total_equity",
                ),
            ),
            True,
            True,
            False,
        ),
        AccountingFormulaPolicy(
            "adjusted_total_liabilities",
            "adjusted_total_liabilities",
            (
                _term("total_liabilities", ("total_liabilities",), 1, "exactly_one"),
                _term(
                    "equity_classified_non_common_claims",
                    ("noncontrolling_interest", "preferred_stock", "other_non_common_equity_claim"),
                    1,
                    "zero_or_more_outside_reported_liabilities",
                    "outside_reported_liabilities",
                ),
            ),
            True,
            True,
            False,
        ),
        AccountingFormulaPolicy(
            "net_operating_assets",
            "net_operating_assets",
            (
                _term(
                    "operating_asset_components",
                    (
                        "operating_assets",
                        "accounts_receivable",
                        "inventory",
                        "property_plant_equipment",
                        "goodwill",
                        "intangible_assets",
                        "operating_right_of_use_asset",
                        "other_operating_assets",
                    ),
                    1,
                    "classified_role_set",
                ),
                _term(
                    "operating_liability_components",
                    (
                        "operating_liabilities",
                        "accounts_payable",
                        "accrued_operating_liabilities",
                        "deferred_revenue",
                        "other_operating_liabilities",
                    ),
                    -1,
                    "classified_role_set",
                ),
            ),
            True,
            True,
            False,
        ),
        AccountingFormulaPolicy(
            "net_financial_obligations",
            "net_financial_obligations",
            (
                _term(
                    "financial_obligation_components",
                    (
                        "financial_obligations",
                        "interest_bearing_debt",
                        "debt_equivalent",
                        "operating_lease_liability",
                        "unfunded_pension",
                        "option_or_dilution_claim",
                        "other_senior_claim",
                    ),
                    1,
                    "classified_role_set",
                ),
                _term(
                    "nfo_non_common_equity_claims",
                    ("noncontrolling_interest", "preferred_stock", "other_non_common_equity_claim"),
                    1,
                    "zero_or_more_without_reported_liabilities",
                    "not_in_reported_liabilities",
                ),
                _term(
                    "financial_asset_components",
                    (
                        "financial_assets",
                        "cash_and_cash_equivalents",
                        "cash_and_nonoperating_investments",
                        "marketable_securities",
                        "other_financial_assets",
                    ),
                    -1,
                    "classified_role_set",
                ),
            ),
            True,
            True,
            False,
        ),
        AccountingFormulaPolicy(
            "invested_capital",
            "invested_capital",
            (_term("net_operating_assets", ("net_operating_assets",), 1, "exactly_one"),),
            True,
            True,
            False,
        ),
        AccountingFormulaPolicy(
            "net_distributions_to_owners",
            "net_distributions_to_owners",
            (
                _term(
                    "distributions",
                    (
                        "common_dividends",
                        "common_share_repurchases",
                        "other_common_owner_distributions",
                    ),
                    1,
                    "all_concepts_require_coverage",
                ),
                _term(
                    "contributions",
                    (
                        "common_equity_issuance_proceeds",
                        "equity_settled_sbc_owner_contribution",
                        "other_common_owner_contributions",
                    ),
                    -1,
                    "all_concepts_require_coverage",
                ),
            ),
            True,
            True,
            False,
        ),
    )
}

PERIOD_ALIGNMENT_POLICIES = {
    item.check_id: item
    for item in (
        PeriodAlignmentPolicy(
            "balance_sheet",
            ("total_assets", "adjusted_total_liabilities", "common_equity"),
            (),
            True,
            True,
            False,
            "all_stock_ends_equal",
            True,
            (
                ("total_assets", 1),
                ("adjusted_total_liabilities", -1),
                ("common_equity", -1),
            ),
        ),
        PeriodAlignmentPolicy(
            "clean_surplus",
            ("beginning_common_equity", "ending_common_equity"),
            ("comprehensive_income_attributable_to_common", "net_distributions_to_owners"),
            True,
            False,
            True,
            "beginning_plus_one_day_equals_flow_start_and_ending_equals_flow_end",
            True,
            (
                ("ending_common_equity", 1),
                ("beginning_common_equity", -1),
                ("comprehensive_income_attributable_to_common", -1),
                ("net_distributions_to_owners", 1),
            ),
        ),
        PeriodAlignmentPolicy(
            "noa_nfo_common_equity",
            ("net_operating_assets", "net_financial_obligations", "common_equity"),
            (),
            True,
            True,
            False,
            "all_stock_ends_equal",
            True,
            (
                ("net_operating_assets", 1),
                ("net_financial_obligations", -1),
                ("common_equity", -1),
            ),
        ),
    )
}

QUALITY_MAPPING_POLICIES = {
    item.evidence_state: item
    for item in (
        QualityMappingPolicy("confirmed_red_flag", True, False, "blocked", "fixed_true"),
        QualityMappingPolicy("cleared", None, True, "pass", "reviewed_final_severity"),
        QualityMappingPolicy("watch", False, False, "pass", "fixed_false"),
        QualityMappingPolicy("informational", False, False, "pass", "fixed_false"),
        QualityMappingPolicy("provisional", None, None, "partial", "unknown"),
        QualityMappingPolicy("blocked", None, None, "blocked", "unknown"),
    )
}

METHOD_TARGET_POLICIES = {
    # Phase 5C-3 compiles only the price-blind accounting base.  The nine
    # reviewed bridge items are emitted by Phase 5C-4 as a separate kernel
    # fragment; accepting them here would let a later bridge Fact bypass the
    # accounting-quality predecessor chain.
    "mckinsey": MethodTargetPolicy("mckinsey", ("invested_capital",), False, ()),
    "penman": MethodTargetPolicy(
        "penman", ("net_financial_obligations", "net_operating_assets"), False, ()
    ),
}

KERNEL_METHOD_VIEW_TARGET_ALLOWLIST = {
    "mckinsey": ("invested_capital", *BRIDGE_ROLES),
    "penman": ("net_financial_obligations", "net_operating_assets"),
}

METHOD_ADJUSTMENT_CALCULATOR_CODE_SHA256 = canonical_sha256(
    {
        "operation": "signed_sum",
        "inputs": "registered_reporting_currency_millions_same_period_single_source",
        "output": "method_adjustment_amount",
        "assumptions": "forbidden",
    }
)
METHOD_ADJUSTMENT_CALCULATOR_POLICY = MethodAdjustmentCalculatorPolicy(
    calculator_id="phase5c.method_adjustment.signed_sum",
    calculator_version="1.0.0",
    calculator_code_sha256=METHOD_ADJUSTMENT_CALCULATOR_CODE_SHA256,
    operation="signed_sum",
    derivation_label="phase5c.method_adjustment.signed_sum/1.0.0",
    permitted_input_categories=(
        "accounting",
        "evidence",
        "financing",
        "nonoperating",
        "operating",
    ),
    requires_reporting_currency_millions=True,
    requires_same_period=True,
    requires_single_source=True,
    requires_zero_assumptions=True,
)

METHOD_ADJUSTMENT_CATEGORY_POLICIES = {
    item.category: item
    for item in (
        MethodAdjustmentCategoryPolicy("r_and_d", (), True),
        MethodAdjustmentCategoryPolicy("brand_investment", (), True),
        MethodAdjustmentCategoryPolicy("lease", ("operating_lease_liability",), False),
        MethodAdjustmentCategoryPolicy("pension", ("unfunded_pension",), False),
        MethodAdjustmentCategoryPolicy("sbc", ("option_or_dilution_claim",), False),
        MethodAdjustmentCategoryPolicy("goodwill", (), True),
        MethodAdjustmentCategoryPolicy("deferred_tax", (), True),
        MethodAdjustmentCategoryPolicy("non_recurring", (), True),
        MethodAdjustmentCategoryPolicy(
            "other",
            (
                "cash_and_nonoperating_investments",
                "debt_equivalent",
                "financial_assets",
                "financial_obligations",
                "interest_bearing_debt",
                "noncontrolling_interest",
                "operating_lease_liability",
                "option_or_dilution_claim",
                "other_senior_claim",
                "preferred_stock",
                "unfunded_pension",
            ),
            False,
        ),
    )
}

BRIDGE_ROLE_POLICIES = {
    role: BridgeRolePolicy(
        role=role,
        kernel_category="nonoperating" if role == "nonoperating_asset" else "financing",
        mckinsey_effect="add" if role == "nonoperating_asset" else "deduct",
        penman_nfo_treatment=(
            "deduct"
            if role == "nonoperating_asset"
            else "add_if_not_in_diluted_shares"
            if role == "option_or_dilution_claim"
            else "add"
        ),
        requires_diluted_share_root_separation=True,
    )
    for role in BRIDGE_ROLES
}

CROSS_CHANNEL_POLICIES = {
    role: CrossChannelPolicy(
        economic_identity=role,
        validation_channels=("accounting_identity",),
        economic_channels=("penman_nfo", "mckinsey_equity_bridge"),
        maximum_economic_consumptions=1,
        permits_cross_method_base_sharing=True,
        consumption_limit_scope="per_method",
    )
    for role in BRIDGE_ROLES
}
CROSS_CHANNEL_POLICIES["option_or_dilution_claim"] = CrossChannelPolicy(
    economic_identity="option_or_dilution_claim",
    validation_channels=("accounting_identity",),
    economic_channels=(
        "penman_nfo",
        "mckinsey_equity_bridge",
        "penman_diluted_shares",
        "mckinsey_diluted_shares",
    ),
    maximum_economic_consumptions=1,
    permits_cross_method_base_sharing=True,
    consumption_limit_scope="per_method",
)
CROSS_CHANNEL_POLICIES["method_base"] = CrossChannelPolicy(
    economic_identity="method_base",
    validation_channels=("balance_sheet", "noa_nfo_common_equity"),
    economic_channels=("mckinsey_invested_capital", "penman_noa_nfo"),
    maximum_economic_consumptions=1,
    permits_cross_method_base_sharing=True,
    consumption_limit_scope="per_method",
)

OWNER_TRANSACTION_POLICIES = {
    concept: OwnerTransactionPolicy(
        concept=concept,
        sign=ACCOUNT_CONCEPT_POLICIES[concept].owner_distribution_sign or 0,
        permitted_coverage_states=OWNER_TRANSACTION_COVERAGE_STATES,
        official_numeric_fact_required=True,
    )
    for concept in OWNER_TRANSACTION_CONCEPTS
}


def account_concept_policy(concept: str) -> AccountConceptPolicy:
    return ACCOUNT_CONCEPT_POLICIES[concept]


def bridge_role_policy(role: str) -> BridgeRolePolicy:
    return BRIDGE_ROLE_POLICIES[role]


def method_target_policy(method: str) -> MethodTargetPolicy:
    return METHOD_TARGET_POLICIES[method]


def method_adjustment_category_policy(category: str) -> MethodAdjustmentCategoryPolicy:
    return METHOD_ADJUSTMENT_CATEGORY_POLICIES[category]


def phase5c_policy_sha256() -> str:
    return canonical_sha256(
        {
            "policy_id": PHASE5C_POLICY_ID,
            "policy_version": PHASE5C_POLICY_VERSION,
            "subpolicies": {
                "accounting": (ACCOUNTING_POLICY_ID, ACCOUNTING_POLICY_VERSION),
                "accounting_quality": (
                    ACCOUNTING_QUALITY_POLICY_ID,
                    ACCOUNTING_QUALITY_POLICY_VERSION,
                ),
                "method_view": (METHOD_VIEW_POLICY_ID, METHOD_VIEW_POLICY_VERSION),
                "equity_bridge": (EQUITY_BRIDGE_POLICY_ID, EQUITY_BRIDGE_POLICY_VERSION),
                "cross_channel": (CROSS_CHANNEL_POLICY_ID, CROSS_CHANNEL_POLICY_VERSION),
                "economic_claim_identity": (
                    ECONOMIC_CLAIM_IDENTITY_POLICY_ID,
                    ECONOMIC_CLAIM_IDENTITY_POLICY_VERSION,
                ),
                "successor_readiness": (
                    SUCCESSOR_READINESS_POLICY_ID,
                    SUCCESSOR_READINESS_POLICY_VERSION,
                ),
            },
            "account_roles": ACCOUNT_ROLE_POLICIES,
            "account_concepts": ACCOUNT_CONCEPT_POLICIES,
            "formulas": FORMULA_POLICIES,
            "owner_transactions": OWNER_TRANSACTION_POLICIES,
            "period_alignment": PERIOD_ALIGNMENT_POLICIES,
            "accounting_reconciliation_relative_tolerance": (
                ACCOUNTING_RECONCILIATION_RELATIVE_TOLERANCE
            ),
            "accounting_formula_derivations": ACCOUNTING_FORMULA_DERIVATIONS,
            "common_equity_alias_derivations": COMMON_EQUITY_ALIAS_DERIVATIONS,
            "quality_mapping": QUALITY_MAPPING_POLICIES,
            "accounting_quality_categories": ACCOUNTING_QUALITY_CATEGORIES,
            "accounting_quality_method_applicability": (
                ACCOUNTING_QUALITY_METHOD_APPLICABILITY
            ),
            "method_targets": METHOD_TARGET_POLICIES,
            "kernel_method_view_target_allowlist": KERNEL_METHOD_VIEW_TARGET_ALLOWLIST,
            "method_adjustment_calculator": METHOD_ADJUSTMENT_CALCULATOR_POLICY,
            "method_adjustment_categories": METHOD_ADJUSTMENT_CATEGORIES,
            "method_adjustment_category_policies": METHOD_ADJUSTMENT_CATEGORY_POLICIES,
            "bridge_roles": BRIDGE_ROLE_POLICIES,
            "bridge_aggregate_derivations": BRIDGE_AGGREGATE_DERIVATIONS,
            "bridge_unresolved_reason_severity": BRIDGE_UNRESOLVED_REASON_SEVERITY,
            "cross_channel": CROSS_CHANNEL_POLICIES,
            "economic_claim_identity": {
                "identity_kinds": ECONOMIC_CLAIM_IDENTITY_KINDS,
                "binding_statuses": ECONOMIC_CLAIM_BINDING_STATUSES,
                "diluted_share_treatments": DILUTED_SHARE_TREATMENTS,
            },
            "successor_readiness": {
                "statuses": SUCCESSOR_READINESS_STATUSES,
                "specialist_routes": SPECIALIST_ROUTES,
                "routing_assessment_ids": ROUTING_ASSESSMENT_IDS,
                "routing_assessment_statuses": ROUTING_ASSESSMENT_STATUSES,
                "routing_assessment_required_evidence": (
                    ROUTING_ASSESSMENT_REQUIRED_EVIDENCE
                ),
                "method_required_roles": METHOD_SUCCESSOR_REQUIRED_ROLES,
                "stable_capital_minimum_annual_snapshots": (
                    STABLE_CAPITAL_MINIMUM_ANNUAL_SNAPSHOTS
                ),
                "stable_capital_required_evidence": STABLE_CAPITAL_REQUIRED_EVIDENCE,
            },
            "kernel_validation_allowlist": KERNEL_VALIDATION_ALLOWLIST,
            "kernel_forbidden_surfaces": tuple(sorted(KERNEL_FORBIDDEN_SURFACES)),
            "reason_codes": tuple(sorted(PHASE5C_REASON_CODES)),
        }
    )
