from __future__ import annotations

from dataclasses import dataclass

from .fingerprints import canonical_sha256

EVENT_POLICY_VERSION = "1.0.0"
OUTCOME_POLICY_VERSION = "1.0.0"
REVIEW_POLICY_ID = "capital-allocation-review"
REVIEW_POLICY_VERSION = "2.0.0"
EVENT_POLICY_PREFIX = "capital-allocation-event"
OUTCOME_POLICY_PREFIX = "capital-allocation-outcome"

SOURCE_FAMILIES = frozenset(
    {
        "10-K",
        "10-Q",
        "8-K",
        "DEF14A",
        "registration_or_prospectus",
        "tender_or_merger_material",
        "credit_or_indentures",
        "official_ir",
    }
)
OFFICIAL_AUTHORITY_LEVELS = frozenset({"primary_regulatory", "company_primary"})

SOURCE_ROLES = frozenset(
    {
        "authorization",
        "announcement",
        "terms",
        "execution_update",
        "completion",
        "cancellation",
        "supersession",
        "financing_terms",
        "purchase_accounting",
        "periodic_recap",
        "rationale",
    }
)

IDENTITY_ROLES = frozenset(
    {
        "program_id",
        "project_id",
        "product_id",
        "scope_id",
        "fiscal_year",
        "fiscal_period",
        "target_entity",
        "disposed_asset",
        "transaction_id",
        "approval_date",
        "declaration_date",
        "announcement_date",
        "security_class",
        "instrument_id",
        "plan_id",
    }
)

IDENTITY_ROLE_SETS: dict[str, dict[str, tuple[frozenset[str], ...]]] = {
    "organic_capex": {
        subtype: (
            frozenset({"program_id", "scope_id"}),
            frozenset({"project_id", "scope_id"}),
            frozenset({"scope_id", "announcement_date"}),
        )
        for subtype in {
            "maintenance",
            "growth_capacity",
            "technology",
            "infrastructure",
            "named_other",
        }
    },
    "research_and_development": {
        "recurring_base": (frozenset({"fiscal_year"}),),
        "named_program": (
            frozenset({"program_id"}),
            frozenset({"product_id"}),
        ),
    },
    "acquisition": {
        subtype: (frozenset({"target_entity", "transaction_id"}),)
        for subtype in {"business_combination", "asset_acquisition", "merger", "tender_offer"}
    },
    "divestiture": {
        subtype: (frozenset({"disposed_asset", "transaction_id"}),)
        for subtype in {"asset_sale", "business_sale", "spin_off", "carve_out"}
    },
    "buyback": {
        subtype: (frozenset({"program_id", "approval_date", "security_class"}),)
        for subtype in {"open_market", "accelerated", "tender_offer", "other_program"}
    },
    "dividend": {
        subtype: (frozenset({"declaration_date", "security_class"}),)
        for subtype in {"regular", "special"}
    },
    "debt_issuance": {
        subtype: (frozenset({"instrument_id"}),)
        for subtype in {"new_money", "refinancing", "revolver_draw"}
    },
    "debt_repayment": {
        subtype: (frozenset({"instrument_id"}),)
        for subtype in {"scheduled", "early_redemption", "refinancing"}
    },
    "equity_issuance": {
        subtype: (
            frozenset({"program_id", "security_class"}),
            frozenset({"plan_id", "security_class"}),
        )
        for subtype in {
            "public_offering",
            "private_placement",
            "at_the_market",
            "acquisition_consideration",
            "employee_plan",
        }
    },
    "stock_based_compensation": {
        subtype: (frozenset({"plan_id", "fiscal_year"}),)
        for subtype in {"grant", "vesting_settlement", "tax_withholding", "employee_purchase"}
    },
    "pension_funding": {
        subtype: (frozenset({"plan_id", "fiscal_year"}),)
        for subtype in {"required", "discretionary"}
    },
    "restructuring": {
        subtype: (frozenset({"program_id", "announcement_date"}),)
        for subtype in {"workforce", "facility", "product_exit", "integration", "mixed"}
    },
    "cash_accumulation": {
        subtype: (frozenset({"program_id", "fiscal_period"}),)
        for subtype in {"operating_liquidity", "restricted_cash", "strategic_reserve"}
    },
}

SHARE_ROLES = frozenset(
    {
        "shares_repurched",
        "sbc_shares_issued",
        "other_equity_shares_issued",
        "basic_shares_change",
        "diluted_shares_change",
        "eligible_shares",
        "shares_issued",
        "shares_granted",
        "shares_vested",
        "shares_withheld",
    }
)
RATE_ROLES = frozenset({"coupon_rate"})
TIME_ROLES = frozenset({"maturity"})
EMPLOYEE_ROLES = frozenset({"headcount_reduction"})


def role_accepts_unit(role_id: str, unit_family: str) -> bool:
    if role_id in SHARE_ROLES:
        return unit_family == "count:shares"
    if role_id in RATE_ROLES:
        return unit_family.startswith("rate:")
    if role_id in TIME_ROLES:
        return unit_family.startswith("time:")
    if role_id in EMPLOYEE_ROLES:
        return unit_family in {"count:employees", "count:count"}
    return unit_family == "monetary" or unit_family.startswith("per_unit:")

CLAIM_ROLES = frozenset(
    {
        "funding",
        "rationale",
        "growth_classification",
        "identity_resolution",
        "lifecycle_support",
    }
)
OUTCOME_CLAIM_ROLES = frozenset(
    {"result_interpretation", "counterevidence", "falsification", "absence_search"}
)
REVIEW_CLAIM_ROLES = frozenset(
    {"not_applicable", "coverage_interpretation", "counterevidence"}
)


@dataclass(frozen=True, slots=True)
class CapitalAllocationPolicy:
    event_type: str
    subtypes: frozenset[str]
    identity_roles: frozenset[str]
    fact_roles: frozenset[str]
    execution_roles: frozenset[str]
    completion_roles: frozenset[str]
    outcome_roles: frozenset[str]

    @property
    def event_policy_id(self) -> str:
        return f"{EVENT_POLICY_PREFIX}/{self.event_type}"

    @property
    def outcome_policy_id(self) -> str:
        return f"{OUTCOME_POLICY_PREFIX}/{self.event_type}"


def _policy(
    event_type: str,
    *,
    subtypes: set[str],
    identity: set[str],
    facts: set[str],
    execution: set[str],
    completion: set[str],
    outcomes: set[str],
) -> CapitalAllocationPolicy:
    return CapitalAllocationPolicy(
        event_type=event_type,
        subtypes=frozenset(subtypes),
        identity_roles=frozenset(identity),
        fact_roles=frozenset(facts),
        execution_roles=frozenset(execution),
        completion_roles=frozenset(completion),
        outcome_roles=frozenset(outcomes),
    )


CAPITAL_ALLOCATION_POLICIES = {
    policy.event_type: policy
    for policy in (
        _policy(
            "organic_capex",
            subtypes={
                "maintenance",
                "growth_capacity",
                "technology",
                "infrastructure",
                "named_other",
            },
            identity={"program_id", "scope_id"},
            facts={"announced_budget", "capex_paid", "assets_placed_in_service"},
            execution={"capex_paid"},
            completion={"capex_paid", "assets_placed_in_service"},
            outcomes={"capex_paid", "assets_placed_in_service"},
        ),
        _policy(
            "research_and_development",
            subtypes={"recurring_base", "named_program"},
            identity={"program_id", "fiscal_year"},
            facts={"announced_budget", "rd_spend", "capitalized_development_cost"},
            execution={"rd_spend"},
            completion={"rd_spend"},
            outcomes={"rd_spend", "capitalized_development_cost"},
        ),
        _policy(
            "acquisition",
            subtypes={"business_combination", "asset_acquisition", "merger", "tender_offer"},
            identity={"target_entity", "transaction_id"},
            facts={
                "purchase_price",
                "cash_consideration",
                "stock_consideration",
                "debt_assumed",
                "contingent_consideration",
                "transaction_cost",
                "goodwill_recognized",
                "intangibles_recognized",
            },
            execution={"purchase_price", "cash_consideration", "stock_consideration"},
            completion={"purchase_price", "goodwill_recognized", "intangibles_recognized"},
            outcomes={
                "consideration_total",
                "goodwill_recognized",
                "intangibles_recognized",
                "impairment",
                "synergy_result",
                "acquired_revenue",
            },
        ),
        _policy(
            "divestiture",
            subtypes={"asset_sale", "business_sale", "spin_off", "carve_out"},
            identity={"disposed_asset", "transaction_id"},
            facts={
                "announced_consideration",
                "cash_proceeds",
                "noncash_proceeds",
                "debt_transferred",
                "gain_loss",
                "retained_interest",
            },
            execution={"cash_proceeds", "noncash_proceeds"},
            completion={"cash_proceeds", "gain_loss"},
            outcomes={"cash_proceeds", "noncash_proceeds", "gain_loss", "retained_interest"},
        ),
        _policy(
            "buyback",
            subtypes={"open_market", "accelerated", "tender_offer", "other_program"},
            identity={"program_id", "approval_date", "security_class"},
            facts={
                "authorization_limit",
                "cash_spent",
                "shares_repurched",
                "average_price",
                "sbc_expense",
                "sbc_shares_issued",
                "other_equity_shares_issued",
                "basic_shares_change",
                "diluted_shares_change",
            },
            execution={"cash_spent", "shares_repurched"},
            completion={"cash_spent", "shares_repurched"},
            outcomes={
                "cash_spent",
                "shares_repurched",
                "sbc_shares_issued",
                "other_equity_shares_issued",
                "basic_shares_change",
                "diluted_shares_change",
            },
        ),
        _policy(
            "dividend",
            subtypes={"regular", "special"},
            identity={"declaration_date", "security_class"},
            facts={
                "dividend_per_share_declared",
                "aggregate_dividend_declared",
                "aggregate_dividend_paid",
                "eligible_shares",
            },
            execution={"aggregate_dividend_paid"},
            completion={"aggregate_dividend_paid"},
            outcomes={"aggregate_dividend_paid", "eligible_shares"},
        ),
        _policy(
            "debt_issuance",
            subtypes={"new_money", "refinancing", "revolver_draw"},
            identity={"instrument_id"},
            facts={
                "principal_issued",
                "gross_proceeds",
                "net_proceeds",
                "issuance_cost",
                "debt_refinanced",
                "maturity",
                "coupon_rate",
            },
            execution={"principal_issued", "gross_proceeds"},
            completion={"principal_issued", "net_proceeds"},
            outcomes={"principal_issued", "debt_refinanced", "incremental_debt", "net_proceeds"},
        ),
        _policy(
            "debt_repayment",
            subtypes={"scheduled", "early_redemption", "refinancing"},
            identity={"instrument_id"},
            facts={
                "principal_repaid",
                "cash_paid",
                "debt_refinanced",
                "extinguishment_gain_loss",
            },
            execution={"principal_repaid", "cash_paid"},
            completion={"principal_repaid", "cash_paid"},
            outcomes={"principal_repaid", "debt_refinanced", "incremental_debt", "cash_paid"},
        ),
        _policy(
            "equity_issuance",
            subtypes={
                "public_offering",
                "private_placement",
                "at_the_market",
                "acquisition_consideration",
                "employee_plan",
            },
            identity={"program_id", "security_class"},
            facts={"shares_issued", "gross_proceeds", "net_proceeds", "issuance_cost"},
            execution={"shares_issued", "gross_proceeds"},
            completion={"shares_issued", "net_proceeds"},
            outcomes={"shares_issued", "net_proceeds"},
        ),
        _policy(
            "stock_based_compensation",
            subtypes={"grant", "vesting_settlement", "tax_withholding", "employee_purchase"},
            identity={"plan_id", "fiscal_year"},
            facts={
                "sbc_expense",
                "shares_granted",
                "shares_vested",
                "shares_issued",
                "shares_withheld",
                "unrecognized_compensation",
            },
            execution={"sbc_expense", "shares_issued"},
            completion={"sbc_expense"},
            outcomes={
                "sbc_expense",
                "shares_issued",
                "shares_withheld",
                "unrecognized_compensation",
            },
        ),
        _policy(
            "pension_funding",
            subtypes={"required", "discretionary"},
            identity={"plan_id", "fiscal_year"},
            facts={
                "required_contribution",
                "discretionary_contribution",
                "cash_contribution",
                "funded_status_change",
            },
            execution={"cash_contribution"},
            completion={"cash_contribution"},
            outcomes={"cash_contribution", "funded_status_change"},
        ),
        _policy(
            "restructuring",
            subtypes={"workforce", "facility", "product_exit", "integration", "mixed"},
            identity={"program_id", "announcement_date"},
            facts={
                "announced_charge",
                "recognized_charge",
                "cash_paid",
                "liability_balance",
                "headcount_reduction",
            },
            execution={"recognized_charge", "cash_paid"},
            completion={"cash_paid", "liability_balance"},
            outcomes={
                "recognized_charge",
                "cash_paid",
                "liability_balance",
                "headcount_reduction",
            },
        ),
        _policy(
            "cash_accumulation",
            subtypes={"operating_liquidity", "restricted_cash", "strategic_reserve"},
            identity={"program_id", "fiscal_period"},
            facts={
                "cash_and_equivalents",
                "restricted_cash",
                "marketable_securities",
                "net_cash_change",
            },
            execution={"net_cash_change"},
            completion={"cash_and_equivalents", "net_cash_change"},
            outcomes={
                "cash_and_equivalents",
                "restricted_cash",
                "marketable_securities",
                "net_cash_change",
            },
        ),
    )
}

EVENT_TYPES = frozenset(CAPITAL_ALLOCATION_POLICIES)
ALL_EVENT_SUBTYPES = frozenset(
    subtype for policy in CAPITAL_ALLOCATION_POLICIES.values() for subtype in policy.subtypes
)
ALL_FACT_ROLES = frozenset(
    role for policy in CAPITAL_ALLOCATION_POLICIES.values() for role in policy.fact_roles
)
ALL_OUTCOME_ROLES = frozenset(
    role for policy in CAPITAL_ALLOCATION_POLICIES.values() for role in policy.outcome_roles
)


def policy_for(event_type: str) -> CapitalAllocationPolicy:
    try:
        return CAPITAL_ALLOCATION_POLICIES[event_type]
    except KeyError as exc:
        raise ValueError(f"unregistered capital-allocation event type: {event_type}") from exc


def economic_event_key(
    *,
    issuer_id: str,
    event_type: str,
    event_subtype: str,
    identity_components: tuple[dict[str, str], ...] | list[dict[str, str]],
) -> str:
    policy = policy_for(event_type)
    if event_subtype not in policy.subtypes:
        raise ValueError("unregistered capital-allocation event subtype")
    roles = [item["role"] for item in identity_components]
    allowed_role_sets = IDENTITY_ROLE_SETS[event_type][event_subtype]
    if len(roles) != len(set(roles)) or frozenset(roles) not in allowed_role_sets:
        raise ValueError("economic identity components do not match policy")
    normalized = sorted(
        (
            {
                "role": item["role"],
                "value": " ".join(item["value"].split()).casefold(),
            }
            for item in identity_components
        ),
        key=lambda item: item["role"],
    )
    return canonical_sha256(
        {
            "issuer_id": issuer_id,
            "event_type": event_type,
            "event_subtype": event_subtype,
            "identity_components": normalized,
        }
    )
