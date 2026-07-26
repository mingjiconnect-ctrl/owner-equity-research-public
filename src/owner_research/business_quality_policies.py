from __future__ import annotations

from dataclasses import dataclass

POLICY_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class MechanismPolicy:
    mechanism: str
    version: str
    support_roles: frozenset[str]
    counterevidence_roles: frozenset[str]
    forbidden_single_indicators: frozenset[str]

    @property
    def allowed_roles(self) -> frozenset[str]:
        return self.support_roles | self.counterevidence_roles


_COMMON_FORBIDDEN = frozenset(
    {
        "high_growth_alone",
        "high_gross_margin_alone",
        "high_roic_alone",
        "price_increase_alone",
        "user_growth_alone",
        "recurring_revenue_alone",
        "patent_count_alone",
        "few_competitors_alone",
    }
)


MECHANISM_POLICIES: dict[str, MechanismPolicy] = {
    "switching_cost": MechanismPolicy(
        "switching_cost",
        POLICY_VERSION,
        frozenset({"retention_churn", "migration_integration_cost"}),
        frozenset({"multihoming_substitution"}),
        _COMMON_FORBIDDEN,
    ),
    "network_effect": MechanismPolicy(
        "network_effect",
        POLICY_VERSION,
        frozenset({"network_density", "feedback_loop", "outcome_quality"}),
        frozenset({"subsidy_multihoming"}),
        _COMMON_FORBIDDEN,
    ),
    "scale_cost_advantage": MechanismPolicy(
        "scale_cost_advantage",
        POLICY_VERSION,
        frozenset({"unit_cost", "scale_driver", "competitor_benchmark"}),
        frozenset({"diseconomy_capital_intensity"}),
        _COMMON_FORBIDDEN,
    ),
    "brand_pricing_power": MechanismPolicy(
        "brand_pricing_power",
        POLICY_VERSION,
        frozenset({"price_mix", "volume_share_resilience"}),
        frozenset({"promotion_competitor_response"}),
        _COMMON_FORBIDDEN,
    ),
    "intellectual_property": MechanismPolicy(
        "intellectual_property",
        POLICY_VERSION,
        frozenset({"protected_right", "protection_duration", "commercial_output"}),
        frozenset({"expiry_substitution"}),
        _COMMON_FORBIDDEN,
    ),
    "regulatory_license": MechanismPolicy(
        "regulatory_license",
        POLICY_VERSION,
        frozenset({"license", "scarcity", "entry_time_cost"}),
        frozenset({"regulatory_change_competitor_access"}),
        _COMMON_FORBIDDEN,
    ),
    "distribution": MechanismPolicy(
        "distribution",
        POLICY_VERSION,
        frozenset({"coverage", "channel_control", "acquisition_fulfillment_economics"}),
        frozenset({"channel_dependency_conflict"}),
        _COMMON_FORBIDDEN,
    ),
    "data_learning": MechanismPolicy(
        "data_learning",
        POLICY_VERSION,
        frozenset({"data_feedback", "measurable_improvement", "data_uniqueness"}),
        frozenset({"replicability_privacy"}),
        _COMMON_FORBIDDEN,
    ),
    "efficient_scale": MechanismPolicy(
        "efficient_scale",
        POLICY_VERSION,
        frozenset({"market_capacity", "minimum_efficient_scale", "entrant_economics"}),
        frozenset({"demand_capacity_change"}),
        _COMMON_FORBIDDEN,
    ),
    "process_execution": MechanismPolicy(
        "process_execution",
        POLICY_VERSION,
        frozenset({"cycle_quality_service", "asset_use", "persistence_benchmark"}),
        frozenset({"regression_replication"}),
        _COMMON_FORBIDDEN,
    ),
}


def mechanism_policy(mechanism: str, version: str = POLICY_VERSION) -> MechanismPolicy:
    if version != POLICY_VERSION or mechanism not in MECHANISM_POLICIES:
        raise KeyError(f"unknown mechanism policy: {mechanism}@{version}")
    return MECHANISM_POLICIES[mechanism]
